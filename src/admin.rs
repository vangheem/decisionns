//! LAN admin UI and JSON API. Password session, private networks only
//! unless `admin.allow_public` is set.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Extension, Path, Query, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::app::App;
use crate::decision::{self, default_block_choices};
use crate::dns::is_lan;
use crate::model::{
    DevicePatch, FailMode, QueryFilter, Rule, RuleInput, ServiceInput, Settings,
};
use crate::policy::{self, QueryContext};

const COOKIE: &str = "decisionns_session";
const UI: &str = include_str!("ui.html");

static LOGIN_HITS: LazyLock<Mutex<HashMap<IpAddr, Vec<Instant>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub fn router(app: App) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/session", get(session))
        .route("/api/status", get(status))
        .route("/api/overview", get(overview))
        .route("/api/queries", get(queries))
        .route("/api/devices", get(devices))
        .route("/api/devices/{id}", patch(patch_device).delete(delete_device))
        .route("/api/rules", get(rules).post(create_rule))
        .route("/api/rules/{id}", patch(update_rule).delete(delete_rule))
        .route("/api/services", get(services).post(create_service))
        .route("/api/services/{id}", patch(update_service).delete(delete_service))
        .route("/api/services/{id}/test", post(test_service))
        .route("/api/lists", get(lists).post(add_list))
        .route("/api/lists/{id}", axum::routing::delete(delete_list))
        .route("/api/lists/import", post(import_lists))
        .route("/api/lists/presets/doh-bypass", post(doh_preset))
        .route("/api/settings", get(get_settings).put(put_settings))
        .route("/api/cache/clear", post(clear_cache))
        .route("/api/account/password", post(change_password))
        .route("/api/simulate", post(simulate))
        .route("/api/presets", get(presets))
        .layer(middleware::from_fn_with_state(app.clone(), gate))
        .with_state(app)
}

fn patch<H, T, S>(handler: H) -> axum::routing::MethodRouter<S>
where
    H: axum::handler::Handler<T, S>,
    T: 'static,
    S: Clone + Send + Sync + 'static,
{
    axum::routing::patch(handler)
}

async fn index() -> Html<&'static str> {
    Html(UI)
}

async fn gate(State(app): State<App>, req: Request, next: Next) -> Response {
    if let Some(ConnectInfo(addr)) = req.extensions().get::<ConnectInfo<SocketAddr>>() {
        if !app.admin_allow_public() && !is_lan(addr.ip()) {
            return ApiError::new(StatusCode::FORBIDDEN, "admin UI is limited to private networks").into_response();
        }
    }
    if !csrf_ok(&req) {
        return ApiError::new(StatusCode::FORBIDDEN, "cross-site request blocked").into_response();
    }
    let path = req.uri().path();
    if path == "/api/login" || !path.starts_with("/api/") {
        return next.run(req).await;
    }
    let Some(token) = session_token(req.headers()) else {
        return ApiError::new(StatusCode::UNAUTHORIZED, "login required").into_response();
    };
    match app.store().user_for_session(&token) {
        Ok(Some((id, username))) => {
            let mut req = req;
            req.extensions_mut().insert(CurrentUser { id, username });
            next.run(req).await
        }
        Ok(None) => ApiError::new(StatusCode::UNAUTHORIZED, "login required").into_response(),
        Err(e) => ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

fn csrf_ok(req: &Request) -> bool {
    if req.method() == axum::http::Method::GET || req.method() == axum::http::Method::HEAD {
        return true;
    }
    let Some(origin) = req.headers().get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        return true;
    };
    let Some(host) = req.headers().get(header::HOST).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    origin == format!("http://{host}") || origin == format!("https://{host}")
}

#[derive(Clone)]
struct CurrentUser {
    id: i64,
    username: String,
}

struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

fn err(status: StatusCode, e: impl ToString) -> ApiError {
    ApiError::new(status, e.to_string())
}

async fn login(
    State(app): State<App>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<LoginBody>,
) -> Result<Response, ApiError> {
    let ip = crate::dns::canonical_ip(addr.ip());
    if login_limited(ip) {
        return Err(ApiError::new(StatusCode::TOO_MANY_REQUESTS, "too many login attempts"));
    }
    let id = app
        .store()
        .verify_login(body.username.trim(), &body.password)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?
        .ok_or_else(|| {
            note_login_failure(ip);
            ApiError::new(StatusCode::UNAUTHORIZED, "invalid username or password")
        })?;
    clear_login_failures(ip);
    let token = app
        .store()
        .create_session(id)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let mut response = Json(json!({ "username": body.username.trim() })).into_response();
    let secure = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        == Some("https");
    let cookie = format!(
        "{COOKIE}={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=1209600{}",
        if secure { "; Secure" } else { "" }
    );
    response.headers_mut().insert(
        header::SET_COOKIE,
        cookie.parse().map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "cookie"))?,
    );
    Ok(response)
}

async fn logout(State(app): State<App>, headers: HeaderMap) -> Result<Response, ApiError> {
    if let Some(token) = session_token(&headers) {
        let _ = app.store().delete_session(&token);
    }
    let mut response = Json(json!({ "ok": true })).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        format!("{COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0")
            .parse()
            .unwrap(),
    );
    Ok(response)
}

async fn session(Extension(user): Extension<CurrentUser>) -> Json<Value> {
    Json(json!({ "username": user.username }))
}

async fn status(State(app): State<App>) -> Json<Value> {
    let snap = app.snapshot();
    Json(json!({
        "version": crate::VERSION,
        "dns_listen": app.dns_listen(),
        "admin_listen": app.admin_listen(),
        "warnings": snap.warnings,
        "decision_cache": app.decider().len().await,
        "services_ready": snap.services.iter().any(|s| s.enabled),
    }))
}

async fn overview(State(app): State<App>, Query(q): Query<RangeQuery>) -> Result<Json<crate::model::Overview>, ApiError> {
    let range = q.range.as_deref().unwrap_or("24h");
    app.store()
        .overview(range)
        .map(Json)
        .map_err(|e| err(StatusCode::BAD_REQUEST, e))
}

async fn queries(State(app): State<App>, Query(q): Query<LogQuery>) -> Result<Json<Value>, ApiError> {
    let rows = app
        .store()
        .queries(&QueryFilter {
            limit: q.limit.unwrap_or(80),
            offset: q.offset.unwrap_or(0),
            device: q.device.filter(|s| !s.is_empty()),
            action: q.action.filter(|s| !s.is_empty()),
            q: q.q.filter(|s| !s.is_empty()),
        })
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(json!({ "queries": rows })))
}

async fn devices(State(app): State<App>) -> Result<Json<Value>, ApiError> {
    let devices = app
        .store()
        .list_devices()
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(json!({ "devices": devices })))
}

async fn patch_device(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(body): Json<DevicePatch>,
) -> Result<Json<crate::model::Device>, ApiError> {
    let device = app
        .store()
        .update_device(id, &body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, e))?;
    app.reload().map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(device))
}

async fn delete_device(State(app): State<App>, Path(id): Path<i64>) -> Result<Json<Value>, ApiError> {
    app.store()
        .delete_device(id)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    app.reload().map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(json!({ "ok": true })))
}

async fn rules(State(app): State<App>) -> Result<Json<Value>, ApiError> {
    let rules = app
        .store()
        .list_rules()
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(json!({ "rules": rules })))
}

async fn create_rule(State(app): State<App>, Json(body): Json<RuleInput>) -> Result<Json<Rule>, ApiError> {
    let rule = app
        .store()
        .create_rule(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, e))?;
    app.reload().map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(rule))
}

async fn update_rule(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(body): Json<RuleInput>,
) -> Result<Json<Rule>, ApiError> {
    let rule = app
        .store()
        .update_rule(id, &body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, e))?;
    app.reload().map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let _ = app.decider().clear().await;
    Ok(Json(rule))
}

async fn delete_rule(State(app): State<App>, Path(id): Path<i64>) -> Result<Json<Value>, ApiError> {
    app.store()
        .delete_rule(id)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    app.reload().map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(json!({ "ok": true })))
}

async fn services(State(app): State<App>) -> Result<Json<Value>, ApiError> {
    let services = app
        .store()
        .list_services()
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(json!({ "services": services })))
}

async fn create_service(
    State(app): State<App>,
    Json(body): Json<ServiceInput>,
) -> Result<Json<crate::model::Service>, ApiError> {
    let service = app
        .store()
        .create_service(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, e))?;
    app.reload().map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(service))
}

async fn update_service(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(body): Json<ServiceInput>,
) -> Result<Json<crate::model::Service>, ApiError> {
    let service = app
        .store()
        .update_service(id, &body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, e))?;
    app.reload().map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let _ = app.decider().clear().await;
    Ok(Json(service))
}

async fn delete_service(State(app): State<App>, Path(id): Path<i64>) -> Result<Json<Value>, ApiError> {
    app.store()
        .delete_service(id)
        .map_err(|e| err(StatusCode::CONFLICT, e))?;
    app.reload().map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(json!({ "ok": true })))
}

async fn test_service(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(body): Json<TestBody>,
) -> Result<Json<Value>, ApiError> {
    let service = app
        .store()
        .service_with_secret(id)
        .map_err(|e| err(StatusCode::NOT_FOUND, e))?;
    if !service.enabled {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "enable the service before testing"));
    }
    let questions = body
        .questions
        .clone()
        .unwrap_or_else(decision::child_safety_questions);
    let profile = if body.profile.is_empty() {
        "child".into()
    } else {
        body.profile.clone()
    };
    let rule = Rule {
        id: 0,
        name: "test".into(),
        enabled: true,
        priority: 0,
        profile: profile.clone(),
        device_ip: String::new(),
        domain_pattern: "*".into(),
        action: "decide".into(),
        service_id: Some(id),
        questions,
        noul_question: if body.noul_question.is_empty() {
            "unsafe_for_children".into()
        } else {
            body.noul_question.clone()
        },
        noul_threshold: body.noul_threshold.unwrap_or(0.8),
        score_question: body.score_question.clone(),
        score_threshold: body.score_threshold.unwrap_or(2.0),
        block_choices: body
            .block_choices
            .clone()
            .unwrap_or_else(default_block_choices),
        min_confidence: body.min_confidence.unwrap_or(0.55),
        on_uncertain: FailMode::Allow,
        on_error: FailMode::Allow,
        hour_start: None,
        hour_end: None,
        days_mask: 0,
        comment: String::new(),
    };
    let ctx = QueryContext::new(&body.domain, "A", "simulate", &profile);
    let started = Instant::now();
    let decision = app
        .decider()
        .evaluate(&service, &rule, &ctx, Duration::ZERO)
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, e))?;
    Ok(Json(json!({
        "block": decision.verdict.block,
        "reason": decision.verdict.reason,
        "model": decision.model,
        "answers": decision.answers,
        "latency_ms": started.elapsed().as_millis() as u64,
        "state": decision::decision_state(&ctx),
    })))
}

async fn lists(State(app): State<App>, Query(q): Query<KindQuery>) -> Result<Json<Value>, ApiError> {
    let kind = q.kind.as_deref().filter(|s| !s.is_empty());
    let lists = app
        .store()
        .list_domains(kind)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(json!({ "lists": lists })))
}

async fn add_list(State(app): State<App>, Json(body): Json<ListBody>) -> Result<Json<crate::model::DomainEntry>, ApiError> {
    let entry = app
        .store()
        .add_domain(&body.kind, &body.pattern, &body.comment.unwrap_or_default())
        .map_err(|e| err(StatusCode::BAD_REQUEST, e))?;
    app.reload().map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(entry))
}

async fn delete_list(State(app): State<App>, Path(id): Path<i64>) -> Result<Json<Value>, ApiError> {
    app.store()
        .delete_domain(id)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    app.reload().map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(json!({ "ok": true })))
}

async fn import_lists(State(app): State<App>, Json(body): Json<ImportBody>) -> Result<Json<Value>, ApiError> {
    let added = app
        .store()
        .import_domains(&body.kind, &body.text)
        .map_err(|e| err(StatusCode::BAD_REQUEST, e))?;
    app.reload().map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(json!({ "added": added })))
}

async fn doh_preset(State(app): State<App>) -> Result<Json<Value>, ApiError> {
    let text = decision::doh_bypass_domains().join("\n");
    let added = app
        .store()
        .import_domains("block", &text)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    app.reload().map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(json!({
        "added": added,
        "note": "Browsers that use these DoH endpoints will stop bypassing DecisionNS. Your own upstream DoH calls are made by this server, not by clients, so blocking these names does not break forwarding."
    })))
}

async fn get_settings(State(app): State<App>) -> Result<Json<Settings>, ApiError> {
    app.store()
        .get_settings()
        .map(Json)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))
}

async fn put_settings(State(app): State<App>, Json(body): Json<Settings>) -> Result<Json<Settings>, ApiError> {
    app.store()
        .put_settings(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, e))?;
    app.reload().map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(body))
}

async fn clear_cache(State(app): State<App>) -> Json<Value> {
    app.decider().clear().await;
    Json(json!({ "ok": true }))
}

async fn change_password(
    State(app): State<App>,
    Extension(user): Extension<CurrentUser>,
    Json(body): Json<PasswordBody>,
) -> Result<Json<Value>, ApiError> {
    let ok = app
        .store()
        .verify_login(&user.username, &body.current)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?
        .is_some();
    if !ok {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "current password is wrong"));
    }
    app.store()
        .set_password(user.id, &body.next)
        .map_err(|e| err(StatusCode::BAD_REQUEST, e))?;
    let path = app.data_dir().join("initial-admin-password.txt");
    let _ = std::fs::remove_file(path);
    Ok(Json(json!({ "ok": true })))
}

async fn simulate(State(app): State<App>, Json(body): Json<SimulateBody>) -> Result<Json<Value>, ApiError> {
    let snap = app.snapshot();
    let device_ip = if body.device_ip.is_empty() {
        "simulate".into()
    } else {
        body.device_ip.clone()
    };
    let profile = if !body.profile.is_empty() {
        body.profile.clone()
    } else {
        snap.device_by_ip(&device_ip)
            .map(|d| d.profile.clone())
            .unwrap_or_else(|| "standard".into())
    };
    let qtype = if body.qtype.is_empty() { "A".into() } else { body.qtype.clone() };
    let ctx = QueryContext::new(&body.domain, &qtype, &device_ip, &profile);
    let step = policy::classify(&snap, &ctx);
    match step {
        policy::Step::Allow { reason } => Ok(Json(json!({
            "action": "allow",
            "reason": reason,
            "profile": profile,
            "domain": ctx.domain,
        }))),
        policy::Step::Block { reason, rule_id } => Ok(Json(json!({
            "action": "block",
            "reason": reason,
            "rule_id": rule_id,
            "profile": profile,
            "domain": ctx.domain,
        }))),
        policy::Step::Decide { rule } => {
            let Some(service) = rule.rule.service_id.and_then(|id| snap.service(id)).cloned() else {
                return Ok(Json(json!({
                    "action": "allow",
                    "reason": "decision service not ready",
                    "profile": profile,
                    "domain": ctx.domain,
                })));
            };
            let started = Instant::now();
            let decision = app
                .decider()
                .evaluate(&service, &rule.rule, &ctx, Duration::from_secs(snap.settings.decision_cache_ttl_secs))
                .await
                .map_err(|e| err(StatusCode::BAD_GATEWAY, e))?;
            let action = if decision.verdict.block { "block" } else { "allow" };
            Ok(Json(json!({
                "action": action,
                "reason": format!("rule {}: {}", rule.rule.name, decision.verdict.reason),
                "rule_id": rule.rule.id,
                "profile": profile,
                "domain": ctx.domain,
                "model": decision.model,
                "answers": decision.answers,
                "cached": decision.cached,
                "latency_ms": started.elapsed().as_millis() as u64,
            })))
        }
    }
}

async fn presets() -> Json<Value> {
    Json(json!({
        "child-safety": {
            "questions": decision::child_safety_questions(),
            "noul_question": "unsafe_for_children",
            "noul_threshold": 0.8,
            "block_choices": default_block_choices(),
            "min_confidence": 0.55,
        },
        "malware": {
            "questions": decision::malware_questions(),
            "noul_question": "malicious",
            "noul_threshold": 0.85,
            "block_choices": { "category": ["phishing", "malware", "scam"] },
            "min_confidence": 0.6,
        }
    }))
}

fn session_token(headers: &HeaderMap) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in cookie.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix(&format!("{COOKIE}=")) {
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn login_limited(ip: IpAddr) -> bool {
    let Ok(mut hits) = LOGIN_HITS.lock() else {
        return false;
    };
    let now = Instant::now();
    let window = hits.entry(ip).or_default();
    window.retain(|t| now.duration_since(*t) < Duration::from_secs(600));
    window.len() >= 8
}

fn note_login_failure(ip: IpAddr) {
    if let Ok(mut hits) = LOGIN_HITS.lock() {
        hits.entry(ip).or_default().push(Instant::now());
    }
}

fn clear_login_failures(ip: IpAddr) {
    if let Ok(mut hits) = LOGIN_HITS.lock() {
        hits.remove(&ip);
    }
}

#[derive(Deserialize)]
struct LoginBody {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct RangeQuery {
    range: Option<String>,
}

#[derive(Deserialize)]
struct LogQuery {
    limit: Option<i64>,
    offset: Option<i64>,
    device: Option<String>,
    action: Option<String>,
    q: Option<String>,
}

#[derive(Deserialize)]
struct KindQuery {
    kind: Option<String>,
}

#[derive(Deserialize)]
struct ListBody {
    kind: String,
    pattern: String,
    comment: Option<String>,
}

#[derive(Deserialize)]
struct ImportBody {
    kind: String,
    text: String,
}

#[derive(Deserialize)]
struct PasswordBody {
    current: String,
    next: String,
}

#[derive(Deserialize)]
struct SimulateBody {
    domain: String,
    #[serde(default)]
    device_ip: String,
    #[serde(default)]
    qtype: String,
    #[serde(default)]
    profile: String,
}

#[derive(Deserialize)]
struct TestBody {
    domain: String,
    #[serde(default)]
    profile: String,
    #[serde(default)]
    questions: Option<Value>,
    #[serde(default)]
    noul_question: String,
    noul_threshold: Option<f64>,
    #[serde(default)]
    score_question: String,
    score_threshold: Option<f64>,
    block_choices: Option<Value>,
    min_confidence: Option<f64>,
}


