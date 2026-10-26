use std::net::Ipv4Addr;
use std::time::Duration;

use axum::extract::Json;
use axum::routing::post;
use axum::Router;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::RData;
use tokio::net::UdpSocket;
use tokio::sync::watch;

use decisionns::model::{FailMode, RuleInput, ServiceInput};

async fn mock_upstream() -> std::net::SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                break;
            };
            let Ok(msg) = Message::from_vec(&buf[..n]) else {
                continue;
            };
            let Some(query) = msg.queries.first().cloned() else {
                continue;
            };
            let mut resp = Message::response(msg.metadata.id, msg.metadata.op_code);
            resp.metadata.recursion_available = true;
            resp.metadata.recursion_desired = msg.metadata.recursion_desired;
            resp.add_query(query.clone());
            let record = hickory_proto::rr::Record::from_rdata(
                query.name().clone(),
                60,
                RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(1, 2, 3, 4))),
            );
            resp.add_answer(record);
            let bytes = resp.to_vec().unwrap();
            let _ = sock.send_to(&bytes, peer).await;
        }
    });
    addr
}

async fn ask(server: std::net::SocketAddr, name: &str) -> Message {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let packet = decisionns::dns::encode_query(name, 42).unwrap();
    sock.send_to(&packet, server).await.unwrap();
    let mut buf = [0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(2), sock.recv(&mut buf))
        .await
        .expect("timeout")
        .unwrap();
    Message::from_vec(&buf[..n]).unwrap()
}

#[tokio::test]
async fn blocklist_sinkholes_and_other_names_are_forwarded() {
    let upstream = mock_upstream().await;
    let dir = std::env::temp_dir().join(format!("decisionns-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let app = decisionns::app::App::open_at(&dir, vec![upstream.to_string()]).unwrap();
    app.store()
        .add_domain("block", "blocked.example", "test")
        .unwrap();
    app.reload().unwrap();

    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dns_addr = sock.local_addr().unwrap();
    let (_tx, rx) = watch::channel(false);
    tokio::spawn(decisionns::dns::serve_udp(sock, app, rx));
    tokio::time::sleep(Duration::from_millis(50)).await;

    let blocked = ask(dns_addr, "blocked.example").await;
    assert_eq!(blocked.metadata.response_code, ResponseCode::NoError);
    match &blocked.answers[0].data {
        RData::A(a) => assert_eq!(Ipv4Addr::from(*a), Ipv4Addr::UNSPECIFIED),
        other => panic!("expected A, got {other:?}"),
    }

    let allowed = ask(dns_addr, "ok.example").await;
    assert_eq!(allowed.metadata.response_code, ResponseCode::NoError);
    match &allowed.answers[0].data {
        RData::A(a) => assert_eq!(Ipv4Addr::from(*a), Ipv4Addr::new(1, 2, 3, 4)),
        other => panic!("expected A, got {other:?}"),
    }
}

async fn mock_model() -> String {
    let app = Router::new().route(
        "/v1/systemone",
        post(|Json(body): Json<serde_json::Value>| async move {
            let domain = body["state"]["domain"].as_str().unwrap_or("");
            let block = domain.contains("bad");
            Json(serde_json::json!({
                "model": "test-model",
                "answers": {
                    "unsafe_for_children": { "type": "noul", "noul": if block { 0.96 } else { 0.04 } },
                    "category": {
                        "type": "choice",
                        "choice": if block { "adult" } else { "safe" },
                        "confidence": 0.9,
                        "probabilities": { "adult": if block { 0.9 } else { 0.05 }, "safe": if block { 0.05 } else { 0.9 } }
                    }
                }
            }))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn decision_model_blocks_only_names_it_rejects() {
    let upstream = mock_upstream().await;
    let model = mock_model().await;
    let dir = std::env::temp_dir().join(format!(
        "decisionns-decide-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let app = decisionns::app::App::open_at(&dir, vec![upstream.to_string()]).unwrap();
    let service = app
        .store()
        .create_service(&ServiceInput {
            name: "mock".into(),
            kind: "custom".into(),
            base_url: model,
            model: "test-model".into(),
            timeout_ms: 2000,
            enabled: true,
            api_key: None,
        })
        .unwrap();
    app.store()
        .create_rule(&RuleInput {
            name: "test decide".into(),
            enabled: true,
            priority: 1,
            profile: "any".into(),
            device_ip: String::new(),
            domain_pattern: "*".into(),
            action: "decide".into(),
            service_id: Some(service.id),
            questions: decisionns::decision::child_safety_questions(),
            noul_question: "unsafe_for_children".into(),
            noul_threshold: 0.8,
            score_question: String::new(),
            score_threshold: 2.0,
            block_choices: serde_json::json!({ "category": ["adult"] }),
            min_confidence: 0.55,
            on_uncertain: FailMode::Allow,
            on_error: FailMode::Allow,
            hour_start: None,
            hour_end: None,
            days_mask: 0,
            comment: String::new(),
        })
        .unwrap();
    app.reload().unwrap();

    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dns_addr = sock.local_addr().unwrap();
    let (_tx, rx) = watch::channel(false);
    tokio::spawn(decisionns::dns::serve_udp(sock, app, rx));
    tokio::time::sleep(Duration::from_millis(50)).await;

    let blocked = ask(dns_addr, "bad.example").await;
    match &blocked.answers[0].data {
        RData::A(a) => assert_eq!(Ipv4Addr::from(*a), Ipv4Addr::UNSPECIFIED),
        other => panic!("expected sinkhole, got {other:?}"),
    }

    let allowed = ask(dns_addr, "ok.example").await;
    match &allowed.answers[0].data {
        RData::A(a) => assert_eq!(Ipv4Addr::from(*a), Ipv4Addr::new(1, 2, 3, 4)),
        other => panic!("expected upstream answer, got {other:?}"),
    }
}
