//! SystemOne client shared by Jev, Clef, and any compatible endpoint.
//!
//! POST `{base_url}/v1/systemone`
//! Authorization: Bearer <key>   (omitted when the key is empty)

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use crate::model::{Rule, Service};
use crate::names::registrable;
use crate::policy::{interpret, QueryContext, Verdict};

#[derive(Debug, Clone)]
pub struct Decision {
    pub verdict: Verdict,
    pub answers: Value,
    pub model: String,
    pub cached: bool,
}

#[derive(Debug)]
struct Cached {
    decision: Decision,
    expires_at: Instant,
}

pub struct DecisionCache {
    http: reqwest::Client,
    cache: Mutex<HashMap<String, Cached>>,
    inflight: Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

impl DecisionCache {
    pub fn new(http: reqwest::Client) -> Self {
        Self {
            http,
            cache: Mutex::new(HashMap::new()),
            inflight: Mutex::new(HashMap::new()),
        }
    }

    pub async fn clear(&self) {
        self.cache.lock().await.clear();
    }

    pub async fn len(&self) -> usize {
        self.cache.lock().await.len()
    }

    pub async fn evaluate(
        &self,
        service: &Service,
        rule: &Rule,
        ctx: &QueryContext,
        cache_ttl: Duration,
    ) -> anyhow::Result<Decision> {
        let key = cache_key(service, rule, ctx);
        if let Some(hit) = self.fresh(&key).await {
            return Ok(hit);
        }

        let gate = {
            let mut gates = self.inflight.lock().await;
            gates
                .entry(key.clone())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        let held = gate.lock().await;
        if let Some(hit) = self.fresh(&key).await {
            drop(held);
            self.release_gate(&key, gate).await;
            return Ok(hit);
        }

        let called = self.call(service, rule, ctx).await;
        if let Ok(decision) = &called {
            if !cache_ttl.is_zero() {
                let mut cache = self.cache.lock().await;
                if cache.len() > 20_000 {
                    let now = Instant::now();
                    cache.retain(|_, v| v.expires_at > now);
                    if cache.len() > 20_000 {
                        cache.clear();
                    }
                }
                cache.insert(
                    key.clone(),
                    Cached {
                        decision: decision.clone(),
                        expires_at: Instant::now() + cache_ttl,
                    },
                );
            }
        }
        drop(held);
        self.release_gate(&key, gate).await;
        called
    }

    async fn release_gate(&self, key: &str, gate: Arc<Mutex<()>>) {
        drop(gate);
        let mut gates = self.inflight.lock().await;
        if gates.get(key).is_some_and(|g| Arc::strong_count(g) == 1) {
            gates.remove(key);
        }
    }

    async fn fresh(&self, key: &str) -> Option<Decision> {
        let cache = self.cache.lock().await;
        let hit = cache.get(key)?;
        if hit.expires_at <= Instant::now() {
            return None;
        }
        let mut decision = hit.decision.clone();
        decision.cached = true;
        Some(decision)
    }

    async fn call(&self, service: &Service, rule: &Rule, ctx: &QueryContext) -> anyhow::Result<Decision> {
        let url = endpoint(&service.base_url);
        let body = json!({
            "model": service.model,
            "state": decision_state(ctx),
            "questions": rule.questions,
        });
        let timeout = Duration::from_millis(service.timeout_ms.max(100));
        let mut req = self
            .http
            .post(url)
            .timeout(timeout)
            .header("content-type", "application/json")
            .header("user-agent", format!("decisionns/{}", crate::VERSION))
            .json(&body);
        if !service.api_key.is_empty() {
            req = req.bearer_auth(&service.api_key);
        }
        let response = req.send().await.map_err(|e| anyhow::anyhow!("decision request failed: {e}"))?;
        let status = response.status();
        if !status.is_success() {
            anyhow::bail!("decision service returned HTTP {status}");
        }
        let parsed: SystemOneResponse = response
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("decision response was not JSON: {e}"))?;
        let answers_obj = parsed.answers.as_object().cloned().unwrap_or_default();
        let verdict = interpret(rule, &answers_obj);
        Ok(Decision {
            verdict,
            answers: parsed.answers,
            model: parsed.model,
            cached: false,
        })
    }
}

#[derive(Debug, Deserialize)]
struct SystemOneResponse {
    #[serde(default)]
    model: String,
    #[serde(default)]
    answers: Value,
}

pub fn endpoint(base_url: &str) -> String {
    let base = base_url.trim().trim_end_matches('/');
    if base.ends_with("/v1/systemone") {
        base.to_string()
    } else {
        format!("{base}/v1/systemone")
    }
}

pub fn decision_state(ctx: &QueryContext) -> Value {
    json!({
        "task": "Decide whether this DNS lookup should be allowed on a home network.",
        "domain": ctx.domain,
        "registrable_domain": registrable(&ctx.domain),
        "query_type": ctx.qtype,
        "device_profile": ctx.profile,
        "constraint": "You can see only the domain name, not page content. Unfamiliar CDN, API, and infrastructure names are normal and usually safe. Treat a name as unsafe only when the name itself indicates the category."
    })
}

fn cache_key(service: &Service, rule: &Rule, ctx: &QueryContext) -> String {
    let mut hasher = Sha256::new();
    hasher.update(rule.questions.to_string().as_bytes());
    hasher.update(rule.noul_question.as_bytes());
    hasher.update(rule.noul_threshold.to_le_bytes());
    hasher.update(rule.block_choices.to_string().as_bytes());
    hasher.update(rule.min_confidence.to_le_bytes());
    let hash = hex::encode(&hasher.finalize()[..8]);
    format!(
        "{}:{}:{}:{}:{}:{}",
        service.id, service.model, hash, ctx.profile, ctx.domain, rule.id
    )
}

pub fn child_safety_questions() -> Value {
    json!({
        "unsafe_for_children": {
            "type": "noul",
            "instructions": "Would loading this domain be unsafe for a child? Consider pornography, graphic violence, illegal drugs, gambling, scams, and malware. Judge only from the domain name and the context. Ordinary sites, CDNs, APIs, and infrastructure should be safe. Do not mark a name unsafe merely because it is unfamiliar.",
            "criteria": {
                "true": "The domain name itself indicates content or infrastructure that is unsafe for a child",
                "false": "The domain is ordinary, infrastructural, or not clearly unsafe"
            }
        },
        "category": {
            "type": "choice",
            "instructions": "What is the most likely purpose of this domain, based only on its name and the context?",
            "criteria": {
                "safe": "Ordinary website, CDN, API, or network infrastructure",
                "adult": "Pornography or explicit sexual content",
                "violence": "Graphic violence, gore, or weapons trafficking",
                "drugs": "Illegal drug sales or promotion",
                "gambling": "Online gambling or betting",
                "malware": "Malware, phishing, or scam infrastructure",
                "unknown": "Not enough information in the name to classify"
            }
        }
    })
}

pub fn malware_questions() -> Value {
    json!({
        "malicious": {
            "type": "noul",
            "instructions": "Is this domain likely malware, phishing, or scam infrastructure? Judge only from the name. Ordinary and unfamiliar infrastructure should not be marked malicious.",
            "criteria": {
                "true": "The name indicates malware, phishing, or a scam",
                "false": "No clear sign of malware, phishing, or a scam"
            }
        },
        "category": {
            "type": "choice",
            "instructions": "What is the most likely purpose of this domain, based only on its name?",
            "criteria": {
                "safe": "Ordinary website, CDN, API, or network infrastructure",
                "phishing": "Credential theft or impersonation",
                "malware": "Malware delivery or command-and-control",
                "scam": "Fraud or scam infrastructure",
                "unknown": "Not enough information in the name to classify"
            }
        }
    })
}

pub fn preset(name: &str) -> Option<Value> {
    match name {
        "child-safety" => Some(child_safety_questions()),
        "malware" => Some(malware_questions()),
        _ => None,
    }
}

pub fn default_block_choices() -> Value {
    json!({
        "category": ["adult", "violence", "drugs", "gambling", "malware", "phishing", "scam"]
    })
}

/// DoH hostnames a browser can use to skip this resolver. Offered as an
/// optional blocklist, not enabled by default.
pub fn doh_bypass_domains() -> &'static [&'static str] {
    &[
        "dns.google",
        "dns.google.com",
        "cloudflare-dns.com",
        "mozilla.cloudflare-dns.com",
        "security.cloudflare-dns.com",
        "family.cloudflare-dns.com",
        "dns.quad9.net",
        "dns9.quad9.net",
        "dns10.quad9.net",
        "doh.opendns.com",
        "dns.nextdns.io",
        "dns.adguard-dns.com",
        "dns.adguard.com",
        "doh.dns.apple.com",
        "mask.icloud.com",
        "dns.switch.ch",
    ]
}


