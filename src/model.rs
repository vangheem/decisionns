use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlockMode {
    Sinkhole,
    Nxdomain,
    Refused,
}

impl BlockMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "sinkhole" => Some(Self::Sinkhole),
            "nxdomain" => Some(Self::Nxdomain),
            "refused" => Some(Self::Refused),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sinkhole => "sinkhole",
            Self::Nxdomain => "nxdomain",
            Self::Refused => "refused",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FailMode {
    Allow,
    Block,
}

impl FailMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "allow" => Some(Self::Allow),
            "block" => Some(Self::Block),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Block => "block",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub upstream_servers: Vec<String>,
    pub upstream_timeout_ms: u64,
    pub block_mode: BlockMode,
    pub block_ttl: u32,
    pub decision_cache_ttl_secs: u64,
    pub query_log_retention_days: i64,
    pub dns_allow_public: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            upstream_servers: vec![
                "https://cloudflare-dns.com/dns-query".into(),
                "https://dns.google/dns-query".into(),
                "1.1.1.1:53".into(),
                "8.8.8.8:53".into(),
            ],
            upstream_timeout_ms: 1500,
            block_mode: BlockMode::Sinkhole,
            block_ttl: 30,
            decision_cache_ttl_secs: 1800,
            query_log_retention_days: 14,
            dns_allow_public: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Device {
    pub id: i64,
    pub ip: String,
    pub name: String,
    pub profile: String,
    pub notes: String,
    pub first_seen: i64,
    pub last_seen: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DevicePatch {
    pub name: String,
    pub profile: String,
    pub notes: String,
}

#[derive(Clone, Serialize)]
pub struct Service {
    pub id: i64,
    pub name: String,
    pub kind: String,
    pub base_url: String,
    pub model: String,
    pub timeout_ms: u64,
    pub enabled: bool,
    pub has_api_key: bool,
    pub key_hint: String,
    #[serde(skip)]
    pub api_key: String,
}

impl std::fmt::Debug for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Service")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("base_url", &self.base_url)
            .field("model", &self.model)
            .field("enabled", &self.enabled)
            .field("has_api_key", &self.has_api_key)
            .finish()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServiceInput {
    pub name: String,
    pub kind: String,
    pub base_url: String,
    pub model: String,
    pub timeout_ms: u64,
    pub enabled: bool,
    /// Absent means "leave the stored key unchanged" on update.
    pub api_key: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Rule {
    pub id: i64,
    pub name: String,
    pub enabled: bool,
    pub priority: i64,
    pub profile: String,
    pub device_ip: String,
    pub domain_pattern: String,
    pub action: String,
    pub service_id: Option<i64>,
    pub questions: Value,
    pub noul_question: String,
    pub noul_threshold: f64,
    pub score_question: String,
    pub score_threshold: f64,
    pub block_choices: Value,
    pub min_confidence: f64,
    pub on_uncertain: FailMode,
    pub on_error: FailMode,
    pub hour_start: Option<u8>,
    pub hour_end: Option<u8>,
    pub days_mask: u8,
    pub comment: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuleInput {
    pub name: String,
    pub enabled: bool,
    pub priority: i64,
    pub profile: String,
    #[serde(default)]
    pub device_ip: String,
    pub domain_pattern: String,
    pub action: String,
    pub service_id: Option<i64>,
    pub questions: Value,
    pub noul_question: String,
    pub noul_threshold: f64,
    #[serde(default)]
    pub score_question: String,
    #[serde(default = "default_score_threshold")]
    pub score_threshold: f64,
    pub block_choices: Value,
    pub min_confidence: f64,
    pub on_uncertain: FailMode,
    pub on_error: FailMode,
    pub hour_start: Option<u8>,
    pub hour_end: Option<u8>,
    pub days_mask: u8,
    #[serde(default)]
    pub comment: String,
}

fn default_score_threshold() -> f64 {
    2.0
}

#[derive(Debug, Clone, Serialize)]
pub struct DomainEntry {
    pub id: i64,
    pub kind: String,
    pub pattern: String,
    pub comment: String,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct CompiledList {
    pub id: i64,
    pub kind: String,
    pub pattern: String,
    pub compiled: crate::names::Pattern,
    pub comment: String,
}

#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub rule: Rule,
    pub pattern: crate::names::Pattern,
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub settings: Settings,
    pub devices: Vec<Device>,
    pub services: Vec<Service>,
    pub rules: Vec<CompiledRule>,
    pub allowlist: Vec<CompiledList>,
    pub blocklist: Vec<CompiledList>,
    pub warnings: Vec<String>,
}

impl Snapshot {
    pub fn device_by_ip(&self, ip: &str) -> Option<&Device> {
        self.devices.iter().find(|d| d.ip == ip)
    }

    pub fn service(&self, id: i64) -> Option<&Service> {
        self.services.iter().find(|s| s.id == id)
    }
}

#[derive(Debug, Clone)]
pub struct QueryEvent {
    pub ts: i64,
    pub device_ip: String,
    pub qname: String,
    pub qtype: String,
    pub action: String,
    pub reason: String,
    pub rule_id: Option<i64>,
    pub decision_json: Option<String>,
    pub latency_ms: i64,
    pub decided: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct QueryRow {
    pub id: i64,
    pub ts: i64,
    pub device_ip: String,
    pub qname: String,
    pub qtype: String,
    pub action: String,
    pub reason: String,
    pub rule_id: Option<i64>,
    pub latency_ms: i64,
}

#[derive(Debug, Clone)]
pub struct QueryFilter {
    pub limit: i64,
    pub offset: i64,
    pub device: Option<String>,
    pub action: Option<String>,
    pub q: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SeriesPoint {
    pub bucket: i64,
    pub queries: i64,
    pub allowed: i64,
    pub blocked: i64,
    pub errors: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceStat {
    pub ip: String,
    pub name: String,
    pub profile: String,
    pub queries: i64,
    pub allowed: i64,
    pub blocked: i64,
    pub errors: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct NameCount {
    pub qname: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Overview {
    pub range: String,
    pub since: i64,
    pub totals: SeriesPoint,
    pub series: Vec<SeriesPoint>,
    pub devices: Vec<DeviceStat>,
    pub top_blocked: Vec<NameCount>,
    pub recent_blocks: Vec<QueryRow>,
}

pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

pub fn valid_profile(p: &str) -> bool {
    matches!(p, "unrestricted" | "standard" | "child")
}

pub fn valid_rule_profile(p: &str) -> bool {
    p == "any" || valid_profile(p)
}

pub fn valid_action(a: &str) -> bool {
    matches!(a, "allow" | "block" | "decide")
}

pub fn valid_kind(k: &str) -> bool {
    matches!(k, "jev" | "clef" | "custom")
}
