use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct Config {
    pub data_dir: PathBuf,
    pub dns_listen: Vec<SocketAddr>,
    pub dns_tcp: bool,
    pub dns_allow_public: bool,
    pub admin_listen: SocketAddr,
    pub admin_username: String,
    pub admin_password: Option<String>,
    pub admin_allow_public: bool,
    pub upstream_servers: Vec<String>,
    pub upstream_timeout_ms: u64,
}

impl Config {
    pub fn dev_default() -> Self {
        Self {
            data_dir: PathBuf::from("data"),
            dns_listen: vec![
                "0.0.0.0:5353".parse().unwrap(),
                "[::]:5353".parse().unwrap(),
            ],
            dns_tcp: true,
            dns_allow_public: false,
            admin_listen: "0.0.0.0:8080".parse().unwrap(),
            admin_username: "admin".into(),
            admin_password: None,
            admin_allow_public: false,
            upstream_servers: crate::model::Settings::default().upstream_servers,
            upstream_timeout_ms: 1500,
        }
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("read {}: {e}", path.display()))?;
        let file: FileConfig = toml::from_str(&text)
            .map_err(|e| anyhow::anyhow!("parse {}: {e}", path.display()))?;
        file.into_config()
    }

    pub fn apply_env(&mut self) {
        if let Ok(dir) = std::env::var("DECISIONNS_DATA_DIR") {
            if !dir.is_empty() {
                self.data_dir = PathBuf::from(dir);
            }
        }
        if let Ok(password) = std::env::var("DECISIONNS_ADMIN_PASSWORD") {
            if !password.is_empty() {
                self.admin_password = Some(password);
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct FileConfig {
    #[serde(default = "default_data_dir")]
    data_dir: String,
    #[serde(default)]
    dns: DnsFile,
    #[serde(default)]
    admin: AdminFile,
    #[serde(default)]
    upstream: UpstreamFile,
}

#[derive(Debug, Deserialize)]
struct DnsFile {
    #[serde(default = "default_dns_listen")]
    listen: Vec<String>,
    #[serde(default = "default_true")]
    tcp: bool,
    #[serde(default)]
    allow_public: bool,
}

#[derive(Debug, Deserialize)]
struct AdminFile {
    #[serde(default = "default_admin_listen")]
    listen: String,
    #[serde(default = "default_username")]
    username: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    allow_public: bool,
}

#[derive(Debug, Deserialize)]
struct UpstreamFile {
    #[serde(default = "default_upstreams")]
    servers: Vec<String>,
    #[serde(default = "default_timeout")]
    timeout_ms: u64,
}

impl Default for DnsFile {
    fn default() -> Self {
        Self {
            listen: default_dns_listen(),
            tcp: true,
            allow_public: false,
        }
    }
}

impl Default for AdminFile {
    fn default() -> Self {
        Self {
            listen: default_admin_listen(),
            username: default_username(),
            password: None,
            allow_public: false,
        }
    }
}

impl Default for UpstreamFile {
    fn default() -> Self {
        Self {
            servers: default_upstreams(),
            timeout_ms: default_timeout(),
        }
    }
}

impl FileConfig {
    fn into_config(self) -> anyhow::Result<Config> {
        let dns_listen = self
            .dns
            .listen
            .iter()
            .map(|s| {
                s.parse::<SocketAddr>()
                    .map_err(|e| anyhow::anyhow!("dns listen `{s}`: {e}"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        if dns_listen.is_empty() {
            anyhow::bail!("dns.listen is empty");
        }
        let admin_listen = self
            .admin
            .listen
            .parse()
            .map_err(|e| anyhow::anyhow!("admin listen `{}`: {e}", self.admin.listen))?;
        Ok(Config {
            data_dir: PathBuf::from(self.data_dir),
            dns_listen,
            dns_tcp: self.dns.tcp,
            dns_allow_public: self.dns.allow_public,
            admin_listen,
            admin_username: self.admin.username,
            admin_password: self.admin.password.filter(|p| !p.is_empty()),
            admin_allow_public: self.admin.allow_public,
            upstream_servers: self.upstream.servers,
            upstream_timeout_ms: self.upstream.timeout_ms,
        })
    }
}

fn default_data_dir() -> String {
    "data".into()
}
fn default_dns_listen() -> Vec<String> {
    vec!["0.0.0.0:53".into(), "[::]:53".into()]
}
fn default_admin_listen() -> String {
    "0.0.0.0:8080".into()
}
fn default_username() -> String {
    "admin".into()
}
fn default_true() -> bool {
    true
}
fn default_timeout() -> u64 {
    1500
}
fn default_upstreams() -> Vec<String> {
    crate::model::Settings::default().upstream_servers
}
