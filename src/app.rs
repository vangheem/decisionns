use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::sync::mpsc;

use crate::config::Config;
use crate::decision::DecisionCache;
use crate::model::{QueryEvent, Snapshot};
use crate::store::Store;

#[derive(Clone)]
pub struct App {
    inner: Arc<AppInner>,
}

struct AppInner {
    store: Store,
    snapshot: ArcSwap<Snapshot>,
    decider: DecisionCache,
    http: reqwest::Client,
    log_tx: mpsc::Sender<QueryEvent>,
    dns_listen: Vec<String>,
    admin_listen: String,
    admin_allow_public: bool,
    data_dir: PathBuf,
}

impl App {
    pub fn open(config: &Config, reset_password: bool) -> anyhow::Result<(Self, Option<String>)> {
        std::fs::create_dir_all(&config.data_dir)?;
        let db_path = config.data_dir.join("decisionns.db");
        let store = Store::open(&db_path)?;
        let generated = store.bootstrap(
            &config.admin_username,
            config.admin_password.as_deref(),
            reset_password,
            &config.upstream_servers,
            config.dns_allow_public,
        )?;
        let snapshot = store.load_snapshot()?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(8))
            .build()?;
        let (log_tx, log_rx) = mpsc::channel(1024);
        let app = Self {
            inner: Arc::new(AppInner {
                store,
                snapshot: ArcSwap::from_pointee(snapshot),
                decider: DecisionCache::new(http.clone()),
                http,
                log_tx,
                dns_listen: config.dns_listen.iter().map(|a| a.to_string()).collect(),
                admin_listen: config.admin_listen.to_string(),
                admin_allow_public: config.admin_allow_public,
                data_dir: config.data_dir.clone(),
            }),
        };
        app.spawn_log_writer(log_rx);
        app.spawn_maintenance();
        Ok((app, generated))
    }

    /// Test helper. Upstreams are seeded into a fresh database.
    pub fn open_at(path: &Path, upstreams: Vec<String>) -> anyhow::Result<Self> {
        let mut config = Config::dev_default();
        config.data_dir = path.to_path_buf();
        config.upstream_servers = upstreams;
        config.admin_password = Some("test-password".into());
        config.dns_allow_public = true;
        Ok(Self::open(&config, false)?.0)
    }

    pub fn reload(&self) -> anyhow::Result<()> {
        let snap = self.inner.store.load_snapshot()?;
        self.inner.snapshot.store(Arc::new(snap));
        Ok(())
    }

    pub fn snapshot(&self) -> Arc<Snapshot> {
        self.inner.snapshot.load_full()
    }

    pub fn store(&self) -> &Store {
        &self.inner.store
    }

    pub fn http(&self) -> &reqwest::Client {
        &self.inner.http
    }

    pub fn decider(&self) -> &DecisionCache {
        &self.inner.decider
    }

    pub fn dns_listen(&self) -> &[String] {
        &self.inner.dns_listen
    }

    pub fn admin_listen(&self) -> &str {
        &self.inner.admin_listen
    }

    pub fn admin_allow_public(&self) -> bool {
        self.inner.admin_allow_public
    }

    pub fn data_dir(&self) -> &Path {
        &self.inner.data_dir
    }

    pub fn log(&self, event: QueryEvent) {
        if self.inner.log_tx.try_send(event).is_err() {
            tracing::warn!("query log channel full; dropping event");
        }
    }

    fn spawn_log_writer(&self, mut rx: mpsc::Receiver<QueryEvent>) {
        let app = self.clone();
        tokio::spawn(async move {
            let mut buf = Vec::new();
            let mut tick = tokio::time::interval(Duration::from_millis(250));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = tick.tick() => flush(&app, &mut buf).await,
                    ev = rx.recv() => {
                        match ev {
                            Some(ev) => {
                                buf.push(ev);
                                if buf.len() >= 40 {
                                    flush(&app, &mut buf).await;
                                }
                            }
                            None => {
                                flush(&app, &mut buf).await;
                                break;
                            }
                        }
                    }
                }
            }
        });
    }

    fn spawn_maintenance(&self) {
        let app = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(2));
            loop {
                tick.tick().await;
                if let Err(e) = app.reload() {
                    tracing::warn!(error = %e, "policy reload failed");
                }
            }
        });
        let app = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(3600));
            loop {
                tick.tick().await;
                let days = app.snapshot().settings.query_log_retention_days;
                if let Err(e) = app.store().prune(days) {
                    tracing::warn!(error = %e, "prune failed");
                }
            }
        });
    }
}

async fn flush(app: &App, buf: &mut Vec<QueryEvent>) {
    if buf.is_empty() {
        return;
    }
    let batch = std::mem::take(buf);
    let app = app.clone();
    match tokio::task::spawn_blocking(move || app.store().insert_queries(&batch)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::warn!(error = %e, "query log write failed"),
        Err(e) => tracing::warn!(error = %e, "query log task failed"),
    }
}
