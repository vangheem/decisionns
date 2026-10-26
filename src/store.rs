use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use crate::decision::{self, default_block_choices};
use crate::model::{
    now_ms, valid_action, valid_kind, valid_profile, valid_rule_profile, CompiledList, CompiledRule,
    Device, DevicePatch, DomainEntry, FailMode, Overview, QueryEvent, QueryFilter, QueryRow, Rule,
    RuleInput, SeriesPoint, Service, ServiceInput, Settings, Snapshot, DeviceStat, NameCount,
};
use crate::names::{self, Pattern};

pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.migrate()?;
        Ok(store)
    }

    fn with<T>(&self, f: impl FnOnce(&Connection) -> anyhow::Result<T>) -> anyhow::Result<T> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        f(&conn)
    }

    fn migrate(&self) -> anyhow::Result<()> {
        self.with(|conn| {
            conn.execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY,
                    ip TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    profile TEXT NOT NULL DEFAULT 'standard',
                    notes TEXT NOT NULL DEFAULT '',
                    first_seen INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS services (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    base_url TEXT NOT NULL,
                    api_key TEXT NOT NULL DEFAULT '',
                    model TEXT NOT NULL,
                    timeout_ms INTEGER NOT NULL DEFAULT 1200,
                    enabled INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS rules (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    priority INTEGER NOT NULL DEFAULT 100,
                    profile TEXT NOT NULL DEFAULT 'any',
                    device_ip TEXT NOT NULL DEFAULT '',
                    domain_pattern TEXT NOT NULL DEFAULT '*',
                    action TEXT NOT NULL,
                    service_id INTEGER,
                    questions_json TEXT NOT NULL DEFAULT '{}',
                    noul_question TEXT NOT NULL DEFAULT '',
                    noul_threshold REAL NOT NULL DEFAULT 0.8,
                    score_question TEXT NOT NULL DEFAULT '',
                    score_threshold REAL NOT NULL DEFAULT 2,
                    block_choices_json TEXT NOT NULL DEFAULT '{}',
                    min_confidence REAL NOT NULL DEFAULT 0.55,
                    on_uncertain TEXT NOT NULL DEFAULT 'allow',
                    on_error TEXT NOT NULL DEFAULT 'allow',
                    hour_start INTEGER,
                    hour_end INTEGER,
                    days_mask INTEGER NOT NULL DEFAULT 0,
                    comment TEXT NOT NULL DEFAULT '',
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS domains (
                    id INTEGER PRIMARY KEY,
                    kind TEXT NOT NULL,
                    pattern TEXT NOT NULL,
                    comment TEXT NOT NULL DEFAULT '',
                    created_at INTEGER NOT NULL,
                    UNIQUE(kind, pattern)
                );
                CREATE TABLE IF NOT EXISTS query_log (
                    id INTEGER PRIMARY KEY,
                    ts INTEGER NOT NULL,
                    device_ip TEXT NOT NULL,
                    qname TEXT NOT NULL,
                    qtype TEXT NOT NULL,
                    action TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    rule_id INTEGER,
                    decision_json TEXT,
                    latency_ms INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_query_log_ts ON query_log(ts);
                CREATE INDEX IF NOT EXISTS idx_query_log_action ON query_log(action, ts);
                CREATE TABLE IF NOT EXISTS stats_hourly (
                    hour INTEGER NOT NULL,
                    device_ip TEXT NOT NULL,
                    queries INTEGER NOT NULL DEFAULT 0,
                    allowed INTEGER NOT NULL DEFAULT 0,
                    blocked INTEGER NOT NULL DEFAULT 0,
                    errors INTEGER NOT NULL DEFAULT 0,
                    decided INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (hour, device_ip)
                );
                CREATE TABLE IF NOT EXISTS settings (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    json TEXT NOT NULL
                );
                "#,
            )?;
            Ok(())
        })
    }

    pub fn bootstrap(
        &self,
        username: &str,
        password: Option<&str>,
        reset_password: bool,
        seed_upstreams: &[String],
        dns_allow_public: bool,
    ) -> anyhow::Result<Option<String>> {
        self.with(|conn| {
            let generated = bootstrap_user(conn, username, password, reset_password)?;
            seed_settings(conn, seed_upstreams, dns_allow_public)?;
            seed_services_and_rules(conn)?;
            Ok(generated)
        })
    }

    pub fn verify_login(&self, username: &str, password: &str) -> anyhow::Result<Option<i64>> {
        self.with(|conn| {
            let row: Option<(i64, String)> = conn
                .query_row(
                    "SELECT id, password_hash FROM users WHERE username = ?1",
                    [username],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((id, hash)) = row else {
                return Ok(None);
            };
            Ok(verify_password(password, &hash).then_some(id))
        })
    }

    pub fn set_password(&self, user_id: i64, password: &str) -> anyhow::Result<()> {
        if password.len() < 8 {
            anyhow::bail!("password must be at least 8 characters");
        }
        let hash = hash_password(password)?;
        self.with(|conn| {
            conn.execute(
                "UPDATE users SET password_hash = ?1 WHERE id = ?2",
                params![hash, user_id],
            )?;
            conn.execute("DELETE FROM sessions WHERE user_id = ?1", [user_id])?;
            Ok(())
        })
    }

    pub fn create_session(&self, user_id: i64) -> anyhow::Result<String> {
        let token = random_token();
        let token_hash = token_hash(&token);
        let expires = now_ms() + 14 * 24 * 60 * 60 * 1000;
        self.with(|conn| {
            conn.execute(
                "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?1, ?2, ?3)",
                params![token_hash, user_id, expires],
            )?;
            Ok(token)
        })
    }

    pub fn user_for_session(&self, token: &str) -> anyhow::Result<Option<(i64, String)>> {
        let token_hash = token_hash(token);
        let now = now_ms();
        self.with(|conn| {
            let row = conn
                .query_row(
                    "SELECT u.id, u.username FROM sessions s JOIN users u ON u.id = s.user_id
                     WHERE s.token_hash = ?1 AND s.expires_at > ?2",
                    params![token_hash, now],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            Ok(row)
        })
    }

    pub fn delete_session(&self, token: &str) -> anyhow::Result<()> {
        let token_hash = token_hash(token);
        self.with(|conn| {
            conn.execute("DELETE FROM sessions WHERE token_hash = ?1", [token_hash])?;
            Ok(())
        })
    }

    pub fn load_snapshot(&self) -> anyhow::Result<Snapshot> {
        self.with(|conn| {
            let settings = load_settings(conn)?;
            let devices = list_devices(conn)?;
            let services = list_services(conn, true)?;
            let rules = list_rules(conn)?;
            let domains = list_domains(conn, None)?;
            let mut allowlist = Vec::new();
            let mut blocklist = Vec::new();
            let mut warnings = Vec::new();
            for entry in domains {
                match names::parse_pattern(&entry.pattern) {
                    Ok(compiled) => {
                        let item = CompiledList {
                            id: entry.id,
                            kind: entry.kind.clone(),
                            pattern: entry.pattern,
                            compiled,
                            comment: entry.comment,
                        };
                        if item.kind == "allow" {
                            allowlist.push(item);
                        } else {
                            blocklist.push(item);
                        }
                    }
                    Err(err) => warnings.push(format!("list pattern `{}`: {err}", entry.pattern)),
                }
            }
            let mut compiled_rules = Vec::new();
            for rule in rules {
                match names::parse_pattern(&rule.domain_pattern) {
                    Ok(pattern) => {
                        if rule.enabled && rule.action == "decide" {
                            let ready = rule
                                .service_id
                                .and_then(|id| services.iter().find(|s| s.id == id))
                                .is_some_and(|s| s.enabled);
                            if !ready {
                                warnings.push(format!(
                                    "rule \"{}\" decides lookups, but its decision service is missing or disabled",
                                    rule.name
                                ));
                            }
                        }
                        compiled_rules.push(CompiledRule { rule, pattern });
                    }
                    Err(err) => warnings.push(format!("rule pattern: {err}")),
                }
            }
            compiled_rules.sort_by_key(|r| r.rule.priority);
            if settings.upstream_servers.is_empty() {
                warnings.push("no upstream DNS servers configured".into());
            }
            Ok(Snapshot {
                settings,
                devices,
                services,
                rules: compiled_rules,
                allowlist,
                blocklist,
                warnings,
            })
        })
    }

    pub fn list_devices(&self) -> anyhow::Result<Vec<Device>> {
        self.with(list_devices)
    }

    pub fn update_device(&self, id: i64, patch: &DevicePatch) -> anyhow::Result<Device> {
        validate_device(patch)?;
        self.with(|conn| {
            let n = conn.execute(
                "UPDATE devices SET name = ?1, profile = ?2, notes = ?3 WHERE id = ?4",
                params![patch.name.trim(), patch.profile, patch.notes, id],
            )?;
            if n == 0 {
                anyhow::bail!("device not found");
            }
            conn.query_row(
                "SELECT id, ip, name, profile, notes, first_seen, last_seen FROM devices WHERE id = ?1",
                [id],
                map_device,
            )
            .map_err(anyhow::Error::from)
        })
    }

    pub fn delete_device(&self, id: i64) -> anyhow::Result<()> {
        self.with(|conn| {
            conn.execute("DELETE FROM devices WHERE id = ?1", [id])?;
            Ok(())
        })
    }

    pub fn list_rules(&self) -> anyhow::Result<Vec<Rule>> {
        self.with(list_rules)
    }

    pub fn create_rule(&self, input: &RuleInput) -> anyhow::Result<Rule> {
        validate_rule(input)?;
        self.with(|conn| {
            exec(
                conn,
                "INSERT INTO rules (
                    name, enabled, priority, profile, device_ip, domain_pattern, action, service_id,
                    questions_json, noul_question, noul_threshold, score_question, score_threshold,
                    block_choices_json, min_confidence, on_uncertain, on_error, hour_start, hour_end,
                    days_mask, comment, created_at
                ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22)",
                rule_params(input, now_ms()),
            )?;
            let id = conn.last_insert_rowid();
            get_rule(conn, id)
        })
    }

    pub fn update_rule(&self, id: i64, input: &RuleInput) -> anyhow::Result<Rule> {
        validate_rule(input)?;
        self.with(|conn| {
            let n = exec(
                conn,
                "UPDATE rules SET
                    name=?1, enabled=?2, priority=?3, profile=?4, device_ip=?5, domain_pattern=?6,
                    action=?7, service_id=?8, questions_json=?9, noul_question=?10, noul_threshold=?11,
                    score_question=?12, score_threshold=?13, block_choices_json=?14, min_confidence=?15,
                    on_uncertain=?16, on_error=?17, hour_start=?18, hour_end=?19, days_mask=?20, comment=?21
                 WHERE id=?22",
                rule_update_params(input, id),
            )?;
            if n == 0 {
                anyhow::bail!("rule not found");
            }
            get_rule(conn, id)
        })
    }

    pub fn delete_rule(&self, id: i64) -> anyhow::Result<()> {
        self.with(|conn| {
            conn.execute("DELETE FROM rules WHERE id = ?1", [id])?;
            Ok(())
        })
    }

    pub fn list_services(&self) -> anyhow::Result<Vec<Service>> {
        self.with(|conn| list_services(conn, false))
    }

    pub fn create_service(&self, input: &ServiceInput) -> anyhow::Result<Service> {
        validate_service(input)?;
        let key = input.api_key.clone().unwrap_or_default();
        self.with(|conn| {
            conn.execute(
                "INSERT INTO services (name, kind, base_url, api_key, model, timeout_ms, enabled, created_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    input.name.trim(),
                    input.kind,
                    input.base_url.trim().trim_end_matches('/'),
                    key,
                    input.model.trim(),
                    input.timeout_ms as i64,
                    input.enabled as i64,
                    now_ms()
                ],
            )?;
            get_service(conn, conn.last_insert_rowid(), false)
        })
    }

    pub fn update_service(&self, id: i64, input: &ServiceInput) -> anyhow::Result<Service> {
        validate_service(input)?;
        self.with(|conn| {
            let existing: Option<String> = conn
                .query_row("SELECT api_key FROM services WHERE id = ?1", [id], |r| r.get(0))
                .optional()?;
            let Some(existing) = existing else {
                anyhow::bail!("service not found");
            };
            let key = match &input.api_key {
                Some(value) => value.clone(),
                None => existing,
            };
            conn.execute(
                "UPDATE services SET name=?1, kind=?2, base_url=?3, api_key=?4, model=?5, timeout_ms=?6, enabled=?7 WHERE id=?8",
                params![
                    input.name.trim(),
                    input.kind,
                    input.base_url.trim().trim_end_matches('/'),
                    key,
                    input.model.trim(),
                    input.timeout_ms as i64,
                    input.enabled as i64,
                    id
                ],
            )?;
            get_service(conn, id, false)
        })
    }

    pub fn delete_service(&self, id: i64) -> anyhow::Result<()> {
        self.with(|conn| {
            let used: i64 = conn.query_row(
                "SELECT COUNT(*) FROM rules WHERE service_id = ?1",
                [id],
                |r| r.get(0),
            )?;
            if used > 0 {
                anyhow::bail!("service is still used by {used} rule(s)");
            }
            let n = conn.execute("DELETE FROM services WHERE id = ?1", [id])?;
            if n == 0 {
                anyhow::bail!("service not found");
            }
            Ok(())
        })
    }

    pub fn service_with_secret(&self, id: i64) -> anyhow::Result<Service> {
        self.with(|conn| get_service(conn, id, true))
    }

    pub fn list_domains(&self, kind: Option<&str>) -> anyhow::Result<Vec<DomainEntry>> {
        self.with(|conn| list_domains(conn, kind))
    }

    pub fn add_domain(&self, kind: &str, pattern: &str, comment: &str) -> anyhow::Result<DomainEntry> {
        validate_list(kind, pattern)?;
        self.with(|conn| {
            conn.execute(
                "INSERT INTO domains (kind, pattern, comment, created_at) VALUES (?1, ?2, ?3, ?4)",
                params![kind, pattern.trim().to_ascii_lowercase(), comment, now_ms()],
            )?;
            let id = conn.last_insert_rowid();
            conn.query_row(
                "SELECT id, kind, pattern, comment, created_at FROM domains WHERE id = ?1",
                [id],
                map_domain,
            )
            .map_err(Into::into)
        })
    }

    pub fn delete_domain(&self, id: i64) -> anyhow::Result<()> {
        self.with(|conn| {
            conn.execute("DELETE FROM domains WHERE id = ?1", [id])?;
            Ok(())
        })
    }

    pub fn import_domains(&self, kind: &str, text: &str) -> anyhow::Result<usize> {
        if kind != "block" && kind != "allow" {
            anyhow::bail!("kind must be block or allow");
        }
        let patterns = parse_import(text);
        self.with(|conn| {
            let tx = conn.unchecked_transaction()?;
            let mut added = 0;
            for pattern in patterns {
                if validate_list(kind, &pattern).is_err() {
                    continue;
                }
                let n = tx.execute(
                    "INSERT OR IGNORE INTO domains (kind, pattern, comment, created_at) VALUES (?1, ?2, '', ?3)",
                    params![kind, pattern, now_ms()],
                )?;
                added += n;
            }
            tx.commit()?;
            Ok(added)
        })
    }

    pub fn get_settings(&self) -> anyhow::Result<Settings> {
        self.with(load_settings)
    }

    pub fn put_settings(&self, settings: &Settings) -> anyhow::Result<()> {
        validate_settings(settings)?;
        let json = serde_json::to_string(settings)?;
        self.with(|conn| {
            conn.execute(
                "INSERT INTO settings (id, json) VALUES (1, ?1)
                 ON CONFLICT(id) DO UPDATE SET json = excluded.json",
                [json],
            )?;
            Ok(())
        })
    }

    pub fn insert_queries(&self, events: &[QueryEvent]) -> anyhow::Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        self.with(|conn| {
            let tx = conn.unchecked_transaction()?;
            let log = tx
                .prepare("SELECT json FROM settings WHERE id = 1")
                .ok()
                .and_then(|mut stmt| stmt.query_row([], |r| r.get::<_, String>(0)).ok());
            let retention = log
                .as_deref()
                .and_then(|s| serde_json::from_str::<Settings>(s).ok())
                .map(|s| s.query_log_retention_days)
                .unwrap_or(14);
            {
                let mut stats = tx.prepare(
                    "INSERT INTO stats_hourly (hour, device_ip, queries, allowed, blocked, errors, decided)
                     VALUES (?1, ?2, 1, ?3, ?4, ?5, ?6)
                     ON CONFLICT(hour, device_ip) DO UPDATE SET
                       queries = queries + 1,
                       allowed = allowed + excluded.allowed,
                       blocked = blocked + excluded.blocked,
                       errors = errors + excluded.errors,
                       decided = decided + excluded.decided",
                )?;
                let mut log_stmt = tx.prepare(
                    "INSERT INTO query_log (ts, device_ip, qname, qtype, action, reason, rule_id, decision_json, latency_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                )?;
                for ev in events {
                    let hour = ev.ts / 1000 / 3600;
                    let allowed = (ev.action == "allow") as i64;
                    let blocked = (ev.action == "block") as i64;
                    let errors = (ev.action == "error") as i64;
                    let decided = ev.decided as i64;
                    stats.execute(params![hour, ev.device_ip, allowed, blocked, errors, decided])?;
                    if retention > 0 {
                        log_stmt.execute(params![
                            ev.ts,
                            ev.device_ip,
                            ev.qname,
                            ev.qtype,
                            ev.action,
                            ev.reason,
                            ev.rule_id,
                            ev.decision_json,
                            ev.latency_ms
                        ])?;
                    }
                }
            }
            tx.commit()?;
            Ok(())
        })
    }

    pub fn prune(&self, retention_days: i64) -> anyhow::Result<()> {
        let now = now_ms();
        let log_cutoff = now - retention_days.max(0) * 24 * 60 * 60 * 1000;
        let stats_cutoff_hour = (now / 1000 / 3600) - 400 * 24;
        self.with(|conn| {
            if retention_days > 0 {
                conn.execute("DELETE FROM query_log WHERE ts < ?1", [log_cutoff])?;
            }
            conn.execute("DELETE FROM stats_hourly WHERE hour < ?1", [stats_cutoff_hour])?;
            conn.execute("DELETE FROM sessions WHERE expires_at < ?1", [now])?;
            Ok(())
        })
    }

    pub fn overview(&self, range: &str) -> anyhow::Result<Overview> {
        let (since_ms, hours) = match range {
            "24h" => (24, 24),
            "7d" => (24 * 7, 24 * 7),
            "30d" => (24 * 30, 24 * 30),
            _ => anyhow::bail!("range must be 24h, 7d, or 30d"),
        };
        let now = now_ms();
        let since = now - since_ms * 60 * 60 * 1000;
        let since_hour = since / 1000 / 3600;
        self.with(|conn| {
            let mut series = Vec::new();
            let mut stmt = conn.prepare(
                "SELECT hour, SUM(queries), SUM(allowed), SUM(blocked), SUM(errors)
                 FROM stats_hourly WHERE hour >= ?1 GROUP BY hour ORDER BY hour",
            )?;
            let rows = stmt.query_map([since_hour], |r| {
                Ok(SeriesPoint {
                    bucket: r.get(0)?,
                    queries: r.get(1)?,
                    allowed: r.get(2)?,
                    blocked: r.get(3)?,
                    errors: r.get(4)?,
                })
            })?;
            for row in rows {
                series.push(row?);
            }
            let series = if hours > 48 {
                bucket_days(series)
            } else {
                series
            };
            let totals = series.iter().fold(
                SeriesPoint {
                    bucket: since_hour,
                    queries: 0,
                    allowed: 0,
                    blocked: 0,
                    errors: 0,
                },
                |mut acc, p| {
                    acc.queries += p.queries;
                    acc.allowed += p.allowed;
                    acc.blocked += p.blocked;
                    acc.errors += p.errors;
                    acc
                },
            );
            let devices_known = list_devices(conn)?;
            let mut device_stats = Vec::new();
            let mut dstmt = conn.prepare(
                "SELECT device_ip, SUM(queries), SUM(allowed), SUM(blocked), SUM(errors)
                 FROM stats_hourly WHERE hour >= ?1 GROUP BY device_ip ORDER BY SUM(queries) DESC",
            )?;
            let drows = dstmt.query_map([since_hour], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                ))
            })?;
            for row in drows {
                let (ip, queries, allowed, blocked, errors) = row?;
                let known = devices_known.iter().find(|d| d.ip == ip);
                device_stats.push(DeviceStat {
                    name: known.map(|d| d.name.clone()).unwrap_or_else(|| ip.clone()),
                    profile: known.map(|d| d.profile.clone()).unwrap_or_else(|| "standard".into()),
                    ip,
                    queries,
                    allowed,
                    blocked,
                    errors,
                });
            }
            let mut top_blocked = Vec::new();
            let mut tstmt = conn.prepare(
                "SELECT qname, COUNT(*) FROM query_log
                 WHERE action = 'block' AND ts >= ?1
                 GROUP BY qname ORDER BY COUNT(*) DESC LIMIT 12",
            )?;
            let trows = tstmt.query_map([since], |r| {
                Ok(NameCount {
                    qname: r.get(0)?,
                    count: r.get(1)?,
                })
            })?;
            for row in trows {
                top_blocked.push(row?);
            }
            let recent_blocks = query_rows(
                conn,
                &QueryFilter {
                    limit: 8,
                    offset: 0,
                    device: None,
                    action: Some("block".into()),
                    q: None,
                },
            )?;
            Ok(Overview {
                range: range.into(),
                since,
                totals,
                series,
                devices: device_stats,
                top_blocked,
                recent_blocks,
            })
        })
    }

    pub fn queries(&self, filter: &QueryFilter) -> anyhow::Result<Vec<QueryRow>> {
        self.with(|conn| query_rows(conn, filter))
    }
}

fn bucket_days(points: Vec<SeriesPoint>) -> Vec<SeriesPoint> {
    let mut out: Vec<SeriesPoint> = Vec::new();
    for point in points {
        let day = point.bucket / 24;
        if let Some(last) = out.last_mut() {
            if last.bucket == day {
                last.queries += point.queries;
                last.allowed += point.allowed;
                last.blocked += point.blocked;
                last.errors += point.errors;
                continue;
            }
        }
        out.push(SeriesPoint {
            bucket: day,
            queries: point.queries,
            allowed: point.allowed,
            blocked: point.blocked,
            errors: point.errors,
        });
    }
    out
}

fn bootstrap_user(
    conn: &Connection,
    username: &str,
    password: Option<&str>,
    reset_password: bool,
) -> anyhow::Result<Option<String>> {
    let existing: Option<i64> = conn
        .query_row("SELECT id FROM users WHERE username = ?1", [username], |r| r.get(0))
        .optional()?;
    if let Some(id) = existing {
        if reset_password {
            let (password, generated) = password_or_generated(password);
            let hash = hash_password(&password)?;
            conn.execute(
                "UPDATE users SET password_hash = ?1 WHERE id = ?2",
                params![hash, id],
            )?;
            conn.execute("DELETE FROM sessions WHERE user_id = ?1", [id])?;
            return Ok(generated.then_some(password));
        }
        return Ok(None);
    }
    let (password, generated) = password_or_generated(password);
    let hash = hash_password(&password)?;
    conn.execute(
        "INSERT INTO users (username, password_hash, created_at) VALUES (?1, ?2, ?3)",
        params![username, hash, now_ms()],
    )?;
    Ok(generated.then_some(password))
}

fn password_or_generated(password: Option<&str>) -> (String, bool) {
    match password {
        Some(p) if !p.is_empty() => (p.to_string(), false),
        _ => (random_password(), true),
    }
}

fn seed_settings(conn: &Connection, upstreams: &[String], dns_allow_public: bool) -> anyhow::Result<()> {
    let exists: i64 = conn.query_row("SELECT COUNT(*) FROM settings", [], |r| r.get(0))?;
    if exists > 0 {
        return Ok(());
    }
    let mut settings = Settings::default();
    if !upstreams.is_empty() {
        settings.upstream_servers = upstreams.to_vec();
    }
    settings.dns_allow_public = dns_allow_public;
    let json = serde_json::to_string(&settings)?;
    conn.execute("INSERT INTO settings (id, json) VALUES (1, ?1)", [json])?;
    Ok(())
}

fn seed_services_and_rules(conn: &Connection) -> anyhow::Result<()> {
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM services", [], |r| r.get(0))?;
    if count > 0 {
        return Ok(());
    }
    let now = now_ms();
    conn.execute(
        "INSERT INTO services (name, kind, base_url, api_key, model, timeout_ms, enabled, created_at)
         VALUES ('Jev', 'jev', 'https://api.typesafe.ai', '', 'jev-latest', 1500, 0, ?1)",
        [now],
    )?;
    let jev_id = conn.last_insert_rowid();
    conn.execute(
        "INSERT INTO services (name, kind, base_url, api_key, model, timeout_ms, enabled, created_at)
         VALUES ('Clef', 'clef', 'http://127.0.0.1:8000', '', 'clef', 2000, 0, ?1)",
        [now],
    )?;
    let questions = decision::child_safety_questions().to_string();
    let choices = default_block_choices().to_string();
    conn.execute(
        "INSERT INTO rules (
            name, enabled, priority, profile, device_ip, domain_pattern, action, service_id,
            questions_json, noul_question, noul_threshold, score_question, score_threshold,
            block_choices_json, min_confidence, on_uncertain, on_error, hour_start, hour_end,
            days_mask, comment, created_at
        ) VALUES (
            'Child safety', 1, 50, 'child', '', '*', 'decide', ?1,
            ?2, 'unsafe_for_children', 0.8, '', 2,
            ?3, 0.55, 'allow', 'allow', NULL, NULL,
            0, 'Blocks child-profile lookups the decision model marks unsafe. Enable a service and paste an API key before this does anything.', ?4
        )",
        params![jev_id, questions, choices, now],
    )?;
    let malware_q = decision::malware_questions().to_string();
    let malware_choices = serde_json::json!({"category": ["phishing", "malware", "scam"]}).to_string();
    conn.execute(
        "INSERT INTO rules (
            name, enabled, priority, profile, device_ip, domain_pattern, action, service_id,
            questions_json, noul_question, noul_threshold, score_question, score_threshold,
            block_choices_json, min_confidence, on_uncertain, on_error, hour_start, hour_end,
            days_mask, comment, created_at
        ) VALUES (
            'House malware screen', 0, 200, 'any', '', '*', 'decide', ?1,
            ?2, 'malicious', 0.85, '', 2,
            ?3, 0.6, 'allow', 'allow', NULL, NULL,
            0, 'Optional whole-house screen for phishing and malware names. Disabled until you turn it on.', ?4
        )",
        params![jev_id, malware_q, malware_choices, now],
    )?;
    Ok(())
}

fn load_settings(conn: &Connection) -> anyhow::Result<Settings> {
    let json: Option<String> = conn
        .query_row("SELECT json FROM settings WHERE id = 1", [], |r| r.get(0))
        .optional()?;
    match json {
        Some(json) => Ok(serde_json::from_str(&json).unwrap_or_default()),
        None => Ok(Settings::default()),
    }
}

fn list_devices(conn: &Connection) -> anyhow::Result<Vec<Device>> {
    let mut stmt = conn.prepare(
        "SELECT id, ip, name, profile, notes, first_seen, last_seen FROM devices ORDER BY last_seen DESC",
    )?;
    let rows = stmt.query_map([], map_device)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

fn map_device(r: &rusqlite::Row<'_>) -> rusqlite::Result<Device> {
    Ok(Device {
        id: r.get(0)?,
        ip: r.get(1)?,
        name: r.get(2)?,
        profile: r.get(3)?,
        notes: r.get(4)?,
        first_seen: r.get(5)?,
        last_seen: r.get(6)?,
    })
}

fn list_services(conn: &Connection, include_secret: bool) -> anyhow::Result<Vec<Service>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, kind, base_url, api_key, model, timeout_ms, enabled FROM services ORDER BY id",
    )?;
    let rows = stmt.query_map([], |r| map_service(r, include_secret))?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

fn get_service(conn: &Connection, id: i64, include_secret: bool) -> anyhow::Result<Service> {
    conn.query_row(
        "SELECT id, name, kind, base_url, api_key, model, timeout_ms, enabled FROM services WHERE id = ?1",
        [id],
        |r| map_service(r, include_secret),
    )
    .map_err(|_| anyhow::anyhow!("service not found"))
}

fn map_service(r: &rusqlite::Row<'_>, include_secret: bool) -> rusqlite::Result<Service> {
    let api_key: String = r.get(4)?;
    let hint = key_hint(&api_key);
    Ok(Service {
        id: r.get(0)?,
        name: r.get(1)?,
        kind: r.get(2)?,
        base_url: r.get(3)?,
        model: r.get(5)?,
        timeout_ms: r.get::<_, i64>(6)? as u64,
        enabled: r.get::<_, i64>(7)? != 0,
        has_api_key: !api_key.is_empty(),
        key_hint: hint,
        api_key: if include_secret { api_key } else { String::new() },
    })
}

fn key_hint(key: &str) -> String {
    if key.is_empty() {
        return String::new();
    }
    if key.len() <= 4 {
        return "••••".into();
    }
    format!("••••{}", &key[key.len() - 4..])
}

fn list_rules(conn: &Connection) -> anyhow::Result<Vec<Rule>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, enabled, priority, profile, device_ip, domain_pattern, action, service_id,
                questions_json, noul_question, noul_threshold, score_question, score_threshold,
                block_choices_json, min_confidence, on_uncertain, on_error, hour_start, hour_end,
                days_mask, comment
         FROM rules ORDER BY priority, id",
    )?;
    let rows = stmt.query_map([], map_rule)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

fn get_rule(conn: &Connection, id: i64) -> anyhow::Result<Rule> {
    conn.query_row(
        "SELECT id, name, enabled, priority, profile, device_ip, domain_pattern, action, service_id,
                questions_json, noul_question, noul_threshold, score_question, score_threshold,
                block_choices_json, min_confidence, on_uncertain, on_error, hour_start, hour_end,
                days_mask, comment
         FROM rules WHERE id = ?1",
        [id],
        map_rule,
    )
    .map_err(|_| anyhow::anyhow!("rule not found"))
}

fn map_rule(r: &rusqlite::Row<'_>) -> rusqlite::Result<Rule> {
    let questions: String = r.get(9)?;
    let choices: String = r.get(14)?;
    let on_uncertain: String = r.get(16)?;
    let on_error: String = r.get(17)?;
    Ok(Rule {
        id: r.get(0)?,
        name: r.get(1)?,
        enabled: r.get::<_, i64>(2)? != 0,
        priority: r.get(3)?,
        profile: r.get(4)?,
        device_ip: r.get(5)?,
        domain_pattern: r.get(6)?,
        action: r.get(7)?,
        service_id: r.get(8)?,
        questions: serde_json::from_str(&questions).unwrap_or(serde_json::json!({})),
        noul_question: r.get(10)?,
        noul_threshold: r.get(11)?,
        score_question: r.get(12)?,
        score_threshold: r.get(13)?,
        block_choices: serde_json::from_str(&choices).unwrap_or(serde_json::json!({})),
        min_confidence: r.get(15)?,
        on_uncertain: FailMode::parse(&on_uncertain).unwrap_or(FailMode::Allow),
        on_error: FailMode::parse(&on_error).unwrap_or(FailMode::Allow),
        hour_start: r.get::<_, Option<i64>>(18)?.map(|v| v as u8),
        hour_end: r.get::<_, Option<i64>>(19)?.map(|v| v as u8),
        days_mask: r.get::<_, i64>(20)? as u8,
        comment: r.get(21)?,
    })
}

fn exec(
    conn: &Connection,
    sql: &str,
    params: Vec<Box<dyn rusqlite::types::ToSql>>,
) -> anyhow::Result<usize> {
    let refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();
    conn.execute(sql, rusqlite::params_from_iter(refs))
        .map_err(Into::into)
}

fn rule_params(input: &RuleInput, created_at: i64) -> Vec<Box<dyn rusqlite::types::ToSql>> {
    let mut params = rule_fields(input);
    params.push(Box::new(created_at));
    params
}

fn rule_update_params(input: &RuleInput, id: i64) -> Vec<Box<dyn rusqlite::types::ToSql>> {
    let mut params = rule_fields(input);
    params.push(Box::new(id));
    params
}

fn rule_fields(input: &RuleInput) -> Vec<Box<dyn rusqlite::types::ToSql>> {
    vec![
        Box::new(input.name.trim().to_string()),
        Box::new(input.enabled as i64),
        Box::new(input.priority),
        Box::new(input.profile.clone()),
        Box::new(input.device_ip.trim().to_string()),
        Box::new(input.domain_pattern.trim().to_string()),
        Box::new(input.action.clone()),
        Box::new(input.service_id),
        Box::new(input.questions.to_string()),
        Box::new(input.noul_question.clone()),
        Box::new(input.noul_threshold),
        Box::new(input.score_question.clone()),
        Box::new(input.score_threshold),
        Box::new(input.block_choices.to_string()),
        Box::new(input.min_confidence),
        Box::new(input.on_uncertain.as_str().to_string()),
        Box::new(input.on_error.as_str().to_string()),
        Box::new(input.hour_start.map(|v| v as i64)),
        Box::new(input.hour_end.map(|v| v as i64)),
        Box::new(input.days_mask as i64),
        Box::new(input.comment.clone()),
    ]
}

fn list_domains(conn: &Connection, kind: Option<&str>) -> anyhow::Result<Vec<DomainEntry>> {
    if let Some(kind) = kind {
        let mut stmt = conn.prepare(
            "SELECT id, kind, pattern, comment, created_at FROM domains WHERE kind = ?1 ORDER BY pattern",
        )?;
        let rows = stmt.query_map([kind], map_domain)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    } else {
        let mut stmt = conn.prepare(
            "SELECT id, kind, pattern, comment, created_at FROM domains ORDER BY kind, pattern",
        )?;
        let rows = stmt.query_map([], map_domain)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }
}

fn map_domain(r: &rusqlite::Row<'_>) -> rusqlite::Result<DomainEntry> {
    Ok(DomainEntry {
        id: r.get(0)?,
        kind: r.get(1)?,
        pattern: r.get(2)?,
        comment: r.get(3)?,
        created_at: r.get(4)?,
    })
}

fn query_rows(conn: &Connection, filter: &QueryFilter) -> anyhow::Result<Vec<QueryRow>> {
    let limit = filter.limit.clamp(1, 500);
    let mut sql = String::from(
        "SELECT id, ts, device_ip, qname, qtype, action, reason, rule_id, latency_ms FROM query_log WHERE 1=1",
    );
    let mut values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
    if let Some(device) = &filter.device {
        if !device.is_empty() {
            sql.push_str(&format!(" AND device_ip = ?{}", values.len() + 1));
            values.push(Box::new(device.clone()));
        }
    }
    if let Some(action) = &filter.action {
        if !action.is_empty() {
            sql.push_str(&format!(" AND action = ?{}", values.len() + 1));
            values.push(Box::new(action.clone()));
        }
    }
    if let Some(q) = &filter.q {
        if !q.is_empty() {
            sql.push_str(&format!(" AND qname LIKE ?{} ESCAPE '\\'", values.len() + 1));
            values.push(Box::new(like_pattern(q)));
        }
    }
    sql.push_str(&format!(
        " ORDER BY ts DESC LIMIT {} OFFSET {}",
        limit, filter.offset.max(0)
    ));
    let mut stmt = conn.prepare(&sql)?;
    let params = rusqlite::params_from_iter(values.iter());
    let rows = stmt.query_map(params, |r| {
        Ok(QueryRow {
            id: r.get(0)?,
            ts: r.get(1)?,
            device_ip: r.get(2)?,
            qname: r.get(3)?,
            qtype: r.get(4)?,
            action: r.get(5)?,
            reason: r.get(6)?,
            rule_id: r.get(7)?,
            latency_ms: r.get(8)?,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

fn like_pattern(q: &str) -> String {
    let escaped = q.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_");
    format!("%{escaped}%")
}

fn parse_import(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }
        let token = line.split_whitespace().next_back().unwrap_or(line);
        let token = token.trim_start_matches("||").trim_end_matches('^');
        if token.contains('/') || token.contains(':') {
            continue;
        }
        let pattern = token.trim_end_matches('.').to_ascii_lowercase();
        if pattern.is_empty() || pattern == "0.0.0.0" || pattern == "127.0.0.1" || pattern == "::" {
            continue;
        }
        out.push(pattern);
    }
    out
}

fn validate_device(patch: &DevicePatch) -> anyhow::Result<()> {
    if patch.name.trim().is_empty() || patch.name.len() > 80 {
        anyhow::bail!("name must be 1-80 characters");
    }
    if !valid_profile(&patch.profile) {
        anyhow::bail!("profile must be unrestricted, standard, or child");
    }
    if patch.notes.len() > 500 {
        anyhow::bail!("notes are too long");
    }
    Ok(())
}

fn validate_service(input: &ServiceInput) -> anyhow::Result<()> {
    if input.name.trim().is_empty() || input.name.len() > 80 {
        anyhow::bail!("name must be 1-80 characters");
    }
    if !valid_kind(&input.kind) {
        anyhow::bail!("kind must be jev, clef, or custom");
    }
    let url = input.base_url.trim();
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        anyhow::bail!("base_url must start with http:// or https://");
    }
    if input.model.trim().is_empty() {
        anyhow::bail!("model is required");
    }
    if !(100..=30_000).contains(&input.timeout_ms) {
        anyhow::bail!("timeout_ms must be between 100 and 30000");
    }
    Ok(())
}

fn validate_rule(input: &RuleInput) -> anyhow::Result<()> {
    if input.name.trim().is_empty() || input.name.len() > 80 {
        anyhow::bail!("name must be 1-80 characters");
    }
    if !(0..=10_000).contains(&input.priority) {
        anyhow::bail!("priority must be 0-10000");
    }
    if !valid_rule_profile(&input.profile) {
        anyhow::bail!("profile must be any, unrestricted, standard, or child");
    }
    if !input.device_ip.is_empty() && input.device_ip.parse::<std::net::IpAddr>().is_err() {
        anyhow::bail!("device_ip is not an IP address");
    }
    if !valid_action(&input.action) {
        anyhow::bail!("action must be allow, block, or decide");
    }
    names::parse_pattern(&input.domain_pattern).map_err(|e| anyhow::anyhow!(e))?;
    if input.action == "decide" {
        if input.service_id.is_none() {
            anyhow::bail!("decide rules need a service_id");
        }
        if !input.questions.is_object() || input.questions.as_object().is_some_and(|o| o.is_empty()) {
            anyhow::bail!("decide rules need a questions object");
        }
    }
    if !(0.0..=1.0).contains(&input.noul_threshold) || !(0.0..=1.0).contains(&input.min_confidence) {
        anyhow::bail!("thresholds must be between 0 and 1");
    }
    if let Some(h) = input.hour_start {
        if h > 23 {
            anyhow::bail!("hour_start must be 0-23");
        }
    }
    if let Some(h) = input.hour_end {
        if h > 23 {
            anyhow::bail!("hour_end must be 0-23");
        }
    }
    if input.days_mask > 0b111_1111 {
        anyhow::bail!("days_mask is invalid");
    }
    let _ = Pattern::Exact(String::new());
    Ok(())
}

fn validate_list(kind: &str, pattern: &str) -> anyhow::Result<()> {
    if kind != "block" && kind != "allow" {
        anyhow::bail!("kind must be block or allow");
    }
    let compiled = names::parse_pattern(pattern).map_err(|e| anyhow::anyhow!(e))?;
    if matches!(compiled, Pattern::Contains(ref s) if s.is_empty()) {
        anyhow::bail!("refusing to add a match-all list pattern");
    }
    Ok(())
}

fn validate_settings(settings: &Settings) -> anyhow::Result<()> {
    if settings.upstream_servers.is_empty() {
        anyhow::bail!("at least one upstream server is required");
    }
    if settings.upstream_servers.len() > 16 {
        anyhow::bail!("too many upstream servers");
    }
    for server in &settings.upstream_servers {
        crate::upstream::parse_upstream(server)?;
    }
    if !(200..=10_000).contains(&settings.upstream_timeout_ms) {
        anyhow::bail!("upstream_timeout_ms must be 200-10000");
    }
    if settings.block_ttl > 86_400 {
        anyhow::bail!("block_ttl must be <= 86400");
    }
    if settings.decision_cache_ttl_secs > 7 * 24 * 3600 {
        anyhow::bail!("decision cache TTL is too large");
    }
    if !(0..=365).contains(&settings.query_log_retention_days) {
        anyhow::bail!("query log retention must be 0-365 days");
    }
    Ok(())
}

fn hash_password(password: &str) -> anyhow::Result<String> {
    use argon2::{
        password_hash::{PasswordHasher, SaltString},
        Argon2,
    };
    let mut salt_bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut salt_bytes);
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|e| anyhow::anyhow!("salt: {e}"))?;
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("hash password: {e}"))?;
    Ok(hash.to_string())
}

fn verify_password(password: &str, hash: &str) -> bool {
    use argon2::{
        password_hash::{PasswordHash, PasswordVerifier},
        Argon2,
    };
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn random_password() -> String {
    const ALPHABET: &[u8] = b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut bytes = [0u8; 20];
    rand::rng().fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|b| ALPHABET[(*b as usize) % ALPHABET.len()] as char)
        .collect()
}

fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

use rand::RngCore;
