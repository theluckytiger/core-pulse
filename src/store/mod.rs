//! SQLite storage.

pub mod insights;
pub mod queries;
mod retention;
pub mod rollup;
pub mod users;

use std::path::Path;

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params};

use crate::clock::DAY;
use crate::config::StorageConfig;
use crate::event::{HttpRequest, SecurityEvent, SystemEvent};

/// Schema migrations in order. A database's `user_version` is the number of
/// migrations already applied to it.
const MIGRATIONS: &[&str] = &[
    include_str!("migrations/0001_init.sql"),
    include_str!("migrations/0002_user_agent_index.sql"),
    include_str!("migrations/0003_auth.sql"),
    include_str!("migrations/0004_details.sql"),
];

/// Where a source stopped reading: a file position or a journal cursor.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceState {
    pub file_id: Option<String>,
    pub position: Option<u64>,
    pub cursor: Option<String>,
}

/// Events from one source, saved together with that source's new read
/// position. One transaction for both means a crash never loses or repeats
/// events.
#[derive(Debug, Default)]
pub struct Batch {
    pub source: String,
    pub http: Vec<HttpRequest>,
    pub security: Vec<SecurityEvent>,
    pub system: Vec<SystemEvent>,
    /// Values that only go into the hourly totals, like bytes sent.
    pub counters: Vec<Counter>,
    pub state: Option<SourceState>,
}

#[derive(Debug, Clone)]
pub struct Counter {
    pub ts: i64,
    pub metric: &'static str,
    pub name: String,
    pub value: i64,
}

#[derive(Debug, Clone, Copy)]
pub struct Retention {
    pub raw_days: u32,
    pub hourly_days: u32,
    pub max_bytes: u64,
}

impl Retention {
    fn raw_cutoff(&self, now: i64) -> i64 {
        now - i64::from(self.raw_days) * DAY
    }

    fn hourly_cutoff(&self, now: i64) -> i64 {
        now - i64::from(self.hourly_days) * DAY
    }
}

impl From<&StorageConfig> for Retention {
    fn from(config: &StorageConfig) -> Self {
        Self {
            raw_days: config.raw_retention_days,
            hourly_days: config.hourly_retention_days,
            max_bytes: config.max_db_size_mb.saturating_mul(1024 * 1024),
        }
    }
}

#[derive(Debug)]
pub struct Status {
    pub bytes: u64,
    pub requests: u64,
    pub security_events: u64,
    pub oldest: Option<i64>,
    pub newest: Option<i64>,
    /// Each source and when it last saved its position.
    pub sources: Vec<(String, i64)>,
}

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("cannot open database {}", path.display()))?;
        let store = Self::init(conn)?;
        restrict_permissions(path)?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        // auto_vacuum only takes effect on a new, empty database.
        conn.execute_batch(
            "PRAGMA auto_vacuum = INCREMENTAL;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;",
        )?;
        let mut store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&mut self) -> Result<()> {
        let applied: i64 = self
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))?;
        let applied = usize::try_from(applied).context("negative schema version")?;
        if applied > MIGRATIONS.len() {
            bail!(
                "database schema v{applied} is newer than this build (v{})",
                MIGRATIONS.len()
            );
        }

        for (index, sql) in MIGRATIONS.iter().enumerate().skip(applied) {
            let version = index + 1;
            let tx = self.conn.transaction()?;
            tx.execute_batch(sql)
                .with_context(|| format!("migration {version} failed"))?;
            tx.execute_batch(&format!("PRAGMA user_version = {version}"))?;
            tx.commit()?;
            tracing::info!("database migrated to schema v{version}");
        }
        Ok(())
    }

    /// Cheap query for the health check.
    pub fn ping(&self) -> Result<()> {
        self.conn.query_row("SELECT 1", [], |_| Ok(()))?;
        Ok(())
    }

    /// Stores a batch: raw events still inside retention, their hourly totals
    /// and the source's read position, all in one transaction.
    pub fn save(&mut self, batch: &Batch, now: i64, retention: &Retention) -> Result<()> {
        let raw_cutoff = retention.raw_cutoff(now);
        let totals = rollup::totals(batch, retention.hourly_cutoff(now));

        let tx = self.conn.transaction()?;
        insert_http(&tx, batch.http.iter().filter(|r| r.ts >= raw_cutoff))?;
        insert_security(&tx, batch.security.iter().filter(|e| e.ts >= raw_cutoff))?;
        insert_system(&tx, batch.system.iter().filter(|e| e.ts >= raw_cutoff))?;
        rollup::save(&tx, &totals)?;
        if let Some(state) = &batch.state {
            tx.execute(
                "INSERT INTO source_state (source, file_id, position, cursor, updated)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (source) DO UPDATE SET file_id = excluded.file_id,
                     position = excluded.position, cursor = excluded.cursor,
                     updated = excluded.updated",
                params![
                    batch.source,
                    state.file_id,
                    state.position.map(|p| i64::try_from(p).unwrap_or(i64::MAX)),
                    state.cursor,
                    now
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Stores one event right away, for things the web server sees itself,
    /// like a sign-in to the dashboard.
    pub fn record(&self, event: &SecurityEvent) -> Result<()> {
        let batch = Batch {
            security: vec![event.clone()],
            ..Batch::default()
        };
        let tx = self.conn.unchecked_transaction()?;
        insert_security(&tx, batch.security.iter())?;
        rollup::save(&tx, &rollup::totals(&batch, i64::MIN))?;
        tx.commit()?;
        Ok(())
    }

    pub fn source_state(&self, source: &str) -> Result<Option<SourceState>> {
        let state = self
            .conn
            .query_row(
                "SELECT file_id, position, cursor FROM source_state WHERE source = ?1",
                [source],
                |row| {
                    Ok(SourceState {
                        file_id: row.get(0)?,
                        position: row.get::<_, Option<i64>>(1)?.map(i64::unsigned_abs),
                        cursor: row.get(2)?,
                    })
                },
            )
            .optional()?;
        Ok(state)
    }

    /// Number of stored HTTP requests and security events.
    pub fn counts(&self) -> Result<(u64, u64)> {
        let count = |table: &str| -> Result<u64> {
            let n: i64 =
                self.conn
                    .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                        row.get(0)
                    })?;
            Ok(n.unsigned_abs())
        };
        Ok((count("http_requests")?, count("security_events")?))
    }

    pub fn status(&self) -> Result<Status> {
        let (requests, security_events) = self.counts()?;
        let (oldest, newest) = self.conn.query_row(
            "SELECT min(ts), max(ts) FROM (
                 SELECT ts FROM http_requests UNION ALL SELECT ts FROM security_events)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let mut stmt = self
            .conn
            .prepare("SELECT source, updated FROM source_state ORDER BY source")?;
        let sources = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        Ok(Status {
            bytes: self.used_bytes()?,
            requests,
            security_events,
            oldest,
            newest,
            sources,
        })
    }
}

fn insert_http<'a>(conn: &Connection, events: impl Iterator<Item = &'a HttpRequest>) -> Result<()> {
    // Returns the id whether the user agent is new or already stored.
    let mut user_agent = conn.prepare_cached(
        "INSERT INTO user_agents (value) VALUES (?1)
         ON CONFLICT (value) DO UPDATE SET value = excluded.value
         RETURNING id",
    )?;
    let mut insert = conn.prepare_cached(
        "INSERT INTO http_requests
             (ts, site, client_ip, peer_ip, method, path, query, status, bytes, ua_id, probe)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
    )?;
    for e in events {
        let ua_id: i64 = user_agent.query_row([&e.user_agent], |row| row.get(0))?;
        insert.execute(params![
            e.ts,
            e.site,
            e.client_ip.to_string(),
            e.peer_ip.to_string(),
            e.method,
            e.path,
            e.query,
            e.status,
            i64::try_from(e.bytes).unwrap_or(i64::MAX),
            ua_id,
            e.probe,
        ])?;
    }
    Ok(())
}

fn insert_security<'a>(
    conn: &Connection,
    events: impl Iterator<Item = &'a SecurityEvent>,
) -> Result<()> {
    let mut insert = conn.prepare_cached(
        "INSERT INTO security_events (ts, kind, source, ip, port, detail)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )?;
    for e in events {
        insert.execute(params![
            e.ts,
            e.kind.as_str(),
            e.source,
            e.ip.to_string(),
            e.port,
            e.detail,
        ])?;
    }
    Ok(())
}

fn insert_system<'a>(
    conn: &Connection,
    events: impl Iterator<Item = &'a SystemEvent>,
) -> Result<()> {
    let mut insert = conn.prepare_cached(
        "INSERT INTO system_events (ts, kind, name, detail) VALUES (?1, ?2, ?3, ?4)",
    )?;
    for e in events {
        insert.execute(params![e.ts, e.kind.as_str(), e.name, e.detail])?;
    }
    Ok(())
}

/// The database holds visitor IPs and login data, so only its owner may read it.
#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("cannot restrict permissions of {}", path.display()))
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::clock::{HOUR, hour_of};
    use crate::event::SecurityKind;

    const NOW: i64 = 1_794_670_407;
    const KEEP_ALL: Retention = Retention {
        raw_days: 90,
        hourly_days: 365,
        max_bytes: u64::MAX,
    };

    pub fn request(ts: i64, user_agent: &str) -> HttpRequest {
        HttpRequest {
            ts,
            site: "example.com".into(),
            client_ip: "192.0.2.1".parse().unwrap(),
            peer_ip: "198.51.100.7".parse().unwrap(),
            method: "GET".into(),
            path: "/".into(),
            query: None,
            status: 200,
            bytes: 512,
            user_agent: user_agent.into(),
            probe: None,
        }
    }

    pub fn security_event(ts: i64) -> SecurityEvent {
        SecurityEvent {
            ts,
            kind: SecurityKind::Ban,
            source: "sshd".into(),
            ip: "203.0.113.9".parse().unwrap(),
            port: None,
            detail: None,
        }
    }

    pub fn batch(http: Vec<HttpRequest>, security: Vec<SecurityEvent>) -> Batch {
        Batch {
            source: "test".into(),
            http,
            security,
            ..Batch::default()
        }
    }

    fn total(store: &Store, metric: &str, name: &str) -> i64 {
        store
            .conn
            .query_row(
                "SELECT coalesce(sum(value), 0) FROM hourly_totals WHERE metric = ?1 AND name = ?2",
                [metric, name],
                |row| row.get(0),
            )
            .unwrap()
    }

    #[test]
    fn migrates_a_fresh_database() {
        let store = Store::open_in_memory().unwrap();
        let version: i64 = store
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, MIGRATIONS.len() as i64);
    }

    #[test]
    fn refuses_a_newer_schema() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA user_version = 99").unwrap();
        assert!(Store::init(conn).is_err());
    }

    #[test]
    fn stores_events_and_dedups_user_agents() {
        let mut store = Store::open_in_memory().unwrap();
        let requests = vec![
            request(NOW, "curl/8.0"),
            request(NOW, "curl/8.0"),
            request(NOW, "Mozilla/5.0"),
        ];
        store
            .save(&batch(requests, vec![security_event(NOW)]), NOW, &KEEP_ALL)
            .unwrap();
        assert_eq!(store.counts().unwrap(), (3, 1));

        let agents: i64 = store
            .conn
            .query_row("SELECT count(*) FROM user_agents", [], |row| row.get(0))
            .unwrap();
        assert_eq!(agents, 2);
    }

    #[test]
    fn adds_up_hourly_totals_across_batches() {
        let mut store = Store::open_in_memory().unwrap();
        let mut probe = request(NOW, "curl");
        probe.status = 444;
        probe.probe = Some("env-file".into());

        store
            .save(
                &batch(vec![request(NOW, "curl"), probe], vec![]),
                NOW,
                &KEEP_ALL,
            )
            .unwrap();
        store
            .save(
                &batch(vec![request(NOW + 1, "curl")], vec![security_event(NOW)]),
                NOW,
                &KEEP_ALL,
            )
            .unwrap();
        store
            .save(
                &batch(vec![request(NOW + HOUR, "curl")], vec![]),
                NOW,
                &KEEP_ALL,
            )
            .unwrap();

        assert_eq!(total(&store, rollup::HTTP_REQUESTS, "example.com"), 4);
        assert_eq!(total(&store, rollup::HTTP_STATUS, "example.com 200"), 3);
        assert_eq!(total(&store, rollup::HTTP_STATUS, "example.com 444"), 1);
        assert_eq!(
            total(&store, rollup::HTTP_PROBES, "example.com env-file"),
            1
        );
        assert_eq!(total(&store, rollup::HTTP_BYTES, "example.com"), 4 * 512);
        assert_eq!(total(&store, rollup::SECURITY, "ban sshd"), 1);

        let hours: i64 = store
            .conn
            .query_row(
                "SELECT count(DISTINCT hour) FROM hourly_totals WHERE metric = 'http.requests'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let expected = if hour_of(NOW) == hour_of(NOW + 1) {
            2
        } else {
            3
        };
        assert_eq!(hours, expected);
    }

    #[test]
    fn old_events_only_count_in_totals() {
        let mut store = Store::open_in_memory().unwrap();
        let old = NOW - 200 * DAY;
        let ancient = NOW - 400 * DAY;
        store
            .save(
                &batch(vec![request(old, "curl"), request(ancient, "curl")], vec![]),
                NOW,
                &KEEP_ALL,
            )
            .unwrap();
        assert_eq!(store.counts().unwrap().0, 0);
        assert_eq!(total(&store, rollup::HTTP_REQUESTS, "example.com"), 1);
    }

    #[test]
    fn saves_source_state_with_the_batch() {
        let mut store = Store::open_in_memory().unwrap();
        assert_eq!(store.source_state("nginx:web").unwrap(), None);

        let state = SourceState {
            file_id: Some("2049:1234".into()),
            position: Some(4096),
            cursor: None,
        };
        let mut b = batch(vec![request(NOW, "curl")], vec![]);
        b.source = "nginx:web".into();
        b.state = Some(state.clone());
        store.save(&b, NOW, &KEEP_ALL).unwrap();
        assert_eq!(store.source_state("nginx:web").unwrap(), Some(state));

        b.state = Some(SourceState {
            cursor: Some("s=abc".into()),
            ..SourceState::default()
        });
        store.save(&b, NOW, &KEEP_ALL).unwrap();
        assert_eq!(
            store
                .source_state("nginx:web")
                .unwrap()
                .unwrap()
                .cursor
                .as_deref(),
            Some("s=abc")
        );
    }

    #[test]
    fn reports_status() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .save(
                &batch(vec![request(NOW - 10, "curl")], vec![security_event(NOW)]),
                NOW,
                &KEEP_ALL,
            )
            .unwrap();
        let status = store.status().unwrap();
        assert_eq!((status.requests, status.security_events), (1, 1));
        assert_eq!((status.oldest, status.newest), (Some(NOW - 10), Some(NOW)));
        assert!(status.bytes > 0);
    }

    #[test]
    fn reopening_keeps_data() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        Store::open(&path)
            .unwrap()
            .save(&batch(vec![request(NOW, "curl")], vec![]), NOW, &KEEP_ALL)
            .unwrap();

        let store = Store::open(&path).unwrap();
        assert_eq!(store.counts().unwrap().0, 1);
    }

    #[cfg(unix)]
    #[test]
    fn database_file_is_private() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        Store::open(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
