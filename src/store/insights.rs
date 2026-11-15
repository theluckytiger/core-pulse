//! Queries behind the overview page: who logged in, how many real people
//! visited, what attacks got back and what broke.

use std::collections::HashSet;

use anyhow::Result;
use rusqlite::params;

use super::Store;
use super::queries::{Counted, Request};
use crate::device;

#[derive(Debug, Clone)]
pub struct Login {
    pub ts: i64,
    /// "ssh_login" or "login".
    pub kind: String,
    /// "sshd", "core-pulse" or the app's name.
    pub source: String,
    pub ip: String,
    pub detail: String,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Visitors {
    /// Addresses that browsed like a person: a real browser, normal pages, no probes.
    pub people: u64,
    pub pages: u64,
}

#[derive(Debug)]
pub struct Failure {
    pub name: String,
    pub count: u64,
    pub last: i64,
    pub detail: String,
    /// When it last finished cleanly, at any time.
    pub last_ok: Option<i64>,
}

impl Failure {
    /// It ran fine after its last failure.
    pub fn recovered(&self) -> bool {
        self.last_ok.is_some_and(|ok| ok > self.last)
    }
}

impl Store {
    /// Successful SSH and app logins since `since`, oldest first.
    pub fn logins(&self, since: i64) -> Result<Vec<Login>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT ts, kind, source, ip, coalesce(detail, '') FROM security_events
             WHERE kind IN ('ssh_login', 'login') AND ts >= ?1 ORDER BY ts",
        )?;
        let rows = stmt.query_map([since], |row| {
            Ok(Login {
                ts: row.get(0)?,
                kind: row.get(1)?,
                source: row.get(2)?,
                ip: row.get(3)?,
                detail: row.get(4)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Failed app and dashboard logins per app.
    pub fn failed_logins(&self, since: i64) -> Result<Vec<Counted>> {
        self.counted_since(
            "SELECT source, count(*) FROM security_events WHERE kind = 'login_fail' AND ts >= ?1
             GROUP BY source ORDER BY 2 DESC",
            since,
        )
    }

    /// An estimate of real people: addresses with a browser user agent that
    /// fetched pages without errors and never sent a probe.
    pub fn visitors(&self, since: i64) -> Result<Visitors> {
        let mut probing = self.conn.prepare_cached(
            "SELECT DISTINCT client_ip FROM http_requests WHERE probe IS NOT NULL AND ts >= ?1",
        )?;
        let probing: HashSet<String> = probing
            .query_map([since], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;

        // A page is a path without a file extension, like "/" or "/shop/".
        let mut stmt = self.conn.prepare_cached(
            "SELECT r.client_ip, coalesce(u.value, '-'), sum(r.path NOT LIKE '%.%')
             FROM http_requests r LEFT JOIN user_agents u ON u.id = r.ua_id
             WHERE r.ts >= ?1 AND r.method = 'GET' AND r.status BETWEEN 200 AND 399
               AND r.probe IS NULL
             GROUP BY r.client_ip, r.ua_id",
        )?;
        let mut people = HashSet::new();
        let mut pages = 0;
        let rows = stmt.query_map([since], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        for row in rows {
            let (ip, user_agent, page_views) = row?;
            if page_views > 0 && !device::is_bot(&user_agent) && !probing.contains(&ip) {
                pages += page_views.unsigned_abs();
                people.insert(ip);
            }
        }
        Ok(Visitors {
            people: people.len() as u64,
            pages,
        })
    }

    /// Probe requests per rule and status code.
    pub fn probe_outcomes(&self, since: i64) -> Result<Vec<(String, u16, u64)>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT probe, status, count(*) FROM http_requests
             WHERE probe IS NOT NULL AND ts >= ?1 GROUP BY probe, status",
        )?;
        let rows = stmt.query_map([since], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get::<_, i64>(2)?.unsigned_abs(),
            ))
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Probes the server answered with 2xx, newest first.
    pub fn answered_probes(&self, since: i64, n: usize) -> Result<Vec<Request>> {
        self.requests_where("probe IS NOT NULL AND status BETWEEN 200 AND 299", since, n)
    }

    /// Units that failed, most often first.
    pub fn failed_services(&self, since: i64) -> Result<Vec<Failure>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT f.name, count(*), max(f.ts), coalesce(max(f.detail), ''),
                    (SELECT max(ts) FROM system_events o WHERE o.kind = 'service_ok' AND o.name = f.name)
             FROM system_events f
             WHERE f.kind = 'service_failed' AND f.ts >= ?1 GROUP BY f.name ORDER BY 2 DESC",
        )?;
        let rows = stmt.query_map([since], |row| {
            Ok(Failure {
                name: row.get(0)?,
                count: row.get::<_, i64>(1)?.unsigned_abs(),
                last: row.get(2)?,
                detail: row.get(3)?,
                last_ok: row.get(4)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Paths that got a 5xx answer, most often first.
    pub fn server_errors(&self, since: i64) -> Result<Vec<Counted>> {
        self.counted_since(
            "SELECT path, count(*) FROM http_requests WHERE status >= 500 AND ts >= ?1
             GROUP BY path ORDER BY 2 DESC",
            since,
        )
    }

    /// Ports the firewall blocked, most often first.
    pub fn blocked_ports(&self, since: i64) -> Result<Vec<Counted>> {
        self.counted_since(
            "SELECT CAST(port AS TEXT), count(*) FROM security_events
             WHERE kind = 'fw_block' AND port IS NOT NULL AND ts >= ?1
             GROUP BY port ORDER BY 2 DESC",
            since,
        )
    }

    /// Every address that attacked: probes, failed logins and blocked connections.
    pub fn attackers(&self, since: i64) -> Result<Vec<Counted>> {
        self.counted_since(
            "SELECT ip, sum(n) FROM (
                 SELECT client_ip AS ip, count(*) AS n FROM http_requests
                 WHERE probe IS NOT NULL AND ts >= ?1 GROUP BY client_ip
                 UNION ALL
                 SELECT ip, count(*) FROM security_events
                 WHERE kind IN ('ssh_fail', 'fw_block', 'login_fail') AND ts >= ?1 GROUP BY ip)
             GROUP BY ip",
            since,
        )
    }

    fn counted_since(&self, sql: &str, since: i64) -> Result<Vec<Counted>> {
        let mut stmt = self.conn.prepare_cached(sql)?;
        let rows = stmt.query_map(params![since], |row| {
            Ok(Counted {
                name: row.get(0)?,
                count: row.get::<_, i64>(1)?.unsigned_abs(),
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{SecurityKind, SystemEvent, SystemKind};
    use crate::store::tests::{batch, request, security_event};
    use crate::store::{Batch, Retention};

    const NOW: i64 = 1_794_670_407;
    const KEEP: Retention = Retention {
        raw_days: 90,
        hourly_days: 365,
        max_bytes: u64::MAX,
    };
    const FIREFOX: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0";

    #[test]
    fn counts_people_not_bots() {
        let mut store = Store::open_in_memory().unwrap();
        let mut person = request(NOW - 10, FIREFOX);
        person.path = "/shop/".into();
        let mut asset = request(NOW - 9, FIREFOX);
        asset.path = "/static/site.css".into();
        let mut bot = request(NOW - 8, "curl/8.5.0");
        bot.client_ip = "203.0.113.2".parse().unwrap();
        let mut sneaky = request(NOW - 7, FIREFOX);
        sneaky.client_ip = "203.0.113.3".parse().unwrap();
        let mut probe = sneaky.clone();
        probe.path = "/.env".into();
        probe.probe = Some("env-file".into());
        store
            .save(
                &batch(vec![person, asset, bot, sneaky, probe], vec![]),
                NOW,
                &KEEP,
            )
            .unwrap();
        assert_eq!(
            store.visitors(NOW - 60).unwrap(),
            Visitors {
                people: 1,
                pages: 1
            }
        );
    }

    #[test]
    fn lists_logins_and_failures() {
        let mut store = Store::open_in_memory().unwrap();
        let mut ssh = security_event(NOW - 30);
        ssh.kind = SecurityKind::SshLogin;
        let mut app = security_event(NOW - 20);
        app.kind = SecurityKind::LoginFail;
        app.source = "Shop admin".into();
        store
            .save(&batch(vec![], vec![ssh, app]), NOW, &KEEP)
            .unwrap();

        let logins = store.logins(NOW - 60).unwrap();
        assert_eq!(logins.len(), 1);
        assert_eq!(logins[0].kind, "ssh_login");
        assert_eq!(store.failed_logins(NOW - 60).unwrap()[0].name, "Shop admin");
        assert_eq!(store.attackers(NOW - 60).unwrap().len(), 1);
    }

    #[test]
    fn groups_failed_services() {
        let mut store = Store::open_in_memory().unwrap();
        let failure = |ts| SystemEvent {
            ts,
            kind: SystemKind::ServiceFailed,
            name: "certbot.service".into(),
            detail: Some("exit-code".into()),
        };
        let b = Batch {
            system: vec![failure(NOW - 20), failure(NOW - 10)],
            ..Batch::default()
        };
        store.save(&b, NOW, &KEEP).unwrap();
        let failed = store.failed_services(NOW - 60).unwrap();
        assert_eq!((failed[0].count, failed[0].last), (2, NOW - 10));
        assert!(!failed[0].recovered());

        let fixed = Batch {
            system: vec![SystemEvent {
                kind: SystemKind::ServiceOk,
                detail: None,
                ..failure(NOW - 5)
            }],
            ..Batch::default()
        };
        store.save(&fixed, NOW, &KEEP).unwrap();
        assert!(store.failed_services(NOW - 60).unwrap()[0].recovered());
    }

    #[test]
    fn finds_answered_probes_and_errors() {
        let mut store = Store::open_in_memory().unwrap();
        let mut answered = request(NOW - 10, "curl");
        answered.probe = Some("env-file".into());
        answered.query = Some("file=../../.env".into());
        let mut error = request(NOW - 5, FIREFOX);
        error.status = 500;
        store
            .save(&batch(vec![answered, error], vec![]), NOW, &KEEP)
            .unwrap();
        let probes = store.answered_probes(NOW - 60, 10).unwrap();
        assert_eq!(probes[0].query.as_deref(), Some("file=../../.env"));
        assert_eq!(store.server_errors(NOW - 60).unwrap()[0].count, 1);
        assert_eq!(store.probe_outcomes(NOW - 60).unwrap().len(), 1);
    }
}
