//! Keeps the database bounded: raw events expire, old hourly totals expire,
//! and when the file is still over its size cap the oldest raw events go.

use anyhow::Result;

use super::{Retention, Store};

const CHUNK: i64 = 5000;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Cleanup {
    pub expired: u64,
    pub over_cap: u64,
    pub bytes: u64,
}

impl Store {
    pub fn enforce_retention(&mut self, now: i64, retention: &Retention) -> Result<Cleanup> {
        let raw_cutoff = retention.raw_cutoff(now);
        let mut expired = 0;
        for table in ["http_requests", "security_events", "system_events"] {
            let sql = format!(
                "DELETE FROM {table} WHERE id IN (SELECT id FROM {table} WHERE ts < ?1 LIMIT {CHUNK})"
            );
            loop {
                let deleted = self.conn.execute(&sql, [raw_cutoff])?;
                expired += deleted as u64;
                if deleted == 0 {
                    break;
                }
            }
        }
        self.conn.execute(
            "DELETE FROM hourly_totals WHERE hour < ?1",
            [retention.hourly_cutoff(now)],
        )?;

        self.delete_unused_user_agents()?;
        let mut over_cap = 0;
        if self.used_bytes()? > retention.max_bytes {
            // Small steps, so only as much as needed is deleted.
            let (http, security) = self.counts()?;
            let step = ((http + security) / 50).max(100);
            while self.used_bytes()? > retention.max_bytes {
                let deleted = self.delete_oldest(step)?;
                if deleted == 0 {
                    break;
                }
                over_cap += deleted;
                self.delete_unused_user_agents()?;
            }
        }

        if expired + over_cap > 0 {
            // Give the freed pages back to the file system and shrink the WAL.
            self.conn
                .execute_batch("PRAGMA incremental_vacuum; PRAGMA wal_checkpoint(TRUNCATE);")?;
        }

        Ok(Cleanup {
            expired,
            over_cap,
            bytes: self.used_bytes()?,
        })
    }

    /// Forgets everything read from logs, and where each log was read up
    /// to, so the next start reads them all again. Users, sessions, the
    /// dashboard's own sign-ins and network totals stay: logs cannot
    /// rebuild those. Run it only while the service is stopped.
    pub fn forget_collected(&mut self) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute_batch(
            "DELETE FROM http_requests;
             DELETE FROM security_events WHERE source != 'core-pulse';
             DELETE FROM system_events;
             DELETE FROM hourly_totals
              WHERE metric NOT LIKE 'net.%'
                AND NOT (metric = 'security' AND name LIKE '% core-pulse');
             DELETE FROM source_state;",
        )?;
        tx.commit()?;
        self.delete_unused_user_agents()?;
        self.conn
            .execute_batch("PRAGMA incremental_vacuum; PRAGMA wal_checkpoint(TRUNCATE);")?;
        Ok(())
    }

    /// Bytes in use by the database, not counting free pages.
    pub fn used_bytes(&self) -> Result<u64> {
        let pragma = |name: &str| -> Result<i64> {
            Ok(self
                .conn
                .query_row(&format!("PRAGMA {name}"), [], |row| row.get(0))?)
        };
        let pages = pragma("page_count")? - pragma("freelist_count")?;
        Ok((pages * pragma("page_size")?).unsigned_abs())
    }

    fn delete_unused_user_agents(&self) -> Result<()> {
        self.conn.execute(
            "DELETE FROM user_agents
             WHERE NOT EXISTS (SELECT 1 FROM http_requests WHERE ua_id = user_agents.id)",
            [],
        )?;
        Ok(())
    }

    /// Deletes up to `limit` of the oldest raw events, from whichever table
    /// holds the oldest one.
    fn delete_oldest(&self, limit: u64) -> Result<u64> {
        let oldest = |table: &str| -> Result<Option<i64>> {
            Ok(self
                .conn
                .query_row(&format!("SELECT min(ts) FROM {table}"), [], |row| {
                    row.get(0)
                })?)
        };
        let table = match (oldest("http_requests")?, oldest("security_events")?) {
            (None, None) => return Ok(0),
            (Some(http), Some(security)) if security < http => "security_events",
            (None, Some(_)) => "security_events",
            _ => "http_requests",
        };
        let deleted = self.conn.execute(
            &format!(
                "DELETE FROM {table} WHERE id IN (SELECT id FROM {table} ORDER BY ts LIMIT ?1)"
            ),
            [i64::try_from(limit).unwrap_or(i64::MAX)],
        )?;
        Ok(deleted as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{DAY, HOUR};
    use crate::store::tests::{batch, request, security_event};

    const NOW: i64 = 1_794_670_407;

    fn retention(max_bytes: u64) -> Retention {
        Retention {
            raw_days: 90,
            hourly_days: 365,
            max_bytes,
        }
    }

    fn count(store: &Store, sql: &str) -> i64 {
        store.conn.query_row(sql, [], |row| row.get(0)).unwrap()
    }

    #[test]
    fn deletes_expired_raw_events_but_keeps_their_totals() {
        let mut store = Store::open_in_memory().unwrap();
        let r = retention(u64::MAX);
        let old = NOW - 100 * DAY;
        let recent = NOW - 10 * DAY;
        store
            .save(
                &batch(vec![request(old, "curl"), request(recent, "curl")], vec![]),
                old,
                &r,
            )
            .unwrap();

        let cleanup = store.enforce_retention(NOW, &r).unwrap();
        assert_eq!(cleanup.expired, 1);
        assert_eq!(store.counts().unwrap().0, 1);
        let totals = count(
            &store,
            "SELECT sum(value) FROM hourly_totals WHERE metric = 'http.requests'",
        );
        assert_eq!(totals, 2);
    }

    #[test]
    fn deletes_hourly_totals_after_their_retention() {
        let mut store = Store::open_in_memory().unwrap();
        let r = retention(u64::MAX);
        let two_years_ago = NOW - 730 * DAY;
        store
            .save(
                &batch(vec![request(two_years_ago, "curl")], vec![]),
                two_years_ago,
                &r,
            )
            .unwrap();
        assert!(count(&store, "SELECT count(*) FROM hourly_totals") > 0);

        store.enforce_retention(NOW, &r).unwrap();
        assert_eq!(count(&store, "SELECT count(*) FROM hourly_totals"), 0);
        assert_eq!(count(&store, "SELECT count(*) FROM user_agents"), 0);
    }

    #[test]
    fn enforces_the_size_cap_oldest_first() {
        let mut store = Store::open_in_memory().unwrap();
        let r = retention(u64::MAX);
        let requests: Vec<_> = (0..4000)
            .map(|i| {
                request(
                    NOW - DAY + i * 10,
                    &format!("agent-{i}-{}", "x".repeat(100)),
                )
            })
            .collect();
        let events = (0..1000)
            .map(|i| security_event(NOW - DAY + i * 30))
            .collect();
        store.save(&batch(requests, events), NOW, &r).unwrap();

        let cap = store.used_bytes().unwrap() / 3;
        let cleanup = store.enforce_retention(NOW, &retention(cap)).unwrap();
        assert!(cleanup.over_cap > 0);
        assert!(cleanup.bytes <= cap, "{} > {cap}", cleanup.bytes);

        let newest = count(&store, "SELECT max(ts) FROM http_requests");
        assert_eq!(newest, NOW - DAY + 3999 * 10);
        let oldest = count(&store, "SELECT min(ts) FROM http_requests");
        assert!(oldest > NOW - DAY + HOUR);
    }

    #[test]
    fn forgets_collected_events_but_keeps_what_logs_cannot_rebuild() {
        use crate::event::SecurityKind;
        use crate::store::{Batch, Counter};

        let mut store = Store::open_in_memory().unwrap();
        let r = retention(u64::MAX);
        let mut own = security_event(NOW);
        own.kind = SecurityKind::Login;
        own.source = "core-pulse".into();
        let mut b = batch(vec![request(NOW, "curl")], vec![security_event(NOW), own]);
        b.counters = vec![Counter {
            ts: NOW,
            metric: "net.rx",
            name: "eth0".into(),
            value: 5,
        }];
        b.state = Some(crate::store::SourceState::default());
        store.save(&b, NOW, &r).unwrap();
        store.save(&Batch::default(), NOW, &r).unwrap();

        store.forget_collected().unwrap();
        assert_eq!(store.counts().unwrap(), (0, 1));
        assert_eq!(count(&store, "SELECT count(*) FROM source_state"), 0);
        let kept = count(&store, "SELECT count(*) FROM hourly_totals");
        assert_eq!(kept, 2, "net.rx and the core-pulse sign-in");
    }

    #[test]
    fn does_nothing_when_everything_is_current() {
        let mut store = Store::open_in_memory().unwrap();
        let r = retention(u64::MAX);
        store
            .save(&batch(vec![request(NOW, "curl")], vec![]), NOW, &r)
            .unwrap();
        let cleanup = store.enforce_retention(NOW, &r).unwrap();
        assert_eq!((cleanup.expired, cleanup.over_cap), (0, 0));
        assert_eq!(store.counts().unwrap().0, 1);
    }
}
