//! Read queries for the dashboards. Each one is bounded by a time range and,
//! for lists, a row limit. Charts use the hourly totals except for the
//! last hour, which comes from raw events at one-minute resolution.

use std::collections::HashMap;
use std::net::IpAddr;

use anyhow::Result;
use rusqlite::{Row, params};

use super::{Store, rollup};
use crate::net;

#[derive(Debug, Clone)]
pub struct Counted {
    pub name: String,
    pub count: u64,
}

#[derive(Debug, Default)]
pub struct TrafficSummary {
    pub requests: u64,
    pub clients: u64,
    pub probes: u64,
    pub errors: u64,
    pub bytes: u64,
}

#[derive(Debug)]
pub struct TopClient {
    pub ip: String,
    pub requests: u64,
    pub probes: u64,
    pub last_seen: i64,
}

#[derive(Debug)]
pub struct Request {
    pub ts: i64,
    pub site: String,
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub status: u16,
    pub probe: Option<String>,
}

#[derive(Debug)]
pub struct Event {
    pub ts: i64,
    pub kind: String,
    pub source: String,
    pub ip: String,
    pub port: Option<u16>,
    pub detail: Option<String>,
}

#[derive(Debug)]
pub struct Offender {
    pub ip: String,
    pub events: u64,
    pub bans: u64,
    pub last_seen: i64,
}

/// A chart: bucket start times and one column of values per series.
#[derive(Debug, Default)]
pub struct Series {
    pub times: Vec<i64>,
    pub columns: Vec<(String, Vec<u64>)>,
}

/// Time buckets for a chart. `offset` shifts them so days start at local midnight.
#[derive(Debug, Clone, Copy)]
pub struct Buckets {
    pub since: i64,
    pub until: i64,
    pub size: i64,
    pub offset: i64,
}

impl Buckets {
    fn start(&self, ts: i64) -> i64 {
        ts - (ts + self.offset).rem_euclid(self.size)
    }

    fn times(&self) -> Vec<i64> {
        let mut times = Vec::new();
        let mut t = self.start(self.since);
        while t <= self.until {
            times.push(t);
            t += self.size;
        }
        times
    }

    /// Places (time, series, value) rows into columns with zeros where empty.
    fn fill(&self, names: &[&str], rows: Vec<(i64, String, u64)>) -> Series {
        let times = self.times();
        let index: HashMap<i64, usize> = times.iter().enumerate().map(|(i, t)| (*t, i)).collect();
        let mut columns: Vec<(String, Vec<u64>)> = names
            .iter()
            .map(|n| (n.to_string(), vec![0; times.len()]))
            .collect();
        for (ts, name, value) in rows {
            let (Some(i), Some(column)) = (
                index.get(&self.start(ts)),
                columns.iter_mut().find(|(n, _)| *n == name),
            ) else {
                continue;
            };
            column.1[*i] += value;
        }
        Series { times, columns }
    }
}

fn counted(row: &Row) -> rusqlite::Result<Counted> {
    Ok(Counted {
        name: row.get(0)?,
        count: row.get::<_, i64>(1)?.unsigned_abs(),
    })
}

fn limit(n: usize) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

impl Store {
    pub fn traffic_summary(&self, since: i64) -> Result<TrafficSummary> {
        Ok(self.conn.query_row(
            "SELECT count(*), count(DISTINCT client_ip), count(probe),
                    coalesce(sum(status >= 400), 0), coalesce(sum(bytes), 0)
             FROM http_requests WHERE ts >= ?1",
            [since],
            |row| {
                let n = |i| row.get::<_, i64>(i).map(i64::unsigned_abs);
                Ok(TrafficSummary {
                    requests: n(0)?,
                    clients: n(1)?,
                    probes: n(2)?,
                    errors: n(3)?,
                    bytes: n(4)?,
                })
            },
        )?)
    }

    /// Requests, probes and error responses over time.
    pub fn traffic_series(&self, buckets: &Buckets, raw: bool) -> Result<Series> {
        let names = ["requests", "attacks", "errors"];
        let rows = if raw {
            self.rows(
                "SELECT ts, 'requests', 1 FROM http_requests WHERE ts >= ?1
                 UNION ALL SELECT ts, 'attacks', 1 FROM http_requests WHERE ts >= ?1 AND probe IS NOT NULL
                 UNION ALL SELECT ts, 'errors', 1 FROM http_requests WHERE ts >= ?1 AND status >= 400",
                buckets.since,
            )?
        } else {
            self.rows(
                &format!(
                    "SELECT hour, 'requests', value FROM hourly_totals WHERE metric = '{}' AND hour >= ?1
                     UNION ALL SELECT hour, 'attacks', value FROM hourly_totals WHERE metric = '{}' AND hour >= ?1
                     UNION ALL SELECT hour, 'errors', value FROM hourly_totals WHERE metric = '{}' AND hour >= ?1
                         AND CAST(substr(name, instr(name, ' ') + 1) AS INTEGER) >= 400",
                    rollup::HTTP_REQUESTS,
                    rollup::HTTP_PROBES,
                    rollup::HTTP_STATUS
                ),
                buckets.start(buckets.since),
            )?
        };
        Ok(buckets.fill(&names, rows))
    }

    pub fn top_clients(&self, since: i64, n: usize) -> Result<Vec<TopClient>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT client_ip, count(*), count(probe), max(ts) FROM http_requests
             WHERE ts >= ?1 GROUP BY client_ip ORDER BY 2 DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![since, limit(n)], |row| {
            Ok(TopClient {
                ip: row.get(0)?,
                requests: row.get::<_, i64>(1)?.unsigned_abs(),
                probes: row.get::<_, i64>(2)?.unsigned_abs(),
                last_seen: row.get(3)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn top_paths(&self, since: i64, n: usize) -> Result<Vec<Counted>> {
        self.counted(
            "SELECT path, count(*) FROM http_requests WHERE ts >= ?1 GROUP BY path ORDER BY 2 DESC LIMIT ?2",
            since,
            n,
        )
    }

    pub fn top_user_agents(&self, since: i64, n: usize) -> Result<Vec<Counted>> {
        self.counted(
            "SELECT coalesce(u.value, '-'), count(*) FROM http_requests r
             LEFT JOIN user_agents u ON u.id = r.ua_id
             WHERE r.ts >= ?1 GROUP BY r.ua_id ORDER BY 2 DESC LIMIT ?2",
            since,
            n,
        )
    }

    pub fn status_codes(&self, since: i64, n: usize) -> Result<Vec<Counted>> {
        self.counted(
            "SELECT CAST(status AS TEXT), count(*) FROM http_requests WHERE ts >= ?1
             GROUP BY status ORDER BY 2 DESC LIMIT ?2",
            since,
            n,
        )
    }

    pub fn sites(&self, since: i64, n: usize) -> Result<Vec<Counted>> {
        self.counted(
            "SELECT site, count(*) FROM http_requests WHERE ts >= ?1 GROUP BY site ORDER BY 2 DESC LIMIT ?2",
            since,
            n,
        )
    }

    pub fn probe_rules(&self, since: i64, n: usize) -> Result<Vec<Counted>> {
        self.counted(
            "SELECT probe, count(*) FROM http_requests WHERE ts >= ?1 AND probe IS NOT NULL
             GROUP BY probe ORDER BY 2 DESC LIMIT ?2",
            since,
            n,
        )
    }

    /// The newest requests, all of them or only probes.
    pub fn recent_requests(&self, since: i64, probes_only: bool, n: usize) -> Result<Vec<Request>> {
        let filter = if probes_only {
            "probe IS NOT NULL"
        } else {
            "1"
        };
        self.requests_where(filter, since, n)
    }

    /// Newest requests matching a fixed SQL condition.
    pub(super) fn requests_where(
        &self,
        condition: &str,
        since: i64,
        n: usize,
    ) -> Result<Vec<Request>> {
        let mut stmt = self.conn.prepare_cached(&format!(
            "SELECT ts, site, client_ip, method, path, query, status, probe FROM http_requests
             WHERE ts >= ?1 AND {condition} ORDER BY ts DESC LIMIT ?2"
        ))?;
        let rows = stmt.query_map(params![since, limit(n)], |row| {
            Ok(Request {
                ts: row.get(0)?,
                site: row.get(1)?,
                client_ip: row.get(2)?,
                method: row.get(3)?,
                path: row.get(4)?,
                query: row.get(5)?,
                status: row.get(6)?,
                probe: row.get(7)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Security events per kind.
    pub fn security_summary(&self, since: i64) -> Result<Vec<Counted>> {
        self.counted(
            "SELECT kind, count(*) FROM security_events WHERE ts >= ?1 GROUP BY kind ORDER BY 2 DESC LIMIT ?2",
            since,
            10,
        )
    }

    pub fn security_series(&self, buckets: &Buckets, raw: bool, kinds: &[&str]) -> Result<Series> {
        let rows = if raw {
            self.rows(
                "SELECT ts, kind, 1 FROM security_events WHERE ts >= ?1",
                buckets.since,
            )?
        } else {
            self.rows(
                &format!(
                    "SELECT hour, substr(name, 1, instr(name, ' ') - 1), value FROM hourly_totals
                     WHERE metric = '{}' AND hour >= ?1",
                    rollup::SECURITY
                ),
                buckets.start(buckets.since),
            )?
        };
        Ok(buckets.fill(kinds, rows))
    }

    pub fn recent_events(&self, since: i64, n: usize) -> Result<Vec<Event>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT ts, kind, source, ip, port, detail FROM security_events
             WHERE ts >= ?1 ORDER BY ts DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![since, limit(n)], |row| {
            Ok(Event {
                ts: row.get(0)?,
                kind: row.get(1)?,
                source: row.get(2)?,
                ip: row.get(3)?,
                port: row.get(4)?,
                detail: row.get(5)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Addresses behind the most failed logins, bans and firewall blocks.
    pub fn offenders(&self, since: i64, n: usize) -> Result<Vec<Offender>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT ip, count(*), coalesce(sum(kind = 'ban'), 0), max(ts) FROM security_events
             WHERE ts >= ?1 AND kind != 'ssh_login' GROUP BY ip ORDER BY 2 DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![since, limit(n)], |row| {
            Ok(Offender {
                ip: row.get(0)?,
                events: row.get::<_, i64>(1)?.unsigned_abs(),
                bans: row.get::<_, i64>(2)?.unsigned_abs(),
                last_seen: row.get(3)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Like `offenders`, grouped into /24 (IPv4) and /48 (IPv6) networks.
    pub fn offending_networks(&self, since: i64, n: usize) -> Result<Vec<Counted>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT ip, count(*) FROM security_events WHERE ts >= ?1 AND kind != 'ssh_login' GROUP BY ip",
        )?;
        let mut networks: HashMap<String, u64> = HashMap::new();
        for row in stmt.query_map([since], counted)? {
            let row = row?;
            if let Ok(ip) = row.name.parse::<IpAddr>() {
                *networks.entry(network_of(ip)).or_default() += row.count;
            }
        }
        let mut top: Vec<Counted> = networks
            .into_iter()
            .map(|(name, count)| Counted { name, count })
            .collect();
        top.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
        top.truncate(n);
        Ok(top)
    }

    /// Bans per jail.
    pub fn bans_by_jail(&self, since: i64) -> Result<Vec<Counted>> {
        self.counted(
            "SELECT source, count(*) FROM security_events WHERE ts >= ?1 AND kind = 'ban'
             GROUP BY source ORDER BY 2 DESC LIMIT ?2",
            since,
            20,
        )
    }

    /// Addresses whose latest fail2ban action in the stored data is a ban.
    pub fn active_bans(&self) -> Result<u64> {
        let n: i64 = self.conn.query_row(
            "SELECT count(*) FROM (
                 SELECT kind, max(ts) FROM security_events
                 WHERE kind IN ('ban', 'unban') GROUP BY ip, source)
             WHERE kind = 'ban'",
            [],
            |row| row.get(0),
        )?;
        Ok(n.unsigned_abs())
    }

    /// Bytes in and out per bucket, summed over the uplink interfaces.
    pub fn network_series(&self, buckets: &Buckets) -> Result<Series> {
        let rows = self.rows(
            &format!(
                "SELECT hour, metric || ' ' || name, value FROM hourly_totals
                 WHERE metric IN ('{}', '{}') AND hour >= ?1",
                rollup::NET_RX,
                rollup::NET_TX
            ),
            buckets.start(buckets.since),
        )?;
        let rows = rows
            .into_iter()
            .filter_map(|(hour, key, value)| {
                let (metric, name) = key.split_once(' ')?;
                let direction = if metric == rollup::NET_RX {
                    "in"
                } else {
                    "out"
                };
                net::is_uplink(name).then(|| (hour, direction.to_string(), value))
            })
            .collect();
        Ok(buckets.fill(&["in", "out"], rows))
    }

    /// Bytes in and out per bucket for one container.
    pub fn container_series(&self, name: &str, buckets: &Buckets) -> Result<Series> {
        let mut stmt = self.conn.prepare_cached(&format!(
            "SELECT hour, CASE metric WHEN '{}' THEN 'in' ELSE 'out' END, value FROM hourly_totals
             WHERE metric IN ('{}', '{}') AND name = ?1 AND hour >= ?2",
            rollup::NET_CT_RX,
            rollup::NET_CT_RX,
            rollup::NET_CT_TX
        ))?;
        let rows = stmt
            .query_map(params![name, buckets.start(buckets.since)], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get::<_, i64>(2)?.unsigned_abs(),
                ))
            })?
            .collect::<rusqlite::Result<_>>()?;
        Ok(buckets.fill(&["in", "out"], rows))
    }

    /// Bytes in and out per container since `since`.
    pub fn container_totals(&self, since: i64) -> Result<Vec<(String, u64, u64)>> {
        self.byte_totals(rollup::NET_CT_RX, rollup::NET_CT_TX, since)
    }

    /// Bytes in and out per interface since `since`.
    pub fn network_totals(&self, since: i64) -> Result<Vec<(String, u64, u64)>> {
        self.byte_totals(rollup::NET_RX, rollup::NET_TX, since)
    }

    fn byte_totals(&self, rx: &str, tx: &str, since: i64) -> Result<Vec<(String, u64, u64)>> {
        let mut stmt = self.conn.prepare_cached(&format!(
            "SELECT name,
                    coalesce(sum(CASE WHEN metric = '{rx}' THEN value END), 0),
                    coalesce(sum(CASE WHEN metric = '{tx}' THEN value END), 0)
             FROM hourly_totals WHERE metric IN ('{rx}', '{tx}') AND hour >= ?1
             GROUP BY name ORDER BY 2 DESC"
        ))?;
        let rows = stmt.query_map([since], |row| {
            Ok((
                row.get(0)?,
                row.get::<_, i64>(1)?.unsigned_abs(),
                row.get::<_, i64>(2)?.unsigned_abs(),
            ))
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    fn counted(&self, sql: &str, since: i64, n: usize) -> Result<Vec<Counted>> {
        let mut stmt = self.conn.prepare_cached(sql)?;
        let rows = stmt.query_map(params![since, limit(n)], counted)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    fn rows(&self, sql: &str, since: i64) -> Result<Vec<(i64, String, u64)>> {
        let mut stmt = self.conn.prepare_cached(sql)?;
        let rows = stmt.query_map([since], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get::<_, i64>(2)?.unsigned_abs(),
            ))
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
}

fn network_of(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            format!("{a}.{b}.{c}.0/24")
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{DAY, HOUR, MINUTE};
    use crate::event::SecurityKind;
    use crate::store::Retention;
    use crate::store::tests::{batch, request, security_event};

    const NOW: i64 = 1_794_670_407;
    const KEEP: Retention = Retention {
        raw_days: 90,
        hourly_days: 365,
        max_bytes: u64::MAX,
    };

    fn store() -> Store {
        let mut store = Store::open_in_memory().unwrap();
        let mut probe = request(NOW - 30, "curl");
        probe.probe = Some("env-file".into());
        probe.status = 444;
        probe.client_ip = "203.0.113.5".parse().unwrap();
        let mut ban = security_event(NOW - 20);
        ban.ip = "203.0.113.5".parse().unwrap();
        let mut fail = security_event(NOW - 25);
        fail.kind = SecurityKind::SshFail;
        fail.ip = "203.0.113.6".parse().unwrap();
        let requests = vec![request(NOW - 90, "a"), request(NOW - 60, "a"), probe];
        store
            .save(&batch(requests, vec![ban, fail]), NOW, &KEEP)
            .unwrap();
        store
    }

    #[test]
    fn summarizes_traffic() {
        let s = store().traffic_summary(NOW - HOUR).unwrap();
        assert_eq!((s.requests, s.clients, s.probes, s.errors), (3, 2, 1, 1));
    }

    #[test]
    fn ranks_clients_and_paths() {
        let store = store();
        let clients = store.top_clients(NOW - HOUR, 10).unwrap();
        assert_eq!(
            (clients[0].ip.as_str(), clients[0].requests),
            ("192.0.2.1", 2)
        );
        assert_eq!(clients[1].probes, 1);
        assert_eq!(store.top_paths(NOW - HOUR, 1).unwrap().len(), 1);
        assert_eq!(
            store.probe_rules(NOW - HOUR, 10).unwrap()[0].name,
            "env-file"
        );
        assert_eq!(store.top_user_agents(NOW - HOUR, 10).unwrap()[0].name, "a");
    }

    #[test]
    fn lists_recent_probes_newest_first() {
        let store = store();
        let all = store.recent_requests(NOW - HOUR, false, 10).unwrap();
        assert_eq!(all.len(), 3);
        assert!(all[0].ts >= all[1].ts);
        let probes = store.recent_requests(NOW - HOUR, true, 10).unwrap();
        assert_eq!(probes.len(), 1);
        assert_eq!(probes[0].status, 444);
    }

    #[test]
    fn builds_series_from_raw_and_totals() {
        let store = store();
        let minute = Buckets {
            since: NOW - HOUR,
            until: NOW,
            size: MINUTE,
            offset: 0,
        };
        let raw = store.traffic_series(&minute, true).unwrap();
        assert_eq!(raw.times.len(), 61);
        let total = |s: &Series, name: &str| -> u64 {
            s.columns
                .iter()
                .find(|(n, _)| n == name)
                .unwrap()
                .1
                .iter()
                .sum()
        };
        assert_eq!(
            (
                total(&raw, "requests"),
                total(&raw, "attacks"),
                total(&raw, "errors")
            ),
            (3, 1, 1)
        );

        let daily = Buckets {
            since: NOW - 7 * DAY,
            until: NOW,
            size: DAY,
            offset: 0,
        };
        let hourly = store.traffic_series(&daily, false).unwrap();
        assert_eq!(
            (total(&hourly, "requests"), total(&hourly, "errors")),
            (3, 1)
        );

        let security = store
            .security_series(&daily, false, &["ban", "ssh_fail"])
            .unwrap();
        assert_eq!(total(&security, "ban") + total(&security, "ssh_fail"), 2);
    }

    #[test]
    fn ranks_offenders_and_networks() {
        let store = store();
        assert_eq!(store.offenders(NOW - HOUR, 10).unwrap().len(), 2);
        let networks = store.offending_networks(NOW - HOUR, 10).unwrap();
        assert_eq!(networks.len(), 1);
        assert_eq!(
            (networks[0].name.as_str(), networks[0].count),
            ("203.0.113.0/24", 2)
        );
        assert_eq!(store.active_bans().unwrap(), 1);
        assert_eq!(store.bans_by_jail(NOW - HOUR).unwrap()[0].name, "sshd");
    }

    #[test]
    fn sums_network_bytes_on_uplinks_only() {
        let mut store = Store::open_in_memory().unwrap();
        let counter = |metric, name: &str, value| crate::store::Counter {
            ts: NOW - 60,
            metric,
            name: name.into(),
            value,
        };
        let batch = crate::store::Batch {
            counters: vec![
                counter(rollup::NET_RX, "eth0", 1000),
                counter(rollup::NET_TX, "eth0", 3000),
                counter(rollup::NET_RX, "docker0", 500),
            ],
            ..crate::store::Batch::default()
        };
        store.save(&batch, NOW, &KEEP).unwrap();

        let hourly = Buckets {
            since: NOW - DAY,
            until: NOW,
            size: HOUR,
            offset: 0,
        };
        let series = store.network_series(&hourly).unwrap();
        let sum = |name: &str| -> u64 {
            series
                .columns
                .iter()
                .find(|(n, _)| n == name)
                .unwrap()
                .1
                .iter()
                .sum()
        };
        assert_eq!((sum("in"), sum("out")), (1000, 3000));

        let totals = store.network_totals(NOW - DAY).unwrap();
        assert_eq!(totals[0], ("eth0".to_string(), 1000, 3000));
        assert_eq!(totals.len(), 2);

        let ct = crate::store::Batch {
            counters: vec![
                counter(rollup::NET_CT_RX, "nginx (abc)", 70),
                counter(rollup::NET_CT_TX, "nginx (abc)", 90),
            ],
            ..crate::store::Batch::default()
        };
        store.save(&ct, NOW, &KEEP).unwrap();
        let series = store.container_series("nginx (abc)", &hourly).unwrap();
        let total = |name: &str| -> u64 {
            series
                .columns
                .iter()
                .find(|(n, _)| n == name)
                .unwrap()
                .1
                .iter()
                .sum()
        };
        assert_eq!((total("in"), total("out")), (70, 90));
        assert_eq!(
            store.container_totals(NOW - DAY).unwrap(),
            vec![("nginx (abc)".to_string(), 70, 90)]
        );
        // Container bytes stay out of the uplink chart.
        assert_eq!(store.network_series(&hourly).unwrap().columns.len(), 2);
    }

    #[test]
    fn groups_ipv6_networks() {
        assert_eq!(
            network_of("2001:db8:1:2::5".parse().unwrap()),
            "2001:db8:1::/48"
        );
    }
}
