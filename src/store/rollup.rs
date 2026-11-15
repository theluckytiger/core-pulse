//! Hourly totals. They are updated in the same transaction as the raw
//! events, so they stay correct after the raw events are deleted.

use std::collections::HashMap;

use anyhow::Result;
use rusqlite::{Connection, params};

use super::Batch;
use crate::clock::hour_of;

/// Requests per site.
pub const HTTP_REQUESTS: &str = "http.requests";
/// Requests per site and status code, named "site status".
pub const HTTP_STATUS: &str = "http.status";
/// Response bytes per site.
pub const HTTP_BYTES: &str = "http.bytes";
/// Probe requests per site and rule, named "site rule".
pub const HTTP_PROBES: &str = "http.probes";
/// Security events per kind and source, named "kind source".
pub const SECURITY: &str = "security";
/// Bytes received and sent per network interface.
pub const NET_RX: &str = "net.rx";
pub const NET_TX: &str = "net.tx";
/// Bytes received and sent per container, named "program (id)".
pub const NET_CT_RX: &str = "net.ct.rx";
pub const NET_CT_TX: &str = "net.ct.tx";

pub type Totals = HashMap<(i64, &'static str, String), i64>;

/// Sums a batch per hour. Events before `cutoff` are left out.
pub fn totals(batch: &Batch, cutoff: i64) -> Totals {
    let mut totals = Totals::new();
    let mut add = |ts: i64, metric: &'static str, name: String, value: i64| {
        let hour = hour_of(ts);
        if hour >= cutoff {
            *totals.entry((hour, metric, name)).or_default() += value;
        }
    };

    for r in &batch.http {
        add(r.ts, HTTP_REQUESTS, r.site.clone(), 1);
        add(r.ts, HTTP_STATUS, format!("{} {}", r.site, r.status), 1);
        add(
            r.ts,
            HTTP_BYTES,
            r.site.clone(),
            i64::try_from(r.bytes).unwrap_or(i64::MAX),
        );
        if let Some(probe) = &r.probe {
            add(r.ts, HTTP_PROBES, format!("{} {probe}", r.site), 1);
        }
    }
    for e in &batch.security {
        add(
            e.ts,
            SECURITY,
            format!("{} {}", e.kind.as_str(), e.source),
            1,
        );
    }
    for c in &batch.counters {
        add(c.ts, c.metric, c.name.clone(), c.value);
    }
    totals
}

pub fn save(conn: &Connection, totals: &Totals) -> Result<()> {
    let mut upsert = conn.prepare_cached(
        "INSERT INTO hourly_totals (hour, metric, name, value) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT (hour, metric, name) DO UPDATE SET value = value + excluded.value",
    )?;
    for ((hour, metric, name), value) in totals {
        upsert.execute(params![hour, metric, name, value])?;
    }
    Ok(())
}
