use std::time::{SystemTime, UNIX_EPOCH};

pub const MINUTE: i64 = 60;
pub const HOUR: i64 = 60 * MINUTE;
pub const DAY: i64 = 24 * HOUR;

/// Current time in unix seconds.
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

/// Start of the hour that `ts` falls in.
pub fn hour_of(ts: i64) -> i64 {
    ts - ts.rem_euclid(HOUR)
}
