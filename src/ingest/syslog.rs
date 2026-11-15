//! Classic syslog lines, for systems that log SSH and UFW to files.
//!
//! Both common timestamp styles are understood:
//!   2026-11-14T17:33:27.123456+02:00 host sshd[812]: message   (rsyslog default)
//!   Nov 14 17:33:27 host sshd[812]: message                    (traditional)

use chrono::{DateTime, Datelike, NaiveDateTime, TimeZone};

pub struct Line<'a> {
    pub ts: i64,
    pub program: &'a str,
    pub message: &'a str,
}

/// `now` decides the year for traditional timestamps, which have none.
pub fn parse<'a, Tz: TimeZone>(line: &'a str, tz: &Tz, now: i64) -> Option<Line<'a>> {
    let (ts, rest) = parse_iso(line).or_else(|| parse_traditional(line, tz, now))?;
    let (_host, rest) = rest.split_once(' ')?;
    let (tag, message) = rest.split_once(": ")?;
    let program = tag.split('[').next().unwrap_or(tag);
    Some(Line {
        ts,
        program,
        message,
    })
}

fn parse_iso(line: &str) -> Option<(i64, &str)> {
    let (stamp, rest) = line.split_once(' ')?;
    let ts = DateTime::parse_from_rfc3339(stamp).ok()?.timestamp();
    Some((ts, rest))
}

fn parse_traditional<'a, Tz: TimeZone>(line: &'a str, tz: &Tz, now: i64) -> Option<(i64, &'a str)> {
    let mut parts = line.split(' ').filter(|p| !p.is_empty());
    let (month, day, time) = (parts.next()?, parts.next()?, parts.next()?);
    // "Nov  4" has two spaces, so find the rest after the time field.
    let rest = line.get(line.find(time)? + time.len() + 1..)?;

    let this_year = tz.timestamp_opt(now, 0).single()?.year();
    let local = |year: i32| {
        let naive = NaiveDateTime::parse_from_str(
            &format!("{year} {month} {day} {time}"),
            "%Y %b %d %H:%M:%S",
        )
        .ok()?;
        Some(tz.from_local_datetime(&naive).earliest()?.timestamp())
    };
    let mut ts = local(this_year)?;
    // A December line read in January belongs to last year.
    if ts > now + 86_400 {
        ts = local(this_year - 1)?;
    }
    Some((ts, rest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::FixedOffset;

    const NOW: i64 = 1_794_670_407; // 2026-11-14 15:33:27 UTC

    fn tz() -> FixedOffset {
        FixedOffset::east_opt(2 * 3600).unwrap()
    }

    #[test]
    fn parses_rsyslog_timestamps() {
        let line = "2026-11-14T17:33:27.123456+02:00 web1 sshd[812]: Accepted publickey for admin";
        let l = parse(line, &tz(), NOW).unwrap();
        assert_eq!(
            (l.ts, l.program, l.message),
            (NOW, "sshd", "Accepted publickey for admin")
        );
    }

    #[test]
    fn parses_traditional_timestamps() {
        let l = parse(
            "Nov 14 17:33:27 web1 kernel: [UFW BLOCK] IN=eth0",
            &tz(),
            NOW,
        )
        .unwrap();
        assert_eq!(
            (l.ts, l.program, l.message),
            (NOW, "kernel", "[UFW BLOCK] IN=eth0")
        );

        let padded = parse("Nov  4 17:33:27 web1 sshd[1]: x", &tz(), NOW).unwrap();
        assert_eq!(padded.ts, NOW - 10 * 86_400);
    }

    #[test]
    fn puts_december_lines_in_the_previous_year() {
        let january = 1_798_761_600; // 2027-01-01 00:00 UTC
        let l = parse("Dec 31 23:00:00 web1 sshd[1]: x", &tz(), january).unwrap();
        assert!(l.ts < january && january - l.ts < 86_400);
    }

    #[test]
    fn rejects_other_lines() {
        assert!(parse("", &tz(), NOW).is_none());
        assert!(parse("hello world", &tz(), NOW).is_none());
    }
}
