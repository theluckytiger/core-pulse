//! fail2ban.log: bans and unbans per jail.
//!
//!   2026-11-14 17:33:27,412 fail2ban.actions [601]: NOTICE  [sshd] Ban 203.0.113.5

use std::sync::LazyLock;

use chrono::{NaiveDateTime, TimeZone};
use regex::Regex;

use crate::event::{SecurityEvent, SecurityKind};

static ACTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+ fail2ban\.actions\s*\[\d+\]:\s+\w+\s+\[([^\]]{1,64})\]\s+(Ban|Unban)\s+(\S+)")
        .expect("valid regex")
});

/// fail2ban writes local time without an offset, so `tz` must be the
/// server's time zone. "Restore Ban" lines after a restart are skipped:
/// those bans were already counted when they happened.
pub fn parse<Tz: TimeZone>(line: &str, tz: &Tz) -> Option<SecurityEvent> {
    let caps = ACTION.captures(line)?;
    let naive = NaiveDateTime::parse_from_str(&caps[1], "%Y-%m-%d %H:%M:%S").ok()?;
    let kind = match &caps[3] {
        "Ban" => SecurityKind::Ban,
        _ => SecurityKind::Unban,
    };
    Some(SecurityEvent {
        ts: tz.from_local_datetime(&naive).earliest()?.timestamp(),
        kind,
        source: caps[2].to_string(),
        ip: caps[4].parse().ok()?,
        port: None,
        detail: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::FixedOffset;

    fn tz() -> FixedOffset {
        FixedOffset::east_opt(2 * 3600).unwrap()
    }

    #[test]
    fn parses_bans_and_unbans() {
        let ban = parse(
            "2026-11-14 17:33:27,412 fail2ban.actions        [601]: NOTICE  [sshd] Ban 203.0.113.5",
            &tz(),
        )
        .unwrap();
        assert_eq!(ban.ts, 1_794_670_407);
        assert_eq!(ban.kind, SecurityKind::Ban);
        assert_eq!(ban.source, "sshd");
        assert_eq!(ban.ip.to_string(), "203.0.113.5");

        let unban = parse(
            "2026-11-14 17:40:00,001 fail2ban.actions        [601]: NOTICE  [recidive] Unban 2001:db8::9",
            &tz(),
        )
        .unwrap();
        assert_eq!(unban.kind, SecurityKind::Unban);
        assert_eq!(unban.source, "recidive");
    }

    #[test]
    fn skips_everything_else() {
        let lines = [
            "2026-11-14 17:33:27,412 fail2ban.actions        [601]: NOTICE  [sshd] Restore Ban 203.0.113.5",
            "2026-11-14 17:33:26,900 fail2ban.filter         [601]: INFO    [sshd] Found 203.0.113.5 - 2026-11-14 17:33:26",
            "2026-11-14 17:30:00,000 fail2ban.server         [601]: INFO    Starting Fail2ban v1.0.2",
            "2026-11-14 17:33:27,412 fail2ban.actions        [601]: NOTICE  [sshd] Ban not-an-ip",
            "",
        ];
        for line in lines {
            assert!(parse(line, &tz()).is_none(), "{line}");
        }
    }
}
