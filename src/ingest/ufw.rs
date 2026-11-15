//! UFW kernel log lines: packets the firewall dropped.
//!
//!   [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=203.0.113.5 DST=192.0.2.1 ... PROTO=TCP SPT=40112 DPT=23 ...

use std::sync::LazyLock;

use regex::Regex;

use crate::event::{SecurityEvent, SecurityKind};

static BLOCK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\[UFW (BLOCK|LIMIT BLOCK)\] .*?\bSRC=(\S+) .*?\bPROTO=(\w+)(?:.*?\bDPT=(\d+))?")
        .expect("valid regex")
});

pub fn parse(message: &str, ts: i64) -> Option<SecurityEvent> {
    let caps = BLOCK.captures(message)?;
    let proto = &caps[3];
    let detail = if &caps[1] == "LIMIT BLOCK" {
        format!("{proto}, rate limit")
    } else {
        proto.to_string()
    };
    Some(SecurityEvent {
        ts,
        kind: SecurityKind::FirewallBlock,
        source: "ufw".into(),
        ip: caps[2].parse().ok()?,
        port: caps.get(4).and_then(|p| p.as_str().parse().ok()),
        detail: Some(detail),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLOCK_LINE: &str = "[UFW BLOCK] IN=eth0 OUT= MAC=02:00:00:00:00:01:02:00:00:00:00:02:08:00 SRC=203.0.113.5 DST=192.0.2.1 LEN=44 TOS=0x00 PREC=0x00 TTL=242 ID=54321 PROTO=TCP SPT=40112 DPT=23 WINDOW=1024 RES=0x00 SYN URGP=0";

    #[test]
    fn parses_blocked_packets() {
        let e = parse(BLOCK_LINE, 7).unwrap();
        assert_eq!(e.ts, 7);
        assert_eq!(e.kind, SecurityKind::FirewallBlock);
        assert_eq!(e.ip.to_string(), "203.0.113.5");
        assert_eq!(e.port, Some(23));
        assert_eq!(e.detail.as_deref(), Some("TCP"));
    }

    #[test]
    fn parses_rate_limits_and_icmp() {
        let limit = BLOCK_LINE.replace("[UFW BLOCK]", "[UFW LIMIT BLOCK]");
        assert_eq!(
            parse(&limit, 0).unwrap().detail.as_deref(),
            Some("TCP, rate limit")
        );

        let icmp = "[UFW BLOCK] IN=eth0 OUT= SRC=2001:db8::5 DST=2001:db8::1 LEN=64 PROTO=ICMPv6 TYPE=128 CODE=0";
        let e = parse(icmp, 0).unwrap();
        assert_eq!(e.ip.to_string(), "2001:db8::5");
        assert_eq!(e.port, None);
    }

    #[test]
    fn ignores_other_kernel_messages() {
        let lines = [
            "[UFW AUDIT] IN= OUT=lo SRC=127.0.0.1 DST=127.0.0.1 PROTO=TCP SPT=1 DPT=2",
            "[UFW ALLOW] IN=eth0 OUT= SRC=203.0.113.5 DST=192.0.2.1 PROTO=TCP SPT=1 DPT=443",
            "br-1234: port 1(veth1) entered forwarding state",
        ];
        for line in lines {
            assert!(parse(line, 0).is_none(), "{line}");
        }
    }
}
