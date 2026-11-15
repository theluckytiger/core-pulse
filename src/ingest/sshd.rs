//! sshd messages: successful logins and attempts that ended before login.
//!
//! sshd writes several lines per attempt ("Invalid user", "Failed password",
//! then a disconnect). Only the line that ends the attempt is counted, so each
//! attempt is one event.

use std::sync::LazyLock;

use regex::Regex;

use crate::event::{SecurityEvent, SecurityKind};

static ACCEPTED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^Accepted (\S+) for (\S{1,64}) from (\S+) port \d+(?: ssh2)?(?:: \S+ (SHA256:[A-Za-z0-9+/=]{1,64}))?")
        .expect("valid regex")
});

static ENDED_BEFORE_LOGIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:Connection closed by|Disconnected from|Disconnecting) (?:(invalid|authenticating) user (\S{0,64}) )?(\S+) port \d+(?::.*)? \[preauth\]$",
    )
    .expect("valid regex")
});

static BAD_HANDSHAKE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:banner exchange: Connection from|Unable to negotiate with|Timeout before authentication for) (\S+) port \d+",
    )
    .expect("valid regex")
});

/// Port scanners that connect and drop before saying anything.
static DROPPED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^Connection (?:closed|reset) by (\S+) port \d+(?: \[preauth\])?$")
        .expect("valid regex")
});

pub fn parse(message: &str, ts: i64) -> Option<SecurityEvent> {
    let (kind, ip, detail) = if let Some(c) = ACCEPTED.captures(message) {
        // The key's fingerprint tells which device logged in.
        let detail = match c.get(4) {
            Some(key) => format!("{} as {}, key {}", &c[1], &c[2], key.as_str()),
            None => format!("{} as {}", &c[1], &c[2]),
        };
        (SecurityKind::SshLogin, c.get(3)?, detail)
    } else if let Some(c) = ENDED_BEFORE_LOGIN.captures(message) {
        let detail = match (c.get(1).map(|m| m.as_str()), c.get(2)) {
            (Some("invalid"), Some(user)) => format!("invalid user {}", user.as_str()),
            (Some(_), Some(user)) => format!("user {}", user.as_str()),
            _ => "no login attempt".to_string(),
        };
        (SecurityKind::SshFail, c.get(3)?, detail)
    } else if let Some(c) = BAD_HANDSHAKE.captures(message) {
        (
            SecurityKind::SshFail,
            c.get(1)?,
            "bad handshake".to_string(),
        )
    } else {
        let c = DROPPED.captures(message)?;
        (
            SecurityKind::SshFail,
            c.get(1)?,
            "no login attempt".to_string(),
        )
    };

    Some(SecurityEvent {
        ts,
        kind,
        source: "sshd".into(),
        ip: ip.as_str().parse().ok()?,
        port: None,
        detail: Some(detail),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(message: &str) -> Option<(SecurityKind, String, String)> {
        parse(message, 0).map(|e| (e.kind, e.ip.to_string(), e.detail.unwrap_or_default()))
    }

    #[test]
    fn counts_logins() {
        let got = check(
            "Accepted publickey for admin from 192.0.2.10 port 51544 ssh2: ED25519 SHA256:abc",
        );
        assert_eq!(
            got,
            Some((
                SecurityKind::SshLogin,
                "192.0.2.10".into(),
                "publickey as admin, key SHA256:abc".into()
            ))
        );
        let password = check("Accepted password for admin from 192.0.2.10 port 51544 ssh2");
        assert_eq!(password.unwrap().2, "password as admin");
    }

    #[test]
    fn counts_the_line_that_ends_an_attempt() {
        let cases = [
            (
                "Connection closed by invalid user oracle 203.0.113.5 port 40112 [preauth]",
                "invalid user oracle",
            ),
            (
                "Disconnected from invalid user git 203.0.113.5 port 40112 [preauth]",
                "invalid user git",
            ),
            (
                "Connection closed by authenticating user root 203.0.113.5 port 40112 [preauth]",
                "user root",
            ),
            (
                "Disconnecting authenticating user root 203.0.113.5 port 40112: Too many authentication failures [preauth]",
                "user root",
            ),
            (
                "Connection closed by 203.0.113.5 port 40112 [preauth]",
                "no login attempt",
            ),
            (
                "Connection closed by invalid user  203.0.113.5 port 40112 [preauth]",
                "invalid user ",
            ),
            (
                "banner exchange: Connection from 203.0.113.5 port 40112: invalid format",
                "bad handshake",
            ),
            (
                "Unable to negotiate with 2001:db8::5 port 40112: no matching key exchange method found.",
                "bad handshake",
            ),
            (
                "Timeout before authentication for 203.0.113.5 port 40112",
                "bad handshake",
            ),
            (
                "Connection closed by 203.0.113.5 port 40112",
                "no login attempt",
            ),
            (
                "Connection reset by 203.0.113.5 port 40112 [preauth]",
                "no login attempt",
            ),
        ];
        for (message, detail) in cases {
            let (kind, _, got) = check(message).unwrap_or_else(|| panic!("{message}"));
            assert_eq!(kind, SecurityKind::SshFail, "{message}");
            assert_eq!(got, detail, "{message}");
        }
    }

    #[test]
    fn ignores_the_other_lines_of_an_attempt() {
        let lines = [
            "Invalid user oracle from 203.0.113.5 port 40112",
            "Failed password for invalid user oracle from 203.0.113.5 port 40112 ssh2",
            "Received disconnect from 203.0.113.5 port 40112:11: Bye Bye [preauth]",
            "Disconnected from user admin 192.0.2.10 port 51544",
            "pam_unix(sshd:session): session opened for user admin(uid=1000) by (uid=0)",
            "error: kex_exchange_identification: Connection closed by remote host",
            "Server listening on 0.0.0.0 port 22.",
        ];
        for line in lines {
            assert!(check(line).is_none(), "{line}");
        }
    }
}
