//! Failed units, from the service manager's own journal messages, such as
//! "certbot.service: Failed with result 'exit-code'.", and services that
//! finished cleanly, so a failure that was fixed stops being reported.

use std::sync::LazyLock;

use regex::Regex;

use crate::event::{SystemEvent, SystemKind};

static FAILED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(\S{1,128}\.(?:service|socket|timer|mount|path)): Failed with result '([\w-]{1,32})'",
    )
    .expect("valid regex")
});

static FINISHED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(\S{1,128}\.service): Deactivated successfully\.?$").expect("valid regex")
});

pub fn parse(message: &str, ts: i64) -> Option<SystemEvent> {
    let (kind, name, detail) = if let Some(c) = FAILED.captures(message) {
        (
            SystemKind::ServiceFailed,
            c[1].to_string(),
            Some(c[2].to_string()),
        )
    } else {
        let c = FINISHED.captures(message)?;
        (SystemKind::ServiceOk, c[1].to_string(), None)
    };
    Some(SystemEvent {
        ts,
        kind,
        name,
        detail,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_failed_units() {
        let e = parse("certbot.service: Failed with result 'exit-code'.", 7).unwrap();
        assert_eq!(e.name, "certbot.service");
        assert_eq!(e.detail.as_deref(), Some("exit-code"));
        assert_eq!(e.kind, SystemKind::ServiceFailed);
    }

    #[test]
    fn finds_clean_finishes() {
        let e = parse("certbot.service: Deactivated successfully.", 9).unwrap();
        assert_eq!(
            (e.kind, e.name.as_str()),
            (SystemKind::ServiceOk, "certbot.service")
        );
    }

    #[test]
    fn ignores_other_messages() {
        for message in [
            "Started certbot.service - Certbot.",
            "session-12.scope: Deactivated successfully.",
            "certbot.service: Main process exited, code=exited, status=1/FAILURE",
        ] {
            assert!(parse(message, 0).is_none(), "{message}");
        }
    }
}
