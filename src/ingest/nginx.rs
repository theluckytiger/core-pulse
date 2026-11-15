//! Parses nginx access log lines with the `log_format` string from nginx.conf.

use std::net::IpAddr;

use anyhow::{Context, Result, bail, ensure};
use chrono::DateTime;

use crate::config::{LoginForm, NginxSource, RealIpConfig};
use crate::device;
use crate::event::{HttpRequest, SecurityEvent, SecurityKind};
use crate::ingest::realip::RealIp;
use crate::probes::ProbeMatcher;

const MAX_PATH: usize = 512;
const MAX_QUERY: usize = 512;
const MAX_USER_AGENT: usize = 512;
const MAX_SITE: usize = 253;

/// A log_format split into literal text and variables.
struct LogFormat {
    prefix: String,
    /// Each variable's name and the literal text that follows it.
    fields: Vec<(String, String)>,
}

impl LogFormat {
    fn compile(format: &str) -> Result<Self> {
        let mut prefix = String::new();
        let mut fields: Vec<(String, String)> = Vec::new();
        let mut literal = String::new();
        let mut chars = format.chars().peekable();

        while let Some(c) = chars.next() {
            if c != '$' {
                literal.push(c);
                continue;
            }
            let braced = chars.next_if_eq(&'{').is_some();
            let mut name = String::new();
            while let Some(c) = chars.next_if(|c| c.is_ascii_alphanumeric() || *c == '_') {
                name.push(c);
            }
            if braced {
                ensure!(chars.next() == Some('}'), "unclosed ${{ in log format");
            }
            ensure!(!name.is_empty(), "lone '$' in log format");

            let text = std::mem::take(&mut literal);
            match fields.last_mut() {
                Some((previous, after)) => {
                    ensure!(
                        !text.is_empty(),
                        "${previous} and ${name} need some text between them"
                    );
                    *after = text;
                }
                None => prefix = text,
            }
            fields.push((name, String::new()));
        }

        match fields.last_mut() {
            Some((_, after)) => *after = literal,
            None => bail!("log format has no variables"),
        }
        Ok(Self { prefix, fields })
    }

    /// Splits a line into variable values, in format order. Text after the
    /// last field is ignored.
    fn split<'a>(&self, line: &'a str) -> Option<Vec<&'a str>> {
        let mut rest = line.strip_prefix(self.prefix.as_str())?;
        let mut values = Vec::with_capacity(self.fields.len());
        for (_, after) in &self.fields {
            if after.is_empty() {
                values.push(rest);
                rest = "";
            } else {
                let end = rest.find(after.as_str())?;
                values.push(&rest[..end]);
                rest = &rest[end + after.len()..];
            }
        }
        Some(values)
    }

    fn index(&self, name: &str) -> Option<usize> {
        self.fields.iter().position(|(n, _)| n == name)
    }
}

enum TimeField {
    Local(usize),
    Iso(usize),
}

/// One format with the position of every variable we use.
struct Layout {
    format: LogFormat,
    remote_addr: usize,
    time: TimeField,
    request: usize,
    status: usize,
    bytes: Option<usize>,
    user_agent: Option<usize>,
    host: Option<usize>,
    client_header: Option<usize>,
}

impl Layout {
    fn new(format: &str, header_variable: Option<&str>) -> Result<Self> {
        let format = LogFormat::compile(format)?;
        let need = |name: &str| {
            format
                .index(name)
                .with_context(|| format!("format needs ${name}"))
        };
        let time = match (format.index("time_local"), format.index("time_iso8601")) {
            (Some(i), _) => TimeField::Local(i),
            (None, Some(i)) => TimeField::Iso(i),
            _ => bail!("format needs $time_local or $time_iso8601"),
        };
        let client_header = match header_variable {
            Some(var) => Some(need(var)?),
            None => None,
        };
        Ok(Self {
            remote_addr: need("remote_addr")?,
            request: need("request")?,
            status: need("status")?,
            bytes: format
                .index("body_bytes_sent")
                .or_else(|| format.index("bytes_sent")),
            user_agent: format.index("http_user_agent"),
            host: format.index("host").or_else(|| format.index("server_name")),
            time,
            client_header,
            format,
        })
    }
}

/// Turns access log lines into requests for one nginx source.
pub struct NginxParser {
    /// The current format first, then older ones still found in the file.
    layouts: Vec<Layout>,
    site: String,
    real_ip: RealIp,
    logins: Vec<LoginForm>,
}

impl NginxParser {
    pub fn new(source: &NginxSource, real_ip: &RealIpConfig) -> Result<Self> {
        let real_ip = RealIp::new(real_ip);
        let layouts = std::iter::once(&source.format)
            .chain(&source.previous_formats)
            .map(|format| Layout::new(format, real_ip.variable()))
            .collect::<Result<_>>()
            .with_context(|| format!("nginx '{}'", source.name))?;
        Ok(Self {
            layouts,
            site: source.site.clone().unwrap_or_else(|| source.name.clone()),
            real_ip,
            logins: source.logins.clone(),
        })
    }

    /// A sign-in event when the request posted to one of the login forms.
    pub fn login(&self, r: &HttpRequest) -> Option<SecurityEvent> {
        if r.method != "POST" {
            return None;
        }
        let form = self.logins.iter().find(|f| f.path == r.path)?;
        let failed = match &form.failure {
            Some(codes) => codes.contains(&r.status),
            None => (200..500).contains(&r.status),
        };
        let kind = if form.success.contains(&r.status) {
            SecurityKind::Login
        } else if failed {
            SecurityKind::LoginFail
        } else {
            return None;
        };
        Some(SecurityEvent {
            ts: r.ts,
            kind,
            source: form.name.clone(),
            ip: r.client_ip,
            port: None,
            detail: Some(device::describe(&r.user_agent)),
        })
    }

    pub fn parse(&self, line: &str, probes: &ProbeMatcher) -> Option<HttpRequest> {
        self.layouts
            .iter()
            .find_map(|layout| self.parse_with(layout, line, probes))
    }

    fn parse_with(
        &self,
        layout: &Layout,
        line: &str,
        probes: &ProbeMatcher,
    ) -> Option<HttpRequest> {
        let values = layout.format.split(line)?;
        let peer: IpAddr = values[layout.remote_addr].parse().ok()?;
        let ts = match layout.time {
            TimeField::Local(i) => {
                DateTime::parse_from_str(values[i], "%d/%b/%Y:%H:%M:%S %z").ok()?
            }
            TimeField::Iso(i) => DateTime::parse_from_rfc3339(values[i]).ok()?,
        }
        .timestamp();
        let status = values[layout.status].parse().ok()?;
        let bytes = layout
            .bytes
            .and_then(|i| values[i].parse().ok())
            .unwrap_or(0);
        let (method, target) = split_request(values[layout.request]);
        let site = layout
            .host
            .map(|i| values[i])
            .filter(|h| !h.is_empty() && *h != "-")
            .unwrap_or(self.site.as_str());
        let user_agent = layout.user_agent.map_or("-", |i| values[i]);
        let header = layout.client_header.map(|i| values[i]);
        let probe = probes.classify(target).map(str::to_string);
        // Attackers' query strings are worth keeping; visitors' may hold tokens.
        let query = probe
            .as_ref()
            .and_then(|_| target.split_once('?'))
            .map(|(_, query)| truncate(query, MAX_QUERY));

        Some(HttpRequest {
            ts,
            site: truncate(&site.to_ascii_lowercase(), MAX_SITE),
            client_ip: self.real_ip.resolve(peer, header),
            peer_ip: peer,
            method: method.to_string(),
            path: truncate(strip_query(target), MAX_PATH),
            query,
            status,
            bytes,
            user_agent: truncate(user_agent, MAX_USER_AGENT),
            probe,
        })
    }
}

/// "GET /a?b HTTP/1.1" gives ("GET", "/a?b"). Junk from scanners keeps the
/// whole request as the target with method "-".
fn split_request(request: &str) -> (&str, &str) {
    let mut parts = request.splitn(3, ' ');
    match (parts.next(), parts.next()) {
        (Some(method), Some(target))
            if !method.is_empty()
                && method.len() <= 16
                && method.bytes().all(|b| b.is_ascii_uppercase()) =>
        {
            (method, target)
        }
        _ => ("-", request),
    }
}

fn strip_query(target: &str) -> &str {
    target.split_once('?').map_or(target, |(path, _)| path)
}

fn truncate(s: &str, max: usize) -> String {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{COMBINED_FORMAT, ClientIpHeader};
    use crate::probes::default_rules;
    use std::path::PathBuf;

    const PROXIED: &str = r#"$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" "$http_x_forwarded_for""#;

    fn parser(format: &str, previous: &[&str], trusted: &[&str]) -> NginxParser {
        let source = NginxSource {
            name: "web".into(),
            path: PathBuf::from("/var/log/nginx/access.log"),
            format: format.into(),
            previous_formats: previous.iter().map(|s| s.to_string()).collect(),
            site: Some("example.com".into()),
            logins: vec![
                LoginForm {
                    name: "Shop admin".into(),
                    path: "/admin/login/".into(),
                    success: vec![302],
                    staff: true,
                    failure: None,
                },
                LoginForm {
                    name: "Two-step app".into(),
                    path: "/app/login/".into(),
                    success: vec![302],
                    staff: true,
                    failure: Some(Vec::new()),
                },
            ],
        };
        let real_ip = RealIpConfig {
            trusted_proxies: trusted.iter().map(|s| s.parse().unwrap()).collect(),
            header: ClientIpHeader::XForwardedFor,
        };
        NginxParser::new(&source, &real_ip).unwrap()
    }

    fn probes() -> ProbeMatcher {
        ProbeMatcher::new(&default_rules()).unwrap()
    }

    #[test]
    fn parses_the_combined_format() {
        let line = r#"192.0.2.10 - - [14/Nov/2026:17:33:27 +0200] "GET /shop/?page=2 HTTP/2.0" 200 5120 "-" "Mozilla/5.0 (X11; Linux x86_64)""#;
        let r = parser(COMBINED_FORMAT, &[], &[])
            .parse(line, &probes())
            .unwrap();
        assert_eq!(r.ts, 1_794_670_407);
        assert_eq!(r.client_ip, r.peer_ip);
        assert_eq!(r.client_ip.to_string(), "192.0.2.10");
        assert_eq!((r.method.as_str(), r.path.as_str()), ("GET", "/shop/"));
        assert_eq!((r.status, r.bytes), (200, 5120));
        assert_eq!(r.site, "example.com");
        assert_eq!(r.user_agent, "Mozilla/5.0 (X11; Linux x86_64)");
        assert_eq!(r.probe, None);
    }

    #[test]
    fn resolves_the_visitor_behind_a_trusted_proxy() {
        let line = r#"198.51.100.20 - - [14/Nov/2026:17:33:27 +0200] "GET /.env HTTP/1.1" 444 0 "-" "curl/8.5.0" "192.0.2.66, 203.0.113.5""#;
        let r = parser(PROXIED, &[], &["198.51.100.0/24"])
            .parse(line, &probes())
            .unwrap();
        assert_eq!(r.peer_ip.to_string(), "198.51.100.20");
        assert_eq!(r.client_ip.to_string(), "203.0.113.5");
        assert_eq!(r.probe.as_deref(), Some("env-file"));
    }

    #[test]
    fn direct_hits_keep_their_own_address() {
        let line = r#"203.0.113.7 - - [14/Nov/2026:17:33:27 +0200] "GET / HTTP/1.1" 400 150 "-" "-" "192.0.2.1""#;
        let r = parser(PROXIED, &[], &["198.51.100.0/24"])
            .parse(line, &probes())
            .unwrap();
        assert_eq!(r.client_ip.to_string(), "203.0.113.7");
    }

    #[test]
    fn falls_back_to_a_previous_format() {
        let current = format!(r#"{PROXIED} "$host""#);
        let p = parser(&current, &[PROXIED], &[]);
        let old =
            r#"192.0.2.10 - - [14/Nov/2026:17:33:27 +0200] "GET / HTTP/1.1" 200 1 "-" "-" "-""#;
        let new = r#"192.0.2.10 - - [14/Nov/2026:17:33:27 +0200] "GET / HTTP/1.1" 200 1 "-" "-" "-" "example.org""#;
        assert_eq!(p.parse(old, &probes()).unwrap().site, "example.com");
        assert_eq!(p.parse(new, &probes()).unwrap().site, "example.org");
    }

    #[test]
    fn keeps_junk_requests_from_scanners() {
        let line = r#"203.0.113.7 - - [14/Nov/2026:17:33:27 +0200] "\x16\x03\x01\x00\xCA\x01" 400 157 "-" "-""#;
        let r = parser(COMBINED_FORMAT, &[], &[])
            .parse(line, &probes())
            .unwrap();
        assert_eq!(r.method, "-");
        assert_eq!(r.status, 400);
    }

    #[test]
    fn parses_iso_time_and_ipv6() {
        let format = r#"$remote_addr [$time_iso8601] "$request" $status"#;
        let line = r#"2001:db8::5 [2026-11-14T15:33:27+00:00] "POST /cart/ HTTP/2.0" 302"#;
        let r = parser(format, &[], &[]).parse(line, &probes()).unwrap();
        assert_eq!(r.ts, 1_794_670_407);
        assert_eq!(r.client_ip.to_string(), "2001:db8::5");
        assert_eq!(r.bytes, 0);
    }

    #[test]
    fn rejects_lines_that_do_not_match() {
        let p = parser(COMBINED_FORMAT, &[], &[]);
        assert!(p.parse("", &probes()).is_none());
        assert!(p.parse("not an access log line", &probes()).is_none());
        let bad_time = r#"192.0.2.1 - - [yesterday] "GET / HTTP/1.1" 200 1 "-" "-""#;
        assert!(p.parse(bad_time, &probes()).is_none());
    }

    #[test]
    fn rejects_bad_formats() {
        assert!(LogFormat::compile("no variables").is_err());
        assert!(LogFormat::compile("$remote_addr$status").is_err());
        assert!(LogFormat::compile("${remote_addr").is_err());
        assert!(Layout::new("$remote_addr $status", None).is_err());
    }

    #[test]
    fn needs_the_header_variable_when_proxies_are_trusted() {
        let source = NginxSource {
            name: "web".into(),
            path: PathBuf::from("/var/log/nginx/access.log"),
            format: COMBINED_FORMAT.into(),
            previous_formats: Vec::new(),
            site: None,
            logins: Vec::new(),
        };
        let real_ip = RealIpConfig {
            trusted_proxies: vec!["198.51.100.0/24".parse().unwrap()],
            header: ClientIpHeader::XForwardedFor,
        };
        let err = NginxParser::new(&source, &real_ip).err().unwrap();
        assert!(format!("{err:#}").contains("http_x_forwarded_for"));
    }

    #[test]
    fn keeps_the_query_of_probes_only() {
        let p = parser(COMBINED_FORMAT, &[], &[]);
        let line = |target: &str| {
            format!(
                r#"192.0.2.10 - - [14/Nov/2026:17:33:27 +0200] "GET {target} HTTP/1.1" 200 1 "-" "-""#
            )
        };
        let probe = p.parse(&line("/?file=../../.env"), &probes()).unwrap();
        assert_eq!(probe.path, "/");
        assert_eq!(probe.query.as_deref(), Some("file=../../.env"));
        let visit = p.parse(&line("/reset/?token=secret"), &probes()).unwrap();
        assert_eq!(visit.query, None);
    }

    #[test]
    fn turns_login_form_posts_into_events() {
        let p = parser(COMBINED_FORMAT, &[], &[]);
        let post = |status: u16| {
            let line = format!(
                r#"192.0.2.10 - - [14/Nov/2026:17:33:27 +0200] "POST /admin/login/?next=/admin/ HTTP/2.0" {status} 1 "-" "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) Safari/604.1""#
            );
            p.login(&p.parse(&line, &probes()).unwrap())
        };
        let ok = post(302).unwrap();
        assert_eq!(
            (ok.kind, ok.source.as_str()),
            (SecurityKind::Login, "Shop admin")
        );
        assert_eq!(ok.detail.as_deref(), Some("iPhone · Safari"));
        assert_eq!(post(200).unwrap().kind, SecurityKind::LoginFail);
        assert!(post(502).is_none());

        let get = r#"192.0.2.10 - - [14/Nov/2026:17:33:27 +0200] "GET /admin/login/ HTTP/2.0" 200 1 "-" "-""#;
        assert!(p.login(&p.parse(get, &probes()).unwrap()).is_none());

        // The code form after a right password is not a failure.
        let step = r#"192.0.2.10 - - [14/Nov/2026:17:33:27 +0200] "POST /app/login/ HTTP/2.0" 200 1 "-" "-""#;
        assert!(p.login(&p.parse(step, &probes()).unwrap()).is_none());
    }

    #[test]
    fn long_values_are_cut_on_a_char_boundary() {
        assert_eq!(truncate("ab€", 3), "ab");
        assert_eq!(truncate("abc", 10), "abc");
    }
}
