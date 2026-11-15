//! Templates and the small view models they render. Askama escapes every
//! value, which matters here: paths and user agents come from attackers.

use askama::Template;
use chrono::{Local, TimeZone};

use super::assets;
use crate::clock::{DAY, HOUR, MINUTE};
use crate::store::queries::Counted;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Range {
    Live,
    Day,
    Week,
    Month,
    Quarter,
}

impl Range {
    pub const ALL: [Range; 5] = [
        Self::Live,
        Self::Day,
        Self::Week,
        Self::Month,
        Self::Quarter,
    ];

    pub fn parse(value: Option<&str>) -> Self {
        Self::ALL
            .into_iter()
            .find(|r| Some(r.param()) == value)
            .unwrap_or(Self::Live)
    }

    pub fn param(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Day => "24h",
            Self::Week => "7d",
            Self::Month => "30d",
            Self::Quarter => "90d",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Live => "Live",
            Self::Day => "24 hours",
            Self::Week => "7 days",
            Self::Month => "30 days",
            Self::Quarter => "90 days",
        }
    }

    pub fn seconds(self) -> i64 {
        match self {
            Self::Live => HOUR,
            Self::Day => DAY,
            Self::Week => 7 * DAY,
            Self::Month => 30 * DAY,
            Self::Quarter => 90 * DAY,
        }
    }

    pub fn bucket(self) -> i64 {
        match self {
            Self::Live => MINUTE,
            Self::Day | Self::Week => HOUR,
            Self::Month => 6 * HOUR,
            Self::Quarter => DAY,
        }
    }

    pub fn is_live(self) -> bool {
        self == Self::Live
    }
}

pub struct RangeLink {
    pub param: &'static str,
    pub label: &'static str,
    pub active: bool,
}

/// What every dashboard page shows around its panel.
pub struct Layout {
    pub base: String,
    pub user: String,
    pub csrf: String,
    pub page: &'static str,
    pub ranges: Vec<RangeLink>,
    pub demo: bool,
    pub version: &'static str,
    /// Countries are shown, so the data source must be credited.
    pub geo_credit: bool,
    /// Query string appended to the range links, such as "&container=x".
    pub extra: String,
}

/// The range buttons, with the current one marked.
pub fn range_links(current: Range, ranges: &[Range]) -> Vec<RangeLink> {
    ranges
        .iter()
        .map(|r| RangeLink {
            param: r.param(),
            label: r.label(),
            active: *r == current,
        })
        .collect()
}

pub struct Stat {
    pub label: &'static str,
    pub value: String,
}

/// A name with a count and its share of the largest count (0 to 100).
pub struct Bar {
    pub name: String,
    pub count: String,
    pub share: u64,
}

/// A titled list of bars, like "Top paths".
pub struct BarSection {
    pub title: &'static str,
    pub rows: Vec<Bar>,
}

pub fn bars(title: &'static str, rows: &[Counted]) -> BarSection {
    let max = rows.iter().map(|r| r.count).max().unwrap_or(0).max(1);
    let rows = rows
        .iter()
        .map(|r| Bar {
            name: r.name.clone(),
            count: count(r.count),
            share: r.count * 100 / max,
        })
        .collect();
    BarSection { title, rows }
}

pub struct ClientRow {
    pub ip: String,
    pub place: String,
    pub requests: String,
    pub probes: String,
    pub last_seen: String,
}

pub struct RequestRow {
    pub time: String,
    pub site: String,
    pub ip: String,
    pub place: String,
    pub method: String,
    /// Path, with the query string when one was kept.
    pub path: String,
    pub status: u16,
    pub class: &'static str,
    /// Plain name of the attack, empty for normal requests.
    pub probe: String,
    /// What the attack got, like "blocked".
    pub outcome: &'static str,
}

pub struct OffenderRow {
    pub ip: String,
    pub place: String,
    pub events: String,
    pub bans: String,
    pub last_seen: String,
}

pub struct EventRow {
    pub time: String,
    pub kind: &'static str,
    pub class: &'static str,
    pub source: String,
    pub ip: String,
    pub port: String,
    pub detail: String,
}

pub struct TrafficPanel {
    pub range: Range,
    pub stats: Vec<Stat>,
    pub chart: String,
    pub clients: Vec<ClientRow>,
    pub sections: Vec<BarSection>,
    pub recent: Vec<RequestRow>,
}

pub struct SecurityPanel {
    pub range: Range,
    pub stats: Vec<Stat>,
    pub chart: String,
    pub offenders: Vec<OffenderRow>,
    pub sections: Vec<BarSection>,
    pub events: Vec<EventRow>,
}

pub struct InterfaceRow {
    pub name: String,
    pub rx_now: String,
    pub tx_now: String,
    pub rx_total: String,
    pub tx_total: String,
}

pub struct ContainerRow {
    pub name: String,
    /// Query string that opens this container's view.
    pub link: String,
    pub active: bool,
    pub rx_now: String,
    pub tx_now: String,
    pub rx_total: String,
    pub tx_total: String,
}

pub struct ConnectionRow {
    pub owner: String,
    pub direction: &'static str,
    pub remote: String,
    pub port: String,
    pub count: String,
}

pub struct NetworkPanel {
    pub range: Range,
    /// The container shown, empty for the host.
    pub container: String,
    /// Extra query string that keeps the container across reloads.
    pub query: String,
    /// When /proc was last read.
    pub sampled: String,
    pub stats: Vec<Stat>,
    pub chart: String,
    pub interfaces: Vec<InterfaceRow>,
    pub containers: Vec<ContainerRow>,
    pub connections: Vec<ConnectionRow>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Ok,
    Warn,
    Bad,
}

impl Level {
    pub fn class(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Bad => "bad",
        }
    }

    pub fn headline(self) -> String {
        match self {
            Self::Ok => "No issues",
            Self::Warn => "Needs attention",
            Self::Bad => "Action required",
        }
        .into()
    }
}

pub struct Notice {
    pub level: Level,
    pub text: String,
}

impl Notice {
    pub fn warn(text: String) -> Self {
        Self {
            level: Level::Warn,
            text,
        }
    }

    pub fn bad(text: String) -> Self {
        Self {
            level: Level::Bad,
            text,
        }
    }
}

pub struct SummaryRow {
    pub label: &'static str,
    pub value: String,
}

pub struct LoginRow {
    /// The latest of the grouped sign-ins, and the first.
    pub time: String,
    pub first: String,
    pub times: u64,
    /// Local day, to group repeats only within a day.
    pub day: i32,
    /// What was signed in to: "the server (SSH)", "core-pulse", an app.
    pub what: String,
    /// User and device or key.
    pub who: String,
    pub place: String,
    pub ip: String,
    /// Why this login is new, empty when it is not.
    pub new: &'static str,
}

pub struct AttackRow {
    pub title: String,
    pub explain: &'static str,
    pub tries: String,
    /// Blocked, not found, redirected or errored.
    pub stopped: String,
    pub answered: String,
    pub sort: u64,
}

/// One kind of attack request that got a 2xx, with how often it came.
pub struct AnsweredRow {
    pub last: String,
    pub request: String,
    pub times: String,
    pub addresses: String,
    pub status: u16,
    pub meaning: &'static str,
    /// The attack itself was answered, not just ignored.
    pub real: bool,
}

pub struct OverviewPanel {
    pub range: Range,
    pub level: Level,
    pub headline: String,
    pub notices: Vec<Notice>,
    pub summary: Vec<SummaryRow>,
    pub logins: Vec<LoginRow>,
    pub attacks: Vec<AttackRow>,
    pub answered: Vec<AnsweredRow>,
    pub countries: Option<BarSection>,
    pub health: Vec<Stat>,
}

#[derive(Template)]
#[template(path = "overview.html")]
pub struct OverviewPage {
    pub layout: Layout,
    pub base: String,
    pub panel: OverviewPanel,
}

#[derive(Template)]
#[template(path = "_overview.html")]
pub struct OverviewFragment {
    pub panel: OverviewPanel,
}

#[derive(Template)]
#[template(path = "network.html")]
pub struct NetworkPage {
    pub layout: Layout,
    pub base: String,
    pub panel: NetworkPanel,
}

#[derive(Template)]
#[template(path = "_network.html")]
pub struct NetworkFragment {
    pub panel: NetworkPanel,
}

#[derive(Template)]
#[template(path = "traffic.html")]
pub struct TrafficPage {
    pub layout: Layout,
    pub base: String,
    pub panel: TrafficPanel,
}

#[derive(Template)]
#[template(path = "_traffic.html")]
pub struct TrafficFragment {
    pub panel: TrafficPanel,
}

#[derive(Template)]
#[template(path = "security.html")]
pub struct SecurityPage {
    pub layout: Layout,
    pub base: String,
    pub panel: SecurityPanel,
}

#[derive(Template)]
#[template(path = "_security.html")]
pub struct SecurityFragment {
    pub panel: SecurityPanel,
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginPage<'a> {
    base: &'a str,
    csrf: &'a str,
    error: Option<&'a str>,
    version: &'static str,
}

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorPage<'a> {
    message: &'a str,
}

pub fn login_page(base: &str, csrf: &str, error: Option<&str>) -> String {
    let page = LoginPage {
        base,
        csrf,
        error,
        version: assets::version(),
    };
    page.render().unwrap_or_else(|e| {
        tracing::error!("login template: {e}");
        String::from("Login is unavailable.")
    })
}

pub fn error_page(message: &str) -> String {
    ErrorPage { message }
        .render()
        .unwrap_or_else(|_| message.to_string())
}

/// Chart data for a `<script type="application/json">` block. Escaping `<`,
/// `>` and `&` keeps a value like "</script>" from ending the block early.
pub fn chart_json(value: &serde_json::Value) -> String {
    value
        .to_string()
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
}

pub fn count(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Local time; the date is left out for today.
pub fn time(ts: i64, now: i64) -> String {
    let Some(t) = Local.timestamp_opt(ts, 0).single() else {
        return "-".into();
    };
    let today = Local
        .timestamp_opt(now, 0)
        .single()
        .is_some_and(|n| n.date_naive() == t.date_naive());
    if today {
        t.format("%H:%M:%S").to_string()
    } else {
        t.format("%b %d %H:%M").to_string()
    }
}

/// "/?file=x" from a path and the query string kept for it.
pub fn target(path: &str, query: Option<&str>) -> String {
    match query {
        Some(query) => format!("{path}?{query}"),
        None => path.to_string(),
    }
}

/// The local calendar day of a timestamp, as a number.
pub fn day(ts: i64) -> i32 {
    use chrono::Datelike;
    Local
        .timestamp_opt(ts, 0)
        .single()
        .map_or(0, |t| t.date_naive().num_days_from_ce())
}

/// Percent-encodes everything but unreserved characters, for query strings.
pub fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// "38 days", "5 hours", "12 minutes".
pub fn duration(seconds: u64) -> String {
    let (n, unit) = match seconds {
        s if s >= 2 * 86_400 => (s / 86_400, "days"),
        s if s >= 2 * 3600 => (s / 3600, "hours"),
        s => (s / 60, "minutes"),
    };
    format!("{n} {unit}")
}

pub fn rate(bytes_per_second: u64) -> String {
    format!("{}/s", bytes(bytes_per_second))
}

/// "443 https" for well-known ports, the bare number otherwise.
pub fn port(port: u16) -> String {
    let name = match port {
        22 => "ssh",
        25 | 587 => "smtp",
        53 => "dns",
        80 => "http",
        443 => "https",
        993 => "imaps",
        3306 => "mysql",
        5432 => "postgres",
        6379 => "redis",
        _ => return port.to_string(),
    };
    format!("{port} {name}")
}

pub fn status_class(status: u16) -> &'static str {
    match status {
        444 => "drop",
        200..=299 => "ok",
        300..=399 => "redirect",
        400..=499 => "client",
        _ => "server",
    }
}

/// Label and style for a security event kind.
pub fn event_kind(kind: &str) -> (&'static str, &'static str) {
    match kind {
        "ban" => ("Ban", "bad"),
        "unban" => ("Unban", "muted"),
        "ssh_fail" => ("SSH failed", "warn"),
        "ssh_login" => ("SSH login", "ok"),
        "fw_block" => ("Firewall block", "muted"),
        "login" => ("Signed in", "ok"),
        "login_fail" => ("Sign-in failed", "warn"),
        _ => ("Other", "muted"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_numbers() {
        assert_eq!(count(0), "0");
        assert_eq!(count(999), "999");
        assert_eq!(count(1_234_567), "1,234,567");
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(5 * 1024 * 1024), "5.0 MB");
    }

    #[test]
    fn chart_json_cannot_close_its_script_tag() {
        let json = chart_json(&serde_json::json!({ "path": "</script><script>alert(1)</script>" }));
        assert!(!json.contains('<') && !json.contains('>'));
        let back: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(back["path"], "</script><script>alert(1)</script>");
    }

    #[test]
    fn encodes_query_values() {
        assert_eq!(url_encode("nginx (3f9c)"), "nginx%20%283f9c%29");
        assert_eq!(url_encode("a&b=c"), "a%26b%3Dc");
    }

    #[test]
    fn writes_targets_and_durations() {
        assert_eq!(target("/", Some("file=../../.env")), "/?file=../../.env");
        assert_eq!(target("/shop/", None), "/shop/");
        assert_eq!(duration(38 * 86_400 + 5), "38 days");
        assert_eq!(duration(5 * 3600), "5 hours");
        assert_eq!(duration(600), "10 minutes");
    }

    #[test]
    fn parses_ranges() {
        assert_eq!(Range::parse(Some("7d")), Range::Week);
        assert_eq!(Range::parse(Some("nonsense")), Range::Live);
        assert_eq!(Range::parse(None), Range::Live);
    }

    #[test]
    fn templates_escape_attacker_text() {
        let fragment = TrafficFragment {
            panel: TrafficPanel {
                range: Range::Live,
                stats: Vec::new(),
                chart: chart_json(&serde_json::json!({})),
                clients: Vec::new(),
                sections: vec![bars(
                    "Top paths",
                    &[Counted {
                        name: "/<script>alert(1)</script>".into(),
                        count: 1,
                    }],
                )],
                recent: Vec::new(),
            },
        };
        let html = fragment.render().unwrap();
        assert!(!html.contains("<script>alert"));
        assert!(
            html.contains("&lt;script&gt;alert(1)&lt;/script&gt;")
                || html.contains("&#60;script&#62;")
        );
    }
}
