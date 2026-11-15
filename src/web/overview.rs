//! The overview page: a status, a summary of the range and the items that
//! need attention.

use std::collections::{BTreeMap, HashMap, HashSet};

use anyhow::Result;

use super::view::{
    self, AnsweredRow, AttackRow, LoginRow, Notice, OverviewPanel, Range, SummaryRow,
};
use crate::clock::{self, DAY};
use crate::geoip::GeoIp;
use crate::health::Health;
use crate::probes::{self, Outcome, ProbeMatcher};
use crate::store::Store;
use crate::store::insights::Login;
use crate::store::queries::Counted;

/// What the overview needs besides the database.
pub struct Context<'a> {
    pub geo: &'a GeoIp,
    pub probes: &'a ProbeMatcher,
    pub ssh_keys: &'a BTreeMap<String, String>,
    /// Login forms used by customers, not by the site's own team.
    pub customer_apps: &'a HashSet<String>,
    /// How far back stored logins go, to tell new devices from known ones.
    pub raw_days: u32,
}

/// Per day: more failed sign-ins than this looks like password guessing.
const GUESSING: u64 = 10;
const GUESSING_DASHBOARD: u64 = 3;
/// Per day: more 5xx answers than this is worth a look.
const SERVER_ERRORS: u64 = 10;
/// At most this many new sign-in notices; the table marks the rest.
const NEW_NOTICES: usize = 3;

pub fn panel(store: &Store, cx: &Context, range: Range, health: &Health) -> Result<OverviewPanel> {
    let now = clock::now();
    let since = now - range.seconds();
    // Limits are per day, so a long range is not alarming for being long.
    let days = (range.seconds() / DAY).max(1).unsigned_abs();
    let mut notices = Vec::new();
    let mut summary = Vec::new();
    let mut row = |label: &'static str, value: String| summary.push(SummaryRow { label, value });

    let visitors = store.visitors(since)?;
    row(
        "Visitors",
        format!(
            "{} ({} page views)",
            view::count(visitors.people),
            view::count(visitors.pages)
        ),
    );

    let (attacks, totals) = attacks(store, since)?;
    let all: u64 = totals.iter().sum();
    row(
        "Attack requests",
        if all == 0 {
            "0".into()
        } else {
            format!(
                "{} ({} stopped, {} served)",
                view::count(all),
                view::count(all - totals[3]),
                view::count(totals[3])
            )
        },
    );
    let answered = answered(store, cx, since, now, &mut notices)?;

    let kinds: HashMap<String, u64> = store
        .security_summary(since)?
        .into_iter()
        .map(|c| (c.name, c.count))
        .collect();
    let n = |kind: &str| kinds.get(kind).copied().unwrap_or(0);
    row(
        "SSH",
        format!(
            "{} failed logins, {} bans",
            view::count(n("ssh_fail")),
            view::count(n("ban"))
        ),
    );
    let mut firewall = format!("{} blocked", view::count(n("fw_block")));
    if let Some(port) = store.blocked_ports(since)?.first() {
        firewall.push_str(&format!(", top port {}", port_name(&port.name)));
    }
    row("Firewall", firewall);

    let sign_ins = logins(store, cx, since, now, &mut notices)?;
    let total: u64 = sign_ins.per_app.iter().map(|(_, n)| n).sum();
    let mut sign_in_text = view::count(total);
    if total > 0 {
        let parts: Vec<String> = sign_ins
            .per_app
            .iter()
            .map(|(app, n)| format!("{app} {n}"))
            .collect();
        sign_in_text.push_str(&format!(" ({})", parts.join(", ")));
    }
    row("Sign-ins", sign_in_text);
    if !sign_ins.customers.is_empty() {
        let parts: Vec<String> = sign_ins
            .customers
            .iter()
            .map(|(app, n)| format!("{app} {n}"))
            .collect();
        row("Customer sign-ins", parts.join(", "));
    }
    for failed in store.failed_logins(since)? {
        let per_day = if failed.name == "core-pulse" {
            GUESSING_DASHBOARD
        } else {
            GUESSING
        };
        if failed.count >= per_day * days {
            notices.push(Notice::warn(format!(
                "Repeated failed sign-ins on {}: {}",
                failed.name,
                view::count(failed.count)
            )));
        }
    }

    let failures = store.failed_services(since)?;
    for failure in &failures {
        if !failure.recovered() {
            notices.push(Notice::warn(format!(
                "{} failed {}× ({}), last {}",
                failure.name,
                view::count(failure.count),
                failure.detail,
                view::time(failure.last, now)
            )));
        }
    }
    if !failures.is_empty() {
        let parts: Vec<String> = failures
            .iter()
            .map(|f| match f.last_ok.filter(|_| f.recovered()) {
                Some(ok) => format!("{} {}×, recovered {}", f.name, f.count, view::time(ok, now)),
                None => format!("{} {}×", f.name, f.count),
            })
            .collect();
        row("Failed services", parts.join("; "));
    }

    let errors = store.server_errors(since)?;
    let error_count: u64 = errors.iter().map(|e| e.count).sum();
    if let Some(worst) = errors.first() {
        let text = format!("{} (top {})", view::count(error_count), worst.name);
        if error_count >= SERVER_ERRORS * days {
            notices.push(Notice::warn(format!("HTTP 5xx responses: {text}")));
        }
        row("HTTP 5xx", text);
    }

    let countries = if cx.geo.available() {
        let top = attack_countries(store, cx.geo, since)?;
        if !top.is_empty() {
            let names: Vec<&str> = top.iter().take(3).map(|c| c.name.as_str()).collect();
            row("Top attack sources", names.join(", "));
        }
        Some(view::bars("Attack sources", &top))
    } else {
        None
    };

    row("Server", health_line(health, &mut notices));

    let level = notices
        .iter()
        .map(|n| n.level)
        .max()
        .unwrap_or(view::Level::Ok);
    Ok(OverviewPanel {
        range,
        level,
        headline: level.headline(),
        notices,
        summary,
        logins: sign_ins.rows,
        attacks,
        answered,
        countries,
        health: health_stats(health),
    })
}

/// Attack requests per kind, and totals per outcome: blocked, not found,
/// redirected, served, error.
fn attacks(store: &Store, since: i64) -> Result<(Vec<AttackRow>, [u64; 5])> {
    let mut rules: BTreeMap<String, [u64; 5]> = BTreeMap::new();
    for (rule, status, count) in store.probe_outcomes(since)? {
        let slot = match probes::outcome(status) {
            Outcome::Blocked => 0,
            Outcome::NotFound => 1,
            Outcome::Redirected => 2,
            Outcome::Answered => 3,
            Outcome::Failed => 4,
        };
        rules.entry(rule).or_default()[slot] += count;
    }
    let mut total = [0u64; 5];
    for counts in rules.values() {
        for (sum, n) in total.iter_mut().zip(counts) {
            *sum += n;
        }
    }
    let mut rows: Vec<AttackRow> = rules
        .iter()
        .map(|(rule, c)| {
            let (title, explain) = probes::describe(rule);
            AttackRow {
                title: title.to_string(),
                explain,
                tries: view::count(c.iter().sum()),
                stopped: view::count(c[0] + c[1] + c[2] + c[4]),
                answered: view::count(c[3]),
                sort: c.iter().sum(),
            }
        })
        .collect();
    rows.sort_by_key(|row| std::cmp::Reverse(row.sort));
    Ok((rows, total))
}

/// Attack requests answered with 2xx. When only the query string matched a
/// rule, the normal page was served and the payload ignored; when the path
/// itself matched, the resource may really be exposed.
fn answered(
    store: &Store,
    cx: &Context,
    since: i64,
    now: i64,
    notices: &mut Vec<Notice>,
) -> Result<Vec<AnsweredRow>> {
    // The same request from many sources is one row.
    let mut groups: Vec<(String, u16, bool, u64, i64, HashSet<String>)> = Vec::new();
    for r in store.answered_probes(since, 500)? {
        let request = format!("{} {}", r.method, view::target(&r.path, r.query.as_deref()));
        match groups
            .iter_mut()
            .find(|g| g.0 == request && g.1 == r.status)
        {
            Some(group) => {
                group.3 += 1;
                group.5.insert(r.client_ip);
            }
            None => {
                let real = cx.probes.classify(&r.path).is_some();
                if real {
                    notices.push(Notice::bad(format!(
                        "Possibly exposed: {request} returned {}",
                        r.status
                    )));
                }
                groups.push((
                    request,
                    r.status,
                    real,
                    1,
                    r.ts,
                    HashSet::from([r.client_ip]),
                ));
            }
        }
    }
    groups.sort_by_key(|g| (!g.2, std::cmp::Reverse(g.3)));
    Ok(groups
        .into_iter()
        .take(15)
        .map(
            |(request, status, real, times, last, addresses)| AnsweredRow {
                last: view::time(last, now),
                request,
                times: view::count(times),
                addresses: view::count(addresses.len() as u64),
                status,
                meaning: if real {
                    "path matched"
                } else {
                    "query ignored"
                },
                real,
            },
        )
        .collect())
}

/// Sign-ins in the range: table rows, newest first with same-day repeats
/// grouped, and counts per app.
struct SignIns {
    rows: Vec<LoginRow>,
    per_app: Vec<(String, u64)>,
    customers: Vec<(String, u64)>,
}

/// Marks each sign-in whose device, key or country was not seen before for
/// that app. Customer logins are only counted.
fn logins(
    store: &Store,
    cx: &Context,
    since: i64,
    now: i64,
    notices: &mut Vec<Notice>,
) -> Result<SignIns> {
    let history = store.logins(now - i64::from(cx.raw_days) * DAY)?;
    let mut seen: HashMap<String, (HashSet<String>, HashSet<String>)> = HashMap::new();
    let mut sign_ins = SignIns {
        rows: Vec::new(),
        per_app: Vec::new(),
        customers: Vec::new(),
    };
    let mut new_ones = Vec::new();

    for login in &history {
        let what = app_name(login);
        if cx.customer_apps.contains(&login.source) {
            if login.ts >= since {
                bump(&mut sign_ins.customers, &what);
            }
            continue;
        }
        let (who, device) = who(login, cx.ssh_keys);
        let country = cx
            .geo
            .country(login.ip.parse().unwrap_or([0, 0, 0, 0].into()));
        let new = match seen.get(&login.source) {
            None => Some("first seen"),
            // Older records may lack the key or device; judge only once known.
            Some((devices, _))
                if !devices.is_empty() && device.as_ref().is_some_and(|d| !devices.contains(d)) =>
            {
                Some(if login.kind == "ssh_login" {
                    "new key"
                } else {
                    "new device"
                })
            }
            Some((_, countries))
                if country
                    .as_ref()
                    .is_some_and(|c| !countries.contains(&c.code)) =>
            {
                Some("new country")
            }
            _ => None,
        };
        let entry = seen.entry(login.source.clone()).or_default();
        entry.0.extend(device);
        entry.1.extend(country.as_ref().map(|c| c.code.clone()));

        if login.ts < since {
            continue;
        }
        bump(&mut sign_ins.per_app, &what);
        let place = country.map_or_else(|| login.ip.clone(), |c| c.name);
        let time = view::time(login.ts, now);
        if let Some(reason) = new {
            new_ones.push(format!(
                "Sign-in on {what} ({reason}): {who}, {place}, {time}"
            ));
        }
        let day = view::day(login.ts);
        match sign_ins.rows.last_mut() {
            Some(last)
                if new.is_none()
                    && last.new.is_empty()
                    && (last.day, &last.what, &last.who, &last.place)
                        == (day, &what, &who, &place) =>
            {
                last.times += 1;
                last.time = time;
            }
            _ => sign_ins.rows.push(LoginRow {
                first: time.clone(),
                time,
                times: 1,
                day,
                what,
                who,
                place,
                ip: login.ip.clone(),
                new: new.unwrap_or_default(),
            }),
        }
    }

    for text in new_ones.iter().rev().take(NEW_NOTICES) {
        notices.push(Notice::warn(text.clone()));
    }
    if new_ones.len() > NEW_NOTICES {
        notices.push(Notice::warn(format!(
            "{} more new sign-ins, marked in the table",
            new_ones.len() - NEW_NOTICES
        )));
    }
    sign_ins.rows.reverse();
    sign_ins.rows.truncate(30);
    Ok(sign_ins)
}

fn bump(counts: &mut Vec<(String, u64)>, name: &str) {
    match counts.iter_mut().find(|(n, _)| n == name) {
        Some((_, count)) => *count += 1,
        None => counts.push((name.to_string(), 1)),
    }
}

/// A readable "who" for a login, and the key or device that identifies it.
fn who(login: &Login, keys: &BTreeMap<String, String>) -> (String, Option<String>) {
    if login.kind != "ssh_login" {
        return (login.detail.clone(), Some(login.detail.clone()));
    }
    // "publickey as user, key SHA256:..."
    let (user, key) = match login.detail.split_once(", key ") {
        Some((head, key)) => (head, Some(key.to_string())),
        None => (login.detail.as_str(), None),
    };
    let user = user.split_once(" as ").map_or(user, |(_, u)| u);
    let who = match &key {
        Some(key) => match keys.get(key) {
            Some(name) => format!("{user} · {name}"),
            None => format!("{user} · {}…", &key[..key.len().min(15)]),
        },
        None => user.to_string(),
    };
    (who, key)
}

fn app_name(login: &Login) -> String {
    match (login.kind.as_str(), login.source.as_str()) {
        ("ssh_login", _) => "SSH".into(),
        (_, app) => app.into(),
    }
}

fn attack_countries(store: &Store, geo: &GeoIp, since: i64) -> Result<Vec<Counted>> {
    let mut per_country: HashMap<String, u64> = HashMap::new();
    for attacker in store.attackers(since)? {
        if let Some(country) = attacker.name.parse().ok().and_then(|ip| geo.country(ip)) {
            *per_country.entry(country.name).or_default() += attacker.count;
        }
    }
    let mut top: Vec<_> = per_country
        .into_iter()
        .map(|(name, count)| Counted { name, count })
        .collect();
    top.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
    top.truncate(10);
    Ok(top)
}

fn health_line(health: &Health, notices: &mut Vec<Notice>) -> String {
    let disk = health.disk_used_percent().unwrap_or(0);
    let memory = health.memory_used_percent().unwrap_or(0);
    match disk {
        90.. => notices.push(Notice::bad(format!("Disk {disk}% full"))),
        80..90 => notices.push(Notice::warn(format!("Disk {disk}% full"))),
        _ => {}
    }
    if memory >= 90 {
        notices.push(Notice::warn(format!("Memory {memory}% used")));
    }
    format!(
        "disk {disk}%, memory {memory}%, up {}",
        view::duration(health.uptime)
    )
}

fn health_stats(health: &Health) -> Vec<view::Stat> {
    let percent = |p: Option<u64>| p.map_or("-".to_string(), |p| format!("{p}%"));
    vec![
        view::Stat {
            label: "Disk used",
            value: percent(health.disk_used_percent()),
        },
        view::Stat {
            label: "Disk free",
            value: view::bytes(health.disk_free),
        },
        view::Stat {
            label: "Memory used",
            value: percent(health.memory_used_percent()),
        },
        view::Stat {
            label: "Load (1 min)",
            value: format!("{:.2} / {} cores", health.load, health.cpus),
        },
        view::Stat {
            label: "Uptime",
            value: view::duration(health.uptime),
        },
    ]
}

/// Country name, or nothing without a country database.
pub fn place(geo: &GeoIp, ip: &str) -> String {
    ip.parse()
        .ok()
        .and_then(|ip| geo.country(ip))
        .map(|c| c.name)
        .unwrap_or_default()
}

fn port_name(port: &str) -> String {
    let name = match port {
        "22" => "SSH",
        "23" => "Telnet",
        "25" => "SMTP",
        "445" => "SMB",
        "1433" => "MSSQL",
        "3306" => "MySQL",
        "3389" => "RDP",
        "5432" => "PostgreSQL",
        "5900" => "VNC",
        "6379" => "Redis",
        "8080" | "8443" => "HTTP alt",
        "9200" => "Elasticsearch",
        "25565" | "19132" => "Minecraft",
        _ => return port.to_string(),
    };
    format!("{port} ({name})")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{SecurityEvent, SecurityKind};
    use crate::probes::default_rules;
    use crate::store::Retention;
    use crate::store::tests::{batch, request};

    const KEEP: Retention = Retention {
        raw_days: 90,
        hourly_days: 365,
        max_bytes: u64::MAX,
    };

    fn login(ts: i64, key: &str, ip: &str) -> SecurityEvent {
        SecurityEvent {
            ts,
            kind: SecurityKind::SshLogin,
            source: "sshd".into(),
            ip: ip.parse().unwrap(),
            port: None,
            detail: Some(format!("publickey as admin, key {key}")),
        }
    }

    fn overview(store: &Store, keys: &BTreeMap<String, String>) -> OverviewPanel {
        let probes = ProbeMatcher::new(&default_rules()).unwrap();
        let cx = Context {
            geo: &GeoIp::demo(),
            probes: &probes,
            ssh_keys: keys,
            customer_apps: &HashSet::from(["Shop customers".to_string()]),
            raw_days: 90,
        };
        panel(store, &cx, Range::Day, &Health::default()).unwrap()
    }

    fn value<'a>(panel: &'a OverviewPanel, label: &str) -> Option<&'a str> {
        panel
            .summary
            .iter()
            .find(|r| r.label == label)
            .map(|r| r.value.as_str())
    }

    #[test]
    fn quiet_day_has_no_issues() {
        let store = Store::open_in_memory().unwrap();
        let panel = overview(&store, &BTreeMap::new());
        assert_eq!(panel.level, view::Level::Ok);
        assert_eq!(value(&panel, "Sign-ins"), Some("0"));
    }

    #[test]
    fn flags_a_new_ssh_key_but_not_a_known_one() {
        let mut store = Store::open_in_memory().unwrap();
        let now = clock::now();
        let mut customer = login(now - 200, "", "192.0.2.50");
        customer.kind = SecurityKind::Login;
        customer.source = "Shop customers".into();
        let events = vec![
            login(now - 10 * DAY, "SHA256:laptop", "192.0.2.10"),
            login(now - 700, "SHA256:laptop", "192.0.2.10"),
            login(now - 600, "SHA256:laptop", "192.0.2.10"),
            login(now - 300, "SHA256:stranger", "192.0.2.10"),
            customer,
        ];
        store.save(&batch(vec![], events), now, &KEEP).unwrap();
        let keys = BTreeMap::from([("SHA256:laptop".to_string(), "laptop".to_string())]);
        let panel = overview(&store, &keys);

        // Two laptop logins share a row; the customer is only counted.
        assert_eq!(panel.logins.len(), 2);
        assert_eq!(panel.logins[0].new, "new key");
        assert_eq!(
            (panel.logins[1].who.as_str(), panel.logins[1].times),
            ("admin · laptop", 2)
        );
        assert_eq!(panel.level, view::Level::Warn);
        assert_eq!(value(&panel, "Sign-ins"), Some("3 (SSH 3)"));
        assert_eq!(value(&panel, "Customer sign-ins"), Some("Shop customers 1"));
    }

    #[test]
    fn a_path_probe_that_was_served_is_bad() {
        let mut store = Store::open_in_memory().unwrap();
        let now = clock::now();
        let mut ignored = request(now - 60, "curl");
        ignored.query = Some("file=../../.env".into());
        ignored.probe = Some("env-file".into());
        let mut leaked = request(now - 30, "curl");
        leaked.path = "/.env".into();
        leaked.probe = Some("env-file".into());
        store
            .save(&batch(vec![ignored.clone()], vec![]), now, &KEEP)
            .unwrap();
        assert_ne!(overview(&store, &BTreeMap::new()).level, view::Level::Bad);

        store
            .save(&batch(vec![leaked], vec![]), now, &KEEP)
            .unwrap();
        let panel = overview(&store, &BTreeMap::new());
        assert_eq!(panel.level, view::Level::Bad);
        assert!(panel.answered.iter().any(|a| a.real));
        assert!(panel.answered.iter().any(|a| !a.real));
    }

    #[test]
    fn names_well_known_ports() {
        assert_eq!(port_name("3389"), "3389 (RDP)");
        assert_eq!(port_name("4444"), "4444");
    }
}
