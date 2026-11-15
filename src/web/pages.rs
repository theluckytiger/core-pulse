//! Dashboard pages and the fragments htmx reloads.

use askama::Template;
use axum::extract::{Extension, Query, State};
use axum::response::Html;
use chrono::{Local, Offset};
use serde::Deserialize;
use serde_json::json;

use super::overview::{self, place};
use super::session::CurrentUser;
use super::view::{self, Layout, NetworkPanel, Range, SecurityPanel, TrafficPanel};
use super::{AppError, AppState};
use crate::clock;
use crate::geoip::GeoIp;
use crate::health::Health;
use crate::net::{self, Snapshot};
use crate::probes;
use crate::store::Store;
use crate::store::queries::{Buckets, Counted, Series};

const TOP: usize = 12;
const RECENT: usize = 50;
const SECURITY_KINDS: [&str; 5] = ["ban", "unban", "ssh_fail", "ssh_login", "fw_block"];

#[derive(Deserialize)]
pub struct RangeQuery {
    range: Option<String>,
    /// Network page: show one container.
    container: Option<String>,
}

impl RangeQuery {
    fn container(&self) -> Option<String> {
        self.container
            .clone()
            .filter(|name| !name.is_empty() && name.len() <= 200)
    }
}

impl AppState {
    /// Ranges worth offering: no 90 days when raw events are kept shorter.
    fn ranges(&self) -> Vec<Range> {
        Range::ALL
            .into_iter()
            .filter(|r| r.seconds() <= i64::from(self.0.raw_days) * clock::DAY)
            .collect()
    }

    fn range(&self, query: &RangeQuery) -> Range {
        let range = Range::parse(query.range.as_deref());
        if self.ranges().contains(&range) {
            range
        } else {
            Range::Live
        }
    }

    fn layout(&self, user: &CurrentUser, page: &'static str, range: Range) -> Layout {
        Layout {
            base: self.0.base.clone(),
            user: user.username.clone(),
            csrf: user.csrf_token.clone(),
            page,
            ranges: view::range_links(range, &self.ranges()),
            demo: self.0.demo,
            version: super::assets::version(),
            geo_credit: self.0.geo.available(),
            extra: String::new(),
        }
    }

    fn overview_context(&self) -> overview::Context<'_> {
        overview::Context {
            geo: &self.0.geo,
            probes: &self.0.probes,
            ssh_keys: &self.0.ssh_keys,
            customer_apps: &self.0.customer_apps,
            raw_days: self.0.raw_days,
        }
    }

    /// The overview opens on the last 24 hours unless a range is asked for.
    fn overview_range(&self, query: &RangeQuery) -> Range {
        if query.range.is_none() {
            Range::Day
        } else {
            self.range(query)
        }
    }

    async fn overview_panel(&self, range: Range) -> Result<view::OverviewPanel, AppError> {
        let state = self.clone();
        self.db(move |store| {
            let health = if state.0.demo {
                Health::demo()
            } else {
                Health::read(std::path::Path::new("/"))
            };
            overview::panel(store, &state.overview_context(), range, &health)
        })
        .await
    }
}

pub async fn overview(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<RangeQuery>,
) -> Result<Html<String>, AppError> {
    let range = state.overview_range(&query);
    let panel = state.overview_panel(range).await?;
    let page = view::OverviewPage {
        layout: state.layout(&user, "overview", range),
        base: state.0.base.clone(),
        panel,
    };
    render(&page)
}

pub async fn overview_fragment(
    State(state): State<AppState>,
    Query(query): Query<RangeQuery>,
) -> Result<Html<String>, AppError> {
    let range = state.overview_range(&query);
    let panel = state.overview_panel(range).await?;
    render(&view::OverviewFragment { panel })
}

pub async fn traffic(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<RangeQuery>,
) -> Result<Html<String>, AppError> {
    let range = state.range(&query);
    let panel = state.traffic(range).await?;
    let page = view::TrafficPage {
        layout: state.layout(&user, "traffic", range),
        base: state.0.base.clone(),
        panel,
    };
    render(&page)
}

pub async fn traffic_fragment(
    State(state): State<AppState>,
    Query(query): Query<RangeQuery>,
) -> Result<Html<String>, AppError> {
    let range = state.range(&query);
    let panel = state.traffic(range).await?;
    render(&view::TrafficFragment { panel })
}

pub async fn security(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<RangeQuery>,
) -> Result<Html<String>, AppError> {
    let range = state.range(&query);
    let panel = state.security(range).await?;
    let page = view::SecurityPage {
        layout: state.layout(&user, "security", range),
        base: state.0.base.clone(),
        panel,
    };
    render(&page)
}

pub async fn security_fragment(
    State(state): State<AppState>,
    Query(query): Query<RangeQuery>,
) -> Result<Html<String>, AppError> {
    let range = state.range(&query);
    let panel = state.security(range).await?;
    render(&view::SecurityFragment { panel })
}

pub async fn network(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<RangeQuery>,
) -> Result<Html<String>, AppError> {
    let range = state.range(&query);
    let live = state.network_snapshot();
    let container = query.container();
    let panel = state
        .db(move |store| network_panel(store, &live, range, container.as_deref()))
        .await?;
    let mut layout = state.layout(&user, "network", range);
    layout.extra = panel.query.clone();
    let page = view::NetworkPage {
        layout,
        base: state.0.base.clone(),
        panel,
    };
    render(&page)
}

pub async fn network_fragment(
    State(state): State<AppState>,
    Query(query): Query<RangeQuery>,
) -> Result<Html<String>, AppError> {
    let range = state.range(&query);
    let live = state.network_snapshot();
    let container = query.container();
    let panel = state
        .db(move |store| network_panel(store, &live, range, container.as_deref()))
        .await?;
    render(&view::NetworkFragment { panel })
}

impl AppState {
    fn network_snapshot(&self) -> Snapshot {
        self.0.network.read().map(|s| s.clone()).unwrap_or_default()
    }

    async fn traffic(&self, range: Range) -> Result<TrafficPanel, AppError> {
        let state = self.clone();
        self.db(move |store| traffic_panel(store, &state.0.geo, range))
            .await
    }

    async fn security(&self, range: Range) -> Result<SecurityPanel, AppError> {
        let state = self.clone();
        self.db(move |store| security_panel(store, &state.0.geo, range))
            .await
    }
}

fn render(template: &impl Template) -> Result<Html<String>, AppError> {
    template
        .render()
        .map(Html)
        .map_err(|e| AppError(anyhow::anyhow!("template: {e}")))
}

fn buckets(range: Range, now: i64) -> Buckets {
    // Day-sized buckets start at local midnight.
    let offset = i64::from(Local::now().offset().fix().local_minus_utc());
    Buckets {
        since: now - range.seconds(),
        until: now,
        size: range.bucket(),
        offset,
    }
}

fn chart(series: &Series) -> String {
    let columns: Vec<_> = series
        .columns
        .iter()
        .map(|(name, values)| json!({ "name": name, "values": values }))
        .collect();
    view::chart_json(&json!({ "times": series.times, "series": columns }))
}

fn traffic_panel(store: &Store, geo: &GeoIp, range: Range) -> anyhow::Result<TrafficPanel> {
    let now = clock::now();
    let since = now - range.seconds();
    let summary = store.traffic_summary(since)?;
    let series = store.traffic_series(&buckets(range, now), range.is_live())?;

    let stats = vec![
        view::Stat {
            label: "Requests",
            value: view::count(summary.requests),
        },
        view::Stat {
            label: "Addresses",
            value: view::count(summary.clients),
        },
        view::Stat {
            label: "Attacks",
            value: view::count(summary.probes),
        },
        view::Stat {
            label: "Errors",
            value: view::count(summary.errors),
        },
        view::Stat {
            label: "Sent",
            value: view::bytes(summary.bytes),
        },
    ];
    let clients = store
        .top_clients(since, TOP)?
        .into_iter()
        .map(|c| view::ClientRow {
            place: place(geo, &c.ip),
            ip: c.ip,
            requests: view::count(c.requests),
            probes: view::count(c.probes),
            last_seen: view::time(c.last_seen, now),
        })
        .collect();
    let recent = store
        .recent_requests(since, !range.is_live(), RECENT)?
        .into_iter()
        .map(|r| view::RequestRow {
            time: view::time(r.ts, now),
            site: r.site,
            place: place(geo, &r.client_ip),
            ip: r.client_ip,
            method: r.method,
            path: view::target(&r.path, r.query.as_deref()),
            status: r.status,
            class: view::status_class(r.status),
            outcome: r
                .probe
                .as_ref()
                .map_or("", |_| probes::outcome(r.status).label()),
            probe: r
                .probe
                .as_deref()
                .map_or_else(String::new, |rule| probes::describe(rule).0.to_string()),
        })
        .collect();

    Ok(TrafficPanel {
        range,
        stats,
        chart: chart(&series),
        clients,
        sections: vec![
            view::bars(
                "Attacks by kind",
                &plain_rules(store.probe_rules(since, TOP)?),
            ),
            view::bars("Top paths", &store.top_paths(since, TOP)?),
            view::bars("Status codes", &store.status_codes(since, TOP)?),
            view::bars("Sites", &store.sites(since, TOP)?),
            view::bars("User agents", &store.top_user_agents(since, TOP)?),
        ],
        recent,
    })
}

/// Probe rule names swapped for their plain titles.
fn plain_rules(rules: Vec<Counted>) -> Vec<Counted> {
    rules
        .into_iter()
        .map(|c| Counted {
            name: probes::describe(&c.name).0.to_string(),
            count: c.count,
        })
        .collect()
}

fn security_panel(store: &Store, geo: &GeoIp, range: Range) -> anyhow::Result<SecurityPanel> {
    let now = clock::now();
    let since = now - range.seconds();
    let mut series =
        store.security_series(&buckets(range, now), range.is_live(), &SECURITY_KINDS)?;
    for (name, _) in &mut series.columns {
        *name = view::event_kind(name).0.to_string();
    }
    let summary = store.security_summary(since)?;
    let kind_count = |kind: &str| {
        summary
            .iter()
            .find(|c| c.name == kind)
            .map_or(0, |c| c.count)
    };

    let stats = vec![
        view::Stat {
            label: "Bans",
            value: view::count(kind_count("ban")),
        },
        view::Stat {
            label: "Active bans",
            value: view::count(store.active_bans()?),
        },
        view::Stat {
            label: "SSH failures",
            value: view::count(kind_count("ssh_fail")),
        },
        view::Stat {
            label: "Firewall blocks",
            value: view::count(kind_count("fw_block")),
        },
        view::Stat {
            label: "SSH logins",
            value: view::count(kind_count("ssh_login")),
        },
    ];
    let offenders = store
        .offenders(since, TOP)?
        .into_iter()
        .map(|o| view::OffenderRow {
            place: place(geo, &o.ip),
            ip: o.ip,
            events: view::count(o.events),
            bans: view::count(o.bans),
            last_seen: view::time(o.last_seen, now),
        })
        .collect();
    let events = store
        .recent_events(since, RECENT)?
        .into_iter()
        .map(|e| {
            let (kind, class) = view::event_kind(&e.kind);
            view::EventRow {
                time: view::time(e.ts, now),
                kind,
                class,
                source: e.source,
                ip: e.ip,
                port: e.port.map(|p| p.to_string()).unwrap_or_default(),
                detail: e.detail.unwrap_or_default(),
            }
        })
        .collect();

    Ok(SecurityPanel {
        range,
        stats,
        chart: chart(&series),
        offenders,
        sections: vec![
            view::bars("Top networks", &store.offending_networks(since, TOP)?),
            view::bars("Bans per jail", &store.bans_by_jail(since)?),
            view::bars("Failed sign-ins per app", &store.failed_logins(since)?),
        ],
        events,
    })
}

/// Network page for the host, or for one container when `container` names it.
fn network_panel(
    store: &Store,
    live: &Snapshot,
    range: Range,
    container: Option<&str>,
) -> anyhow::Result<NetworkPanel> {
    let now = clock::now();
    let since = now - range.seconds();
    let (rx_now, tx_now) = match container {
        Some(name) => live
            .containers
            .iter()
            .find(|c| c.name == name)
            .map_or((0, 0), |c| (c.rx, c.tx)),
        None => live
            .interfaces
            .iter()
            .filter(|r| net::is_uplink(&r.name))
            .fold((0, 0), |(rx, tx), r| (rx + r.rx, tx + r.tx)),
    };
    let connections: Vec<_> = live
        .connections
        .iter()
        .filter(|c| container.is_none_or(|name| c.owner == name))
        .collect();
    let open: usize = connections.iter().map(|c| c.count).sum();
    let container_totals = store.container_totals(since)?;
    let totals_of = |name: &str| {
        container_totals
            .iter()
            .find(|(n, _, _)| n == name)
            .map_or((0, 0), |(_, rx, tx)| (*rx, *tx))
    };

    let mut stats = vec![
        view::Stat {
            label: "In now",
            value: view::rate(rx_now),
        },
        view::Stat {
            label: "Out now",
            value: view::rate(tx_now),
        },
        view::Stat {
            label: "Connections",
            value: view::count(open as u64),
        },
    ];
    match container {
        Some(name) => {
            let (rx, tx) = totals_of(name);
            stats.push(view::Stat {
                label: "In (range)",
                value: view::bytes(rx),
            });
            stats.push(view::Stat {
                label: "Out (range)",
                value: view::bytes(tx),
            });
        }
        None => stats.push(view::Stat {
            label: "Containers",
            value: view::count(live.containers.len() as u64),
        }),
    }

    // The last hour comes from memory at 10 s steps; longer ranges from the
    // hourly totals, shown as an average rate per bucket.
    let chart = if range.is_live() {
        let empty = std::collections::VecDeque::new();
        let history = match container {
            Some(name) => live.container_history.get(name).unwrap_or(&empty),
            None => &live.history,
        };
        let times: Vec<i64> = history.iter().map(|(t, _, _)| *t).collect();
        let rx: Vec<u64> = history.iter().map(|(_, rx, _)| *rx).collect();
        let tx: Vec<u64> = history.iter().map(|(_, _, tx)| *tx).collect();
        view::chart_json(&json!({
            "times": times,
            "series": [{ "name": "in B/s", "values": rx }, { "name": "out B/s", "values": tx }],
        }))
    } else {
        let buckets = buckets(range, now);
        let mut series = match container {
            Some(name) => store.container_series(name, &buckets)?,
            None => store.network_series(&buckets)?,
        };
        let seconds = range.bucket().unsigned_abs();
        for (name, values) in &mut series.columns {
            name.push_str(" B/s");
            values.iter_mut().for_each(|v| *v /= seconds);
        }
        chart(&series)
    };

    let interfaces = if container.is_some() {
        Vec::new()
    } else {
        let totals = store.network_totals(since)?;
        live.interfaces
            .iter()
            .map(|r| {
                let (rx, tx) = totals
                    .iter()
                    .find(|(name, _, _)| *name == r.name)
                    .map_or((0, 0), |(_, rx, tx)| (*rx, *tx));
                view::InterfaceRow {
                    name: r.name.clone(),
                    rx_now: view::rate(r.rx),
                    tx_now: view::rate(r.tx),
                    rx_total: view::bytes(rx),
                    tx_total: view::bytes(tx),
                }
            })
            .collect()
    };

    // Running containers first, then ones that only have stored totals.
    let mut names: Vec<(String, u64, u64)> = live
        .containers
        .iter()
        .map(|c| (c.name.clone(), c.rx, c.tx))
        .collect();
    for (name, _, _) in &container_totals {
        if !names.iter().any(|(n, _, _)| n == name) {
            names.push((name.clone(), 0, 0));
        }
    }
    let containers = names
        .into_iter()
        .map(|(name, rx_now, tx_now)| {
            let (rx, tx) = totals_of(&name);
            view::ContainerRow {
                link: format!("container={}", view::url_encode(&name)),
                active: container == Some(name.as_str()),
                rx_now: view::rate(rx_now),
                tx_now: view::rate(tx_now),
                rx_total: view::bytes(rx),
                tx_total: view::bytes(tx),
                name,
            }
        })
        .collect();
    let connections = connections
        .iter()
        .map(|c| view::ConnectionRow {
            owner: c.owner.clone(),
            direction: if c.inbound { "in" } else { "out" },
            remote: c.remote.clone(),
            port: view::port(c.port),
            count: view::count(c.count as u64),
        })
        .collect();

    let sampled = if live.updated > 0 {
        view::time(live.updated, now)
    } else {
        "not yet".into()
    };

    Ok(NetworkPanel {
        range,
        container: container.unwrap_or_default().to_string(),
        query: container
            .map(|name| format!("&container={}", view::url_encode(name)))
            .unwrap_or_default(),
        sampled,
        stats,
        chart,
        interfaces,
        containers,
        connections,
    })
}
