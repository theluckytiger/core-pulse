//! Bandwidth per interface and live TCP connections, read from /proc every
//! few seconds. No packet capture and no extra privileges.
//!
//! Containers are found through their processes' cgroups, and their own
//! network view is read from /proc/<pid>/net. Process names of sockets owned
//! by other users would need root, so those show the owning user instead.

mod procfs;

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::sync::mpsc;

use crate::clock;
use crate::ingest::Message;
use crate::store::rollup::{NET_CT_RX, NET_CT_TX, NET_RX, NET_TX};
use crate::store::{Batch, Counter};
use procfs::{Socket, TcpState};

pub const SAMPLE_EVERY: Duration = Duration::from_secs(10);
/// Samples kept for the live chart: one hour.
const HISTORY: usize = 360;
const MAX_CONNECTIONS: usize = 300;
/// Samples between two writes of the hourly byte totals.
const SAMPLES_PER_SAVE: usize = 6;

#[derive(Debug, Clone, Default)]
pub struct Rate {
    pub name: String,
    /// Bytes per second over the last sample.
    pub rx: u64,
    pub tx: u64,
}

/// Connections with the same owner, direction and remote end, counted together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    pub owner: String,
    pub inbound: bool,
    pub remote: String,
    /// Local port for inbound connections, remote port for outbound ones.
    pub port: u16,
    pub count: usize,
}

/// What the network page shows. Replaced after every sample.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub updated: i64,
    pub interfaces: Vec<Rate>,
    pub containers: Vec<Rate>,
    pub connections: Vec<Connection>,
    /// (time, bytes/s in, bytes/s out) on the uplink interfaces, newest last.
    pub history: VecDeque<(i64, u64, u64)>,
    /// The same per container, keyed by its label.
    pub container_history: HashMap<String, VecDeque<(i64, u64, u64)>>,
}

/// Bytes moved since the previous sample by one interface or container.
struct Moved {
    name: String,
    rx: u64,
    tx: u64,
    container: bool,
}

pub type Live = Arc<RwLock<Snapshot>>;

/// Interfaces that carry traffic to and from the outside, as opposed to
/// loopback and the virtual ones Docker and VMs create.
pub fn is_uplink(name: &str) -> bool {
    const VIRTUAL: [&str; 7] = ["lo", "veth", "docker", "br-", "virbr", "vnet", "cni"];
    !VIRTUAL.iter().any(|prefix| name.starts_with(prefix))
}

struct Sampler {
    proc: PathBuf,
    users: HashMap<u32, String>,
    own_uid: Option<u32>,
    /// Last counters per interface or container, with when they were read.
    previous: HashMap<String, (i64, u64, u64)>,
    history: VecDeque<(i64, u64, u64)>,
    container_history: HashMap<String, VecDeque<(i64, u64, u64)>>,
}

impl Sampler {
    fn new(proc: &Path) -> Self {
        let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
        let own_uid = std::fs::read_to_string(proc.join("self/status"))
            .ok()
            .and_then(|status| {
                status
                    .lines()
                    .find_map(|l| l.strip_prefix("Uid:"))?
                    .split_whitespace()
                    .next()?
                    .parse()
                    .ok()
            });
        Self {
            proc: proc.to_path_buf(),
            users: procfs::user_names(&passwd),
            own_uid,
            previous: HashMap::new(),
            history: VecDeque::with_capacity(HISTORY),
            container_history: HashMap::new(),
        }
    }

    /// Reads everything once. Returns the new snapshot and the bytes moved per
    /// interface and container since the previous sample.
    fn sample(&mut self, now: i64) -> (Snapshot, Vec<Moved>) {
        let host = procfs::parse_dev(&self.read("net/dev"));
        let mut moved = Vec::new();
        let mut interfaces = Vec::new();
        for c in &host {
            if c.name == "lo" {
                continue;
            }
            let (rate, delta) = self.rate(&c.name, now, c.rx, c.tx);
            interfaces.push(rate);
            if let Some((rx, tx)) = delta {
                moved.push(Moved {
                    name: c.name.clone(),
                    rx,
                    tx,
                    container: false,
                });
            }
        }

        let containers = procfs::containers(&self.proc);
        let mut container_rates = Vec::new();
        let mut sockets: Vec<(String, Vec<Socket>)> =
            vec![(String::new(), self.sockets(&self.proc.join("net")))];
        for container in &containers {
            let label = format!("{} ({})", container.program, container.id);
            let net = self.proc.join(container.pid.to_string()).join("net");
            let dev =
                procfs::parse_dev(&std::fs::read_to_string(net.join("dev")).unwrap_or_default());
            let (rx, tx) = dev
                .iter()
                .filter(|c| c.name != "lo")
                .fold((0, 0), |(rx, tx), c| (rx + c.rx, tx + c.tx));
            let (rate, delta) = self.rate(&format!("container {}", container.id), now, rx, tx);
            let history = self.container_history.entry(label.clone()).or_default();
            if history.len() == HISTORY {
                history.pop_front();
            }
            history.push_back((now, rate.rx, rate.tx));
            if let Some((rx, tx)) = delta {
                moved.push(Moved {
                    name: label.clone(),
                    rx,
                    tx,
                    container: true,
                });
            }
            container_rates.push(rate.named(&label));
            sockets.push((label, self.sockets(&net)));
        }

        let (rx, tx) = interfaces
            .iter()
            .filter(|r| is_uplink(&r.name))
            .fold((0, 0), |(rx, tx), r| (rx + r.rx, tx + r.tx));
        if self.history.len() == HISTORY {
            self.history.pop_front();
        }
        self.history.push_back((now, rx, tx));

        // Forget interfaces and containers that are gone.
        let seen: HashSet<String> = host
            .iter()
            .map(|c| c.name.clone())
            .chain(containers.iter().map(|c| format!("container {}", c.id)))
            .collect();
        self.previous.retain(|key, _| seen.contains(key));
        let labels: HashSet<&String> = container_rates.iter().map(|r| &r.name).collect();
        self.container_history
            .retain(|label, _| labels.contains(label));

        let snapshot = Snapshot {
            updated: now,
            interfaces,
            containers: container_rates,
            connections: self.group(sockets),
            history: self.history.clone(),
            container_history: self.container_history.clone(),
        };
        (snapshot, moved)
    }

    /// Rate since the last reading, and the bytes moved. Counters that went
    /// down (an interface was recreated) start over without a delta.
    fn rate(&mut self, key: &str, now: i64, rx: u64, tx: u64) -> (Rate, Option<(u64, u64)>) {
        let previous = self.previous.insert(key.to_string(), (now, rx, tx));
        let delta = previous
            .filter(|(at, old_rx, old_tx)| now > *at && rx >= *old_rx && tx >= *old_tx)
            .map(|(at, old_rx, old_tx)| (rx - old_rx, tx - old_tx, (now - at).unsigned_abs()));
        let rate = Rate {
            name: key.to_string(),
            rx: delta.map_or(0, |(d, _, secs)| d / secs),
            tx: delta.map_or(0, |(_, d, secs)| d / secs),
        };
        (rate, delta.map(|(rx, tx, _)| (rx, tx)))
    }

    fn read(&self, relative: &str) -> String {
        std::fs::read_to_string(self.proc.join(relative)).unwrap_or_default()
    }

    fn sockets(&self, net: &Path) -> Vec<Socket> {
        ["tcp", "tcp6"]
            .iter()
            .flat_map(|file| {
                procfs::parse_tcp(&std::fs::read_to_string(net.join(file)).unwrap_or_default())
            })
            .collect()
    }

    /// Groups established connections per owner. `owner` is empty for the
    /// host, where the socket's user names it.
    fn group(&self, by_namespace: Vec<(String, Vec<Socket>)>) -> Vec<Connection> {
        let mut groups: HashMap<(String, bool, String, u16), usize> = HashMap::new();
        for (owner, sockets) in by_namespace {
            let listening: HashSet<u16> = sockets
                .iter()
                .filter(|s| s.state == TcpState::Listen)
                .map(|s| s.local.port())
                .collect();
            for socket in sockets.iter().filter(|s| s.state == TcpState::Established) {
                let owner = if owner.is_empty() {
                    self.owner(socket.uid)
                } else {
                    owner.clone()
                };
                let inbound = listening.contains(&socket.local.port());
                let port = if inbound {
                    socket.local.port()
                } else {
                    socket.remote.port()
                };
                *groups
                    .entry((owner, inbound, ip_of(socket.remote), port))
                    .or_default() += 1;
            }
        }
        let mut connections: Vec<Connection> = groups
            .into_iter()
            .map(|((owner, inbound, remote, port), count)| Connection {
                owner,
                inbound,
                remote,
                port,
                count,
            })
            .collect();
        connections.sort_by(|a, b| {
            b.count
                .cmp(&a.count)
                .then_with(|| a.owner.cmp(&b.owner))
                .then_with(|| a.remote.cmp(&b.remote))
        });
        connections.truncate(MAX_CONNECTIONS);
        connections
    }

    fn owner(&self, uid: u32) -> String {
        if Some(uid) == self.own_uid {
            return "core-pulse".into();
        }
        match self.users.get(&uid) {
            Some(name) => format!("user {name}"),
            None => format!("uid {uid}"),
        }
    }
}

impl Rate {
    fn named(mut self, name: &str) -> Self {
        self.name = name.to_string();
        self
    }
}

fn ip_of(addr: SocketAddr) -> String {
    addr.ip().to_string()
}

/// Samples until `stop` is set. Byte totals go to the writer once a minute.
pub fn run(live: Live, tx: mpsc::Sender<Message>, stop: Arc<AtomicBool>) {
    let mut sampler = Sampler::new(Path::new("/proc"));
    let mut pending: Vec<Counter> = Vec::new();
    let mut samples: usize = 0;

    while !stop.load(Ordering::Relaxed) {
        let now = clock::now();
        let (snapshot, moved) = sampler.sample(now);
        if let Ok(mut shared) = live.write() {
            *shared = snapshot;
        }
        for m in moved {
            let (rx_metric, tx_metric) = if m.container {
                (NET_CT_RX, NET_CT_TX)
            } else {
                (NET_RX, NET_TX)
            };
            pending.push(Counter {
                ts: now,
                metric: rx_metric,
                name: m.name.clone(),
                value: to_i64(m.rx),
            });
            pending.push(Counter {
                ts: now,
                metric: tx_metric,
                name: m.name,
                value: to_i64(m.tx),
            });
        }

        samples += 1;
        if samples.is_multiple_of(SAMPLES_PER_SAVE) && !save(&tx, &mut pending) {
            return;
        }
        // Sleep in short steps so a shutdown is not kept waiting.
        for _ in 0..SAMPLE_EVERY.as_secs() {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    save(&tx, &mut pending);
}

/// Sends the collected byte counts to the writer. False once it is gone.
fn save(tx: &mpsc::Sender<Message>, pending: &mut Vec<Counter>) -> bool {
    if pending.is_empty() {
        return true;
    }
    let batch = Batch {
        source: "network".into(),
        counters: std::mem::take(pending),
        ..Batch::default()
    };
    tx.blocking_send(Message::Save(batch)).is_ok()
}

fn to_i64(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

/// Made-up network data for demo mode, with documentation addresses only.
pub fn demo_snapshot(now: i64) -> Snapshot {
    let wave = |scale: u64| -> VecDeque<(i64, u64, u64)> {
        (0..HISTORY as i64)
            .map(|i| {
                let t = now - (HISTORY as i64 - i) * 10;
                let w = (i % 60) as u64;
                (t, (70 + w) * scale / 10, (900 + w * 12) * scale / 10)
            })
            .collect()
    };
    let history = wave(10);
    let container_history = [
        ("nginx (3f9c1a2b7d4e)", 9),
        ("gunicorn (8a71c0e2f5b9)", 6),
        ("postgres (c42d9e8b1a07)", 1),
    ]
    .into_iter()
    .map(|(name, scale)| (name.to_string(), wave(scale)))
    .collect();
    let rate = |name: &str, rx, tx| Rate {
        name: name.into(),
        rx,
        tx,
    };
    let connection = |owner: &str, inbound, remote: &str, port, count| Connection {
        owner: owner.into(),
        inbound,
        remote: remote.into(),
        port,
        count,
    };
    Snapshot {
        updated: now,
        interfaces: vec![
            rate("eth0", 95, 1_180),
            rate("br-app", 70, 1_020),
            rate("docker0", 0, 0),
        ],
        containers: vec![
            rate("nginx (3f9c1a2b7d4e)", 60, 1_050),
            rate("gunicorn (8a71c0e2f5b9)", 40, 700),
            rate("postgres (c42d9e8b1a07)", 5, 12),
        ],
        connections: vec![
            connection("nginx (3f9c1a2b7d4e)", true, "198.51.100.204", 443, 38),
            connection("nginx (3f9c1a2b7d4e)", true, "198.51.100.207", 443, 21),
            connection("gunicorn (8a71c0e2f5b9)", true, "192.0.2.80", 8000, 9),
            connection("gunicorn (8a71c0e2f5b9)", false, "203.0.113.40", 443, 2),
            connection("user root", true, "192.0.2.10", 22, 1),
            connection("core-pulse", true, "127.0.0.1", 8790, 1),
        ],
        history,
        container_history,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tells_uplinks_from_virtual_interfaces() {
        for name in ["eth0", "enp3s0", "wlan0", "ens18"] {
            assert!(is_uplink(name), "{name}");
        }
        for name in ["lo", "docker0", "br-1a2b3c", "veth12ab", "virbr0"] {
            assert!(!is_uplink(name), "{name}");
        }
    }

    #[test]
    fn computes_rates_and_handles_counter_resets() {
        let mut sampler = Sampler::new(Path::new("/nonexistent"));
        assert_eq!(sampler.rate("eth0", 100, 1000, 500).1, None);
        let (rate, moved) = sampler.rate("eth0", 110, 21_000, 10_500);
        assert_eq!((rate.rx, rate.tx), (2000, 1000));
        assert_eq!(moved, Some((20_000, 10_000)));
        // The interface was recreated and its counters started over.
        assert_eq!(sampler.rate("eth0", 120, 50, 50).1, None);
    }

    #[test]
    fn groups_connections_by_owner_and_remote_end() {
        let sampler = Sampler::new(Path::new("/nonexistent"));
        let socket = |local: &str, remote: &str, state| Socket {
            local: local.parse().unwrap(),
            remote: remote.parse().unwrap(),
            state,
            uid: 4242,
        };
        let sockets = vec![
            socket("0.0.0.0:443", "0.0.0.0:0", TcpState::Listen),
            socket("192.0.2.1:443", "203.0.113.5:40001", TcpState::Established),
            socket("192.0.2.1:443", "203.0.113.5:40002", TcpState::Established),
            socket("192.0.2.1:51000", "198.51.100.9:443", TcpState::Established),
        ];
        let groups = sampler.group(vec![("nginx (abc)".into(), sockets)]);
        assert_eq!(groups.len(), 2);
        assert_eq!(
            groups[0],
            Connection {
                owner: "nginx (abc)".into(),
                inbound: true,
                remote: "203.0.113.5".into(),
                port: 443,
                count: 2
            }
        );
        assert!(!groups[1].inbound);
        assert_eq!(groups[1].port, 443);
    }

    #[test]
    fn names_host_socket_owners() {
        let mut sampler = Sampler::new(Path::new("/nonexistent"));
        sampler.users.insert(0, "root".into());
        sampler.own_uid = Some(990);
        assert_eq!(sampler.owner(0), "user root");
        assert_eq!(sampler.owner(990), "core-pulse");
        assert_eq!(sampler.owner(12345), "uid 12345");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn samples_this_machine() {
        let mut sampler = Sampler::new(Path::new("/proc"));
        let (first, _) = sampler.sample(1000);
        assert!(!first.interfaces.is_empty() || std::fs::metadata("/proc/net/dev").is_err());
        let (_, moved) = sampler.sample(1010);
        assert!(moved.iter().all(|m| m.name != "lo"));
    }
}
