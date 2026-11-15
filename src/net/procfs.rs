//! Parsers for /proc/net/dev and /proc/net/tcp{,6}, plus container discovery
//! through /proc/<pid>/cgroup. Everything here works without root.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

/// Byte counters of one network interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Counters {
    pub name: String,
    pub rx: u64,
    pub tx: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Established,
    Listen,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socket {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: TcpState,
    pub uid: u32,
}

/// /proc/net/dev: two header lines, then "name: rx_bytes ... tx_bytes ...".
pub fn parse_dev(text: &str) -> Vec<Counters> {
    text.lines()
        .skip(2)
        .filter_map(|line| {
            let (name, rest) = line.split_once(':')?;
            let fields: Vec<&str> = rest.split_whitespace().collect();
            Some(Counters {
                name: name.trim().to_string(),
                rx: fields.first()?.parse().ok()?,
                tx: fields.get(8)?.parse().ok()?,
            })
        })
        .collect()
}

/// /proc/net/tcp or tcp6: one header line, then one socket per line.
pub fn parse_tcp(text: &str) -> Vec<Socket> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let state = match *fields.get(3)? {
                "01" => TcpState::Established,
                "0A" => TcpState::Listen,
                _ => TcpState::Other,
            };
            Some(Socket {
                local: parse_addr(fields.get(1)?)?,
                remote: parse_addr(fields.get(2)?)?,
                state,
                uid: fields.get(7)?.parse().ok()?,
            })
        })
        .collect()
}

/// "0100007F:0050" is 127.0.0.1:80. The kernel prints each 32-bit word of
/// the address in host byte order, so the bytes come back with to_ne_bytes.
fn parse_addr(field: &str) -> Option<SocketAddr> {
    let (addr, port) = field.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let word = |i: usize| -> Option<[u8; 4]> {
        let hex = addr.get(i * 8..i * 8 + 8)?;
        Some(u32::from_str_radix(hex, 16).ok()?.to_ne_bytes())
    };
    let ip = match addr.len() {
        8 => IpAddr::V4(Ipv4Addr::from(word(0)?)),
        32 => {
            let mut bytes = [0u8; 16];
            for i in 0..4 {
                bytes[i * 4..i * 4 + 4].copy_from_slice(&word(i)?);
            }
            let v6 = Ipv6Addr::from(bytes);
            // Show IPv4 clients of dual-stack sockets as plain IPv4.
            v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4)
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// A running container, found through its processes' cgroups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Container {
    /// First 12 characters of the container id, as `docker ps` shows it.
    pub id: String,
    /// A process inside it; its /proc/<pid>/net shows the container's network.
    pub pid: u32,
    /// Name of its main program, such as "nginx".
    pub program: String,
}

/// The container id in a cgroup file, for Docker and Podman.
pub fn container_id(cgroup: &str) -> Option<String> {
    cgroup.lines().find_map(|line| {
        let path = line.rsplit(':').next()?;
        path.split('/').find_map(|part| {
            let id = part
                .strip_prefix("docker-")
                .or_else(|| part.strip_prefix("libpod-"))
                .and_then(|p| p.strip_suffix(".scope"))
                .unwrap_or(part);
            (id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()))
                .then(|| id[..12].to_string())
        })
    })
}

/// Lists containers by walking /proc. Shell wrappers are skipped when
/// naming the main program.
pub fn containers(proc: &Path) -> Vec<Container> {
    const WRAPPERS: [&str; 6] = ["sh", "bash", "dash", "tini", "dumb-init", "docker-init"];
    let mut found: HashMap<String, Vec<(u32, String)>> = HashMap::new();

    let Ok(entries) = std::fs::read_dir(proc) else {
        return Vec::new();
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(cgroup) = std::fs::read_to_string(entry.path().join("cgroup")) else {
            continue;
        };
        if let Some(id) = container_id(&cgroup) {
            let program = std::fs::read_to_string(entry.path().join("comm")).unwrap_or_default();
            found
                .entry(id)
                .or_default()
                .push((pid, program.trim().to_string()));
        }
    }

    let mut containers: Vec<Container> = found
        .into_iter()
        .map(|(id, mut processes)| {
            processes.sort();
            let pid = processes[0].0;
            let program = processes
                .iter()
                .find(|(_, name)| !WRAPPERS.contains(&name.as_str()))
                .unwrap_or(&processes[0])
                .1
                .clone();
            Container { id, pid, program }
        })
        .collect();
    containers.sort_by(|a, b| a.program.cmp(&b.program).then_with(|| a.id.cmp(&b.id)));
    containers
}

/// uid to user name, from /etc/passwd.
pub fn user_names(passwd: &str) -> HashMap<u32, String> {
    passwd
        .lines()
        .filter_map(|line| {
            let mut fields = line.split(':');
            let name = fields.next()?;
            let uid = fields.nth(1)?.parse().ok()?;
            Some((uid, name.to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEV: &str = "Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:    1000      10    0    0    0     0          0         0     1000      10    0    0    0     0       0          0
  eth0: 123456789 1200000    0   12    0     0          0       300 987654321 1500000    0    0    0     0       0          0
docker0:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
";

    // 192.0.2.10:443 <- 203.0.113.5:51544 established, and a listener on 127.0.0.1:8790.
    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:2256 00000000:0000 0A 00000000:00000000 00:00000000 00000000   998        0 18923 1 0000000000000000 100 0 0 10 0
   1: 0A0200C0:01BB 057100CB:C958 01 00000000:00000000 02:000A7B2C 00000000   101        0 21934 2 0000000000000000 20 4 30 10 -1
";

    // [2001:db8::5]:443 and an IPv4 client on a dual-stack socket.
    const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: B80D0120000000000000000005000000:01BB B80D0120000000000000000009000000:D431 01 00000000:00000000 00:00000000 00000000     0        0 1 1 0 20 4 30 10 -1
   1: 0000000000000000FFFF00000A0200C0:01BB 0000000000000000FFFF0000057100CB:C958 01 00000000:00000000 00:00000000 00000000     0        0 2 1 0 20 4 30 10 -1
";

    #[test]
    fn reads_interface_counters() {
        let counters = parse_dev(DEV);
        assert_eq!(counters.len(), 3);
        assert_eq!(
            counters[1],
            Counters {
                name: "eth0".into(),
                rx: 123_456_789,
                tx: 987_654_321
            }
        );
        assert_eq!(counters[2].name, "docker0");
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn reads_ipv4_sockets() {
        let sockets = parse_tcp(TCP);
        assert_eq!(sockets.len(), 2);
        assert_eq!(sockets[0].local.to_string(), "127.0.0.1:8790");
        assert_eq!(sockets[0].state, TcpState::Listen);
        assert_eq!(sockets[1].local.to_string(), "192.0.2.10:443");
        assert_eq!(sockets[1].remote.to_string(), "203.0.113.5:51544");
        assert_eq!(
            (sockets[1].state, sockets[1].uid),
            (TcpState::Established, 101)
        );
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn reads_ipv6_and_mapped_ipv4_sockets() {
        let sockets = parse_tcp(TCP6);
        assert_eq!(sockets[0].local.to_string(), "[2001:db8::5]:443");
        assert_eq!(sockets[0].remote.to_string(), "[2001:db8::9]:54321");
        assert_eq!(sockets[1].remote.to_string(), "203.0.113.5:51544");
    }

    #[test]
    fn skips_garbage() {
        assert!(parse_tcp("header\nnot a socket line\n").is_empty());
        assert!(parse_dev("a\nb\nbroken line\n").is_empty());
    }

    #[test]
    fn finds_container_ids_in_cgroups() {
        let id = "4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a";
        assert_eq!(
            container_id(&format!("0::/system.slice/docker-{id}.scope\n")).as_deref(),
            Some("4f3a2b1c0d9e")
        );
        assert_eq!(
            container_id(&format!("12:pids:/docker/{id}\n")).as_deref(),
            Some("4f3a2b1c0d9e")
        );
        assert_eq!(
            container_id(&format!("0::/machine.slice/libpod-{id}.scope\n")).as_deref(),
            Some("4f3a2b1c0d9e")
        );
        assert_eq!(
            container_id("0::/user.slice/user-1000.slice/session-4.scope\n"),
            None
        );
    }

    #[test]
    fn maps_uids_to_names() {
        let names = user_names(
            "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\n",
        );
        assert_eq!(names.get(&33).map(String::as_str), Some("www-data"));
        assert_eq!(names.get(&0).map(String::as_str), Some("root"));
    }
}
