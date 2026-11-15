//! The server's vital signs, read when a page needs them: disk, memory,
//! load and uptime. All from /proc and statvfs, no privileges needed.

use std::path::Path;

#[derive(Debug, Default, Clone)]
pub struct Health {
    pub disk_total: u64,
    pub disk_free: u64,
    pub memory_total: u64,
    pub memory_available: u64,
    /// One-minute load average.
    pub load: f64,
    pub cpus: usize,
    /// Seconds since boot.
    pub uptime: u64,
}

impl Health {
    pub fn read(disk: &Path) -> Self {
        let mut health = Self {
            cpus: std::thread::available_parallelism().map_or(1, |n| n.get()),
            ..Self::default()
        };
        if let Ok(fs) = rustix::fs::statvfs(disk) {
            health.disk_total = fs.f_blocks.saturating_mul(fs.f_frsize);
            health.disk_free = fs.f_bavail.saturating_mul(fs.f_frsize);
        }
        if let Ok(text) = std::fs::read_to_string("/proc/meminfo") {
            (health.memory_total, health.memory_available) = parse_meminfo(&text);
        }
        let first = |file: &str| -> Option<f64> {
            std::fs::read_to_string(file)
                .ok()?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        };
        health.load = first("/proc/loadavg").unwrap_or(0.0);
        health.uptime = first("/proc/uptime").map_or(0, |s| s as u64);
        health
    }

    /// Made-up numbers for demo mode, so screenshots never show a real machine.
    pub fn demo() -> Self {
        const GB: u64 = 1024 * 1024 * 1024;
        Self {
            disk_total: 120 * GB,
            disk_free: 81 * GB,
            memory_total: 4 * GB,
            memory_available: 3 * GB,
            load: 0.24,
            cpus: 2,
            uptime: 12 * 86_400,
        }
    }

    pub fn disk_used_percent(&self) -> Option<u64> {
        percent_used(self.disk_total, self.disk_free)
    }

    pub fn memory_used_percent(&self) -> Option<u64> {
        percent_used(self.memory_total, self.memory_available)
    }
}

fn percent_used(total: u64, free: u64) -> Option<u64> {
    (total > 0).then(|| total.saturating_sub(free) * 100 / total)
}

/// MemTotal and MemAvailable in bytes.
fn parse_meminfo(text: &str) -> (u64, u64) {
    let field = |name: &str| -> u64 {
        text.lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|kb| kb.parse::<u64>().ok())
            .map_or(0, |kb| kb * 1024)
    };
    (field("MemTotal:"), field("MemAvailable:"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_memory_numbers() {
        let text = "MemTotal:        8000000 kB\nMemFree:  100 kB\nMemAvailable:    6000000 kB\n";
        assert_eq!(parse_meminfo(text), (8_192_000_000, 6_144_000_000));
    }

    #[test]
    fn computes_percent_used() {
        assert_eq!(percent_used(200, 50), Some(75));
        assert_eq!(percent_used(0, 0), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reads_this_machine() {
        let health = Health::read(Path::new("/"));
        assert!(health.disk_total > 0 && health.memory_total > 0);
        assert!(health.cpus >= 1);
    }
}
