//! Limits login attempts per client address, in memory.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

/// Addresses tracked at most; old windows are dropped first when full.
const MAX_TRACKED: usize = 10_000;

pub struct Limiter {
    attempts: u32,
    window: i64,
    seen: Mutex<HashMap<IpAddr, (u32, i64)>>,
}

impl Limiter {
    /// Allows `attempts` per `window` seconds for each address.
    pub fn new(attempts: u32, window: i64) -> Self {
        Self {
            attempts,
            window,
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Counts one attempt and says whether it may go ahead.
    pub fn allow(&self, ip: IpAddr, now: i64) -> bool {
        let Ok(mut seen) = self.seen.lock() else {
            return false;
        };
        if seen.len() >= MAX_TRACKED && !seen.contains_key(&ip) {
            seen.retain(|_, (_, start)| now - *start < self.window);
            if seen.len() >= MAX_TRACKED {
                return false;
            }
        }
        let (count, start) = seen.entry(ip).or_insert((0, now));
        if now - *start >= self.window {
            (*count, *start) = (0, now);
        }
        *count += 1;
        *count <= self.attempts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([192, 0, 2, last])
    }

    #[test]
    fn blocks_after_the_limit_until_the_window_ends() {
        let limiter = Limiter::new(3, 60);
        assert!((0..3).all(|_| limiter.allow(ip(1), 1000)));
        assert!(!limiter.allow(ip(1), 1001));
        assert!(
            limiter.allow(ip(2), 1001),
            "other addresses are not affected"
        );
        assert!(limiter.allow(ip(1), 1060));
    }

    #[test]
    fn stays_bounded() {
        let limiter = Limiter::new(1, 60);
        for i in 0..MAX_TRACKED as u32 {
            limiter.allow(IpAddr::from(i.to_be_bytes()), 0);
        }
        assert!(
            !limiter.allow(ip(9), 10),
            "full table refuses new addresses"
        );
        assert!(limiter.allow(ip(9), 100), "expired entries make room");
    }
}
