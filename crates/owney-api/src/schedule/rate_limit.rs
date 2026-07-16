//! Minimal in-memory per-IP fixed-window rate limiter for the public booking
//! endpoints. Per-process state (resets on restart) — adequate for a
//! single-binary deployment; documented in docs/SCHEDULING.md.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// (window_start, hits) per (ip, action).
type Buckets = HashMap<(IpAddr, &'static str), (u64, u32)>;

#[derive(Debug, Default)]
pub struct RateLimiter {
    buckets: Mutex<Buckets>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one hit for (ip, action); false when over `limit` per `window_secs`.
    pub fn allow(&self, ip: IpAddr, action: &'static str, limit: u32, window_secs: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let window = now - now % window_secs;
        let mut buckets = self.buckets.lock().expect("rate limiter lock");
        if buckets.len() > 10_000 {
            buckets.retain(|_, (start, _)| *start + window_secs > now);
        }
        let entry = buckets.entry((ip, action)).or_insert((window, 0));
        if entry.0 != window {
            *entry = (window, 0);
        }
        entry.1 += 1;
        entry.1 <= limit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_the_window_limit() {
        let limiter = RateLimiter::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..10 {
            assert!(limiter.allow(ip, "book", 10, 3600));
        }
        assert!(!limiter.allow(ip, "book", 10, 3600), "11th call blocked");
        // Different action or IP is unaffected.
        assert!(limiter.allow(ip, "slots", 10, 3600));
        assert!(limiter.allow("10.0.0.2".parse().unwrap(), "book", 10, 3600));
    }
}
