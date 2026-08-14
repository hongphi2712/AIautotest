use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};

use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};

type DirectLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// Per-host request rate limiting. Keeps one direct `governor` limiter per
/// host so pacing never blocks unrelated hosts.
pub struct HostRateLimiter {
    per_host_per_sec: u32,
    limiters: Mutex<HashMap<String, Arc<DirectLimiter>>>,
}

impl HostRateLimiter {
    /// Returns None when no per-host limit is configured (unlimited).
    pub fn new(per_host_per_sec: u32) -> Option<Self> {
        if per_host_per_sec == 0 {
            return None;
        }
        Some(Self {
            per_host_per_sec,
            limiters: Mutex::new(HashMap::new()),
        })
    }

    pub async fn until_ready(&self, host: &str) {
        let limiter = {
            let mut limiters = self
                .limiters
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            limiters
                .entry(host.to_owned())
                .or_insert_with(|| {
                    let quota = Quota::per_second(
                        NonZeroU32::new(self.per_host_per_sec).expect("rate > 0"),
                    );
                    Arc::new(RateLimiter::direct(quota))
                })
                .clone()
        };
        let _ = limiter.until_ready().await;
    }
}

#[cfg(test)]
mod tests {
    use super::HostRateLimiter;
    use std::time::Duration;

    #[tokio::test]
    async fn paces_requests() {
        let limiter = HostRateLimiter::new(15).unwrap();
        let started = std::time::Instant::now();
        for _ in 0..20 {
            limiter.until_ready("example.com").await;
        }
        assert!(
            started.elapsed() >= Duration::from_millis(250),
            "expected pacing, took {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn paces_concurrent_waiters() {
        let limiter = std::sync::Arc::new(HostRateLimiter::new(15).unwrap());
        let started = std::time::Instant::now();
        let mut handles = Vec::new();
        for _ in 0..4 {
            let limiter = limiter.clone();
            handles.push(tokio::spawn(async move {
                for _ in 0..9 {
                    limiter.until_ready("example.com").await;
                }
            }));
        }
        for handle in handles {
            handle.await.unwrap();
        }
        assert!(
            started.elapsed() >= Duration::from_millis(1200),
            "concurrent waiters should be paced, took {:?}",
            started.elapsed()
        );
    }
}
