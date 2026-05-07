// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;

pub struct RateLimiter {
    // MAX_CONNECTIONS bounds contention. One lock removes a dependency family.
    limits: Arc<Mutex<HashMap<u32, RateEntry>>>,
    cleanup_task: Option<JoinHandle<()>>,
}

struct RateEntry {
    last_reset: Instant,
    count: u32,
}

impl RateLimiter {
    pub fn new() -> Self {
        let limits = Arc::new(Mutex::new(HashMap::new()));

        // Entries older than 60s are dead — no traffic from that UID in a full
        // minute. Without cleanup, a slow DoS that rotates UIDs grows the table
        // without bound. Cleanup runs every 60s, so dead entries live 60–120s
        // past their last request.
        let limits_clone = limits.clone();
        let cleanup_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                Self::cleanup_stale(&limits_clone);
            }
        });

        Self {
            limits,
            cleanup_task: Some(cleanup_task),
        }
    }

    pub fn check(&self, uid: u32, max_per_sec: u32) -> bool {
        let now = Instant::now();
        let Ok(mut limits) = self.limits.lock() else {
            return false;
        };
        let entry = limits.entry(uid).or_insert(RateEntry {
            last_reset: now,
            count: 0,
        });
        if now.duration_since(entry.last_reset) > Duration::from_secs(1) {
            entry.last_reset = now;
            entry.count = 0;
        }
        entry.count = entry.count.saturating_add(1);
        entry.count <= max_per_sec
    }

    fn cleanup_stale(limits: &Mutex<HashMap<u32, RateEntry>>) {
        let now = Instant::now();
        let Ok(mut limits) = limits.lock() else {
            return;
        };
        limits.retain(|_, entry| now.duration_since(entry.last_reset) < Duration::from_secs(60));
    }
}

impl Drop for RateLimiter {
    fn drop(&mut self) {
        if let Some(task) = self.cleanup_task.take() {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limit_blocks_after_budget() {
        let limiter = RateLimiter::new();
        assert!(limiter.check(1000, 2));
        assert!(limiter.check(1000, 2));
        assert!(!limiter.check(1000, 2));
    }

    #[test]
    fn test_cleanup_removes_only_stale_entries() {
        let limits = Mutex::new(HashMap::from([
            (
                1000,
                RateEntry {
                    last_reset: Instant::now() - Duration::from_secs(61),
                    count: 1,
                },
            ),
            (
                1001,
                RateEntry {
                    last_reset: Instant::now(),
                    count: 1,
                },
            ),
        ]));

        RateLimiter::cleanup_stale(&limits);

        let limits = limits.lock().expect("rate limit state");
        assert!(limits.get(&1000).is_none());
        assert!(limits.get(&1001).is_some());
    }
}
