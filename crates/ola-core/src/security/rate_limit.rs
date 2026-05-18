// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;

const MAX_TRACKED_UIDS: usize = 4096;
const RATE_WINDOW: Duration = Duration::from_secs(1);
const STALE_AFTER: Duration = Duration::from_secs(60);

pub struct RateLimiter {
    // MAX_CONNECTIONS bounds contention. One lock removes a dependency family.
    limits: Arc<Mutex<HashMap<u32, RateEntry>>>,
    max_tracked_uids: usize,
    cleanup_task: Option<JoinHandle<()>>,
}

struct RateEntry {
    last_reset: Instant,
    count: u32,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::with_max_tracked_uids(MAX_TRACKED_UIDS)
    }

    fn with_max_tracked_uids(max_tracked_uids: usize) -> Self {
        let limits = Arc::new(Mutex::new(HashMap::new()));

        // Cleanup keeps old UID slots reusable. The hard cap is the real bound.
        let limits_clone = limits.clone();
        let cleanup_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(STALE_AFTER);
            loop {
                interval.tick().await;
                Self::cleanup_stale(&limits_clone);
            }
        });

        Self {
            limits,
            max_tracked_uids,
            cleanup_task: Some(cleanup_task),
        }
    }

    pub fn check(&self, uid: u32, max_per_sec: u32) -> bool {
        let now = Instant::now();
        let Ok(mut limits) = self.limits.lock() else {
            return false;
        };

        if !limits.contains_key(&uid) && limits.len() >= self.max_tracked_uids {
            Self::cleanup_stale_locked(&mut limits, now);
            if limits.len() >= self.max_tracked_uids {
                return false;
            }
        }

        let entry = limits.entry(uid).or_insert(RateEntry {
            last_reset: now,
            count: 0,
        });
        if now.duration_since(entry.last_reset) > RATE_WINDOW {
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
        Self::cleanup_stale_locked(&mut limits, now);
    }

    fn cleanup_stale_locked(limits: &mut HashMap<u32, RateEntry>, now: Instant) {
        limits.retain(|_, entry| now.duration_since(entry.last_reset) < STALE_AFTER);
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

    #[tokio::test]
    async fn test_rejects_new_uid_when_table_is_full() {
        let limiter = RateLimiter::with_max_tracked_uids(1);

        assert!(limiter.check(1000, 10));
        assert!(!limiter.check(1001, 10));
    }

    #[tokio::test]
    async fn test_existing_uid_uses_existing_slot_when_table_is_full() {
        let limiter = RateLimiter::with_max_tracked_uids(1);

        assert!(limiter.check(1000, 2));
        assert!(limiter.check(1000, 2));
        assert!(!limiter.check(1000, 2));
    }

    #[tokio::test]
    async fn test_cleanup_frees_slot_before_rejecting_new_uid() {
        let limiter = RateLimiter::with_max_tracked_uids(1);
        {
            let mut limits = limiter.limits.lock().expect("rate limit state");
            limits.insert(
                1000,
                RateEntry {
                    last_reset: Instant::now() - STALE_AFTER - Duration::from_secs(1),
                    count: 1,
                },
            );
        }

        assert!(limiter.check(1001, 10));
    }
}
