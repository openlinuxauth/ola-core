// SPDX-License-Identifier: Apache-2.0

use log::info;
use std::sync::atomic::{AtomicU64, Ordering};

// Aggregate counters. Relaxed ordering — the monitoring side cares about
// final totals, not strict happens-before. A mutex on the hot path serializes
// every request.

pub static TOTAL_REQUESTS: AtomicU64 = AtomicU64::new(0);
pub static REQUEST_FAILURES: AtomicU64 = AtomicU64::new(0);
pub static ACTIVE_CONNECTIONS: AtomicU64 = AtomicU64::new(0);
pub static IDLE_CONNECTION_CLOSES: AtomicU64 = AtomicU64::new(0);

pub fn inc_requests() {
    TOTAL_REQUESTS.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_failures() {
    REQUEST_FAILURES.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_active_connections() {
    ACTIVE_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
}

pub fn dec_active_connections() {
    let mut current = ACTIVE_CONNECTIONS.load(Ordering::Relaxed);
    loop {
        if current == 0 {
            return;
        }
        match ACTIVE_CONNECTIONS.compare_exchange_weak(
            current,
            current - 1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return,
            Err(next) => current = next,
        }
    }
}

pub fn inc_idle_closes() {
    IDLE_CONNECTION_CLOSES.fetch_add(1, Ordering::Relaxed);
}

pub fn log_metrics() {
    let reqs = TOTAL_REQUESTS.load(Ordering::Relaxed);
    let fails = REQUEST_FAILURES.load(Ordering::Relaxed);
    let conns = ACTIVE_CONNECTIONS.load(Ordering::Relaxed);
    let idle = IDLE_CONNECTION_CLOSES.load(Ordering::Relaxed);

    info!(
        "METRICS: Requests: {}, Failures: {}, Active Connections: {}, Idle Closes: {}",
        reqs, fails, conns, idle
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_increment() {
        let before = TOTAL_REQUESTS.load(Ordering::Relaxed);
        inc_requests();
        let after = TOTAL_REQUESTS.load(Ordering::Relaxed);
        assert_eq!(after, before + 1);
    }

    #[test]
    fn test_metrics_active_connections() {
        let before = ACTIVE_CONNECTIONS.load(Ordering::Relaxed);

        inc_active_connections();
        assert_eq!(ACTIVE_CONNECTIONS.load(Ordering::Relaxed), before + 1);

        dec_active_connections();
        assert_eq!(ACTIVE_CONNECTIONS.load(Ordering::Relaxed), before);
    }

    #[test]
    fn test_metrics_active_connections_saturates_at_zero() {
        ACTIVE_CONNECTIONS.store(0, Ordering::Relaxed);
        dec_active_connections();
        assert_eq!(ACTIVE_CONNECTIONS.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_metrics_log_doesnt_panic() {
        log_metrics();
    }
}
