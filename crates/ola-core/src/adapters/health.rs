// SPDX-License-Identifier: Apache-2.0

use crate::adapters::client::AdapterClient;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;

#[derive(Clone, Debug)]
pub struct AdapterHealth {
    pub status: HealthStatus,
    pub consecutive_failures: u32,
    pub last_checked: Instant,
    pub last_success: Option<Instant>,
}

// Three states: Up, Degraded, Down.
// Down is also the initial state. An adapter must answer one ping before
// list_methods or dispatch can route to it.
// Up → Degraded on first failure. Adapter can be busy or restarting; do
//   not hide it yet.
// Degraded → Down at 3 consecutive failures. Stop routing requests to it
//   and hide its methods from list_methods.
// Any → Up on a single successful ping. One good response is enough; fast
//   recovery beats waiting for N consecutive successes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthStatus {
    Up,
    Degraded,
    Down,
}

pub type HealthMap = Arc<Mutex<HashMap<String, AdapterHealth>>>;

pub struct HealthMonitor {
    health_map: HealthMap,
    task: JoinHandle<()>,
}

impl HealthMonitor {
    pub fn spawn(clients: Arc<Vec<AdapterClient>>) -> Self {
        let now = Instant::now();
        let health_map = Arc::new(Mutex::new(
            clients
                .iter()
                .map(|client| (client.name.clone(), new_health(HealthStatus::Down, now)))
                .collect::<HashMap<_, _>>(),
        ));
        let map_clone = health_map.clone();

        let task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            loop {
                interval.tick().await;
                for client in clients.iter() {
                    if client.concurrency.available_permits() == 0 {
                        continue;
                    }

                    let is_up = client.ping().await;
                    let now = Instant::now();
                    let Ok(mut map) = map_clone.lock() else {
                        continue;
                    };
                    map.entry(client.name.clone())
                        .and_modify(|health| record_probe(health, is_up, now))
                        .or_insert_with(|| {
                            let mut health = new_health(HealthStatus::Down, now);
                            record_probe(&mut health, is_up, now);
                            health
                        });
                }
            }
        });

        Self { health_map, task }
    }

    pub fn health_map(&self) -> HealthMap {
        self.health_map.clone()
    }
}

fn new_health(status: HealthStatus, now: Instant) -> AdapterHealth {
    AdapterHealth {
        status,
        consecutive_failures: 0,
        last_checked: now,
        last_success: (status == HealthStatus::Up).then_some(now),
    }
}

fn record_probe(health: &mut AdapterHealth, is_up: bool, now: Instant) {
    if is_up {
        health.status = HealthStatus::Up;
        health.consecutive_failures = 0;
        health.last_success = Some(now);
    } else {
        health.consecutive_failures += 1;
        health.status = if health.last_success.is_some() && health.consecutive_failures < 3 {
            HealthStatus::Degraded
        } else {
            HealthStatus::Down
        };
    }
    health.last_checked = now;
}

impl Drop for HealthMonitor {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_requires_success_before_degraded() {
        let now = Instant::now();
        let mut health = new_health(HealthStatus::Down, now);

        record_probe(&mut health, false, now);
        assert_eq!(health.status, HealthStatus::Down);

        record_probe(&mut health, true, now);
        assert_eq!(health.status, HealthStatus::Up);

        record_probe(&mut health, false, now);
        assert_eq!(health.status, HealthStatus::Degraded);

        record_probe(&mut health, false, now);
        assert_eq!(health.status, HealthStatus::Degraded);

        record_probe(&mut health, false, now);
        assert_eq!(health.status, HealthStatus::Down);
    }
}
