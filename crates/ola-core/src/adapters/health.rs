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
// Up → Degraded on first failure. Adapter can be busy or restarting; do
//   not hide it yet.
// Degraded → Down at 3 consecutive failures. Stop routing requests to it
//   and hide its methods from list_methods.
// Any → Up on a single successful ping. One good response is enough; fast
//   recovery beats waiting for N consecutive successes.
#[derive(Clone, Debug, PartialEq)]
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
        let health_map = Arc::new(Mutex::new(HashMap::new()));
        let map_clone = health_map.clone();

        let task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            loop {
                interval.tick().await;
                for client in clients.iter() {
                    if client.concurrency.available_permits() == 0 {
                        let Ok(mut map) = map_clone.lock() else {
                            continue;
                        };
                        map.entry(client.name.clone()).or_insert(AdapterHealth {
                            status: HealthStatus::Up,
                            consecutive_failures: 0,
                            last_checked: Instant::now(),
                            last_success: None,
                        });
                        continue;
                    }

                    let is_up = client.ping().await;
                    let Ok(mut map) = map_clone.lock() else {
                        continue;
                    };
                    map.entry(client.name.clone())
                        .and_modify(|health| {
                            if is_up {
                                health.status = HealthStatus::Up;
                                health.consecutive_failures = 0;
                                health.last_success = Some(Instant::now());
                            } else {
                                health.consecutive_failures += 1;
                                health.status = if health.consecutive_failures >= 3 {
                                    HealthStatus::Down
                                } else {
                                    HealthStatus::Degraded
                                };
                            }
                            health.last_checked = Instant::now();
                        })
                        .or_insert(AdapterHealth {
                            status: if is_up {
                                HealthStatus::Up
                            } else {
                                HealthStatus::Degraded
                            },
                            consecutive_failures: if is_up { 0 } else { 1 },
                            last_checked: Instant::now(),
                            last_success: if is_up { Some(Instant::now()) } else { None },
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

impl Drop for HealthMonitor {
    fn drop(&mut self) {
        self.task.abort();
    }
}
