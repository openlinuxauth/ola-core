// SPDX-License-Identifier: Apache-2.0

use crate::adapters::client::{AdapterClient, AdapterError};
use crate::adapters::config_loader;
use crate::adapters::health::{HealthMap, HealthMonitor, HealthStatus};
use crate::core::types::request::VerificationRequest;
use crate::core::types::result::VerificationResult;
use crate::security::fs::OwnerPolicy;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::time::{timeout, Instant};

const ADAPTER_QUEUE_TIMEOUT: Duration = Duration::from_millis(250);

#[derive(Debug, Deserialize)]
pub struct AdapterConfig {
    pub name: String,
    pub socket_path: PathBuf,
    pub expected_uid: u32,
    pub methods: Vec<String>,
    pub timeout_ms: u64,
}

pub struct AdapterRegistry {
    // method name → client. Lookup is direct from what the PAM client asks for.
    clients: HashMap<String, Arc<AdapterClient>>,
    adapter_names: Vec<String>,
    health: HealthMap,
    _health_monitor: HealthMonitor,
}

pub struct ResolvedAdapter {
    pub adapter_name: String,
    pub method: String,
    pub timeout_ms: u64,
    client: Arc<AdapterClient>,
}

impl AdapterRegistry {
    #[cfg(test)]
    pub fn load_from_dir(dir: &Path, strict: bool) -> anyhow::Result<Self> {
        Self::load_from_dir_with_owner(dir, strict, OwnerPolicy::RootOrCurrent)
    }

    pub fn load_from_dir_with_owner(
        dir: &Path,
        strict: bool,
        owner: OwnerPolicy,
    ) -> anyhow::Result<Self> {
        let mut clients: HashMap<String, Arc<AdapterClient>> = HashMap::new();
        let configs = config_loader::load_adapter_configs(dir, strict, owner)?;
        let mut all_clients = Vec::new();
        let mut adapter_names = HashSet::new();

        for config in configs {
            if !adapter_names.insert(config.name.clone()) {
                anyhow::bail!("duplicate adapter name {}", config.name);
            }

            let client = AdapterClient {
                name: config.name.clone(),
                socket_path: config.socket_path,
                expected_uid: config.expected_uid,
                timeout: Duration::from_millis(config.timeout_ms),
                concurrency: Arc::new(Semaphore::new(1)),
            };
            let shared = Arc::new(client.clone());
            for method in config.methods {
                if let Some(existing) = clients.get(&method) {
                    anyhow::bail!(
                        "duplicate adapter method {} owned by both {} and {}",
                        method,
                        existing.name,
                        shared.name
                    );
                }
                clients.insert(method, shared.clone());
            }
            all_clients.push(client);
        }

        let mut adapter_names: Vec<String> = adapter_names.into_iter().collect();
        adapter_names.sort();

        let health_monitor = HealthMonitor::spawn(Arc::new(all_clients));
        let health = health_monitor.health_map();

        Ok(Self {
            clients,
            adapter_names,
            health,
            _health_monitor: health_monitor,
        })
    }

    pub fn resolve(&self, method: &str) -> Result<ResolvedAdapter, AdapterError> {
        let (resolved_method, client) = self.resolve_client(method)?;
        Ok(ResolvedAdapter {
            adapter_name: client.name.clone(),
            method: resolved_method,
            timeout_ms: client.timeout.as_millis() as u64,
            client,
        })
    }

    pub async fn dispatch_resolved(
        &self,
        resolved: &ResolvedAdapter,
        request: VerificationRequest,
        deadline: Instant,
    ) -> Result<VerificationResult, AdapterError> {
        let client = &resolved.client;

        // Down means recent probes could not reach the adapter. Fail before
        // sending a nonce, the health monitor will restore routing after a
        // successful probe.
        if self.adapter_down(&client.name) {
            return Err(AdapterError::AdapterDown(client.name.clone()));
        }

        let _permit = timeout(ADAPTER_QUEUE_TIMEOUT, client.concurrency.acquire())
            .await
            .map_err(|_| AdapterError::AdapterBusy(client.name.clone()))?
            .map_err(|_| AdapterError::AdapterDown(client.name.clone()))?;
        client.verify(request, deadline).await
    }

    pub fn available_methods(&self) -> Vec<String> {
        let mut methods: Vec<String> = self
            .clients
            .keys()
            .filter(|method| {
                // Surface methods whose adapter is Up or Degraded. Hide Down.
                // Degraded means some failures but still responding — keep it
                // listed. Down means 3+ consecutive ping failures — hide it,
                // rather than let clients queue requests that time out.
                self.clients
                    .get(*method)
                    .is_some_and(|client| !self.adapter_down(&client.name))
            })
            .cloned()
            .collect();
        methods.sort();
        methods
    }

    pub fn adapter_names(&self) -> &[String] {
        &self.adapter_names
    }

    fn resolve_client(&self, method: &str) -> Result<(String, Arc<AdapterClient>), AdapterError> {
        if method == "any" {
            // "any" means first available method alphabetically. Resolve once
            // before building the request deadline, dispatch uses the same
            // adapter.
            return self
                .available_methods()
                .into_iter()
                .next()
                .and_then(|name| {
                    self.clients
                        .get(&name)
                        .cloned()
                        .map(|client| (name, client))
                })
                .ok_or_else(|| AdapterError::MethodNotFound(method.to_string()));
        }

        self.clients
            .get(method)
            .cloned()
            .map(|client| (method.to_string(), client))
            .ok_or_else(|| AdapterError::MethodNotFound(method.to_string()))
    }

    fn adapter_down(&self, name: &str) -> bool {
        self.health
            .lock()
            .ok()
            .and_then(|health| {
                health
                    .get(name)
                    .map(|entry| entry.status == HealthStatus::Down)
            })
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn write_config(dir: &Path, file: &str, name: &str, methods: &[&str]) -> anyhow::Result<()> {
        let methods = methods
            .iter()
            .map(|method| format!("\"{method}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let contents = format!(
            "name = \"{name}\"\nsocket_path = \"/tmp/{name}.sock\"\nexpected_uid = 1000\nmethods = [{methods}]\ntimeout_ms = 1000\n"
        );
        let path = dir.join(file);
        std::fs::write(&path, contents)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
        Ok(())
    }

    #[tokio::test]
    async fn rejects_duplicate_method_ownership() {
        let temp = tempfile::tempdir().expect("temp dir");
        write_config(temp.path(), "a.toml", "adapter_a", &["fido2"]).expect("write config");
        write_config(temp.path(), "b.toml", "adapter_b", &["fido2"]).expect("write config");

        let err = match AdapterRegistry::load_from_dir(temp.path(), true) {
            Ok(_) => panic!("duplicate method must fail"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("duplicate adapter method fido2"));
    }

    #[tokio::test]
    async fn rejects_duplicate_adapter_names() {
        let temp = tempfile::tempdir().expect("temp dir");
        write_config(temp.path(), "a.toml", "adapter_a", &["fido2"]).expect("write config");
        write_config(temp.path(), "b.toml", "adapter_a", &["pin"]).expect("write config");

        let err = match AdapterRegistry::load_from_dir(temp.path(), true) {
            Ok(_) => panic!("duplicate adapter name must fail"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("duplicate adapter name adapter_a"));
    }

    #[tokio::test]
    async fn resolves_any_once_with_timeout() {
        let temp = tempfile::tempdir().expect("temp dir");
        write_config(temp.path(), "b.toml", "adapter_b", &["pin"]).expect("write config");
        write_config(temp.path(), "a.toml", "adapter_a", &["fido2"]).expect("write config");

        let registry = AdapterRegistry::load_from_dir(temp.path(), true).expect("load registry");
        let resolved = registry.resolve("any").expect("resolve any");

        assert_eq!(resolved.method, "fido2");
        assert_eq!(resolved.adapter_name, "adapter_a");
        assert_eq!(resolved.timeout_ms, 1000);
    }
}
