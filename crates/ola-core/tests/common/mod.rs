// SPDX-License-Identifier: Apache-2.0

//! Shared test infrastructure.
//!
//! `TestServer` spawns the real ola-core binary against a tempdir tree.
//! `MockAdapter` is a Tokio listener that signs real HMAC evidence hashes,
//! so the daemon's verify path runs end-to-end without hardware.
//!
//! Usage from an integration test:
//! ```ignore
//! mod common;
//! use common::{TestServer, MockAdapterBehavior};
//! ```

// Each integration test compiles this module separately, helpers unused in one
// test are used in another.
#![allow(dead_code)]

use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinHandle;

pub const PROTOCOL_VERSION: u8 = 1;

#[derive(Clone)]
pub struct MockAdapterBehavior {
    pub method: &'static str,
    pub result_method: Option<&'static str>,
    pub confidence: f32,
    pub tamper_hash: bool,
    pub tamper_nonce: bool,
    pub replay_first_response: bool,
    pub response_delay_ms: u64,
}

impl MockAdapterBehavior {
    pub fn allow(method: &'static str) -> Self {
        Self {
            method,
            result_method: None,
            confidence: 1.0,
            tamper_hash: false,
            tamper_nonce: false,
            replay_first_response: false,
            response_delay_ms: 0,
        }
    }

    pub fn with_result_method(mut self, method: &'static str) -> Self {
        self.result_method = Some(method);
        self
    }

    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence;
        self
    }

    pub fn with_tamper_hash(mut self) -> Self {
        self.tamper_hash = true;
        self
    }

    pub fn with_tamper_nonce(mut self) -> Self {
        self.tamper_nonce = true;
        self
    }

    pub fn with_replay_first_response(mut self) -> Self {
        self.replay_first_response = true;
        self
    }

    pub fn with_response_delay_ms(mut self, delay_ms: u64) -> Self {
        self.response_delay_ms = delay_ms;
        self
    }
}

pub struct MockAdapterHandle {
    pub socket_path: PathBuf,
    pub _temp_dir: TempDir,
    task: JoinHandle<()>,
}

impl Drop for MockAdapterHandle {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

pub async fn spawn_mock_adapter(
    root: &Path,
    method_name: &str,
    key: [u8; 32],
    behavior: MockAdapterBehavior,
) -> MockAdapterHandle {
    let temp_dir = tempfile::tempdir_in(root).expect("adapter temp dir");
    let socket_path = temp_dir.path().join(format!("{method_name}.sock"));
    let listener = UnixListener::bind(&socket_path).expect("bind mock adapter");
    let state = Arc::new(Mutex::new(None::<serde_json::Value>));
    let task = tokio::spawn(run_mock_adapter(listener, behavior, key, state));
    MockAdapterHandle {
        socket_path,
        _temp_dir: temp_dir,
        task,
    }
}

async fn run_mock_adapter(
    listener: UnixListener,
    behavior: MockAdapterBehavior,
    key: [u8; 32],
    replay_state: Arc<Mutex<Option<serde_json::Value>>>,
) {
    loop {
        let (mut stream, _) = listener.accept().await.expect("accept adapter connection");
        let mut buf = Vec::new();
        loop {
            let mut chunk = [0u8; 1024];
            let n = stream.read(&mut chunk).await.expect("read request");
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.contains(&b'\n') {
                break;
            }
        }
        let line = String::from_utf8_lossy(&buf);
        let line = line.lines().next().unwrap_or("");
        if line.trim().is_empty() {
            continue;
        }
        let request: serde_json::Value = serde_json::from_str(line).expect("parse adapter request");
        if request["method"] == "ping" {
            stream
                .write_all(br#"{"version":1,"ok":true}"#)
                .await
                .expect("write ping response");
            stream.write_all(b"\n").await.expect("write newline");
            continue;
        }

        if behavior.response_delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(behavior.response_delay_ms)).await;
        }

        let response = if behavior.replay_first_response {
            let mut guard = replay_state.lock().expect("lock replay state");
            if let Some(first) = guard.clone() {
                let mut replayed = first;
                replayed["id"] = request["id"].clone();
                replayed
            } else {
                let fresh = build_adapter_response(&request, &behavior, key);
                *guard = Some(fresh.clone());
                fresh
            }
        } else {
            build_adapter_response(&request, &behavior, key)
        };

        let line = format!(
            "{}\n",
            serde_json::to_string(&response).expect("serialize response")
        );
        stream
            .write_all(line.as_bytes())
            .await
            .expect("write response");
    }
}

fn build_adapter_response(
    request: &serde_json::Value,
    behavior: &MockAdapterBehavior,
    key: [u8; 32],
) -> serde_json::Value {
    let id: [u8; 16] = serde_json::from_value(request["id"].clone()).expect("request id");
    let mut nonce: [u8; 32] = serde_json::from_value(request["nonce"].clone()).expect("nonce");
    let uid = request["uid"].as_u64().expect("uid") as u32;
    let timestamp_ms = now_ms();
    let method = behavior.result_method.unwrap_or(behavior.method);
    if behavior.tamper_nonce {
        nonce[0] ^= 0xFF;
    }
    let mut evidence_hash =
        compute_evidence_hash(&key, &nonce, uid, method, behavior.confidence, timestamp_ms);
    if behavior.tamper_hash {
        evidence_hash[0] ^= 0xFF;
    }

    json!({
        "version": PROTOCOL_VERSION,
        "id": id,
        "confidence": behavior.confidence,
        "method": method,
        "timestamp_ms": timestamp_ms,
        "uid": uid,
        "nonce": nonce,
        "evidence_hash": evidence_hash,
    })
}

pub fn compute_evidence_hash(
    key: &[u8; 32],
    nonce: &[u8; 32],
    uid: u32,
    method: &str,
    confidence: f32,
    timestamp_ms: u64,
) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("construct hmac");
    mac.update(nonce);
    mac.update(&uid.to_le_bytes());
    mac.update(&Sha256::digest(method.as_bytes()));
    mac.update(&confidence.to_bits().to_le_bytes());
    mac.update(&timestamp_ms.to_le_bytes());

    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes.as_slice());
    out
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_millis() as u64
}

pub struct TestServer {
    child: Child,
    pub socket_path: String,
    pub temp_dir: TempDir,
    pub _adapter: Option<MockAdapterHandle>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

impl TestServer {
    pub async fn start_without_adapter(policy_toml: &str) -> Self {
        Self::start(policy_toml, None).await
    }

    pub async fn start_with_adapter(
        policy_toml: &str,
        behavior: MockAdapterBehavior,
        method_name: &str,
    ) -> Self {
        Self::start(policy_toml, Some((behavior, method_name.to_string()))).await
    }

    async fn start(policy_toml: &str, adapter: Option<(MockAdapterBehavior, String)>) -> Self {
        let cwd = std::env::current_dir().expect("current dir");
        let temp_dir = tempfile::tempdir_in(cwd).expect("create temp dir");
        let uuid = uuid::Uuid::new_v4();
        let socket_path = format!("/tmp/ola_it_{}.sock", &uuid.to_string()[..8]);
        let audit_log = temp_dir.path().join("audit.log");
        let allowlist_path = temp_dir.path().join("allowlist");
        let policy_path = temp_dir.path().join("policy.toml");
        let adapters_dir = temp_dir.path().join("adapters.d");
        let adapter_keys_dir = temp_dir.path().join("adapter-keys");
        std::fs::create_dir_all(&adapters_dir).expect("create adapters dir");
        std::fs::create_dir_all(&adapter_keys_dir).expect("create adapter keys dir");
        std::fs::write(
            &allowlist_path,
            format!("{}\n", nix::unistd::getuid().as_raw()),
        )
        .expect("write allowlist");
        let mut allowlist_perms = std::fs::metadata(&allowlist_path)
            .expect("allowlist metadata")
            .permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut allowlist_perms, 0o600);
        std::fs::set_permissions(&allowlist_path, allowlist_perms).expect("set allowlist perms");
        std::fs::write(&policy_path, policy_toml).expect("write policy");
        let mut policy_perms = std::fs::metadata(&policy_path)
            .expect("policy metadata")
            .permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut policy_perms, 0o600);
        std::fs::set_permissions(&policy_path, policy_perms).expect("set policy perms");

        let adapter_handle = if let Some((behavior, method_name)) = adapter {
            let key = [7u8; 32];
            let key_path = adapter_keys_dir.join(format!("{method_name}.key"));
            std::fs::write(&key_path, key).expect("write adapter key");
            let mut key_perms = std::fs::metadata(&key_path)
                .expect("adapter key metadata")
                .permissions();
            std::os::unix::fs::PermissionsExt::set_mode(&mut key_perms, 0o600);
            std::fs::set_permissions(&key_path, key_perms).expect("set adapter key perms");

            let handle = spawn_mock_adapter(temp_dir.path(), &method_name, key, behavior).await;
            let adapter_config = format!(
                "name = \"{name}\"\nsocket_path = \"{socket}\"\nexpected_uid = {uid}\nmethods = [\"{name}\"]\ntimeout_ms = 2000\n",
                name = method_name,
                socket = handle.socket_path.display(),
                uid = nix::unistd::getuid().as_raw()
            );
            std::fs::write(
                adapters_dir.join(format!("{method_name}.toml")),
                adapter_config,
            )
            .expect("write adapter config");
            Some(handle)
        } else {
            None
        };

        if Path::new(&socket_path).exists() {
            let _ = std::fs::remove_file(&socket_path);
        }

        let mut child = Command::new(env!("CARGO_BIN_EXE_ola-core"))
            .env("OLA_RUNMODE", "dev")
            .env("OLA_SOCKET_PATH", &socket_path)
            .env("OLA_AUDIT_LOG_PATH", &audit_log)
            .env("OLA_ALLOWLIST_PATH", &allowlist_path)
            .env("OLA_POLICY_PATH", &policy_path)
            .env("OLA_ADAPTERS_DIR", &adapters_dir)
            .env("OLA_ADAPTER_KEYS_DIR", &adapter_keys_dir)
            .env("OLA_CLIENT_IDLE_TIMEOUT_SECS", "1")
            .env("RUST_LOG", "info")
            .spawn()
            .expect("Failed to start server");

        for _ in 0..50 {
            if Path::new(&socket_path).exists()
                && std::os::unix::net::UnixStream::connect(&socket_path).is_ok()
            {
                tokio::time::sleep(Duration::from_millis(50)).await;
                return Self {
                    child,
                    socket_path,
                    temp_dir,
                    _adapter: adapter_handle,
                };
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let _ = child.kill();
        let _ = child.wait();
        panic!("Server failed to create socket");
    }

    pub async fn send_request(
        &self,
        id: &str,
        method: &str,
        params: serde_json::Value,
    ) -> serde_json::Value {
        let mut stream = UnixStream::connect(&self.socket_path)
            .await
            .expect("connect failed");

        let req = json!({
            "version": PROTOCOL_VERSION,
            "id": id,
            "method": method,
            "params": params
        });

        let req_str = format!(
            "{}\n",
            serde_json::to_string(&req).expect("serialize request")
        );
        stream
            .write_all(req_str.as_bytes())
            .await
            .expect("write request");

        let mut buf = Vec::new();
        loop {
            let mut chunk = [0u8; 1024];
            let n = stream.read(&mut chunk).await.expect("read response");
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.contains(&b'\n') {
                break;
            }
        }

        let line = String::from_utf8_lossy(&buf);
        let line = line.lines().next().unwrap_or("");
        serde_json::from_str(line).expect("parse response")
    }

    pub fn audit_log_path(&self) -> PathBuf {
        self.temp_dir.path().join("audit.log")
    }

    pub fn policy_path(&self) -> PathBuf {
        self.temp_dir.path().join("policy.toml")
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }
}
