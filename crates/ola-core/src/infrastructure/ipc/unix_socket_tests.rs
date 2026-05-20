// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::core::types::result::{AuthMethod, VerificationResult};
use crate::infrastructure::audit::hex::encode_hex;
use crate::infrastructure::ipc::socket_setup::{
    prepare_socket_parent, remove_stale_socket_with, set_socket_mode, set_socket_owner,
};
use arc_swap::ArcSwap;
use futures::StreamExt;
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::ErrorKind;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

#[test]
fn set_socket_mode_fails_on_invalid_fd() {
    let err = set_socket_mode(-1).expect_err("fchmod must fail on invalid fd");
    assert!(err.to_string().contains("fchmod failed"));
}

#[test]
fn set_socket_owner_fails_on_invalid_fd() {
    let err = set_socket_owner(-1, 0, 0).expect_err("fchown must fail on invalid fd");
    assert!(err.to_string().contains("fchown failed"));
}

fn test_config(socket_path: std::path::PathBuf, run_mode: &str) -> Config {
    Config {
        socket_path,
        run_mode: run_mode.to_string(),
        drain_secs: 1,
        client_idle_timeout_secs: 1,
        allowlist_path: std::path::PathBuf::from("/tmp/allowlist"),
        adapters_dir: std::path::PathBuf::from("/tmp/adapters"),
        policy_path: std::path::PathBuf::from("/tmp/policy.toml"),
        audit_log_path: std::path::PathBuf::from("/tmp/audit.log"),
        adapter_keys_dir: std::path::PathBuf::from("/tmp/keys"),
        max_result_age_secs: 30,
        require_attestation: false,
    }
}

fn write_secure(path: &std::path::Path, contents: &str) {
    fs::write(path, contents).expect("write file");
    let mut perms = fs::metadata(path).expect("file metadata").permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms).expect("set file perms");
}

#[test]
fn prod_mode_rejects_disabled_attestation() {
    let config = test_config(std::path::PathBuf::from("/tmp/ola.sock"), "prod");
    let err = validate_attestation_mode(&config).expect_err("prod must require attestation");
    assert_eq!(
        err.to_string(),
        "OLA_REQUIRE_ATTESTATION cannot be disabled in prod mode"
    );
}

#[test]
fn dev_mode_allows_disabled_attestation() {
    let config = test_config(std::path::PathBuf::from("/tmp/ola.sock"), "dev");
    validate_attestation_mode(&config).expect("dev may disable attestation");
}

fn policy(confidence: f32) -> String {
    format!(
        "[[rules]]\nmethod = \"fido2\"\nmin_confidence = {confidence}\nmax_age_secs = 30\nrequire_uid_match = true\n"
    )
}

fn reload_test_state(temp: &tempfile::TempDir, allowed_uid: u32, confidence: f32) -> ServerState {
    let adapters_dir = temp.path().join("adapters.d");
    let adapter_keys_dir = temp.path().join("adapter-keys");
    fs::create_dir_all(&adapters_dir).expect("create adapters dir");
    fs::create_dir_all(&adapter_keys_dir).expect("create adapter keys dir");

    let allowlist_path = temp.path().join("allowlist");
    let policy_path = temp.path().join("policy.toml");
    write_secure(&allowlist_path, &format!("{allowed_uid}\n"));
    write_secure(&policy_path, &policy(confidence));

    let config = Arc::new(Config {
        socket_path: temp.path().join("ola.sock"),
        run_mode: "prod".to_string(),
        drain_secs: 1,
        client_idle_timeout_secs: 1,
        allowlist_path,
        adapters_dir: adapters_dir.clone(),
        policy_path,
        audit_log_path: temp.path().join("audit.log"),
        adapter_keys_dir,
        max_result_age_secs: 30,
        require_attestation: true,
    });

    ServerState {
        adapter_registry: Arc::new(
            AdapterRegistry::load_from_dir(&adapters_dir, false).expect("load adapter registry"),
        ),
        reloadable: Arc::new(ArcSwap::from(Arc::new(
            ReloadableState::load(&config, OwnerPolicy::RootOrCurrent)
                .expect("load reloadable state"),
        ))),
        attester: Arc::new(AttestationVerifier::new(HashMap::new())),
        nonce_store: Arc::new(NonceStore::new()),
        audit_logger: Arc::new(
            AuditLogger::open(&config.audit_log_path, OwnerPolicy::RootOrCurrent)
                .expect("open audit log"),
        ),
        rate_limiter: Arc::new(RateLimiter::new()),
        config,
        owner_policy: OwnerPolicy::RootOrCurrent,
    }
}

fn policy_allows(reloadable: &ReloadableState, confidence: f32) -> bool {
    let now = now_ms();
    let context = AuthContext {
        uid: 1000,
        method: "fido2".to_string(),
        request: VerificationRequest {
            version: PROTOCOL_VERSION,
            id: [1u8; 16],
            uid: 1000,
            nonce: [2u8; 32],
            deadline_ms: now + 1000,
        },
        result: VerificationResult {
            version: PROTOCOL_VERSION,
            id: [1u8; 16],
            confidence,
            method: AuthMethod::Fido2,
            timestamp_ms: now,
            uid: 1000,
            nonce: [2u8; 32],
            evidence_hash: [3u8; 32],
        },
        decision: None,
    };

    reloadable.policy_engine.evaluate(&context) == PolicyDecision::Allow
}

#[test]
fn prepare_socket_parent_refuses_symlink() {
    let dir = tempfile::tempdir().expect("tempdir");
    let real = dir.path().join("real");
    let link = dir.path().join("link");
    fs::create_dir(&real).expect("real dir");
    symlink(&real, &link).expect("symlink");
    let config = test_config(link.join("ola.sock"), "prod");

    let err = prepare_socket_parent(&link, &config).expect_err("symlink must fail");
    assert!(err.to_string().contains("symlink"));
}

#[test]
fn encode_hex_uses_lowercase_hex() {
    assert_eq!(encode_hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
}

#[test]
fn root_verify_once_requires_explicit_uid() {
    let err = request_uid(0, None).expect_err("root fallback must fail closed");
    assert_eq!(err, "root caller must supply params.uid");
}

#[test]
fn root_verify_once_accepts_explicit_uid() {
    let params = serde_json::json!({ "uid": 1000 });
    assert_eq!(request_uid(0, Some(&params)).unwrap(), 1000);
}

#[test]
fn non_root_verify_once_uses_peercred_uid() {
    let params = serde_json::json!({ "uid": 0 });
    assert_eq!(request_uid(1000, Some(&params)).unwrap(), 1000);
}

#[test]
fn verify_once_method_defaults_only_when_absent() {
    assert_eq!(request_method(None).unwrap(), "any");
    assert_eq!(request_method(Some(&serde_json::json!({}))).unwrap(), "any");
    assert_eq!(
        request_method(Some(&serde_json::json!({"method": "fido2"}))).unwrap(),
        "fido2"
    );
}

#[test]
fn verify_once_method_rejects_invalid_present_value() {
    assert_eq!(
        request_method(Some(&serde_json::json!({"method": null}))).unwrap_err(),
        "params.method must be a string"
    );
    assert_eq!(
        request_method(Some(&serde_json::json!({"method": ""}))).unwrap_err(),
        "params.method is invalid"
    );
    assert_eq!(
        request_method(Some(&serde_json::json!({"method": " fido2"}))).unwrap_err(),
        "params.method is invalid"
    );
    assert_eq!(
        request_method(Some(&serde_json::json!({"method": "two words"}))).unwrap_err(),
        "params.method is invalid"
    );
    assert_eq!(
        request_method(Some(&serde_json::json!("bad"))).unwrap_err(),
        "params must be an object"
    );
}

#[tokio::test]
async fn line_codec_rejects_oversized_payload() {
    let (mut writer, reader) = tokio::io::duplex(MAX_LINE_BYTES + 64);
    let oversized = format!("{}\n", "x".repeat(MAX_LINE_BYTES + 1));
    writer
        .write_all(oversized.as_bytes())
        .await
        .expect("write oversized payload");
    drop(writer);

    let mut framed = Framed::new(reader, new_line_codec());
    let line = framed.next().await.expect("expected frame result");
    assert!(line.is_err(), "oversized line rejected by codec");
}

#[tokio::test]
async fn verify_once_returns_error_when_allow_audit_fails() {
    let temp = tempfile::tempdir().expect("create temp dir");
    let adapters_dir = temp.path().join("adapters.d");
    let adapter_keys_dir = temp.path().join("adapter-keys");
    fs::create_dir_all(&adapters_dir).expect("create adapters dir");
    fs::create_dir_all(&adapter_keys_dir).expect("create adapter keys dir");

    let adapter_socket = temp.path().join("adapter.sock");
    let listener = UnixListener::bind(&adapter_socket).expect("bind adapter socket");
    let adapter_task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                let Ok(n) = reader.read_line(&mut line).await else {
                    return;
                };
                if n == 0 {
                    return;
                }

                let Ok(value) = serde_json::from_str::<serde_json::Value>(line.trim()) else {
                    return;
                };
                let mut stream = reader.into_inner();
                if value.get("method").and_then(|method| method.as_str()) == Some("ping") {
                    let _ = stream
                        .write_all(
                            format!(
                                "{}\n",
                                serde_json::json!({
                                    "version": PROTOCOL_VERSION,
                                    "ok": true
                                })
                            )
                            .as_bytes(),
                        )
                        .await;
                    return;
                }

                let Ok(request) = serde_json::from_value::<VerificationRequest>(value) else {
                    return;
                };
                let response = serde_json::json!({
                    "version": PROTOCOL_VERSION,
                    "id": request.id,
                    "confidence": 1.0,
                    "method": "fido2",
                    "timestamp_ms": now_ms(),
                    "uid": request.uid,
                    "nonce": request.nonce,
                    "evidence_hash": vec![0u8; 32],
                });
                let _ = stream.write_all(format!("{response}\n").as_bytes()).await;
            });
        }
    });

    let adapter_config_path = adapters_dir.join("fido2.toml");
    fs::write(
        &adapter_config_path,
        format!(
            "name = \"fido2\"\nsocket_path = \"{}\"\nexpected_uid = {}\nmethods = [\"fido2\"]\ntimeout_ms = 2000\n",
            adapter_socket.display(),
            nix::unistd::getuid().as_raw()
        ),
    )
    .expect("write adapter config");
    let mut adapter_config_perms = fs::metadata(&adapter_config_path)
        .expect("adapter config metadata")
        .permissions();
    adapter_config_perms.set_mode(0o644);
    fs::set_permissions(&adapter_config_path, adapter_config_perms)
        .expect("set adapter config perms");

    let policy_path = temp.path().join("policy.toml");
    fs::write(
        &policy_path,
        "[[rules]]\nmethod = \"fido2\"\nmin_confidence = 0.9\nmax_age_secs = 30\nrequire_uid_match = true\n",
    )
    .expect("write policy");
    let mut policy_perms = fs::metadata(&policy_path)
        .expect("policy metadata")
        .permissions();
    policy_perms.set_mode(0o600);
    fs::set_permissions(&policy_path, policy_perms).expect("set policy perms");

    let failing_audit = OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .expect("open /dev/full");
    let config = Arc::new(Config {
        socket_path: temp.path().join("ola.sock"),
        run_mode: "dev".to_string(),
        drain_secs: 3,
        client_idle_timeout_secs: 20,
        allowlist_path: temp.path().join("allowlist"),
        adapters_dir: adapters_dir.clone(),
        policy_path: policy_path.clone(),
        audit_log_path: temp.path().join("audit.log"),
        adapter_keys_dir,
        max_result_age_secs: 30,
        require_attestation: false,
    });
    let state = ServerState {
        adapter_registry: Arc::new(
            AdapterRegistry::load_from_dir(&adapters_dir, true).expect("load adapter registry"),
        ),
        reloadable: Arc::new(ArcSwap::from(Arc::new(ReloadableState {
            allowlist: Allowlist::new(),
            policy_engine: PolicyEngine::from_config(&policy_path, 30).expect("load policy"),
        }))),
        attester: Arc::new(AttestationVerifier::new(HashMap::new())),
        nonce_store: Arc::new(NonceStore::new()),
        audit_logger: Arc::new(AuditLogger::from_file_for_test(failing_audit)),
        rate_limiter: Arc::new(RateLimiter::new()),
        config,
        owner_policy: OwnerPolicy::RootOrCurrent,
    };

    let uid = nix::unistd::getuid().as_raw();
    let reloadable = state.reloadable.load_full();
    let response = handle_verify_once(
        &state,
        &reloadable,
        uid,
        uid,
        "fido2",
        Some("audit-fail".to_string()),
    )
    .await;

    adapter_task.abort();

    assert_eq!(response.id.as_deref(), Some("audit-fail"));
    assert_eq!(response.error.as_deref(), Some("audit failed"));
    assert!(response.result.is_none(), "audit failure must not allow");
}

#[tokio::test]
async fn reload_keeps_old_state_when_new_policy_is_bad() {
    let temp = tempfile::tempdir().expect("tempdir");
    let old_uid = nix::unistd::getuid().as_raw().saturating_add(10_000);
    let new_uid = old_uid + 1;
    let state = reload_test_state(&temp, old_uid, 0.9);

    write_secure(&state.config.allowlist_path, &format!("{new_uid}\n"));
    write_secure(&state.config.policy_path, "not valid toml");

    reload_state(&state);

    let reloadable = state.reloadable.load();
    assert!(reloadable.allowlist.is_allowed(old_uid));
    assert!(!reloadable.allowlist.is_allowed(new_uid));
    assert!(!policy_allows(&reloadable, 0.5));
}

#[tokio::test]
async fn reload_keeps_old_state_when_new_allowlist_is_bad() {
    let temp = tempfile::tempdir().expect("tempdir");
    let old_uid = nix::unistd::getuid().as_raw().saturating_add(10_000);
    let state = reload_test_state(&temp, old_uid, 0.9);

    write_secure(&state.config.allowlist_path, "not-a-uid\n");
    write_secure(&state.config.policy_path, &policy(0.4));

    reload_state(&state);

    let reloadable = state.reloadable.load();
    assert!(reloadable.allowlist.is_allowed(old_uid));
    assert!(!policy_allows(&reloadable, 0.5));
}

#[tokio::test]
async fn reload_applies_allowlist_and_policy_together() {
    let temp = tempfile::tempdir().expect("tempdir");
    let old_uid = nix::unistd::getuid().as_raw().saturating_add(10_000);
    let new_uid = old_uid + 1;
    let state = reload_test_state(&temp, old_uid, 0.9);

    write_secure(&state.config.allowlist_path, &format!("{new_uid}\n"));
    write_secure(&state.config.policy_path, &policy(0.4));

    reload_state(&state);

    let reloadable = state.reloadable.load();
    assert!(!reloadable.allowlist.is_allowed(old_uid));
    assert!(reloadable.allowlist.is_allowed(new_uid));
    assert!(policy_allows(&reloadable, 0.5));
}

#[test]
fn remove_stale_socket_errors_on_permission_denied() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let socket_path = dir.path().join("ola.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&socket_path).expect("bind socket path");

    let err = remove_stale_socket_with(&socket_path, |_| {
        Err(std::io::Error::new(
            ErrorKind::PermissionDenied,
            "simulated denied",
        ))
    })
    .expect_err("must fail on PermissionDenied");
    let msg = err.to_string();
    assert!(
        msg.contains("not accessible"),
        "unexpected error message: {msg}"
    );
    assert!(socket_path.exists(), "path remains on PermissionDenied");
}

#[test]
fn remove_stale_socket_refuses_regular_file() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let socket_path = dir.path().join("ola.sock");
    fs::write(&socket_path, b"not a socket").expect("create regular file");

    let err = remove_stale_socket_with(&socket_path, |_| unreachable!("not a socket"))
        .expect_err("regular file must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("not a Unix socket"),
        "unexpected error message: {msg}"
    );
    assert!(socket_path.exists(), "regular file must not be removed");
}

#[test]
fn remove_stale_socket_refuses_symlink() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let target = dir.path().join("target.sock");
    let socket_path = dir.path().join("ola.sock");
    fs::write(&target, b"target").expect("create target");
    symlink(&target, &socket_path).expect("create symlink");

    let err = remove_stale_socket_with(&socket_path, |_| unreachable!("symlink"))
        .expect_err("symlink must fail");
    let msg = err.to_string();
    assert!(msg.contains("symlink"), "unexpected error message: {msg}");
    assert!(socket_path.exists(), "symlink must not be removed");
}
