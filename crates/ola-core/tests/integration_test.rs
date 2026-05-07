// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::zombie_processes)]

mod common;

use common::{MockAdapterBehavior, TestServer, PROTOCOL_VERSION};
use serde_json::json;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

#[tokio::test]
async fn test_ping() {
    let server = TestServer::start_without_adapter(
        "[[rules]]\nmin_confidence = 0.0\nmax_age_secs = 30\nrequire_uid_match = true\n",
    )
    .await;

    let response = server.send_request("ping-1", "ping", json!({})).await;
    assert_eq!(response["version"], PROTOCOL_VERSION);
    assert_eq!(response["id"], "ping-1");
    assert_eq!(response["result"]["ok"], true);
    assert!(response["error"].is_null());
}

#[tokio::test]
async fn test_status() {
    let server = TestServer::start_without_adapter(
        "[[rules]]\nmin_confidence = 0.0\nmax_age_secs = 30\nrequire_uid_match = true\n",
    )
    .await;

    let response = server.send_request("status-1", "status", json!({})).await;
    assert_eq!(response["result"]["status"], "running");
    assert!(response["result"]["version"].is_string());
}

#[tokio::test]
async fn test_list_methods_empty() {
    let server = TestServer::start_without_adapter(
        "[[rules]]\nmin_confidence = 0.0\nmax_age_secs = 30\nrequire_uid_match = true\n",
    )
    .await;

    let response = server
        .send_request("methods-1", "list_methods", json!({}))
        .await;
    assert_eq!(response["id"], "methods-1");
    assert_eq!(response["result"], json!([]));
    assert!(response["error"].is_null());
}

#[tokio::test]
async fn test_invalid_json() {
    let server = TestServer::start_without_adapter(
        "[[rules]]\nmin_confidence = 0.0\nmax_age_secs = 30\nrequire_uid_match = true\n",
    )
    .await;
    let mut stream = UnixStream::connect(&server.socket_path)
        .await
        .expect("connect");

    stream
        .write_all(b"invalid json\n")
        .await
        .expect("write invalid json");

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await.expect("read error response");
    let response = String::from_utf8_lossy(&buf[..n]);

    let resp: serde_json::Value = serde_json::from_str(response.trim()).expect("parse response");
    assert!(resp["error"]
        .as_str()
        .expect("string error")
        .contains("Invalid JSON"));
}

#[tokio::test]
async fn test_sighup_reload_survives_seccomp() {
    let server = TestServer::start_without_adapter(
        "[[rules]]\nmin_confidence = 0.0\nmax_age_secs = 30\nrequire_uid_match = true\n",
    )
    .await;

    // SAFETY: server.pid() is the child process spawned by this test.
    let ret = unsafe { libc::kill(server.pid() as i32, libc::SIGHUP) };
    assert_eq!(ret, 0, "send SIGHUP");
    tokio::time::sleep(Duration::from_millis(100)).await;

    let response = server
        .send_request("ping-after-hup", "ping", json!({}))
        .await;
    assert_eq!(response["result"]["ok"], true);
}

#[tokio::test]
async fn test_verify_once_rejects_invalid_method_type() {
    let server = TestServer::start_without_adapter(
        "[[rules]]\nmin_confidence = 0.0\nmax_age_secs = 30\nrequire_uid_match = true\n",
    )
    .await;

    let response = server
        .send_request("bad-method", "verify_once", json!({"method": null}))
        .await;
    assert!(response["result"].is_null());
    assert!(response["error"]
        .as_str()
        .expect("error")
        .contains("params.method must be a string"));
}

#[tokio::test]
async fn test_sighup_policy_reload_takes_effect() {
    let server = TestServer::start_with_adapter(
        "[[rules]]\nmethod = \"fido2\"\nmin_confidence = 0.9\nmax_age_secs = 30\nrequire_uid_match = true\n",
        MockAdapterBehavior::allow("fido2").with_confidence(0.5),
        "fido2",
    )
    .await;

    let denied = server
        .send_request("reload-before", "verify_once", json!({"method": "fido2"}))
        .await;
    assert_eq!(denied["result"]["decision"], "deny");

    std::fs::write(
        server.policy_path(),
        "[[rules]]\nmethod = \"fido2\"\nmin_confidence = 0.4\nmax_age_secs = 30\nrequire_uid_match = true\n",
    )
    .expect("rewrite policy");
    // SAFETY: server.pid() is the child process spawned by this test.
    let ret = unsafe { libc::kill(server.pid() as i32, libc::SIGHUP) };
    assert_eq!(ret, 0, "send SIGHUP");
    tokio::time::sleep(Duration::from_millis(100)).await;

    let allowed = server
        .send_request("reload-after", "verify_once", json!({"method": "fido2"}))
        .await;
    assert_eq!(allowed["result"]["decision"], "allow");
}

#[tokio::test]
async fn test_unknown_method() {
    let server = TestServer::start_without_adapter(
        "[[rules]]\nmin_confidence = 0.0\nmax_age_secs = 30\nrequire_uid_match = true\n",
    )
    .await;

    let response = server
        .send_request("unknown-1", "nonexistent_method", json!({}))
        .await;

    assert!(response["error"]
        .as_str()
        .expect("error string")
        .contains("Unknown method"));
}

#[tokio::test]
async fn test_oversized_payload() {
    let server = TestServer::start_without_adapter(
        "[[rules]]\nmin_confidence = 0.0\nmax_age_secs = 30\nrequire_uid_match = true\n",
    )
    .await;
    let huge_string = "a".repeat(600 * 1024);

    let mut stream = UnixStream::connect(&server.socket_path)
        .await
        .expect("connect");
    let req = json!({
        "version": PROTOCOL_VERSION,
        "id": "oversized-1",
        "method": "ping",
        "params": {"data": huge_string}
    });
    let req_str = format!(
        "{}\n",
        serde_json::to_string(&req).expect("serialize request")
    );
    stream
        .write_all(req_str.as_bytes())
        .await
        .expect("write oversized request");

    let mut buf = [0u8; 1024];
    let read_result = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .expect("read timeout");
    match read_result {
        Ok(0) => {}
        Ok(n) => panic!(
            "expected oversized payload to be rejected at framing layer with closed connection, got {n} bytes"
        ),
        Err(e) => {
            let kind = e.kind();
            assert!(
                matches!(
                    kind,
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::UnexpectedEof
                ),
                "unexpected read error kind: {kind:?}"
            );
        }
    }
}

#[tokio::test]
async fn test_idle_connections_release_connection_permits() {
    let server = TestServer::start_without_adapter(
        "[[rules]]\nmin_confidence = 0.0\nmax_age_secs = 30\nrequire_uid_match = true\n",
    )
    .await;

    let mut idle_connections = Vec::new();
    for _ in 0..16 {
        idle_connections.push(
            UnixStream::connect(&server.socket_path)
                .await
                .expect("connect idle client"),
        );
    }

    tokio::time::sleep(Duration::from_millis(1200)).await;

    let response = tokio::time::timeout(
        Duration::from_secs(3),
        server.send_request("after-idle", "ping", json!({})),
    )
    .await
    .expect("idle connections release permits");
    assert_eq!(response["result"]["ok"], true);

    drop(idle_connections);
}

#[tokio::test]
async fn test_rate_limit_applies_to_reused_connection() {
    let server = TestServer::start_without_adapter(
        "[[rules]]\nmin_confidence = 0.0\nmax_age_secs = 30\nrequire_uid_match = true\n",
    )
    .await;
    let mut stream = UnixStream::connect(&server.socket_path)
        .await
        .expect("connect");

    for i in 0..120 {
        let req = json!({
            "version": PROTOCOL_VERSION,
            "id": format!("rl-{i}"),
            "method": "ping",
            "params": {}
        });
        let line = format!(
            "{}\n",
            serde_json::to_string(&req).expect("serialize request")
        );
        if let Err(e) = stream.write_all(line.as_bytes()).await {
            if e.kind() == std::io::ErrorKind::BrokenPipe {
                break;
            }
            panic!("write request: {e}");
        }
    }

    let mut buf = Vec::new();
    let saw_rate_limit = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let mut chunk = [0u8; 4096];
            let n = stream.read(&mut chunk).await.expect("read response");
            if n == 0 {
                return String::from_utf8_lossy(&buf).contains("Rate limit exceeded");
            }
            buf.extend_from_slice(&chunk[..n]);
            if String::from_utf8_lossy(&buf).contains("Rate limit exceeded") {
                return true;
            }
        }
    })
    .await
    .expect("rate limit response timeout");

    assert!(
        saw_rate_limit,
        "expected persistent connection to hit request rate limit"
    );
}

#[tokio::test]
async fn test_verify_once_no_adapters_denied() {
    let server = TestServer::start_without_adapter(
        "[[rules]]\nmin_confidence = 0.0\nmax_age_secs = 30\nrequire_uid_match = true\n",
    )
    .await;

    let response = server
        .send_request("verify-none", "verify_once", json!({"method": "fido2"}))
        .await;
    assert_eq!(response["result"]["decision"], "deny");
    assert!(response["result"]["deny_reason"]
        .as_str()
        .expect("deny reason")
        .contains("method"));
}

#[tokio::test]
async fn test_verify_once_mock_adapter_allow() {
    let server = TestServer::start_with_adapter(
        "[[rules]]\nmethod = \"fido2\"\nmin_confidence = 1.0\nmax_age_secs = 30\nrequire_uid_match = true\n",
        MockAdapterBehavior::allow("fido2"),
        "fido2",
    )
    .await;

    let response = server
        .send_request("verify-ok", "verify_once", json!({"method": "fido2"}))
        .await;
    assert_eq!(response["result"]["decision"], "allow");
    assert_eq!(response["result"]["method"], "fido2");

    let audit = std::fs::read_to_string(server.audit_log_path()).expect("read audit log");
    assert!(audit.contains("\"decision\":\"allow\""));
    assert!(audit.contains("\"request_id\":\"verify-ok\""));
    assert!(audit.contains("\"adapter_name\":\"fido2\""));
    assert!(audit.contains(&format!(
        "\"caller_uid\":{}",
        nix::unistd::getuid().as_raw()
    )));
}

#[tokio::test]
async fn test_nonce_replay_denied() {
    let server = TestServer::start_with_adapter(
        "[[rules]]\nmethod = \"fido2\"\nmin_confidence = 1.0\nmax_age_secs = 30\nrequire_uid_match = true\n",
        MockAdapterBehavior::allow("fido2").with_replay_first_response(),
        "fido2",
    )
    .await;

    let first = server
        .send_request("replay-1", "verify_once", json!({"method": "fido2"}))
        .await;
    assert_eq!(first["result"]["decision"], "allow");

    let second = server
        .send_request("replay-2", "verify_once", json!({"method": "fido2"}))
        .await;
    assert_eq!(second["result"]["decision"], "deny");
    assert!(second["result"]["deny_reason"]
        .as_str()
        .expect("deny reason")
        .contains("nonce"));
}

#[tokio::test]
async fn test_nonce_mismatch_denied() {
    let server = TestServer::start_with_adapter(
        "[[rules]]\nmethod = \"fido2\"\nmin_confidence = 1.0\nmax_age_secs = 30\nrequire_uid_match = true\n",
        MockAdapterBehavior::allow("fido2").with_tamper_nonce(),
        "fido2",
    )
    .await;

    let response = server
        .send_request("nonce-mismatch", "verify_once", json!({"method": "fido2"}))
        .await;
    assert_eq!(response["result"]["decision"], "deny");
    assert!(response["result"]["deny_reason"]
        .as_str()
        .expect("deny reason")
        .contains("nonce"));

    let audit = std::fs::read_to_string(server.audit_log_path()).expect("read audit log");
    let entry: serde_json::Value =
        serde_json::from_str(audit.lines().next().expect("audit entry")).expect("parse audit");
    assert_eq!(entry["adapter_name"], "fido2");
    assert_eq!(entry["deny_reason"], "nonce_mismatch");
    assert_eq!(entry["evidence_hash"].as_str().unwrap().len(), 64);
    assert_eq!(entry["nonce_prefix"].as_str().unwrap().len(), 16);
}

#[tokio::test]
async fn test_invalid_evidence_hash_denied() {
    let server = TestServer::start_with_adapter(
        "[[rules]]\nmethod = \"fido2\"\nmin_confidence = 1.0\nmax_age_secs = 30\nrequire_uid_match = true\n",
        MockAdapterBehavior::allow("fido2").with_tamper_hash(),
        "fido2",
    )
    .await;

    let response = server
        .send_request("bad-hash", "verify_once", json!({"method": "fido2"}))
        .await;
    assert_eq!(response["result"]["decision"], "deny");
    assert!(response["result"]["deny_reason"]
        .as_str()
        .expect("deny reason")
        .contains("invalid evidence hash"));

    let audit = std::fs::read_to_string(server.audit_log_path()).expect("read audit log");
    let entry: serde_json::Value =
        serde_json::from_str(audit.lines().next().expect("audit entry")).expect("parse audit");
    assert_eq!(entry["adapter_name"], "fido2");
    assert_eq!(entry["deny_reason"], "attestation_hash_mismatch");
    assert_eq!(entry["evidence_hash"].as_str().unwrap().len(), 64);
    assert_eq!(entry["nonce_prefix"].as_str().unwrap().len(), 16);
}

#[tokio::test]
async fn test_method_mismatch_denied() {
    let server = TestServer::start_with_adapter(
        "[[rules]]\nmin_confidence = 1.0\nmax_age_secs = 30\nrequire_uid_match = true\n",
        MockAdapterBehavior::allow("fido2").with_result_method("pin"),
        "fido2",
    )
    .await;

    let response = server
        .send_request("method-mismatch", "verify_once", json!({"method": "fido2"}))
        .await;
    assert_eq!(response["result"]["decision"], "deny");
    assert!(response["result"]["deny_reason"]
        .as_str()
        .expect("deny reason")
        .contains("method mismatch"));
}

#[tokio::test]
async fn test_low_confidence_denied() {
    let server = TestServer::start_with_adapter(
        "[[rules]]\nmethod = \"fido2\"\nmin_confidence = 0.9\nmax_age_secs = 30\nrequire_uid_match = true\n",
        MockAdapterBehavior::allow("fido2").with_confidence(0.4),
        "fido2",
    )
    .await;

    let response = server
        .send_request("low-confidence", "verify_once", json!({"method": "fido2"}))
        .await;
    assert_eq!(response["result"]["decision"], "deny");
    assert!(response["result"]["deny_reason"]
        .as_str()
        .expect("deny reason")
        .contains("ConfidenceTooLow"));
}

#[tokio::test]
async fn test_adapter_queue_times_out_when_adapter_is_busy() {
    let server = TestServer::start_with_adapter(
        "[[rules]]\nmethod = \"fido2\"\nmin_confidence = 1.0\nmax_age_secs = 30\nrequire_uid_match = true\n",
        MockAdapterBehavior::allow("fido2").with_response_delay_ms(1000),
        "fido2",
    )
    .await;

    let first = server.send_request("busy-first", "verify_once", json!({"method": "fido2"}));
    let second = async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        server
            .send_request("busy-second", "verify_once", json!({"method": "fido2"}))
            .await
    };

    let (first_response, second_response) = tokio::join!(first, second);
    assert_eq!(first_response["result"]["decision"], "allow");
    assert_eq!(second_response["result"]["decision"], "deny");
    assert!(second_response["result"]["deny_reason"]
        .as_str()
        .expect("deny reason")
        .contains("adapter busy"));
}
