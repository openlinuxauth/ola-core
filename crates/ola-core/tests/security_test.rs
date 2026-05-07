// SPDX-License-Identifier: Apache-2.0

mod common;

#[path = "../src/security/fs.rs"]
pub mod secure_fs;

mod security {
    pub use crate::secure_fs as fs;
}

#[path = "../src/security/allowlist.rs"]
mod allowlist;

use allowlist::Allowlist;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;

#[test]
fn allowlist_rejects_world_readable_file() {
    let file = tempfile::NamedTempFile::new().expect("create allowlist");
    std::fs::write(file.path(), "1000\n").expect("write allowlist");

    let mut perms = file.as_file().metadata().unwrap().permissions();
    perms.set_mode(0o644);
    file.as_file().set_permissions(perms).unwrap();

    let mut allowlist = Allowlist::new();
    let err = allowlist
        .load_from_file(file.path())
        .expect_err("world-readable allowlist must be rejected");
    assert!(err.to_string().contains("mode 0600 or 0640"));
}

#[tokio::test]
async fn basic_rpc_responses_do_not_expose_sensitive_fields() {
    let server = common::TestServer::start_without_adapter(
        "[[rules]]\nmin_confidence = 0.9\nmax_age_secs = 30\nrequire_uid_match = true\n",
    )
    .await;

    for (id, method) in [
        ("sec-ping", "ping"),
        ("sec-status", "status"),
        ("sec-list-methods", "list_methods"),
    ] {
        let response = server.send_request(id, method, json!({})).await;
        let response_str = serde_json::to_string(&response).unwrap();
        assert!(!response_str.contains("password"));
        assert!(!response_str.contains("secret"));
        assert!(!response_str.contains("private_key"));
        assert!(!response_str.contains("nonce"));
        assert!(!response_str.contains("evidence_hash"));
    }
}
