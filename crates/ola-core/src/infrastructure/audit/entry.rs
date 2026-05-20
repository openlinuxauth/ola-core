// SPDX-License-Identifier: Apache-2.0

use crate::core::types::context::AuthContext;
use crate::core::types::decision::PolicyDecision;
use crate::core::types::result::VerificationResult;
use crate::infrastructure::audit::hex::encode_hex;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

const HASH_PAYLOAD_V1_PREFIX: &[u8] = b"OLA-AUDIT-HASH-V1\n";

/// One durable authorization fact. The logger fills `prev_hash` and
/// `entry_hash`; callers leave them empty.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEntry {
    pub ts_ms: u64,
    pub request_id: Option<String>,
    pub caller_uid: u32,
    pub uid: u32,
    pub adapter_name: Option<String>,
    pub method: String,
    pub decision: String,
    pub deny_reason: Option<String>,
    pub confidence: f32,
    pub evidence_hash: String,
    pub nonce_prefix: String,

    #[serde(skip_serializing_if = "String::is_empty")]
    pub prev_hash: String,

    #[serde(skip_serializing_if = "String::is_empty")]
    pub entry_hash: String,
}

impl AuditEntry {
    /// Stable input for audit hashes. JSON is only the storage format.
    pub(crate) fn hash_payload_v1(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(HASH_PAYLOAD_V1_PREFIX);

        push_value(&mut out, "ts_ms", self.ts_ms);
        push_opt(&mut out, "request_id", self.request_id.as_deref());
        push_value(&mut out, "caller_uid", self.caller_uid);
        push_value(&mut out, "uid", self.uid);
        push_opt(&mut out, "adapter_name", self.adapter_name.as_deref());
        push_str(&mut out, "method", &self.method);
        push_str(&mut out, "decision", &self.decision);
        push_opt(&mut out, "deny_reason", self.deny_reason.as_deref());
        push_value(
            &mut out,
            "confidence",
            format!("{:08x}", self.confidence.to_bits()),
        );
        push_str(&mut out, "evidence_hash", &self.evidence_hash);
        push_str(&mut out, "nonce_prefix", &self.nonce_prefix);
        push_str(&mut out, "prev_hash", &self.prev_hash);

        out
    }

    pub(crate) fn deny(
        caller_uid: u32,
        uid: u32,
        method: &str,
        reason: &str,
        adapter_name: Option<String>,
        request_id: Option<String>,
        result: Option<&VerificationResult>,
    ) -> Self {
        let (confidence, evidence_hash, nonce_prefix) = result
            .map(result_fields)
            .unwrap_or_else(|| (0.0, String::new(), String::new()));

        Self {
            ts_ms: now_ms(),
            request_id,
            caller_uid,
            uid,
            adapter_name,
            method: method.to_string(),
            decision: "deny".to_string(),
            deny_reason: Some(reason.to_string()),
            confidence,
            evidence_hash,
            nonce_prefix,
            prev_hash: String::new(),
            entry_hash: String::new(),
        }
    }

    pub(crate) fn from_decision(
        context: &AuthContext,
        decision: &PolicyDecision,
        caller_uid: u32,
        adapter_name: Option<String>,
        request_id: Option<String>,
    ) -> Self {
        let (decision, deny_reason) = match decision {
            PolicyDecision::Allow => ("allow".to_string(), None),
            PolicyDecision::Deny(reason) => ("deny".to_string(), Some(format!("{reason:?}"))),
        };
        let (_, evidence_hash, nonce_prefix) = result_fields(&context.result);

        Self {
            ts_ms: now_ms(),
            request_id,
            caller_uid,
            uid: context.uid,
            adapter_name,
            method: context.method.clone(),
            decision,
            deny_reason,
            confidence: context.result.confidence,
            evidence_hash,
            nonce_prefix,
            prev_hash: String::new(),
            entry_hash: String::new(),
        }
    }
}

fn push_value(out: &mut Vec<u8>, name: &str, value: impl std::fmt::Display) {
    push_bytes(out, name, b'v', value.to_string().as_bytes());
}

fn push_str(out: &mut Vec<u8>, name: &str, value: &str) {
    push_bytes(out, name, b'v', value.as_bytes());
}

fn push_opt(out: &mut Vec<u8>, name: &str, value: Option<&str>) {
    match value {
        Some(value) => push_bytes(out, name, b's', value.as_bytes()),
        None => push_bytes(out, name, b'n', b""),
    }
}

fn push_bytes(out: &mut Vec<u8>, name: &str, tag: u8, value: &[u8]) {
    out.extend_from_slice(name.as_bytes());
    out.push(b':');
    out.push(tag);
    out.push(b':');
    out.extend_from_slice(value.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(value);
    out.push(b'\n');
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn result_fields(result: &VerificationResult) -> (f32, String, String) {
    (
        result.confidence,
        encode_hex(&result.evidence_hash),
        encode_hex(&result.nonce[0..8]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::audit::hex::hex_sha256;

    fn entry() -> AuditEntry {
        AuditEntry {
            ts_ms: 1,
            request_id: Some("req-1".to_string()),
            caller_uid: 1000,
            uid: 1000,
            adapter_name: Some("fido2".to_string()),
            method: "fido2".to_string(),
            decision: "allow".to_string(),
            deny_reason: None,
            confidence: 1.0,
            evidence_hash: "abc123".to_string(),
            nonce_prefix: "0011223344556677".to_string(),
            prev_hash: "0".repeat(64),
            entry_hash: String::new(),
        }
    }

    #[test]
    fn hash_payload_v1_has_known_digest() {
        assert_eq!(
            hex_sha256(&entry().hash_payload_v1()),
            "f0370ed8cca05c9c7c3b7d280627134d3c140413e904e2cef10104bcbecd5521"
        );
    }

    #[test]
    fn entry_hash_is_not_hashed() {
        let mut entry = entry();
        let before = entry.hash_payload_v1();

        entry.entry_hash = "changed".to_string();

        assert_eq!(entry.hash_payload_v1(), before);
    }

    #[test]
    fn absent_and_empty_optional_strings_differ() {
        let mut absent = entry();
        absent.request_id = None;

        let mut empty = entry();
        empty.request_id = Some(String::new());

        assert_ne!(absent.hash_payload_v1(), empty.hash_payload_v1());
    }
}
