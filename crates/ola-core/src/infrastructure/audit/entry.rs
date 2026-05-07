// SPDX-License-Identifier: Apache-2.0

use crate::core::types::context::AuthContext;
use crate::core::types::decision::PolicyDecision;
use crate::core::types::result::VerificationResult;
use crate::infrastructure::audit::hex::encode_hex;
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

/// One durable authorization fact. The logger fills `prev_hash` and
/// `entry_hash`; callers leave them empty.
#[derive(Serialize)]
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
