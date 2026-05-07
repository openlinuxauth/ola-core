// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

// Core → adapter challenge. Every request carries a fresh single-use nonce
// the adapter must echo back.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationRequest {
    // Wire version. Mismatch fails loudly, no fallback.
    pub version: u8,

    // UUID for tracing the request through the audit log.
    pub id: [u8; 16],

    // Target UID for this authentication. Non-root clients get their
    // SO_PEERCRED UID; root callers must supply an explicit target UID.
    pub uid: u32,

    // Single-use challenge. The adapter commits to it in evidence_hash, so
    // a captured result cannot be replayed against a fresh nonce.
    pub nonce: [u8; 32],

    // Hard deadline. The adapter must respond before this UNIX-ms timestamp;
    // core also rejects late results after the adapter returns.
    pub deadline_ms: u64,
}
