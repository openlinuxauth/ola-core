// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, Clone, PartialEq)]
pub enum PolicyDecision {
    Allow,
    Deny(DenyReason),
}

#[derive(Debug, Clone, PartialEq)]
pub enum DenyReason {
    ConfidenceTooLow { got: f32, required: f32 },
    InvalidConfidence { got: f32 },
    ResultTooOld { age_ms: u64, max_age_ms: u64 },
    ResultFromFuture { skew_ms: u64 },
    UidMismatch { claimed: u32, result_uid: u32 },
    NoMatchingRule,
}
