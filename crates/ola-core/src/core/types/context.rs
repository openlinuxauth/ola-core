// SPDX-License-Identifier: Apache-2.0

use crate::core::types::decision::PolicyDecision;
use crate::core::types::request::VerificationRequest;
use crate::core::types::result::VerificationResult;

#[derive(Debug)]
pub struct AuthContext {
    pub uid: u32,
    pub method: String,
    pub request: VerificationRequest,
    pub result: VerificationResult,
    pub decision: Option<PolicyDecision>,
}
