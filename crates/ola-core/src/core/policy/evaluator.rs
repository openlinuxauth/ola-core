// SPDX-License-Identifier: Apache-2.0

use crate::core::policy::parser::PolicyParser;
use crate::core::policy::types::PolicyRule;
use crate::core::types::context::AuthContext;
use crate::core::types::decision::{DenyReason, PolicyDecision};
use crate::core::types::result::VerificationResult;
use crate::security::fs::OwnerPolicy;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct PolicyEngine {
    rules: Vec<PolicyRule>,
    max_result_age_secs: u64,
}

impl PolicyEngine {
    #[cfg(test)]
    pub fn from_config(path: &Path, max_result_age_secs: u64) -> anyhow::Result<Self> {
        Self::from_config_with_owner(path, max_result_age_secs, OwnerPolicy::RootOrCurrent)
    }

    pub fn from_config_with_owner(
        path: &Path,
        max_result_age_secs: u64,
        owner: OwnerPolicy,
    ) -> anyhow::Result<Self> {
        let config = PolicyParser::load_with_owner(path, owner)?;
        Ok(Self {
            rules: config.rules,
            max_result_age_secs,
        })
    }

    /// Single decision point. AuthContext in, PolicyDecision out. No side
    /// effects — does not write the audit log, consume nonces, or call
    /// adapters. Pure evaluation.
    ///
    /// Rule order is most-specific first — a rule targeting a specific
    /// AuthMethod beats a wildcard. Lets the operator set different
    /// thresholds per method: libfprint at 0.90, PIN at 1.0.
    pub fn evaluate(&self, context: &AuthContext) -> PolicyDecision {
        let result = &context.result;
        let request = &context.request;

        // No specific or wildcard rule matched. Fail closed.
        let Some(rule) = self.rules.iter().find(|r| Self::rule_matches(r, result)) else {
            return PolicyDecision::Deny(DenyReason::NoMatchingRule);
        };

        // Effective max age = min(rule.max_age_secs, global cap). The global
        // OLA_MAX_RESULT_AGE_SECS is a system-wide ceiling — even a rule that
        // accepts five-minute-old results gets clamped. Useful where any
        // result older than ten seconds is already suspect.
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        if result.timestamp_ms > now_ms {
            return PolicyDecision::Deny(DenyReason::ResultFromFuture {
                skew_ms: result.timestamp_ms - now_ms,
            });
        }

        let age_ms = now_ms - result.timestamp_ms;
        let max_age_secs = rule.max_age_secs.min(self.max_result_age_secs);
        let Some(max_age_ms) = max_age_secs.checked_mul(1000) else {
            return PolicyDecision::Deny(DenyReason::ResultTooOld {
                age_ms,
                max_age_ms: u64::MAX,
            });
        };
        if age_ms > max_age_ms {
            return PolicyDecision::Deny(DenyReason::ResultTooOld { age_ms, max_age_ms });
        }

        if !result.confidence.is_finite() || !(0.0..=1.0).contains(&result.confidence) {
            return PolicyDecision::Deny(DenyReason::InvalidConfidence {
                got: result.confidence,
            });
        }

        if result.confidence < rule.min_confidence {
            return PolicyDecision::Deny(DenyReason::ConfidenceTooLow {
                got: result.confidence,
                required: rule.min_confidence,
            });
        }

        // require_uid_match: the adapter-reported UID must match the request's
        // target UID. The adapter binds its sensor reading to an enrolled
        // identity; mismatches are denied.
        if rule.require_uid_match && result.uid != request.uid {
            return PolicyDecision::Deny(DenyReason::UidMismatch {
                claimed: request.uid,
                result_uid: result.uid,
            });
        }

        PolicyDecision::Allow
    }

    fn rule_matches(rule: &PolicyRule, result: &VerificationResult) -> bool {
        // PartialEq, not std::mem::discriminant. AuthMethod::Other("custom_a")
        // and AuthMethod::Other("custom_b") share a discriminant but are
        // different values; discriminant compare lets a rule for "custom_a"
        // match results from "custom_b".
        match &rule.method {
            None => true,
            Some(m) => m == &result.method,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::policy::types::PolicyRule;
    use crate::core::types::context::AuthContext;
    use crate::core::types::request::VerificationRequest;
    use crate::core::types::result::{AuthMethod, VerificationResult};

    fn engine_with_rule(rule: PolicyRule) -> PolicyEngine {
        engine_with_rule_and_global(rule, 30)
    }

    fn engine_with_rule_and_global(rule: PolicyRule, max_result_age_secs: u64) -> PolicyEngine {
        PolicyEngine {
            rules: vec![rule],
            max_result_age_secs,
        }
    }

    fn context(confidence: f32, result_uid: u32, timestamp_ms: u64) -> AuthContext {
        AuthContext {
            uid: 1000,
            method: "fido2".to_string(),
            request: VerificationRequest {
                version: 1,
                id: [1u8; 16],
                uid: 1000,
                nonce: [2u8; 32],
                deadline_ms: timestamp_ms + 1000,
            },
            result: VerificationResult {
                version: 1,
                id: [1u8; 16],
                confidence,
                method: AuthMethod::Fido2,
                timestamp_ms,
                uid: result_uid,
                nonce: [2u8; 32],
                evidence_hash: [3u8; 32],
            },
            decision: None,
        }
    }

    fn context_with_method(
        confidence: f32,
        result_uid: u32,
        timestamp_ms: u64,
        method: AuthMethod,
    ) -> AuthContext {
        let mut ctx = context(confidence, result_uid, timestamp_ms);
        ctx.result.method = method;
        ctx
    }

    #[test]
    fn test_policy_allows_matching_result() {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_millis() as u64;
        let engine = engine_with_rule(PolicyRule {
            method: Some(AuthMethod::Fido2),
            min_confidence: 1.0,
            max_age_secs: 30,
            require_uid_match: true,
        });
        assert_eq!(
            engine.evaluate(&context(1.0, 1000, now_ms)),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn test_policy_denies_low_confidence() {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_millis() as u64;
        let engine = engine_with_rule(PolicyRule {
            method: None,
            min_confidence: 0.9,
            max_age_secs: 30,
            require_uid_match: true,
        });
        assert!(matches!(
            engine.evaluate(&context(0.2, 1000, now_ms)),
            PolicyDecision::Deny(DenyReason::ConfidenceTooLow { .. })
        ));
    }

    #[test]
    fn test_policy_denies_uid_substitution() {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_millis() as u64;
        let engine = engine_with_rule(PolicyRule {
            method: Some(AuthMethod::Fido2),
            min_confidence: 0.9,
            max_age_secs: 30,
            require_uid_match: true,
        });

        assert!(matches!(
            engine.evaluate(&context(1.0, 1001, now_ms)),
            PolicyDecision::Deny(DenyReason::UidMismatch {
                claimed: 1000,
                result_uid: 1001
            })
        ));
    }

    #[test]
    fn test_policy_denies_result_older_than_rule_window() {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_millis() as u64;
        let engine = engine_with_rule(PolicyRule {
            method: Some(AuthMethod::Fido2),
            min_confidence: 0.9,
            max_age_secs: 1,
            require_uid_match: true,
        });

        assert!(matches!(
            engine.evaluate(&context(1.0, 1000, now_ms.saturating_sub(2_000))),
            PolicyDecision::Deny(DenyReason::ResultTooOld {
                max_age_ms: 1000,
                ..
            })
        ));
    }

    #[test]
    fn test_policy_global_age_cap_clamps_rule_window() {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_millis() as u64;
        let engine = engine_with_rule_and_global(
            PolicyRule {
                method: Some(AuthMethod::Fido2),
                min_confidence: 0.9,
                max_age_secs: 300,
                require_uid_match: true,
            },
            1,
        );

        assert!(matches!(
            engine.evaluate(&context(1.0, 1000, now_ms.saturating_sub(2_000))),
            PolicyDecision::Deny(DenyReason::ResultTooOld {
                max_age_ms: 1000,
                ..
            })
        ));
    }

    #[test]
    fn test_policy_denies_future_timestamp() {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_millis() as u64;
        let engine = engine_with_rule(PolicyRule {
            method: None,
            min_confidence: 0.1,
            max_age_secs: 30,
            require_uid_match: true,
        });
        assert!(matches!(
            engine.evaluate(&context(0.9, 1000, now_ms + 1000)),
            PolicyDecision::Deny(DenyReason::ResultFromFuture { .. })
        ));
    }

    #[test]
    fn test_policy_denies_overflowing_age_window() {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_millis() as u64;
        let engine = engine_with_rule_and_global(
            PolicyRule {
                method: Some(AuthMethod::Fido2),
                min_confidence: 0.9,
                max_age_secs: u64::MAX,
                require_uid_match: true,
            },
            u64::MAX,
        );

        assert!(matches!(
            engine.evaluate(&context(1.0, 1000, now_ms)),
            PolicyDecision::Deny(DenyReason::ResultTooOld {
                max_age_ms: u64::MAX,
                ..
            })
        ));
    }

    #[test]
    fn test_policy_denies_invalid_confidence() {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_millis() as u64;
        let engine = engine_with_rule(PolicyRule {
            method: None,
            min_confidence: 0.1,
            max_age_secs: 30,
            require_uid_match: true,
        });
        assert!(matches!(
            engine.evaluate(&context(1.5, 1000, now_ms)),
            PolicyDecision::Deny(DenyReason::InvalidConfidence { .. })
        ));
    }

    #[test]
    fn test_policy_other_method_requires_exact_value_match() {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_millis() as u64;
        let engine = engine_with_rule(PolicyRule {
            method: Some(AuthMethod::Other("custom_a".to_string())),
            min_confidence: 0.1,
            max_age_secs: 30,
            require_uid_match: true,
        });

        let mismatch =
            context_with_method(0.9, 1000, now_ms, AuthMethod::Other("custom_b".to_string()));
        assert!(matches!(
            engine.evaluate(&mismatch),
            PolicyDecision::Deny(DenyReason::NoMatchingRule)
        ));

        let match_ctx =
            context_with_method(0.9, 1000, now_ms, AuthMethod::Other("custom_a".to_string()));
        assert_eq!(engine.evaluate(&match_ctx), PolicyDecision::Allow);
    }
}
