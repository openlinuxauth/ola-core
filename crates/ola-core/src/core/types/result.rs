// SPDX-License-Identifier: Apache-2.0

use crate::core::types::method::validate_method_name;
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AuthMethod {
    Libfprint,
    Fido2,
    Pin,
    // Adapter-declared string. Forward compat for methods not enumerated yet.
    Other(String),
}

impl AuthMethod {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Libfprint => "libfprint",
            Self::Fido2 => "fido2",
            Self::Pin => "pin",
            Self::Other(value) => value.as_str(),
        }
    }
}

impl Serialize for AuthMethod {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AuthMethod {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Ok(match raw.as_str() {
            "libfprint" => Self::Libfprint,
            "fido2" => Self::Fido2,
            "pin" => Self::Pin,
            "any" => {
                return Err(D::Error::custom(
                    "'any' is only valid as a wildcard policy selector",
                ))
            }
            other => {
                validate_method_name(other, false).map_err(D::Error::custom)?;
                Self::Other(other.to_string())
            }
        })
    }
}

impl fmt::Display for AuthMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// Adapter-returned evidence. Policy engine treats this as raw data and
// evaluates it against the operator's rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    // Wire version. Mismatch means the adapter binary is wrong.
    pub version: u8,

    // Correlation ID echoed from the VerificationRequest.
    pub id: [u8; 16],

    // Match score. 1.0 is binary (FIDO2, PIN). Biometrics return floats
    // compared against the rule's min_confidence.
    pub confidence: f32,

    pub method: AuthMethod,

    // Adapter's clock when it produced the result. Checked against freshness
    // rules. HMAC binding stops unsigned timestamp mutation after signing.
    pub timestamp_ms: u64,

    // UID the adapter claims it authenticated. Policy can require this to
    // match the target UID in the request.
    pub uid: u32,

    // The challenge nonce from the request, echoed unchanged. Single-use.
    // Primary replay defence.
    pub nonce: [u8; 32],

    // HMAC over (nonce ‖ uid ‖ method_sha256 ‖ confidence ‖ timestamp). Proves
    // the result came from a process holding the configured adapter key. Binary
    // identity is a deployment and provenance question; the wire proof is key
    // possession. Without the key, no valid hash for a given nonce.
    pub evidence_hash: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn libfprint_has_no_fingerprint_alias() {
        let method: AuthMethod = serde_json::from_str(r#""libfprint""#).expect("libfprint");
        assert_eq!(method, AuthMethod::Libfprint);
        assert!(serde_json::from_str::<AuthMethod>(r#""fingerprint""#).is_ok());
        assert_eq!(
            serde_json::from_str::<AuthMethod>(r#""fingerprint""#)
                .expect("custom fingerprint")
                .as_str(),
            "fingerprint"
        );
    }
}
