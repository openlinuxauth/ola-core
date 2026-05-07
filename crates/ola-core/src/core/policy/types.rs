// SPDX-License-Identifier: Apache-2.0

use crate::core::types::method::validate_method_name;
use crate::core::types::result::AuthMethod;
use serde::{de::IntoDeserializer, Deserialize};

#[derive(Debug, Deserialize)]
pub struct PolicyRule {
    // Method this rule applies to. None = wildcard. Specific rules win over
    // wildcards, so order in the file does not matter.
    #[serde(default, deserialize_with = "deserialize_policy_method")]
    pub method: Option<AuthMethod>,

    // Allow threshold. 1.0 is binary (FIDO2, PIN). Biometrics use 0.85–0.95
    // depending on the operator's risk tolerance.
    pub min_confidence: f32,

    // Freshness limit on the adapter's timestamp. Rejects results older than
    // this — kills replay of old-but-valid results.
    pub max_age_secs: u64,

    // result.uid must equal request.uid. Core's defence against substitution
    // where the adapter reports a different identity than the target user.
    pub require_uid_match: bool,
}

#[derive(Debug, Deserialize)]
pub struct PolicyConfig {
    pub rules: Vec<PolicyRule>,
}

fn deserialize_policy_method<'de, D>(deserializer: D) -> Result<Option<AuthMethod>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = Option::<String>::deserialize(deserializer)?;
    match raw.as_deref() {
        None | Some("any") => Ok(None),
        Some(value) => {
            validate_method_name(value, false).map_err(serde::de::Error::custom)?;
            AuthMethod::deserialize(value.into_deserializer()).map(Some)
        }
    }
}
