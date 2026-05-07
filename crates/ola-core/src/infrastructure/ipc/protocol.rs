// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

pub(crate) const PROTOCOL_VERSION: u8 = 1;

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct Request {
    pub(crate) version: u8,
    pub(crate) id: Option<String>,
    pub(crate) method: String,
    pub(crate) params: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct Response {
    pub(crate) version: u8,
    pub(crate) id: Option<String>,
    pub(crate) result: Option<serde_json::Value>,
    pub(crate) error: Option<String>,
}

impl Response {
    pub(crate) fn ok(id: Option<String>, result: serde_json::Value) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            id,
            result: Some(result),
            error: None,
        }
    }

    pub(crate) fn error(id: Option<String>, msg: impl Into<String>) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            id,
            result: None,
            error: Some(msg.into()),
        }
    }

    pub(crate) fn deny(id: Option<String>, reason: &str) -> Self {
        Self::ok(
            id,
            serde_json::json!({
                "decision": "deny",
                "deny_reason": reason,
            }),
        )
    }

    pub(crate) fn allow(id: Option<String>, method: &str) -> Self {
        Self::ok(
            id,
            serde_json::json!({
                "decision": "allow",
                "method": method,
            }),
        )
    }
}
