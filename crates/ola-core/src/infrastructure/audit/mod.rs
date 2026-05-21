// SPDX-License-Identifier: Apache-2.0

pub mod entry;
pub(crate) mod hex;
pub mod logger;
pub mod metrics;
pub(crate) mod verifier;

pub use entry::AuditEntry;
pub use logger::AuditLogger;

pub(crate) const ZERO_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
