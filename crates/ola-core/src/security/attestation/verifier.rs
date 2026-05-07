// SPDX-License-Identifier: Apache-2.0

use crate::core::types::result::{AuthMethod, VerificationResult};
use crate::security::fs::{read_secure_exact, ModePolicy, OwnerPolicy, SecureFileSpec, SizePolicy};
use anyhow::Context;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use subtle::ConstantTimeEq;

/// HMAC verification for adapter responses.
///
/// Each adapter has a 32-byte key, provisioned at registration and stored at
/// /etc/ola/adapter-keys/<name>.key. The adapter HMAC-SHA256s the result
/// fields and sends the digest as evidence_hash. Core recomputes from its
/// copy of the key and compares constant-time.
///
/// Closes two attacks. First, a process squatting on the adapter socket
/// cannot fabricate results unless it also has the adapter key. Second, a
/// captured result cannot be replayed — the HMAC commits to the nonce, which
/// is single-use.
pub struct AttestationVerifier {
    adapter_keys: HashMap<String, [u8; 32]>,
}

impl AttestationVerifier {
    pub fn new(adapter_keys: HashMap<String, [u8; 32]>) -> Self {
        Self { adapter_keys }
    }

    pub fn load_from_dir_with_owner(dir: &Path, owner: OwnerPolicy) -> anyhow::Result<Self> {
        let mut keys = HashMap::new();

        if !dir.exists() || !dir.is_dir() {
            return Ok(Self::new(keys));
        }

        for entry in std::fs::read_dir(dir)
            .with_context(|| format!("reading adapter key directory {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() || path.extension().is_none_or(|ext| ext != "key") {
                continue;
            }

            let name = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .ok_or_else(|| anyhow::anyhow!("invalid adapter key filename {}", path.display()))?
                .to_string();
            let key = load_key_file_with_owner(&path, owner)?;
            keys.insert(name, key);
        }

        Ok(Self::new(keys))
    }

    pub fn require_keys_for_adapters(&self, adapter_names: &[String]) -> anyhow::Result<()> {
        let missing = adapter_names
            .iter()
            .filter(|name| !self.adapter_keys.contains_key(*name))
            .cloned()
            .collect::<Vec<_>>();

        if !missing.is_empty() {
            anyhow::bail!(
                "missing HMAC key for configured adapter(s): {}",
                missing.join(", ")
            );
        }

        Ok(())
    }

    pub fn verify(
        &self,
        adapter_name: &str,
        result: &VerificationResult,
    ) -> Result<(), AttestationError> {
        let key = self
            .adapter_keys
            .get(adapter_name)
            .ok_or(AttestationError::UnknownAdapter)?;

        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key size");

        // HMAC commits to: nonce ‖ uid_le ‖ method_sha256 ‖ confidence_bits_le ‖ timestamp_le.
        //
        // nonce — ties the result to a specific request, kills replay.
        // uid — binds the signed result to the adapter-reported target UID.
        // method_sha256 — commits to the exact method string. Custom methods
        //   cannot collapse onto one shared "other" byte.
        // confidence — adapter cannot return 0.4 over the wire while signing 1.0.
        // timestamp — policy engine checks freshness independently. Committing
        //   to the timestamp stops unsigned mutation after the adapter signs;
        //   a key-holding adapter can still choose the timestamp it signs.
        mac.update(&result.nonce);
        mac.update(&result.uid.to_le_bytes());
        mac.update(&Self::method_commitment(&result.method));
        mac.update(&result.confidence.to_bits().to_le_bytes());
        mac.update(&result.timestamp_ms.to_le_bytes());

        let expected = mac.finalize().into_bytes();

        // Constant-time compare. == short-circuits on first mismatch — the
        // comparison takes less time for a "more wrong" hash, leaking how close
        // the guess was. The practical risk over a local Unix socket is small,
        // the implementation cost is zero, and the principle matters in code
        // other projects cite.
        if expected.ct_eq(result.evidence_hash.as_slice()).unwrap_u8() != 1 {
            return Err(AttestationError::HashMismatch);
        }

        Ok(())
    }

    fn method_commitment(method: &AuthMethod) -> [u8; 32] {
        Sha256::digest(method.as_str().as_bytes()).into()
    }
}

#[cfg(test)]
fn load_key_file(path: &Path) -> anyhow::Result<[u8; 32]> {
    load_key_file_with_owner(path, OwnerPolicy::RootOrCurrent)
}

fn load_key_file_with_owner(path: &Path, owner: OwnerPolicy) -> anyhow::Result<[u8; 32]> {
    read_secure_exact::<32>(
        path,
        SecureFileSpec {
            label: "adapter key",
            size: SizePolicy::Exact(32),
            mode: ModePolicy::Exact(&[0o600]),
            owner,
        },
    )
}

#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    #[error("unknown adapter: no key found")]
    UnknownAdapter,
    #[error("evidence hash mismatch")]
    HashMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn sample_result() -> VerificationResult {
        VerificationResult {
            version: 1,
            id: [9u8; 16],
            confidence: 1.0,
            method: AuthMethod::Fido2,
            timestamp_ms: 1234,
            uid: 1000,
            nonce: [7u8; 32],
            evidence_hash: [0u8; 32],
        }
    }

    fn signed_result(key: [u8; 32]) -> VerificationResult {
        let mut result = sample_result();
        let mut mac = Hmac::<Sha256>::new_from_slice(&key).expect("hmac");
        mac.update(&result.nonce);
        mac.update(&result.uid.to_le_bytes());
        mac.update(&AttestationVerifier::method_commitment(&result.method));
        mac.update(&result.confidence.to_bits().to_le_bytes());
        mac.update(&result.timestamp_ms.to_le_bytes());
        result
            .evidence_hash
            .copy_from_slice(&mac.finalize().into_bytes());
        result
    }

    #[test]
    fn test_attestation_verifies_valid_hash() {
        let key = [5u8; 32];
        let mut keys = HashMap::new();
        keys.insert("fido2".to_string(), key);
        let verifier = AttestationVerifier::new(keys);
        assert!(verifier.verify("fido2", &signed_result(key)).is_ok());
    }

    #[test]
    fn test_attestation_rejects_unknown_adapter() {
        let verifier = AttestationVerifier::new(HashMap::new());
        assert!(matches!(
            verifier.verify("missing", &sample_result()),
            Err(AttestationError::UnknownAdapter)
        ));
    }

    #[test]
    fn test_attestation_rejects_modified_hash() {
        let key = [5u8; 32];
        let mut keys = HashMap::new();
        keys.insert("fido2".to_string(), key);
        let verifier = AttestationVerifier::new(keys);

        let mut result = signed_result(key);
        result.evidence_hash[0] ^= 0x01;

        assert!(matches!(
            verifier.verify("fido2", &result),
            Err(AttestationError::HashMismatch)
        ));
    }

    #[test]
    fn test_require_keys_for_configured_adapters() {
        let mut keys = HashMap::new();
        keys.insert("fido2".to_string(), [5u8; 32]);
        let verifier = AttestationVerifier::new(keys);

        let configured = vec!["fido2".to_string(), "pin".to_string()];
        let err = verifier
            .require_keys_for_adapters(&configured)
            .expect_err("pin key must be missing");
        assert!(err.to_string().contains("missing HMAC key"));
        assert!(err.to_string().contains("pin"));
    }

    #[test]
    fn test_custom_methods_have_distinct_commitments() {
        let left = AuthMethod::Other("custom_a".to_string());
        let right = AuthMethod::Other("custom_b".to_string());
        assert_ne!(
            AttestationVerifier::method_commitment(&left),
            AttestationVerifier::method_commitment(&right)
        );
    }

    fn write_key(path: &Path, bytes: &[u8], mode: u32) {
        std::fs::write(path, bytes).expect("write key");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .expect("set key mode");
    }

    #[test]
    fn test_key_loader_rejects_symlink() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("target.key");
        let link = dir.path().join("link.key");
        write_key(&target, &[7u8; 32], 0o600);
        symlink(&target, &link).expect("symlink key");

        let err = load_key_file(&link).expect_err("symlink key must fail");
        assert!(err.to_string().contains("safely open adapter key"));
    }

    #[test]
    fn test_key_loader_rejects_non_regular_file() {
        let dir = tempfile::tempdir().expect("tempdir");

        let err = load_key_file(dir.path()).expect_err("directory key path must fail");
        assert!(err.to_string().contains("regular file"));
    }

    #[test]
    fn test_key_loader_rejects_wrong_mode() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("adapter.key");
        write_key(&key_path, &[7u8; 32], 0o640);

        let err = load_key_file(&key_path).expect_err("group-readable key must fail");
        assert!(err.to_string().contains("mode 0600"));
    }

    #[test]
    fn test_key_loader_rejects_wrong_size() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("adapter.key");
        write_key(&key_path, &[7u8; 31], 0o600);

        let err = load_key_file(&key_path).expect_err("short key must fail");
        assert!(err.to_string().contains("exactly 32 bytes"));
    }
}
