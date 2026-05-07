// SPDX-License-Identifier: Apache-2.0

use crate::infrastructure::audit::entry::AuditEntry;
use crate::infrastructure::audit::hex::hex_sha256;
use crate::security::fs::{open_secure_append, OwnerPolicy};
use anyhow::Context;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Append-mode audit log. Allow or deny returns only after its entry lands.
/// Serialize, write, sync. If one fails, callers fail closed.
///
/// O_NOFOLLOW rejects log symlinks. The mutex keeps each JSON line whole.
struct AuditState {
    file: File,
    prev_hash: String,
}

pub struct AuditLogger {
    path: PathBuf,
    owner: OwnerPolicy,
    state: Arc<Mutex<AuditState>>,
}

impl AuditLogger {
    pub fn open(path: &Path, owner: OwnerPolicy) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let prev_hash = last_entry_hash(path)?;
        let file = open_secure_append(path, 0o640, owner)?;
        Ok(Self {
            path: path.to_path_buf(),
            owner,
            state: Arc::new(Mutex::new(AuditState { file, prev_hash })),
        })
    }

    pub fn reopen(&self) -> anyhow::Result<()> {
        let prev_hash = last_entry_hash(&self.path)?;
        let file = open_secure_append(&self.path, 0o640, self.owner)?;
        let mut guard = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("audit mutex poisoned"))?;
        *guard = AuditState { file, prev_hash };
        Ok(())
    }

    pub async fn log(&self, mut entry: AuditEntry) -> anyhow::Result<()> {
        let state = self.state.clone();

        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let mut state = state
                .lock()
                .map_err(|_| anyhow::anyhow!("audit mutex poisoned"))?;

            entry.prev_hash = state.prev_hash.clone();
            entry.entry_hash.clear();
            let payload = serde_json::to_vec(&entry).context("audit serialization failed")?;
            entry.entry_hash = hex_sha256(&payload);
            let line = serde_json::to_string(&entry).context("audit serialization failed")? + "\n";

            state
                .file
                .write_all(line.as_bytes())
                .context("audit write failed")?;

            // Missing audit entries are worse than local login latency.
            state.file.sync_data().context("audit fsync failed")?;
            state.prev_hash = entry.entry_hash;
            Ok(())
        })
        .await
        .context("audit logging task failed")??;

        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn from_file_for_test(file: File) -> Self {
        Self {
            path: PathBuf::new(),
            owner: OwnerPolicy::RootOrCurrent,
            state: Arc::new(Mutex::new(AuditState {
                file,
                prev_hash: ZERO_HASH.to_string(),
            })),
        }
    }
}

fn last_entry_hash(path: &Path) -> anyhow::Result<String> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(ZERO_HASH.to_string()),
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            anyhow::bail!("audit log {} is a symlink", path.display());
        }
        Err(e) => return Err(e).with_context(|| format!("reading audit log {}", path.display())),
    };

    let mut last = None;
    for line in BufReader::new(file).lines() {
        let line = line?;
        if !line.trim().is_empty() {
            last = Some(line);
        }
    }

    let Some(line) = last else {
        return Ok(ZERO_HASH.to_string());
    };
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) {
        if let Some(hash) = value.get("entry_hash").and_then(|v| v.as_str()) {
            if is_hex_hash(hash) {
                return Ok(hash.to_string());
            }
        }
    }
    Ok(hex_sha256(line.as_bytes()))
}

fn is_hex_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn entry(id: &str) -> AuditEntry {
        AuditEntry {
            ts_ms: 1,
            request_id: Some(id.to_string()),
            caller_uid: 1000,
            uid: 1000,
            adapter_name: Some("fido2".to_string()),
            method: "fido2".to_string(),
            decision: "allow".to_string(),
            deny_reason: None,
            confidence: 1.0,
            evidence_hash: String::new(),
            nonce_prefix: String::new(),
            prev_hash: String::new(),
            entry_hash: String::new(),
        }
    }

    #[test]
    fn test_open_rejects_symlink_log_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("real.log");
        let link = dir.path().join("audit.log");
        std::fs::write(&target, b"").expect("write target");
        symlink(&target, &link).expect("symlink log");

        let err = AuditLogger::open(&link, OwnerPolicy::RootOrCurrent)
            .err()
            .expect("symlink log must fail");
        assert!(err.to_string().contains("Too many levels") || err.to_string().contains("symlink"));
    }

    #[test]
    fn test_open_enforces_audit_log_mode() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log_path = dir.path().join("audit.log");
        std::fs::write(&log_path, b"").expect("write log");
        std::fs::set_permissions(&log_path, std::fs::Permissions::from_mode(0o600))
            .expect("set log mode");

        let _logger =
            AuditLogger::open(&log_path, OwnerPolicy::RootOrCurrent).expect("open audit log");
        let mode = std::fs::metadata(&log_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
    }

    #[tokio::test]
    async fn test_reopen_writes_to_recreated_log() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log_path = dir.path().join("audit.log");
        let rotated_path = dir.path().join("audit.log.1");
        let logger =
            AuditLogger::open(&log_path, OwnerPolicy::RootOrCurrent).expect("open audit log");

        logger
            .log(entry("before"))
            .await
            .expect("first audit write");
        std::fs::rename(&log_path, &rotated_path).expect("rotate log");
        std::fs::write(&log_path, b"").expect("create replacement log");
        std::fs::set_permissions(&log_path, std::fs::Permissions::from_mode(0o640))
            .expect("set replacement mode");

        logger.reopen().expect("reopen audit log");
        logger
            .log(entry("after"))
            .await
            .expect("second audit write");

        let old_log = std::fs::read_to_string(rotated_path).expect("read rotated log");
        let new_log = std::fs::read_to_string(log_path).expect("read new log");
        assert!(old_log.contains("before"));
        assert!(!old_log.contains("after"));
        assert!(new_log.contains("after"));
    }

    #[tokio::test]
    async fn audit_entries_form_hash_chain() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log_path = dir.path().join("audit.log");
        let logger =
            AuditLogger::open(&log_path, OwnerPolicy::RootOrCurrent).expect("open audit log");

        logger.log(entry("one")).await.expect("write first");
        logger.log(entry("two")).await.expect("write second");

        let log = std::fs::read_to_string(log_path).expect("read log");
        let lines = log.lines().collect::<Vec<_>>();
        let first: serde_json::Value = serde_json::from_str(lines[0]).expect("first json");
        let second: serde_json::Value = serde_json::from_str(lines[1]).expect("second json");
        let first_hash = first["entry_hash"].as_str().expect("first hash");

        assert_eq!(first["prev_hash"], ZERO_HASH);
        assert_eq!(second["prev_hash"], first_hash);
        assert!(is_hex_hash(first_hash));
        assert!(is_hex_hash(
            second["entry_hash"].as_str().expect("second hash")
        ));
    }
}
