// SPDX-License-Identifier: Apache-2.0

use crate::infrastructure::audit::entry::AuditEntry;
use crate::infrastructure::audit::hex::hex_sha256;
use crate::security::fs::{open_secure_append, OwnerPolicy};
use anyhow::Context;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const AUDIT_RECOVERY_WINDOW_BYTES: u64 = 1024 * 1024;

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

        let file = open_secure_append(path, 0o640, owner)?;
        let prev_hash = last_entry_hash(&file, path)?;
        Ok(Self {
            path: path.to_path_buf(),
            owner,
            state: Arc::new(Mutex::new(AuditState { file, prev_hash })),
        })
    }

    pub fn reopen(&self) -> anyhow::Result<()> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("audit mutex poisoned"))?;
        let prev_hash = guard.prev_hash.clone();
        let file = open_secure_append(&self.path, 0o640, self.owner)?;
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
            entry.entry_hash = hex_sha256(&entry.hash_payload_v1());
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

fn last_entry_hash(file: &File, path: &Path) -> anyhow::Result<String> {
    let mut file = file
        .try_clone()
        .with_context(|| format!("cloning audit log {}", path.display()))?;
    let len = file
        .metadata()
        .with_context(|| format!("checking audit log {}", path.display()))?
        .len();
    if len == 0 {
        return Ok(ZERO_HASH.to_string());
    }

    let start = len.saturating_sub(AUDIT_RECOVERY_WINDOW_BYTES);
    file.seek(SeekFrom::Start(start))
        .with_context(|| format!("seeking audit log {}", path.display()))?;

    let mut tail = Vec::with_capacity((len - start) as usize);
    file.read_to_end(&mut tail)
        .with_context(|| format!("reading audit log {}", path.display()))?;

    let truncated = start != 0;
    let tail = if !truncated {
        tail.as_slice()
    } else {
        match tail.iter().position(|b| *b == b'\n') {
            Some(pos) => &tail[pos + 1..],
            None => &[],
        }
    };

    let Some(line) = last_complete_line(tail) else {
        if !truncated && tail.iter().all(|b| b.is_ascii_whitespace()) {
            return Ok(ZERO_HASH.to_string());
        }
        anyhow::bail!(
            "audit log {} has no complete entry in recovery window",
            path.display()
        );
    };
    let line_str = std::str::from_utf8(line)
        .with_context(|| format!("audit log {} has non-utf8 entry", path.display()))?;
    recover_entry_hash(line_str, path)
}

fn last_complete_line(tail: &[u8]) -> Option<&[u8]> {
    if tail.last().is_some_and(|b| *b != b'\n') {
        return None;
    }

    tail.split(|b| *b == b'\n')
        .rev()
        .find(|line| !line.iter().all(|b| b.is_ascii_whitespace()))
}

// Startup carries this hash into the next entry. Do not recover from malformed data.
fn recover_entry_hash(line: &str, path: &Path) -> anyhow::Result<String> {
    let mut entry: AuditEntry = serde_json::from_str(line)
        .with_context(|| format!("audit log {} has malformed final entry", path.display()))?;

    if !is_lower_hex_hash(&entry.prev_hash) {
        anyhow::bail!("audit log {} has invalid final prev_hash", path.display());
    }
    if !is_lower_hex_hash(&entry.entry_hash) {
        anyhow::bail!("audit log {} has invalid final entry_hash", path.display());
    }

    let recovered = std::mem::take(&mut entry.entry_hash);
    let expected = hex_sha256(&entry.hash_payload_v1());
    if recovered != expected {
        anyhow::bail!(
            "audit log {} final entry_hash does not match entry",
            path.display()
        );
    }

    Ok(recovered)
}

fn is_lower_hex_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::io::{Seek, Write};
    use std::os::unix::ffi::OsStrExt;
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

    fn signed_entry_line(id: &str, prev_hash: &str) -> (String, String) {
        let mut entry = entry(id);
        entry.prev_hash = prev_hash.to_string();
        entry.entry_hash = hex_sha256(&entry.hash_payload_v1());
        let hash = entry.entry_hash.clone();
        (
            serde_json::to_string(&entry).expect("serialize entry"),
            hash,
        )
    }

    fn write_log(path: &std::path::Path, line: &str) {
        std::fs::write(path, format!("{line}\n")).expect("write log");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640))
            .expect("set log mode");
    }

    fn open_log_error(line: &str) -> String {
        let dir = tempfile::tempdir().expect("tempdir");
        let log_path = dir.path().join("audit.log");
        write_log(&log_path, line);
        AuditLogger::open(&log_path, OwnerPolicy::RootOrCurrent)
            .err()
            .expect("open must fail")
            .to_string()
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
    fn test_open_rejects_directory_log_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log_path = dir.path().join("audit.log");
        std::fs::create_dir(&log_path).expect("create log dir");

        assert!(AuditLogger::open(&log_path, OwnerPolicy::RootOrCurrent).is_err());
    }

    #[test]
    fn test_open_rejects_fifo_log_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log_path = dir.path().join("audit.log");
        let c_path = CString::new(log_path.as_os_str().as_bytes()).expect("cstring path");
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo failed: {}", std::io::Error::last_os_error());

        assert!(AuditLogger::open(&log_path, OwnerPolicy::RootOrCurrent).is_err());
    }

    #[test]
    fn test_open_accepts_private_log_mode_and_normalizes_it() {
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

    #[test]
    fn test_open_rejects_world_readable_log_mode() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log_path = dir.path().join("audit.log");
        std::fs::write(&log_path, b"").expect("write log");
        std::fs::set_permissions(&log_path, std::fs::Permissions::from_mode(0o644))
            .expect("set log mode");

        let err = AuditLogger::open(&log_path, OwnerPolicy::RootOrCurrent)
            .err()
            .expect("world-readable log must fail");
        assert!(err.to_string().contains("mode 0600 or 0640"));
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
    async fn test_reopen_rejects_bad_replacement_mode() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log_path = dir.path().join("audit.log");
        let rotated_path = dir.path().join("audit.log.1");
        let logger =
            AuditLogger::open(&log_path, OwnerPolicy::RootOrCurrent).expect("open audit log");

        logger.log(entry("before")).await.expect("write before");
        std::fs::rename(&log_path, &rotated_path).expect("rotate log");
        std::fs::write(&log_path, b"").expect("create replacement log");
        std::fs::set_permissions(&log_path, std::fs::Permissions::from_mode(0o644))
            .expect("set replacement mode");

        assert!(logger.reopen().is_err());
    }

    #[tokio::test]
    async fn test_reopen_keeps_hash_chain_after_late_write() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log_path = dir.path().join("audit.log");
        let rotated_path = dir.path().join("audit.log.1");
        let logger =
            AuditLogger::open(&log_path, OwnerPolicy::RootOrCurrent).expect("open audit log");

        logger.log(entry("one")).await.expect("write first");
        std::fs::rename(&log_path, &rotated_path).expect("rotate log");
        std::fs::write(&log_path, b"").expect("create replacement log");
        std::fs::set_permissions(&log_path, std::fs::Permissions::from_mode(0o640))
            .expect("set replacement mode");

        logger.log(entry("two")).await.expect("write late");
        logger.reopen().expect("reopen audit log");
        logger
            .log(entry("three"))
            .await
            .expect("write after reopen");

        let rotated_log = std::fs::read_to_string(rotated_path).expect("read rotated log");
        let new_log = std::fs::read_to_string(log_path).expect("read new log");
        let rotated_lines = rotated_log.lines().collect::<Vec<_>>();
        let late: serde_json::Value =
            serde_json::from_str(rotated_lines[1]).expect("late entry json");
        let after: serde_json::Value =
            serde_json::from_str(new_log.lines().next().expect("new entry")).expect("new json");

        assert_eq!(after["prev_hash"], late["entry_hash"]);
    }

    #[tokio::test]
    async fn test_open_recovers_hash_from_existing_log() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log_path = dir.path().join("audit.log");
        let logger =
            AuditLogger::open(&log_path, OwnerPolicy::RootOrCurrent).expect("open audit log");

        logger.log(entry("one")).await.expect("write first");
        drop(logger);

        let logger =
            AuditLogger::open(&log_path, OwnerPolicy::RootOrCurrent).expect("reopen audit log");
        logger.log(entry("two")).await.expect("write second");

        let log = std::fs::read_to_string(log_path).expect("read log");
        let lines = log.lines().collect::<Vec<_>>();
        let first: serde_json::Value = serde_json::from_str(lines[0]).expect("first json");
        let second: serde_json::Value = serde_json::from_str(lines[1]).expect("second json");
        assert_eq!(second["prev_hash"], first["entry_hash"]);
    }

    #[tokio::test]
    async fn test_open_recovers_hash_from_bounded_tail() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log_path = dir.path().join("audit.log");
        let (line, hash) = signed_entry_line("tail", ZERO_HASH);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&log_path)
            .expect("create log");
        file.seek(std::io::SeekFrom::Start(AUDIT_RECOVERY_WINDOW_BYTES + 10))
            .expect("seek log");
        file.write_all(b"\n").expect("write separator");
        file.write_all(line.as_bytes()).expect("write entry");
        file.write_all(b"\n").expect("write newline");
        drop(file);
        std::fs::set_permissions(&log_path, std::fs::Permissions::from_mode(0o640))
            .expect("set log mode");

        let logger =
            AuditLogger::open(&log_path, OwnerPolicy::RootOrCurrent).expect("open audit log");
        logger.log(entry("after")).await.expect("write after");

        let log = std::fs::read_to_string(log_path).expect("read log");
        let after_line = log
            .lines()
            .find(|line| line.contains(r#""request_id":"after""#))
            .expect("after line");
        let after: serde_json::Value = serde_json::from_str(after_line).expect("after json");
        assert_eq!(after["prev_hash"], hash);
    }

    #[test]
    fn test_open_rejects_malformed_final_entry() {
        let err = open_log_error("not json");
        assert!(err.contains("malformed final entry"));
    }

    #[test]
    fn test_open_rejects_missing_final_entry_hash() {
        let mut entry = entry("missing-hash");
        entry.prev_hash = ZERO_HASH.to_string();
        let err = open_log_error(&serde_json::to_string(&entry).expect("serialize entry"));
        assert!(err.contains("malformed final entry"));
    }

    #[test]
    fn test_open_rejects_invalid_final_entry_hash() {
        let mut entry = entry("bad-hash");
        entry.prev_hash = ZERO_HASH.to_string();
        entry.entry_hash = "A".repeat(64);
        let err = open_log_error(&serde_json::to_string(&entry).expect("serialize entry"));
        assert!(err.contains("invalid final entry_hash"));
    }

    #[test]
    fn test_open_rejects_invalid_final_prev_hash() {
        let mut entry = entry("bad-prev");
        entry.prev_hash = "A".repeat(64);
        entry.entry_hash = hex_sha256(&entry.hash_payload_v1());
        let err = open_log_error(&serde_json::to_string(&entry).expect("serialize entry"));
        assert!(err.contains("invalid final prev_hash"));
    }

    #[test]
    fn test_open_rejects_unknown_final_entry_field() {
        let (line, _) = signed_entry_line("unknown-field", ZERO_HASH);
        let mut value: serde_json::Value = serde_json::from_str(&line).expect("entry json");
        value["extra"] = serde_json::Value::Bool(true);

        let err = open_log_error(&serde_json::to_string(&value).expect("json"));
        assert!(err.contains("malformed final entry"));
    }

    #[test]
    fn test_open_rejects_final_entry_hash_mismatch() {
        let (line, _) = signed_entry_line("mismatch", ZERO_HASH);
        let mut value: serde_json::Value = serde_json::from_str(&line).expect("entry json");
        value["entry_hash"] = serde_json::Value::String("1".repeat(64));

        let err = open_log_error(&serde_json::to_string(&value).expect("json"));
        assert!(err.contains("entry_hash does not match"));
    }

    #[test]
    fn test_open_rejects_entry_larger_than_recovery_window() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log_path = dir.path().join("audit.log");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&log_path)
            .expect("create log");
        file.write_all(&vec![b'a'; AUDIT_RECOVERY_WINDOW_BYTES as usize + 1])
            .expect("write oversized line");
        file.write_all(b"\n").expect("write newline");
        drop(file);
        std::fs::set_permissions(&log_path, std::fs::Permissions::from_mode(0o640))
            .expect("set log mode");

        let err = AuditLogger::open(&log_path, OwnerPolicy::RootOrCurrent)
            .err()
            .expect("oversized final entry must fail");
        assert!(err.to_string().contains("no complete entry"));
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
        let mut expected_first = entry("one");
        expected_first.prev_hash = ZERO_HASH.to_string();

        assert_eq!(first["prev_hash"], ZERO_HASH);
        assert_eq!(first_hash, hex_sha256(&expected_first.hash_payload_v1()));
        assert_eq!(second["prev_hash"], first_hash);
        assert!(is_lower_hex_hash(first_hash));
        assert!(is_lower_hex_hash(
            second["entry_hash"].as_str().expect("second hash")
        ));
    }
}
