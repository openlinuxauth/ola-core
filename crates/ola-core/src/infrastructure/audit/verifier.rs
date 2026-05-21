// SPDX-License-Identifier: Apache-2.0

use crate::infrastructure::audit::entry::AuditEntry;
use crate::infrastructure::audit::hex::{hex_sha256, is_lower_hex_hash};
use crate::infrastructure::audit::ZERO_HASH;
use anyhow::Context;
use nix::sys::stat::fstat;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

#[derive(Debug)]
pub(crate) struct AuditVerifyReport {
    pub entries: u64,
    pub last_hash: String,
}

pub(crate) fn verify_audit_log(path: &Path) -> anyhow::Result<AuditVerifyReport> {
    let file = open_audit_log(path)?;
    verify_reader(BufReader::new(file), path)
}

fn open_audit_log(path: &Path) -> anyhow::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("opening audit log {}", path.display()))?;
    let stat = fstat(file.as_raw_fd())?;
    if (stat.st_mode & libc::S_IFMT) != libc::S_IFREG {
        anyhow::bail!("audit log {} must be a regular file", path.display());
    }
    Ok(file)
}

fn verify_reader(mut reader: impl BufRead, path: &Path) -> anyhow::Result<AuditVerifyReport> {
    let mut prev_hash = ZERO_HASH.to_string();
    let mut entries = 0u64;
    let mut line_no = 0u64;
    let mut buf = Vec::new();

    loop {
        buf.clear();
        let read = reader
            .read_until(b'\n', &mut buf)
            .with_context(|| format!("reading audit log {}", path.display()))?;
        if read == 0 {
            break;
        }

        line_no += 1;
        if buf.last() != Some(&b'\n') {
            anyhow::bail!(
                "audit log {} line {} is incomplete",
                path.display(),
                line_no
            );
        }
        buf.pop();

        let line = std::str::from_utf8(&buf).with_context(|| {
            format!("audit log {} line {} is not utf-8", path.display(), line_no)
        })?;
        let mut entry: AuditEntry = serde_json::from_str(line).with_context(|| {
            format!(
                "audit log {} line {} has malformed entry",
                path.display(),
                line_no
            )
        })?;

        if !is_lower_hex_hash(&entry.prev_hash) {
            anyhow::bail!(
                "audit log {} line {} has invalid prev_hash",
                path.display(),
                line_no
            );
        }
        if !is_lower_hex_hash(&entry.entry_hash) {
            anyhow::bail!(
                "audit log {} line {} has invalid entry_hash",
                path.display(),
                line_no
            );
        }
        if entry.prev_hash != prev_hash {
            anyhow::bail!(
                "audit log {} line {} prev_hash does not match previous entry",
                path.display(),
                line_no
            );
        }

        let entry_hash = std::mem::take(&mut entry.entry_hash);
        let expected = hex_sha256(&entry.hash_payload_v1());
        if entry_hash != expected {
            anyhow::bail!(
                "audit log {} line {} entry_hash does not match entry",
                path.display(),
                line_no
            );
        }

        prev_hash = entry_hash;
        entries += 1;
    }

    Ok(AuditVerifyReport {
        entries,
        last_hash: prev_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::os::unix::fs::symlink;

    fn entry(id: &str, prev_hash: &str) -> AuditEntry {
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
            prev_hash: prev_hash.to_string(),
            entry_hash: String::new(),
        }
    }

    fn signed_line(id: &str, prev_hash: &str) -> (String, String) {
        let mut entry = entry(id, prev_hash);
        entry.entry_hash = hex_sha256(&entry.hash_payload_v1());
        let hash = entry.entry_hash.clone();
        (
            serde_json::to_string(&entry).expect("serialize entry"),
            hash,
        )
    }

    fn verify_text(text: &str) -> anyhow::Result<AuditVerifyReport> {
        verify_reader(Cursor::new(text.as_bytes()), Path::new("audit.log"))
    }

    #[test]
    fn rejects_symlink_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("real.log");
        let link = dir.path().join("audit.log");
        std::fs::write(&target, b"").expect("write target");
        symlink(&target, &link).expect("symlink");

        assert!(verify_audit_log(&link).is_err());
    }

    #[test]
    fn verifies_empty_log() {
        let report = verify_text("").expect("verify empty log");

        assert_eq!(report.entries, 0);
        assert_eq!(report.last_hash, ZERO_HASH);
    }

    #[test]
    fn verifies_valid_chain() {
        let (line1, hash1) = signed_line("req-1", ZERO_HASH);
        let (line2, hash2) = signed_line("req-2", &hash1);
        let report = verify_text(&format!("{line1}\n{line2}\n")).expect("verify chain");

        assert_eq!(report.entries, 2);
        assert_eq!(report.last_hash, hash2);
    }

    #[test]
    fn rejects_broken_prev_hash() {
        let (line1, _) = signed_line("req-1", ZERO_HASH);
        let (line2, _) = signed_line("req-2", ZERO_HASH);
        let err = verify_text(&format!("{line1}\n{line2}\n"))
            .expect_err("broken chain must fail")
            .to_string();

        assert!(err.contains("line 2 prev_hash does not match previous entry"));
    }

    #[test]
    fn rejects_entry_hash_mismatch() {
        let (line, _) = signed_line("req-1", ZERO_HASH);
        let line = line.replace("\"decision\":\"allow\"", "\"decision\":\"deny\"");
        let err = verify_text(&format!("{line}\n"))
            .expect_err("hash mismatch must fail")
            .to_string();

        assert!(err.contains("line 1 entry_hash does not match entry"));
    }

    #[test]
    fn rejects_malformed_line() {
        let err = verify_text("{bad}\n")
            .expect_err("malformed line must fail")
            .to_string();

        assert!(err.contains("line 1 has malformed entry"));
    }

    #[test]
    fn rejects_incomplete_final_entry() {
        let (line, _) = signed_line("req-1", ZERO_HASH);
        let err = verify_text(&line)
            .expect_err("incomplete final entry must fail")
            .to_string();

        assert!(err.contains("line 1 is incomplete"));
    }
}
