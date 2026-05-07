// SPDX-License-Identifier: Apache-2.0

use crate::security::fs::{
    read_secure_to_string, ModePolicy, OwnerPolicy, SecureFileSpec, SizePolicy,
};
use log::warn;
use std::collections::HashSet;
use std::path::Path;

const MAX_ALLOWLIST_BYTES: i64 = 1024 * 1024;

pub struct Allowlist {
    allowed_uids: HashSet<u32>,
}

impl Allowlist {
    pub fn new() -> Self {
        Self {
            allowed_uids: HashSet::new(),
        }
    }

    #[cfg(test)]
    pub fn load_from_file<P: AsRef<Path>>(&mut self, path: P) -> anyhow::Result<()> {
        self.load_from_file_with_options(path, false, OwnerPolicy::RootOrCurrent)
    }

    pub fn load_from_file_with_options<P: AsRef<Path>>(
        &mut self,
        path: P,
        strict: bool,
        owner: OwnerPolicy,
    ) -> anyhow::Result<()> {
        let path_ref = path.as_ref();
        let content = read_secure_to_string(
            path_ref,
            SecureFileSpec {
                label: "Allowlist file",
                size: SizePolicy::Max(MAX_ALLOWLIST_BYTES),
                mode: ModePolicy::Exact(&[0o600, 0o640]),
                owner,
            },
        )?;

        self.allowed_uids.clear();
        for (i, line) in content.lines().enumerate() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            match line.parse::<u32>() {
                Ok(uid) => {
                    self.allowed_uids.insert(uid);
                }
                Err(_) => {
                    if strict {
                        anyhow::bail!("invalid UID on line {} in allowlist", i + 1);
                    }
                    warn!("Skipping invalid UID on line {} in allowlist", i + 1);
                }
            }
        }
        Ok(())
    }

    pub fn is_allowed(&self, uid: u32) -> bool {
        // Root passes. Root owns the daemon's config; blocking root blocks
        // legitimate administration. The daemon controls non-root callers,
        // not the sysadmin.
        if uid == 0 {
            return true;
        }

        // The service user passes — health checks and local integration tests
        // connect under our own UID.
        if uid == nix::unistd::getuid().as_raw() {
            return true;
        }

        self.allowed_uids.contains(&uid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::NamedTempFile;

    // Temp file at 0600 so the hardened loader accepts it.
    fn create_secure_temp_file(content: &str) -> NamedTempFile {
        let file = NamedTempFile::new().expect("create temp file");
        file.as_file()
            .write_all(content.as_bytes())
            .expect("write content");

        let mut perms = file.as_file().metadata().unwrap().permissions();
        perms.set_mode(0o600);
        file.as_file().set_permissions(perms).unwrap();

        file
    }

    // Test UIDs offset from the running user, so they never collide with the
    // self-uid bypass in is_allowed().
    fn test_uids() -> (u32, u32, u32) {
        let self_uid = nix::unistd::getuid().as_raw();
        let base = self_uid.saturating_add(10_000);
        (base, base + 1, base + 2)
    }

    #[test]
    fn test_allowlist_valid_uids() {
        let mut allowlist = Allowlist::new();
        let (u1, u2, u3) = test_uids();
        let content = format!("{}\n{}", u1, u2);
        let t = create_secure_temp_file(&content);
        allowlist.load_from_file(t.path()).expect("load allowlist");

        assert!(allowlist.is_allowed(u1));
        assert!(allowlist.is_allowed(u2));
        assert!(!allowlist.is_allowed(u3));
    }

    #[test]
    fn test_allowlist_insecure_permissions() {
        let file = NamedTempFile::new().expect("create temp file");
        let mut perms = file.as_file().metadata().unwrap().permissions();
        perms.set_mode(0o666); // world-writable — must be rejected
        file.as_file().set_permissions(perms).unwrap();

        let mut allowlist = Allowlist::new();
        let err = allowlist.load_from_file(file.path());
        assert!(err.is_err());
        let msg = err.unwrap_err().to_string();
        assert!(
            msg.contains("must have mode 0600 or 0640"),
            "Unexpected error: {}",
            msg
        );
    }

    #[test]
    fn test_allowlist_comments_and_whitespace() {
        let mut allowlist = Allowlist::new();
        let (u1, u2, u3) = test_uids();
        let content = format!(
            "\
            {} # Alice
            # This is a comment
            {}
              {}
        ",
            u1, u2, u3
        );
        let t = create_secure_temp_file(&content);
        allowlist.load_from_file(t.path()).expect("load allowlist");

        assert!(allowlist.is_allowed(u1));
        assert!(allowlist.is_allowed(u2));
        assert!(allowlist.is_allowed(u3));

        let self_uid = nix::unistd::getuid().as_raw();
        let mut forbidden = u1 + 1000;
        if forbidden == self_uid {
            forbidden += 1;
        }

        assert!(!allowlist.is_allowed(forbidden));
    }

    #[test]
    fn test_allowlist_always_allows_root() {
        let allowlist = Allowlist::new();
        assert!(allowlist.is_allowed(0));
    }

    #[test]
    fn test_allowlist_always_allows_self() {
        let allowlist = Allowlist::new();
        let self_uid = nix::unistd::getuid().as_raw();
        assert!(allowlist.is_allowed(self_uid));
    }

    #[test]
    fn test_load_nonexistent_file() {
        let mut allowlist = Allowlist::new();
        let res = allowlist.load_from_file("/path/that/does/not/exist");
        assert!(res.is_err());
    }

    #[test]
    fn test_allowlist_large_file() {
        // 10,000 UIDs — scale check.
        let mut content = String::new();
        for i in 10000..20000 {
            content.push_str(&format!("{}\n", i));
        }

        let t = create_secure_temp_file(&content);
        let mut allowlist = Allowlist::new();
        allowlist
            .load_from_file(t.path())
            .expect("load large allowlist");

        assert!(allowlist.is_allowed(15000));
        assert!(!allowlist.is_allowed(30000));
    }

    #[test]
    fn test_allowlist_duplicate_uids() {
        let (u1, _, _) = test_uids();
        let content = format!("{}\n{}\n{}\n", u1, u1, u1);
        let t = create_secure_temp_file(&content);
        let mut allowlist = Allowlist::new();
        allowlist.load_from_file(t.path()).expect("load allowlist");

        assert!(allowlist.is_allowed(u1));
    }

    #[test]
    fn test_allowlist_reload_clears_old() {
        let mut allowlist = Allowlist::new();
        let (u1, u2, _) = test_uids();

        let t1 = create_secure_temp_file(&format!("{}\n{}", u1, u2));
        allowlist.load_from_file(t1.path()).expect("first load");
        assert!(allowlist.is_allowed(u1));

        let u_new = u1 + 100;
        let t2 = create_secure_temp_file(&format!("{}", u_new));
        allowlist.load_from_file(t2.path()).expect("second load");

        assert!(!allowlist.is_allowed(u1)); // reload must clear the old set
        assert!(allowlist.is_allowed(u_new));
    }

    #[test]
    fn test_allowlist_malformed_lines() {
        let (u1, u2, u3) = test_uids();
        let content = format!("{}\n99999999999999999999\n{}\nfoobar\n{}", u1, u2, u3);
        let t = create_secure_temp_file(&content);
        let mut allowlist = Allowlist::new();
        allowlist
            .load_from_file(t.path())
            .expect("load with malformed");

        assert!(allowlist.is_allowed(u1));
        assert!(allowlist.is_allowed(u2));
        assert!(allowlist.is_allowed(u3));
    }

    #[test]
    fn test_allowlist_strict_rejects_malformed_lines() {
        let (u1, _, _) = test_uids();
        let content = format!("{}\nnot-a-uid\n", u1);
        let t = create_secure_temp_file(&content);
        let mut allowlist = Allowlist::new();
        let err = allowlist
            .load_from_file_with_options(t.path(), true, OwnerPolicy::RootOrCurrent)
            .expect_err("strict allowlist must reject malformed line");

        assert!(err.to_string().contains("invalid UID on line 2"));
    }

    #[test]
    fn test_allowlist_empty_file() {
        let t = create_secure_temp_file("");
        let mut allowlist = Allowlist::new();
        allowlist.load_from_file(t.path()).expect("load empty");

        // Empty file: only root and the service user pass.
        assert!(allowlist.is_allowed(0));
        assert!(allowlist.is_allowed(nix::unistd::getuid().as_raw()));
    }

    #[test]
    fn test_allowlist_only_comments() {
        let content = "# Only comments\n# Nothing else";
        let t = create_secure_temp_file(content);
        let mut allowlist = Allowlist::new();
        allowlist
            .load_from_file(t.path())
            .expect("load comments-only");

        assert!(allowlist.is_allowed(0));
    }
}
