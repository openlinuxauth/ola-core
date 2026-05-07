// SPDX-License-Identifier: Apache-2.0

use crate::core::policy::types::PolicyConfig;
use crate::security::fs::{
    read_secure_to_string, ModePolicy, OwnerPolicy, SecureFileSpec, SizePolicy,
};
use anyhow::Context;
use std::collections::HashSet;
use std::path::Path;

const MAX_POLICY_BYTES: i64 = 1024 * 1024;

pub struct PolicyParser;

impl PolicyParser {
    #[cfg(test)]
    pub fn load(path: &Path) -> anyhow::Result<PolicyConfig> {
        Self::load_with_owner(path, OwnerPolicy::RootOrCurrent)
    }

    pub fn load_with_owner(path: &Path, owner: OwnerPolicy) -> anyhow::Result<PolicyConfig> {
        let contents = read_policy_file(path, owner)?;

        let mut config: PolicyConfig =
            toml::from_str(&contents).with_context(|| "Failed to parse policy TOML")?;

        let mut seen_methods = HashSet::new();
        let mut seen_wildcard = false;
        for rule in &config.rules {
            if !(0.0..=1.0).contains(&rule.min_confidence) {
                anyhow::bail!("Invalid min_confidence: must be between 0.0 and 1.0");
            }

            match &rule.method {
                Some(method) if !seen_methods.insert(method.clone()) => {
                    anyhow::bail!("duplicate policy rule for method {}", method);
                }
                Some(_) => {}
                None if seen_wildcard => {
                    anyhow::bail!("duplicate wildcard policy rule");
                }
                None => seen_wildcard = true,
            }
        }

        config.rules.sort_by_key(|rule| rule.method.is_none());

        Ok(config)
    }
}

fn read_policy_file(path: &Path, owner: OwnerPolicy) -> anyhow::Result<String> {
    read_secure_to_string(
        path,
        SecureFileSpec {
            label: "policy file",
            size: SizePolicy::Max(MAX_POLICY_BYTES),
            mode: ModePolicy::Exact(&[0o600, 0o640]),
            owner,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn write_policy(contents: &str) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().expect("create policy file");
        std::fs::write(file.path(), contents).expect("write policy file");
        file
    }

    #[test]
    fn sorts_specific_rules_before_wildcard() {
        let file = write_policy(
            r#"
[[rules]]
min_confidence = 0.5
max_age_secs = 30
require_uid_match = true

[[rules]]
method = "fido2"
min_confidence = 1.0
max_age_secs = 30
require_uid_match = true
"#,
        );

        let config = PolicyParser::load(file.path()).expect("load policy");
        assert!(config.rules[0].method.is_some());
        assert!(config.rules[1].method.is_none());
    }

    #[test]
    fn rejects_duplicate_method_rules() {
        let file = write_policy(
            r#"
[[rules]]
method = "fido2"
min_confidence = 1.0
max_age_secs = 30
require_uid_match = true

[[rules]]
method = "fido2"
min_confidence = 0.5
max_age_secs = 30
require_uid_match = true
"#,
        );

        assert!(PolicyParser::load(file.path()).is_err());
    }

    #[test]
    fn rejects_duplicate_wildcard_rules() {
        let file = write_policy(
            r#"
[[rules]]
min_confidence = 1.0
max_age_secs = 30
require_uid_match = true

[[rules]]
min_confidence = 0.9
max_age_secs = 30
require_uid_match = true
"#,
        );

        let err = PolicyParser::load(file.path()).expect_err("duplicate wildcard must fail");
        assert!(err.to_string().contains("duplicate wildcard"));
    }

    #[test]
    fn rejects_min_confidence_outside_unit_range() {
        let file = write_policy(
            r#"
[[rules]]
method = "fido2"
min_confidence = 1.2
max_age_secs = 30
require_uid_match = true
"#,
        );

        let err = PolicyParser::load(file.path()).expect_err("invalid confidence must fail");
        assert!(err.to_string().contains("min_confidence"));
    }

    #[test]
    fn rejects_invalid_method_name() {
        let file = write_policy(
            r#"
[[rules]]
method = "two words"
min_confidence = 1.0
max_age_secs = 30
require_uid_match = true
"#,
        );

        let err = PolicyParser::load(file.path()).expect_err("invalid method must fail");
        assert!(format!("{err:#}").contains("method"));
    }

    #[test]
    fn rejects_world_readable_policy_file() {
        let file = write_policy(
            r#"
[[rules]]
min_confidence = 0.9
max_age_secs = 30
require_uid_match = true
"#,
        );
        let mut perms = file.as_file().metadata().unwrap().permissions();
        perms.set_mode(0o644);
        file.as_file().set_permissions(perms).unwrap();

        let err = PolicyParser::load(file.path()).unwrap_err();
        assert!(err.to_string().contains("mode 0600 or 0640"));
    }

    #[test]
    fn rejects_symlink_policy_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let target = dir.path().join("target.toml");
        let link = dir.path().join("link.toml");
        std::fs::write(
            &target,
            "[[rules]]\nmin_confidence = 0.9\nmax_age_secs = 30\nrequire_uid_match = true\n",
        )
        .expect("write policy");
        let mut perms = std::fs::metadata(&target).unwrap().permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&target, perms).unwrap();
        symlink(&target, &link).expect("create symlink");

        let err = PolicyParser::load(&link).unwrap_err();
        assert!(err.to_string().contains("safely open policy file"));
    }
}
