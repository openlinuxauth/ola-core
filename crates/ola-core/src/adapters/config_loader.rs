// SPDX-License-Identifier: Apache-2.0

use crate::adapters::registry::AdapterConfig;
use crate::core::types::method::{validate_adapter_name, validate_method_name};
use crate::security::fs::{
    read_secure_to_string, ModePolicy, OwnerPolicy, SecureFileSpec, SizePolicy,
};
use anyhow::Context;
use log::warn;
use std::path::Path;

const MAX_ADAPTER_CONFIG_BYTES: i64 = 64 * 1024;

/// Load adapter configs from a directory.
///
/// Adapter configs route real auth requests with real nonces. A malicious or
/// misconfigured config can redirect those to a socket the attacker controls.
/// Adapter configs are not secret, so their mode policy is less restrictive
/// than key files.
///
/// `strict = true` (prod): one bad file aborts startup. The daemon does not
/// run in an unknown partial configuration.
/// `strict = false` (dev): bad files are skipped with a warning, so a
/// half-configured dev tree is workable.
pub fn load_adapter_configs(
    dir: &Path,
    strict: bool,
    owner: OwnerPolicy,
) -> anyhow::Result<Vec<AdapterConfig>> {
    let mut configs = Vec::new();

    if !dir.exists() || !dir.is_dir() {
        if strict {
            anyhow::bail!(
                "adapter config directory {} does not exist or is not a directory",
                dir.display()
            );
        }
        warn!(
            "Adapter config directory {:?} does not exist or is not a directory.",
            dir
        );
        return Ok(configs);
    }

    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                handle_violation(
                    strict,
                    dir,
                    &format!("failed reading directory entry: {}", e),
                )?;
                continue;
            }
        };
        let path = entry.path();
        if path.extension().is_none_or(|ext| ext != "toml") {
            continue;
        }

        let contents = match read_secure_to_string(
            &path,
            SecureFileSpec {
                label: "adapter config",
                size: SizePolicy::Max(MAX_ADAPTER_CONFIG_BYTES),
                mode: ModePolicy::NotGroupWorldWritable,
                owner,
            },
        ) {
            Ok(contents) => contents,
            Err(e) => {
                handle_violation(strict, &path, &e.to_string())?;
                continue;
            }
        };

        let cfg = match toml::from_str::<AdapterConfig>(&contents) {
            Ok(cfg) => cfg,
            Err(e) => {
                handle_violation(strict, &path, &format!("parse failed: {}", e))?;
                continue;
            }
        };

        if let Err(e) = validate_adapter_config(&cfg) {
            handle_violation(strict, &path, &format!("validation failed: {}", e))?;
            continue;
        }

        configs.push(cfg);
    }

    if strict && configs.is_empty() {
        anyhow::bail!(
            "adapter config directory {} contains no adapter configs",
            dir.display()
        );
    }

    Ok(configs)
}

fn handle_violation(strict: bool, path: &Path, reason: &str) -> anyhow::Result<()> {
    // Prod: a bad config file is a hard stop. Refuse to start rather than
    // run with an unknown partial configuration. The operator fixes it
    // explicitly. Silent degradation is wrong for security infrastructure.
    if strict {
        anyhow::bail!("adapter config {} {}", path.display(), reason);
    }
    warn!("Skipping adapter config {}: {}", path.display(), reason);
    Ok(())
}

fn validate_adapter_config(cfg: &AdapterConfig) -> anyhow::Result<()> {
    validate_adapter_name(&cfg.name).map_err(|message| anyhow::anyhow!(message))?;
    if cfg.socket_path.as_os_str().is_empty() {
        anyhow::bail!("socket_path must not be empty");
    }
    if cfg.methods.is_empty() {
        anyhow::bail!("methods must not be empty");
    }
    let mut seen_methods = std::collections::HashSet::new();
    for method in &cfg.methods {
        validate_method_name(method, false).map_err(|message| anyhow::anyhow!(message))?;
        if !seen_methods.insert(method) {
            anyhow::bail!("duplicate method {}", method);
        }
    }
    if !(100..=30_000).contains(&cfg.timeout_ms) {
        anyhow::bail!("timeout_ms must be between 100 and 30000");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn write_config(path: &Path, methods: &str, timeout_ms: u64) {
        let toml = format!(
            r#"
name = "adapter_a"
socket_path = "/tmp/adapter_a.sock"
expected_uid = 1000
methods = {methods}
timeout_ms = {timeout_ms}
"#
        );
        std::fs::write(path, toml).expect("write config");
    }

    #[test]
    fn test_rejects_symlink_config() {
        let temp = tempfile::tempdir().expect("tempdir");
        let real = temp.path().join("real.conf");
        let link = temp.path().join("link.toml");
        write_config(&real, r#"["fido2"]"#, 1000);
        symlink(&real, &link).expect("create symlink");

        let err = load_adapter_configs(temp.path(), true, OwnerPolicy::RootOrCurrent)
            .expect_err("strict mode must fail");
        assert!(err.to_string().contains("safely open adapter config"));
    }

    #[test]
    fn test_rejects_world_writable_config() {
        let temp = tempfile::tempdir().expect("tempdir");
        let cfg_path = temp.path().join("bad.toml");
        write_config(&cfg_path, r#"["fido2"]"#, 1000);
        std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o666))
            .expect("set mode");

        let err = load_adapter_configs(temp.path(), true, OwnerPolicy::RootOrCurrent)
            .expect_err("strict mode must fail");
        assert!(err.to_string().contains("group/world writable"));
    }

    #[test]
    fn test_rejects_empty_methods() {
        let cfg: AdapterConfig = toml::from_str(
            r#"
name = "adapter_a"
socket_path = "/tmp/adapter_a.sock"
expected_uid = 1000
methods = []
timeout_ms = 1000
"#,
        )
        .expect("parse config");

        let err = validate_adapter_config(&cfg).expect_err("empty methods must fail");
        assert!(err.to_string().contains("methods must not be empty"));
    }

    #[test]
    fn test_rejects_invalid_adapter_name() {
        let cfg: AdapterConfig = toml::from_str(
            r#"
name = "bad name"
socket_path = "/tmp/adapter_a.sock"
expected_uid = 1000
methods = ["fido2"]
timeout_ms = 1000
"#,
        )
        .expect("parse config");

        let err = validate_adapter_config(&cfg).expect_err("invalid name must fail");
        assert!(err.to_string().contains("adapter name"));
    }

    #[test]
    fn test_rejects_large_config_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let cfg_path = temp.path().join("large.toml");
        std::fs::write(&cfg_path, "x".repeat(MAX_ADAPTER_CONFIG_BYTES as usize + 1))
            .expect("write large config");
        std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o644))
            .expect("set mode");

        let err = load_adapter_configs(temp.path(), true, OwnerPolicy::RootOrCurrent)
            .expect_err("large config must fail");
        assert!(err.to_string().contains("too large"));
    }

    #[test]
    fn test_rejects_empty_method_entry() {
        let cfg: AdapterConfig = toml::from_str(
            r#"
name = "adapter_a"
socket_path = "/tmp/adapter_a.sock"
expected_uid = 1000
methods = [" "]
timeout_ms = 1000
"#,
        )
        .expect("parse config");

        let err = validate_adapter_config(&cfg).expect_err("empty method must fail");
        assert!(err.to_string().contains("leading or trailing whitespace"));
    }

    #[test]
    fn test_rejects_reserved_any_method() {
        let cfg: AdapterConfig = toml::from_str(
            r#"
name = "adapter_a"
socket_path = "/tmp/adapter_a.sock"
expected_uid = 1000
methods = ["any"]
timeout_ms = 1000
"#,
        )
        .expect("parse config");

        let err = validate_adapter_config(&cfg).expect_err("reserved method must fail");
        assert!(err.to_string().contains("reserved"));
    }

    #[test]
    fn test_rejects_timeout_too_low() {
        let cfg: AdapterConfig = toml::from_str(
            r#"
name = "adapter_a"
socket_path = "/tmp/adapter_a.sock"
expected_uid = 1000
methods = ["fido2"]
timeout_ms = 50
"#,
        )
        .expect("parse config");

        let err = validate_adapter_config(&cfg).expect_err("low timeout must fail");
        assert!(err
            .to_string()
            .contains("timeout_ms must be between 100 and 30000"));
    }

    #[test]
    fn test_dev_mode_skips_bad_file_and_loads_good() {
        let temp = tempfile::tempdir().expect("tempdir");
        let bad = temp.path().join("bad.toml");
        let good = temp.path().join("good.toml");
        write_config(&bad, r#"["fido2"]"#, 1000);
        write_config(&good, r#"["pin"]"#, 1000);
        std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o666)).expect("set mode");

        let loaded = load_adapter_configs(temp.path(), false, OwnerPolicy::RootOrCurrent)
            .expect("dev mode continues");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].methods, vec!["pin"]);
    }

    #[test]
    fn test_prod_mode_requires_config_directory_and_files() {
        let temp = tempfile::tempdir().expect("tempdir");
        let missing = temp.path().join("missing");
        let err = load_adapter_configs(&missing, true, OwnerPolicy::RootOrCurrent)
            .expect_err("strict mode requires directory");
        assert!(err.to_string().contains("does not exist"));

        let empty = temp.path().join("empty");
        std::fs::create_dir(&empty).expect("create empty dir");
        let err = load_adapter_configs(&empty, true, OwnerPolicy::RootOrCurrent)
            .expect_err("strict mode requires at least one config");
        assert!(err.to_string().contains("contains no adapter configs"));
    }

    #[test]
    fn test_prod_mode_fails_on_any_bad_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let bad = temp.path().join("bad.toml");
        let good = temp.path().join("good.toml");
        write_config(&bad, r#"["fido2"]"#, 1000);
        write_config(&good, r#"["pin"]"#, 1000);
        std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o666)).expect("set mode");

        let err = load_adapter_configs(temp.path(), true, OwnerPolicy::RootOrCurrent)
            .expect_err("strict mode must fail");
        assert!(err.to_string().contains("group/world writable"));
    }
}
