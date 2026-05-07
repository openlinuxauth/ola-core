// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use std::env;
use std::path::PathBuf;

const DEFAULT_SOCKET_PATH: &str = "/run/ola/ola.sock";
const DEFAULT_ALLOWLIST_PATH: &str = "/etc/ola/allowlist";
const DEFAULT_DRAIN_SECS: u64 = 3;
const DEFAULT_CLIENT_IDLE_TIMEOUT_SECS: u64 = 20;
const DEFAULT_ADAPTERS_DIR: &str = "/etc/ola/adapters.d";
const DEFAULT_POLICY_PATH: &str = "/etc/ola/policy.toml";
const DEFAULT_AUDIT_LOG_PATH: &str = "/var/log/ola/audit.log";
const DEFAULT_ADAPTER_KEYS_DIR: &str = "/etc/ola/adapter-keys";
const DEFAULT_MAX_RESULT_AGE_SECS: u64 = 30;
const MAX_RESULT_AGE_SECS_UPPER_BOUND: u64 = u64::MAX / 1000;

#[derive(Clone, Debug)]
pub struct Config {
    pub socket_path: PathBuf,
    pub run_mode: String,

    // OLA_DRAIN_SECS preferred; OLA_SHUTDOWN_TIMEOUT honoured for back-compat.
    pub drain_secs: u64,
    pub client_idle_timeout_secs: u64,

    pub allowlist_path: PathBuf,
    pub adapters_dir: PathBuf,
    pub policy_path: PathBuf,
    pub audit_log_path: PathBuf,
    pub adapter_keys_dir: PathBuf,
    pub max_result_age_secs: u64,

    // Cannot be disabled in prod — startup hard-bails. Dev mode can set
    // OLA_REQUIRE_ATTESTATION=false to run mock adapters without keys.
    pub require_attestation: bool,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let run_mode = env::var("OLA_RUNMODE").unwrap_or_else(|_| "prod".to_string());

        if !["prod", "dev"].contains(&run_mode.as_str()) {
            anyhow::bail!("Invalid OLA_RUNMODE: must be 'prod' or 'dev'");
        }

        let socket_path = env::var("OLA_SOCKET_PATH")
            .unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_string())
            .into();

        let drain_secs = parse_env_u64_with_fallback(
            "OLA_DRAIN_SECS",
            "OLA_SHUTDOWN_TIMEOUT",
            DEFAULT_DRAIN_SECS,
        )?;

        let client_idle_timeout_secs = parse_env_nonzero_u64(
            "OLA_CLIENT_IDLE_TIMEOUT_SECS",
            DEFAULT_CLIENT_IDLE_TIMEOUT_SECS,
        )?;

        let allowlist_path = env::var("OLA_ALLOWLIST_PATH")
            .unwrap_or_else(|_| DEFAULT_ALLOWLIST_PATH.to_string())
            .into();

        let adapters_dir = env::var("OLA_ADAPTERS_DIR")
            .unwrap_or_else(|_| DEFAULT_ADAPTERS_DIR.to_string())
            .into();

        let policy_path = env::var("OLA_POLICY_PATH")
            .unwrap_or_else(|_| DEFAULT_POLICY_PATH.to_string())
            .into();

        let audit_log_path = env::var("OLA_AUDIT_LOG_PATH")
            .unwrap_or_else(|_| DEFAULT_AUDIT_LOG_PATH.to_string())
            .into();

        let adapter_keys_dir = env::var("OLA_ADAPTER_KEYS_DIR")
            .unwrap_or_else(|_| DEFAULT_ADAPTER_KEYS_DIR.to_string())
            .into();

        let max_result_age_secs =
            parse_env_u64("OLA_MAX_RESULT_AGE_SECS", DEFAULT_MAX_RESULT_AGE_SECS)?;
        if max_result_age_secs > MAX_RESULT_AGE_SECS_UPPER_BOUND {
            anyhow::bail!(
                "OLA_MAX_RESULT_AGE_SECS must be <= {}",
                MAX_RESULT_AGE_SECS_UPPER_BOUND
            );
        }

        let require_attestation = env::var("OLA_REQUIRE_ATTESTATION")
            .map(|v| v.to_lowercase() != "false" && v != "0")
            .unwrap_or(true);

        Ok(Self {
            socket_path,
            run_mode,
            drain_secs,
            client_idle_timeout_secs,
            allowlist_path,
            adapters_dir,
            policy_path,
            audit_log_path,
            adapter_keys_dir,
            max_result_age_secs,
            require_attestation,
        })
    }

    pub fn is_prod_mode(&self) -> bool {
        self.run_mode == "prod"
    }
}

fn parse_env_u64(name: &str, default: u64) -> anyhow::Result<u64> {
    match env::var(name) {
        Ok(value) => value
            .parse::<u64>()
            .with_context(|| format!("{name} must be an unsigned integer")),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(env::VarError::NotUnicode(_)) => anyhow::bail!("{name} must be valid UTF-8"),
    }
}

fn parse_env_nonzero_u64(name: &str, default: u64) -> anyhow::Result<u64> {
    let value = parse_env_u64(name, default)?;
    if value == 0 {
        anyhow::bail!("{name} must be greater than zero");
    }
    Ok(value)
}

fn parse_env_u64_with_fallback(primary: &str, fallback: &str, default: u64) -> anyhow::Result<u64> {
    match env::var(primary) {
        Ok(value) => value
            .parse::<u64>()
            .with_context(|| format!("{primary} must be an unsigned integer")),
        Err(env::VarError::NotPresent) => parse_env_u64(fallback, default),
        Err(env::VarError::NotUnicode(_)) => anyhow::bail!("{primary} must be valid UTF-8"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::{Mutex, MutexGuard};

    static ENV_LOCK: Mutex<()> = Mutex::new(());
    const OLA_ENV_KEYS: &[&str] = &[
        "OLA_RUNMODE",
        "OLA_SOCKET_PATH",
        "OLA_DRAIN_SECS",
        "OLA_SHUTDOWN_TIMEOUT",
        "OLA_CLIENT_IDLE_TIMEOUT_SECS",
        "OLA_ALLOWLIST_PATH",
        "OLA_ADAPTERS_DIR",
        "OLA_POLICY_PATH",
        "OLA_AUDIT_LOG_PATH",
        "OLA_ADAPTER_KEYS_DIR",
        "OLA_MAX_RESULT_AGE_SECS",
        "OLA_REQUIRE_ATTESTATION",
    ];

    // Scoped env-var setter. Restores the original value on drop, so tests
    // do not leak state into each other.
    struct EnvGuard {
        key: String,
        old_value: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &str, value: &str) -> Self {
            let old_value = env::var(key).ok();
            env::set_var(key, value);
            Self {
                key: key.to_string(),
                old_value,
            }
        }

        fn remove(key: &str) -> Self {
            let old_value = env::var(key).ok();
            env::remove_var(key);
            Self {
                key: key.to_string(),
                old_value,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.old_value {
                Some(v) => env::set_var(&self.key, v),
                None => env::remove_var(&self.key),
            }
        }
    }

    fn env_lock() -> MutexGuard<'static, ()> {
        ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn clean_ola_env() -> Vec<EnvGuard> {
        OLA_ENV_KEYS
            .iter()
            .map(|key| EnvGuard::remove(key))
            .collect()
    }

    #[test]
    fn test_config_defaults() {
        let _lock = env_lock();
        let _env = clean_ola_env();

        let config = Config::from_env().unwrap();
        assert_eq!(config.socket_path.to_str().unwrap(), DEFAULT_SOCKET_PATH);
        assert_eq!(config.run_mode, "prod");
        assert_eq!(config.drain_secs, DEFAULT_DRAIN_SECS);
        assert_eq!(
            config.client_idle_timeout_secs,
            DEFAULT_CLIENT_IDLE_TIMEOUT_SECS
        );
        assert_eq!(
            config.allowlist_path.to_str().unwrap(),
            DEFAULT_ALLOWLIST_PATH
        );
    }

    #[test]
    fn test_config_custom_values() {
        let _lock = env_lock();
        let _env = clean_ola_env();
        let _g1 = EnvGuard::set("OLA_RUNMODE", "dev");
        let _g2 = EnvGuard::set("OLA_SOCKET_PATH", "/tmp/test.sock");
        let _g3 = EnvGuard::set("OLA_DRAIN_SECS", "10");
        let _g4 = EnvGuard::set("OLA_ALLOWLIST_PATH", "/tmp/allowlist");
        let _g5 = EnvGuard::set("OLA_CLIENT_IDLE_TIMEOUT_SECS", "9");

        let config = Config::from_env().unwrap();
        assert_eq!(config.socket_path.to_str().unwrap(), "/tmp/test.sock");
        assert_eq!(config.run_mode, "dev");
        assert_eq!(config.drain_secs, 10);
        assert_eq!(config.client_idle_timeout_secs, 9);
        assert_eq!(config.allowlist_path.to_str().unwrap(), "/tmp/allowlist");
    }

    #[test]
    fn test_config_invalid_runmode() {
        let _lock = env_lock();
        let _env = clean_ola_env();
        let _g = EnvGuard::set("OLA_RUNMODE", "invalid");
        let result = Config::from_env();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid OLA_RUNMODE"));
    }

    #[test]
    fn test_config_backward_compat_shutdown_timeout() {
        let _lock = env_lock();
        let _env = clean_ola_env();
        let _g1 = EnvGuard::set("OLA_RUNMODE", "prod");
        let _g2 = EnvGuard::set("OLA_SHUTDOWN_TIMEOUT", "7");

        let config = Config::from_env().unwrap();
        assert_eq!(config.drain_secs, 7);
    }

    #[test]
    fn test_config_drain_secs_priority() {
        let _lock = env_lock();
        let _env = clean_ola_env();
        let _g1 = EnvGuard::set("OLA_RUNMODE", "prod");
        let _g2 = EnvGuard::set("OLA_DRAIN_SECS", "5");
        let _g3 = EnvGuard::set("OLA_SHUTDOWN_TIMEOUT", "10");

        let config = Config::from_env().unwrap();
        assert_eq!(config.drain_secs, 5);
    }

    #[test]
    fn test_config_invalid_drain_secs() {
        let _lock = env_lock();
        let _env = clean_ola_env();
        let _g1 = EnvGuard::set("OLA_RUNMODE", "prod");
        let _g2 = EnvGuard::set("OLA_DRAIN_SECS", "not_a_number");

        let err = Config::from_env().expect_err("invalid drain must fail");
        assert!(err.to_string().contains("OLA_DRAIN_SECS"));
    }

    #[test]
    fn test_config_invalid_client_idle_timeout_secs() {
        let _lock = env_lock();
        let _env = clean_ola_env();
        let _g1 = EnvGuard::set("OLA_RUNMODE", "prod");
        let _g2 = EnvGuard::set("OLA_CLIENT_IDLE_TIMEOUT_SECS", "0");

        let err = Config::from_env().expect_err("zero idle timeout must fail");
        assert!(err.to_string().contains("OLA_CLIENT_IDLE_TIMEOUT_SECS"));
    }

    #[test]
    fn test_config_invalid_max_result_age_secs() {
        let _lock = env_lock();
        let _env = clean_ola_env();
        let _g1 = EnvGuard::set("OLA_RUNMODE", "prod");
        let _g2 = EnvGuard::set("OLA_MAX_RESULT_AGE_SECS", "not_a_number");

        let err = Config::from_env().expect_err("invalid max age must fail");
        assert!(err.to_string().contains("OLA_MAX_RESULT_AGE_SECS"));
    }

    #[test]
    fn test_config_helpers() {
        let _lock = env_lock();
        let _env = clean_ola_env();
        let _g = EnvGuard::set("OLA_RUNMODE", "dev");
        let config = Config::from_env().unwrap();

        assert_eq!(config.run_mode, "dev");
        assert!(!config.is_prod_mode());
    }
}
