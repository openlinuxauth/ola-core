// SPDX-License-Identifier: Apache-2.0

use crate::security::seccomp;
use anyhow::{anyhow, Context};
use caps::{clear, CapSet};
use log::info;
use nix::unistd::{setgid, setgroups, setuid, Gid, Uid};
use std::env;
use uzers::get_user_by_name;

const DEFAULT_SERVICE_USER: &str = "ola";

pub fn service_user_name() -> String {
    env::var("OLA_USER").unwrap_or_else(|_| DEFAULT_SERVICE_USER.to_string())
}

/// Drop root irreversibly, then sandbox.
///
/// Step order is correctness, not style. Reordering either silently fails
/// (groups not cleared before UID drop) or crashes (seccomp blocking syscalls
/// later steps need). Read every step before changing anything.
///
/// Started as non-root (systemd User=ola with socket activation): UID, GID,
/// and capability steps are skipped. Seccomp and NO_NEW_PRIVS apply either way.
pub fn drop_privileges_completely() -> anyhow::Result<()> {
    if nix::unistd::geteuid().is_root() {
        let service_user = service_user_name();
        let ola_user = get_user_by_name(&service_user)
            .ok_or_else(|| anyhow!("service user {} not found", service_user))?;

        // Clear supplementary groups first. They persist across setuid, so a
        // process started in the `docker` or `sudo` group keeps that access
        // after becoming `ola`. Must happen before setgid — after GID drop,
        // group mutation can fail.
        setgroups(&[]).context("Failed to clear supplementary groups")?;
        info!("Cleared supplementary groups");

        // GID before UID. After UID drop, GID changes are no longer permitted.
        setgid(Gid::from_raw(ola_user.primary_group_id())).context("Failed to set GID")?;
        info!("Set GID to {}", ola_user.primary_group_id());

        // Point of no return. After this point the process runs as `ola`, no
        // normal path back to root. The steps that follow defend against kernel
        // bugs and namespace misconfigurations that make the drop reversible.
        setuid(Uid::from_raw(ola_user.uid())).context("Failed to set UID")?;
        info!("Set UID to {}", ola_user.uid());

        // Try to setuid back to 0. Must fail. If it succeeds, the drop was
        // silent — a kernel bug or namespace misconfiguration is letting us
        // escalate. Bail loudly rather than run under the illusion of being
        // unprivileged.
        if setuid(Uid::from_raw(0)).is_ok() {
            anyhow::bail!("CRITICAL: Failed to drop root! (Able to setuid back to 0)");
        }

        // Non-root processes can still hold capabilities — CAP_NET_BIND_SERVICE,
        // CAP_DAC_OVERRIDE, the rest. None are retained. Clear all three sets:
        // Permitted (activatable), Effective (active now), Inheritable (survives
        // exec).
        clear(None, CapSet::Permitted).context("Failed to clear Permitted caps")?;
        clear(None, CapSet::Effective).context("Failed to clear Effective caps")?;
        clear(None, CapSet::Inheritable).context("Failed to clear Inheritable caps")?;
        info!("Dropped all capabilities");
    } else {
        info!("Not running as root; skipping UID/GID/caps drop. Sandboxing only.");
    }

    // After NO_NEW_PRIVS, no exec() can grant new privileges — not setuid
    // binaries, not file capabilities. RCE that tries to exec sudo or su
    // gets nothing.
    if let Err(e) = prctl::set_no_new_privileges(true) {
        anyhow::bail!("Failed to set NO_NEW_PRIVS: {}", e);
    }
    info!("Set NO_NEW_PRIVS");

    // Seccomp last. Earlier steps (user lookup, logging, capability ops)
    // need syscalls the filter blocks. After this, only the whitelisted
    // syscalls run; anything else returns EPERM. See seccomp.rs for the
    // list and the reason each entry is on it.
    seccomp::apply_seccomp().context("Failed to apply seccomp filter")?;
    info!("Applied seccomp filter");

    Ok(())
}
