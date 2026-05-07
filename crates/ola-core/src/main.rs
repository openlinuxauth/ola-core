// SPDX-License-Identifier: Apache-2.0

#![deny(unused_must_use)]

mod adapters;
mod config;
mod core;
mod infrastructure;
mod security;

use crate::config::Config;
use log::info;
use std::sync::Arc;

// Lock the process umask before anything opens a file. Without this, files
// created during startup (log handles, sockets) inherit the calling
// shell's umask. On many systems that is 0o022, group-readable. For a daemon
// that holds auth keys and an audit log, that is unacceptable. 0o077:
// owner-only.
fn harden_umask() {
    // SAFETY: umask is process-global and accepts any mode_t mask. Startup is
    // single-threaded before Tokio tasks are spawned.
    unsafe {
        libc::umask(0o077);
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Umask first — before any file touches disk.
    harden_umask();

    let config = Arc::new(Config::from_env()?);
    info!("Starting ola-core {}", env!("CARGO_PKG_VERSION"));
    info!("Running in {} mode", config.run_mode);

    // Server last. Umask, logging, and config are already in place.
    infrastructure::ipc::unix_socket::run_server(config).await?;

    info!("OLA Core service stopped cleanly.");
    Ok(())
}
