// SPDX-License-Identifier: Apache-2.0

use crate::config::Config;
use crate::security::privilege;
use anyhow::Context;
use listenfd::ListenFd;
use log::info;
use std::fs::{self, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use tokio::net::UnixListener;
use uzers::get_user_by_name;

pub(crate) fn setup_listener(config: &Config) -> anyhow::Result<UnixListener> {
    let listener = if let Ok(Some(std_listener)) = ListenFd::from_env().take_unix_listener(0) {
        info!("Using systemd socket activation");
        std_listener.set_nonblocking(true)?;
        UnixListener::from_std(std_listener)?
    } else {
        if let Some(parent) = config.socket_path.parent() {
            prepare_socket_parent(parent, config)?;
        }

        remove_stale_socket(&config.socket_path)?;

        let manual_listener = UnixListener::bind(&config.socket_path)
            .with_context(|| format!("binding to socket {}", config.socket_path.display()))?;
        let fd = manual_listener.as_raw_fd();

        set_socket_mode(fd)?;

        if nix::unistd::geteuid().is_root() {
            let service_user = privilege::service_user_name();
            let ola_user = get_user_by_name(&service_user)
                .ok_or_else(|| anyhow::anyhow!("service user {} not found", service_user))?;
            set_socket_owner(fd, ola_user.uid(), ola_user.primary_group_id())?;
        }

        manual_listener
    };

    privilege::drop_privileges_completely()?;
    Ok(listener)
}

pub(crate) fn set_socket_mode(fd: i32) -> anyhow::Result<()> {
    // SAFETY: fd targets the bound socket inode, not a swappable path.
    let ret = unsafe { libc::fchmod(fd, 0o660) };
    if ret != 0 {
        return Err(anyhow::anyhow!(
            "fchmod failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

pub(crate) fn set_socket_owner(fd: i32, uid: u32, gid: u32) -> anyhow::Result<()> {
    // SAFETY: fd targets the bound socket inode, not a swappable path.
    let ret = unsafe { libc::fchown(fd, uid, gid) };
    if ret != 0 {
        return Err(anyhow::anyhow!(
            "fchown failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

pub(crate) fn prepare_socket_parent(parent: &Path, config: &Config) -> anyhow::Result<()> {
    if !parent.exists() {
        fs::create_dir_all(parent)?;
    }

    if !(config.is_prod_mode() || nix::unistd::geteuid().is_root()) {
        return Ok(());
    }

    let metadata = fs::symlink_metadata(parent)?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!("Socket parent {} is a symlink", parent.display());
    }
    if !metadata.is_dir() {
        anyhow::bail!("Socket parent {} is not a directory", parent.display());
    }

    if nix::unistd::geteuid().is_root() {
        let service_user = privilege::service_user_name();
        let ola_user = get_user_by_name(&service_user)
            .ok_or_else(|| anyhow::anyhow!("service user {} not found", service_user))?;
        set_socket_parent_owner(parent, ola_user.primary_group_id())?;
    } else {
        let mut perms = metadata.permissions();
        perms.set_mode(0o750);
        fs::set_permissions(parent, perms)?;
    }

    Ok(())
}

fn set_socket_parent_owner(parent: &Path, gid: u32) -> anyhow::Result<()> {
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)
        .with_context(|| format!("opening socket parent {}", parent.display()))?;
    let fd = dir.as_raw_fd();

    // SAFETY: O_NOFOLLOW pins the directory, chmod cannot land on a symlink.
    let chmod_ret = unsafe { libc::fchmod(fd, 0o750) };
    if chmod_ret != 0 {
        anyhow::bail!(
            "fchmod socket parent {} failed: {}",
            parent.display(),
            std::io::Error::last_os_error()
        );
    }

    // SAFETY: fd is still pinned, chown cannot land on a symlink.
    let chown_ret = unsafe { libc::fchown(fd, 0, gid) };
    if chown_ret != 0 {
        anyhow::bail!(
            "fchown socket parent {} failed: {}",
            parent.display(),
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

fn remove_stale_socket(path: &Path) -> anyhow::Result<()> {
    remove_stale_socket_with(path, |p| std::os::unix::net::UnixStream::connect(p))
}

pub(crate) fn remove_stale_socket_with<F>(path: &Path, connect: F) -> anyhow::Result<()>
where
    F: for<'a> Fn(&'a Path) -> std::io::Result<std::os::unix::net::UnixStream>,
{
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("checking {}", path.display())),
    };
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        anyhow::bail!(
            "Socket path {} is a symlink; remove it manually",
            path.display()
        );
    }
    if !file_type.is_socket() {
        anyhow::bail!(
            "Socket path {} exists but is not a Unix socket; remove it manually",
            path.display()
        );
    }

    match connect(path) {
        Ok(_) => anyhow::bail!("Socket in use"),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            fs::remove_file(path)?;
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            anyhow::bail!(
                "Socket at {} exists but is not accessible: {}. \
                 Check permissions or remove manually.",
                path.display(),
                e
            )
        }
        Err(_) => {
            fs::remove_file(path)?;
            Ok(())
        }
    }
}
