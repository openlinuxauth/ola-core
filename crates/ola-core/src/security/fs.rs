// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use nix::sys::stat::{fstat, FileStat};
use nix::unistd::getuid;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

#[derive(Clone, Copy)]
pub enum SizePolicy {
    Max(i64),
    Exact(i64),
}

#[derive(Clone, Copy)]
pub enum ModePolicy {
    Exact(&'static [u32]),
    NotGroupWorldWritable,
}

#[derive(Clone, Copy)]
pub enum OwnerPolicy {
    RootOrCurrent,
    RootOrUid(u32),
}

#[derive(Clone, Copy)]
pub struct SecureFileSpec {
    pub label: &'static str,
    pub size: SizePolicy,
    pub mode: ModePolicy,
    pub owner: OwnerPolicy,
}

pub fn read_secure_to_string(path: &Path, spec: SecureFileSpec) -> anyhow::Result<String> {
    let mut file = open_secure_read(path, spec)?;
    let stat = validate_open_file(&file, path, spec)?;
    let mut contents = String::with_capacity(stat.st_size.max(0) as usize);
    match spec.size {
        SizePolicy::Max(max) => {
            file.by_ref()
                .take((max as u64).saturating_add(1))
                .read_to_string(&mut contents)
                .with_context(|| format!("Failed to read {} at {}", spec.label, path.display()))?;
            if contents.len() > max as usize {
                anyhow::bail!("{} {} grew while reading", spec.label, path.display());
            }
        }
        _ => {
            file.read_to_string(&mut contents)
                .with_context(|| format!("Failed to read {} at {}", spec.label, path.display()))?;
        }
    }
    Ok(contents)
}

pub fn read_secure_exact<const N: usize>(
    path: &Path,
    mut spec: SecureFileSpec,
) -> anyhow::Result<[u8; N]> {
    spec.size = SizePolicy::Exact(N as i64);
    let mut file = open_secure_read(path, spec)?;
    validate_open_file(&file, path, spec)?;
    let mut bytes = [0u8; N];
    file.read_exact(&mut bytes)
        .with_context(|| format!("Failed to read {} at {}", spec.label, path.display()))?;
    let mut extra = [0u8; 1];
    if file.read(&mut extra).with_context(|| {
        format!(
            "Failed to finish reading {} at {}",
            spec.label,
            path.display()
        )
    })? != 0
    {
        anyhow::bail!("{} {} grew while reading", spec.label, path.display());
    }
    Ok(bytes)
}

pub fn open_secure_append(path: &Path, mode: u32, owner: OwnerPolicy) -> anyhow::Result<File> {
    let existing = open_append_existing(path);
    let (file, check_mode) = match existing {
        Ok(file) => (file, true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => match create_append_log(path, mode) {
            Ok(file) => (file, false),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (
                open_append_existing(path).map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to safely open append log at {}: {}",
                        path.display(),
                        e
                    )
                })?,
                true,
            ),
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Failed to safely open append log at {}: {}",
                    path.display(),
                    e
                ));
            }
        },
        Err(e) => {
            return Err(anyhow::anyhow!(
                "Failed to safely open append log at {}: {}",
                path.display(),
                e
            ));
        }
    };

    let stat = fstat(file.as_raw_fd())?;
    if (stat.st_mode & libc::S_IFMT) != libc::S_IFREG {
        anyhow::bail!("append log {} must be a regular file", path.display());
    }
    validate_owner(stat.st_uid, path, "append log", owner)?;
    if check_mode {
        let existing_mode = stat.st_mode & 0o777;
        if ![0o600, mode].contains(&existing_mode) {
            anyhow::bail!(
                "append log {} must have mode 0600 or {:04o}, found {:o}",
                path.display(),
                mode,
                existing_mode
            );
        }
    }

    // SAFETY: file is an open regular file descriptor, mode is a permission mask.
    let ret = unsafe { libc::fchmod(file.as_raw_fd(), mode) };
    if ret != 0 {
        anyhow::bail!(
            "fchmod append log {} failed: {}",
            path.display(),
            std::io::Error::last_os_error()
        );
    }

    Ok(file)
}

fn open_append_existing(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .append(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
}

fn create_append_log(path: &Path, mode: u32) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .append(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
}

fn open_secure_read(path: &Path, spec: SecureFileSpec) -> anyhow::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    opts.open(path)
        .with_context(|| format!("Failed to safely open {} at {}", spec.label, path.display()))
}

fn validate_open_file(file: &File, path: &Path, spec: SecureFileSpec) -> anyhow::Result<FileStat> {
    let stat = fstat(file.as_raw_fd())?;
    if (stat.st_mode & libc::S_IFMT) != libc::S_IFREG {
        anyhow::bail!("{} {} must be a regular file", spec.label, path.display());
    }

    match spec.size {
        SizePolicy::Max(max) if stat.st_size > max => {
            anyhow::bail!(
                "{} {} too large: {} bytes, max {}",
                spec.label,
                path.display(),
                stat.st_size,
                max
            );
        }
        SizePolicy::Max(_) => {}
        SizePolicy::Exact(expected) if stat.st_size != expected => {
            anyhow::bail!(
                "{} {} must be exactly {} bytes, got {}",
                spec.label,
                path.display(),
                expected,
                stat.st_size
            );
        }
        SizePolicy::Exact(_) => {}
    }

    let mode = stat.st_mode & 0o777;
    match spec.mode {
        ModePolicy::Exact(allowed) if !allowed.contains(&mode) => {
            anyhow::bail!(
                "{} {} must have mode {}, found {:o}",
                spec.label,
                path.display(),
                format_modes(allowed),
                mode
            );
        }
        ModePolicy::Exact(_) => {}
        ModePolicy::NotGroupWorldWritable if mode & 0o022 != 0 => {
            anyhow::bail!("{} {} is group/world writable", spec.label, path.display());
        }
        ModePolicy::NotGroupWorldWritable => {}
    }

    validate_owner(stat.st_uid, path, spec.label, spec.owner)?;

    Ok(stat)
}

fn validate_owner(uid: u32, path: &Path, label: &str, owner: OwnerPolicy) -> anyhow::Result<()> {
    if uid == 0 {
        return Ok(());
    }

    let current_uid = getuid().as_raw();
    let allowed = match owner {
        OwnerPolicy::RootOrCurrent => uid == current_uid,
        OwnerPolicy::RootOrUid(extra_uid) => uid == extra_uid,
    };

    if !allowed {
        anyhow::bail!(
            "{} {} must be owned by root or service user. Owner UID: {}",
            label,
            path.display(),
            uid
        );
    }

    Ok(())
}

fn format_modes(modes: &[u32]) -> String {
    modes
        .iter()
        .map(|mode| format!("{mode:04o}"))
        .collect::<Vec<_>>()
        .join(" or ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn spec(owner: OwnerPolicy) -> SecureFileSpec {
        SecureFileSpec {
            label: "test file",
            size: SizePolicy::Max(1024),
            mode: ModePolicy::Exact(&[0o600]),
            owner,
        }
    }

    #[test]
    fn owner_policy_accepts_current_uid() {
        let file = tempfile::NamedTempFile::new().expect("temp file");
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600))
            .expect("set mode");

        read_secure_to_string(file.path(), spec(OwnerPolicy::RootOrCurrent))
            .expect("current uid owner is valid");
    }

    #[test]
    fn owner_policy_rejects_unlisted_non_root_uid() {
        if getuid().is_root() {
            return;
        }

        let file = tempfile::NamedTempFile::new().expect("temp file");
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600))
            .expect("set mode");
        let other_uid = getuid().as_raw().saturating_add(10_000);

        let err = read_secure_to_string(file.path(), spec(OwnerPolicy::RootOrUid(other_uid)))
            .expect_err("owner must fail");
        assert!(err.to_string().contains("owned by root or service user"));
    }

    #[test]
    fn append_owner_policy_rejects_unlisted_non_root_uid() {
        if getuid().is_root() {
            return;
        }

        let file = tempfile::NamedTempFile::new().expect("temp file");
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600))
            .expect("set mode");
        let other_uid = getuid().as_raw().saturating_add(10_000);

        let err = open_secure_append(file.path(), 0o640, OwnerPolicy::RootOrUid(other_uid))
            .expect_err("append owner must fail");
        assert!(err.to_string().contains("owned by root or service user"));
    }
}
