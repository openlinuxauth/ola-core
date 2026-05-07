// SPDX-License-Identifier: Apache-2.0

use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

pub(crate) fn connect_with_timeout(path: &str, timeout: Duration) -> std::io::Result<UnixStream> {
    let fd = new_socket()?;
    let addr = match unix_addr(path) {
        Ok(addr) => addr,
        Err(e) => {
            close_fd(fd);
            return Err(e);
        }
    };

    // SAFETY: fd is a nonblocking AF_UNIX stream socket. addr is initialized
    // for the returned length.
    let rc = unsafe { libc::connect(fd, (&addr.0 as *const libc::sockaddr_un).cast(), addr.1) };
    if rc == 0 {
        return stream_from_fd(fd);
    }

    let err = std::io::Error::last_os_error();
    if err.raw_os_error() != Some(libc::EINPROGRESS) {
        close_fd(fd);
        return Err(err);
    }

    wait_connected(fd, timeout)?;
    stream_from_fd(fd)
}

fn new_socket() -> std::io::Result<RawFd> {
    // SAFETY: socket has no Rust-side aliasing requirements. Return value is
    // checked before use.
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(fd)
}

fn unix_addr(path: &str) -> std::io::Result<(libc::sockaddr_un, libc::socklen_t)> {
    let bytes = Path::new(path).as_os_str().as_bytes();
    if bytes.is_empty() || bytes.contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "socket path is invalid",
        ));
    }

    // SAFETY: zeroed sockaddr_un is valid before fields are set.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    if bytes.len() + 1 > addr.sun_path.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "socket path is too long",
        ));
    }
    for (dst, src) in addr.sun_path.iter_mut().zip(bytes) {
        *dst = *src as libc::c_char;
    }
    Ok((
        addr,
        (std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1) as libc::socklen_t,
    ))
}

fn wait_connected(fd: RawFd, timeout: Duration) -> std::io::Result<()> {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLOUT,
        revents: 0,
    };
    let start = Instant::now();

    loop {
        let Some(timeout_ms) = poll_timeout_ms(start, timeout) else {
            close_fd(fd);
            return Err(connect_timeout());
        };
        pfd.revents = 0;

        // SAFETY: pfd points to one valid pollfd for the duration of the call.
        let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if rc == 0 {
            close_fd(fd);
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "connect timed out",
            ));
        }
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            close_fd(fd);
            return Err(err);
        }

        let mut so_error: libc::c_int = 0;
        let mut len = std::mem::size_of_val(&so_error) as libc::socklen_t;
        // SAFETY: so_error and len are valid output pointers for SO_ERROR.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&mut so_error as *mut libc::c_int).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            close_fd(fd);
            return Err(err);
        }
        if so_error != 0 {
            close_fd(fd);
            return Err(std::io::Error::from_raw_os_error(so_error));
        }
        return Ok(());
    }
}

fn poll_timeout_ms(start: Instant, timeout: Duration) -> Option<libc::c_int> {
    let remaining = timeout.checked_sub(start.elapsed())?;
    if remaining.is_zero() {
        return None;
    }
    Some(remaining.as_millis().clamp(1, i32::MAX as u128) as libc::c_int)
}

fn connect_timeout() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timed out")
}

fn stream_from_fd(fd: RawFd) -> std::io::Result<UnixStream> {
    // SAFETY: fd is an owned connected AF_UNIX stream socket.
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    stream.set_nonblocking(false)?;
    Ok(stream)
}

fn close_fd(fd: RawFd) {
    // SAFETY: fd is owned by the caller and should not be used afterward.
    unsafe {
        libc::close(fd);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_addr_rejects_invalid_paths() {
        assert!(unix_addr("").is_err());
        assert!(unix_addr("bad\0path").is_err());
    }

    #[test]
    fn poll_timeout_uses_remaining_deadline() {
        let start = Instant::now()
            .checked_sub(Duration::from_millis(50))
            .expect("instant subtraction");
        let timeout_ms = poll_timeout_ms(start, Duration::from_millis(100)).expect("remaining");
        assert!((1..=50).contains(&timeout_ms));

        let expired = Instant::now()
            .checked_sub(Duration::from_millis(100))
            .expect("instant subtraction");
        assert!(poll_timeout_ms(expired, Duration::from_millis(1)).is_none());
    }
}
