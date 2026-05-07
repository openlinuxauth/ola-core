// SPDX-License-Identifier: Apache-2.0

use log::warn;
use std::env;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixDatagram as StdUnixDatagram;
use std::time::Duration;
use tokio::net::UnixDatagram;

// Send READY=1 over NOTIFY_SOCKET. Without this, systemd Type=notify times
// out and kills the daemon — even after a successful bind.
pub fn notify_ready() {
    notify("READY=1");
}

pub fn spawn_watchdog() {
    let Ok(raw_usec) = env::var("WATCHDOG_USEC") else {
        return;
    };
    let Ok(usec) = raw_usec.parse::<u64>() else {
        warn!("invalid WATCHDOG_USEC value: {}", raw_usec);
        return;
    };
    if usec == 0 {
        return;
    }

    let interval = Duration::from_micros(usec / 3).max(Duration::from_secs(1));
    let Ok(socket_path) = env::var("NOTIFY_SOCKET") else {
        warn!("WATCHDOG_USEC set but NOTIFY_SOCKET is missing");
        return;
    };
    let Ok(sock) = UnixDatagram::unbound() else {
        warn!("failed to create systemd watchdog notification socket");
        return;
    };

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            notify_with_socket_async(&sock, &socket_path, "WATCHDOG=1").await;
        }
    });
}

fn notify(message: &str) {
    if let Ok(socket_path) = env::var("NOTIFY_SOCKET") {
        if let Ok(sock) = StdUnixDatagram::unbound() {
            notify_with_socket(&sock, &socket_path, message);
        }
    }
}

fn notify_with_socket(sock: &StdUnixDatagram, socket_path: &str, message: &str) {
    if let Err(e) = send_notify(sock.as_raw_fd(), socket_path, message.as_bytes()) {
        warn!("systemd notification failed ({}): {}", message, e);
    }
}

async fn notify_with_socket_async(sock: &UnixDatagram, socket_path: &str, message: &str) {
    loop {
        match send_notify(sock.as_raw_fd(), socket_path, message.as_bytes()) {
            Ok(()) => return,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(e) = sock.writable().await {
                    warn!("systemd notification failed ({}): {}", message, e);
                    return;
                }
            }
            Err(e) => {
                warn!("systemd notification failed ({}): {}", message, e);
                return;
            }
        }
    }
}

fn send_notify(fd: RawFd, socket_path: &str, message: &[u8]) -> io::Result<()> {
    let (addr, len) = notify_addr(socket_path)?;
    // SAFETY: addr/len come from notify_addr, fd is a Unix datagram socket,
    // and message points to a valid byte slice for the duration of sendto.
    let ret = unsafe {
        libc::sendto(
            fd,
            message.as_ptr().cast(),
            message.len(),
            libc::MSG_NOSIGNAL,
            (&addr as *const libc::sockaddr_un).cast(),
            len,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn notify_addr(socket_path: &str) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
    if socket_path.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NOTIFY_SOCKET is empty",
        ));
    }

    // SAFETY: zeroed sockaddr_un is a valid base value before fields are set.
    let mut addr: libc::sockaddr_un = unsafe { mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let base_len = mem::size_of::<libc::sa_family_t>();
    let sun_path = &mut addr.sun_path;

    if let Some(name) = socket_path.strip_prefix('@') {
        let bytes = name.as_bytes();
        if bytes.is_empty() || bytes.len() + 1 > sun_path.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "abstract NOTIFY_SOCKET length is invalid",
            ));
        }
        sun_path[0] = 0;
        for (dst, src) in sun_path[1..].iter_mut().zip(bytes) {
            *dst = *src as libc::c_char;
        }
        return Ok((addr, (base_len + 1 + bytes.len()) as libc::socklen_t));
    }

    let bytes = socket_path.as_bytes();
    if bytes.len() + 1 > sun_path.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NOTIFY_SOCKET path is too long",
        ));
    }
    for (dst, src) in sun_path.iter_mut().zip(bytes) {
        *dst = *src as libc::c_char;
    }
    Ok((addr, (base_len + bytes.len() + 1) as libc::socklen_t))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notify_addr_supports_abstract_socket() {
        let (addr, len) = notify_addr("@ola-notify").expect("abstract address");
        assert_eq!(addr.sun_path[0], 0);
        assert_eq!(addr.sun_path[1] as u8, b'o');
        assert_eq!(
            len as usize,
            mem::size_of::<libc::sa_family_t>() + 1 + "ola-notify".len()
        );
    }

    #[test]
    fn notify_addr_supports_path_socket() {
        let (addr, len) = notify_addr("/run/systemd/notify").expect("path address");
        assert_eq!(addr.sun_path[0] as u8, b'/');
        assert_eq!(
            len as usize,
            mem::size_of::<libc::sa_family_t>() + "/run/systemd/notify".len() + 1
        );
    }
}
