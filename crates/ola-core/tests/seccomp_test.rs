// SPDX-License-Identifier: Apache-2.0

#[path = "../src/security/seccomp.rs"]
mod seccomp;

#[test]
fn production_seccomp_blocks_unlisted_syscall() {
    // SAFETY: fork isolates seccomp in the child, parent waits for that exact pid.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());

    if pid == 0 {
        let exit_code = match seccomp::apply_seccomp() {
            Ok(()) => {
                // SAFETY: direct syscall is confined to the child after seccomp.
                let rc = unsafe { libc::syscall(libc::SYS_getpid) };
                if rc == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM) {
                    0
                } else {
                    1
                }
            }
            Err(_) => 2,
        };
        // SAFETY: child exits immediately, no Rust destructors after fork.
        unsafe { libc::_exit(exit_code) };
    }

    let mut status = 0;
    // SAFETY: pid came from fork and status points to valid writable memory.
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(
        waited,
        pid,
        "waitpid failed: {}",
        std::io::Error::last_os_error()
    );
    assert!(
        libc::WIFEXITED(status),
        "seccomp child did not exit normally: status={status}"
    );
    assert_eq!(libc::WEXITSTATUS(status), 0);
}
