// SPDX-License-Identifier: Apache-2.0

use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};

// Adding a dependency that needs a new syscall makes the filter return EPERM
// and the failure looks mysterious. Find the blocked syscall with:
//   strace -c ./target/debug/ola-core
// Then add it here with a comment naming the dependency or runtime feature
// that needs it.
pub fn apply_seccomp() -> anyhow::Result<()> {
    let allowed = &[
        // File I/O.
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_close,
        libc::SYS_fcntl,
        libc::SYS_fchmod,
        libc::SYS_openat,
        libc::SYS_fstat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        // Unix-socket IPC.
        libc::SYS_socket,
        libc::SYS_connect,
        libc::SYS_accept4,
        libc::SYS_getsockopt,
        libc::SYS_recvfrom,
        libc::SYS_recvmsg,
        libc::SYS_sendmsg,
        libc::SYS_sendto,
        libc::SYS_socketpair,
        // Tokio event loop.
        libc::SYS_epoll_wait,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_create1,
        libc::SYS_eventfd2,
        libc::SYS_pipe2,
        // Threads and synchronization.
        libc::SYS_futex,
        libc::SYS_clone,
        libc::SYS_clone3,
        libc::SYS_rseq,
        libc::SYS_sched_yield,
        libc::SYS_gettid,
        libc::SYS_getuid,
        libc::SYS_geteuid,
        // Tokio and glibc name late-spawned blocking threads with prctl(PR_SET_NAME).
        libc::SYS_prctl,
        // Signals and process state.
        // Tokio's SIGINT/SIGTERM/SIGHUP handlers need rt_sigaction and rt_sigprocmask.
        // sigaltstack is needed for panic stack unwinding — without it, a panic
        // inside a signal handler turns into SIGSEGV instead of a clean crash.
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_sigaltstack,
        // Time and sleep.
        libc::SYS_clock_gettime,
        libc::SYS_nanosleep,
        // Memory management.
        // The allocator needs these. Blocking mmap/brk crashes the process
        // before any auth code runs — Rust's runtime allocates on startup.
        // Not a security concern: these touch our own address space, not other
        // processes and not the filesystem.
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_mprotect,
        libc::SYS_brk,
        libc::SYS_madvise,
        // Randomness.
        libc::SYS_getrandom,
        // Audit durability.
        // Audit logger calls File::sync_data() per decision; on Linux that is
        // fdatasync(2).
        libc::SYS_fdatasync,
        // Process exit.
        libc::SYS_rt_sigreturn,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ];

    // Default action is EPERM, not KILL. The Rust runtime gets a chance to
    // unwind and log before dying. An unexpected syscall means the process
    // panics next, but the stack trace is worth keeping.
    let filter = SeccompFilter::new(
        allowed.iter().map(|&s| (s, vec![])).collect(),
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        std::env::consts::ARCH.try_into()?,
    )?;

    let bpf: BpfProgram = filter.try_into()?;
    seccompiler::apply_filter_all_threads(&bpf)?;
    Ok(())
}
