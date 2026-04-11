// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Supervisor-side readiness probe for forked worker children.
//!
//! After the supervisor `fork()`s a new worker (either as part of initial
//! startup, a crash-loop restart, or a SIGHUP-driven reload) it must verify
//! that the child has actually bound its listening sockets before declaring
//! the restart successful. Without this check, a race window exists where
//! clients can connect while no worker owns the listening port, or the old
//! worker is signalled to drain before the replacement is ready.
//!
//! This module exposes a small blocking probe that polls a TCP address or a
//! Unix domain socket until either:
//!   1. `connect()` succeeds → the child has bound the listener → Ok(())
//!   2. `waitpid(pid, WNOHANG)` reports the child has exited → `ChildExited`
//!   3. The overall deadline is reached → Timeout
//!
//! We use blocking stdlib sockets rather than Tokio here because the
//! supervisor loop in `main.rs` is itself synchronous — it runs before
//! Pingora starts and has no Tokio runtime. Spinning up a current-thread
//! runtime just for this probe would add complexity for no benefit.

use std::io;
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Upper bound for the supervisor readiness probe. A worker that cannot
/// bind its listeners within this window is assumed wedged and killed.
pub(crate) const MAX_READINESS_TIMEOUT: Duration = Duration::from_secs(10);

/// Delay between probe attempts. Short enough to catch a ready child
/// within ~50 ms of actual readiness, long enough to avoid a busy loop.
const PROBE_INTERVAL: Duration = Duration::from_millis(50);

/// Which endpoint to probe.
#[derive(Debug, Clone)]
pub(crate) enum ReadinessTarget {
    /// TCP address — used for the always-on admin listener (127.0.0.1:6190).
    Tcp(String),
    /// Unix domain socket path — used when `--admin-socket` is set.
    Uds(PathBuf),
}

impl ReadinessTarget {
    /// Return a human-readable label for logging.
    pub(crate) fn label(&self) -> String {
        match self {
            Self::Tcp(addr) => format!("tcp://{addr}"),
            Self::Uds(path) => format!("uds://{}", path.display()),
        }
    }
}

/// Errors returned by the supervisor readiness probe.
#[derive(Debug)]
pub(crate) enum ReadinessError {
    /// The child did not accept a connection before the deadline.
    Timeout { target: String, waited: Duration },
    /// The child exited (crashed or self-terminated) while we were probing.
    ChildExited {
        pid: libc::pid_t,
        description: String,
    },
}

impl std::fmt::Display for ReadinessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout { target, waited } => {
                write!(
                    f,
                    "worker did not become ready on {target} within {waited:?}"
                )
            }
            Self::ChildExited { pid, description } => write!(
                f,
                "worker pid {pid} exited before becoming ready: {description}"
            ),
        }
    }
}

impl std::error::Error for ReadinessError {}

/// Block until the forked child accepts a connection on `target`, or until
/// the child exits, or until `timeout` elapses — whichever happens first.
///
/// `timeout` is silently clamped to [`MAX_READINESS_TIMEOUT`] so a caller
/// cannot accidentally pin the supervisor waiting forever on a wedged child.
///
/// Blocking by design — the supervisor thread runs outside any Tokio runtime.
pub(crate) fn wait_for_child_ready(
    pid: libc::pid_t,
    target: &ReadinessTarget,
    timeout: Duration,
) -> Result<(), ReadinessError> {
    let effective = timeout.min(MAX_READINESS_TIMEOUT);
    let started = Instant::now();

    loop {
        // Short per-attempt timeout so a half-open TCP listener doesn't stall
        // the probe beyond the overall deadline. 100 ms is plenty for a
        // localhost connect, well under PROBE_INTERVAL's cadence.
        match try_connect(target, Duration::from_millis(100)) {
            Ok(()) => return Ok(()),
            Err(e) if is_transient(&e) => {
                // Not yet listening — fall through to child-exit / timeout checks.
            }
            Err(e) => {
                // Unexpected error — treat as transient and keep probing.
                // If it is persistent we'll still hit the deadline.
                tracing::debug!(
                    error = %e,
                    target = target.label(),
                    "unexpected error while probing child readiness (will retry)"
                );
            }
        }

        // Did the child die underneath us? `waitpid(pid, WNOHANG)` returns
        // `pid` on exit, `0` while still alive, `-1` on error.
        if let Some(description) = child_exited(pid) {
            return Err(ReadinessError::ChildExited { pid, description });
        }

        if started.elapsed() >= effective {
            return Err(ReadinessError::Timeout {
                target: target.label(),
                waited: effective,
            });
        }

        std::thread::sleep(PROBE_INTERVAL);
    }
}

/// Attempt a single synchronous connection to `target`.
fn try_connect(target: &ReadinessTarget, per_attempt: Duration) -> io::Result<()> {
    match target {
        ReadinessTarget::Tcp(addr) => {
            // Resolve-then-connect with a timeout so we don't block forever
            // on an unreachable address.
            let sock_addr = addr
                .parse::<std::net::SocketAddr>()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            let stream = TcpStream::connect_timeout(&sock_addr, per_attempt)?;
            drop(stream);
            Ok(())
        }
        ReadinessTarget::Uds(path) => {
            // UnixStream::connect is non-configurable for timeouts but is
            // effectively instant on an in-kernel socket — either the file
            // is there and the listener is accepting, or we get ENOENT /
            // ECONNREFUSED immediately.
            let stream = UnixStream::connect(path)?;
            drop(stream);
            Ok(())
        }
    }
}

/// Return `true` if `err` means "not yet ready" (listener hasn't bound).
fn is_transient(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::NotFound
            | io::ErrorKind::TimedOut
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::AddrNotAvailable
    )
}

/// Poll `waitpid(pid, WNOHANG)`. Returns `Some(description)` if the child
/// has exited, `None` if it is still running.
fn child_exited(pid: libc::pid_t) -> Option<String> {
    let mut status: libc::c_int = 0;
    // SAFETY: standard waitpid with WNOHANG — does not block.
    #[allow(unsafe_code)]
    let result = unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG) };
    if result == pid {
        // Child reaped — describe how it died so the caller can log it.
        if libc::WIFEXITED(status) {
            Some(format!("exit code {}", libc::WEXITSTATUS(status)))
        } else if libc::WIFSIGNALED(status) {
            Some(format!("signal {}", libc::WTERMSIG(status)))
        } else {
            Some("unknown status".to_string())
        }
    } else {
        None
    }
}

/// Pick a readiness target given the CLI `--admin-socket` option.
///
/// If a UDS path was supplied we prefer it — it is deterministic and only
/// worker 0 binds it. Otherwise fall back to the TCP admin listener, which
/// is unconditionally registered on `127.0.0.1:6190` by worker 0.
pub(crate) fn target_from_admin_socket(admin_socket: Option<&Path>) -> ReadinessTarget {
    match admin_socket {
        Some(path) => ReadinessTarget::Uds(path.to_path_buf()),
        None => ReadinessTarget::Tcp("127.0.0.1:6190".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn timeout_on_missing_uds_under_500ms() {
        // Probe a socket path that definitely does not exist. The probe
        // must return Timeout (not block, not panic) within well under the
        // configured ceiling.
        let missing = PathBuf::from("/tmp/dwaar-readiness-test-nonexistent.sock");
        let target = ReadinessTarget::Uds(missing);

        // PID 1 is always alive on Linux/macOS so child_exited() never
        // short-circuits during the test — we're strictly exercising the
        // timeout path.
        let started = Instant::now();
        let err = wait_for_child_ready(1, &target, Duration::from_millis(300))
            .expect_err("missing socket must not connect");
        let elapsed = started.elapsed();

        assert!(
            matches!(err, ReadinessError::Timeout { .. }),
            "expected Timeout, got {err:?}"
        );
        assert!(
            elapsed < Duration::from_millis(500),
            "probe must respect the 300 ms deadline (waited {elapsed:?})"
        );
    }

    #[test]
    fn timeout_on_unbound_tcp_port() {
        // 127.0.0.1:1 is reserved and will refuse immediately on every
        // attempt. The probe should return Timeout after the deadline.
        let target = ReadinessTarget::Tcp("127.0.0.1:1".to_string());
        let started = Instant::now();
        let err = wait_for_child_ready(1, &target, Duration::from_millis(250))
            .expect_err("unbound port must not connect");
        let elapsed = started.elapsed();
        assert!(matches!(err, ReadinessError::Timeout { .. }));
        assert!(elapsed < Duration::from_millis(600));
    }

    #[test]
    fn target_from_admin_socket_prefers_uds() {
        let path = PathBuf::from("/var/run/dwaar-admin.sock");
        match target_from_admin_socket(Some(&path)) {
            ReadinessTarget::Uds(p) => assert_eq!(p, path),
            ReadinessTarget::Tcp(_) => panic!("expected UDS target when admin_socket is set"),
        }
    }

    #[test]
    fn target_from_admin_socket_falls_back_to_tcp() {
        match target_from_admin_socket(None) {
            ReadinessTarget::Tcp(addr) => assert_eq!(addr, "127.0.0.1:6190"),
            ReadinessTarget::Uds(_) => panic!("expected TCP target when admin_socket is None"),
        }
    }

    #[test]
    fn label_formats_cleanly() {
        assert_eq!(
            ReadinessTarget::Tcp("127.0.0.1:6190".to_string()).label(),
            "tcp://127.0.0.1:6190"
        );
        assert_eq!(
            ReadinessTarget::Uds(PathBuf::from("/tmp/a.sock")).label(),
            "uds:///tmp/a.sock"
        );
    }
}
