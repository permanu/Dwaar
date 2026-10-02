// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1

//! The single-threaded supervisor accepts readiness only from a particular
//! live child after its listening services have started. A shared public
//! listener cannot establish which worker is ready.

use std::cell::RefCell;
use std::collections::HashSet;
use std::io;
use std::os::unix::net::UnixListener;
use std::time::{Duration, Instant};

pub(crate) const MAX_READINESS_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) struct WorkerReadiness {
    directory: tempfile::TempDir,
    listener: UnixListener,
    received: RefCell<HashSet<(libc::pid_t, String)>>,
}

impl WorkerReadiness {
    pub(crate) fn new() -> io::Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::Builder::new()
            .prefix("dwaar-workers-")
            .tempdir_in("/tmp")?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let listener = UnixListener::bind(directory.path().join("ready.sock"))?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            directory,
            listener,
            received: RefCell::new(HashSet::new()),
        })
    }

    /// Called only in the single-threaded supervisor immediately before fork.
    #[allow(unsafe_code)]
    pub(crate) fn prepare_fork(&self) -> String {
        let nonce = crate::upgrade::random_nonce();
        // SAFETY: the supervisor has not started Tokio, Pingora or threads.
        unsafe {
            std::env::set_var(
                "DWAAR_WORKER_READY_SOCKET",
                self.directory.path().join("ready.sock"),
            );
            std::env::set_var("DWAAR_WORKER_READY_NONCE", &nonce);
            std::env::set_var("DWAAR_SUPERVISOR_PID", std::process::id().to_string());
        }
        nonce
    }

    #[allow(unsafe_code)]
    pub(crate) fn clear_fork_environment() {
        // SAFETY: called only in the single-threaded supervisor after fork.
        unsafe {
            std::env::remove_var("DWAAR_WORKER_READY_SOCKET");
            std::env::remove_var("DWAAR_WORKER_READY_NONCE");
            std::env::remove_var("DWAAR_SUPERVISOR_PID");
        }
    }

    pub(crate) fn wait(&self, pid: libc::pid_t, nonce: &str, timeout: Duration) -> io::Result<()> {
        let deadline = Instant::now() + timeout.min(MAX_READINESS_TIMEOUT);
        let key = (pid, nonce.to_owned());
        while Instant::now() < deadline {
            if !child_alive(pid)? {
                return Err(io::Error::other("worker exited before readiness"));
            }
            if self.received.borrow_mut().remove(&key) {
                return Ok(());
            }
            match self.listener.accept() {
                Ok((mut stream, _)) => {
                    if let Ok(body) = crate::upgrade::read_ack(
                        &mut stream,
                        deadline.min(Instant::now() + Duration::from_millis(100)),
                    ) {
                        let fields = body
                            .strip_suffix('\n')
                            .and_then(|body| body.split_once(' '));
                        if let Some((received_nonce, received_pid)) = fields
                            && received_nonce.len() == 32
                            && received_nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
                            && let Ok(received_pid) = received_pid.parse::<libc::pid_t>()
                            && received_pid > 1
                        {
                            let mut received = self.received.borrow_mut();
                            if received.len() < 64 {
                                received.insert((received_pid, received_nonce.to_owned()));
                            }
                        }
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "private worker readiness timed out",
        ))
    }
}

#[allow(unsafe_code)]
fn child_alive(pid: libc::pid_t) -> io::Result<bool> {
    let mut status = 0;
    // SAFETY: the supervisor checks only its own recorded fork child.
    let result = unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(result == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::process::{Child, Command};

    struct TestChild(Child);
    impl Drop for TestChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    fn child() -> TestChild {
        TestChild(Command::new("sleep").arg("5").spawn().expect("test child"))
    }
    fn ack(channel: &WorkerReadiness, nonce: &str, pid: u32) {
        let mut socket = UnixStream::connect(channel.directory.path().join("ready.sock"))
            .expect("private channel");
        writeln!(socket, "{nonce} {pid}").expect("acknowledge");
    }

    #[test]
    fn private_worker_readiness_is_not_satisfied_by_an_old_listener() {
        let channel = WorkerReadiness::new().expect("private readiness channel");
        let child = child();
        let started = Instant::now();
        let result = channel.wait(
            i32::try_from(child.0.id()).expect("readiness test operation"),
            "0123456789abcdef0123456789abcdef",
            Duration::from_millis(100),
        );
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_millis(500));
    }

    #[test]
    fn readiness_binds_child_pid_and_fresh_nonce() {
        let channel = WorkerReadiness::new().expect("readiness test operation");
        let child = child();
        let nonce = "0123456789abcdef0123456789abcdef";
        ack(&channel, "abcdef0123456789abcdef0123456789", child.0.id());
        ack(&channel, nonce, child.0.id() + 1);
        assert!(
            channel
                .wait(
                    i32::try_from(child.0.id()).expect("readiness test operation"),
                    nonce,
                    Duration::from_millis(50)
                )
                .is_err()
        );
        ack(&channel, nonce, child.0.id());
        channel
            .wait(
                i32::try_from(child.0.id()).expect("readiness test operation"),
                nonce,
                Duration::from_millis(100),
            )
            .expect("readiness test operation");
    }

    #[test]
    fn every_worker_ack_is_retained_when_readiness_arrives_out_of_order() {
        let channel = WorkerReadiness::new().expect("readiness test operation");
        let first = child();
        let second = child();
        let first_nonce = "0123456789abcdef0123456789abcdef";
        let second_nonce = "abcdef0123456789abcdef0123456789";
        ack(&channel, second_nonce, second.0.id());
        ack(&channel, first_nonce, first.0.id());
        channel
            .wait(
                i32::try_from(first.0.id()).expect("readiness test operation"),
                first_nonce,
                Duration::from_millis(100),
            )
            .expect("readiness test operation");
        channel
            .wait(
                i32::try_from(second.0.id()).expect("readiness test operation"),
                second_nonce,
                Duration::from_millis(100),
            )
            .expect("readiness test operation");
    }
}
