// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1

//! Private, child-specific upgrade readiness. Listener transfer precedes
//! readiness; the parent keeps accepting until the child acknowledges.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::Child;
use std::time::{Duration, Instant};

pub(crate) fn read_parent_pid(path: &std::path::Path) -> std::io::Result<i32> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    #[allow(unsafe_code)]
    let uid = unsafe { libc::getuid() };
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o022 != 0
        || metadata.len() > 32
    {
        return Err(std::io::Error::other("unsafe PID file"));
    }
    let mut body = String::new();
    file.take(33).read_to_string(&mut body)?;
    let pid = body.trim().parse::<i32>().ok().filter(|pid| *pid > 1);
    if body.len() > 32 {
        return Err(std::io::Error::other("invalid parent PID"));
    }
    pid.ok_or_else(|| std::io::Error::other("invalid parent PID"))
}

pub(crate) fn verify_parent_process(pid: i32) -> std::io::Result<()> {
    if pid <= 1 {
        return Err(std::io::Error::other("invalid Dwaar parent"));
    }
    #[cfg(target_os = "linux")]
    let executable = {
        use std::os::unix::fs::MetadataExt;
        #[allow(unsafe_code)]
        let uid = unsafe { libc::getuid() };
        if std::fs::metadata(format!("/proc/{pid}"))?.uid() != uid {
            return Err(std::io::Error::other(
                "Dwaar parent belongs to another user",
            ));
        }
        std::fs::read_link(format!("/proc/{pid}/exe"))?
    };
    #[cfg(target_os = "macos")]
    let executable = {
        use std::os::unix::ffi::OsStrExt;
        let mut path = [0u8; 4096];
        #[allow(unsafe_code)]
        let count = unsafe { libc::proc_pidpath(pid, path.as_mut_ptr().cast(), 4096) };
        if count <= 0 {
            return Err(std::io::Error::last_os_error());
        }
        let length = path
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(path.len());
        std::path::PathBuf::from(std::ffi::OsStr::from_bytes(&path[..length]))
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    return Err(std::io::Error::other(
        "process identity verification is unsupported",
    ));
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if executable != std::env::current_exe()? {
        return Err(std::io::Error::other(
            "PID does not identify this Dwaar executable",
        ));
    }
    Ok(())
}

fn matches_ack(body: &str, nonce: &str, pid: u32) -> bool {
    body == format!("{nonce} {pid}\n")
}

use pingora_core::server::{ListenFds, Server, ShutdownWatch};
use pingora_core::services::{Service, ServiceHandle, ServiceWithDependents};
use std::sync::{Mutex, OnceLock};

static LISTENERS: OnceLock<ListenFds> = OnceLock::new();
static SERVICES: Mutex<Vec<ServiceHandle>> = Mutex::new(Vec::new());

pub(crate) fn add_service<S: ServiceWithDependents + 'static>(server: &mut Server, service: S) {
    let handle = server.add_service(service);
    SERVICES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(handle);
}

pub(crate) fn install(server: &mut Server) {
    let handles = SERVICES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let ready = server.add_service(Coordinator);
    for handle in handles {
        ready.add_dependency(&handle);
    }
}

pub(crate) struct Coordinator;

#[async_trait::async_trait]
impl Service for Coordinator {
    async fn start_service(
        &mut self,
        fds: Option<ListenFds>,
        mut shutdown: ShutdownWatch,
        _: usize,
    ) {
        let Some(fds) = fds else { return };
        let _ = LISTENERS.set(fds.clone());
        if fds.lock().await.serialize().0.is_empty() {
            return;
        }
        if dwaar_core::readiness::failed() || *shutdown.borrow() {
            return;
        }
        let _ = acknowledge_environment("DWAAR_WORKER_READY_SOCKET", "DWAAR_WORKER_READY_NONCE");
        if std::env::var_os("DWAAR_WORKER_READY_SOCKET").is_none() {
            let _ = acknowledge_environment("DWAAR_UPGRADE_ACK", "DWAAR_UPGRADE_NONCE");
        }
        let _ = shutdown.changed().await;
    }
    fn name(&self) -> &'static str {
        "upgrade-ready"
    }
    fn threads(&self) -> Option<usize> {
        Some(1)
    }
}

pub(crate) struct Handshake {
    directory: tempfile::TempDir,
    listener: UnixListener,
    nonce: String,
}

impl Handshake {
    pub(crate) fn new() -> std::io::Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::Builder::new()
            .prefix("dwaar-up-")
            .tempdir_in("/tmp")?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let listener = UnixListener::bind(directory.path().join("ack.sock"))?;
        listener.set_nonblocking(true)?;
        let nonce = random_nonce();
        Ok(Self {
            directory,
            listener,
            nonce,
        })
    }

    pub(crate) fn configure(&self, command: &mut std::process::Command) {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
        command
            .env_remove("DWAAR_WORKER_READY_SOCKET")
            .env_remove("DWAAR_WORKER_READY_NONCE")
            .env_remove("DWAAR_SUPERVISOR_PID")
            .env("DWAAR_UPGRADE_SOCK", self.directory.path().join("fds.sock"))
            .env("DWAAR_UPGRADE_ACK", self.directory.path().join("ack.sock"))
            .env("DWAAR_UPGRADE_NONCE", &self.nonce)
            .env("DWAAR_UPGRADE_FROM", "1");
    }

    pub(crate) fn await_ready(&self, child: &mut Child, timeout: Duration) -> std::io::Result<()> {
        let deadline = Instant::now() + timeout.min(Duration::from_secs(300));
        self.transfer(child, deadline)?;
        self.await_ack(child, deadline)
    }

    fn transfer(&self, child: &mut Child, deadline: Instant) -> std::io::Result<()> {
        let socket = self.directory.path().join("fds.sock");
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (child, deadline, socket);
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "listener transfer requires Linux",
            ))
        }
        #[cfg(target_os = "linux")]
        {
            let fds = LISTENERS
                .get()
                .ok_or_else(|| std::io::Error::other("running listener descriptors unavailable"))?;
            let descriptors = fds.blocking_lock();
            let (keys, values) = descriptors.serialize();
            if keys.is_empty() || values.len() > 32 || keys.join(" ").len() > 2048 {
                return Err(std::io::Error::other(
                    "listener transfer exceeds protocol bounds",
                ));
            }
            // Pingora's child bootstrap opens this private rendezvous. Do not
            // ask its parent to drain just to initiate descriptor transfer.
            while !socket.exists() {
                if child.try_wait()?.is_some() {
                    return Err(std::io::Error::other("upgrade child exited"));
                }
                if Instant::now() >= deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "upgrade child did not receive listeners",
                    ));
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            descriptors
                .send_to_sock(
                    socket
                        .to_str()
                        .ok_or_else(|| std::io::Error::other("invalid upgrade socket path"))?,
                )
                .map_err(|_| std::io::Error::other("listener transfer failed"))?;
            drop(descriptors);
            Ok(())
        }
    }

    fn await_ack(&self, child: &mut Child, deadline: Instant) -> std::io::Result<()> {
        while Instant::now() < deadline {
            if child.try_wait()?.is_some() {
                return Err(std::io::Error::other(
                    "upgrade child exited before readiness",
                ));
            }
            match self.listener.accept() {
                Ok((mut stream, _)) => {
                    if let Ok(body) = read_ack(
                        &mut stream,
                        deadline.min(Instant::now() + Duration::from_millis(100)),
                    ) && matches_ack(&body, &self.nonce, child.id())
                        && child.try_wait()?.is_none()
                    {
                        return Ok(());
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "upgrade child readiness timed out",
        ))
    }
}

pub(crate) fn read_ack(stream: &mut UnixStream, deadline: Instant) -> std::io::Result<String> {
    stream.set_nonblocking(true)?;
    let mut body = Vec::new();
    let mut buffer = [0; 128];
    while Instant::now() < deadline {
        match stream.read(&mut buffer) {
            Ok(0) => {
                return String::from_utf8(body)
                    .map_err(|_| std::io::Error::other("invalid acknowledgement"));
            }
            Ok(count) => {
                if body.len() + count > 128 {
                    return Err(std::io::Error::other("oversized acknowledgement"));
                }
                body.extend_from_slice(&buffer[..count]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "acknowledgement read timed out",
    ))
}

pub(crate) fn acknowledge_environment(socket_var: &str, nonce_var: &str) -> std::io::Result<()> {
    let Some(path) = std::env::var_os(socket_var) else {
        return Ok(());
    };
    let nonce =
        std::env::var(nonce_var).map_err(|_| std::io::Error::other("missing readiness nonce"))?;
    if nonce.len() != 32 || !nonce.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(std::io::Error::other("invalid readiness nonce"));
    }
    let mut stream = UnixStream::connect(path)?;
    stream.set_nonblocking(true)?;
    let body = format!("{nonce} {}\n", std::process::id());
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut written = 0;
    while written < body.len() && Instant::now() < deadline {
        match stream.write(&body.as_bytes()[written..]) {
            Ok(0) => return Err(std::io::Error::other("readiness channel closed")),
            Ok(count) => written += count,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error),
        }
    }
    if written != body.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "readiness write timed out",
        ));
    }
    Ok(())
}

pub(crate) fn stop_child(child: &mut Child) {
    let Ok(group) = i32::try_from(child.id()) else {
        return;
    };
    if group <= 1 {
        return;
    }
    // The child was spawned into this freshly owned process group.
    #[allow(unsafe_code)]
    unsafe {
        libc::kill(-group, libc::SIGTERM);
    }
    std::thread::sleep(Duration::from_millis(100));
    #[allow(unsafe_code)]
    unsafe {
        libc::kill(-group, libc::SIGKILL);
    }
    let _ = child.wait();
}

pub(crate) fn random_nonce() -> String {
    let mut nonce = String::with_capacity(32);
    for byte in rand::random::<[u8; 16]>() {
        use std::fmt::Write as _;
        write!(&mut nonce, "{byte:02x}").expect("writing to a String cannot fail");
    }
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_file_rejects_symlinks_writable_and_oversized_contents() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let directory = tempfile::tempdir().expect("fixture");
        let file = directory.path().join("pid");
        std::fs::write(&file, "42\n").expect("fixture");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).expect("fixture");
        assert_eq!(read_parent_pid(&file).expect("valid"), 42);
        let link = directory.path().join("link");
        symlink(&file, &link).expect("fixture");
        assert!(read_parent_pid(&link).is_err());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o620)).expect("fixture");
        assert!(read_parent_pid(&file).is_err());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).expect("fixture");
        std::fs::write(&file, "4".repeat(33)).expect("fixture");
        assert!(read_parent_pid(&file).is_err());
        std::fs::write(&file, "1").expect("fixture");
        assert!(read_parent_pid(&file).is_err());
    }

    #[test]
    fn unrelated_process_cannot_receive_upgrade_signal() {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("2")
            .spawn()
            .expect("fixture");
        assert!(verify_parent_process(i32::try_from(child.id()).expect("PID")).is_err());
        child.kill().expect("cleanup");
        child.wait().expect("reap");
    }

    #[test]
    fn readiness_is_bound_to_both_nonce_and_child_identity() {
        assert!(matches_ack("one 42\n", "one", 42));
        assert!(!matches_ack("one 41\n", "one", 42));
        assert!(!matches_ack("old 42\n", "one", 42));
        assert!(!matches_ack("one 42\ntrailing", "one", 42));
    }

    #[test]
    fn another_process_ack_cannot_drain_the_parent() {
        let handshake = Handshake::new().expect("upgrade test fixture");
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("2")
            .spawn()
            .expect("upgrade test fixture");
        let mut stream = UnixStream::connect(handshake.directory.path().join("ack.sock"))
            .expect("upgrade test fixture");
        writeln!(stream, "{} {}", handshake.nonce, std::process::id())
            .expect("upgrade test fixture");
        drop(stream);
        assert!(
            handshake
                .await_ack(&mut child, Instant::now() + Duration::from_millis(100))
                .is_err()
        );
        child.kill().expect("upgrade test fixture");
        child.wait().expect("upgrade test fixture");
    }

    #[test]
    fn only_live_child_with_current_nonce_can_acknowledge() {
        let handshake = Handshake::new().expect("upgrade test fixture");
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("2")
            .spawn()
            .expect("upgrade test fixture");
        let mut stream = UnixStream::connect(handshake.directory.path().join("ack.sock"))
            .expect("upgrade test fixture");
        writeln!(stream, "{} {}", handshake.nonce, child.id()).expect("upgrade test fixture");
        drop(stream);
        let result = handshake.await_ack(&mut child, Instant::now() + Duration::from_millis(100));
        assert!(result.is_ok(), "{result:?}");
        child.kill().expect("upgrade test fixture");
        child.wait().expect("upgrade test fixture");
    }
}
