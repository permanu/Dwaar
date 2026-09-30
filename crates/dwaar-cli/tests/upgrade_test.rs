// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Integration test: zero-downtime SIGUSR2 upgrade.
//!
//! This test is `#[ignore]` because it requires:
//!   - A built `dwaar` binary in `target/`
//!   - An available loopback port (6664) — picked to avoid clashing with the
//!     default proxy port 6188 and admin port 6190
//!   - Linux semantics for `SIGQUIT` / `SIGUSR2` signal delivery
//!   - At least ~5 seconds of wall-clock time
//!
//! Run it explicitly with:
//!   `cargo test --test upgrade_test -- --ignored`
//!
//! CI runs this step in a dedicated "Run ignored tests" job (Linux only).

// Needed for libc::kill, pid_t casts, and raw waitpid.
#![allow(unsafe_code, clippy::cast_possible_wrap, clippy::cast_sign_loss)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ── helpers ───────────────────────────────────────────────────────────────────

/// Resolve the path to the `dwaar` binary produced by `cargo build`.
///
/// Cargo supplies the exact binary built for this test invocation.
fn dwaar_binary() -> PathBuf {
    assert_cmd::cargo::cargo_bin!("dwaar").to_path_buf()
}

/// Write a minimal valid Dwaarfile to a tempfile and return the path.
///
/// Uses port 6664 for the proxy listener so we don't clash with defaults.
fn write_dwaarfile(dir: &tempfile::TempDir, upstream: std::net::SocketAddr) -> PathBuf {
    let path = dir.path().join("Dwaarfile");
    std::fs::write(
        &path,
        format!("{{\n    http_port 6664\n}}\n\nupgrade.test {{\n    tls off\n    reverse_proxy {upstream}\n}}\n"),
    )
    .expect("write Dwaarfile");
    path
}

struct TestUpstream {
    address: std::net::SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    held: std::sync::mpsc::Receiver<()>,
}
impl TestUpstream {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("owned upstream listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let address = listener.local_addr().expect("upstream address");
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let (held, received) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let mut connections = Vec::new();
            while !stopping.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let held = held.clone();
                        connections.push(std::thread::spawn(move || {
                            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                            let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                            let mut request = [0; 4096];
                            if let Ok(count) = stream.read(&mut request) {
                                if request[..count].starts_with(b"GET /hold ") {
                                    let _ = held.send(());
                                    std::thread::sleep(Duration::from_secs(2));
                                }
                                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nupgrade-ok");
                            }
                        }));
                        if connections.len() >= 128 {
                            break;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
            for connection in connections {
                connection.join().expect("upstream request worker");
            }
        });
        Self {
            address,
            stop,
            thread: Some(thread),
            held: received,
        }
    }
}
impl Drop for TestUpstream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            thread.join().expect("owned upstream worker");
        }
    }
}

/// Start a dwaar process in the background. Returns the `Child` handle.
fn start_dwaar(
    binary: &PathBuf,
    dwaarfile: &PathBuf,
    upgrade_sock: &str,
    is_upgrade: bool,
    workers: usize,
) -> Child {
    use std::os::unix::process::CommandExt;
    let mut cmd = Command::new(binary);
    std::fs::create_dir_all(
        dwaarfile
            .parent()
            .expect("test configuration directory")
            .join("state"),
    )
    .expect("private instance state");
    cmd.process_group(0);
    if dwaarfile
        .parent()
        .expect("fixture")
        .join("fail-child")
        .exists()
    {
        cmd.env("DWAAR_UPGRADE_BINARY", "/bin/true");
    }
    cmd.arg("--config")
        .arg(dwaarfile)
        .arg("--no-logging")
        .arg("--no-analytics")
        .arg("--no-geoip")
        .arg("--no-metrics")
        .arg("--no-plugins")
        .arg("--workers").arg(workers.to_string())
        .arg("--state-dir").arg(dwaarfile.parent().expect("test configuration directory").join("state"))
        .env("DWAAR_UPGRADE_SOCK", upgrade_sock)
        // Admin token so /version is reachable without auth on loopback.
        .env("DWAAR_ADMIN_TOKEN", "test-token")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if is_upgrade {
        cmd.arg("--upgrade");
    }

    cmd.spawn().expect("dwaar should start")
}

/// Wait until `http://addr/path` returns HTTP 200, or the deadline elapses.
fn wait_for_200(addr: &str, path: &str, deadline: Instant) -> bool {
    loop {
        if Instant::now() >= deadline {
            return false;
        }
        if let Ok(stream) = TcpStream::connect(addr) {
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap_or(());
            stream
                .set_write_timeout(Some(Duration::from_secs(1)))
                .unwrap_or(());
            let mut stream = stream;
            let req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
            if stream.write_all(req.as_bytes()).is_ok() {
                let mut buf = [0u8; 16];
                if stream.read(&mut buf).is_ok()
                    && (buf.starts_with(b"HTTP/1.1 200") || buf.starts_with(b"HTTP/1.0 200"))
                {
                    return true;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Read the `pid` field from the JSON body of `GET /version`.
fn fetch_pid_from_version(admin_addr: &str) -> Option<u32> {
    let stream = TcpStream::connect(admin_addr).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap_or(());
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap_or(());
    let mut stream = stream;
    let req = format!("GET /version HTTP/1.1\r\nHost: {admin_addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).ok()?;
    let mut body = Vec::new();
    stream.read_to_end(&mut body).ok()?;
    let text = String::from_utf8_lossy(&body);
    // Find the body after the blank line.
    let json = text
        .split_once("\r\n\r\n")
        .map_or(&text as &str, |(_, b)| b);
    // Extract "pid": NUMBER — robust enough for our controlled JSON.
    let after_pid = json.split(r#""pid":"#).nth(1)?;
    after_pid
        .split_once(|c: char| !c.is_ascii_digit())
        .map(|(n, _)| n)
        .or(Some(after_pid.trim()))
        .and_then(|s| s.parse().ok())
}

// ── the actual test ───────────────────────────────────────────────────────────

/// Zero-downtime SIGUSR2 upgrade test.
///
/// Starts a dwaar process, sends sustained HTTP traffic to it (all requests
/// should succeed or get RST'd only by the upstream not existing — not by the
/// upgrade itself), sends SIGUSR2 to trigger a hot upgrade, waits for the new
/// process's `/version` endpoint to show a different PID.
///
/// Marked `#[ignore]` so `cargo test` stays fast; run explicitly with
/// `cargo test --test upgrade_test -- --ignored`.
#[test]
#[ignore = "requires running dwaar binary and Linux signal semantics; run with: cargo test --test upgrade_test -- --ignored"]
fn sigusr2_upgrade_no_failed_requests() {
    check_upgrade(1);
}

#[test]
#[ignore = "requires Linux fork and listener transfer; run in the owned Linux qualification container"]
fn sigusr2_multiworker_upgrade_no_failed_requests() {
    check_upgrade(2);
}

static UPGRADE_TEST_LOCK: Mutex<()> = Mutex::new(());

// One sequential lifecycle makes the traffic, replacement and cleanup evidence reviewable.
#[allow(clippy::too_many_lines)]
fn check_upgrade(workers: usize) {
    let _lock = UPGRADE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = tempfile::TempDir::new().expect("tempdir");
    let binary = dwaar_binary();
    let upstream = TestUpstream::start();
    let dwaarfile = write_dwaarfile(&dir, upstream.address);

    // Use a unique socket path per test run to avoid conflicts.
    let upgrade_sock = dir.path().join("upgrade.sock");
    let upgrade_sock_str = upgrade_sock.to_str().expect("valid utf-8");

    // Admin API on the default 127.0.0.1:6190
    let admin_addr = "127.0.0.1:6190";

    // Start the "old" parent process.
    let mut parent = start_dwaar(&binary, &dwaarfile, upgrade_sock_str, false, workers);
    let parent_pid = parent.id();

    // Wait for /healthz to become 200 (up to 10 s).
    let deadline = Instant::now() + Duration::from_secs(10);
    assert!(
        wait_for_200(admin_addr, "/healthz", deadline),
        "dwaar did not become healthy within 10s (PID {parent_pid})"
    );

    // Capture the initial PID from /version.
    let initial_pid = fetch_pid_from_version(admin_addr)
        .expect("/version should return a pid once the server is up");
    if workers == 1 {
        assert_eq!(
            initial_pid, parent_pid,
            "/version pid should match the process we started"
        );
    }

    let mut held = TcpStream::connect("127.0.0.1:6664").expect("held request connection");
    held.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("held request timeout");
    held.write_all(b"GET /hold HTTP/1.1\r\nHost: upgrade.test\r\nConnection: close\r\n\r\n")
        .expect("held request");
    if upstream.held.recv_timeout(Duration::from_secs(2)).is_err() {
        let mut response = [0; 512];
        let got = held.read(&mut response).unwrap_or_default();
        unsafe {
            libc::kill(-parent_pid.cast_signed(), libc::SIGKILL);
        }
        let _ = parent.wait();
        panic!(
            "held request did not reach owned fixture: {}",
            String::from_utf8_lossy(&response[..got])
                .lines()
                .next()
                .unwrap_or_default()
        );
    }

    // Spawn a background thread to make ~50 successive HTTP requests.
    // Every exchange must reach the owned upstream and return its exact body.
    let failed = Arc::new(AtomicU32::new(0));
    let failed_clone = Arc::clone(&failed);
    let proxy_addr = "127.0.0.1:6664";
    let traffic_handle = std::thread::spawn(move || {
        for _ in 0..50_u32 {
            std::thread::sleep(Duration::from_millis(100));
            match TcpStream::connect(proxy_addr) {
                Ok(stream) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap_or(());
                    stream
                        .set_write_timeout(Some(Duration::from_secs(2)))
                        .unwrap_or(());
                    let mut stream = stream;
                    let sent = stream.write_all(
                        b"GET / HTTP/1.1\r\nHost: upgrade.test\r\nConnection: close\r\n\r\n",
                    );
                    // Validate the complete routed response across the generation swap.
                    let mut body = Vec::new();
                    let received = stream.read_to_end(&mut body);
                    if sent.is_err()
                        || received.is_err()
                        || !body.starts_with(b"HTTP/1.1 200")
                        || !body.ends_with(b"upgrade-ok")
                    {
                        failed_clone.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(_) => {
                    // Proxy port not yet bound or briefly unavailable — count it.
                    failed_clone.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    });

    // Give traffic ~1 s to establish, then send SIGUSR2 to the parent.
    std::thread::sleep(Duration::from_secs(1));

    // SIGUSR2 → the parent spawns a new binary and triggers a graceful upgrade.
    // SAFETY: sending SIGUSR2 to a known PID we own.
    unsafe {
        libc::kill(parent_pid.cast_signed(), libc::SIGUSR2);
    }

    // Wait for the PID on /version to change (up to 15 s).
    let upgrade_deadline = Instant::now() + Duration::from_secs(15);
    let mut new_pid: Option<u32> = None;
    loop {
        if Instant::now() >= upgrade_deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
        if let Some(pid) = fetch_pid_from_version(admin_addr)
            && pid != initial_pid
        {
            new_pid = Some(pid);
            break;
        }
    }

    // Join the traffic thread.
    traffic_handle.join().expect("traffic thread panicked");
    let mut held_response = Vec::new();
    held.read_to_end(&mut held_response)
        .expect("held request survived old generation drain");
    assert!(held_response.starts_with(b"HTTP/1.1 200") && held_response.ends_with(b"upgrade-ok"));

    // Assert upgrade happened.
    let new_pid = new_pid.unwrap_or_else(|| {
        panic!("upgrade did not complete within 15s — /version still shows PID {initial_pid}")
    });
    assert_ne!(
        new_pid, initial_pid,
        "/version should show new PID after upgrade"
    );

    // Assert zero connection-refused errors during the swap window.
    let connection_failures = failed.load(Ordering::Relaxed);
    assert_eq!(
        connection_failures, 0,
        "{connection_failures} requests failed to connect to the proxy during upgrade"
    );

    // Clean up: kill the new child gracefully.
    let new_child_pid = new_pid.cast_signed();
    let new_group = unsafe { libc::getpgid(new_child_pid) };
    unsafe {
        if new_group > 1 {
            libc::kill(-new_group, libc::SIGTERM);
        }
    }

    // Reap the parent (it should have exited after the drain).
    let _ = parent.wait();
    unsafe {
        libc::kill(-parent_pid.cast_signed(), libc::SIGKILL);
        if new_group > 1 {
            libc::kill(-new_group, libc::SIGKILL);
        }
    }
    let stopped_deadline = Instant::now() + Duration::from_secs(3);
    while TcpStream::connect(admin_addr).is_ok() && Instant::now() < stopped_deadline {
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(
        TcpStream::connect(admin_addr).is_err(),
        "owned upgrade processes did not release admin listener"
    );
}

#[test]
#[ignore = "requires Linux fork and listener transfer"]
fn failed_replacement_keeps_old_generation_serving() {
    for workers in [1, 2] {
        let _lock = UPGRADE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().expect("fixture");
        std::fs::write(dir.path().join("fail-child"), "").expect("fixture");
        let upstream = TestUpstream::start();
        let config = write_dwaarfile(&dir, upstream.address);
        let socket = dir.path().join("upgrade.sock");
        let mut parent = start_dwaar(
            &dwaar_binary(),
            &config,
            socket.to_str().expect("path"),
            false,
            workers,
        );
        assert!(wait_for_200(
            "127.0.0.1:6190",
            "/healthz",
            Instant::now() + Duration::from_secs(10)
        ));
        let original = fetch_pid_from_version("127.0.0.1:6190").expect("version");
        unsafe {
            libc::kill(parent.id().cast_signed(), libc::SIGUSR2);
        }
        std::thread::sleep(Duration::from_secs(2));
        let alive = parent.try_wait().expect("child status").is_none();
        let same = fetch_pid_from_version("127.0.0.1:6190") == Some(original);
        let mut stream = TcpStream::connect("127.0.0.1:6664").expect("old route");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: upgrade.test\r\nConnection: close\r\n\r\n")
            .expect("request");
        let mut body = Vec::new();
        let received = stream.read_to_end(&mut body);
        unsafe {
            libc::kill(-parent.id().cast_signed(), libc::SIGTERM);
        }
        let _ = parent.wait();
        unsafe {
            libc::kill(-parent.id().cast_signed(), libc::SIGKILL);
        }
        assert!(
            alive
                && same
                && received.is_ok()
                && body.starts_with(b"HTTP/1.1 200")
                && body.ends_with(b"upgrade-ok")
        );
    }
}
