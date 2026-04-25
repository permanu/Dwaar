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
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

// ── helpers ───────────────────────────────────────────────────────────────────

/// Resolve the path to the `dwaar` binary produced by `cargo build`.
///
/// We prefer the release binary (faster shutdown) but fall back to debug.
/// If neither exists the test is skipped with a clear message.
fn dwaar_binary() -> PathBuf {
    // assert_cmd knows the right path regardless of workspace layout.
    let out = std::process::Command::new("cargo")
        .args(["build", "--bin", "dwaar", "--message-format=json"])
        .output()
        .expect("cargo build should succeed");
    // Just find the binary via target layout — simpler than parsing JSON.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest.ancestors().nth(2).expect("workspace root");
    let release = workspace.join("target/release/dwaar");
    let debug = workspace.join("target/debug/dwaar");
    if release.exists() {
        return release;
    }
    if debug.exists() {
        return debug;
    }
    // Build it now (slow but guaranteed).
    assert!(
        out.status.success(),
        "cargo build failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    debug
}

/// Write a minimal valid Dwaarfile to a tempfile and return the path.
///
/// Uses port 6664 for the proxy listener so we don't clash with defaults.
fn write_dwaarfile(dir: &tempfile::TempDir) -> PathBuf {
    let path = dir.path().join("Dwaarfile");
    std::fs::write(
        &path,
        "{\n    http_port 6664\n}\n\n:6664 {\n    reverse_proxy 127.0.0.1:1\n}\n",
    )
    .expect("write Dwaarfile");
    path
}

/// Start a dwaar process in the background. Returns the `Child` handle.
fn start_dwaar(
    binary: &PathBuf,
    dwaarfile: &PathBuf,
    upgrade_sock: &str,
    is_upgrade: bool,
) -> Child {
    let mut cmd = Command::new(binary);
    cmd.arg("--config")
        .arg(dwaarfile)
        .arg("--no-logging")
        .arg("--no-analytics")
        .arg("--no-geoip")
        .arg("--no-metrics")
        .arg("--no-plugins")
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
    let dir = tempfile::TempDir::new().expect("tempdir");
    let binary = dwaar_binary();
    let dwaarfile = write_dwaarfile(&dir);

    // Use a unique socket path per test run to avoid conflicts.
    let upgrade_sock = dir.path().join("upgrade.sock");
    let upgrade_sock_str = upgrade_sock.to_str().expect("valid utf-8");

    // Admin API on the default 127.0.0.1:6190
    let admin_addr = "127.0.0.1:6190";

    // Start the "old" parent process.
    let mut parent = start_dwaar(&binary, &dwaarfile, upgrade_sock_str, false);
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
    assert_eq!(
        initial_pid, parent_pid,
        "/version pid should match the process we started"
    );

    // Spawn a background thread to make ~50 successive HTTP requests.
    // The proxy tries to reach 127.0.0.1:1 (which refuses), so we get 502s
    // from Dwaar — but those are valid responses, not connection resets.
    // We count connection-refused errors (TcpStream::connect fail) as failures.
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
                    let _ = stream.write_all(
                        b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                    );
                    // We don't care about the response body, just that the
                    // connection didn't get RST before we sent the request.
                    let mut buf = [0u8; 64];
                    let _ = stream.read(&mut buf);
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
    unsafe {
        libc::kill(new_child_pid, libc::SIGTERM);
    }

    // Reap the parent (it should have exited after the drain).
    let _ = parent.wait();
}
