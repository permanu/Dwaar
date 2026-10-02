// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! End-to-end checks of admin-API routes on a Permanu server (`QA_M2` F16).
//!
//! Starts the real binary the way `dwaar.service` does — a Dwaarfile with
//! only global options, an admin socket and a state directory — and checks
//! that the TLS listener is up although no Dwaarfile site uses TLS, that
//! routes added through the admin API come back after a restart, that the
//! ACME service runs for them, and that a graceful stop takes under 10 s.
//!
//! The tests share the fixed admin TCP port, so they run one at a time.

#![cfg(unix)]
// Test-only: libc::kill needs unsafe and a u32 → i32 PID cast.
#![allow(unsafe_code, clippy::cast_possible_wrap)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

static SERIAL: Mutex<()> = Mutex::new(());

struct Dwaar {
    child: Child,
    http_port: u16,
    tls_port: u16,
    admin: PathBuf,
    logs: mpsc::Receiver<String>,
}

impl Dwaar {
    /// SIGTERM the PID this test started; returns how long it took to exit.
    fn stop(&mut self) -> Duration {
        let start = Instant::now();
        unsafe {
            libc::kill(self.child.id() as i32, libc::SIGTERM);
        }
        while start.elapsed() < Duration::from_secs(90) {
            if let Ok(Some(_)) = self.child.try_wait() {
                return start.elapsed();
            }
            thread::sleep(Duration::from_millis(50));
        }
        self.child.kill().ok();
        self.child.wait().ok();
        start.elapsed()
    }

    /// Log lines (stdout and stderr) seen so far.
    fn drain_logs(&self) -> Vec<String> {
        self.logs.try_iter().collect()
    }
}

impl Drop for Dwaar {
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            self.stop();
        }
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral")
        .local_addr()
        .expect("local addr")
        .port()
}

/// Start Dwaar with a Dwaarfile of global options only (like the Permanu
/// installer's `{ http_port 80 }`) on ephemeral ports.
fn start_dwaar(dir: &Path, http_port: u16, tls_port: u16) -> Dwaar {
    let config = dir.join("Dwaarfile");
    std::fs::write(
        &config,
        format!("{{\n    http_port {http_port}\n    https_port {tls_port}\n}}\n"),
    )
    .expect("write Dwaarfile");
    let admin = dir.join("admin.sock");
    let state = dir.join("state");
    std::fs::create_dir_all(&state).expect("state dir");

    let mut child = Command::new(env!("CARGO_BIN_EXE_dwaar"))
        .arg("--config")
        .arg(&config)
        .arg("--admin-socket")
        .arg(&admin)
        .arg("--state-dir")
        .arg(&state)
        .args([
            "--grpc-addr=",
            "--no-analytics",
            "--no-geoip",
            "--workers",
            "1",
        ])
        .env("RUST_LOG", "info")
        .current_dir(dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start dwaar");

    let (tx, rx) = mpsc::channel();
    for pipe in [
        Box::new(child.stdout.take().expect("stdout")) as Box<dyn Read + Send>,
        Box::new(child.stderr.take().expect("stderr")),
    ] {
        let tx = tx.clone();
        thread::spawn(move || {
            for line in BufReader::new(pipe).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
    }

    let dwaar = Dwaar {
        child,
        http_port,
        tls_port,
        admin,
        logs: rx,
    };
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(15) {
        if TcpStream::connect(("127.0.0.1", http_port)).is_ok()
            && UnixStream::connect(&dwaar.admin).is_ok()
        {
            return dwaar;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("dwaar did not come up on 127.0.0.1:{http_port}");
}

/// One HTTP/1.1 request over the admin Unix socket; returns (status, body).
fn admin_request(socket: &Path, method: &str, path: &str, body: &str) -> (u16, String) {
    let mut stream = UnixStream::connect(socket).expect("connect admin socket");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .expect("write admin request");
    let mut raw = String::new();
    stream.read_to_string(&mut raw).ok();
    let status = raw
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = raw
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_owned())
        .unwrap_or_default();
    (status, body)
}

/// Send a request to the proxy and return the response status.
fn send(port: u16, head: &str) -> u16 {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect proxy");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    stream.write_all(head.as_bytes()).expect("write head");
    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line).ok();
    status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// Accept one connection, capture the request head, answer 202.
fn capture_one(listener: TcpListener) -> thread::JoinHandle<String> {
    thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept upstream");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        let mut reader = BufReader::new(stream.try_clone().expect("clone"));
        let mut head = String::new();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                break;
            }
            head.push_str(&line);
        }
        let mut stream = stream;
        stream
            .write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .expect("respond");
        stream.shutdown(Shutdown::Both).ok();
        head
    })
}

#[test]
fn tls_listener_is_up_without_tls_sites_and_acme_runs_for_admin_routes() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = tempfile::tempdir().expect("tempdir");
    let dwaar = start_dwaar(dir.path(), free_port(), free_port());

    // Admin-API TLS routes arrive at runtime; the listener must already exist.
    assert!(
        TcpStream::connect(("127.0.0.1", dwaar.tls_port)).is_ok(),
        "no TLS listener on {}",
        dwaar.tls_port
    );
    let logs = dwaar.drain_logs().join("\n");
    assert!(
        logs.contains("TLS background service registered"),
        "ACME service not started for admin-API routes:\n{logs}"
    );
}

#[test]
fn admin_routes_are_restored_after_a_restart() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = tempfile::tempdir().expect("tempdir");
    let (http_port, tls_port) = (free_port(), free_port());
    let mut dwaar = start_dwaar(dir.path(), http_port, tls_port);

    let upstream = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
    let upstream_addr = upstream.local_addr().expect("addr");
    for body in [
        r#"{"domain":"web-prod-shop.203-0-113-5.sslip.test","upstream":"127.0.0.1:9","tls":true,"source":"permanu-runner"}"#.to_owned(),
        format!(
            r#"{{"domain":"203.0.113.5","upstream":"{upstream_addr}","tls":false,"source":"permanu-runner","kind":"webhook"}}"#
        ),
    ] {
        let (status, reply) = admin_request(&dwaar.admin, "POST", "/routes", &body);
        assert_eq!(status, 201, "{reply}");
    }
    let state_file = dir.path().join("state").join("admin-routes.json");
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&state_file)
            .expect("admin routes persisted")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    dwaar.stop();
    drop(dwaar);

    let dwaar = start_dwaar(dir.path(), http_port, tls_port);
    let (status, listed) = admin_request(&dwaar.admin, "GET", "/routes", "");
    assert_eq!(status, 200);
    let routes: Vec<serde_json::Value> = serde_json::from_str(&listed).expect("routes JSON");
    let find = |domain: &str| {
        routes
            .iter()
            .find(|r| r["domain"] == domain)
            .unwrap_or_else(|| panic!("{domain} not restored: {listed}"))
            .clone()
    };
    let app = find("web-prod-shop.203-0-113-5.sslip.test");
    assert_eq!(app["tls"], true);
    let hook = find("203.0.113.5");
    assert_eq!(hook["kind"], "webhook");
    assert_eq!(hook["tls"], false);

    // The restored IP-only webhook route serves plain HTTP (D-063 #4).
    let captured = capture_one(upstream);
    let status = send(
        dwaar.http_port,
        "POST /hooks/prj_1 HTTP/1.1\r\nHost: 203.0.113.5\r\nContent-Length: 0\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(status, 202);
    let head = captured.join().expect("upstream thread");
    assert!(head.starts_with("POST /hooks/prj_1 HTTP/1.1\r\n"), "{head}");

    // A deleted admin route stays deleted after the next restart.
    let (status, _) = admin_request(&dwaar.admin, "DELETE", "/routes/203.0.113.5", "");
    assert_eq!(status, 200);
    let restored = std::fs::read_to_string(&state_file).expect("state");
    assert!(!restored.contains("203.0.113.5"), "{restored}");
}

#[test]
fn graceful_stop_takes_under_ten_seconds() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut dwaar = start_dwaar(dir.path(), free_port(), free_port());
    let took = dwaar.stop();
    assert!(
        took < Duration::from_secs(10),
        "graceful stop took {took:?}"
    );
}

#[test]
fn signed_replica_health_and_conditional_deletion_cross_the_admin_socket() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = tempfile::tempdir().expect("private fixture");
    let dwaar = start_dwaar(dir.path(), free_port(), free_port());
    let mut probes = Vec::new();
    let mut addresses = Vec::new();
    for _ in 0..2 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("owned health listener");
        addresses.push(listener.local_addr().expect("health address").to_string());
        listener
            .set_nonblocking(true)
            .expect("nonblocking health listener");
        probes.push(thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            while Instant::now() < deadline {
                if let Ok((mut stream, _)) = listener.accept() {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .expect("health read bound");
                    stream
                        .set_write_timeout(Some(Duration::from_secs(2)))
                        .expect("health write bound");
                    let mut request = [0; 4096];
                    let Ok(count) = stream.read(&mut request) else {
                        continue;
                    };
                    if count == 0 {
                        continue;
                    }
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .expect("health response");
                    return String::from_utf8_lossy(&request[..count]).into_owned();
                }
                thread::sleep(Duration::from_millis(20));
            }
            panic!("signed health policy never reached the owned upstream");
        }));
    }
    let health = serde_json::json!({"path":"/ready/signed","host":"health.example.test","port":null,"interval_seconds":1,"timeout_seconds":1});
    let body = serde_json::json!({"domain":"replica.example.test","upstream":addresses[0],"upstreams":addresses,"tls":false,"source":"permanu-runner","healthcheck":health}).to_string();
    let (status, reply) = admin_request(&dwaar.admin, "POST", "/routes", &body);
    assert_eq!(status, 201, "{reply}");
    for probe in probes {
        let request = probe.join().expect("owned health observer");
        assert!(
            request.starts_with("GET /ready/signed HTTP/1.1\r\n"),
            "{request}"
        );
        assert!(
            request
                .to_ascii_lowercase()
                .contains("host: health.example.test\r\n"),
            "{request}"
        );
    }
    let state_file = dir.path().join("state/admin-routes.json");
    let persisted: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&state_file).expect("persisted routes"))
            .expect("route JSON");
    assert_eq!(persisted["routes"][0]["healthcheck"], health);
    for (source, upstream) in [
        ("another-owner", addresses[0].as_str()),
        ("permanu-runner", "127.0.0.1:9"),
    ] {
        let deletion = serde_json::json!({"domain":"replica.example.test","source":source,"upstream":upstream}).to_string();
        assert_eq!(
            admin_request(&dwaar.admin, "POST", "/routes/delete-if", &deletion).0,
            200
        );
        let (status, listed) = admin_request(&dwaar.admin, "GET", "/routes", "");
        assert_eq!(status, 200);
        let routes: Vec<serde_json::Value> = serde_json::from_str(&listed).expect("listed routes");
        assert!(
            routes
                .iter()
                .any(|route| route["domain"] == "replica.example.test")
        );
    }
    let deletion = serde_json::json!({"domain":"replica.example.test","source":"permanu-runner","upstream":addresses[0]}).to_string();
    assert_eq!(
        admin_request(&dwaar.admin, "POST", "/routes/delete-if", &deletion).0,
        200
    );
    let (_, listed) = admin_request(&dwaar.admin, "GET", "/routes", "");
    let routes: Vec<serde_json::Value> = serde_json::from_str(&listed).expect("listed routes");
    assert!(
        !routes
            .iter()
            .any(|route| route["domain"] == "replica.example.test")
    );
}
