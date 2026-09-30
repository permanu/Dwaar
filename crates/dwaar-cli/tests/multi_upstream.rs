// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Admin-API multi-upstream routes (signed-plan §14.7, D-033).
//!
//! A route posted with only `upstream` keeps the single-backend path. A
//! non-empty `upstreams` list is the backend set, load-balanced by the
//! existing pool, skipping any backend the health check has marked down.
//! Webhook routes stay one loopback upstream. An on-disk file without
//! `upstreams` still serves.

#![cfg(unix)]
#![allow(unsafe_code, clippy::cast_possible_wrap)]

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

static SERIAL: Mutex<()> = Mutex::new(());

struct Dwaar {
    child: Child,
    http_port: u16,
    admin: PathBuf,
}

impl Dwaar {
    fn stop(&mut self) {
        unsafe {
            libc::kill(self.child.id() as i32, libc::SIGTERM);
        }
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(30) {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

impl Drop for Dwaar {
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            self.stop();
        }
    }
}

struct Backend {
    addr: String,
    body: &'static str,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Backend {
    fn start(body: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
        let addr = listener.local_addr().expect("addr").to_string();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let thread = thread::spawn(move || serve(&listener, body, &stop_flag));
        Self {
            addr,
            body,
            stop,
            thread: Some(thread),
        }
    }

    fn close(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        self.close();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve(listener: &TcpListener, body: &'static str, stop: &AtomicBool) {
    listener.set_nonblocking(true).expect("nonblocking");
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
                let mut buf = [0u8; 8192];
                let read = stream.read(&mut buf).unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..read]);
                if body == "protected"
                    && (!request.starts_with("GET /ready ")
                        || !request.contains("Host: lb.example.com\r\n"))
                {
                    let _ = stream.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                } else {
                    let _ = stream.write_all(response.as_bytes());
                }
                let _ = stream.shutdown(Shutdown::Both);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(_) => break,
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

fn start_dwaar(dir: &Path, prepare: impl FnOnce(&Path)) -> Dwaar {
    let config = dir.join("Dwaarfile");
    let http_port = free_port();
    let tls_port = free_port();
    std::fs::write(
        &config,
        format!("{{\n    http_port {http_port}\n    https_port {tls_port}\n}}\n"),
    )
    .expect("write Dwaarfile");
    let admin = dir.join("admin.sock");
    let state = dir.join("state");
    std::fs::create_dir_all(&state).expect("state dir");
    prepare(&state);

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
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start dwaar");

    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(15) {
        if child.try_wait().ok().flatten().is_some() {
            let _ = child.wait();
            panic!("dwaar exited before it was ready");
        }
        if TcpStream::connect(("127.0.0.1", http_port)).is_ok()
            && UnixStream::connect(&admin).is_ok()
        {
            return Dwaar {
                child,
                http_port,
                admin,
            };
        }
        thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("dwaar did not come up on 127.0.0.1:{http_port}");
}

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

fn proxy_get(port: u16, host: &str, path: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect proxy");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    )
    .expect("write proxy request");
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

fn post_route(admin: &Path, body: &str) -> (u16, String) {
    admin_request(admin, "POST", "/routes", body)
}

fn state_text(dir: &Path) -> String {
    let path = dir.join("state").join("admin-routes.json");
    std::fs::read_to_string(&path).unwrap_or_default()
}

#[test]
fn single_upstream_still_proxies() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = tempfile::tempdir().expect("tempdir");
    let backend = Backend::start("backend-a");
    let dwaar = start_dwaar(dir.path(), |_| {});
    let (status, reply) = post_route(
        &dwaar.admin,
        &format!(
            r#"{{"domain":"only.example.com","upstream":"{}","tls":false}}"#,
            backend.addr
        ),
    );
    assert_eq!(status, 201, "{reply}");
    let (status, body) = proxy_get(dwaar.http_port, "only.example.com", "/hit");
    assert_eq!(status, 200, "{body}");
    assert!(
        body.contains(backend.body),
        "single upstream was not proxied: {body}"
    );
}

#[test]
fn two_upstreams_receive_successive_requests() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = tempfile::tempdir().expect("tempdir");
    let a = Backend::start("backend-a");
    let b = Backend::start("backend-b");
    let dwaar = start_dwaar(dir.path(), |_| {});
    let (status, reply) = post_route(
        &dwaar.admin,
        &format!(
            r#"{{"domain":"lb.example.com","upstream":"{}","upstreams":["{}","{}"],"tls":false}}"#,
            a.addr, a.addr, b.addr
        ),
    );
    assert_eq!(status, 201, "{reply}");

    let mut seen = Vec::new();
    for _ in 0..2 {
        let (status, body) = proxy_get(dwaar.http_port, "lb.example.com", "/hit");
        assert_eq!(status, 200, "{body}");
        seen.push(body);
    }
    assert!(
        seen.iter().any(|body| body.contains(a.body))
            && seen.iter().any(|body| body.contains(b.body)),
        "successive requests did not reach both upstreams: {seen:?}"
    );
}

#[test]
fn unhealthy_upstream_is_skipped() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = tempfile::tempdir().expect("tempdir");
    let a = Backend::start("backend-a");
    let b = Backend::start("backend-b");
    let dwaar = start_dwaar(dir.path(), |_| {});
    let (status, reply) = post_route(
        &dwaar.admin,
        &format!(
            r#"{{"domain":"lb.example.com","upstream":"{}","upstreams":["{}","{}"],"tls":false,"healthcheck":{{"path":"/","host":"lb.example.com","interval_seconds":1,"timeout_seconds":2}}}}"#,
            a.addr, a.addr, b.addr
        ),
    );
    assert_eq!(status, 201, "{reply}");
    b.close();

    let start = Instant::now();
    let mut last = String::new();
    let marked = loop {
        let (status, body) = admin_request(&dwaar.admin, "GET", "/routes", "");
        assert_eq!(status, 200, "{body}");
        let down = serde_json::from_str::<Vec<serde_json::Value>>(&body)
            .ok()
            .and_then(|routes| {
                routes
                    .into_iter()
                    .find(|route| route["domain"] == "lb.example.com")
            })
            .and_then(|route| {
                route["state"]["upstreams"]
                    .as_array()
                    .and_then(|upstreams| {
                        upstreams
                            .iter()
                            .find(|upstream| upstream["upstream"] == b.addr)
                            .map(|upstream| upstream["healthy"] == serde_json::Value::Bool(false))
                    })
            })
            .unwrap_or(false);
        if down {
            break true;
        }
        last = body;
        if start.elapsed() > Duration::from_secs(20) {
            break false;
        }
        // The admin API allows 60 requests per minute, and the checker
        // may sleep for up to 10s before its first probe.
        thread::sleep(Duration::from_secs(1));
    };
    assert!(marked, "closed backend was not marked unhealthy:\n{last}");

    for _ in 0..4 {
        let (status, body) = proxy_get(dwaar.http_port, "lb.example.com", "/hit");
        assert_eq!(status, 200, "{body}");
        assert!(
            body.contains(a.body) && !body.contains(b.body),
            "request did not stay on the healthy upstream: {body}"
        );
    }
}

#[test]
fn webhook_with_two_upstreams_is_rejected_and_not_persisted() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = tempfile::tempdir().expect("tempdir");
    let backend = Backend::start("backend-a");
    let dwaar = start_dwaar(dir.path(), |_| {});
    let (status, reply) = post_route(
        &dwaar.admin,
        &format!(
            r#"{{"domain":"kept.example.com","upstream":"{}","tls":false}}"#,
            backend.addr
        ),
    );
    assert_eq!(status, 201, "{reply}");

    let (status, reply) = post_route(
        &dwaar.admin,
        r#"{"domain":"hooks.example.com","upstream":"127.0.0.1:7461","tls":false,"kind":"webhook","upstreams":["127.0.0.1:7461","127.0.0.1:7462"]}"#,
    );
    assert_eq!(status, 400, "{reply}");
    let stored = state_text(dir.path());
    assert!(
        stored.contains("kept.example.com"),
        "existing route was dropped: {stored}"
    );
    assert!(
        !stored.contains("hooks.example.com"),
        "rejected webhook was persisted: {stored}"
    );
    let (status, listed) = admin_request(&dwaar.admin, "GET", "/routes", "");
    assert_eq!(status, 200, "{listed}");
    assert!(!listed.contains("hooks.example.com"), "{listed}");
}

#[test]
fn old_admin_routes_file_still_serves_its_upstream() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = tempfile::tempdir().expect("tempdir");
    let backend = Backend::start("backend-a");
    let addr = backend.addr.clone();
    let dwaar = start_dwaar(dir.path(), |state| {
        let file = serde_json::json!({
            "version": 1,
            "routes": [{
                "domain": "legacy.example.com",
                "upstream": addr,
                "tls": false,
                "source": "permanu-runner"
            }]
        });
        std::fs::write(
            state.join("admin-routes.json"),
            serde_json::to_string_pretty(&file).expect("json"),
        )
        .expect("write old admin routes");
    });
    let (status, body) = proxy_get(dwaar.http_port, "legacy.example.com", "/hit");
    assert_eq!(status, 200, "{body}");
    assert!(
        body.contains(backend.body),
        "old admin route did not proxy to its single upstream: {body}"
    );
}

#[test]
fn upstream_missing_from_upstreams_is_rejected_and_not_persisted() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = tempfile::tempdir().expect("tempdir");
    let dwaar = start_dwaar(dir.path(), |_| {});
    let (status, reply) = post_route(
        &dwaar.admin,
        r#"{"domain":"lb.example.com","upstream":"127.0.0.1:9","upstreams":["127.0.0.1:10","127.0.0.1:11"],"tls":false}"#,
    );
    assert_eq!(status, 400, "{reply}");
    let stored = state_text(dir.path());
    assert!(
        !stored.contains("lb.example.com"),
        "rejected route was persisted: {stored}"
    );
}

#[test]
fn explicit_ready_path_keeps_protected_root_backends_healthy() {
    let _serial = SERIAL.lock().expect("serial");
    let dir = tempfile::tempdir().expect("tempdir");
    let first = Backend::start("protected");
    let second = Backend::start("protected");
    let dwaar = start_dwaar(dir.path(), |_| {});
    let body=serde_json::json!({"domain":"lb.example.com","upstream":first.addr,"upstreams":[first.addr,second.addr],"tls":false,"healthcheck":{"path":"/ready","host":"lb.example.com","interval_seconds":1,"timeout_seconds":2}}).to_string();
    let (status, _) = admin_request(&dwaar.admin, "POST", "/routes", &body);
    assert_eq!(status, 201);
    thread::sleep(Duration::from_secs(12));
    for _ in 0..4 {
        assert_eq!(
            proxy_get(dwaar.http_port, "lb.example.com", "/ready").0,
            200
        );
    }
    assert_eq!(proxy_get(dwaar.http_port, "lb.example.com", "/").0, 401);
}
