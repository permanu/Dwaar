// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! End-to-end test of the webhook intake route (Permanu agent-protocol §11.1).
//!
//! Starts the real binary with an admin socket and a state directory,
//! installs a `kind: webhook` route through `POST /routes`, and checks what a
//! sender on the public listener can and cannot reach: `/hooks/*` reaches the
//! loopback upstream with the body and provider headers intact and a
//! Dwaar-owned `X-Real-IP`; a body over 1 MiB is refused with 413 even when the
//! sender claims gRPC; other paths are 404; the access log names the route.
//!
//! Every port is ephemeral, so this runs alongside the other suites.

#![cfg(unix)]
// Test-only: libc::kill needs unsafe and a u32 → i32 PID cast.
#![allow(unsafe_code, clippy::cast_possible_wrap)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const WEBHOOK_HOST: &str = "hooks.permanu.test";
const ONE_MIB: usize = 1024 * 1024;

struct Dwaar {
    child: Child,
    port: u16,
    admin: PathBuf,
    stdout: mpsc::Receiver<String>,
}

impl Drop for Dwaar {
    fn drop(&mut self) {
        // SIGTERM the PID this test started, then reap it.
        unsafe {
            libc::kill(self.child.id() as i32, libc::SIGTERM);
        }
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(15) {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral")
        .local_addr()
        .expect("local addr")
        .port()
}

fn start_dwaar(dir: &Path) -> Dwaar {
    let port = free_port();
    let config = dir.join("Dwaarfile");
    std::fs::write(
        &config,
        format!("127.0.0.1 {{\n    bind 127.0.0.1:{port}\n    reverse_proxy 127.0.0.1:9\n}}\n"),
    )
    .expect("write Dwaarfile");
    let admin = dir.join("admin.sock");
    let state = dir.join("state");

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
        .current_dir(dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("start dwaar");

    let (tx, rx) = mpsc::channel();
    let stdout = child.stdout.take().expect("stdout");
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });

    let dwaar = Dwaar {
        child,
        port,
        admin,
        stdout: rx,
    };
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(15) {
        let listening = TcpStream::connect(("127.0.0.1", port)).is_ok();
        if listening && UnixStream::connect(&dwaar.admin).is_ok() {
            return dwaar;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!(
        "dwaar did not come up on 127.0.0.1:{port} and {}",
        dwaar.admin.display()
    );
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

/// Send raw request bytes to the proxy and return the response status.
fn send(port: u16, head: &str, body: &[u8]) -> u16 {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect proxy");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    stream.write_all(head.as_bytes()).expect("write head");
    // The proxy may answer 413 and close before the body is sent.
    let _ = stream.write_all(body);
    let _ = stream.flush();
    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line).ok();
    status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// Accept one connection, capture the request head and body, answer 202.
fn capture_one(listener: TcpListener) -> thread::JoinHandle<(String, Vec<u8>)> {
    thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept upstream");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        let mut reader = BufReader::new(stream.try_clone().expect("clone"));
        let mut head = String::new();
        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                break;
            }
            if let Some((name, value)) = line.split_once(':')
                && name.eq_ignore_ascii_case("content-length")
            {
                content_length = value.trim().parse().unwrap_or(0);
            }
            head.push_str(&line);
        }
        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body).expect("read body");
        let mut stream = stream;
        stream
            .write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .expect("respond");
        stream.shutdown(Shutdown::Both).ok();
        (head, body)
    })
}

fn header<'a>(head: &'a str, name: &str) -> Vec<&'a str> {
    head.lines()
        .filter_map(|line| line.split_once(':'))
        .filter(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim())
        .collect()
}

#[test]
fn webhook_route_forwards_hooks_and_enforces_its_limits() {
    let dir = tempfile::tempdir().expect("tempdir");
    let dwaar = start_dwaar(dir.path());

    let upstream = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
    let upstream_addr = upstream.local_addr().expect("addr");

    // A non-loopback upstream is refused for a webhook route.
    let (status, _) = admin_request(
        &dwaar.admin,
        "POST",
        "/routes",
        &format!(
            r#"{{"domain":"{WEBHOOK_HOST}","upstream":"192.0.2.10:7461","tls":false,"kind":"webhook"}}"#
        ),
    );
    assert_eq!(status, 400);

    let (status, body) = admin_request(
        &dwaar.admin,
        "POST",
        "/routes",
        &format!(
            r#"{{"domain":"{WEBHOOK_HOST}","upstream":"{upstream_addr}","tls":false,"source":"permanu","kind":"webhook"}}"#
        ),
    );
    assert_eq!(status, 201, "{body}");
    let (_, listed) = admin_request(&dwaar.admin, "GET", "/routes", "");
    assert!(listed.contains(r#""kind":"webhook""#), "{listed}");

    // 1. A signed push reaches the upstream unchanged, with Dwaar's X-Real-IP.
    let captured = capture_one(upstream);
    let payload = br#"{"ref":"refs/heads/main"}"#;
    let status = send(
        dwaar.port,
        &format!(
            "POST /hooks/prj_01H?x=1 HTTP/1.1\r\nHost: {WEBHOOK_HOST}\r\n\
             X-GitHub-Event: push\r\nX-Hub-Signature-256: sha256=abc\r\n\
             X-Real-IP: 6.6.6.6\r\nX-Forwarded-For: 6.6.6.6\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n",
            payload.len()
        ),
        payload,
    );
    assert_eq!(status, 202);
    let (head, body) = captured.join().expect("upstream thread");
    assert!(
        head.starts_with("POST /hooks/prj_01H?x=1 HTTP/1.1\r\n"),
        "{head}"
    );
    assert_eq!(body, payload);
    assert_eq!(header(&head, "x-real-ip"), ["127.0.0.1"]);
    assert_eq!(header(&head, "x-forwarded-for"), ["127.0.0.1"]);
    assert_eq!(header(&head, "x-github-event"), ["push"]);
    assert_eq!(header(&head, "x-hub-signature-256"), ["sha256=abc"]);

    // 2. Over 1 MiB → 413, also when the sender claims gRPC (the upstream
    //    listener is closed now, so anything forwarded would be a 502).
    for content_type in ["application/json", "application/grpc"] {
        let status = send(
            dwaar.port,
            &format!(
                "POST /hooks/prj_01H HTTP/1.1\r\nHost: {WEBHOOK_HOST}\r\n\
                 Content-Type: {content_type}\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n",
                ONE_MIB + 1
            ),
            &[],
        );
        assert_eq!(status, 413, "{content_type}");
    }

    // 3. Nothing but /hooks/ is served on the webhook host.
    for path in ["/", "/hooks", "/admin", "/metrics"] {
        let status = send(
            dwaar.port,
            &format!("GET {path} HTTP/1.1\r\nHost: {WEBHOOK_HOST}\r\nConnection: close\r\n\r\n"),
            &[],
        );
        assert_eq!(status, 404, "{path}");
    }

    // 4. The access log names the matched route and has what the agent's
    //    DWAAR/http ingestion reads.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut found = None;
    while found.is_none() && Instant::now() < deadline {
        if let Ok(line) = dwaar.stdout.recv_timeout(Duration::from_millis(200))
            && let Ok(v) = serde_json::from_str::<serde_json::Value>(&line)
            && v["path"] == "/hooks/prj_01H"
            && v["status"] == 202
        {
            found = Some(v);
        }
    }
    let entry = found.expect("access log line for the forwarded push");
    assert_eq!(entry["route"], WEBHOOK_HOST);
    assert_eq!(entry["host"], WEBHOOK_HOST);
    assert_eq!(entry["method"], "POST");
    for field in [
        "timestamp",
        "response_time_us",
        "bytes_sent",
        "client_ip",
        "request_id",
    ] {
        assert!(entry.get(field).is_some(), "missing {field}: {entry}");
    }
}
