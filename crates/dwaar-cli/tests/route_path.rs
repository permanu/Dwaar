// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! End-to-end test of the `route_path` label (contracts v1.1.3, D-061).
//!
//! Starts the real binary with an admin socket, installs a proxy route
//! through `POST /routes`, sends requests whose paths carry ids, and checks
//! that the access log line and `GET /metrics` carry the path template
//! (`/api/users/:id/orders`), not the raw path.
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

const APP_HOST: &str = "app.permanu.test";

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

/// GET `path` on the proxy for `APP_HOST`; returns the response status.
fn get(port: u16, path: &str) -> u16 {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect proxy");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {APP_HOST}\r\nConnection: close\r\n\r\n"
    )
    .expect("write request");
    let mut status_line = String::new();
    BufReader::new(stream).read_line(&mut status_line).ok();
    status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// Answer every connection with an empty 200 until the test ends.
fn serve_ok(listener: TcpListener) {
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .ok();
            stream.shutdown(Shutdown::Both).ok();
        }
    });
}

#[test]
fn access_log_and_metrics_carry_the_route_path_template() {
    let dir = tempfile::tempdir().expect("tempdir");
    let dwaar = start_dwaar(dir.path());

    let upstream = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
    let upstream_addr = upstream.local_addr().expect("addr");
    serve_ok(upstream);

    let (status, body) = admin_request(
        &dwaar.admin,
        "POST",
        "/routes",
        &format!(r#"{{"domain":"{APP_HOST}","upstream":"{upstream_addr}","tls":false}}"#),
    );
    assert_eq!(status, 201, "{body}");

    assert_eq!(get(dwaar.port, "/api/Users/42/orders?token=secret"), 200);
    assert_eq!(
        get(
            dwaar.port,
            "/api/users/3f2504e0-4f89-11d3-9a0c-0305e82c3301/orders"
        ),
        200
    );

    // The access log carries the template next to the raw path.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut entries = Vec::new();
    while entries.len() < 2 && Instant::now() < deadline {
        if let Ok(line) = dwaar.stdout.recv_timeout(Duration::from_millis(200))
            && let Ok(v) = serde_json::from_str::<serde_json::Value>(&line)
            && v["host"] == APP_HOST
        {
            entries.push(v);
        }
    }
    assert_eq!(entries.len(), 2, "access log lines: {entries:?}");
    assert_eq!(entries[0]["path"], "/api/Users/42/orders");
    for entry in &entries {
        assert_eq!(entry["route"], APP_HOST);
        assert_eq!(entry["route_path"], "/api/users/:id/orders", "{entry}");
    }

    // Both requests land in one low-cardinality series.
    let (status, metrics) = admin_request(&dwaar.admin, "GET", "/metrics", "");
    assert_eq!(status, 200);
    assert!(
        metrics.contains(&format!(
            "dwaar_route_path_requests_total{{route=\"{APP_HOST}\",route_path=\"/api/users/:id/orders\",status_class=\"2xx\"}} 2"
        )),
        "{metrics}"
    );
    assert!(
        metrics.contains(&format!(
            "dwaar_route_path_request_duration_seconds_count{{route=\"{APP_HOST}\",route_path=\"/api/users/:id/orders\"}} 2"
        )),
        "{metrics}"
    );
    assert!(!metrics.contains("secret"));
    assert!(!metrics.contains("/42/"));
}
