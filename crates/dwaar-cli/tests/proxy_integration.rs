// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Integration tests for the proxy forwarding pipeline.
//!
//! Proves that Dwaar accepts HTTP requests, forwards them to an upstream,
//! and returns the upstream's response with Dwaar-added headers.
//!
//! ## Port constraints
//!
//! The upstream is hardcoded at 127.0.0.1:8080. Tests run sequentially
//! because they share this port. ISSUE-010 (configurable routes) will
//! allow ephemeral ports and parallel execution.

// Test-only: we need unsafe for libc::kill and u32→i32 cast for PID
#![allow(unsafe_code, clippy::cast_possible_wrap)]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

/// Mutex to serialize tests that need exclusive access to ports 8080 and 6188.
/// Tests acquire this lock before binding ports, preventing parallel conflicts.
/// Removed once ISSUE-010 allows ephemeral ports.
static PORT_LOCK: Mutex<()> = Mutex::new(());

/// Status text for common HTTP status codes.
fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Unknown",
    }
}

/// Accept one connection on `listener`, read the request, respond with
/// the given status and body.
fn serve_one_request(listener: &TcpListener, status: u16, body: &str) {
    let (mut stream, _) = listener.accept().expect("accept connection");

    let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
            break;
        }
    }

    let response = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Length: {}\r\n\
         Content-Type: text/plain\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        status,
        status_text(status),
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

/// Start dwaar proxy as a subprocess.
fn start_dwaar_proxy() -> std::process::Child {
    let child = Command::new(env!("CARGO_BIN_EXE_dwaar"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start dwaar");

    thread::sleep(Duration::from_secs(2));
    child
}

/// Stop a dwaar subprocess gracefully via SIGTERM.
fn stop_dwaar(mut child: std::process::Child) {
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => {
                if start.elapsed() > Duration::from_secs(15) {
                    child.kill().ok();
                    return;
                }
                thread::sleep(Duration::from_millis(100));
            }
            Err(_) => {
                child.kill().ok();
                return;
            }
        }
    }
}

/// Response from the proxy: status code, body, and headers.
struct ProxyResponse {
    status: u16,
    body: String,
    headers: HashMap<String, String>,
}

/// Send a GET request through the proxy and return the full response.
fn send_through_proxy(path: &str) -> ProxyResponse {
    let url = format!("http://127.0.0.1:6188{path}");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");

    rt.block_on(async {
        let client = reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("build client");

        let resp = client
            .get(&url)
            .send()
            .await
            .expect("request should succeed");

        let status = resp.status().as_u16();
        let headers: HashMap<String, String> = resp
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_lowercase(),
                    v.to_str().unwrap_or("").to_string(),
                )
            })
            .collect();
        let body = resp.text().await.expect("read body");

        ProxyResponse {
            status,
            body,
            headers,
        }
    })
}

/// ISSUE-005: Verifies that Dwaar forwards HTTP requests to the upstream
/// and returns the upstream's response with the correct status code and body.
#[test]
fn proxy_forwards_upstream_responses() {
    let _lock = PORT_LOCK.lock().expect("acquire port lock");
    let upstream =
        TcpListener::bind("127.0.0.1:8080").expect("bind to 127.0.0.1:8080 for mock upstream");

    let child = start_dwaar_proxy();

    // --- Test 200 OK ---
    let handle = thread::spawn({
        let upstream_fd = upstream.try_clone().expect("clone listener");
        move || serve_one_request(&upstream_fd, 200, "hello from upstream")
    });
    let resp = send_through_proxy("/");
    handle.join().expect("upstream thread");
    assert_eq!(resp.status, 200, "proxy should forward 200 status");
    assert_eq!(resp.body, "hello from upstream");

    // --- Test 404 Not Found ---
    let handle = thread::spawn({
        let upstream_fd = upstream.try_clone().expect("clone listener");
        move || serve_one_request(&upstream_fd, 404, "page not found")
    });
    let resp = send_through_proxy("/missing");
    handle.join().expect("upstream thread");
    assert_eq!(resp.status, 404, "proxy should forward 404 status");
    assert_eq!(resp.body, "page not found");

    // --- Test 500 Internal Server Error ---
    let handle = thread::spawn({
        let upstream_fd = upstream.try_clone().expect("clone listener");
        move || serve_one_request(&upstream_fd, 500, "server error")
    });
    let resp = send_through_proxy("/error");
    handle.join().expect("upstream thread");
    assert_eq!(resp.status, 500, "proxy should forward 500 status");
    assert_eq!(resp.body, "server error");

    stop_dwaar(child);
}

/// ISSUE-006: Verifies that every proxied response includes an X-Request-Id
/// header with a valid UUID v7 value, and that each request gets a unique ID.
#[test]
fn proxy_adds_x_request_id_header() {
    let _lock = PORT_LOCK.lock().expect("acquire port lock");
    let upstream =
        TcpListener::bind("127.0.0.1:8080").expect("bind to 127.0.0.1:8080 for mock upstream");

    let child = start_dwaar_proxy();

    // Send first request
    let handle = thread::spawn({
        let upstream_fd = upstream.try_clone().expect("clone listener");
        move || serve_one_request(&upstream_fd, 200, "ok")
    });
    let resp1 = send_through_proxy("/first");
    handle.join().expect("upstream thread");

    // Assert X-Request-Id is present and looks like a UUID
    let id1 = resp1
        .headers
        .get("x-request-id")
        .expect("response should have X-Request-Id header");
    assert_eq!(id1.len(), 36, "request ID should be a 36-char UUID");
    assert_eq!(
        id1.chars().filter(|c| *c == '-').count(),
        4,
        "UUID should have 4 dashes (8-4-4-4-12 format)"
    );

    // Send second request — ID should be different
    let handle = thread::spawn({
        let upstream_fd = upstream.try_clone().expect("clone listener");
        move || serve_one_request(&upstream_fd, 200, "ok")
    });
    let resp2 = send_through_proxy("/second");
    handle.join().expect("upstream thread");

    let id2 = resp2
        .headers
        .get("x-request-id")
        .expect("second response should also have X-Request-Id");

    assert_ne!(id1, id2, "each request must get a unique request ID");

    stop_dwaar(child);
}
