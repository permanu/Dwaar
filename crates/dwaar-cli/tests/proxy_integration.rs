// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Integration tests for the proxy forwarding pipeline (ISSUE-005).
//!
//! Proves that Dwaar accepts HTTP requests, forwards them to an upstream,
//! and returns the upstream's response to the client.
//!
//! ## Port constraints (ISSUE-005 only)
//!
//! The upstream is hardcoded at 127.0.0.1:8080. Tests run sequentially
//! because they share this port. ISSUE-010 (configurable routes) will
//! allow ephemeral ports and parallel execution.

// Test-only: we need unsafe for libc::kill and u32→i32 cast for PID
#![allow(unsafe_code, clippy::cast_possible_wrap)]

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

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
/// the given status and body. This is a complete HTTP server in ~20 lines.
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

/// Send a GET request through the proxy (blocking) and return (status, body).
fn send_through_proxy(path: &str) -> (u16, String) {
    let url = format!("http://127.0.0.1:6188{path}");

    // Use reqwest's blocking client — no async runtime needed.
    // We build a one-off runtime just for this request.
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
        let body = resp.text().await.expect("read body");
        (status, body)
    })
}

/// Core proxy integration test: verifies that Dwaar forwards HTTP requests
/// to the upstream and returns the upstream's response unchanged.
///
/// Tests 200, 404, and 500 sequentially. All three must pass — a proxy
/// must faithfully forward any status code from the upstream.
#[test]
fn proxy_forwards_upstream_responses() {
    let upstream =
        TcpListener::bind("127.0.0.1:8080").expect("bind to 127.0.0.1:8080 for mock upstream");

    let child = start_dwaar_proxy();

    // --- Test 200 OK ---
    let handle = thread::spawn({
        let upstream_fd = upstream.try_clone().expect("clone listener");
        move || serve_one_request(&upstream_fd, 200, "hello from upstream")
    });
    let (status, body) = send_through_proxy("/");
    handle.join().expect("upstream thread");
    assert_eq!(status, 200, "proxy should forward 200 status");
    assert_eq!(body, "hello from upstream");

    // --- Test 404 Not Found ---
    let handle = thread::spawn({
        let upstream_fd = upstream.try_clone().expect("clone listener");
        move || serve_one_request(&upstream_fd, 404, "page not found")
    });
    let (status, body) = send_through_proxy("/missing");
    handle.join().expect("upstream thread");
    assert_eq!(status, 404, "proxy should forward 404 status");
    assert_eq!(body, "page not found");

    // --- Test 500 Internal Server Error ---
    let handle = thread::spawn({
        let upstream_fd = upstream.try_clone().expect("clone listener");
        move || serve_one_request(&upstream_fd, 500, "server error")
    });
    let (status, body) = send_through_proxy("/error");
    handle.join().expect("upstream thread");
    assert_eq!(status, 500, "proxy should forward 500 status");
    assert_eq!(body, "server error");

    stop_dwaar(child);
}
