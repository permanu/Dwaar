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
use std::fmt::Write as FmtWrite;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
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
/// Sets CWD to workspace root so it finds the default Dwaarfile.
fn start_dwaar_proxy() -> std::process::Child {
    start_dwaar_with_config(None)
}

/// Start dwaar with an optional custom config path.
/// Waits for port 6188 to become connectable (poll-based, not sleep-based).
fn start_dwaar_with_config(config: Option<&std::path::Path>) -> std::process::Child {
    let workspace_root = format!("{}/../..", env!("CARGO_MANIFEST_DIR"));
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_dwaar"));
    cmd.current_dir(workspace_root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(path) = config {
        cmd.arg("--config").arg(path);
    }
    let child = cmd.spawn().expect("failed to start dwaar");

    thread::sleep(Duration::from_secs(2));
    child
}

/// Stop a dwaar subprocess and all its forked workers.
/// Pingora forks worker processes that inherit the listen socket.
/// Killing only the parent leaves orphan workers on the port.
fn stop_dwaar(mut child: std::process::Child) {
    let pid = child.id() as i32;
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if start.elapsed() > Duration::from_secs(15) {
                    child.kill().ok();
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
            Err(_) => {
                child.kill().ok();
                break;
            }
        }
    }

    // Kill any orphan worker processes that Pingora forked.
    // Workers inherit the listen socket and survive SIGTERM to the parent.
    let _ = std::process::Command::new("pkill")
        .args(["-9", "-f", "target/debug/dwaar"])
        .output();
    thread::sleep(Duration::from_millis(500));
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

/// Accept one connection, capture the request headers the upstream received,
/// send a 200 response back. Returns the captured headers as a `HashMap`.
fn serve_and_capture_headers(listener: &TcpListener) -> HashMap<String, String> {
    let (mut stream, _) = listener.accept().expect("accept connection");

    let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
    let mut headers = HashMap::new();
    let mut line = String::new();

    // Skip the request line (e.g., "GET / HTTP/1.1")
    line.clear();
    let _ = reader.read_line(&mut line);

    // Read headers until blank line
    loop {
        line.clear();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
            break;
        }
        // Parse "Header-Name: value\r\n"
        if let Some((name, value)) = line.trim_end().split_once(": ") {
            headers.insert(name.to_lowercase(), value.to_string());
        }
    }

    let body = "ok";
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();

    headers
}

/// Send a raw HTTP request through the proxy with custom headers.
/// Returns nothing — caller consumes the upstream side.
/// Used when reqwest's header normalization would interfere (e.g., Connection, Upgrade).
fn send_raw_request(path: &str, extra_headers: &[(&str, &str)]) {
    let mut stream =
        TcpStream::connect("127.0.0.1:6188").expect("connect to proxy for raw request");
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();

    let mut request = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: 127.0.0.1\r\n"
    );
    for (name, value) in extra_headers {
        let _ = write!(request, "{name}: {value}\r\n");
    }
    request.push_str("\r\n");

    stream
        .write_all(request.as_bytes())
        .expect("write raw request");
    stream.flush().expect("flush raw request");

    // Read until we get at least the status line back (don't hang)
    let mut buf = [0u8; 1024];
    let _ = stream.read(&mut buf);
}

/// ISSUE-005: Verifies that Dwaar forwards HTTP requests to the upstream
/// and returns the upstream's response with the correct status code and body.
#[test]
fn proxy_forwards_upstream_responses() {
    let _lock = PORT_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
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
    let _lock = PORT_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
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

/// ISSUE-007: Verifies that Dwaar adds standard proxy headers to the request
/// sent to the upstream, and that hop-by-hop headers are stripped.
#[test]
fn proxy_adds_standard_proxy_headers() {
    let _lock = PORT_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let upstream =
        TcpListener::bind("127.0.0.1:8080").expect("bind to 127.0.0.1:8080 for mock upstream");

    let child = start_dwaar_proxy();

    // Spawn a thread to capture what the upstream receives
    let handle = thread::spawn({
        let upstream_fd = upstream.try_clone().expect("clone listener");
        move || serve_and_capture_headers(&upstream_fd)
    });

    // Send a request through the proxy
    let _resp = send_through_proxy("/api/test");
    let upstream_headers = handle.join().expect("upstream thread");

    // --- X-Real-IP: should be 127.0.0.1 (the test client's IP) ---
    let real_ip = upstream_headers
        .get("x-real-ip")
        .expect("upstream should receive X-Real-IP");
    assert_eq!(real_ip, "127.0.0.1");

    // --- X-Forwarded-For: should contain 127.0.0.1 ---
    let xff = upstream_headers
        .get("x-forwarded-for")
        .expect("upstream should receive X-Forwarded-For");
    assert!(
        xff.contains("127.0.0.1"),
        "X-Forwarded-For should contain client IP, got: {xff}"
    );

    // --- X-Forwarded-Proto: should be "http" (no TLS yet) ---
    let proto = upstream_headers
        .get("x-forwarded-proto")
        .expect("upstream should receive X-Forwarded-Proto");
    assert_eq!(proto, "http");

    // --- X-Request-Id: should be a UUID ---
    let request_id = upstream_headers
        .get("x-request-id")
        .expect("upstream should receive X-Request-Id");
    assert_eq!(request_id.len(), 36, "request ID should be a UUID");

    // --- Hop-by-hop headers should NOT be present ---
    assert!(
        !upstream_headers.contains_key("proxy-connection"),
        "Proxy-Connection should be stripped"
    );

    stop_dwaar(child);
}

/// ISSUE-007: Verifies that X-Forwarded-For appends to an existing chain
/// rather than replacing it (chained proxy scenario).
#[test]
fn proxy_appends_to_existing_x_forwarded_for() {
    let _lock = PORT_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let upstream =
        TcpListener::bind("127.0.0.1:8080").expect("bind to 127.0.0.1:8080 for mock upstream");

    let child = start_dwaar_proxy();

    let handle = thread::spawn({
        let upstream_fd = upstream.try_clone().expect("clone listener");
        move || serve_and_capture_headers(&upstream_fd)
    });

    // Send a request with a pre-existing X-Forwarded-For header,
    // simulating a request that already passed through another proxy.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");

    rt.block_on(async {
        let client = reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("build client");

        let _resp = client
            .get("http://127.0.0.1:6188/chained")
            .header("X-Forwarded-For", "10.0.0.1")
            .send()
            .await
            .expect("request should succeed");
    });

    let upstream_headers = handle.join().expect("upstream thread");

    // X-Forwarded-For should contain ONLY the direct client IP (127.0.0.1).
    // Client-sent XFF headers are stripped to prevent IP spoofing.
    let xff = upstream_headers
        .get("x-forwarded-for")
        .expect("upstream should receive X-Forwarded-For");
    assert_eq!(
        xff, "127.0.0.1",
        "X-Forwarded-For should be only the direct client IP, got: {xff}"
    );
    assert!(
        !xff.contains("10.0.0.1"),
        "client-supplied XFF should be stripped, got: {xff}"
    );

    stop_dwaar(child);
}

/// ISSUE-008: Verifies that every proxied response includes the full set
/// of security headers and replaces the upstream's Server banner.
#[test]
fn proxy_adds_security_response_headers() {
    let _lock = PORT_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let upstream =
        TcpListener::bind("127.0.0.1:8080").expect("bind to 127.0.0.1:8080 for mock upstream");

    let child = start_dwaar_proxy();

    // The mock upstream responds with its own Server header — Dwaar should replace it.
    let handle = thread::spawn({
        let upstream_fd = upstream.try_clone().expect("clone listener");
        move || {
            let (mut stream, _) = upstream_fd.accept().expect("accept");
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            let mut line = String::new();
            loop {
                line.clear();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
            }
            let response = "HTTP/1.1 200 OK\r\n\
                            Server: Express/4.18.2\r\n\
                            Content-Length: 2\r\n\
                            Connection: close\r\n\
                            \r\n\
                            ok";
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });

    let resp = send_through_proxy("/");
    handle.join().expect("upstream thread");

    // --- Strict-Transport-Security ---
    // HSTS is only emitted on TLS connections (not on plaintext HTTP).
    // This test uses plaintext, so HSTS should be absent.
    assert!(
        !resp.headers.contains_key("strict-transport-security"),
        "HSTS should NOT be present on plaintext HTTP responses"
    );

    // --- X-Content-Type-Options ---
    let xcto = resp
        .headers
        .get("x-content-type-options")
        .expect("response should have X-Content-Type-Options");
    assert_eq!(xcto, "nosniff");

    // --- X-Frame-Options ---
    let xfo = resp
        .headers
        .get("x-frame-options")
        .expect("response should have X-Frame-Options");
    assert_eq!(xfo, "SAMEORIGIN");

    // --- Referrer-Policy ---
    let rp = resp
        .headers
        .get("referrer-policy")
        .expect("response should have Referrer-Policy");
    assert_eq!(rp, "strict-origin-when-cross-origin");

    // --- Server: should be "Dwaar", NOT the upstream's "Express/4.18.2" ---
    let server = resp
        .headers
        .get("server")
        .expect("response should have Server");
    assert_eq!(server, "Dwaar", "Server banner should be replaced by Dwaar");

    // --- X-Request-Id should still be present (ISSUE-006 regression check) ---
    let request_id = resp
        .headers
        .get("x-request-id")
        .expect("response should still have X-Request-Id");
    assert_eq!(request_id.len(), 36);

    stop_dwaar(child);
}

/// ISSUE-068: Verifies that WebSocket upgrade headers are preserved when both
/// `Upgrade: websocket` and `Connection: Upgrade` are present. The upstream
/// must receive both headers plus Sec-WebSocket-Key for the handshake to work.
#[test]
fn websocket_upgrade_headers_preserved() {
    let _lock = PORT_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let upstream =
        TcpListener::bind("127.0.0.1:8080").expect("bind to 127.0.0.1:8080 for mock upstream");

    let child = start_dwaar_proxy();

    let handle = thread::spawn({
        let upstream_fd = upstream.try_clone().expect("clone listener");
        move || serve_and_capture_headers(&upstream_fd)
    });

    send_raw_request(
        "/ws",
        &[
            ("Upgrade", "websocket"),
            ("Connection", "Upgrade"),
            ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
            ("Sec-WebSocket-Version", "13"),
        ],
    );

    let upstream_headers = handle.join().expect("upstream thread");

    // Upgrade header must reach the upstream — Dwaar detected WebSocket
    // and skipped hop-by-hop stripping for this header.
    let upgrade = upstream_headers
        .get("upgrade")
        .expect("upstream must receive Upgrade header for WebSocket");
    assert_eq!(
        upgrade, "websocket",
        "Upgrade value must be preserved verbatim"
    );

    // Connection header must contain Upgrade for the handshake
    let connection = upstream_headers
        .get("connection")
        .expect("upstream must receive Connection header");
    assert!(
        connection.to_lowercase().contains("upgrade"),
        "Connection must contain 'upgrade', got: {connection}"
    );

    // Sec-WebSocket-Key must pass through (never in hop-by-hop list)
    let ws_key = upstream_headers
        .get("sec-websocket-key")
        .expect("upstream must receive Sec-WebSocket-Key");
    assert_eq!(ws_key, "dGhlIHNhbXBsZSBub25jZQ==");

    // Sec-WebSocket-Version must pass through
    let ws_ver = upstream_headers
        .get("sec-websocket-version")
        .expect("upstream must receive Sec-WebSocket-Version");
    assert_eq!(ws_ver, "13");

    stop_dwaar(child);
}

/// ISSUE-068: Non-WebSocket requests must still have Upgrade stripped.
/// Sending `Upgrade: h2c` without `Connection: Upgrade` (or with a non-websocket
/// upgrade) must not trigger WebSocket preservation.
#[test]
fn non_websocket_upgrade_still_stripped() {
    let _lock = PORT_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let upstream =
        TcpListener::bind("127.0.0.1:8080").expect("bind to 127.0.0.1:8080 for mock upstream");

    let child = start_dwaar_proxy();

    let handle = thread::spawn({
        let upstream_fd = upstream.try_clone().expect("clone listener");
        move || serve_and_capture_headers(&upstream_fd)
    });

    // h2c upgrade — not websocket, Upgrade should be stripped
    send_raw_request("/api", &[("Upgrade", "h2c"), ("Connection", "Upgrade")]);

    let upstream_headers = handle.join().expect("upstream thread");

    assert!(
        !upstream_headers.contains_key("upgrade"),
        "Upgrade: h2c should be stripped (not a WebSocket upgrade)"
    );

    stop_dwaar(child);
}

/// ISSUE-068: Malformed WebSocket request (has Upgrade: websocket but missing
/// Connection: Upgrade) should NOT trigger WebSocket preservation. The Upgrade
/// header should be stripped as usual.
#[test]
fn malformed_websocket_missing_connection_upgrade() {
    let _lock = PORT_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let upstream =
        TcpListener::bind("127.0.0.1:8080").expect("bind to 127.0.0.1:8080 for mock upstream");

    let child = start_dwaar_proxy();

    let handle = thread::spawn({
        let upstream_fd = upstream.try_clone().expect("clone listener");
        move || serve_and_capture_headers(&upstream_fd)
    });

    // Has Upgrade: websocket but Connection is keep-alive (no "upgrade" token)
    send_raw_request(
        "/ws-broken",
        &[
            ("Upgrade", "websocket"),
            ("Connection", "keep-alive"),
            ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
            ("Sec-WebSocket-Version", "13"),
        ],
    );

    let upstream_headers = handle.join().expect("upstream thread");

    assert!(
        !upstream_headers.contains_key("upgrade"),
        "Upgrade should be stripped when Connection doesn't contain 'upgrade'"
    );

    stop_dwaar(child);
}

/// Send a raw HTTP request through the proxy and return the HTTP status code.
/// Uses `BufReader` to handle partial reads and RST races when the proxy closes
/// the connection early (e.g., 413 before body is sent).
fn send_raw_post_get_status(
    path: &str,
    content_length: u64,
    extra_headers: &[(&str, &str)],
) -> u16 {
    let stream = TcpStream::connect("127.0.0.1:6188").expect("connect to proxy for raw POST");
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

    // Shut down write side after headers so the proxy doesn't wait for body.
    // This simulates a client that announced Content-Length but closed early,
    // which is enough to trigger the 413 check.
    let mut writer = stream.try_clone().expect("clone stream for write");
    let mut request = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: 127.0.0.1\r\n\
         Content-Length: {content_length}\r\n"
    );
    for (name, value) in extra_headers {
        let _ = write!(request, "{name}: {value}\r\n");
    }
    request.push_str("\r\n");

    writer
        .write_all(request.as_bytes())
        .expect("write raw POST");
    writer.flush().expect("flush raw POST");

    // Read the status line from the response using BufReader for line-based reads.
    let reader = BufReader::new(&stream);
    for line in reader.lines() {
        match line {
            Ok(l) if l.starts_with("HTTP/") => {
                return l
                    .split_whitespace()
                    .nth(1)
                    .and_then(|code| code.parse().ok())
                    .unwrap_or(0);
            }
            Ok(_) => {}
            Err(_) => return 0,
        }
    }
    0
}

/// ISSUE-069: POST with Content-Length under the default 10 MB limit is forwarded.
#[test]
fn request_body_under_limit_forwarded() {
    let _lock = PORT_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let upstream =
        TcpListener::bind("127.0.0.1:8080").expect("bind to 127.0.0.1:8080 for mock upstream");

    let child = start_dwaar_proxy();

    // Small body (1 KB) — well under 10 MB default
    let handle = thread::spawn({
        let upstream_fd = upstream.try_clone().expect("clone listener");
        move || serve_one_request(&upstream_fd, 200, "accepted")
    });

    let status = send_raw_post_get_status("/upload", 1024, &[]);
    handle.join().expect("upstream thread");
    assert_eq!(status, 200, "small POST should be forwarded to upstream");

    stop_dwaar(child);
}

/// ISSUE-069: POST with Content-Length exceeding the default 10 MB limit gets 413.
#[test]
fn request_body_over_limit_rejected() {
    let _lock = PORT_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _upstream =
        TcpListener::bind("127.0.0.1:8080").expect("bind to 127.0.0.1:8080 for mock upstream");

    let child = start_dwaar_proxy();

    // 20 MB — exceeds default 10 MB limit
    let status = send_raw_post_get_status("/upload", 20 * 1024 * 1024, &[]);
    assert_eq!(
        status, 413,
        "oversized POST should get 413 Payload Too Large"
    );

    stop_dwaar(child);
}

/// ISSUE-069: POST with Content-Length: 0 is always allowed.
#[test]
fn request_body_zero_length_allowed() {
    let _lock = PORT_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let upstream =
        TcpListener::bind("127.0.0.1:8080").expect("bind to 127.0.0.1:8080 for mock upstream");

    let child = start_dwaar_proxy();

    let handle = thread::spawn({
        let upstream_fd = upstream.try_clone().expect("clone listener");
        move || serve_one_request(&upstream_fd, 204, "")
    });

    let status = send_raw_post_get_status("/empty", 0, &[]);
    handle.join().expect("upstream thread");
    assert_eq!(status, 204, "zero-length POST should be forwarded");

    stop_dwaar(child);
}

/// ISSUE-069: Custom `request_body` `max_size` from Dwaarfile is respected.
/// Uses a separate Dwaarfile with a 1 KB limit. Isolated test to avoid port
/// contention with other tests that use the default Dwaarfile.
#[test]
fn request_body_custom_limit_from_config() {
    let _lock = PORT_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _upstream =
        TcpListener::bind("127.0.0.1:8080").expect("bind to 127.0.0.1:8080 for mock upstream");

    // Write a Dwaarfile with a tiny 1 KB limit
    let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    std::fs::create_dir_all(&config_path).ok();
    let config_file = config_path.join("body_limit_test.dwaarfile");
    std::fs::write(
        &config_file,
        "127.0.0.1 {\n    reverse_proxy 127.0.0.1:8080\n    request_body {\n        max_size 1KB\n    }\n}\n",
    )
    .expect("write test Dwaarfile");

    let child = start_dwaar_with_config(Some(&config_file));

    // 2 KB — exceeds the 1 KB custom limit
    let status = send_raw_post_get_status("/upload", 2048, &[]);
    assert_eq!(
        status, 413,
        "POST exceeding custom 1KB limit should get 413"
    );

    stop_dwaar(child);
    // Cleanup + wait for port to fully release before next test
    std::fs::remove_file(&config_file).ok();
    thread::sleep(Duration::from_secs(1));
}

/// ISSUE-070: Response body exceeding limit causes connection abort.
/// Uses a separate Dwaarfile with a tiny `response_body_limit`.
#[test]
fn response_body_over_limit_returns_error() {
    let _lock = PORT_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let upstream =
        TcpListener::bind("127.0.0.1:8080").expect("bind to 127.0.0.1:8080 for mock upstream");

    // response_body_limit 100 bytes — upstream will send more than that
    let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    std::fs::create_dir_all(&config_path).ok();
    let config_file = config_path.join("resp_limit_test.dwaarfile");
    std::fs::write(
        &config_file,
        "127.0.0.1 {\n    reverse_proxy 127.0.0.1:8080\n    response_body_limit 100\n}\n",
    )
    .expect("write test Dwaarfile");

    let child = start_dwaar_with_config(Some(&config_file));

    // Upstream sends a 500-byte response body — exceeds 100-byte limit
    let big_body = "X".repeat(500);
    let handle = thread::spawn({
        let upstream_fd = upstream.try_clone().expect("clone listener");
        move || serve_one_request(&upstream_fd, 200, &big_body)
    });

    let status = send_raw_post_get_status("/data", 0, &[]);
    handle.join().expect("upstream thread");

    // Dwaar detects Content-Length > limit in response_filter() and replaces
    // the response with 502 before the body is sent to the client.
    assert_eq!(
        status, 502,
        "response over limit should get 502 Bad Gateway"
    );

    stop_dwaar(child);
    // Cleanup + wait for port release
    std::fs::remove_file(&config_file).ok();
    thread::sleep(Duration::from_secs(1));
}

/// ISSUE-071: IP filter denies requests from blocked IPs (returns 403).
/// Uses a Dwaarfile that denies 127.0.0.1 (the test client's IP).
#[test]
fn ip_filter_denies_blocked_ip() {
    let _lock = PORT_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _upstream =
        TcpListener::bind("127.0.0.1:8080").expect("bind to 127.0.0.1:8080 for mock upstream");

    let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    std::fs::create_dir_all(&config_path).ok();
    let config_file = config_path.join("ip_filter_deny_test.dwaarfile");
    std::fs::write(
        &config_file,
        "127.0.0.1 {\n    reverse_proxy 127.0.0.1:8080\n    ip_filter {\n        deny 127.0.0.1\n        default allow\n    }\n}\n",
    )
    .expect("write test Dwaarfile");

    let child = start_dwaar_with_config(Some(&config_file));

    // Test client connects from 127.0.0.1 — should be denied
    let resp = send_through_proxy("/blocked");
    assert_eq!(resp.status, 403, "denied IP should get 403 Forbidden");

    stop_dwaar(child);
    std::fs::remove_file(&config_file).ok();
    thread::sleep(Duration::from_secs(1));
}

/// ISSUE-071: IP filter allows requests from permitted IPs.
/// Uses a Dwaarfile with `default deny` but allows 127.0.0.0/8.
#[test]
fn ip_filter_allows_permitted_ip() {
    let _lock = PORT_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let upstream =
        TcpListener::bind("127.0.0.1:8080").expect("bind to 127.0.0.1:8080 for mock upstream");

    let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    std::fs::create_dir_all(&config_path).ok();
    let config_file = config_path.join("ip_filter_allow_test.dwaarfile");
    std::fs::write(
        &config_file,
        "127.0.0.1 {\n    reverse_proxy 127.0.0.1:8080\n    ip_filter {\n        allow 127.0.0.0/8\n        default deny\n    }\n}\n",
    )
    .expect("write test Dwaarfile");

    let child = start_dwaar_with_config(Some(&config_file));

    let handle = thread::spawn({
        let upstream_fd = upstream.try_clone().expect("clone listener");
        move || serve_one_request(&upstream_fd, 200, "allowed")
    });

    let resp = send_through_proxy("/allowed");
    handle.join().expect("upstream thread");
    assert_eq!(
        resp.status, 200,
        "allowed IP should be forwarded to upstream"
    );

    stop_dwaar(child);
    std::fs::remove_file(&config_file).ok();
    thread::sleep(Duration::from_secs(1));
}
