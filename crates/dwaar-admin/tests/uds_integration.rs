// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Integration tests for Admin API Unix domain socket support.
//!
//! These tests start a real Pingora service with both TCP and UDS listeners,
//! then verify auth bypass on UDS and auth enforcement on TCP.
//!
//! MUST run with --test-threads=1 to avoid port conflicts between tests.

use std::fs::Permissions;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
use dashmap::DashMap;
use dwaar_admin::AdminService;
use dwaar_analytics::aggregation::DomainMetrics;
use dwaar_core::route::RouteTable;

/// Helper: build an `AdminService` with a test token.
fn test_admin_service() -> AdminService {
    let route_table = Arc::new(ArcSwap::from_pointee(RouteTable::new(vec![])));
    let metrics: Arc<DashMap<String, DomainMetrics>> = Arc::new(DashMap::new());
    AdminService::new(
        route_table,
        metrics,
        std::time::Instant::now(),
        Some("test-token".to_string()),
    )
}

/// Send a raw HTTP/1.1 request and return the full response as a String.
/// Uses read timeout to detect end of response.
fn send_http_request(stream: &mut (impl Read + Write), request: &str) -> String {
    stream.write_all(request.as_bytes()).expect("write request");
    stream.flush().expect("flush");

    let mut response = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(e) => panic!("read error: {e}"),
        }
    }

    String::from_utf8_lossy(&response).to_string()
}

/// Start a Pingora service with TCP + UDS, return the thread handle.
/// `run_forever()` blocks, so we use a thread.
fn start_test_server(socket_path: &str, tcp_port: u16) -> std::thread::JoinHandle<()> {
    let socket_path = socket_path.to_string();
    let handle = std::thread::spawn(move || {
        use pingora_core::server::Server;
        use pingora_core::server::configuration::{Opt as PingoraOpt, ServerConf};

        let conf = ServerConf {
            grace_period_seconds: Some(1),
            graceful_shutdown_timeout_seconds: Some(1),
            ..ServerConf::default()
        };
        let pingora_opt = PingoraOpt {
            upgrade: false,
            daemon: false,
            nocapture: false,
            test: false,
            conf: None,
        };

        let mut server = Server::new_with_opt_and_conf(Some(pingora_opt), conf);
        server.bootstrap();

        let admin = test_admin_service();
        let mut service =
            pingora_core::services::listening::Service::new("test admin".to_string(), admin);
        service.add_tcp(&format!("127.0.0.1:{tcp_port}"));

        // Stale socket cleanup
        let _ = std::fs::remove_file(&socket_path);
        service.add_uds(&socket_path, Some(Permissions::from_mode(0o660)));

        server.add_service(service);
        server.run_forever();
    });

    // Give the server time to bind
    std::thread::sleep(std::time::Duration::from_secs(2));
    handle
}

#[test]
fn uds_skips_auth_on_health() {
    let socket_path = "/tmp/dwaar-test-health.sock";
    let _server = start_test_server(socket_path, 16190);

    let mut stream = UnixStream::connect(socket_path).expect("connect to UDS");
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .expect("set read timeout");

    let response = send_http_request(
        &mut stream,
        "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );

    assert!(response.contains("200"), "expected 200, got: {response}");
    assert!(response.contains("\"status\":\"ok\""));
}

#[test]
fn uds_skips_auth_on_routes() {
    let socket_path = "/tmp/dwaar-test-routes.sock";
    let _server = start_test_server(socket_path, 16191);

    let mut stream = UnixStream::connect(socket_path).expect("connect to UDS");
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .expect("set read timeout");

    // GET /routes without auth token — should succeed over UDS
    let response = send_http_request(
        &mut stream,
        "GET /routes HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );

    assert!(response.contains("200"), "expected 200, got: {response}");
}

#[test]
fn tcp_requires_auth_on_routes() {
    let socket_path = "/tmp/dwaar-test-tcp-auth.sock";
    let tcp_port = 16192;
    let _server = start_test_server(socket_path, tcp_port);

    let mut stream =
        std::net::TcpStream::connect(format!("127.0.0.1:{tcp_port}")).expect("connect to TCP");
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .expect("set read timeout");

    // GET /routes without auth token — should fail over TCP
    let response = send_http_request(
        &mut stream,
        "GET /routes HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );

    assert!(response.contains("401"), "expected 401, got: {response}");
    assert!(response.contains("unauthorized"));
}

#[test]
fn uds_route_push_without_auth() {
    let socket_path = "/tmp/dwaar-test-push.sock";
    let _server = start_test_server(socket_path, 16194);

    let mut stream = UnixStream::connect(socket_path).expect("connect to UDS");
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .expect("set read timeout");

    let body = r#"{"domain":"example.com","upstream":"127.0.0.1:3000","tls":false}"#;
    let request = format!(
        "POST /routes HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
        body.len(),
        body
    );
    let response = send_http_request(&mut stream, &request);

    assert!(response.contains("201"), "expected 201, got: {response}");
}

#[test]
fn uds_analytics_pull_without_auth() {
    let socket_path = "/tmp/dwaar-test-analytics.sock";
    let _server = start_test_server(socket_path, 16195);

    let mut stream = UnixStream::connect(socket_path).expect("connect to UDS");
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .expect("set read timeout");

    let response = send_http_request(
        &mut stream,
        "GET /analytics HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );

    assert!(response.contains("200"), "expected 200, got: {response}");
}

#[test]
fn stale_socket_does_not_block_startup() {
    let socket_path = "/tmp/dwaar-test-stale.sock";

    // Clean up any leftover socket from prior test runs, then create
    // a regular file to simulate a stale socket left by a crashed process.
    let _ = std::fs::remove_file(socket_path);
    std::fs::write(socket_path, "stale").expect("create stale file");
    assert!(PathBuf::from(socket_path).exists());

    // Server should start despite the stale file
    let _server = start_test_server(socket_path, 16193);

    // Verify we can connect
    let mut stream = UnixStream::connect(socket_path).expect("connect after stale cleanup");
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .expect("set read timeout");

    let response = send_http_request(
        &mut stream,
        "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );

    assert!(response.contains("200"), "expected 200, got: {response}");
}
