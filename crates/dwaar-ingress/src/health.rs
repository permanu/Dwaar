// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! HTTP health and readiness endpoints.
//!
//! `/healthz` — liveness: always 200 if the process is running.
//! `/readyz`  — readiness: 200 only when this pod holds the leader lease and
//!              has finished its initial sync. Non-leaders return 503 so that
//!              the K8s service load balancer routes traffic elsewhere.
//!
//! The `ReadinessState` is shared between this module and `leader.rs` via
//! `Arc<AtomicBool>`. Leader election sets/clears it; the health server reads it.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::net::TcpListener;
use tracing::{info, warn};

/// Shared readiness state.
///
/// Split into two flags so callers can distinguish "we have the lease" from
/// "the initial sync has completed". Both must be `true` for `/readyz` to return 200.
#[derive(Debug, Clone)]
pub struct ReadinessState {
    /// Set `true` by the leader election loop when this pod holds the lease.
    pub leader_ready: Arc<AtomicBool>,
    /// Set `true` after the first full reconcile pass completes.
    pub sync_ready: Arc<AtomicBool>,
}

impl ReadinessState {
    /// Create a new `ReadinessState` with both flags initialised to `false`.
    pub fn new() -> Self {
        Self {
            leader_ready: Arc::new(AtomicBool::new(false)),
            sync_ready: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Return `true` if this pod is the leader and has completed initial sync.
    pub fn is_ready(&self) -> bool {
        self.leader_ready.load(Ordering::Acquire) && self.sync_ready.load(Ordering::Acquire)
    }
}

impl Default for ReadinessState {
    fn default() -> Self {
        Self::new()
    }
}

/// Run the health/readiness HTTP server until `shutdown` is cancelled.
///
/// The server listens on `addr` and handles two paths:
/// - `GET /healthz` → always 200 (`{"status":"alive"}`)
/// - `GET /readyz`  → 200 if ready, 503 otherwise (`{"status":"not-ready"}`)
///
/// Everything else returns 404.
pub async fn serve(addr: SocketAddr, state: ReadinessState) -> Result<(), std::io::Error> {
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "health server listening");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!(error = %e, "health server accept error");
                continue;
            }
        };

        let state = state.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, &state).await {
                warn!(%peer, error = %e, "health connection error");
            }
        });
    }
}

/// Minimal HTTP/1.1 handler — no external dependency needed for two routes.
///
/// We read just enough of the request to extract the method and path, then
/// write a static response. This avoids pulling in a full HTTP framework for
/// what is essentially two string comparisons.
async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    state: &ReadinessState,
) -> Result<(), std::io::Error> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let mut reader = BufReader::new(&mut stream);
    let mut request_line = String::new();

    // Read only the request line — we don't need headers.
    reader.read_line(&mut request_line).await?;

    // Drain remaining headers to be a well-behaved HTTP server.
    let mut header_line = String::new();
    loop {
        header_line.clear();
        reader.read_line(&mut header_line).await?;
        if header_line == "\r\n" || header_line.is_empty() {
            break;
        }
    }

    let response = build_response(request_line.trim(), state);
    stream.write_all(response.as_bytes()).await?;
    Ok(())
}

fn build_response(request_line: &str, state: &ReadinessState) -> String {
    // Expect: "GET /path HTTP/1.1"
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");

    if method != "GET" {
        return http_response(405, r#"{"error":"method not allowed"}"#);
    }

    match path {
        "/healthz" => http_response(200, r#"{"status":"alive"}"#),
        "/readyz" => {
            if state.is_ready() {
                http_response(200, r#"{"status":"ready"}"#)
            } else {
                http_response(503, r#"{"status":"not-ready"}"#)
            }
        }
        _ => http_response(404, r#"{"error":"not found"}"#),
    }
}

fn http_response(status: u16, body: &str) -> String {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        405 => "Method Not Allowed",
        503 => "Service Unavailable",
        _ => "Unknown",
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// Suppress unused-import for `Infallible` — it exists to support the
/// never-type in future error chain expansions without breaking callers.
const _: fn() -> Option<Infallible> = || None;

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state(leader: bool, sync: bool) -> ReadinessState {
        let s = ReadinessState::new();
        s.leader_ready.store(leader, Ordering::Release);
        s.sync_ready.store(sync, Ordering::Release);
        s
    }

    #[test]
    fn healthz_always_200() {
        let state = make_state(false, false);
        let resp = build_response("GET /healthz HTTP/1.1", &state);
        assert!(resp.starts_with("HTTP/1.1 200"));
        assert!(resp.contains("alive"));
    }

    #[test]
    fn readyz_503_when_not_ready() {
        // Neither flag set
        let state = make_state(false, false);
        let resp = build_response("GET /readyz HTTP/1.1", &state);
        assert!(resp.starts_with("HTTP/1.1 503"));
        assert!(resp.contains("not-ready"));
    }

    #[test]
    fn readyz_503_when_only_leader() {
        // Leader but no sync yet
        let state = make_state(true, false);
        let resp = build_response("GET /readyz HTTP/1.1", &state);
        assert!(resp.starts_with("HTTP/1.1 503"));
    }

    #[test]
    fn readyz_503_when_only_sync() {
        // Sync done but not leader (e.g. just lost the lease)
        let state = make_state(false, true);
        let resp = build_response("GET /readyz HTTP/1.1", &state);
        assert!(resp.starts_with("HTTP/1.1 503"));
    }

    #[test]
    fn readyz_200_when_both_ready() {
        let state = make_state(true, true);
        let resp = build_response("GET /readyz HTTP/1.1", &state);
        assert!(resp.starts_with("HTTP/1.1 200"));
        assert!(resp.contains("\"status\":\"ready\""));
    }

    #[test]
    fn unknown_path_returns_404() {
        let state = make_state(true, true);
        let resp = build_response("GET /unknown HTTP/1.1", &state);
        assert!(resp.starts_with("HTTP/1.1 404"));
    }

    #[test]
    fn non_get_returns_405() {
        let state = make_state(true, true);
        let resp = build_response("POST /healthz HTTP/1.1", &state);
        assert!(resp.starts_with("HTTP/1.1 405"));
    }

    #[test]
    fn state_is_ready_requires_both_flags() {
        let s = ReadinessState::new();
        assert!(!s.is_ready());
        s.leader_ready.store(true, Ordering::Release);
        assert!(!s.is_ready()); // still needs sync_ready
        s.sync_ready.store(true, Ordering::Release);
        assert!(s.is_ready());
    }
}
