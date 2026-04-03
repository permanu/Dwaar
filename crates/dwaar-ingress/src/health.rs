// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Liveness, readiness, and metrics HTTP endpoints.
//!
//! Serves a minimal HTTP/1.1 server on the configured probe port (default 8081).
//! All three endpoints are on the same port:
//!
//! - `GET /healthz` — liveness probe: always 200 once the process is up.
//! - `GET /readyz` — readiness probe: 200 only when the watcher is connected
//!   AND the leader lease is held. 503 otherwise.
//! - `GET /metrics` — Prometheus text exposition format.
//!
//! We use `hyper` directly (no framework) to keep the dependency surface small.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tracing::{error, info};

use crate::metrics::IngressMetrics;

/// Shared readiness state.
///
/// Both flags must be `true` for `/readyz` to return 200.
#[derive(Debug, Clone)]
pub struct ReadinessState {
    /// Set to `true` once the kube watch stream is successfully connected.
    pub watcher_ready: Arc<AtomicBool>,
    /// Set to `true` when this pod holds the leader lease. For controllers
    /// that skip leader election this should be permanently set to `true`.
    pub leader_ready: Arc<AtomicBool>,
}

impl ReadinessState {
    pub fn new() -> Self {
        Self {
            watcher_ready: Arc::new(AtomicBool::new(false)),
            leader_ready: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Returns `true` when both conditions are satisfied.
    pub fn is_ready(&self) -> bool {
        self.watcher_ready.load(Ordering::Acquire) && self.leader_ready.load(Ordering::Acquire)
    }
}

impl Default for ReadinessState {
    fn default() -> Self {
        Self::new()
    }
}

/// Start the health/readiness/metrics HTTP server.
///
/// Runs until the process exits. Blocks the calling task; spawn with
/// `tokio::spawn` if you need concurrent work.
pub async fn serve(
    addr: SocketAddr,
    readiness: ReadinessState,
    metrics: Arc<IngressMetrics>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!(addr = %addr, "health server listening");

    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!(error = %e, "health server accept failed");
                continue;
            }
        };

        let readiness = readiness.clone();
        let metrics = Arc::clone(&metrics);

        // Each connection is handled in its own task so a slow client
        // cannot block other probes (Kubernetes can probe rapidly on startup).
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |req: Request<hyper::body::Incoming>| {
                let readiness = readiness.clone();
                let metrics = Arc::clone(&metrics);
                async move {
                    Ok::<_, Infallible>(dispatch_request(req.uri().path(), &readiness, &metrics))
                }
            });

            if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                // Connection errors are normal (kubelet probes can close mid-response)
                error!(error = %e, "health connection error");
            }
        });
    }
}

/// Route a request path to the appropriate probe handler.
///
/// Separated from the `Request` type so tests can call this directly
/// without needing to construct a `hyper::body::Incoming`.
pub(crate) fn dispatch_request(
    path: &str,
    readiness: &ReadinessState,
    metrics: &IngressMetrics,
) -> Response<Full<Bytes>> {
    match path {
        "/healthz" => liveness_response(),
        "/readyz" => readiness_response(readiness),
        "/metrics" => metrics_response(metrics),
        _ => not_found_response(),
    }
}

/// Liveness probe: always 200 once the process is running.
/// Kubernetes restarts the pod if this returns non-2xx.
fn liveness_response() -> Response<Full<Bytes>> {
    json_response(StatusCode::OK, r#"{"status":"ok"}"#)
}

/// Readiness probe: 200 only when watcher connected AND leader lease held.
/// Kubernetes removes the pod from load-balancer endpoints until this is 200.
fn readiness_response(readiness: &ReadinessState) -> Response<Full<Bytes>> {
    if readiness.is_ready() {
        json_response(StatusCode::OK, r#"{"status":"ready"}"#)
    } else {
        json_response(StatusCode::SERVICE_UNAVAILABLE, r#"{"status":"not ready"}"#)
    }
}

/// Metrics endpoint: Prometheus text format.
fn metrics_response(metrics: &IngressMetrics) -> Response<Full<Bytes>> {
    let body = metrics.render();
    Response::builder()
        .status(StatusCode::OK)
        .header(
            hyper::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )
        .body(Full::new(Bytes::from(body)))
        .expect("metrics response is always valid")
}

fn not_found_response() -> Response<Full<Bytes>> {
    json_response(StatusCode::NOT_FOUND, r#"{"error":"not found"}"#)
}

fn json_response(status: StatusCode, body: &'static str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from_static(body.as_bytes())))
        .expect("health response is always valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn liveness_always_200() {
        let state = ReadinessState::new();
        let metrics = IngressMetrics::new();
        let resp = dispatch_request("/healthz", &state, &metrics);
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn readiness_503_when_not_ready() {
        let state = ReadinessState::new(); // both flags false
        let metrics = IngressMetrics::new();
        let resp = dispatch_request("/readyz", &state, &metrics);
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn readiness_503_when_only_watcher_ready() {
        let state = ReadinessState::new();
        state.watcher_ready.store(true, Ordering::Release);
        // leader_ready still false
        let metrics = IngressMetrics::new();
        let resp = dispatch_request("/readyz", &state, &metrics);
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn readiness_503_when_only_leader_ready() {
        let state = ReadinessState::new();
        state.leader_ready.store(true, Ordering::Release);
        // watcher_ready still false
        let metrics = IngressMetrics::new();
        let resp = dispatch_request("/readyz", &state, &metrics);
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn readiness_200_when_both_ready() {
        let state = ReadinessState::new();
        state.watcher_ready.store(true, Ordering::Release);
        state.leader_ready.store(true, Ordering::Release);
        let metrics = IngressMetrics::new();
        let resp = dispatch_request("/readyz", &state, &metrics);
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn unknown_path_returns_404() {
        let state = ReadinessState::new();
        let metrics = IngressMetrics::new();
        let resp = dispatch_request("/unknown", &state, &metrics);
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn metrics_endpoint_returns_prometheus_text() {
        let state = ReadinessState::new();
        let metrics = IngressMetrics::new();
        let resp = dispatch_request("/metrics", &state, &metrics);
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .expect("content-type header")
            .to_str()
            .expect("header is utf8");
        assert!(ct.contains("text/plain"));
    }
}
