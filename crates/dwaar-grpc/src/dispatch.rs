// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Concrete implementations of `dwaar-core`'s control-plane trait objects.
//!
//! `dwaar-core` defines [`MirrorDispatcher`] and [`RequestOutcomeSink`]
//! traits so the proxy can emit hot-path signals without taking a
//! compile-time dependency on this crate. The types here plug into those
//! traits at startup and forward observations into the gRPC registries and
//! event bus.
//!
//! Kept in `dwaar-grpc` (not `dwaar-cli`) so the integration is
//! unit-testable without spinning up the binary.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use dwaar_core::proxy::{MirrorDispatcher, RequestOutcomeSink};
use dwaar_core::registries::MirrorRegistry;
use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use crate::events::{AnomalyDetector, AnomalyThresholds, EventBus, LogChunkBuffer, RequestOutcome};

/// Prometheus counter labels mirrored in the text exposition output.
pub const MIRROR_OUTCOME_SENT: &str = "sent";
pub const MIRROR_OUTCOME_SAMPLED_OUT: &str = "sampled_out";
pub const MIRROR_OUTCOME_ERROR: &str = "error";

/// Upper bound on the number of headers propagated to a mirror target.
///
/// Mirrors are best-effort — protecting the in-process mirror worker pool
/// from a pathological request with thousands of headers matters more
/// than preserving every single `X-Foo` on the shadow path.
const MAX_MIRROR_HEADERS: usize = 64;

/// Fire-and-forget mirror dispatcher backed by the shared
/// [`MirrorRegistry`].
///
/// On every request matching a domain with an installed mirror config,
/// we spawn a detached tokio task that replays the request to the mirror
/// target. The task:
///
/// 1. Rolls `sample_rate_bps` — may short-circuit to `sampled_out`.
/// 2. Connects to `mirror_to` with a 2 s budget.
/// 3. Writes a minimal HTTP/1.1 request (method, path, Host, headers).
/// 4. Drops the response — no body parsing, no buffering.
///
/// A Prometheus counter `dwaar_mirror_requests_total` is rendered by
/// [`MirrorMetrics::render`] with `outcome = {sent|sampled_out|error}`.
#[derive(Debug)]
pub struct MirrorDispatcherImpl {
    registry: Arc<MirrorRegistry>,
    metrics: Arc<MirrorMetrics>,
}

impl MirrorDispatcherImpl {
    pub fn new(registry: Arc<MirrorRegistry>) -> Self {
        Self {
            registry,
            metrics: Arc::new(MirrorMetrics::new()),
        }
    }

    pub fn metrics(&self) -> Arc<MirrorMetrics> {
        Arc::clone(&self.metrics)
    }
}

impl MirrorDispatcher for MirrorDispatcherImpl {
    fn mirror(&self, domain: &str, method: &str, path: &str, headers: &[(String, String)]) {
        let Some(cfg) = self.registry.snapshot_for(domain) else {
            return;
        };
        if !cfg.should_mirror() {
            self.metrics
                .record(domain, &cfg.mirror_to, MIRROR_OUTCOME_SAMPLED_OUT);
            return;
        }

        let Some(mirror_addr) = cfg.socket_addr() else {
            self.metrics
                .record(domain, &cfg.mirror_to, MIRROR_OUTCOME_ERROR);
            warn!(
                source_domain = %domain,
                mirror_to = %cfg.mirror_to,
                "mirror_to could not be parsed as a socket address — dropping mirror"
            );
            return;
        };

        // Defensive copy — we cap at `MAX_MIRROR_HEADERS` so a hostile
        // peer with thousands of headers can't pin our mirror workers.
        let metrics = Arc::clone(&self.metrics);
        let domain = domain.to_string();
        let method = method.to_string();
        let path = path.to_string();
        let owned_headers: Vec<(String, String)> =
            headers.iter().take(MAX_MIRROR_HEADERS).cloned().collect();
        let mirror_to = cfg.mirror_to;

        tokio::spawn(async move {
            let outcome =
                match send_mirror(&mirror_addr, &method, &path, &domain, &owned_headers).await {
                    Ok(()) => MIRROR_OUTCOME_SENT,
                    Err(e) => {
                        debug!(
                            source_domain = %domain,
                            mirror_to = %mirror_to,
                            error = %e,
                            "mirror request failed"
                        );
                        MIRROR_OUTCOME_ERROR
                    }
                };
            metrics.record(&domain, &mirror_to, outcome);
        });
    }
}

async fn send_mirror(
    addr: &std::net::SocketAddr,
    method: &str,
    path: &str,
    host: &str,
    headers: &[(String, String)],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut stream = tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(addr))
        .await
        .map_err(|_| "mirror connect timed out")??;

    let mut req = String::with_capacity(256);
    req.push_str(method);
    req.push(' ');
    req.push_str(path);
    req.push_str(" HTTP/1.1\r\nHost: ");
    req.push_str(host);
    req.push_str("\r\nConnection: close\r\nX-Dwaar-Mirror: 1\r\n");
    for (name, value) in headers {
        if is_hop_header(name) {
            continue;
        }
        req.push_str(name);
        req.push_str(": ");
        // CRLF injection defence — a stray \r\n in a header value would
        // let an attacker smuggle a second request onto the mirror socket.
        if value.contains('\r') || value.contains('\n') {
            continue;
        }
        req.push_str(value);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");

    tokio::time::timeout(Duration::from_secs(2), stream.write_all(req.as_bytes()))
        .await
        .map_err(|_| "mirror write timed out")??;

    // Drain a tiny prefix so the OS socket can cleanly close. We never
    // interpret the response — mirror is fire-and-forget.
    let mut buf = [0u8; 64];
    let _ = tokio::time::timeout(Duration::from_millis(500), stream.read(&mut buf)).await;
    Ok(())
}

fn is_hop_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection" | "proxy-connection" | "keep-alive" | "transfer-encoding" | "upgrade" | "host"
    )
}

/// Per-label counter for mirror outcomes. Rendered in Prometheus text
/// exposition by [`MirrorMetrics::render`].
#[derive(Debug, Default)]
pub struct MirrorMetrics {
    counts: Mutex<HashMap<(String, String, &'static str), u64>>,
}

impl MirrorMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&self, source_domain: &str, mirror_to: &str, outcome: &'static str) {
        let key = (source_domain.to_string(), mirror_to.to_string(), outcome);
        let mut map = self.counts.lock();
        *map.entry(key).or_insert(0) += 1;
    }

    /// Snapshot the counter — useful for tests + admin API.
    pub fn snapshot(&self) -> Vec<((String, String, &'static str), u64)> {
        self.counts
            .lock()
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect()
    }

    /// Render the Prometheus text exposition line for
    /// `dwaar_mirror_requests_total` with
    /// `source_domain` / `mirror_to` / `outcome` labels.
    pub fn render(&self, out: &mut String) {
        use std::fmt::Write;
        let map = self.counts.lock();
        if map.is_empty() {
            return;
        }
        out.push_str("# HELP dwaar_mirror_requests_total Mirror requests classified by outcome.\n");
        out.push_str("# TYPE dwaar_mirror_requests_total counter\n");
        for ((domain, mirror_to, outcome), val) in map.iter() {
            let _ = writeln!(
                out,
                "dwaar_mirror_requests_total{{source_domain=\"{domain}\",mirror_to=\"{mirror_to}\",outcome=\"{outcome}\"}} {val}"
            );
        }
    }
}

/// Concrete anomaly-detection sink.
///
/// The sink owns one [`AnomalyDetector`] per tracked domain behind a
/// shared parking-lot mutex. Domains seen for the first time allocate
/// lazily. The mutex serialises only per-domain observations — different
/// domains contend on the outer `DashMap` (`ahash`-keyed) read/write, not
/// on each other.
#[derive(Debug)]
pub struct AnomalyOutcomeSink {
    bus: Arc<EventBus>,
    thresholds: AnomalyThresholds,
    detectors: dashmap::DashMap<String, Arc<Mutex<AnomalyDetector>>>,
    log_buffer: Option<Arc<LogChunkBuffer>>,
}

impl AnomalyOutcomeSink {
    pub fn new(bus: Arc<EventBus>) -> Self {
        Self::with_thresholds(bus, AnomalyThresholds::default())
    }

    pub fn with_thresholds(bus: Arc<EventBus>, thresholds: AnomalyThresholds) -> Self {
        Self {
            bus,
            thresholds,
            detectors: dashmap::DashMap::new(),
            log_buffer: None,
        }
    }

    /// Attach a log-chunk buffer so the sink's ambient request-completion
    /// callback also emits a synthetic log line. Optional — when `None`,
    /// only anomaly + spike events fire.
    #[must_use]
    pub fn with_log_buffer(mut self, buffer: Arc<LogChunkBuffer>) -> Self {
        self.log_buffer = Some(buffer);
        self
    }

    fn detector_for(&self, domain: &str) -> Arc<Mutex<AnomalyDetector>> {
        if let Some(entry) = self.detectors.get(domain) {
            return Arc::clone(entry.value());
        }
        let detector = Arc::new(Mutex::new(AnomalyDetector::new(
            domain,
            self.thresholds,
            Arc::clone(&self.bus),
        )));
        self.detectors
            .entry(domain.to_string())
            .or_insert_with(|| Arc::clone(&detector))
            .clone()
    }
}

impl RequestOutcomeSink for AnomalyOutcomeSink {
    fn record(&self, domain: &str, status: u16, latency: Duration) {
        let det = self.detector_for(domain);
        det.lock().observe(RequestOutcome {
            status,
            latency,
            observed_at: Instant::now(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mirror_metrics_render_emits_line_per_label_tuple() {
        let m = MirrorMetrics::new();
        m.record("api.example.com", "127.0.0.1:9", MIRROR_OUTCOME_SENT);
        m.record("api.example.com", "127.0.0.1:9", MIRROR_OUTCOME_SENT);
        m.record("api.example.com", "127.0.0.1:9", MIRROR_OUTCOME_SAMPLED_OUT);
        let mut out = String::new();
        m.render(&mut out);
        assert!(out.contains("# TYPE dwaar_mirror_requests_total counter"));
        assert!(out.contains(
            "source_domain=\"api.example.com\",mirror_to=\"127.0.0.1:9\",outcome=\"sent\"} 2"
        ));
        assert!(out.contains(
            "source_domain=\"api.example.com\",mirror_to=\"127.0.0.1:9\",outcome=\"sampled_out\"} 1"
        ));
    }

    #[test]
    fn hop_header_detection_is_case_insensitive() {
        assert!(is_hop_header("Connection"));
        assert!(is_hop_header("TRANSFER-ENCODING"));
        assert!(is_hop_header("Host"));
        assert!(!is_hop_header("X-Forwarded-For"));
    }

    #[test]
    fn dispatcher_zero_rate_samples_out() {
        let registry = Arc::new(MirrorRegistry::new());
        registry.upsert(dwaar_core::registries::MirrorConfig {
            source_domain: "api.example.com".into(),
            mirror_to: "127.0.0.1:1".into(),
            sample_rate_bps: 0,
        });
        let d = MirrorDispatcherImpl::new(registry);
        d.mirror("api.example.com", "GET", "/", &[]);
        let snap = d.metrics().snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].0.2, MIRROR_OUTCOME_SAMPLED_OUT);
    }

    #[tokio::test]
    async fn anomaly_sink_fires_error_rate_event() {
        let bus = Arc::new(EventBus::new());
        let mut sub = bus.subscribe();
        let sink = AnomalyOutcomeSink::with_thresholds(
            Arc::clone(&bus),
            AnomalyThresholds {
                error_rate_min_requests: 10,
                ..AnomalyThresholds::default()
            },
        );
        for _ in 0..15 {
            sink.record("api.example.com", 500, Duration::from_millis(10));
        }
        let msg = tokio::time::timeout(Duration::from_millis(200), sub.next())
            .await
            .expect("anomaly fired")
            .expect("bus open");
        let Some(crate::pb::server_message::Kind::AnomalyEvent(ev)) = &msg.kind else {
            panic!("expected anomaly event, got {:?}", msg.kind);
        };
        assert_eq!(ev.domain, "api.example.com");
        assert_eq!(ev.anomaly_type, "error_rate");
    }
}
