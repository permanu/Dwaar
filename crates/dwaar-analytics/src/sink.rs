// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Analytics sink — externalizes domain metrics snapshots.
//!
//! The `AggregationService` calls `sink.flush()` every 60 seconds per domain.
//! `StdoutSink` preserves the current behavior; `SocketSink` streams snapshots
//! to the Permanu agent over a Unix domain socket.

use std::collections::VecDeque;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::Serialize;
use tracing::warn;

use crate::aggregation::DomainMetrics;
use crate::aggregation::web_vitals::Percentiles;

const MAX_BUFFER_SNAPSHOTS: usize = 100;
const RECONNECT_DELAY: Duration = Duration::from_secs(1);

// ── Snapshot ────────────────────────────────────────────────────────

/// Serializable subset of [`DomainMetrics`] for external consumers.
///
/// Flatter than the internal `AnalyticsSnapshot` (used by the Admin API)
/// because the Permanu agent doesn't need the full web vitals struct — just
/// the p50/p75/p95/p99 numbers for each vital.
#[derive(Debug, Clone, Serialize)]
pub struct DomainMetricsSnapshot {
    pub domain: String,
    pub unique_visitors: u64,
    pub total_pageviews: u64,
    pub top_pages: Vec<(String, u64)>,
    pub referrers: Vec<(String, u64)>,
    pub countries: Vec<(String, u64)>,
    /// Per-device-class pageview counts across the fixed
    /// `mobile|desktop|tablet|bot|unknown` enum. Classification lives
    /// in [`crate::aggregation::classify_device`]. Cardinality is
    /// bounded at the enum size so downstream emitters cannot explode.
    pub devices: Vec<(String, u64)>,
    /// Top-N UTM source values (e.g. `google`, `newsletter`). Lowercased
    /// at ingest; bounded at the counter cap so the agent cannot fan
    /// out an unbounded label set to `VictoriaMetrics`.
    pub utm_sources: Vec<(String, u64)>,
    /// Top-N UTM medium values (e.g. `cpc`, `email`, `social`).
    pub utm_mediums: Vec<(String, u64)>,
    /// Top-N UTM campaign values (e.g. `spring-launch-2026`).
    pub utm_campaigns: Vec<(String, u64)>,
    /// HTTP status-class counts across the fixed 1xx..5xx enum, emitted
    /// in order with zero counts included so downstream heatmaps do not
    /// have to synthesize missing buckets. Sourced from the first five
    /// indices of [`crate::aggregation::DomainMetrics::status_codes`].
    pub status_classes: Vec<(String, u64)>,
    pub status_codes: [u64; 6],
    pub bytes_sent: u64,
    pub lcp: Percentiles,
    pub cls: Percentiles,
    pub inp: Percentiles,
    pub timestamp: String,
}

impl DomainMetricsSnapshot {
    /// Build from immutable domain metrics. All reads are non-mutating.
    pub fn from_metrics(domain: &str, m: &DomainMetrics) -> Self {
        Self {
            domain: domain.to_owned(),
            unique_visitors: m.unique_visitors.len() as u64,
            total_pageviews: m.page_views.count_last_n_now(60),
            top_pages: m.top_pages.top(),
            referrers: m.referrers.top(),
            countries: m.countries.top(),
            devices: m.devices.top(),
            utm_sources: m.utm_sources.top(),
            utm_mediums: m.utm_mediums.top(),
            utm_campaigns: m.utm_campaigns.top(),
            status_classes: crate::aggregation::status_class_snapshot(&m.status_codes),
            status_codes: m.status_codes,
            bytes_sent: m.bytes_sent,
            lcp: m.web_vitals.peek_lcp_percentiles(),
            cls: m.web_vitals.peek_cls_percentiles(),
            inp: m.web_vitals.peek_inp_percentiles(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }
}

// ── Trait ────────────────────────────────────────────────────────────

/// Destination for periodic analytics snapshots.
///
/// Object-safe so it can be stored as `Box<dyn AnalyticsSink>`.
/// Called synchronously from the aggregation flush loop (once per 60s),
/// so blocking I/O is acceptable.
pub trait AnalyticsSink: Send + Sync {
    fn flush(&self, snapshot: &DomainMetricsSnapshot) -> Result<(), std::io::Error>;
}

// ── StdoutSink ──────────────────────────────────────────────────────

/// Writes JSON snapshots to stdout — the default when no socket is configured.
#[derive(Debug)]
pub struct StdoutSink;

impl AnalyticsSink for StdoutSink {
    fn flush(&self, snapshot: &DomainMetricsSnapshot) -> Result<(), std::io::Error> {
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        serde_json::to_writer(&mut handle, snapshot).map_err(std::io::Error::other)?;
        handle.write_all(b"\n")?;
        handle.flush()
    }
}

// ── SocketSink ──────────────────────────────────────────────────────

/// Mutable state for [`SocketSink`] — collapsed into a single
/// `parking_lot::Mutex` to satisfy Guardrail #58 and avoid the tri-mutex
/// lock-ordering footgun the previous layout had.
struct SocketSinkState {
    stream: Option<UnixStream>,
    buffer: VecDeque<Vec<u8>>,
    last_attempt: Option<Instant>,
}

impl SocketSinkState {
    fn new() -> Self {
        Self {
            stream: None,
            buffer: VecDeque::new(),
            last_attempt: None,
        }
    }
}

/// Writes JSON snapshots to a Unix domain socket.
///
/// Uses `parking_lot::Mutex` (not tokio) because `flush()` is called
/// synchronously from the aggregation service's loop — the trait method
/// is non-async and there are no `.await` points under the lock.
pub struct SocketSink {
    path: PathBuf,
    state: Mutex<SocketSinkState>,
}

impl std::fmt::Debug for SocketSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SocketSink")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl SocketSink {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            state: Mutex::new(SocketSinkState::new()),
        }
    }

    /// Attempt a fresh connect, honoring the reconnect back-off stored in
    /// `state.last_attempt`. Caller holds the state lock.
    fn try_connect_locked(&self, state: &mut SocketSinkState) -> Option<UnixStream> {
        if let Some(t) = state.last_attempt
            && t.elapsed() < RECONNECT_DELAY
        {
            return None;
        }
        state.last_attempt = Some(Instant::now());

        match UnixStream::connect(&self.path) {
            Ok(stream) => Some(stream),
            Err(e) => {
                warn!(path = %self.path.display(), error = %e, "analytics socket connect failed");
                None
            }
        }
    }

    fn serialize(snapshot: &DomainMetricsSnapshot) -> Result<Vec<u8>, std::io::Error> {
        let mut buf = serde_json::to_vec(snapshot).map_err(std::io::Error::other)?;
        buf.push(b'\n');
        Ok(buf)
    }

    fn write_line(stream: &mut UnixStream, line: &[u8]) -> bool {
        stream.write_all(line).is_ok()
    }

    fn drain_buffer(stream: &mut UnixStream, buffer: &mut VecDeque<Vec<u8>>) {
        while let Some(line) = buffer.front() {
            if Self::write_line(stream, line) {
                buffer.pop_front();
            } else {
                break;
            }
        }
    }

    fn enqueue(buffer: &mut VecDeque<Vec<u8>>, line: Vec<u8>) {
        if buffer.len() >= MAX_BUFFER_SNAPSHOTS {
            buffer.pop_front();
        }
        buffer.push_back(line);
    }
}

impl AnalyticsSink for SocketSink {
    fn flush(&self, snapshot: &DomainMetricsSnapshot) -> Result<(), std::io::Error> {
        let line = Self::serialize(snapshot)?;

        // Single lock acquisition — covers stream, buffer, and last_attempt.
        // `flush()` is sync (no `.await`), so holding across blocking I/O
        // is fine — this is the same behavior as the prior std::Mutex code.
        let mut state = self.state.lock();

        if state.stream.is_none()
            && let Some(new_stream) = self.try_connect_locked(&mut state)
        {
            state.stream = Some(new_stream);
        }

        if let Some(mut stream) = state.stream.take() {
            Self::drain_buffer(&mut stream, &mut state.buffer);

            if Self::write_line(&mut stream, &line) {
                state.stream = Some(stream);
            } else {
                // Stream broken — drop it and queue for retry.
                Self::enqueue(&mut state.buffer, line);
            }
        } else {
            Self::enqueue(&mut state.buffer, line);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aggregation::DomainMetrics;
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixListener;

    fn test_snapshot() -> DomainMetricsSnapshot {
        let dm = DomainMetrics::new();
        DomainMetricsSnapshot::from_metrics("test.example.com", &dm)
    }

    #[test]
    fn snapshot_from_empty_metrics() {
        let snap = test_snapshot();
        assert_eq!(snap.domain, "test.example.com");
        assert_eq!(snap.unique_visitors, 0);
        assert_eq!(snap.total_pageviews, 0);
        assert!(snap.top_pages.is_empty());
        assert!(snap.referrers.is_empty());
        assert!(snap.devices.is_empty());
    }

    #[test]
    fn snapshot_surfaces_referrer_device_and_top_pages() {
        use crate::aggregation::AggEvent;
        use std::net::{IpAddr, Ipv4Addr};

        let mut dm = DomainMetrics::new();
        let uas = [
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/15E148", // mobile
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120 Safari",    // desktop
            "Googlebot/2.1",                                                        // bot
        ];
        for (i, ua) in uas.iter().enumerate() {
            dm.ingest_log(&AggEvent {
                host: "test.example.com".into(),
                path: if i == 0 {
                    "/home".into()
                } else {
                    "/about".into()
                },
                query: None,
                status: 200,
                bytes_sent: 512,
                client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, i as u8 + 1)),
                country: None,
                referer: Some("https://news.ycombinator.com/".into()),
                user_agent: Some((*ua).into()),
                is_bot: false,
            });
        }

        let snap = DomainMetricsSnapshot::from_metrics("test.example.com", &dm);
        // referrer emission — unblocks ReferrerBreakdown.svelte
        assert_eq!(snap.referrers.len(), 1);
        assert_eq!(snap.referrers[0].0, "news.ycombinator.com");
        // device emission — unblocks DeviceBreakdown.svelte
        let devices: std::collections::HashMap<_, _> = snap.devices.iter().cloned().collect();
        assert_eq!(devices.get("mobile").copied(), Some(1));
        assert_eq!(devices.get("desktop").copied(), Some(1));
        assert_eq!(devices.get("bot").copied(), Some(1));
        // top_pages emission — unblocks per-path drill-down
        let paths: std::collections::HashMap<_, _> = snap.top_pages.iter().cloned().collect();
        assert_eq!(paths.get("/home").copied(), Some(1));
        assert_eq!(paths.get("/about").copied(), Some(2));
    }

    #[test]
    fn snapshot_serializes_to_valid_json() {
        let snap = test_snapshot();
        let json = serde_json::to_string(&snap).expect("serialize");
        assert!(json.contains("\"domain\":\"test.example.com\""));
        assert!(json.contains("\"unique_visitors\":0"));
    }

    #[test]
    fn snapshot_surfaces_utm_and_status_classes() {
        use crate::aggregation::AggEvent;
        use std::net::{IpAddr, Ipv4Addr};

        // Three requests so each status class is populated differently:
        // 2xx x2, 4xx x1, 5xx x1. UTM comes in on the first event only so
        // source/medium/campaign appear once each after ingest.
        let mut dm = DomainMetrics::new();
        let events = [
            (
                200,
                Some("utm_source=Google&utm_medium=cpc&utm_campaign=Spring_2026"),
            ),
            (201, None),
            (404, None),
            (503, None),
        ];
        for (i, (status, query)) in events.into_iter().enumerate() {
            dm.ingest_log(&AggEvent {
                host: "test.example.com".into(),
                path: "/".into(),
                query: query.map(Into::into),
                status,
                bytes_sent: 100,
                client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, i as u8 + 1)),
                country: None,
                referer: None,
                user_agent: None,
                is_bot: false,
            });
        }

        let snap = DomainMetricsSnapshot::from_metrics("test.example.com", &dm);

        // UTM fan-out: case-folded values each counted once.
        let sources: std::collections::HashMap<_, _> = snap.utm_sources.iter().cloned().collect();
        assert_eq!(sources.get("google").copied(), Some(1));
        let mediums: std::collections::HashMap<_, _> = snap.utm_mediums.iter().cloned().collect();
        assert_eq!(mediums.get("cpc").copied(), Some(1));
        let campaigns: std::collections::HashMap<_, _> =
            snap.utm_campaigns.iter().cloned().collect();
        assert_eq!(campaigns.get("spring_2026").copied(), Some(1));

        // Status classes: always all 5 labels present, in order.
        assert_eq!(snap.status_classes.len(), 5);
        let classes: std::collections::HashMap<_, _> =
            snap.status_classes.iter().cloned().collect();
        assert_eq!(classes.get("1xx").copied(), Some(0));
        assert_eq!(classes.get("2xx").copied(), Some(2));
        assert_eq!(classes.get("3xx").copied(), Some(0));
        assert_eq!(classes.get("4xx").copied(), Some(1));
        assert_eq!(classes.get("5xx").copied(), Some(1));
        // Order is stable 1xx..5xx so downstream heatmaps can rely on it.
        let labels: Vec<_> = snap
            .status_classes
            .iter()
            .map(|(l, _)| l.as_str())
            .collect();
        assert_eq!(labels, vec!["1xx", "2xx", "3xx", "4xx", "5xx"]);
    }

    #[test]
    fn empty_metrics_emit_zero_status_classes() {
        // Status classes must always surface, even when no requests
        // landed yet, so the agent can propagate a zero baseline to
        // VictoriaMetrics the moment a new domain appears.
        let snap = test_snapshot();
        assert_eq!(snap.status_classes.len(), 5);
        for (_, count) in &snap.status_classes {
            assert_eq!(*count, 0);
        }
        assert!(snap.utm_sources.is_empty());
        assert!(snap.utm_mediums.is_empty());
        assert!(snap.utm_campaigns.is_empty());
    }

    #[test]
    fn stdout_sink_does_not_panic() {
        let sink = StdoutSink;
        let snap = test_snapshot();
        sink.flush(&snap).expect("stdout flush");
    }

    #[test]
    fn socket_sink_sends_json() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let sock_path = dir.path().join("analytics.sock");
        let listener = UnixListener::bind(&sock_path).expect("bind");
        let sink = SocketSink::new(sock_path);

        let snap = test_snapshot();
        sink.flush(&snap).expect("socket flush");

        let (conn, _) = listener.accept().expect("accept");
        let reader = BufReader::new(conn);
        let line = reader.lines().next().expect("line").expect("read");
        let parsed: serde_json::Value = serde_json::from_str(&line).expect("valid JSON");
        assert_eq!(parsed["domain"], "test.example.com");
    }

    #[test]
    fn socket_down_buffers_snapshots() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let sock_path = dir.path().join("noexist.sock");
        let sink = SocketSink::new(sock_path);

        let snap = test_snapshot();
        sink.flush(&snap).expect("flush");
        sink.flush(&snap).expect("flush");

        let state = sink.state.lock();
        assert_eq!(state.buffer.len(), 2);
    }

    #[test]
    fn buffer_overflow_drops_oldest() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let sock_path = dir.path().join("overflow.sock");
        let sink = SocketSink::new(sock_path);

        let snap = test_snapshot();
        for _ in 0..MAX_BUFFER_SNAPSHOTS + 10 {
            sink.flush(&snap).expect("flush");
        }

        let state = sink.state.lock();
        assert_eq!(state.buffer.len(), MAX_BUFFER_SNAPSHOTS);
    }

    #[test]
    fn trait_is_object_safe() {
        let _: Box<dyn AnalyticsSink> = Box::new(StdoutSink);
    }

    #[test]
    fn is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<StdoutSink>();
        assert_send_sync::<SocketSink>();
    }
}
