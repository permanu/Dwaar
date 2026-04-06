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
use std::sync::Mutex;
use std::time::{Duration, Instant};

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

/// Writes JSON snapshots to a Unix domain socket.
///
/// Uses `std::sync::Mutex` (not tokio) because `flush()` is called
/// synchronously from the aggregation service's loop.
pub struct SocketSink {
    path: PathBuf,
    stream: Mutex<Option<UnixStream>>,
    buffer: Mutex<VecDeque<Vec<u8>>>,
    last_attempt: Mutex<Option<Instant>>,
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
            stream: Mutex::new(None),
            buffer: Mutex::new(VecDeque::new()),
            last_attempt: Mutex::new(None),
        }
    }

    fn try_connect(&self) -> Option<UnixStream> {
        let mut last = self
            .last_attempt
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(t) = *last
            && t.elapsed() < RECONNECT_DELAY
        {
            return None;
        }
        *last = Some(Instant::now());
        drop(last);

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

        let mut stream_guard = self
            .stream
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut buffer_guard = self
            .buffer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if stream_guard.is_none()
            && let Some(new_stream) = self.try_connect()
        {
            *stream_guard = Some(new_stream);
        }

        if let Some(ref mut stream) = *stream_guard {
            Self::drain_buffer(stream, &mut buffer_guard);

            if !Self::write_line(stream, &line) {
                *stream_guard = None;
                Self::enqueue(&mut buffer_guard, line);
            }
        } else {
            Self::enqueue(&mut buffer_guard, line);
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
    }

    #[test]
    fn snapshot_serializes_to_valid_json() {
        let snap = test_snapshot();
        let json = serde_json::to_string(&snap).expect("serialize");
        assert!(json.contains("\"domain\":\"test.example.com\""));
        assert!(json.contains("\"unique_visitors\":0"));
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

        let buffer = sink.buffer.lock().expect("lock");
        assert_eq!(buffer.len(), 2);
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

        let buffer = sink.buffer.lock().expect("lock");
        assert_eq!(buffer.len(), MAX_BUFFER_SNAPSHOTS);
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
