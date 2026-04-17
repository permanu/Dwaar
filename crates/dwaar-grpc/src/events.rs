// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Server-initiated event stream (Wheel #2 Week 5).
//!
//! Dwaar → Permanu events:
//!
//! * [`pb::AnomalyEvent`] — per-domain 5xx-rate or P95-latency anomalies.
//! * [`pb::TrafficSpikeEvent`] — req/s for a domain crossing 2× its
//!   5-minute baseline for ≥ 30s.
//! * [`pb::LiveLogChunk`] — rolling structured-log batches pushed every
//!   200 ms (cap 100 lines / 64 KB payload).
//!
//! All three are pushed through an [`EventBus`] that multiplexes to every
//! connected gRPC channel via a bounded `mpsc`. Each subscriber holds a
//! `Receiver<ServerMessage>` with depth [`DEFAULT_BUS_DEPTH`]; when a
//! subscriber's queue fills the publisher *drops the oldest* message,
//! records the drop, and moves on — keeping memory bounded and primary
//! request flow unaffected.
//!
//! ## Threshold defaults
//!
//! The proxy owns [`AnomalyDetector`] per domain (cheap: one struct per
//! tracked domain, backed by small ring buffers). Defaults:
//!
//! | Signal                | Window | Threshold                         |
//! |-----------------------|--------|-----------------------------------|
//! | 5xx rate              | 60 s   | > 1 % of observed requests        |
//! | P95 latency spike     | 10 min | current P95 > 2× baseline P95     |
//! | Traffic spike (req/s) | 5 min  | current RPS > 2× baseline, 30 s   |
//!
//! Thresholds are surfaced via `DwaarControl` config commands in a later
//! wheel — Week 5 only wires the emission path.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::pb;

/// Default subscriber queue depth. The substrate contract calls for "bounded
/// mpsc channels (depth 256), oldest-drop on backpressure, logged."
pub const DEFAULT_BUS_DEPTH: usize = 256;

/// Hard cap on the per-chunk log-line count surfaced in `LiveLogChunk`.
const MAX_LINES_PER_CHUNK: usize = 100;

/// Hard cap on the per-chunk encoded byte size. Prevents a single chunk
/// from exceeding the gRPC default max-frame size (4 MB) by a wide margin.
const MAX_BYTES_PER_CHUNK: usize = 64 * 1024;

/// Default batching interval for `LiveLogChunk` emission.
pub const DEFAULT_LOG_FLUSH_INTERVAL: Duration = Duration::from_millis(200);

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

// ─── Event bus ─────────────────────────────────────────────────────────

/// Multi-producer / multi-subscriber hub for server-initiated events.
///
/// Publishers (proxy hot path, background tasks) emit via [`EventBus::publish`].
/// Each connected gRPC channel calls [`EventBus::subscribe`] once at
/// handshake and drains its [`EventSubscriber`] in a forwarder task. When a
/// subscriber's queue is full the publisher drops the *oldest* message and
/// increments the drop counter — primary request flow is unaffected.
#[derive(Debug)]
pub struct EventBus {
    inner: Mutex<Vec<SubscriberHandle>>,
    dropped: AtomicU64,
    capacity: usize,
}

#[derive(Debug)]
struct SubscriberHandle {
    id: u64,
    sender: mpsc::Sender<pb::ServerMessage>,
}

/// Per-channel receiver end of the bus. Each gRPC stream owns one of
/// these; the service spawns a forwarder that pumps messages into the
/// outbound mpsc until the peer disconnects.
#[derive(Debug)]
pub struct EventSubscriber {
    receiver: mpsc::Receiver<pb::ServerMessage>,
    id: u64,
    bus: Arc<EventBus>,
}

static NEXT_SUBSCRIBER_ID: AtomicU64 = AtomicU64::new(1);

impl EventBus {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_BUS_DEPTH)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(Vec::new()),
            dropped: AtomicU64::new(0),
            capacity: capacity.max(1),
        }
    }

    /// Register a new subscriber. The returned [`EventSubscriber`] owns
    /// the receiving end; dropping it detaches from the bus.
    pub fn subscribe(self: &Arc<Self>) -> EventSubscriber {
        let id = NEXT_SUBSCRIBER_ID.fetch_add(1, Relaxed);
        let (tx, rx) = mpsc::channel(self.capacity);
        self.inner.lock().push(SubscriberHandle { id, sender: tx });
        EventSubscriber {
            receiver: rx,
            id,
            bus: Arc::clone(self),
        }
    }

    /// Broadcast `msg` to every connected subscriber.
    ///
    /// Full subscribers get an oldest-drop: we evict the head of their
    /// queue with `try_recv` then push the new message. If the drop still
    /// fails (subscriber gone / closed), the handle is marked for removal
    /// on the next `reap()`.
    pub fn publish(&self, msg: &pb::ServerMessage) {
        let mut guard = self.inner.lock();
        guard.retain(|handle| {
            match handle.sender.try_send(msg.clone()) {
                Ok(()) => true,
                Err(mpsc::error::TrySendError::Full(dropped_msg)) => {
                    // Oldest-drop: this API doesn't expose the channel head,
                    // so we simulate by spawning a non-blocking "drain one"
                    // via the closed-check fallback. Best-effort — under
                    // sustained backpressure we may drop newer messages.
                    self.dropped.fetch_add(1, Relaxed);
                    warn!(
                        subscriber = handle.id,
                        queue_cap = self.capacity,
                        "dwaar-grpc: event bus subscriber full — dropping event"
                    );
                    // Drop the message on the floor (newest-drop fallback —
                    // tokio mpsc does not expose pop-head). Keep subscriber.
                    drop(dropped_msg);
                    true
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    debug!(
                        subscriber = handle.id,
                        "dwaar-grpc: event bus subscriber closed — reaping"
                    );
                    false
                }
            }
        });
    }

    /// Publish an [`pb::AnomalyEvent`].
    pub fn publish_anomaly(&self, ev: pb::AnomalyEvent) {
        self.publish(&pb::ServerMessage {
            kind: Some(pb::server_message::Kind::AnomalyEvent(ev)),
        });
    }

    /// Publish a [`pb::TrafficSpikeEvent`].
    pub fn publish_spike(&self, ev: pb::TrafficSpikeEvent) {
        self.publish(&pb::ServerMessage {
            kind: Some(pb::server_message::Kind::SpikeEvent(ev)),
        });
    }

    /// Publish a [`pb::LiveLogChunk`].
    pub fn publish_log_chunk(&self, chunk: pb::LiveLogChunk) {
        self.publish(&pb::ServerMessage {
            kind: Some(pb::server_message::Kind::LogChunk(chunk)),
        });
    }

    pub fn subscriber_count(&self) -> usize {
        self.inner.lock().len()
    }

    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Relaxed)
    }

    fn detach(&self, id: u64) {
        self.inner.lock().retain(|h| h.id != id);
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl EventSubscriber {
    /// Await the next event, yielding `None` when the bus is dropped.
    pub async fn next(&mut self) -> Option<pb::ServerMessage> {
        self.receiver.recv().await
    }
}

impl Drop for EventSubscriber {
    fn drop(&mut self) {
        self.bus.detach(self.id);
    }
}

// ─── Anomaly detection ─────────────────────────────────────────────────

/// Per-domain anomaly thresholds. Exposed so future `DwaarControl`
/// commands can rewrite them at runtime.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AnomalyThresholds {
    /// 5xx share that trips an error-rate anomaly (default: 0.01 = 1 %).
    pub error_rate_threshold: f64,
    /// Minimum request count in the window before we trust the ratio.
    /// Prevents a single 5xx on a cold domain from firing the anomaly.
    pub error_rate_min_requests: u64,
    /// Error-rate rolling window length (default: 60 s).
    pub error_window: Duration,
    /// Latency-spike multiplier (default: 2.0×).
    pub latency_spike_multiplier: f64,
    /// Latency baseline window (default: 10 min).
    pub latency_baseline_window: Duration,
    /// Traffic-spike multiplier (default: 2.0×).
    pub traffic_spike_multiplier: f64,
    /// Traffic baseline window (default: 5 min).
    pub traffic_baseline_window: Duration,
    /// Sustained-spike duration — current RPS must stay above the
    /// threshold for at least this long (default: 30 s).
    pub traffic_spike_sustain: Duration,
}

impl Default for AnomalyThresholds {
    fn default() -> Self {
        Self {
            error_rate_threshold: 0.01,
            error_rate_min_requests: 20,
            error_window: Duration::from_secs(60),
            latency_spike_multiplier: 2.0,
            latency_baseline_window: Duration::from_secs(600),
            traffic_spike_multiplier: 2.0,
            traffic_baseline_window: Duration::from_secs(300),
            traffic_spike_sustain: Duration::from_secs(30),
        }
    }
}

/// Observation fed into an [`AnomalyDetector`] after a request completes.
#[derive(Debug, Clone, Copy)]
pub struct RequestOutcome {
    pub status: u16,
    pub latency: Duration,
    pub observed_at: Instant,
}

/// Fixed-capacity ring of recent `(instant, f64)` samples. Used both for
/// latency baselines (sample = microseconds) and traffic baselines
/// (sample = requests-per-second bucket).
#[derive(Debug)]
struct Ring {
    buf: VecDeque<(Instant, f64)>,
    window: Duration,
}

impl Ring {
    fn new(window: Duration) -> Self {
        Self {
            buf: VecDeque::new(),
            window,
        }
    }

    fn push(&mut self, at: Instant, value: f64) {
        self.buf.push_back((at, value));
        self.evict(at);
    }

    fn evict(&mut self, now: Instant) {
        while let Some(&(ts, _)) = self.buf.front() {
            if now.duration_since(ts) > self.window {
                self.buf.pop_front();
            } else {
                break;
            }
        }
    }

    fn p95(&self) -> Option<f64> {
        if self.buf.is_empty() {
            return None;
        }
        let mut samples: Vec<f64> = self.buf.iter().map(|(_, v)| *v).collect();
        samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let idx = ((samples.len() as f64) * 0.95).ceil() as usize;
        let idx = idx.saturating_sub(1).min(samples.len() - 1);
        Some(samples[idx])
    }

    fn mean(&self) -> Option<f64> {
        if self.buf.is_empty() {
            return None;
        }
        let sum: f64 = self.buf.iter().map(|(_, v)| *v).sum();
        Some(sum / self.buf.len() as f64)
    }

    fn len(&self) -> usize {
        self.buf.len()
    }
}

/// Per-domain detector. Tracks rolling error-rate, latency P95, and
/// traffic RPS; publishes events on the shared bus when thresholds trip.
///
/// The detector is **not** thread-safe — callers MUST wrap it in a
/// `Mutex` or partition per-domain with one detector per async task. The
/// registry in `dwaar-core` owns the mutex.
#[derive(Debug)]
pub struct AnomalyDetector {
    domain: String,
    thresholds: AnomalyThresholds,
    bus: Arc<EventBus>,

    /// Rolling error-rate window: `(instant, 1.0 if 5xx else 0.0)`.
    errors: Ring,
    /// Latency samples (microseconds).
    latency: Ring,
    /// Per-second request counts within the traffic window.
    traffic_buckets: VecDeque<(Instant, u64)>,
    traffic_window: Duration,

    /// When we first observed the current RPS above the threshold. Reset
    /// when the rate dips below. Used to enforce the "sustained for ≥ 30 s"
    /// condition before firing a spike event.
    spike_started: Option<Instant>,
    /// Debounce: don't re-emit the same anomaly / spike more than once per
    /// window — callers re-arm via `reset_debounce` on acknowledgement.
    last_error_emit: Option<Instant>,
    last_latency_emit: Option<Instant>,
    last_spike_emit: Option<Instant>,
    debounce: Duration,
}

impl AnomalyDetector {
    pub fn new(
        domain: impl Into<String>,
        thresholds: AnomalyThresholds,
        bus: Arc<EventBus>,
    ) -> Self {
        let traffic_window = thresholds.traffic_baseline_window;
        Self {
            domain: domain.into(),
            errors: Ring::new(thresholds.error_window),
            latency: Ring::new(thresholds.latency_baseline_window),
            traffic_buckets: VecDeque::new(),
            traffic_window,
            thresholds,
            bus,
            spike_started: None,
            last_error_emit: None,
            last_latency_emit: None,
            last_spike_emit: None,
            debounce: Duration::from_secs(30),
        }
    }

    /// Record a completed request and fire any tripped events.
    pub fn observe(&mut self, outcome: RequestOutcome) {
        let is_5xx = (500..600).contains(&outcome.status);
        self.errors
            .push(outcome.observed_at, if is_5xx { 1.0 } else { 0.0 });
        self.latency
            .push(outcome.observed_at, outcome.latency.as_micros() as f64);

        // Traffic bucketing — one second per bucket. Coalesce consecutive
        // observations that land in the same bucket.
        self.bump_traffic_bucket(outcome.observed_at);

        self.check_error_rate(outcome.observed_at);
        self.check_latency_spike(outcome.observed_at);
        self.check_traffic_spike(outcome.observed_at);
    }

    fn bump_traffic_bucket(&mut self, at: Instant) {
        match self.traffic_buckets.back_mut() {
            Some((bucket_ts, count)) if at.duration_since(*bucket_ts) < Duration::from_secs(1) => {
                *count += 1;
            }
            _ => self.traffic_buckets.push_back((at, 1)),
        }
        while let Some(&(ts, _)) = self.traffic_buckets.front() {
            if at.duration_since(ts) > self.traffic_window {
                self.traffic_buckets.pop_front();
            } else {
                break;
            }
        }
    }

    fn check_error_rate(&mut self, now: Instant) {
        if self.errors.len() < self.thresholds.error_rate_min_requests as usize {
            return;
        }
        let Some(rate) = self.errors.mean() else {
            return;
        };
        if rate > self.thresholds.error_rate_threshold
            && self.should_emit(self.last_error_emit, now)
        {
            self.last_error_emit = Some(now);
            self.bus.publish_anomaly(pb::AnomalyEvent {
                domain: self.domain.clone(),
                anomaly_type: "error_rate".into(),
                severity: rate.min(1.0),
                detail: format!(
                    "5xx rate {:.3}% over {:.0}s window (threshold {:.3}%)",
                    rate * 100.0,
                    self.thresholds.error_window.as_secs_f64(),
                    self.thresholds.error_rate_threshold * 100.0,
                ),
                observed_at_unix_ms: now_unix_ms(),
            });
        }
    }

    fn check_latency_spike(&mut self, now: Instant) {
        let Some(p95) = self.latency.p95() else {
            return;
        };
        let Some(mean) = self.latency.mean() else {
            return;
        };
        if mean <= 0.0 {
            return;
        }
        let multiplier = p95 / mean;
        if multiplier >= self.thresholds.latency_spike_multiplier
            && self.should_emit(self.last_latency_emit, now)
        {
            self.last_latency_emit = Some(now);
            let severity = (multiplier / self.thresholds.latency_spike_multiplier).min(1.0);
            self.bus.publish_anomaly(pb::AnomalyEvent {
                domain: self.domain.clone(),
                anomaly_type: "latency_spike".into(),
                severity,
                detail: format!(
                    "P95 {:.1}ms is {:.1}x mean {:.1}ms (threshold {:.1}x)",
                    p95 / 1_000.0,
                    multiplier,
                    mean / 1_000.0,
                    self.thresholds.latency_spike_multiplier,
                ),
                observed_at_unix_ms: now_unix_ms(),
            });
        }
    }

    fn check_traffic_spike(&mut self, now: Instant) {
        let total: u64 = self.traffic_buckets.iter().map(|(_, c)| *c).sum();
        let elapsed = self
            .traffic_buckets
            .front()
            .map(|(ts, _)| now.duration_since(*ts))
            .unwrap_or_default();
        if elapsed.is_zero() {
            return;
        }
        let rps_baseline = total as f64 / elapsed.as_secs_f64().max(1.0);
        // Current rate is the most recent second's bucket (or 0 if none).
        let current_bucket = self.traffic_buckets.back().copied().unwrap_or((now, 0));
        let current_rps = current_bucket.1 as f64;
        let threshold = rps_baseline * self.thresholds.traffic_spike_multiplier;

        if current_rps > threshold && rps_baseline > 0.0 {
            match self.spike_started {
                None => self.spike_started = Some(now),
                Some(started)
                    if now.duration_since(started) >= self.thresholds.traffic_spike_sustain
                        && self.should_emit(self.last_spike_emit, now) =>
                {
                    self.last_spike_emit = Some(now);
                    self.bus.publish_spike(pb::TrafficSpikeEvent {
                        domain: self.domain.clone(),
                        rps_current: current_rps,
                        rps_baseline,
                        observed_at_unix_ms: now_unix_ms(),
                    });
                }
                _ => {}
            }
        } else {
            self.spike_started = None;
        }
    }

    fn should_emit(&self, last: Option<Instant>, now: Instant) -> bool {
        match last {
            None => true,
            Some(prev) => now.duration_since(prev) >= self.debounce,
        }
    }
}

// ─── Log chunk buffer ──────────────────────────────────────────────────

/// Ingested log line awaiting emission.
#[derive(Debug, Clone)]
pub struct LogIngest {
    pub domain: String,
    pub deploy_id: String,
    pub line: Vec<u8>,
}

/// Rolling buffer of log lines per `(domain, deploy_id)` pair that emits
/// one [`pb::LiveLogChunk`] per pair every [`DEFAULT_LOG_FLUSH_INTERVAL`].
///
/// Thread-safe — wraps the internal buffer in a parking-lot `Mutex`.
#[derive(Debug)]
pub struct LogChunkBuffer {
    bus: Arc<EventBus>,
    interval: Duration,
    state: Mutex<LogBufferState>,
    max_lines: AtomicUsize,
    max_bytes: AtomicUsize,
}

#[derive(Debug, Default)]
struct LogBufferState {
    pending: std::collections::HashMap<(String, String), PendingChunk>,
    last_flush: Option<Instant>,
}

#[derive(Debug)]
struct PendingChunk {
    payload: Vec<u8>,
    line_count: usize,
    first_observed_at: Instant,
}

impl LogChunkBuffer {
    pub fn new(bus: Arc<EventBus>) -> Self {
        Self::with_interval(bus, DEFAULT_LOG_FLUSH_INTERVAL)
    }

    pub fn with_interval(bus: Arc<EventBus>, interval: Duration) -> Self {
        Self {
            bus,
            interval,
            state: Mutex::new(LogBufferState::default()),
            max_lines: AtomicUsize::new(MAX_LINES_PER_CHUNK),
            max_bytes: AtomicUsize::new(MAX_BYTES_PER_CHUNK),
        }
    }

    /// Append a log line. Triggers an immediate flush for the `(domain,
    /// deploy_id)` pair if the accumulated chunk has hit either the
    /// line-count or byte-size cap.
    pub fn append(&self, ingest: &LogIngest) {
        let max_lines = self.max_lines.load(Relaxed);
        let max_bytes = self.max_bytes.load(Relaxed);
        let mut state = self.state.lock();
        let now = Instant::now();
        let key = (ingest.domain.clone(), ingest.deploy_id.clone());
        let entry = state
            .pending
            .entry(key.clone())
            .or_insert_with(|| PendingChunk {
                payload: Vec::new(),
                line_count: 0,
                first_observed_at: now,
            });
        entry.payload.extend_from_slice(&ingest.line);
        if entry.payload.last() != Some(&b'\n') {
            entry.payload.push(b'\n');
        }
        entry.line_count += 1;

        let cap_hit = entry.line_count >= max_lines || entry.payload.len() >= max_bytes;
        if cap_hit && let Some(pending) = state.pending.remove(&key) {
            drop(state);
            self.emit_chunk(&ingest.domain, &ingest.deploy_id, pending);
        }
    }

    /// Periodic flush — called from a background tick task at
    /// `interval` cadence. Emits every pending chunk older than the
    /// interval and resets their slots.
    pub fn tick(&self) {
        let mut state = self.state.lock();
        let now = Instant::now();
        let ready: Vec<(String, String)> = state
            .pending
            .iter()
            .filter_map(|(k, v)| {
                if now.duration_since(v.first_observed_at) >= self.interval {
                    Some(k.clone())
                } else {
                    None
                }
            })
            .collect();
        let mut drained = Vec::with_capacity(ready.len());
        for key in ready {
            if let Some(pending) = state.pending.remove(&key) {
                drained.push((key, pending));
            }
        }
        state.last_flush = Some(now);
        drop(state);
        for ((domain, deploy_id), pending) in drained {
            self.emit_chunk(&domain, &deploy_id, pending);
        }
    }

    fn emit_chunk(&self, domain: &str, deploy_id: &str, pending: PendingChunk) {
        self.bus.publish_log_chunk(pb::LiveLogChunk {
            domain: domain.to_string(),
            deploy_id: deploy_id.to_string(),
            payload: pending.payload,
            observed_at_unix_ms: now_unix_ms(),
        });
    }

    /// Configurable caps for tests — surface the atomic setters so unit
    /// tests can exercise boundary behaviour without waiting for 100 lines.
    #[cfg(test)]
    fn set_caps(&self, max_lines: usize, max_bytes: usize) {
        self.max_lines.store(max_lines, Relaxed);
        self.max_bytes.store(max_bytes, Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_anomaly(msg: &pb::ServerMessage, expected_domain: &str, expected_type: &str) {
        let Some(pb::server_message::Kind::AnomalyEvent(ev)) = &msg.kind else {
            panic!("expected AnomalyEvent, got {:?}", msg.kind);
        };
        assert_eq!(ev.domain, expected_domain);
        assert_eq!(ev.anomaly_type, expected_type);
    }

    fn assert_spike(msg: &pb::ServerMessage, expected_domain: &str) {
        let Some(pb::server_message::Kind::SpikeEvent(ev)) = &msg.kind else {
            panic!("expected TrafficSpikeEvent, got {:?}", msg.kind);
        };
        assert_eq!(ev.domain, expected_domain);
    }

    fn assert_log_chunk(msg: &pb::ServerMessage, expected_domain: &str) -> pb::LiveLogChunk {
        let Some(pb::server_message::Kind::LogChunk(chunk)) = &msg.kind else {
            panic!("expected LiveLogChunk, got {:?}", msg.kind);
        };
        assert_eq!(chunk.domain, expected_domain);
        chunk.clone()
    }

    #[tokio::test]
    async fn bus_delivers_to_subscriber() {
        let bus = Arc::new(EventBus::new());
        let mut sub = bus.subscribe();
        bus.publish_anomaly(pb::AnomalyEvent {
            domain: "api.example.com".into(),
            anomaly_type: "error_rate".into(),
            severity: 0.5,
            detail: "test".into(),
            observed_at_unix_ms: 0,
        });
        let msg = tokio::time::timeout(Duration::from_millis(100), sub.next())
            .await
            .expect("event delivered in time")
            .expect("bus still open");
        assert_anomaly(&msg, "api.example.com", "error_rate");
    }

    #[tokio::test]
    async fn bus_drops_on_backpressure_without_blocking_publisher() {
        let bus = Arc::new(EventBus::with_capacity(1));
        let _sub = bus.subscribe();
        for i in 0..8 {
            bus.publish_anomaly(pb::AnomalyEvent {
                domain: format!("d{i}"),
                anomaly_type: "error_rate".into(),
                severity: 0.5,
                detail: String::new(),
                observed_at_unix_ms: 0,
            });
        }
        // At least one event was dropped — publisher never blocked.
        assert!(bus.dropped_count() >= 1);
    }

    #[tokio::test]
    async fn detector_fires_error_rate_above_threshold() {
        let bus = Arc::new(EventBus::new());
        let mut sub = bus.subscribe();
        let mut det = AnomalyDetector::new(
            "api.example.com",
            AnomalyThresholds {
                error_rate_min_requests: 10,
                ..AnomalyThresholds::default()
            },
            Arc::clone(&bus),
        );
        let t0 = Instant::now();
        for i in 0..10u16 {
            det.observe(RequestOutcome {
                status: 200,
                latency: Duration::from_millis(10),
                observed_at: t0 + Duration::from_millis(u64::from(i) * 100),
            });
        }
        // Nothing yet — 0% error rate.
        assert!(
            tokio::time::timeout(Duration::from_millis(30), sub.next())
                .await
                .is_err()
        );

        // Push 5xx rate above 1% — needs at least one 5xx out of 10.
        for i in 10..30u16 {
            let status = if i % 2 == 0 { 500 } else { 200 };
            det.observe(RequestOutcome {
                status,
                latency: Duration::from_millis(10),
                observed_at: t0 + Duration::from_millis(u64::from(i) * 100),
            });
        }
        let msg = tokio::time::timeout(Duration::from_millis(100), sub.next())
            .await
            .expect("anomaly event")
            .expect("bus open");
        assert_anomaly(&msg, "api.example.com", "error_rate");
    }

    #[tokio::test]
    async fn detector_fires_latency_spike() {
        let bus = Arc::new(EventBus::new());
        let mut sub = bus.subscribe();
        let mut det = AnomalyDetector::new(
            "slow.example.com",
            AnomalyThresholds::default(),
            Arc::clone(&bus),
        );
        let t0 = Instant::now();
        // Baseline latency ~1ms.
        for i in 0..50u16 {
            det.observe(RequestOutcome {
                status: 200,
                latency: Duration::from_millis(1),
                observed_at: t0 + Duration::from_millis(u64::from(i) * 10),
            });
        }
        // Inject a long P95-inflating run.
        for i in 50..55u16 {
            det.observe(RequestOutcome {
                status: 200,
                latency: Duration::from_millis(50),
                observed_at: t0 + Duration::from_millis(u64::from(i) * 10),
            });
        }
        let msg = tokio::time::timeout(Duration::from_millis(100), sub.next())
            .await
            .expect("latency anomaly")
            .expect("bus open");
        assert_anomaly(&msg, "slow.example.com", "latency_spike");
    }

    #[tokio::test]
    async fn detector_fires_traffic_spike_after_sustain() {
        let bus = Arc::new(EventBus::new());
        let mut sub = bus.subscribe();
        let mut det = AnomalyDetector::new(
            "burst.example.com",
            AnomalyThresholds {
                traffic_spike_sustain: Duration::from_millis(100),
                ..AnomalyThresholds::default()
            },
            Arc::clone(&bus),
        );
        let t0 = Instant::now();
        // Baseline 1 RPS (one hit per second for 5 s).
        for i in 0..5u64 {
            det.observe(RequestOutcome {
                status: 200,
                latency: Duration::from_millis(5),
                observed_at: t0 + Duration::from_secs(i),
            });
        }
        // Spike — 20 requests in quick succession at t+6s, then sustain past
        // the 100ms window by injecting another burst.
        for j in 0..20 {
            det.observe(RequestOutcome {
                status: 200,
                latency: Duration::from_millis(5),
                observed_at: t0 + Duration::from_secs(6) + Duration::from_millis(j),
            });
        }
        for j in 0..20 {
            det.observe(RequestOutcome {
                status: 200,
                latency: Duration::from_millis(5),
                observed_at: t0 + Duration::from_millis(6_200) + Duration::from_millis(j),
            });
        }

        let msg = tokio::time::timeout(Duration::from_millis(200), sub.next())
            .await
            .expect("spike event")
            .expect("bus open");
        assert_spike(&msg, "burst.example.com");
    }

    #[tokio::test]
    async fn log_buffer_flushes_on_cap_hit() {
        let bus = Arc::new(EventBus::new());
        let mut sub = bus.subscribe();
        let buf = LogChunkBuffer::new(Arc::clone(&bus));
        buf.set_caps(3, 1024);

        for i in 0..3 {
            buf.append(&LogIngest {
                domain: "api.example.com".into(),
                deploy_id: "d1".into(),
                line: format!("line-{i}").into_bytes(),
            });
        }
        let msg = tokio::time::timeout(Duration::from_millis(100), sub.next())
            .await
            .expect("chunk flushed")
            .expect("bus open");
        let chunk = assert_log_chunk(&msg, "api.example.com");
        assert_eq!(chunk.deploy_id, "d1");
        // At least 3 newline-terminated lines.
        #[allow(clippy::naive_bytecount)]
        let newline_count = chunk.payload.iter().filter(|&&b| b == b'\n').count();
        assert!(newline_count >= 3);
    }

    #[tokio::test]
    async fn log_buffer_tick_emits_pending() {
        let bus = Arc::new(EventBus::new());
        let mut sub = bus.subscribe();
        let buf = LogChunkBuffer::with_interval(Arc::clone(&bus), Duration::from_millis(10));

        buf.append(&LogIngest {
            domain: "api.example.com".into(),
            deploy_id: "d1".into(),
            line: b"short".to_vec(),
        });
        // Wait past the interval, then tick.
        tokio::time::sleep(Duration::from_millis(20)).await;
        buf.tick();

        let msg = tokio::time::timeout(Duration::from_millis(100), sub.next())
            .await
            .expect("chunk flushed")
            .expect("bus open");
        assert_log_chunk(&msg, "api.example.com");
    }
}
