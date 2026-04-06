// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Prometheus metrics — atomic counters, histograms, and text exposition.
//!
//! All metric types use lock-free atomics. Per-domain metrics are keyed by
//! `CompactString` in `DashMap` for concurrent access without allocation
//! after the first request per domain.

use std::fmt::Write;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed};

use compact_str::CompactString;
use dashmap::DashMap;

// -- Histogram bucket bounds (microseconds) ----------------------------------
// Matches the issue spec: 5ms, 10ms, 25ms, 50ms, 100ms, 250ms, 500ms, 1s,
// 2.5s, 5s, 10s. Stored as microseconds to avoid atomic-float issues.
const BUCKET_BOUNDS_US: &[u64] = &[
    5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000, 1_000_000, 2_500_000, 5_000_000,
    10_000_000,
];

// Bucket bounds as seconds (for rendering)
const BUCKET_BOUNDS_SECS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// A Prometheus histogram with pre-allocated buckets.
///
/// Observations are recorded in microseconds internally and converted to
/// seconds during text rendering. Each bucket count and the sum/total are
/// atomic — no locks, no allocation per observation.
pub struct Histogram {
    /// One counter per bucket boundary, plus one for +Inf.
    bucket_counts: Box<[AtomicU64]>,
    /// Running sum of all observed values in microseconds.
    sum_us: AtomicU64,
    /// Total number of observations.
    count: AtomicU64,
}

impl std::fmt::Debug for Histogram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Histogram")
            .field("count", &self.count.load(Relaxed))
            .field("sum_us", &self.sum_us.load(Relaxed))
            .finish_non_exhaustive()
    }
}

impl Default for Histogram {
    fn default() -> Self {
        Self::new()
    }
}

impl Histogram {
    pub fn new() -> Self {
        // +1 for the +Inf bucket
        let num_buckets = BUCKET_BOUNDS_US.len() + 1;
        let mut buckets = Vec::with_capacity(num_buckets);
        for _ in 0..num_buckets {
            buckets.push(AtomicU64::new(0));
        }
        Self {
            bucket_counts: buckets.into_boxed_slice(),
            sum_us: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    /// Record an observation in microseconds.
    ///
    /// Stores a **non-cumulative** per-bucket count — exactly 1 bucket is
    /// incremented per observation (3 atomic ops total). Cumulative totals
    /// required by Prometheus are derived in [`snapshot()`] on the rare
    /// `/metrics` scrape path, not on the hot request path.
    pub fn observe(&self, value_us: u64) {
        let idx = BUCKET_BOUNDS_US
            .iter()
            .position(|&bound| value_us <= bound)
            .unwrap_or(BUCKET_BOUNDS_US.len()); // +Inf bucket
        self.bucket_counts[idx].fetch_add(1, Relaxed);
        self.sum_us.fetch_add(value_us, Relaxed);
        self.count.fetch_add(1, Relaxed);
    }

    /// Snapshot as cumulative buckets (Prometheus wire format), sum, and count.
    fn snapshot(&self) -> HistogramSnapshot {
        let raw: Vec<u64> = self.bucket_counts.iter().map(|c| c.load(Relaxed)).collect();
        let mut cumulative = Vec::with_capacity(raw.len());
        let mut running = 0u64;
        for &count in &raw {
            running += count;
            cumulative.push(running);
        }
        HistogramSnapshot {
            buckets: cumulative,
            sum_secs: self.sum_us.load(Relaxed) as f64 / 1_000_000.0,
            count: self.count.load(Relaxed),
        }
    }
}

struct HistogramSnapshot {
    /// Cumulative counts per bucket (last entry is +Inf).
    buckets: Vec<u64>,
    sum_secs: f64,
    count: u64,
}

// -- Status × Method counters ------------------------------------------------

/// HTTP method slots — 8 covers all standard methods plus OTHER.
const METHOD_COUNT: usize = 8;
/// Status group slots — 1xx through 5xx.
const STATUS_GROUP_COUNT: usize = 5;
const COUNTER_SLOTS: usize = STATUS_GROUP_COUNT * METHOD_COUNT;

fn method_index(method: &str) -> usize {
    match method {
        "GET" => 0,
        "POST" => 1,
        "PUT" => 2,
        "DELETE" => 3,
        "PATCH" => 4,
        "HEAD" => 5,
        "OPTIONS" => 6,
        _ => 7, // OTHER
    }
}

fn status_group(status: u16) -> usize {
    match status {
        100..=199 => 0,
        200..=299 => 1,
        300..=399 => 2,
        400..=499 => 3,
        _ => 4, // 5xx and anything unexpected
    }
}

const METHODS: &[&str] = &[
    "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "OTHER",
];
const STATUS_CODES: &[&str] = &["1xx", "2xx", "3xx", "4xx", "5xx"];

/// Pre-allocated counters for every (`status_group`, method) combination.
///
/// 5 status groups × 8 methods = 40 `AtomicU64` slots. Zero allocation
/// per request — just index math and an atomic increment.
pub struct StatusMethodCounters {
    counts: [AtomicU64; COUNTER_SLOTS],
}

impl std::fmt::Debug for StatusMethodCounters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StatusMethodCounters")
            .field("total", &self.total())
            .finish()
    }
}

impl Default for StatusMethodCounters {
    fn default() -> Self {
        Self::new()
    }
}

impl StatusMethodCounters {
    pub fn new() -> Self {
        Self {
            counts: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    /// Increment the counter for the given status code and method.
    pub fn increment(&self, status: u16, method: &str) {
        let idx = status_group(status) * METHOD_COUNT + method_index(method);
        self.counts[idx].fetch_add(1, Relaxed);
    }

    fn total(&self) -> u64 {
        self.counts.iter().map(|c| c.load(Relaxed)).sum()
    }
}

// -- Top-level metrics registry ----------------------------------------------

/// Maximum number of distinct domains tracked in per-domain `DashMap`s.
/// Beyond this limit new domains are silently dropped to prevent unbounded
/// memory growth in multi-tenant or wildcard setups.
const MAX_TRACKED_DOMAINS: usize = 10_000;

/// Per-domain request metrics bundled into a single struct.
///
/// One `DashMap` lookup per request instead of four — reduces lock contention
/// by ~75% under high concurrency.
pub struct DomainRequestMetrics {
    pub requests: StatusMethodCounters,
    pub duration: Histogram,
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
}

impl std::fmt::Debug for DomainRequestMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DomainRequestMetrics")
            .field("total_requests", &self.requests.total())
            .finish_non_exhaustive()
    }
}

impl Default for DomainRequestMetrics {
    fn default() -> Self {
        Self {
            requests: StatusMethodCounters::new(),
            duration: Histogram::new(),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
        }
    }
}

/// All Prometheus metrics for the Dwaar proxy.
///
/// Created once in `main()`, passed as `Arc<PrometheusMetrics>` to both
/// `DwaarProxy` (writes in `logging()`) and `AdminService` (reads on
/// `GET /metrics`).
pub struct PrometheusMetrics {
    /// Per-domain request metrics — single `DashMap` for the hot path.
    pub domains: DashMap<CompactString, DomainRequestMetrics>,
    /// Active connections gauge — separate because it has a different
    /// lifecycle (`connection_start`/`connection_end` vs per-request record).
    pub active_connections: DashMap<CompactString, AtomicI64>,

    // Per-upstream
    pub upstream_connect_duration: DashMap<CompactString, Histogram>,
    pub upstream_health: DashMap<CompactString, AtomicU64>,

    // Global
    pub tls_handshake_duration: Histogram,
    pub config_reloads_success: AtomicU64,
    pub config_reloads_failure: AtomicU64,

    // ISSUE-113: standard process metrics (CPU, RSS, FDs, threads)
    pub process: crate::process_metrics::ProcessMetrics,

    // ISSUE-114: rate limiter + cache counters
    pub rate_cache: crate::rate_cache_metrics::RateCacheMetrics,
}

impl std::fmt::Debug for PrometheusMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrometheusMetrics")
            .field("domains_tracked", &self.domains.len())
            .finish_non_exhaustive()
    }
}

impl Default for PrometheusMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl PrometheusMetrics {
    pub fn new() -> Self {
        Self {
            domains: DashMap::new(),
            active_connections: DashMap::new(),
            upstream_connect_duration: DashMap::new(),
            upstream_health: DashMap::new(),
            tls_handshake_duration: Histogram::new(),
            config_reloads_success: AtomicU64::new(0),
            config_reloads_failure: AtomicU64::new(0),
            process: crate::process_metrics::ProcessMetrics::new(),
            rate_cache: crate::rate_cache_metrics::RateCacheMetrics::new(),
        }
    }

    fn domain_within_limit(&self, domain: &CompactString) -> bool {
        self.domains.contains_key(domain) || self.domains.len() < MAX_TRACKED_DOMAINS
    }

    /// Record all per-request metrics from the `logging()` callback.
    ///
    /// Single `DashMap` lookup per request — the bundled `DomainRequestMetrics`
    /// holds counters, histogram, and byte totals in one allocation.
    pub fn record_request(
        &self,
        domain: &CompactString,
        method: &str,
        status: u16,
        duration_us: u64,
        bytes_tx: u64,
        bytes_rx: u64,
    ) {
        if !self.domain_within_limit(domain) {
            return;
        }

        let entry = self.domains.entry(domain.clone()).or_default();
        entry.requests.increment(status, method);
        entry.duration.observe(duration_us);
        entry.bytes_sent.fetch_add(bytes_tx, Relaxed);
        entry.bytes_received.fetch_add(bytes_rx, Relaxed);
    }

    /// Increment active connections gauge for a domain.
    ///
    /// Skipped if the domain count exceeds [`MAX_TRACKED_DOMAINS`].
    pub fn connection_start(&self, domain: &CompactString) {
        if self.active_connections.contains_key(domain)
            || self.active_connections.len() < MAX_TRACKED_DOMAINS
        {
            self.active_connections
                .entry(domain.clone())
                .or_default()
                .fetch_add(1, Relaxed);
        }
    }

    /// Decrement active connections gauge for a domain.
    pub fn connection_end(&self, domain: &CompactString) {
        self.active_connections
            .entry(domain.clone())
            .or_default()
            .fetch_sub(1, Relaxed);
    }

    /// Render all metrics in Prometheus text exposition format.
    ///
    /// Called on `GET /metrics` — iterates `DashMap` entries and formats
    /// each metric with HELP, TYPE, and value lines.
    pub fn render(&self) -> String {
        // Pre-allocate generously — typical output for 10 domains is ~8 KB
        let mut out = String::with_capacity(8192);

        self.render_requests(&mut out);
        self.render_request_duration(&mut out);
        self.render_bytes(&mut out);
        self.render_active_connections(&mut out);
        self.render_upstream_connect_duration(&mut out);
        self.render_upstream_health(&mut out);
        self.render_tls_handshake_duration(&mut out);
        self.render_config_reloads(&mut out);
        self.process.render(&mut out);
        self.rate_cache.render(&mut out);

        out
    }

    fn render_requests(&self, out: &mut String) {
        out.push_str("# HELP dwaar_requests_total Total HTTP requests processed.\n");
        out.push_str("# TYPE dwaar_requests_total counter\n");
        for entry in &self.domains {
            let domain = entry.key();
            let counters = &entry.value().requests;
            for (si, &status_label) in STATUS_CODES.iter().enumerate() {
                for (mi, &method_label) in METHODS.iter().enumerate() {
                    let val = counters.counts[si * METHOD_COUNT + mi].load(Relaxed);
                    if val > 0 {
                        let _ = writeln!(
                            out,
                            "dwaar_requests_total{{domain=\"{domain}\",method=\"{method_label}\",status=\"{status_label}\"}} {val}"
                        );
                    }
                }
            }
        }
    }

    fn render_request_duration(&self, out: &mut String) {
        out.push_str("# HELP dwaar_request_duration_seconds Request duration in seconds.\n");
        out.push_str("# TYPE dwaar_request_duration_seconds histogram\n");
        for entry in &self.domains {
            render_histogram(
                out,
                "dwaar_request_duration_seconds",
                entry.key(),
                &entry.value().duration.snapshot(),
            );
        }
    }

    fn render_bytes(&self, out: &mut String) {
        out.push_str("# HELP dwaar_bytes_sent_total Total response bytes sent.\n");
        out.push_str("# TYPE dwaar_bytes_sent_total counter\n");
        for entry in &self.domains {
            let val = entry.value().bytes_sent.load(Relaxed);
            if val > 0 {
                let _ = writeln!(
                    out,
                    "dwaar_bytes_sent_total{{domain=\"{}\"}} {val}",
                    entry.key()
                );
            }
        }

        out.push_str("# HELP dwaar_bytes_received_total Total request bytes received.\n");
        out.push_str("# TYPE dwaar_bytes_received_total counter\n");
        for entry in &self.domains {
            let val = entry.value().bytes_received.load(Relaxed);
            if val > 0 {
                let _ = writeln!(
                    out,
                    "dwaar_bytes_received_total{{domain=\"{}\"}} {val}",
                    entry.key()
                );
            }
        }
    }

    fn render_active_connections(&self, out: &mut String) {
        out.push_str("# HELP dwaar_active_connections Currently active connections.\n");
        out.push_str("# TYPE dwaar_active_connections gauge\n");
        for entry in &self.active_connections {
            let val = entry.value().load(Relaxed);
            let _ = writeln!(
                out,
                "dwaar_active_connections{{domain=\"{}\"}} {val}",
                entry.key()
            );
        }
    }

    fn render_upstream_connect_duration(&self, out: &mut String) {
        out.push_str(
            "# HELP dwaar_upstream_connect_duration_seconds Upstream connection time in seconds.\n",
        );
        out.push_str("# TYPE dwaar_upstream_connect_duration_seconds histogram\n");
        for entry in &self.upstream_connect_duration {
            render_histogram(
                out,
                "dwaar_upstream_connect_duration_seconds",
                entry.key(),
                &entry.value().snapshot(),
            );
        }
    }

    fn render_upstream_health(&self, out: &mut String) {
        out.push_str(
            "# HELP dwaar_upstream_health Upstream health status (1=healthy, 0=unhealthy).\n",
        );
        out.push_str("# TYPE dwaar_upstream_health gauge\n");
        for entry in &self.upstream_health {
            let val = entry.value().load(Relaxed);
            let _ = writeln!(
                out,
                "dwaar_upstream_health{{upstream=\"{}\"}} {val}",
                entry.key()
            );
        }
    }

    fn render_tls_handshake_duration(&self, out: &mut String) {
        let snap = self.tls_handshake_duration.snapshot();
        if snap.count == 0 {
            return;
        }
        out.push_str(
            "# HELP dwaar_tls_handshake_duration_seconds TLS handshake duration in seconds.\n",
        );
        out.push_str("# TYPE dwaar_tls_handshake_duration_seconds histogram\n");
        render_histogram_no_labels(out, "dwaar_tls_handshake_duration_seconds", &snap);
    }

    fn render_config_reloads(&self, out: &mut String) {
        let success = self.config_reloads_success.load(Relaxed);
        let failure = self.config_reloads_failure.load(Relaxed);
        if success == 0 && failure == 0 {
            return;
        }
        out.push_str("# HELP dwaar_config_reload_total Config reload attempts.\n");
        out.push_str("# TYPE dwaar_config_reload_total counter\n");
        if success > 0 {
            let _ = writeln!(
                out,
                "dwaar_config_reload_total{{result=\"success\"}} {success}"
            );
        }
        if failure > 0 {
            let _ = writeln!(
                out,
                "dwaar_config_reload_total{{result=\"failure\"}} {failure}"
            );
        }
    }
}

/// Write a histogram with a `domain` label.
fn render_histogram(out: &mut String, name: &str, domain: &str, snap: &HistogramSnapshot) {
    for (i, &le) in BUCKET_BOUNDS_SECS.iter().enumerate() {
        let _ = writeln!(
            out,
            "{name}_bucket{{domain=\"{domain}\",le=\"{le}\"}} {}",
            snap.buckets[i]
        );
    }
    let _ = writeln!(
        out,
        "{name}_bucket{{domain=\"{domain}\",le=\"+Inf\"}} {}",
        snap.buckets[BUCKET_BOUNDS_SECS.len()]
    );
    let _ = writeln!(out, "{name}_sum{{domain=\"{domain}\"}} {}", snap.sum_secs);
    let _ = writeln!(out, "{name}_count{{domain=\"{domain}\"}} {}", snap.count);
}

/// Write a histogram without labels (global metrics like TLS handshake).
fn render_histogram_no_labels(out: &mut String, name: &str, snap: &HistogramSnapshot) {
    for (i, &le) in BUCKET_BOUNDS_SECS.iter().enumerate() {
        let _ = writeln!(out, "{name}_bucket{{le=\"{le}\"}} {}", snap.buckets[i]);
    }
    let _ = writeln!(
        out,
        "{name}_bucket{{le=\"+Inf\"}} {}",
        snap.buckets[BUCKET_BOUNDS_SECS.len()]
    );
    let _ = writeln!(out, "{name}_sum {}", snap.sum_secs);
    let _ = writeln!(out, "{name}_count {}", snap.count);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn histogram_observe_correct_bucket() {
        let h = Histogram::new();
        // 3ms = 3000us — should land in the 5ms (5000us) bucket
        h.observe(3_000);

        let snap = h.snapshot();
        assert_eq!(snap.buckets[0], 1, "le=5ms bucket should have 1");
        // All higher buckets are cumulative — they should also have 1
        for b in &snap.buckets[1..] {
            assert_eq!(*b, 1, "cumulative bucket should have 1");
        }
        assert_eq!(snap.count, 1);
        assert!((snap.sum_secs - 0.003).abs() < f64::EPSILON);
    }

    #[test]
    fn histogram_observe_highest_bucket() {
        let h = Histogram::new();
        // 15s = 15_000_000us — exceeds all bounds, only +Inf
        h.observe(15_000_000);

        let snap = h.snapshot();
        for (i, &count) in snap.buckets.iter().enumerate() {
            if i < BUCKET_BOUNDS_US.len() {
                assert_eq!(count, 0, "bounded bucket {i} should be 0");
            } else {
                assert_eq!(count, 1, "+Inf bucket should be 1");
            }
        }
        assert_eq!(snap.count, 1);
    }

    #[test]
    fn histogram_sum_and_count_accumulate() {
        let h = Histogram::new();
        h.observe(1_000); // 1ms
        h.observe(2_000); // 2ms
        h.observe(3_000); // 3ms

        let snap = h.snapshot();
        assert_eq!(snap.count, 3);
        // 6000us = 0.006s
        assert!((snap.sum_secs - 0.006).abs() < f64::EPSILON);
    }

    #[test]
    fn histogram_exact_boundary() {
        let h = Histogram::new();
        // Exactly 5ms — should be <= 5ms bucket
        h.observe(5_000);

        let snap = h.snapshot();
        assert_eq!(snap.buckets[0], 1, "le=5ms should include exact boundary");
    }

    /// Helper: get counter value by status group index and method index.
    fn counter_at(c: &StatusMethodCounters, sg: usize, mi: usize) -> u64 {
        c.counts[sg * METHOD_COUNT + mi].load(Relaxed)
    }

    #[test]
    fn status_method_counters_basic() {
        let c = StatusMethodCounters::new();
        c.increment(200, "GET");
        c.increment(200, "GET");
        c.increment(404, "POST");

        assert_eq!(counter_at(&c, 1, 0), 2); // 2xx GET
        assert_eq!(counter_at(&c, 3, 1), 1); // 4xx POST
        assert_eq!(c.total(), 3);
    }

    #[test]
    fn status_method_counters_unknown_method() {
        let c = StatusMethodCounters::new();
        c.increment(200, "PROPFIND");

        assert_eq!(counter_at(&c, 1, 7), 1); // 2xx OTHER
    }

    #[test]
    fn status_method_counters_edge_statuses() {
        let c = StatusMethodCounters::new();
        c.increment(100, "GET"); // 1xx
        c.increment(199, "GET"); // 1xx
        c.increment(500, "GET"); // 5xx
        c.increment(599, "GET"); // 5xx
        c.increment(999, "GET"); // mapped to 5xx (catch-all)

        assert_eq!(counter_at(&c, 0, 0), 2); // 1xx GET
        assert_eq!(counter_at(&c, 4, 0), 3); // 5xx GET
    }

    #[test]
    fn prometheus_metrics_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PrometheusMetrics>();
    }

    #[test]
    fn record_request_populates_domain_metrics() {
        let m = PrometheusMetrics::new();
        let domain = CompactString::from("test.example.com");
        m.record_request(&domain, "GET", 200, 5_000, 1024, 256);

        let entry = m.domains.get(&domain).expect("domain should be tracked");
        assert_eq!(entry.requests.total(), 1);
        assert_eq!(entry.duration.count.load(Relaxed), 1);
        assert_eq!(entry.bytes_sent.load(Relaxed), 1024);
        assert_eq!(entry.bytes_received.load(Relaxed), 256);
    }

    #[test]
    fn active_connections_increment_decrement() {
        let m = PrometheusMetrics::new();
        let domain = CompactString::from("test.com");

        m.connection_start(&domain);
        m.connection_start(&domain);
        assert_eq!(
            m.active_connections
                .get(&domain)
                .expect("gauge")
                .load(Relaxed),
            2
        );

        m.connection_end(&domain);
        assert_eq!(
            m.active_connections
                .get(&domain)
                .expect("gauge")
                .load(Relaxed),
            1
        );
    }

    #[test]
    fn render_empty_registry() {
        let m = PrometheusMetrics::new();
        let text = m.render();
        // Should still have HELP/TYPE lines but no data lines
        assert!(text.contains("# HELP dwaar_requests_total"));
        assert!(text.contains("# TYPE dwaar_requests_total counter"));
        // No data values since no requests recorded
        assert!(!text.contains("domain="));
    }

    #[test]
    fn render_counter_values() {
        let m = PrometheusMetrics::new();
        let domain = CompactString::from("app.example.com");
        m.record_request(&domain, "GET", 200, 1_000, 512, 64);
        m.record_request(&domain, "GET", 200, 2_000, 512, 64);
        m.record_request(&domain, "POST", 404, 3_000, 0, 128);

        let text = m.render();
        assert!(text.contains(
            "dwaar_requests_total{domain=\"app.example.com\",method=\"GET\",status=\"2xx\"} 2"
        ));
        assert!(text.contains(
            "dwaar_requests_total{domain=\"app.example.com\",method=\"POST\",status=\"4xx\"} 1"
        ));
        assert!(text.contains("dwaar_bytes_sent_total{domain=\"app.example.com\"} 1024"));
    }

    #[test]
    fn render_histogram_format() {
        let m = PrometheusMetrics::new();
        let domain = CompactString::from("h.test");
        m.record_request(&domain, "GET", 200, 3_000, 0, 0); // 3ms

        let text = m.render();
        // Check bucket format
        assert!(
            text.contains(
                "dwaar_request_duration_seconds_bucket{domain=\"h.test\",le=\"0.005\"} 1"
            )
        );
        assert!(
            text.contains("dwaar_request_duration_seconds_bucket{domain=\"h.test\",le=\"+Inf\"} 1")
        );
        assert!(text.contains("dwaar_request_duration_seconds_sum{domain=\"h.test\"} 0.003"));
        assert!(text.contains("dwaar_request_duration_seconds_count{domain=\"h.test\"} 1"));
    }

    #[test]
    fn render_config_reload_counters() {
        let m = PrometheusMetrics::new();
        m.config_reloads_success.fetch_add(3, Relaxed);
        m.config_reloads_failure.fetch_add(1, Relaxed);

        let text = m.render();
        assert!(text.contains("dwaar_config_reload_total{result=\"success\"} 3"));
        assert!(text.contains("dwaar_config_reload_total{result=\"failure\"} 1"));
    }

    #[test]
    fn render_skips_zero_config_reloads() {
        let m = PrometheusMetrics::new();
        let text = m.render();
        assert!(!text.contains("dwaar_config_reload_total"));
    }

    #[test]
    fn render_active_connections_gauge() {
        let m = PrometheusMetrics::new();
        let domain = CompactString::from("gauge.test");
        m.connection_start(&domain);

        let text = m.render();
        assert!(text.contains("dwaar_active_connections{domain=\"gauge.test\"} 1"));
    }
}
