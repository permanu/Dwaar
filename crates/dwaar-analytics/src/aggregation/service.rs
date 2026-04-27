// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Background service that consumes beacon and request-log channels,
//! updating per-domain [`DomainMetrics`] in a shared [`DashMap`].
//!
//! Runs as a Pingora `BackgroundService` — started inside the Pingora
//! runtime after `run_forever()`. Flushes aggregate snapshots to
//! stdout every 60 seconds.
//!
//! The `DashMap` is shared via `Arc` so ISSUE-029's Admin API can
//! read it concurrently without blocking the aggregation loop.

use std::collections::HashSet;
use std::io::Write;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use dashmap::DashMap;
use serde::Serialize;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use super::web_vitals::Percentiles;
use super::{AggEvent, AggReceiver, DomainMetrics};
use crate::beacon::BeaconEvent;
use crate::sink::{AnalyticsSink, DomainMetricsSnapshot};

/// Flush aggregates every 60 seconds.
const FLUSH_INTERVAL: Duration = Duration::from_secs(60);

/// Abstraction for checking if a host exists in the route table.
///
/// Production code passes the real `ArcSwap<RouteTable>`. Tests pass
/// a simple `HashSet`. This keeps `dwaar-analytics` independent of
/// `dwaar-core` (no circular dependency).
pub trait RouteValidator: Send + Sync {
    fn is_known_host(&self, host: &str) -> bool;

    /// Return the set of known hosts at the time of the call.
    ///
    /// Used by [`AggregationService::new`] to pre-seed the metrics map so
    /// the first `entry().or_default()` for each domain is a contention-free
    /// read of an existing entry rather than a write that competes with other
    /// concurrent first-writes. See issue #163.
    ///
    /// The default returns an empty `Vec`, preserving backward compatibility
    /// for implementations that cannot enumerate domains (pre-seeding
    /// degrades gracefully to the lazy-allocation status quo).
    fn known_hosts(&self) -> Vec<String> {
        Vec::new()
    }
}

/// Aggregation background service.
///
/// Consumes two channels (beacons + request logs), updates per-domain
/// metrics, and flushes snapshots periodically. The `DashMap` is shared
/// via `Arc` so ISSUE-029's Admin API can read it concurrently.
pub struct AggregationService<RT: RouteValidator> {
    metrics: Arc<DashMap<String, DomainMetrics>>,
    route_validator: RT,
    beacon_rx: Mutex<Option<mpsc::Receiver<BeaconEvent>>>,
    log_rx: Mutex<Option<AggReceiver>>,
    /// External sink for analytics snapshots (ISSUE-116). `None` uses the
    /// legacy stdout flush path for backwards compatibility.
    sink: Option<Box<dyn AnalyticsSink>>,
    /// When set, `run()` listens for notifications and calls
    /// `evict_unknown_domains()` each time one arrives. Wire this to the
    /// same `Notify` that `ConfigWatcher::with_post_reload_notify` fires so
    /// the map shrinks whenever domains are removed from the config. #167
    evict_notify: Option<Arc<tokio::sync::Notify>>,
}

impl<RT: RouteValidator> std::fmt::Debug for AggregationService<RT> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AggregationService")
            .field("domains", &self.metrics.len())
            .finish_non_exhaustive()
    }
}

impl<RT: RouteValidator> AggregationService<RT> {
    pub fn new(
        metrics: Arc<DashMap<String, DomainMetrics>>,
        route_validator: RT,
        beacon_rx: mpsc::Receiver<BeaconEvent>,
        log_rx: AggReceiver,
    ) -> Self {
        // Pre-seed the map with all currently known domains so the first
        // event per domain hits an existing entry instead of racing to
        // create one. Under high concurrency with many new domains appearing
        // simultaneously, multiple workers could call entry().or_default()
        // simultaneously, each racing to insert a short-lived DomainMetrics
        // allocation — DashMap serialises those writes at the shard level,
        // causing unnecessary contention. With the map pre-seeded, every
        // ingest() call for a known domain is a contention-free shard read.
        // Unknown hosts are still gated by is_known_host() before they ever
        // reach the entry() call, so they never appear in the map. #163
        for host in route_validator.known_hosts() {
            metrics.entry(host).or_default();
        }

        Self {
            metrics,
            route_validator,
            beacon_rx: Mutex::new(Some(beacon_rx)),
            log_rx: Mutex::new(Some(log_rx)),
            sink: None,
            evict_notify: None,
        }
    }

    /// Set an external sink for analytics snapshots (ISSUE-116).
    /// When set, `flush()` sends `DomainMetricsSnapshot` to the sink
    /// in addition to the legacy stdout path.
    #[must_use]
    pub fn with_sink(mut self, sink: Box<dyn AnalyticsSink>) -> Self {
        self.sink = Some(sink);
        self
    }

    /// Register the `Notify` that fires after each hot-reload. On every
    /// notification, `run()` calls `evict_unknown_domains()` so the metrics
    /// map shrinks when domains are removed from the config. Wire this to
    /// `ConfigWatcher::with_post_reload_notify`. See issue #167.
    #[must_use]
    pub fn with_evict_notify(mut self, notify: Arc<tokio::sync::Notify>) -> Self {
        self.evict_notify = Some(notify);
        self
    }

    /// Drop metrics entries for domains that are no longer in the known-hosts
    /// set.
    ///
    /// Called on hot-reload to keep the working set bounded as domains are
    /// added and removed from the config over time. The pre-seeding pass at
    /// construction (issue #163) keeps lookup contention-free; this paired
    /// eviction sweep keeps the map from growing indefinitely. A `retain()`
    /// over the `DashMap` is O(N) — one shard lock per shard — which is
    /// acceptable since reloads are rare. #167
    pub fn evict_unknown_domains(&self) {
        let known: HashSet<String> = self.route_validator.known_hosts().into_iter().collect();
        let before = self.metrics.len();
        self.metrics.retain(|domain, _| known.contains(domain));
        let removed = before.saturating_sub(self.metrics.len());
        if removed > 0 {
            debug!(removed, "evicted stale domain metrics after config reload");
        }
    }

    /// Read-only access to the shared metrics map.
    /// Used by ISSUE-029's Admin API for `GET /analytics/{domain}`.
    pub fn metrics(&self) -> &Arc<DashMap<String, DomainMetrics>> {
        &self.metrics
    }

    fn ingest_log(&self, event: &AggEvent) {
        if !self.route_validator.is_known_host(&event.host) {
            return;
        }
        let mut entry = self.metrics.entry(event.host.to_string()).or_default();
        entry.ingest_log(event);
    }

    fn ingest_beacon(&self, beacon: &BeaconEvent) {
        if !self.route_validator.is_known_host(&beacon.host) {
            return;
        }
        let mut entry = self.metrics.entry(beacon.host.clone()).or_default();
        entry.ingest_beacon(beacon);
    }

    fn flush(&self) {
        if let Some(ref sink) = self.sink {
            // Sink path: send structured snapshots to external consumer.
            // Reads are non-mutating so the sink sees the same counts the
            // stdout path will serialize and reset below.
            for entry in self.metrics.iter() {
                let snapshot = DomainMetricsSnapshot::from_metrics(entry.key(), entry.value());
                if let Err(e) = sink.flush(&snapshot) {
                    warn!(error = %e, domain = entry.key().as_str(), "analytics sink flush failed");
                }
            }
        }

        // Legacy stdout path — always runs so standalone Dwaar still logs.
        // Each entry is consumed mutably: after serialization we zero the
        // per-window counters (status_codes, bytes_sent, bot_views,
        // human_views) so the next flush reports the delta for the next
        // 60s window rather than a perpetually growing lifetime total.
        //
        // This matches the documented intent in `FlushSnapshot` ("Cumulative
        // since the last flush. `bot_views + human_views` ≈ `page_views_60m`
        // modulo timing.") and in `AnalyticsSnapshot` ("Cumulative since the
        // last 60s aggregation flush."). Prior to H-13 the code silently
        // accumulated lifetime totals, contradicting both doc comments.
        //
        // `page_views`, `unique_visitors`, `top_pages`, `referrers`,
        // `countries`, and `web_vitals` manage their own windows internally
        // (minute buckets, HyperLogLog, TopK, bounded counter, tdigest) and
        // do NOT need explicit reset here.
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        for mut entry in self.metrics.iter_mut() {
            let domain = entry.key().clone();
            let metrics = entry.value_mut();
            let snapshot = FlushSnapshot::from_metrics(&domain, metrics);
            if let Err(e) = serde_json::to_writer(&mut handle, &snapshot)
                .and_then(|()| handle.write_all(b"\n").map_err(serde_json::Error::io))
            {
                warn!(error = %e, domain = domain.as_str(), "failed to flush analytics");
            }
            // Reset cumulative per-window counters AFTER serialization.
            metrics.status_codes = [0; 6];
            metrics.bytes_sent = 0;
            metrics.bot_views = 0;
            metrics.human_views = 0;
            // Same per-window semantics as the other cumulative counters:
            // the flush snapshot reports the delta for this window, so
            // we zero the histogram after serialising it. Without this,
            // every flush would report a lifetime total while the status
            // counters next to it would show a window delta — operators
            // would read the two side-by-side and get conflicting stories.
            metrics.response_latency_buckets = super::latency_histogram::BucketHistogram::new();
        }
        if let Err(e) = handle.flush() {
            warn!(error = %e, "failed to flush stdout");
        }
        debug!(domains = self.metrics.len(), "analytics flushed");
    }

    /// The main event loop. Call from `BackgroundService::start()`.
    ///
    /// Consumes both channels via `tokio::select!`. The shutdown watch
    /// triggers a final flush before returning (Guardrail #20: all async
    /// work in `BackgroundService`, not raw `tokio::spawn`).
    pub async fn run(&self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let mut beacon_rx = self
            .beacon_rx
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .expect("run() called more than once");
        let mut log_rx = self
            .log_rx
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .expect("run() called more than once");

        let mut flush_timer = tokio::time::interval(FLUSH_INTERVAL);
        // Skip the first immediate tick so the timer starts fresh
        flush_timer.tick().await;

        loop {
            tokio::select! {
                Some(beacon) = beacon_rx.recv() => {
                    self.ingest_beacon(&beacon);
                }
                Some(log) = log_rx.rx.recv() => {
                    self.ingest_log(&log);
                }
                _ = flush_timer.tick() => {
                    self.flush();
                }
                // Hot-reload: drop entries for domains no longer in the config.
                // The ConfigWatcher fires this after swapping the route table,
                // so known_hosts() already reflects the new domain set. #167
                () = async {
                    match &self.evict_notify {
                        Some(n) => n.notified().await,
                        None => std::future::pending().await,
                    }
                } => {
                    self.evict_unknown_domains();
                }
                _ = shutdown.changed() => {
                    self.flush();
                    debug!("aggregation service shutting down");
                    return;
                }
            }
        }
    }
}

// ── Flush Serialization ──────────────────────────────────────────

/// Current schema version of the per-domain flush snapshot.
///
/// Bumped on every breaking field rename so downstream readers reject
/// mismatched messages instead of silently dropping data via serde
/// unknown-field defaults.
const FLUSH_SCHEMA_VERSION: u32 = 1;

/// JSON snapshot emitted per domain during flush.
#[derive(Debug, Serialize)]
struct FlushSnapshot {
    r#type: &'static str,
    /// Schema version. Consumers compare against their own constant
    /// and reject mismatches loudly so a future field rename never
    /// silently corrupts downstream data.
    schema_version: u32,
    domain: String,
    /// Deprecated: use `window_end`. Kept for one release cycle so
    /// pre-window_end readers continue to receive a sane timestamp.
    timestamp: String,
    /// Explicit aggregation window so consumers can detect heartbeat
    /// gaps. `window_end` mirrors `timestamp`; `window_start` is
    /// `window_end - 60s` for the fixed 60s flush cycle today.
    window_start: String,
    window_end: String,
    page_views_1m: u64,
    page_views_60m: u64,
    unique_visitors: u64,
    /// Bot vs human pageview split. Cumulative since the last flush.
    /// `bot_views + human_views` ≈ `page_views_60m` modulo timing.
    bot_views: u64,
    human_views: u64,
    top_pages: Vec<PageCount>,
    referrers: Vec<ReferrerCount>,
    countries: Vec<CountryCount>,
    /// Per-device-class pageview counts across the fixed
    /// `mobile|desktop|tablet|bot|unknown` enum. Sibling of
    /// [`crate::sink::DomainMetricsSnapshot::devices`] — same data,
    /// different wire format (stdout-legacy JSON vs socket sink).
    devices: Vec<DeviceCount>,
    /// Top-N UTM counters across all five dimensions. Mirrors the socket
    /// sink so consumers tailing the stdout legacy path see the same
    /// attribution numbers as the agent does. Lowercased at ingest;
    /// term/content are bounded tighter than source/medium/campaign
    /// (see `TOP_UTM_TERMS_N` / `TOP_UTM_CONTENTS_N`).
    utm_sources: Vec<UtmCount>,
    utm_mediums: Vec<UtmCount>,
    utm_campaigns: Vec<UtmCount>,
    utm_terms: Vec<UtmCount>,
    utm_contents: Vec<UtmCount>,
    /// HTTP status classes (1xx..5xx) emitted in order with zero counts
    /// included. Sibling of [`crate::sink::DomainMetricsSnapshot::status_classes`].
    status_classes: Vec<StatusClassCount>,
    /// Server-observed response-latency histogram across ten fixed
    /// buckets (edges `[10, 50, 100, 250, 500, 1000, 2500, 5000, 10000,
    /// +Inf]` milliseconds). Sibling of
    /// [`crate::sink::DomainMetricsSnapshot::response_latency_buckets`]
    /// — same data, different wire format (stdout-legacy JSON vs socket
    /// sink). Always emitted in order with zero counts included.
    response_latency_buckets: Vec<LatencyBucketCount>,
    status_codes: StatusCodes,
    bytes_sent: u64,
    web_vitals: VitalsSnapshot,
}

#[derive(Debug, Serialize)]
struct PageCount {
    path: String,
    count: u64,
}

#[derive(Debug, Serialize)]
struct ReferrerCount {
    source: String,
    count: u64,
}

#[derive(Debug, Serialize)]
struct CountryCount {
    code: String,
    count: u64,
}

#[derive(Debug, Serialize)]
struct DeviceCount {
    device: String,
    count: u64,
}

/// One UTM attribution entry for the stdout-legacy flush. Field name
/// is deliberately generic (`value`) so a single struct handles all
/// five UTM dimensions (`utm_source`, `utm_medium`, `utm_campaign`,
/// `utm_term`, `utm_content`) without five near-identical types; the
/// owning field on `FlushSnapshot` carries the dimension.
#[derive(Debug, Serialize)]
struct UtmCount {
    value: String,
    count: u64,
}

#[derive(Debug, Serialize)]
struct StatusClassCount {
    class: String,
    count: u64,
}

/// One response-latency histogram bucket entry for the stdout-legacy
/// flush. `le` is the bucket upper-bound label (`"10"` … `"10000"` or
/// `"+Inf"`). Structure mirrors the socket-sink wire format so
/// consumers can parse both paths with the same shape.
#[derive(Debug, Serialize)]
struct LatencyBucketCount {
    le: String,
    count: u64,
}

#[derive(Debug, Serialize)]
struct StatusCodes {
    #[serde(rename = "1xx")]
    s1xx: u64,
    #[serde(rename = "2xx")]
    s2xx: u64,
    #[serde(rename = "3xx")]
    s3xx: u64,
    #[serde(rename = "4xx")]
    s4xx: u64,
    #[serde(rename = "5xx")]
    s5xx: u64,
    other: u64,
}

#[derive(Debug, Serialize)]
struct VitalsSnapshot {
    lcp: Percentiles,
    cls: Percentiles,
    inp: Percentiles,
}

impl FlushSnapshot {
    fn from_metrics(domain: &str, m: &mut DomainMetrics) -> Self {
        let now = chrono::Utc::now();
        let window_end = now.to_rfc3339();
        let window_start = (now - chrono::Duration::seconds(60)).to_rfc3339();
        Self {
            r#type: "analytics",
            schema_version: FLUSH_SCHEMA_VERSION,
            domain: domain.to_string(),
            timestamp: window_end.clone(),
            window_start,
            window_end,
            page_views_1m: m.page_views.count_last_n_now(1),
            page_views_60m: m.page_views.count_last_n_now(60),
            unique_visitors: m.unique_visitors.len() as u64,
            bot_views: m.bot_views,
            human_views: m.human_views,
            top_pages: m
                .top_pages
                .top()
                .into_iter()
                .map(|(path, count)| PageCount { path, count })
                .collect(),
            referrers: m
                .referrers
                .top()
                .into_iter()
                .map(|(source, count)| ReferrerCount { source, count })
                .collect(),
            countries: m
                .countries
                .top()
                .into_iter()
                .map(|(code, count)| CountryCount { code, count })
                .collect(),
            devices: m
                .devices
                .top()
                .into_iter()
                .map(|(device, count)| DeviceCount { device, count })
                .collect(),
            utm_sources: m
                .utm_sources
                .top()
                .into_iter()
                .map(|(value, count)| UtmCount { value, count })
                .collect(),
            utm_mediums: m
                .utm_mediums
                .top()
                .into_iter()
                .map(|(value, count)| UtmCount { value, count })
                .collect(),
            utm_campaigns: m
                .utm_campaigns
                .top()
                .into_iter()
                .map(|(value, count)| UtmCount { value, count })
                .collect(),
            utm_terms: m
                .utm_terms
                .top()
                .into_iter()
                .map(|(value, count)| UtmCount { value, count })
                .collect(),
            utm_contents: m
                .utm_contents
                .top()
                .into_iter()
                .map(|(value, count)| UtmCount { value, count })
                .collect(),
            status_classes: super::status_class_snapshot(&m.status_codes)
                .into_iter()
                .map(|(class, count)| StatusClassCount { class, count })
                .collect(),
            response_latency_buckets: m
                .response_latency_buckets
                .snapshot()
                .into_iter()
                .map(|(le, count)| LatencyBucketCount { le, count })
                .collect(),
            status_codes: StatusCodes {
                s1xx: m.status_codes[0],
                s2xx: m.status_codes[1],
                s3xx: m.status_codes[2],
                s4xx: m.status_codes[3],
                s5xx: m.status_codes[4],
                other: m.status_codes[5],
            },
            bytes_sent: m.bytes_sent,
            web_vitals: VitalsSnapshot {
                lcp: m.web_vitals.lcp_percentiles(),
                cls: m.web_vitals.cls_percentiles(),
                inp: m.web_vitals.inp_percentiles(),
            },
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::net::Ipv4Addr;

    /// Test route validator — accepts a fixed set of domains.
    struct TestValidator(HashSet<String>);

    impl RouteValidator for TestValidator {
        fn is_known_host(&self, host: &str) -> bool {
            self.0.contains(host)
        }

        fn known_hosts(&self) -> Vec<String> {
            self.0.iter().cloned().collect()
        }
    }

    fn test_event(host: &str, path: &str, status: u16) -> AggEvent {
        AggEvent {
            host: host.into(),
            path: path.into(),
            query: None,
            status,
            bytes_sent: 1024,
            client_ip: std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            country: Some("US".into()),
            referer: Some("https://google.com/search".into()),
            user_agent: Some(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit Chrome/120 Safari"
                    .into(),
            ),
            is_bot: false,
            response_latency_us: 0,
        }
    }

    type ServiceHandles = (
        Arc<AggregationService<TestValidator>>,
        mpsc::Sender<BeaconEvent>,
        mpsc::Sender<AggEvent>,
        tokio::sync::watch::Sender<bool>,
        Arc<DashMap<String, DomainMetrics>>,
    );

    fn make_service(domains: &[&str]) -> ServiceHandles {
        let domain_set: HashSet<String> = domains.iter().map(|&s| s.into()).collect();
        let (beacon_tx, beacon_rx) = mpsc::channel(8192);
        let (log_tx, log_rx) = mpsc::channel(8192);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let metrics = Arc::new(DashMap::new());
        let svc = Arc::new(AggregationService::new(
            Arc::clone(&metrics),
            TestValidator(domain_set),
            beacon_rx,
            AggReceiver { rx: log_rx },
        ));

        let svc_clone = Arc::clone(&svc);
        tokio::spawn(async move {
            svc_clone.run(shutdown_rx).await;
        });

        (svc, beacon_tx, log_tx, shutdown_tx, metrics)
    }

    #[test]
    fn ingest_log_known_host() {
        let domains: HashSet<String> = ["example.com".into()].into();
        let (_beacon_tx, beacon_rx) = mpsc::channel(1);
        let (_log_tx, log_rx) = mpsc::channel(1);
        let metrics = Arc::new(DashMap::new());
        let svc = AggregationService::new(
            Arc::clone(&metrics),
            TestValidator(domains),
            beacon_rx,
            AggReceiver { rx: log_rx },
        );
        svc.ingest_log(&test_event("example.com", "/home", 200));
        assert_eq!(metrics.len(), 1);
        let entry = metrics.get("example.com").expect("domain should exist");
        assert_eq!(entry.status_codes[1], 1); // 2xx
        assert_eq!(entry.bytes_sent, 1024);
    }

    #[test]
    fn ingest_log_unknown_host_rejected() {
        let domains: HashSet<String> = ["example.com".into()].into();
        let (_beacon_tx, beacon_rx) = mpsc::channel(1);
        let (_log_tx, log_rx) = mpsc::channel(1);
        let metrics = Arc::new(DashMap::new());
        let svc = AggregationService::new(
            Arc::clone(&metrics),
            TestValidator(domains),
            beacon_rx,
            AggReceiver { rx: log_rx },
        );
        // Pre-seeding adds example.com at construction; unknown hosts must
        // never be inserted, so the map must not contain evil.com after
        // this ingest. #163
        svc.ingest_log(&test_event("evil.com", "/hack", 200));
        assert!(
            !metrics.contains_key("evil.com"),
            "unknown host must not create entry"
        );
    }

    #[test]
    fn flush_produces_valid_json() {
        let domains: HashSet<String> = ["test.dev".into()].into();
        let (_beacon_tx, beacon_rx) = mpsc::channel(1);
        let (_log_tx, log_rx) = mpsc::channel(1);
        let metrics = Arc::new(DashMap::new());
        let svc = AggregationService::new(
            Arc::clone(&metrics),
            TestValidator(domains),
            beacon_rx,
            AggReceiver { rx: log_rx },
        );
        svc.ingest_log(&test_event("test.dev", "/", 200));
        // flush writes to stdout — verify it doesn't panic
        svc.flush();
    }

    #[tokio::test]
    async fn run_processes_logs_and_shuts_down() {
        let (_svc, _beacon_tx, log_tx, shutdown_tx, metrics) = make_service(&["app.io"]);

        for _ in 0..10 {
            log_tx
                .send(test_event("app.io", "/api", 200))
                .await
                .expect("send should succeed");
        }

        // Give the service time to process the ingested events.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // H-13 (v0.2.3): per-window counters are reset by `flush`, and the
        // shutdown path triggers a final flush. Capture the in-memory state
        // *before* signalling shutdown so we're asserting on the ingest-side
        // behaviour, not the flush-side reset behaviour (which is covered
        // separately by `flush_resets_cumulative_counters`).
        {
            let entry = metrics.get("app.io").expect("domain should exist");
            assert_eq!(entry.status_codes[1], 10); // 10 x 2xx
        }

        // Now verify the shutdown path itself: signal, wait, and confirm
        // the service exited cleanly without panic. After the final flush,
        // per-window counters are expected to be zero per H-13.
        shutdown_tx.send(true).expect("shutdown send");
        tokio::time::sleep(Duration::from_millis(50)).await;
        let entry = metrics.get("app.io").expect("domain should exist");
        assert_eq!(
            entry.status_codes[1], 0,
            "final flush must zero per-window counters"
        );
    }

    #[tokio::test]
    async fn concurrent_ingest_no_corruption() {
        let (_svc, _beacon_tx, log_tx, shutdown_tx, metrics) = make_service(&["stress.io"]);

        // Blast 1000 logs from 4 concurrent tasks
        let mut senders = Vec::new();
        for _ in 0..4 {
            let tx = log_tx.clone();
            senders.push(tokio::spawn(async move {
                for _ in 0..250 {
                    let _ = tx.send(test_event("stress.io", "/api", 200)).await;
                }
            }));
        }
        for s in senders {
            s.await.expect("sender task panicked");
        }

        tokio::time::sleep(Duration::from_millis(100)).await;

        // H-13 (v0.2.3): assert the ingested total *before* shutdown-flush
        // zeros the per-window counters. The shutdown path is still
        // exercised below; we just decouple the two assertions.
        {
            let entry = metrics.get("stress.io").expect("domain should exist");
            assert_eq!(entry.status_codes[1], 1000, "4 * 250 = 1000 requests");
        }

        shutdown_tx.send(true).expect("shutdown send");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    #[test]
    fn flush_resets_response_latency_buckets() {
        // Per-window semantics: the flush snapshot reports the delta
        // for this window, so the histogram must zero out after the
        // flush just like status_codes and bytes_sent already do.
        let domains: HashSet<String> = ["lat.test".into()].into();
        let (_beacon_tx, beacon_rx) = mpsc::channel(1);
        let (_log_tx, log_rx) = mpsc::channel(1);
        let metrics = Arc::new(DashMap::new());
        let svc = AggregationService::new(
            Arc::clone(&metrics),
            TestValidator(domains),
            beacon_rx,
            AggReceiver { rx: log_rx },
        );

        // Ingest two requests with distinct latencies so the histogram
        // is populated before the flush.
        let mut ev1 = test_event("lat.test", "/", 200);
        ev1.response_latency_us = 25_000; // 25ms → bucket 1 (le=50)
        svc.ingest_log(&ev1);
        let mut ev2 = test_event("lat.test", "/", 200);
        ev2.response_latency_us = 750_000; // 750ms → bucket 5 (le=1000)
        svc.ingest_log(&ev2);

        {
            let entry = metrics.get("lat.test").expect("domain");
            assert_eq!(entry.response_latency_buckets.total(), 2);
        }

        svc.flush();

        {
            let entry = metrics.get("lat.test").expect("domain");
            assert_eq!(
                entry.response_latency_buckets.total(),
                0,
                "flush must zero the histogram so next window reports a delta"
            );
            for count in entry.response_latency_buckets.counts() {
                assert_eq!(*count, 0);
            }
        }
    }

    #[test]
    fn flush_resets_cumulative_counters() {
        // H-13: per-window counters (status_codes, bytes_sent, bot_views,
        // human_views) must zero out after a flush so downstream consumers
        // see per-window deltas instead of lifetime totals.
        let domains: HashSet<String> = ["cumul.test".into()].into();
        let (_beacon_tx, beacon_rx) = mpsc::channel(1);
        let (_log_tx, log_rx) = mpsc::channel(1);
        let metrics = Arc::new(DashMap::new());
        let svc = AggregationService::new(
            Arc::clone(&metrics),
            TestValidator(domains),
            beacon_rx,
            AggReceiver { rx: log_rx },
        );

        svc.ingest_log(&test_event("cumul.test", "/a", 200));
        svc.ingest_log(&test_event("cumul.test", "/b", 200));
        svc.ingest_log(&test_event("cumul.test", "/c", 404));

        {
            let entry = metrics.get("cumul.test").expect("domain");
            assert_eq!(entry.status_codes[1], 2, "2xx before flush");
            assert_eq!(entry.status_codes[3], 1, "4xx before flush");
            assert_eq!(entry.bytes_sent, 3 * 1024);
            assert_eq!(entry.human_views, 3);
            assert_eq!(entry.bot_views, 0);
        }

        svc.flush();

        {
            let entry = metrics.get("cumul.test").expect("domain");
            assert_eq!(entry.status_codes, [0; 6], "status_codes reset");
            assert_eq!(entry.bytes_sent, 0, "bytes_sent reset");
            assert_eq!(entry.bot_views, 0, "bot_views reset");
            assert_eq!(entry.human_views, 0, "human_views reset");
        }

        svc.flush();
        {
            let entry = metrics.get("cumul.test").expect("domain");
            assert_eq!(entry.status_codes, [0; 6]);
            assert_eq!(entry.bytes_sent, 0);
        }

        svc.ingest_log(&test_event("cumul.test", "/d", 500));
        {
            let entry = metrics.get("cumul.test").expect("domain");
            assert_eq!(entry.status_codes[4], 1, "only window 2 5xx");
            assert_eq!(entry.bytes_sent, 1024, "only window 2 bytes");
            assert_eq!(entry.human_views, 1);
        }
    }

    #[test]
    fn pre_seed_known_domains_no_stampede_on_first_ingest() {
        // After construction the map already contains an entry for every
        // known domain, so ingest_log()'s entry().or_default() becomes a
        // contention-free read of an existing shard entry rather than a
        // write that races against concurrent first-writes for other new
        // domains. The map must not grow during the first ingest. #163
        let known = ["a.example.com", "b.example.com", "c.example.com"];
        let domain_set: HashSet<String> = known.iter().map(|&s| s.into()).collect();
        let (_beacon_tx, beacon_rx) = mpsc::channel(1);
        let (_log_tx, log_rx) = mpsc::channel(1);
        let metrics = Arc::new(DashMap::new());
        let _svc = AggregationService::new(
            Arc::clone(&metrics),
            TestValidator(domain_set),
            beacon_rx,
            AggReceiver { rx: log_rx },
        );

        // All three domains seeded at construction — no ingest needed.
        assert_eq!(
            metrics.len(),
            3,
            "all known domains pre-seeded at construction"
        );

        // First ingest for a known domain: entry already exists, map does not grow.
        let entry = metrics.entry("a.example.com".to_string()).or_default();
        drop(entry);
        assert_eq!(metrics.len(), 3, "first ingest must not grow the map");
    }

    /// A test validator whose known-host set can be swapped at runtime,
    /// simulating what happens when a hot-reload changes the route table.
    struct MutableTestValidator(Arc<std::sync::Mutex<HashSet<String>>>);

    impl MutableTestValidator {
        fn new(domains: &[&str]) -> Self {
            Self(Arc::new(std::sync::Mutex::new(
                domains.iter().map(|&s| s.into()).collect(),
            )))
        }

        fn set_known(&self, domains: &[&str]) {
            *self.0.lock().expect("test mutex poisoned") =
                domains.iter().map(|&s| s.into()).collect();
        }
    }

    impl RouteValidator for MutableTestValidator {
        fn is_known_host(&self, host: &str) -> bool {
            self.0.lock().expect("test mutex poisoned").contains(host)
        }

        fn known_hosts(&self) -> Vec<String> {
            self.0
                .lock()
                .expect("test mutex poisoned")
                .iter()
                .cloned()
                .collect()
        }
    }

    #[test]
    fn evict_drops_domains_not_in_new_known_set() {
        // Pair with #163 pre-seed: on hot reload, entries for domains that were
        // removed from the config must be cleaned up. Without this, the DashMap
        // grows indefinitely as domains are cycled in and out over the process
        // lifetime. The retain() sweep is O(N) per reload — acceptable since
        // reloads are rare. #167
        let validator = MutableTestValidator::new(&["a.example.com", "b.example.com"]);
        let (_beacon_tx, beacon_rx) = mpsc::channel(1);
        let (_log_tx, log_rx) = mpsc::channel(1);
        let metrics = Arc::new(DashMap::new());
        let svc = AggregationService::new(
            Arc::clone(&metrics),
            validator,
            beacon_rx,
            AggReceiver { rx: log_rx },
        );

        // Both domains pre-seeded at construction (#163).
        assert!(metrics.contains_key("a.example.com"), "a pre-seeded");
        assert!(metrics.contains_key("b.example.com"), "b pre-seeded");

        // Simulate config reload: 'a' removed from route table.
        svc.route_validator.set_known(&["b.example.com"]);
        svc.evict_unknown_domains();

        assert!(
            !metrics.contains_key("a.example.com"),
            "a must be evicted after reload removes it from config"
        );
        assert!(
            metrics.contains_key("b.example.com"),
            "b must survive — it is still in the config"
        );
    }

    #[test]
    fn evict_with_empty_known_set_clears_all() {
        // When all domains are removed from the config (e.g. the operator
        // blanks the Dwaarfile during debugging), eviction must clear the map
        // completely so no stale entry consumes memory.
        let validator = MutableTestValidator::new(&["a.example.com"]);
        let (_beacon_tx, beacon_rx) = mpsc::channel(1);
        let (_log_tx, log_rx) = mpsc::channel(1);
        let metrics = Arc::new(DashMap::new());
        let svc = AggregationService::new(
            Arc::clone(&metrics),
            validator,
            beacon_rx,
            AggReceiver { rx: log_rx },
        );

        assert_eq!(metrics.len(), 1);
        svc.route_validator.set_known(&[]);
        svc.evict_unknown_domains();
        assert_eq!(metrics.len(), 0, "empty known set must clear the map");
    }

    #[tokio::test]
    async fn evict_notify_triggers_eviction_in_run_loop() {
        // Verify the end-to-end wiring: when evict_notify fires, the run loop
        // calls evict_unknown_domains() and drops stale entries. #167
        let validator = MutableTestValidator::new(&["a.example.com", "b.example.com"]);
        let (beacon_tx, beacon_rx) = mpsc::channel(8192);
        let (log_tx, log_rx) = mpsc::channel(8192);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let evict_notify = Arc::new(tokio::sync::Notify::new());
        let metrics = Arc::new(DashMap::new());

        let svc = Arc::new(
            AggregationService::new(
                Arc::clone(&metrics),
                validator,
                beacon_rx,
                AggReceiver { rx: log_rx },
            )
            .with_evict_notify(Arc::clone(&evict_notify)),
        );

        // Both domains pre-seeded.
        assert!(metrics.contains_key("a.example.com"));
        assert!(metrics.contains_key("b.example.com"));

        // Start the run loop in the background.
        let svc_clone = Arc::clone(&svc);
        tokio::spawn(async move { svc_clone.run(shutdown_rx).await });

        // Simulate reload: remove 'a' from the route table, then fire the notify.
        svc.route_validator.set_known(&["b.example.com"]);
        evict_notify.notify_one();

        // Give the run loop a chance to process the notification.
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert!(
            !metrics.contains_key("a.example.com"),
            "run loop must evict 'a' after notify"
        );
        assert!(metrics.contains_key("b.example.com"), "b survives");

        // Clean up
        drop(beacon_tx);
        drop(log_tx);
        shutdown_tx.send(true).expect("shutdown");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    #[tokio::test]
    async fn unknown_host_does_not_grow_dashmap() {
        let (_svc, _beacon_tx, log_tx, shutdown_tx, metrics) = make_service(&["legit.com"]);

        // Send 100 logs with random unknown hosts
        for i in 0..100 {
            log_tx
                .send(test_event(&format!("evil-{i}.com"), "/hack", 200))
                .await
                .expect("send");
        }
        // One legit log
        log_tx
            .send(test_event("legit.com", "/", 200))
            .await
            .expect("send");

        tokio::time::sleep(Duration::from_millis(50)).await;
        shutdown_tx.send(true).expect("shutdown");
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert_eq!(metrics.len(), 1, "only legit.com should be in DashMap");
        assert!(metrics.contains_key("legit.com"));
    }
}
