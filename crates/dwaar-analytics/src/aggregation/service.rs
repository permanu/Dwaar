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
        Self {
            metrics,
            route_validator,
            beacon_rx: Mutex::new(Some(beacon_rx)),
            log_rx: Mutex::new(Some(log_rx)),
            sink: None,
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
        svc.ingest_log(&test_event("evil.com", "/hack", 200));
        assert_eq!(metrics.len(), 0, "unknown host must not create entry");
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
