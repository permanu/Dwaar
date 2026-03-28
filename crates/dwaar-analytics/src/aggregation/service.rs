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
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        for mut entry in self.metrics.iter_mut() {
            let domain = entry.key().clone();
            let snapshot = FlushSnapshot::from_metrics(&domain, entry.value_mut());
            if let Err(e) = serde_json::to_writer(&mut handle, &snapshot)
                .and_then(|()| handle.write_all(b"\n").map_err(serde_json::Error::io))
            {
                warn!(error = %e, domain = entry.key().as_str(), "failed to flush analytics");
            }
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

/// JSON snapshot emitted per domain during flush.
#[derive(Debug, Serialize)]
struct FlushSnapshot {
    r#type: &'static str,
    domain: String,
    timestamp: String,
    page_views_1m: u64,
    page_views_60m: u64,
    unique_visitors: u64,
    top_pages: Vec<PageCount>,
    referrers: Vec<ReferrerCount>,
    countries: Vec<CountryCount>,
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
        Self {
            r#type: "analytics",
            domain: domain.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            page_views_1m: m.page_views.count_last_n_now(1),
            page_views_60m: m.page_views.count_last_n_now(60),
            unique_visitors: m.unique_visitors.len() as u64,
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
            status,
            bytes_sent: 1024,
            client_ip: std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            country: Some("US".into()),
            referer: Some("https://google.com/search".into()),
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

        // Give the service time to process
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Signal shutdown
        shutdown_tx.send(true).expect("shutdown send");
        // Give the service time to flush and exit
        tokio::time::sleep(Duration::from_millis(50)).await;

        let entry = metrics.get("app.io").expect("domain should exist");
        assert_eq!(entry.status_codes[1], 10); // 10 x 2xx
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
        shutdown_tx.send(true).expect("shutdown send");
        tokio::time::sleep(Duration::from_millis(50)).await;

        let entry = metrics.get("stress.io").expect("domain should exist");
        assert_eq!(entry.status_codes[1], 1000, "4 * 250 = 1000 requests");
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
