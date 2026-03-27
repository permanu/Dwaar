// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Per-domain analytics aggregation.
//!
//! Collects server-side request logs and client-side beacon events into
//! bounded, probabilistic data structures. The [`service::AggregationService`]
//! consumes both channels and flushes snapshots every 60 seconds.

pub mod bounded_counter;
pub mod minute_buckets;
pub mod service;
pub mod top_k;
pub mod web_vitals;

use hyperloglog::HyperLogLog;
use tokio::sync::mpsc;
use tracing::warn;

use self::bounded_counter::BoundedCounter;
use self::minute_buckets::MinuteBuckets;
use self::top_k::TopK;
use self::web_vitals::WebVitals;

const CHANNEL_CAPACITY: usize = 8192;
const TOP_PAGES_K: usize = 100;
const TOP_REFERRERS_N: usize = 50;
const TOP_COUNTRIES_N: usize = 250;

/// Per-domain analytics aggregates.
///
/// ~30 KB per domain. All structures are bounded — no unbounded
/// growth regardless of traffic volume.
#[derive(Debug)]
pub struct DomainMetrics {
    pub page_views: MinuteBuckets,
    pub unique_visitors: HyperLogLog,
    pub top_pages: TopK<String>,
    pub referrers: BoundedCounter<String>,
    pub countries: BoundedCounter<String>,
    pub status_codes: [u64; 6],
    pub bytes_sent: u64,
    pub web_vitals: WebVitals,
}

impl DomainMetrics {
    pub fn new() -> Self {
        Self {
            page_views: MinuteBuckets::new(),
            unique_visitors: HyperLogLog::new(0.02),
            top_pages: TopK::new(TOP_PAGES_K),
            referrers: BoundedCounter::new(TOP_REFERRERS_N),
            countries: BoundedCounter::new(TOP_COUNTRIES_N),
            status_codes: [0; 6],
            bytes_sent: 0,
            web_vitals: WebVitals::new(),
        }
    }

    /// Update from a server-side request log entry.
    pub fn ingest_log(&mut self, log: &dwaar_log::RequestLog) {
        self.page_views.increment();
        self.unique_visitors.insert(&log.client_ip);
        self.top_pages.insert(log.path.clone());
        self.status_codes[status_bucket(log.status)] += 1;
        self.bytes_sent += log.bytes_sent;

        if let Some(domain) = log.referer.as_deref().and_then(extract_domain) {
            self.referrers.insert(domain);
        }
        if let Some(ref country) = log.country {
            self.countries.insert(country.clone());
        }
    }

    /// Update from a client-side beacon event.
    pub fn ingest_beacon(&mut self, beacon: &crate::beacon::BeaconEvent) {
        self.unique_visitors.insert(&beacon.client_ip);

        self.top_pages.insert(extract_path(&beacon.url));

        if let Some(domain) = beacon.referrer.as_deref().and_then(extract_domain) {
            self.referrers.insert(domain);
        }
        if let Some(lcp) = beacon.lcp_ms {
            self.web_vitals.record_lcp(lcp);
        }
        if let Some(cls) = beacon.cls {
            self.web_vitals.record_cls(cls);
        }
        if let Some(inp) = beacon.inp_ms {
            self.web_vitals.record_inp(inp);
        }
    }
}

impl Default for DomainMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Map HTTP status code to bucket index: [1xx, 2xx, 3xx, 4xx, 5xx, other].
pub fn status_bucket(status: u16) -> usize {
    match status {
        100..=199 => 0,
        200..=299 => 1,
        300..=399 => 2,
        400..=499 => 3,
        500..=599 => 4,
        _ => 5,
    }
}

/// Extract domain from a URL (e.g., `https://google.com/search` → `google.com`).
fn extract_domain(url: &str) -> Option<String> {
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let domain = without_scheme.split('/').next()?;
    let domain = domain.split(':').next()?; // strip port
    if domain.is_empty() { None } else { Some(domain.to_lowercase()) }
}

/// Extract path from a full URL (e.g., `https://example.com/about?q=1` → `/about`).
fn extract_path(url: &str) -> String {
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let after_host = without_scheme.find('/').map(|i| &without_scheme[i..]);
    let path = after_host.unwrap_or("/");
    let path = path.split('?').next().unwrap_or(path);
    path.to_string()
}

/// Sender handle for request log entries going to aggregation.
#[derive(Debug, Clone)]
pub struct AggSender {
    tx: mpsc::Sender<dwaar_log::RequestLog>,
}

impl AggSender {
    /// Non-blocking send. Drops the entry if the channel is full.
    pub fn send(&self, entry: dwaar_log::RequestLog) {
        if self.tx.try_send(entry).is_err() {
            warn!("aggregation channel full, dropping entry");
        }
    }
}

/// Receiver end of the aggregation channel.
///
/// Consumed by [`service::AggregationService`] in its `run()`  method.
#[derive(Debug)]
pub struct AggReceiver {
    /// Read by `AggregationService::run()` — currently unused until Task 7.
    pub rx: mpsc::Receiver<dwaar_log::RequestLog>,
}

/// Create a bounded aggregation channel.
pub fn agg_channel() -> (AggSender, AggReceiver) {
    let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
    (AggSender { tx }, AggReceiver { rx })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn domain_metrics_new_is_empty() {
        let dm = DomainMetrics::new();
        assert_eq!(dm.status_codes, [0; 6]);
        assert_eq!(dm.bytes_sent, 0);
        assert!(dm.top_pages.is_empty());
        assert!(dm.referrers.is_empty());
        assert!(dm.countries.is_empty());
    }

    #[test]
    fn status_bucket_mapping() {
        assert_eq!(status_bucket(100), 0);
        assert_eq!(status_bucket(200), 1);
        assert_eq!(status_bucket(301), 2);
        assert_eq!(status_bucket(404), 3);
        assert_eq!(status_bucket(503), 4);
        assert_eq!(status_bucket(0), 5);
        assert_eq!(status_bucket(600), 5);
    }

    #[test]
    fn agg_channel_bounded() {
        let (sender, _rx) = agg_channel();
        let dummy = dwaar_log::RequestLog {
            timestamp: chrono::Utc::now(),
            request_id: String::new(),
            method: "GET".into(),
            path: "/".into(),
            query: None,
            host: "test.com".into(),
            status: 200,
            response_time_us: 0,
            client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            user_agent: None,
            referer: None,
            bytes_sent: 0,
            bytes_received: 0,
            tls_version: None,
            http_version: "HTTP/1.1".into(),
            is_bot: false,
            country: None,
            upstream_addr: String::new(),
            upstream_response_time_us: 0,
            cache_status: None,
            compression: None,
        };
        // Should not panic — drops silently when full
        for _ in 0..10_000 {
            sender.send(dummy.clone());
        }
    }

    #[test]
    fn hyperloglog_accuracy() {
        // Use deterministic seed so the test is reproducible
        let mut hll = HyperLogLog::new_deterministic(0.02, 42);
        for i in 0..100_000u32 {
            let ip = IpAddr::V4(Ipv4Addr::from(i));
            hll.insert(&ip);
        }
        let estimate = hll.len() as u64;
        let error = (estimate as f64 - 100_000.0).abs() / 100_000.0;
        assert!(error < 0.05, "HLL error {error:.4} exceeds 5% (estimate={estimate})");
    }

    #[test]
    fn extract_domain_from_urls() {
        assert_eq!(extract_domain("https://google.com/search"), Some("google.com".into()));
        assert_eq!(extract_domain("http://example.com:8080/path"), Some("example.com".into()));
        assert_eq!(extract_domain("https://"), None);
        assert_eq!(extract_domain("bare-domain.com/path"), Some("bare-domain.com".into()));
    }

    #[test]
    fn extract_path_from_urls() {
        assert_eq!(extract_path("https://example.com/about?q=1"), "/about");
        assert_eq!(extract_path("https://example.com/"), "/");
        assert_eq!(extract_path("https://example.com"), "/");
    }

    #[test]
    fn ingest_log_updates_all_fields() {
        let mut dm = DomainMetrics::new();
        let log = dwaar_log::RequestLog {
            timestamp: chrono::Utc::now(),
            request_id: String::new(),
            method: "GET".into(),
            path: "/home".into(),
            query: None,
            host: "example.com".into(),
            status: 200,
            response_time_us: 100,
            client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            user_agent: None,
            referer: Some("https://google.com/search".into()),
            bytes_sent: 1024,
            bytes_received: 0,
            tls_version: None,
            http_version: "HTTP/1.1".into(),
            is_bot: false,
            country: Some("US".into()),
            upstream_addr: "127.0.0.1:8080".into(),
            upstream_response_time_us: 50,
            cache_status: None,
            compression: None,
        };
        dm.ingest_log(&log);

        assert_eq!(dm.status_codes[1], 1); // 2xx
        assert_eq!(dm.bytes_sent, 1024);
        assert_eq!(dm.top_pages.top()[0].0, "/home");
        assert_eq!(dm.referrers.top()[0].0, "google.com");
        assert_eq!(dm.countries.top()[0].0, "US");
    }
}
