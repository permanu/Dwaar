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
pub mod snapshot;
pub mod top_k;
pub mod web_vitals;

use hyperloglog::HyperLogLog;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::warn;

use self::bounded_counter::BoundedCounter;
use self::minute_buckets::MinuteBuckets;
use self::top_k::TopK;
use self::web_vitals::WebVitals;

const CHANNEL_CAPACITY: usize = 8192;

/// Slim event for analytics aggregation — only the fields the aggregation
/// service actually reads. Avoids cloning the full `RequestLog` (20+ fields)
/// on every request when only a handful are needed.
#[derive(Debug, Clone)]
pub struct AggEvent {
    pub host: Arc<str>,
    pub path: Arc<str>,
    pub status: u16,
    pub bytes_sent: u64,
    pub client_ip: IpAddr,
    pub country: Option<Arc<str>>,
    pub referer: Option<Arc<str>>,
    /// Raw `User-Agent` request header. Used by
    /// [`DomainMetrics::ingest_log`] to classify the request into a
    /// fixed `mobile|desktop|tablet|bot|unknown` bucket via
    /// [`classify_device`]. Never retained beyond classification so
    /// the raw string is not stored in any aggregate.
    pub user_agent: Option<Arc<str>>,
    /// Bot classification from the bot-detect plugin (priority 10),
    /// propagated so the aggregation snapshot can surface bot-vs-human
    /// pageview ratios. Default `false` is treated as a human request.
    pub is_bot: bool,
}
const TOP_PAGES_K: usize = 100;
const TOP_REFERRERS_N: usize = 50;
const TOP_COUNTRIES_N: usize = 250;
/// Fixed device enum (mobile, desktop, tablet, bot, unknown) — the
/// `BoundedCounter` capacity is sized to exactly cover this enum so
/// cardinality can never exceed the number of buckets even if a new
/// classifier branch is added.
const DEVICE_BUCKETS: usize = 5;

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
    /// Per-device-class pageview counter across the fixed
    /// `mobile|desktop|tablet|bot|unknown` enum. Sized to exactly
    /// cover the classifier output so the bounded counter can never
    /// exceed its capacity regardless of traffic.
    pub devices: BoundedCounter<String>,
    pub status_codes: [u64; 6],
    pub bytes_sent: u64,
    pub web_vitals: WebVitals,
    /// Cumulative bot vs human pageview counters. The `page_views`
    /// `MinuteBuckets` counter is the union of both — these counters
    /// answer "what fraction of traffic is bot?" without needing a
    /// separate time-windowed structure.
    pub bot_views: u64,
    pub human_views: u64,
}

impl DomainMetrics {
    pub fn new() -> Self {
        Self {
            page_views: MinuteBuckets::new(),
            unique_visitors: HyperLogLog::new(0.02),
            top_pages: TopK::new(TOP_PAGES_K),
            referrers: BoundedCounter::new(TOP_REFERRERS_N),
            countries: BoundedCounter::new(TOP_COUNTRIES_N),
            devices: BoundedCounter::new(DEVICE_BUCKETS),
            status_codes: [0; 6],
            bytes_sent: 0,
            web_vitals: WebVitals::new(),
            bot_views: 0,
            human_views: 0,
        }
    }

    /// Update from a server-side aggregation event.
    ///
    /// The client IP is anonymized via [`crate::beacon::anonymize_ip`]
    /// before insertion into the unique-visitors sketch so the beacon
    /// path and the log path agree on the same /24 (IPv4) or /48 (IPv6)
    /// prefix — see M-22 in the audit remediation notes.
    pub fn ingest_log(&mut self, event: &AggEvent) {
        self.page_views.increment();
        let anon_ip = crate::beacon::anonymize_ip(event.client_ip);
        self.unique_visitors.insert(&anon_ip);
        self.top_pages.insert(event.path.to_string());
        self.status_codes[status_bucket(event.status)] += 1;
        self.bytes_sent += event.bytes_sent;
        // Split bot vs human counters from the bot-detect classification.
        if event.is_bot {
            self.bot_views += 1;
        } else {
            self.human_views += 1;
        }

        if let Some(domain) = event.referer.as_deref().and_then(extract_domain) {
            self.referrers.insert(domain);
        }
        if let Some(ref country) = event.country {
            self.countries.insert(country.to_string());
        }
        // Classify the User-Agent into the fixed five-bucket device enum
        // so `devices.top()` reports mobile vs desktop vs tablet vs bot vs
        // unknown without ever persisting the raw header (PII-sensitive
        // and unbounded in cardinality).
        let device = match event.user_agent.as_deref() {
            Some(ua) => classify_device(ua),
            None => "unknown",
        };
        self.devices.insert(device.to_string());
    }

    /// Update from a client-side beacon event.
    ///
    /// `beacon.url` and `beacon.referrer` are user-controlled, so both
    /// go through [`crate::beacon::sanitize_url_to_path`] and
    /// [`crate::beacon::sanitize_referrer_host`] before hitting the
    /// bounded counters (C-05). Any beacon that fails URL validation
    /// is dropped silently — the beacon is best-effort telemetry and
    /// returning an error status would leak validation state to the
    /// client.
    ///
    /// `client_ip` is already anonymized by `BeaconEvent::from_raw`,
    /// which goes through the same [`crate::beacon::anonymize_ip`]
    /// policy as `ingest_log` above.
    pub fn ingest_beacon(&mut self, beacon: &crate::beacon::BeaconEvent) {
        let Some(path) = crate::beacon::sanitize_url_to_path(&beacon.url) else {
            // Drop malformed beacons entirely — no partial aggregation.
            return;
        };

        self.unique_visitors.insert(&beacon.client_ip);
        self.top_pages.insert(path);

        if let Some(referrer) = beacon
            .referrer
            .as_deref()
            .and_then(crate::beacon::sanitize_referrer_host)
        {
            self.referrers.insert(referrer);
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

/// Classify a `User-Agent` string into a fixed five-bucket enum:
/// `mobile | desktop | tablet | bot | unknown`.
///
/// Intentionally coarse — headline numbers only. Precedence:
/// 1. Bot / crawler / spider markers win over everything else so
///    automated traffic never counts toward mobile/desktop share.
/// 2. Tablet markers win over mobile because iPads advertise "Mobile"
///    in their UA and would otherwise double-count.
/// 3. Mobile markers (`mobile`, `android`, `iphone`).
/// 4. Everything else is `desktop`.
///
/// An empty UA returns `unknown` so downstream dashboards can flag
/// the gap instead of misattributing it to desktop. The raw UA is
/// never retained — this function is the sole path from
/// `User-Agent` to the bounded counter.
pub fn classify_device(ua: &str) -> &'static str {
    if ua.is_empty() {
        return "unknown";
    }
    let ua_lower = ua.to_lowercase();
    if ua_lower.contains("bot") || ua_lower.contains("crawler") || ua_lower.contains("spider") {
        return "bot";
    }
    if ua_lower.contains("tablet") || ua_lower.contains("ipad") {
        return "tablet";
    }
    if ua_lower.contains("mobile") || ua_lower.contains("android") || ua_lower.contains("iphone") {
        return "mobile";
    }
    "desktop"
}

/// Extract domain from a URL (e.g., `https://google.com/search` → `google.com`).
fn extract_domain(url: &str) -> Option<String> {
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let domain = without_scheme.split('/').next()?;
    let domain = domain.split(':').next()?; // strip port
    if domain.is_empty() {
        None
    } else {
        Some(domain.to_lowercase())
    }
}

/// Sender handle for aggregation events.
#[derive(Debug, Clone)]
pub struct AggSender {
    tx: mpsc::Sender<AggEvent>,
}

impl AggSender {
    /// Non-blocking send. Drops the entry if the channel is full.
    pub fn send(&self, entry: AggEvent) {
        if self.tx.try_send(entry).is_err() {
            warn!("aggregation channel full, dropping entry");
        }
    }
}

/// Receiver end of the aggregation channel.
///
/// Consumed by [`service::AggregationService`] in its `run()` method.
#[derive(Debug)]
pub struct AggReceiver {
    pub rx: mpsc::Receiver<AggEvent>,
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
        let dummy = AggEvent {
            host: "test.com".into(),
            path: "/".into(),
            status: 200,
            bytes_sent: 0,
            client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            country: None,
            referer: None,
            user_agent: None,
            is_bot: false,
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
        assert!(
            error < 0.05,
            "HLL error {error:.4} exceeds 5% (estimate={estimate})"
        );
    }

    #[test]
    fn extract_domain_from_urls() {
        assert_eq!(
            extract_domain("https://google.com/search"),
            Some("google.com".into())
        );
        assert_eq!(
            extract_domain("http://example.com:8080/path"),
            Some("example.com".into())
        );
        assert_eq!(extract_domain("https://"), None);
        assert_eq!(
            extract_domain("bare-domain.com/path"),
            Some("bare-domain.com".into())
        );
    }

    #[test]
    fn ingest_log_updates_all_fields() {
        let mut dm = DomainMetrics::new();
        let event = AggEvent {
            host: "example.com".into(),
            path: "/home".into(),
            status: 200,
            bytes_sent: 1024,
            client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            country: Some("US".into()),
            referer: Some("https://google.com/search".into()),
            user_agent: Some(
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/15E148".into(),
            ),
            is_bot: false,
        };
        dm.ingest_log(&event);

        assert_eq!(dm.status_codes[1], 1); // 2xx
        assert_eq!(dm.bytes_sent, 1024);
        assert_eq!(dm.top_pages.top()[0].0, "/home");
        assert_eq!(dm.referrers.top()[0].0, "google.com");
        assert_eq!(dm.countries.top()[0].0, "US");
        assert_eq!(dm.devices.top()[0].0, "mobile");
    }

    #[test]
    fn classify_device_buckets() {
        // Bots / crawlers / spiders win over any other match.
        assert_eq!(
            classify_device("Googlebot/2.1 (+http://www.google.com/bot.html)"),
            "bot"
        );
        assert_eq!(classify_device("AhrefsBot/7.0"), "bot");
        assert_eq!(classify_device("Bingbot"), "bot");
        assert_eq!(classify_device("facebookexternalhit/1.1"), "desktop"); // no bot/crawler marker
        assert_eq!(classify_device("Mozilla spider v1"), "bot");
        assert_eq!(classify_device("Screaming Frog SEO Spider/19.5"), "bot");
        assert_eq!(classify_device("web crawler edu"), "bot");

        // Tablet markers win over mobile — iPads advertise "Mobile" too.
        assert_eq!(
            classify_device("Mozilla/5.0 (iPad; CPU OS 17_0) AppleWebKit Mobile/15E148"),
            "tablet"
        );
        assert_eq!(
            classify_device("Mozilla/5.0 (Linux; Android 11; SM-T870) AppleWebKit Tablet"),
            "tablet"
        );

        // Mobile markers.
        assert_eq!(
            classify_device("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/15E148"),
            "mobile"
        );
        assert_eq!(
            classify_device("Mozilla/5.0 (Linux; Android 13; Pixel 8) AppleWebKit Mobile Safari"),
            "mobile"
        );

        // Desktop fallback — regular Chrome/Firefox on macOS/Linux/Windows.
        assert_eq!(
            classify_device(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit Chrome/120 Safari"
            ),
            "desktop"
        );
        assert_eq!(
            classify_device("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/122.0"),
            "desktop"
        );
        assert_eq!(classify_device("curl/8.1.0"), "desktop");

        // Empty / missing UA → unknown so the dashboard can surface the gap.
        assert_eq!(classify_device(""), "unknown");
    }

    #[test]
    fn ingest_log_classifies_missing_ua_as_unknown() {
        let mut dm = DomainMetrics::new();
        let event = AggEvent {
            host: "example.com".into(),
            path: "/".into(),
            status: 200,
            bytes_sent: 128,
            client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            country: None,
            referer: None,
            user_agent: None,
            is_bot: false,
        };
        dm.ingest_log(&event);
        assert_eq!(dm.devices.top()[0].0, "unknown");
    }
}
