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
    /// Raw request query string (without the leading `?`), if present.
    /// Used by [`DomainMetrics::ingest_log`] to extract marketing-attribution
    /// UTM parameters via [`extract_utm_params`] and nothing else — the
    /// raw query is never persisted to any aggregate. `None` when the
    /// request carried no query string.
    pub query: Option<Arc<str>>,
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
/// UTM top-N caps. Source/campaign cardinality is higher than medium
/// (medium is typically one of a dozen conventional values like
/// `cpc|email|social|organic`), so we size the bounded counters to
/// match observed real-world attribution shapes while still preventing
/// unbounded label growth under adversarial input.
///
/// Term and content are capped tighter (25 vs 50) because their value
/// space is the most ad-hoc of the five UTM dimensions: term typically
/// carries ad-network keyword bids (long tail — thousands of variants
/// per campaign) and content typically carries A/B creative identifiers
/// (dynamic across ad rotations). Keeping these two counters small is
/// the primary cardinality-risk mitigation for shipping them at all.
const TOP_UTM_SOURCES_N: usize = 50;
const TOP_UTM_MEDIUMS_N: usize = 20;
const TOP_UTM_CAMPAIGNS_N: usize = 50;
const TOP_UTM_TERMS_N: usize = 25;
const TOP_UTM_CONTENTS_N: usize = 25;
/// Per-UTM-value length cap to defend against adversarial ballast values
/// designed to blow up the bounded counter's memory footprint. Longer
/// than any legitimate campaign slug but short enough that 150
/// (sources+campaigns combined) * 128 bytes = 19 KiB worst case.
const UTM_VALUE_MAX_LEN: usize = 128;
/// Fixed HTTP status class enum (1xx, 2xx, 3xx, 4xx, 5xx) — always
/// emitted in order with zero counts included so downstream dashboards
/// can render heatmaps without having to synthesize missing buckets.
/// Matches the first five indices of [`DomainMetrics::status_codes`]
/// (the sixth `other` bucket is never surfaced as a class — it is a
/// catch-all for out-of-range codes, reported via `status_codes`).
const STATUS_CLASS_LABELS: [&str; 5] = ["1xx", "2xx", "3xx", "4xx", "5xx"];

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
    /// UTM source counter (e.g. `google`, `newsletter`, `twitter`).
    /// Top-N sampled to prevent unbounded label growth from campaigns
    /// in the wild; the cap is set so the typical long tail of organic
    /// traffic sources is captured without becoming a `DoS` vector.
    /// Values are case-folded to lowercase at insertion time so
    /// `"Google"` and `"google"` merge.
    pub utm_sources: BoundedCounter<String>,
    /// UTM medium counter (e.g. `cpc`, `email`, `social`, `organic`).
    /// Tighter bound than source/campaign because the value space is
    /// conventionally small.
    pub utm_mediums: BoundedCounter<String>,
    /// UTM campaign counter (e.g. `spring-launch-2026`, `black-friday`).
    /// Same cap as source; campaign values are typically marketing-team
    /// controlled, but we bound anyway to defend against adversarial
    /// ballast traffic.
    pub utm_campaigns: BoundedCounter<String>,
    /// UTM term counter (e.g. `running+shoes`, `crm_software`). Typically
    /// carries ad-network keyword bids, which have the highest real-world
    /// cardinality of any UTM dimension — hence the tighter cap (25 vs
    /// 50 for source/campaign). Values are case-folded to lowercase and
    /// length-capped at insertion time just like the other UTM fields.
    pub utm_terms: BoundedCounter<String>,
    /// UTM content counter (e.g. `hero-cta-blue`, `v2-banner`). Typically
    /// carries A/B creative identifiers that rotate across ad variants,
    /// so cardinality is similarly ad-hoc to term — same tighter cap.
    pub utm_contents: BoundedCounter<String>,
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
            utm_sources: BoundedCounter::new(TOP_UTM_SOURCES_N),
            utm_mediums: BoundedCounter::new(TOP_UTM_MEDIUMS_N),
            utm_campaigns: BoundedCounter::new(TOP_UTM_CAMPAIGNS_N),
            utm_terms: BoundedCounter::new(TOP_UTM_TERMS_N),
            utm_contents: BoundedCounter::new(TOP_UTM_CONTENTS_N),
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

        // Marketing-attribution UTM parameters across the full
        // source/medium/campaign/term/content set. term/content are
        // capped tighter than the other three because their value
        // space is the most ad-hoc (keyword bids, A/B creative IDs);
        // see `TOP_UTM_TERMS_N` / `TOP_UTM_CONTENTS_N` for the cap
        // rationale. Each extracted value is lowercased at insertion
        // so `Google` and `google` merge into one bucket.
        if let Some(ref query) = event.query {
            let utm = extract_utm_params(query);
            if let Some(s) = utm.source {
                self.utm_sources.insert(s);
            }
            if let Some(m) = utm.medium {
                self.utm_mediums.insert(m);
            }
            if let Some(c) = utm.campaign {
                self.utm_campaigns.insert(c);
            }
            if let Some(t) = utm.term {
                self.utm_terms.insert(t);
            }
            if let Some(ct) = utm.content {
                self.utm_contents.insert(ct);
            }
        }
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

/// Emit the `[1xx, 2xx, 3xx, 4xx, 5xx]` status-class counts as a
/// label-count pair vector, always in order, with zero counts included.
/// Drops the sixth `other` bucket because downstream dashboards
/// already treat out-of-range codes separately via the raw
/// `status_codes` array — folding them into a class label would
/// conflate RFC-valid status codes with malformed-response counts.
pub fn status_class_snapshot(status_codes: &[u64; 6]) -> Vec<(String, u64)> {
    STATUS_CLASS_LABELS
        .iter()
        .enumerate()
        .map(|(i, label)| ((*label).to_string(), status_codes[i]))
        .collect()
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

/// Parsed UTM attribution values from a raw query string. Any
/// parameter absent or empty after trimming is returned as `None` so
/// the caller can skip inserts into the bounded counters entirely.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct UtmParams {
    pub source: Option<String>,
    pub medium: Option<String>,
    pub campaign: Option<String>,
    pub term: Option<String>,
    pub content: Option<String>,
}

/// Extract the five tracked UTM attribution parameters from a raw
/// query string (without the leading `?`). Returns lowercased,
/// length-capped values ready for insertion into the per-domain
/// bounded counters.
///
/// Covers `utm_source`, `utm_medium`, `utm_campaign`, `utm_term`, and
/// `utm_content`. term/content carry tighter downstream caps
/// (`TOP_UTM_TERMS_N`, `TOP_UTM_CONTENTS_N`) because their value space
/// is the most ad-hoc — this function merely extracts; cardinality
/// containment happens at the bounded-counter layer.
///
/// The parser is deliberately simple — no percent-decoding, no
/// fragment handling, no repeated-key semantics — because:
/// 1. UTM values in the wild are overwhelmingly ASCII slugs that
///    need no decoding to stay unique.
/// 2. Percent-decoding the raw query string would pull in the `url`
///    crate, violating the no-new-deps constraint for this cut.
/// 3. Repeated keys are handled last-wins, which matches the
///    behavior of every major analytics platform.
///
/// Values longer than [`UTM_VALUE_MAX_LEN`] are dropped (not
/// truncated) so adversarial inputs cannot grow the counter value
/// keys beyond the defensive cap.
pub fn extract_utm_params(query: &str) -> UtmParams {
    let mut out = UtmParams::default();

    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let Some((raw_key, raw_val)) = pair.split_once('=') else {
            continue;
        };
        // Only the five UTM keys matter; reject anything else without
        // allocating a new String. Case-insensitive key comparison
        // because campaign tools produce both `UTM_SOURCE` and
        // `utm_source` in the wild.
        let slot = if raw_key.eq_ignore_ascii_case("utm_source") {
            &mut out.source
        } else if raw_key.eq_ignore_ascii_case("utm_medium") {
            &mut out.medium
        } else if raw_key.eq_ignore_ascii_case("utm_campaign") {
            &mut out.campaign
        } else if raw_key.eq_ignore_ascii_case("utm_term") {
            &mut out.term
        } else if raw_key.eq_ignore_ascii_case("utm_content") {
            &mut out.content
        } else {
            continue;
        };

        let trimmed = raw_val.trim();
        if trimmed.is_empty() || trimmed.len() > UTM_VALUE_MAX_LEN {
            continue;
        }
        // Last-wins semantics: `?utm_source=a&utm_source=b` → `b`.
        *slot = Some(trimmed.to_lowercase());
    }

    out
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
            query: None,
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
            query: None,
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
            query: None,
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

    /// Table-driven UTM extraction coverage. Each row exercises one
    /// axis of the parser (happy path, case folding, missing params,
    /// malformed syntax, length cap, repeated keys, term/content
    /// coverage) so a regression in any single branch fails its own
    /// row loudly.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn extract_utm_params_table_driven() {
        struct Case {
            name: &'static str,
            query: &'static str,
            want_source: Option<&'static str>,
            want_medium: Option<&'static str>,
            want_campaign: Option<&'static str>,
            want_term: Option<&'static str>,
            want_content: Option<&'static str>,
        }
        let cases = [
            Case {
                name: "all five present",
                query: "utm_source=google&utm_medium=cpc&utm_campaign=spring_launch\
                        &utm_term=running_shoes&utm_content=hero_blue",
                want_source: Some("google"),
                want_medium: Some("cpc"),
                want_campaign: Some("spring_launch"),
                want_term: Some("running_shoes"),
                want_content: Some("hero_blue"),
            },
            Case {
                name: "case folded values merge",
                query: "utm_source=Google&utm_medium=EMAIL&utm_term=RUNNING&utm_content=HERO",
                want_source: Some("google"),
                want_medium: Some("email"),
                want_campaign: None,
                want_term: Some("running"),
                want_content: Some("hero"),
            },
            Case {
                name: "case insensitive keys for term and content",
                query: "UTM_TERM=shoes&Utm_Content=Variant_A",
                want_source: None,
                want_medium: None,
                want_campaign: None,
                want_term: Some("shoes"),
                want_content: Some("variant_a"),
            },
            Case {
                name: "missing utm entirely",
                query: "q=foo&page=2",
                want_source: None,
                want_medium: None,
                want_campaign: None,
                want_term: None,
                want_content: None,
            },
            Case {
                name: "empty query",
                query: "",
                want_source: None,
                want_medium: None,
                want_campaign: None,
                want_term: None,
                want_content: None,
            },
            Case {
                name: "malformed pairs ignored",
                query: "utm_source=reddit&brokenpair&utm_campaign=winter&utm_term=brand",
                want_source: Some("reddit"),
                want_medium: None,
                want_campaign: Some("winter"),
                want_term: Some("brand"),
                want_content: None,
            },
            Case {
                name: "empty term and content dropped",
                query: "utm_source=bing&utm_term=&utm_content=  &utm_medium=cpc",
                want_source: Some("bing"),
                want_medium: Some("cpc"),
                want_campaign: None,
                want_term: None,
                want_content: None,
            },
            Case {
                name: "term and content captured alongside rest",
                query: "utm_source=google&utm_term=shoes&utm_content=ad1",
                want_source: Some("google"),
                want_medium: None,
                want_campaign: None,
                want_term: Some("shoes"),
                want_content: Some("ad1"),
            },
            Case {
                name: "repeated term last wins",
                query: "utm_term=a&utm_term=b&utm_content=c&utm_content=d",
                want_source: None,
                want_medium: None,
                want_campaign: None,
                want_term: Some("b"),
                want_content: Some("d"),
            },
        ];
        for c in cases {
            let got = extract_utm_params(c.query);
            assert_eq!(
                got.source.as_deref(),
                c.want_source,
                "{}: source mismatch for {:?}",
                c.name,
                c.query
            );
            assert_eq!(
                got.medium.as_deref(),
                c.want_medium,
                "{}: medium mismatch for {:?}",
                c.name,
                c.query
            );
            assert_eq!(
                got.campaign.as_deref(),
                c.want_campaign,
                "{}: campaign mismatch for {:?}",
                c.name,
                c.query
            );
            assert_eq!(
                got.term.as_deref(),
                c.want_term,
                "{}: term mismatch for {:?}",
                c.name,
                c.query
            );
            assert_eq!(
                got.content.as_deref(),
                c.want_content,
                "{}: content mismatch for {:?}",
                c.name,
                c.query
            );
        }
    }

    #[test]
    fn extract_utm_params_drops_oversized_values() {
        // Adversarial ballast: term and content values exceed
        // UTM_VALUE_MAX_LEN so the keys survive the parse but the
        // values are dropped to keep the bounded counter's key-space
        // small. Source stays populated as a control.
        let huge = "x".repeat(UTM_VALUE_MAX_LEN + 1);
        let q = format!("utm_source=google&utm_term={huge}&utm_content={huge}");
        let got = extract_utm_params(&q);
        assert_eq!(got.source.as_deref(), Some("google"));
        assert!(got.term.is_none(), "oversized term must be dropped");
        assert!(got.content.is_none(), "oversized content must be dropped");
    }

    #[test]
    fn ingest_log_extracts_utm_into_bounded_counters() {
        let mut dm = DomainMetrics::new();
        let event = AggEvent {
            host: "example.com".into(),
            path: "/landing".into(),
            query: Some(
                "utm_source=Google&utm_medium=cpc&utm_campaign=Spring_2026\
                 &utm_term=Running+Shoes&utm_content=Hero_Blue"
                    .into(),
            ),
            status: 200,
            bytes_sent: 512,
            client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            country: None,
            referer: None,
            user_agent: None,
            is_bot: false,
        };
        dm.ingest_log(&event);
        assert_eq!(dm.utm_sources.top()[0].0, "google");
        assert_eq!(dm.utm_mediums.top()[0].0, "cpc");
        assert_eq!(dm.utm_campaigns.top()[0].0, "spring_2026");
        assert_eq!(dm.utm_terms.top()[0].0, "running+shoes");
        assert_eq!(dm.utm_contents.top()[0].0, "hero_blue");
    }

    #[test]
    fn ingest_log_without_query_leaves_utm_counters_empty() {
        let mut dm = DomainMetrics::new();
        let event = AggEvent {
            host: "example.com".into(),
            path: "/".into(),
            query: None,
            status: 200,
            bytes_sent: 0,
            client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
            country: None,
            referer: None,
            user_agent: None,
            is_bot: false,
        };
        dm.ingest_log(&event);
        assert!(dm.utm_sources.is_empty());
        assert!(dm.utm_mediums.is_empty());
        assert!(dm.utm_campaigns.is_empty());
        assert!(dm.utm_terms.is_empty());
        assert!(dm.utm_contents.is_empty());
    }
}
