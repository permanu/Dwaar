// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Serializable snapshot of [`DomainMetrics`] for the Admin API.
//!
//! [`AnalyticsSnapshot`] takes an immutable reference to live aggregates and
//! copies out only what the HTTP response needs. This keeps the Admin API
//! read-only — no flushes, no mutable borrows, no side-effects on the
//! hot aggregation path.

use serde::Serialize;

use super::DomainMetrics;
use super::web_vitals::Percentiles;

/// A single top-page entry, ordered by page-view count descending.
#[derive(Debug, Serialize)]
pub struct PageEntry {
    pub path: String,
    pub views: u64,
}

/// A single referrer domain entry, ordered by count descending.
#[derive(Debug, Serialize)]
pub struct ReferrerEntry {
    pub domain: String,
    pub count: u64,
}

/// A single country entry, ordered by count descending.
#[derive(Debug, Serialize)]
pub struct CountryEntry {
    pub country: String,
    pub count: u64,
}

/// HTTP status code breakdown across the six standard buckets.
#[derive(Debug, Serialize)]
pub struct StatusCodeBreakdown {
    pub s1xx: u64,
    pub s2xx: u64,
    pub s3xx: u64,
    pub s4xx: u64,
    pub s5xx: u64,
    pub other: u64,
}

/// HTTP status-class count entry for the Admin API. Always emitted in
/// order 1xx..5xx with zero counts included so frontend heatmaps can
/// key on a stable label set.
#[derive(Debug, Serialize)]
pub struct StatusClassEntry {
    pub class: String,
    pub count: u64,
}

/// One UTM attribution entry for the Admin API. A single struct covers
/// all five UTM dimensions (`utm_source`, `utm_medium`, `utm_campaign`,
/// `utm_term`, `utm_content`) — the owning field on
/// [`AnalyticsSnapshot`] carries the dimension.
#[derive(Debug, Serialize)]
pub struct UtmEntry {
    pub value: String,
    pub count: u64,
}

/// One response-latency histogram bucket entry for the Admin API. `le`
/// is the bucket upper-bound label (`"10"` … `"10000"` or `"+Inf"`);
/// `count` is the non-cumulative observation count that landed in
/// `(previous_edge, le]`. Always emitted in order across all ten
/// buckets so downstream heatmaps key on a stable axis.
#[derive(Debug, Serialize)]
pub struct LatencyBucketEntry {
    pub le: String,
    pub count: u64,
}

/// Percentile snapshot for LCP, CLS, and INP Web Vitals.
///
/// Read via `peek_*_percentiles` — intentionally does not flush the
/// pending `TDigest` buffer, so values may lag by up to `BATCH_SIZE`
/// observations. Accurate enough for a dashboard read; the flush
/// happens at the 60-second aggregation cycle regardless.
#[derive(Debug, Serialize)]
pub struct VitalsSnapshot {
    pub lcp: Percentiles,
    pub cls: Percentiles,
    pub inp: Percentiles,
}

/// Current schema version of the `AnalyticsSnapshot` wire format.
///
/// Consumers reject any snapshot whose `schema_version` doesn't match
/// the version they were compiled against. Bumping this on a breaking
/// field rename forces upstream code to re-test against the new shape
/// rather than silently dropping data via serde defaults.
pub const ANALYTICS_SCHEMA_VERSION: u32 = 1;

/// Serializable read-only view of per-domain analytics.
///
/// Constructed from an immutable `&DomainMetrics` — never mutates
/// the live aggregates. Safe to call on every Admin API GET.
#[derive(Debug, Serialize)]
pub struct AnalyticsSnapshot {
    /// Schema version for downstream readers.
    pub schema_version: u32,
    pub domain: String,
    /// May include stale counts if no traffic has arrived recently — the 60s flush cycle clears stale buckets.
    pub page_views_1m: u64,
    pub page_views_60m: u64,
    pub unique_visitors: u64,
    pub top_pages: Vec<PageEntry>,
    pub referrers: Vec<ReferrerEntry>,
    pub countries: Vec<CountryEntry>,
    pub status_codes: StatusCodeBreakdown,
    /// HTTP status classes 1xx..5xx in order with zero counts included.
    /// Sibling of `status_codes` but shaped for dashboards that want a
    /// stable label enumeration rather than a struct of fields.
    pub status_classes: Vec<StatusClassEntry>,
    /// Top-N UTM attribution counters. Lowercased and length-capped at
    /// ingest; bounded at 50/20/50/25/25 respectively (term/content are
    /// tighter because their value space is the most ad-hoc) so the
    /// Admin API response stays small regardless of traffic.
    pub utm_sources: Vec<UtmEntry>,
    pub utm_mediums: Vec<UtmEntry>,
    pub utm_campaigns: Vec<UtmEntry>,
    pub utm_terms: Vec<UtmEntry>,
    pub utm_contents: Vec<UtmEntry>,
    /// Server-observed response-latency histogram across ten fixed
    /// buckets (edges `[10, 50, 100, 250, 500, 1000, 2500, 5000, 10000,
    /// +Inf]` milliseconds). Always emitted in order with zero counts
    /// included so the Admin API heatmap renders a stable axis without
    /// gap-filling. Cardinality is bounded at ten labels by
    /// construction — see
    /// [`crate::aggregation::latency_histogram::BucketHistogram`].
    pub response_latency_buckets: Vec<LatencyBucketEntry>,
    pub bytes_sent: u64,
    pub web_vitals: VitalsSnapshot,
    /// Bot vs human pageview split. Cumulative since the last 60s
    /// aggregation flush. Both fields together approximately sum to
    /// the page-view counters above modulo timing race.
    pub bot_views: u64,
    pub human_views: u64,
    /// Explicit aggregation window so consumers can detect heartbeat
    /// gaps. `window_end` is the cutoff for this snapshot; `window_start`
    /// is `window_end - 60s` for the fixed 60-second flush cycle today.
    pub window_start: String,
    pub window_end: String,
    /// Deprecated alias of `window_end`. Kept for one release cycle
    /// so pre-window_end readers continue to receive a sane timestamp.
    pub timestamp: String,
}

impl AnalyticsSnapshot {
    /// Build a snapshot from immutable domain metrics.
    ///
    /// All reads are non-mutating — safe to call concurrently with ingestion.
    pub fn from_metrics(domain: &str, m: &DomainMetrics) -> Self {
        let top_pages = m
            .top_pages
            .top()
            .into_iter()
            .map(|(path, views)| PageEntry { path, views })
            .collect();

        let referrers = m
            .referrers
            .top()
            .into_iter()
            .map(|(domain, count)| ReferrerEntry { domain, count })
            .collect();

        let countries = m
            .countries
            .top()
            .into_iter()
            .map(|(country, count)| CountryEntry { country, count })
            .collect();

        // status_codes layout: [1xx, 2xx, 3xx, 4xx, 5xx, other]
        let sc = &m.status_codes;
        let status_codes = StatusCodeBreakdown {
            s1xx: sc[0],
            s2xx: sc[1],
            s3xx: sc[2],
            s4xx: sc[3],
            s5xx: sc[4],
            other: sc[5],
        };
        let status_classes = crate::aggregation::status_class_snapshot(sc)
            .into_iter()
            .map(|(class, count)| StatusClassEntry { class, count })
            .collect();
        let utm_sources = m
            .utm_sources
            .top()
            .into_iter()
            .map(|(value, count)| UtmEntry { value, count })
            .collect();
        let utm_mediums = m
            .utm_mediums
            .top()
            .into_iter()
            .map(|(value, count)| UtmEntry { value, count })
            .collect();
        let utm_campaigns = m
            .utm_campaigns
            .top()
            .into_iter()
            .map(|(value, count)| UtmEntry { value, count })
            .collect();
        let utm_terms = m
            .utm_terms
            .top()
            .into_iter()
            .map(|(value, count)| UtmEntry { value, count })
            .collect();
        let utm_contents = m
            .utm_contents
            .top()
            .into_iter()
            .map(|(value, count)| UtmEntry { value, count })
            .collect();
        let response_latency_buckets = m
            .response_latency_buckets
            .snapshot()
            .into_iter()
            .map(|(le, count)| LatencyBucketEntry { le, count })
            .collect();

        let web_vitals = VitalsSnapshot {
            lcp: m.web_vitals.peek_lcp_percentiles(),
            cls: m.web_vitals.peek_cls_percentiles(),
            inp: m.web_vitals.peek_inp_percentiles(),
        };

        let now = chrono::Utc::now();
        let window_end = now.to_rfc3339();
        // 60-second flush cycle is the only supported window today.
        // When variable windows ship, replace this with the real boundary.
        let window_start = (now - chrono::Duration::seconds(60)).to_rfc3339();

        Self {
            schema_version: ANALYTICS_SCHEMA_VERSION,
            domain: domain.to_owned(),
            page_views_1m: m.page_views.count_last_n_now(1),
            page_views_60m: m.page_views.count_last_n_now(60),
            unique_visitors: m.unique_visitors.len() as u64,
            top_pages,
            referrers,
            countries,
            status_codes,
            status_classes,
            utm_sources,
            utm_mediums,
            utm_campaigns,
            utm_terms,
            utm_contents,
            response_latency_buckets,
            bytes_sent: m.bytes_sent,
            web_vitals,
            bot_views: m.bot_views,
            human_views: m.human_views,
            window_start,
            window_end: window_end.clone(),
            timestamp: window_end, // deprecated alias
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aggregation::{AggEvent, DomainMetrics};
    use std::net::{IpAddr, Ipv4Addr};

    fn test_event(path: &str, status: u16) -> AggEvent {
        AggEvent {
            host: "test.example.com".into(),
            path: path.into(),
            query: None,
            status,
            bytes_sent: 1024,
            client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
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

    #[test]
    fn snapshot_reflects_ingested_logs() {
        let mut dm = DomainMetrics::new();
        for _ in 0..5 {
            dm.ingest_log(&test_event("/home", 200));
        }
        dm.ingest_log(&test_event("/about", 404));

        let snap = AnalyticsSnapshot::from_metrics("test.example.com", &dm);

        assert_eq!(snap.domain, "test.example.com");
        assert_eq!(snap.page_views_1m, 6);
        assert_eq!(snap.unique_visitors, 1);
        assert_eq!(snap.status_codes.s2xx, 5);
        assert_eq!(snap.status_codes.s4xx, 1);
        assert_eq!(snap.bytes_sent, 6 * 1024);
        assert!(!snap.top_pages.is_empty());
        assert!(!snap.referrers.is_empty());
        assert!(!snap.countries.is_empty());
    }

    #[test]
    fn snapshot_serializes_to_valid_json() {
        let dm = DomainMetrics::new();
        let snap = AnalyticsSnapshot::from_metrics("empty.com", &dm);
        let json = serde_json::to_string(&snap).expect("serialize");
        assert!(json.contains("\"domain\":\"empty.com\""));
        assert!(json.contains("\"page_views_1m\":0"));
    }

    #[test]
    fn snapshot_is_immutable() {
        let dm = DomainMetrics::new();
        let _snap1 = AnalyticsSnapshot::from_metrics("a.com", &dm);
        let _snap2 = AnalyticsSnapshot::from_metrics("a.com", &dm);
    }
}
