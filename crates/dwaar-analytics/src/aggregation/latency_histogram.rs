// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Fixed-cardinality response-latency bucket histogram.
//!
//! Each request's server-observed response time lands in one of ten
//! cumulative buckets (edges in milliseconds). The bucket edges are
//! deliberately static — the same ten labels emit across every flush
//! so the downstream heatmap keys on a stable axis and `VictoriaMetrics`
//! cardinality is bounded at `10 × domains` regardless of traffic.
//!
//! # Why fixed edges, not a `TDigest`
//!
//! [`crate::aggregation::web_vitals::WebVitals`] already uses `TDigest`
//! for LCP/CLS/INP because those feeds only care about p75. Request
//! latency additionally needs a heatmap-friendly shape (distribution
//! over time), and `TDigest` percentiles don't serialise cleanly into
//! heatmap-cell buckets. A fixed histogram keeps the wire format
//! compact (ten `(le, count)` pairs) and lets the frontend render
//! the heatmap with no additional bucketing work.
//!
//! # Bucket edges
//!
//! The ten edges `[10, 50, 100, 250, 500, 1000, 2500, 5000, 10000, +Inf]`
//! span from sub-10ms static hits through multi-second upstream calls.
//! They match the default Prometheus histogram for HTTP duration and
//! the shape operators already read when triaging latency incidents.

use serde::Serialize;

/// Bucket upper-bounds in milliseconds. The final `+Inf` bucket catches
/// everything above 10 s so no request is ever dropped from the count.
///
/// Exposed as `&'static [&'static str]` for the snapshot path so no
/// allocation happens per-flush — the labels are baked into the binary.
pub const BUCKET_EDGES_MS: [u64; 9] = [10, 50, 100, 250, 500, 1000, 2500, 5000, 10000];

/// Labels emitted on each bucket's `le` dimension. Matches the Prometheus
/// convention of labelling the cumulative upper-bound with `+Inf` for
/// the catch-all bucket. Kept as `&'static str` so the snapshot path
/// copies a `String` only when producing wire output.
pub const BUCKET_LABELS: [&str; 10] = [
    "10", "50", "100", "250", "500", "1000", "2500", "5000", "10000", "+Inf",
];

/// Ten-bucket latency histogram. Cardinality is fixed at construction
/// time so the memory footprint is 80 B per domain regardless of
/// traffic volume (ten `u64` counts).
///
/// Counts are **non-cumulative** internally (one count per bucket),
/// which keeps the increment path a single array write. The wire
/// format emitted by [`Self::snapshot`] also uses non-cumulative
/// counts — the heatmap renderer sums as needed; exposing cumulative
/// counts here would force every consumer to undo the sum.
#[derive(Debug, Clone, Default)]
pub struct BucketHistogram {
    counts: [u64; 10],
}

impl BucketHistogram {
    /// Zeroed histogram. Equivalent to `Default::default()` — the
    /// explicit constructor mirrors the other aggregation structs so
    /// `DomainMetrics::new` reads consistently.
    pub const fn new() -> Self {
        Self { counts: [0; 10] }
    }

    /// Record one observation. `latency_ms` is the server-observed
    /// response latency in milliseconds. Values above the last finite
    /// edge land in the `+Inf` bucket so no request is ever dropped.
    ///
    /// Hot path: called once per request from the aggregation service.
    /// The branch-free `partition_point` call runs in `O(log n)` over
    /// the ten edges — an unmeasurable cost next to the `DashMap`
    /// lookup that guards it.
    pub fn record(&mut self, latency_ms: u64) {
        // partition_point returns the index of the first edge strictly
        // greater than latency_ms, which is also the bucket the
        // observation belongs to. A latency equal to an edge (e.g. 50
        // on the 50 ms edge) lands in the 100 ms bucket — matches the
        // Prometheus-style `le` (less-than-or-equal) semantics where
        // the edge is the inclusive upper-bound.
        let idx = BUCKET_EDGES_MS.partition_point(|&edge| edge < latency_ms);
        self.counts[idx] += 1;
    }

    /// Total observations across every bucket. Primarily a test helper,
    /// but also useful as a sanity check in downstream consumers that
    /// want to derive a denominator for percentile-like calculations.
    pub fn total(&self) -> u64 {
        self.counts.iter().sum()
    }

    /// Non-cumulative counts, bucket-index-aligned with
    /// [`BUCKET_LABELS`]. Primarily exposed for tests; production code
    /// should use [`Self::snapshot`] which attaches the label strings.
    pub fn counts(&self) -> &[u64; 10] {
        &self.counts
    }

    /// Per-bucket `(label, count)` wire snapshot, always emitted in
    /// order with zero counts included so the frontend heatmap keys
    /// on a stable label set. Allocates one `String` per bucket
    /// (ten heap allocations per flush per domain) — acceptable because
    /// the flush cadence is 60 s.
    pub fn snapshot(&self) -> Vec<(String, u64)> {
        BUCKET_LABELS
            .iter()
            .zip(self.counts.iter())
            .map(|(label, count)| ((*label).to_string(), *count))
            .collect()
    }
}

/// Serde-friendly single-bucket entry. Matches the per-dimension entry
/// types used elsewhere in the snapshot (e.g. `StatusClassCount`) so
/// the wire shape stays visually consistent across aggregations.
#[derive(Debug, Clone, Serialize)]
pub struct BucketCount {
    /// Bucket upper-bound label. One of the ten `BUCKET_LABELS` values.
    pub le: String,
    /// Non-cumulative count of observations whose latency landed in
    /// the half-open interval `(previous_edge, this_edge]`.
    pub count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_empty() {
        let h = BucketHistogram::new();
        assert_eq!(h.total(), 0);
        assert_eq!(h.counts(), &[0u64; 10]);
    }

    #[test]
    fn record_routes_each_edge_into_expected_bucket() {
        // Table-driven: one observation per bucket, then assert the
        // count lands in exactly the right slot. Also covers the
        // inclusive-edge semantics (50 ms → second bucket because
        // 50 is ≤ the 50 ms edge).
        struct Case {
            latency_ms: u64,
            expected_bucket: usize,
        }
        let cases = [
            Case {
                latency_ms: 0,
                expected_bucket: 0,
            }, // sub-10ms
            Case {
                latency_ms: 5,
                expected_bucket: 0,
            }, // sub-10ms
            Case {
                latency_ms: 10,
                expected_bucket: 0,
            }, // = 10ms edge → first bucket
            Case {
                latency_ms: 11,
                expected_bucket: 1,
            }, // 10–50ms
            Case {
                latency_ms: 50,
                expected_bucket: 1,
            }, // = 50ms edge
            Case {
                latency_ms: 99,
                expected_bucket: 2,
            }, // 50–100ms
            Case {
                latency_ms: 200,
                expected_bucket: 3,
            }, // 100–250ms
            Case {
                latency_ms: 400,
                expected_bucket: 4,
            }, // 250–500ms
            Case {
                latency_ms: 999,
                expected_bucket: 5,
            }, // 500–1000ms
            Case {
                latency_ms: 1500,
                expected_bucket: 6,
            }, // 1000–2500ms
            Case {
                latency_ms: 4000,
                expected_bucket: 7,
            }, // 2500–5000ms
            Case {
                latency_ms: 7500,
                expected_bucket: 8,
            }, // 5000–10000ms
            Case {
                latency_ms: 10_000,
                expected_bucket: 8,
            }, // = 10 s edge
            Case {
                latency_ms: 15_000,
                expected_bucket: 9,
            }, // +Inf
            Case {
                latency_ms: u64::MAX,
                expected_bucket: 9,
            }, // +Inf
        ];
        for c in cases {
            let mut h = BucketHistogram::new();
            h.record(c.latency_ms);
            assert_eq!(
                h.counts()[c.expected_bucket],
                1,
                "latency {} ms should land in bucket {}",
                c.latency_ms,
                c.expected_bucket
            );
            assert_eq!(h.total(), 1);
        }
    }

    #[test]
    fn snapshot_is_stable_and_labeled() {
        let mut h = BucketHistogram::new();
        h.record(5); // bucket 0
        h.record(60); // bucket 2
        h.record(60); // bucket 2
        h.record(20_000); // bucket 9 (+Inf)

        let snap = h.snapshot();
        assert_eq!(snap.len(), 10, "ten buckets always emitted");

        // Labels must appear in the fixed order so the heatmap axis stays stable.
        let labels: Vec<_> = snap.iter().map(|(l, _)| l.as_str()).collect();
        assert_eq!(
            labels,
            vec![
                "10", "50", "100", "250", "500", "1000", "2500", "5000", "10000", "+Inf"
            ]
        );

        // Counts follow the label order.
        let counts: Vec<_> = snap.iter().map(|(_, c)| *c).collect();
        assert_eq!(counts, vec![1, 0, 2, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn snapshot_emits_zeroes_when_empty() {
        // Downstream heatmap relies on every bucket being present even
        // when no traffic has landed; otherwise an empty dashboard
        // column could be mistaken for missing data rather than zero.
        let h = BucketHistogram::new();
        let snap = h.snapshot();
        assert_eq!(snap.len(), 10);
        for (_, count) in &snap {
            assert_eq!(*count, 0);
        }
    }

    #[test]
    fn record_accumulates_across_many_observations() {
        let mut h = BucketHistogram::new();
        for _ in 0..1_000 {
            h.record(15); // always bucket 1 (10–50ms)
        }
        assert_eq!(h.counts()[1], 1_000);
        assert_eq!(h.total(), 1_000);
    }
}
