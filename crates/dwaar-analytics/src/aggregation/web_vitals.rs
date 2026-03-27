// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Streaming Web Vitals percentile tracking using `TDigest`.
//!
//! Three independent `TDigest` instances track LCP (Largest Contentful
//! Paint), CLS (Cumulative Layout Shift), and INP (Interaction to
//! Next Paint). Values are buffered and merged in batches to avoid
//! per-record heap allocation. Queries flush the buffer first.

use serde::Serialize;
use tdigest::TDigest;

/// Percentile snapshot for a single Web Vital metric.
#[derive(Debug, Clone, Serialize)]
pub struct Percentiles {
    pub p50: f64,
    pub p75: f64,
    pub p95: f64,
    pub p99: f64,
}

/// Batch size for buffered `TDigest` merges.
///
/// At 100, each merge amortizes the Vec allocation and sort across 100
/// values instead of allocating per-record. 100 is small enough that
/// queries see near-real-time data (at most 100 values behind).
const BATCH_SIZE: usize = 100;

/// Buffered `TDigest` wrapper that batches inserts.
///
/// Values accumulate in a fixed-capacity buffer. When the buffer is
/// full (or when a percentile query arrives), the buffer is flushed
/// into the `TDigest` in one `merge_unsorted` call.
#[derive(Debug)]
struct BufferedDigest {
    digest: TDigest,
    buffer: Vec<f64>,
}

impl BufferedDigest {
    fn new() -> Self {
        // TDigest size of 100 centroids — ~1 KB memory, ~1-5% accuracy
        Self {
            digest: TDigest::new_with_size(100),
            buffer: Vec::with_capacity(BATCH_SIZE),
        }
    }

    fn record(&mut self, value: f64) {
        self.buffer.push(value);
        if self.buffer.len() >= BATCH_SIZE {
            self.flush();
        }
    }

    fn flush(&mut self) {
        if self.buffer.is_empty() {
            return;
        }
        // Single allocation + sort for the whole batch
        let batch = std::mem::replace(&mut self.buffer, Vec::with_capacity(BATCH_SIZE));
        self.digest = self.digest.merge_unsorted(batch);
    }

    fn estimate_quantile(&mut self, q: f64) -> f64 {
        self.flush(); // ensure all values are merged
        self.digest.estimate_quantile(q)
    }

    fn is_empty(&mut self) -> bool {
        self.flush();
        self.digest.is_empty()
    }
}

/// Streaming Web Vitals percentile tracker.
///
/// Each metric is tracked independently via a buffered `TDigest`.
/// Inserts are O(1) amortized (buffered). Queries flush the buffer
/// first, so they always reflect the latest data.
#[derive(Debug)]
pub struct WebVitals {
    lcp: BufferedDigest,
    cls: BufferedDigest,
    inp: BufferedDigest,
}

impl WebVitals {
    pub fn new() -> Self {
        Self {
            lcp: BufferedDigest::new(),
            cls: BufferedDigest::new(),
            inp: BufferedDigest::new(),
        }
    }

    pub fn record_lcp(&mut self, ms: f64) {
        self.lcp.record(ms);
    }

    pub fn record_cls(&mut self, score: f64) {
        self.cls.record(score);
    }

    pub fn record_inp(&mut self, ms: f64) {
        self.inp.record(ms);
    }

    pub fn lcp_percentiles(&mut self) -> Percentiles {
        Self::query(&mut self.lcp)
    }

    pub fn cls_percentiles(&mut self) -> Percentiles {
        Self::query(&mut self.cls)
    }

    pub fn inp_percentiles(&mut self) -> Percentiles {
        Self::query(&mut self.inp)
    }

    fn query(digest: &mut BufferedDigest) -> Percentiles {
        if digest.is_empty() {
            return Percentiles {
                p50: 0.0,
                p75: 0.0,
                p95: 0.0,
                p99: 0.0,
            };
        }
        Percentiles {
            p50: digest.estimate_quantile(0.50),
            p75: digest.estimate_quantile(0.75),
            p95: digest.estimate_quantile(0.95),
            p99: digest.estimate_quantile(0.99),
        }
    }
}

impl Default for WebVitals {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_query_lcp() {
        let mut wv = WebVitals::new();
        for ms in (1000..=2000).step_by(100) {
            wv.record_lcp(f64::from(ms));
        }
        let p = wv.lcp_percentiles();
        assert!((p.p50 - 1500.0).abs() < 200.0, "p50={}", p.p50);
        assert!(p.p99 >= 1800.0, "p99={}", p.p99);
    }

    #[test]
    fn record_and_query_cls() {
        let mut wv = WebVitals::new();
        for i in 0..100 {
            wv.record_cls(f64::from(i) * 0.01);
        }
        let p = wv.cls_percentiles();
        assert!((p.p50 - 0.50).abs() < 0.1, "p50={}", p.p50);
    }

    #[test]
    fn record_and_query_inp() {
        let mut wv = WebVitals::new();
        for ms in (50..=500).step_by(10) {
            wv.record_inp(f64::from(ms));
        }
        let p = wv.inp_percentiles();
        assert!((p.p50 - 275.0).abs() < 50.0, "p50={}", p.p50);
    }

    #[test]
    fn empty_returns_zeros() {
        let mut wv = WebVitals::new();
        let p = wv.lcp_percentiles();
        assert!(p.p50.abs() < f64::EPSILON);
        assert!(p.p99.abs() < f64::EPSILON);
    }

    #[test]
    fn tdigest_accuracy_within_5_percent() {
        let mut wv = WebVitals::new();
        let mut values: Vec<f64> = (0..100_000).map(f64::from).collect();
        for &v in &values {
            wv.record_lcp(v);
        }
        values.sort_by(|a, b| a.partial_cmp(b).expect("no NaN"));
        let exact_p50 = values[49_999];
        let exact_p99 = values[98_999];
        let p = wv.lcp_percentiles();
        let p50_err = (p.p50 - exact_p50).abs() / exact_p50;
        let p99_err = (p.p99 - exact_p99).abs() / exact_p99;
        assert!(p50_err < 0.05, "p50 error {p50_err:.4} exceeds 5%");
        assert!(p99_err < 0.05, "p99 error {p99_err:.4} exceeds 5%");
    }

    #[test]
    fn batch_flush_happens_at_capacity() {
        let mut bd = BufferedDigest::new();
        for i in 0..BATCH_SIZE {
            bd.record(f64::from(i as u32));
        }
        // Buffer should have auto-flushed at BATCH_SIZE
        assert!(
            bd.buffer.is_empty(),
            "buffer should be empty after reaching batch size"
        );
        assert!(!bd.digest.is_empty(), "digest should have data after flush");
    }

    #[test]
    fn partial_buffer_flushed_on_query() {
        let mut bd = BufferedDigest::new();
        bd.record(42.0);
        bd.record(84.0);
        assert_eq!(bd.buffer.len(), 2, "buffer holds values before flush");
        // Query forces flush
        let p50 = bd.estimate_quantile(0.5);
        assert!(bd.buffer.is_empty(), "query should flush buffer");
        assert!((p50 - 63.0).abs() < 25.0, "p50={p50}");
    }
}
