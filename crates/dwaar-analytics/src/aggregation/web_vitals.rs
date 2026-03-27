// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Streaming Web Vitals percentile tracking using `TDigest`.
//!
//! Three independent `TDigest` instances track LCP (Largest Contentful
//! Paint), CLS (Cumulative Layout Shift), and INP (Interaction to
//! Next Paint). Each supports streaming inserts and quantile queries
//! at p50/p75/p95/p99.

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

/// Streaming Web Vitals percentile tracker.
///
/// Each metric is tracked independently. `TDigest` gives ~1-5% accuracy
/// at all quantiles with bounded memory (~1 KB per digest).
#[derive(Debug)]
pub struct WebVitals {
    lcp: TDigest,
    cls: TDigest,
    inp: TDigest,
}

impl WebVitals {
    pub fn new() -> Self {
        Self {
            lcp: TDigest::new_with_size(100),
            cls: TDigest::new_with_size(100),
            inp: TDigest::new_with_size(100),
        }
    }

    pub fn record_lcp(&mut self, ms: f64) {
        self.lcp = self.lcp.merge_unsorted(vec![ms]);
    }

    pub fn record_cls(&mut self, score: f64) {
        self.cls = self.cls.merge_unsorted(vec![score]);
    }

    pub fn record_inp(&mut self, ms: f64) {
        self.inp = self.inp.merge_unsorted(vec![ms]);
    }

    pub fn lcp_percentiles(&self) -> Percentiles {
        Self::query(&self.lcp)
    }

    pub fn cls_percentiles(&self) -> Percentiles {
        Self::query(&self.cls)
    }

    pub fn inp_percentiles(&self) -> Percentiles {
        Self::query(&self.inp)
    }

    fn query(digest: &TDigest) -> Percentiles {
        if digest.is_empty() {
            return Percentiles { p50: 0.0, p75: 0.0, p95: 0.0, p99: 0.0 };
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
        let wv = WebVitals::new();
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
}
