// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Rate limiter and cache counters for Prometheus exposition.
//!
//! These metrics make rate limiting and caching visible to operators —
//! rejection rates and cache hit ratios are critical for tuning, but
//! were previously invisible despite both systems being fully functional.

use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

use compact_str::CompactString;
use dashmap::DashMap;

const MAX_TRACKED_DOMAINS: usize = 10_000;

/// Prometheus counters for rate limiting and HTTP cache activity.
///
/// All operations are atomic — no locks, no allocation after the first
/// request per domain. Shared via `Arc` between the plugin chain
/// (writes) and the admin service (reads on `GET /metrics`).
pub struct RateCacheMetrics {
    rate_limit_rejected: DashMap<CompactString, AtomicU64>,
    rate_limit_allowed: DashMap<CompactString, AtomicU64>,
    cache_hits: DashMap<CompactString, AtomicU64>,
    cache_misses: DashMap<CompactString, AtomicU64>,
    cache_stored_bytes: AtomicU64,
}

impl std::fmt::Debug for RateCacheMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateCacheMetrics")
            .field("domains", &self.rate_limit_rejected.len())
            .finish_non_exhaustive()
    }
}

impl Default for RateCacheMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl RateCacheMetrics {
    pub fn new() -> Self {
        Self {
            rate_limit_rejected: DashMap::new(),
            rate_limit_allowed: DashMap::new(),
            cache_hits: DashMap::new(),
            cache_misses: DashMap::new(),
            cache_stored_bytes: AtomicU64::new(0),
        }
    }

    /// Increment a per-domain counter. Fast path: read-only `get()`, no clone.
    /// Cold path (first seen): `entry()` with clone, bounded by domain limit.
    fn increment(map: &DashMap<CompactString, AtomicU64>, domain: &CompactString) {
        if let Some(counter) = map.get(domain) {
            counter.fetch_add(1, Relaxed);
            return;
        }
        if map.len() < MAX_TRACKED_DOMAINS {
            map.entry(domain.clone()).or_default().fetch_add(1, Relaxed);
        }
    }

    pub fn record_rate_limit_allowed(&self, domain: &CompactString) {
        Self::increment(&self.rate_limit_allowed, domain);
    }

    pub fn record_rate_limit_rejected(&self, domain: &CompactString) {
        Self::increment(&self.rate_limit_rejected, domain);
    }

    pub fn record_cache_hit(&self, domain: &CompactString) {
        Self::increment(&self.cache_hits, domain);
    }

    pub fn record_cache_miss(&self, domain: &CompactString) {
        Self::increment(&self.cache_misses, domain);
    }

    pub fn add_cache_bytes(&self, bytes: u64) {
        self.cache_stored_bytes.fetch_add(bytes, Relaxed);
    }

    pub fn remove_cache_bytes(&self, bytes: u64) {
        self.cache_stored_bytes.fetch_sub(bytes, Relaxed);
    }

    /// Render rate limit and cache metrics in Prometheus text format.
    pub fn render(&self, out: &mut String) {
        self.render_rate_limit(out);
        self.render_cache(out);
    }

    fn render_rate_limit(&self, out: &mut String) {
        if !self.rate_limit_rejected.is_empty() || !self.rate_limit_allowed.is_empty() {
            out.push_str(
                "# HELP dwaar_rate_limit_rejected_total Total rate-limited (429) requests.\n",
            );
            out.push_str("# TYPE dwaar_rate_limit_rejected_total counter\n");
            for entry in &self.rate_limit_rejected {
                let val = entry.value().load(Relaxed);
                if val > 0 {
                    let _ = writeln!(
                        out,
                        "dwaar_rate_limit_rejected_total{{domain=\"{}\"}} {val}",
                        entry.key()
                    );
                }
            }

            out.push_str(
                "# HELP dwaar_rate_limit_allowed_total Total requests allowed by rate limiter.\n",
            );
            out.push_str("# TYPE dwaar_rate_limit_allowed_total counter\n");
            for entry in &self.rate_limit_allowed {
                let val = entry.value().load(Relaxed);
                if val > 0 {
                    let _ = writeln!(
                        out,
                        "dwaar_rate_limit_allowed_total{{domain=\"{}\"}} {val}",
                        entry.key()
                    );
                }
            }
        }
    }

    fn render_cache(&self, out: &mut String) {
        let has_cache_data = !self.cache_hits.is_empty()
            || !self.cache_misses.is_empty()
            || self.cache_stored_bytes.load(Relaxed) > 0;

        if !has_cache_data {
            return;
        }

        out.push_str("# HELP dwaar_cache_hits_total Total cache hits.\n");
        out.push_str("# TYPE dwaar_cache_hits_total counter\n");
        for entry in &self.cache_hits {
            let val = entry.value().load(Relaxed);
            if val > 0 {
                let _ = writeln!(
                    out,
                    "dwaar_cache_hits_total{{domain=\"{}\"}} {val}",
                    entry.key()
                );
            }
        }

        out.push_str("# HELP dwaar_cache_misses_total Total cache misses.\n");
        out.push_str("# TYPE dwaar_cache_misses_total counter\n");
        for entry in &self.cache_misses {
            let val = entry.value().load(Relaxed);
            if val > 0 {
                let _ = writeln!(
                    out,
                    "dwaar_cache_misses_total{{domain=\"{}\"}} {val}",
                    entry.key()
                );
            }
        }

        let stored = self.cache_stored_bytes.load(Relaxed);
        out.push_str("# HELP dwaar_cache_stored_bytes Total bytes stored in cache.\n");
        out.push_str("# TYPE dwaar_cache_stored_bytes gauge\n");
        let _ = writeln!(out, "dwaar_cache_stored_bytes {stored}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit_rejected_increments() {
        let m = RateCacheMetrics::new();
        let domain = CompactString::from("test.com");
        m.record_rate_limit_rejected(&domain);
        m.record_rate_limit_rejected(&domain);
        let val = m
            .rate_limit_rejected
            .get(&domain)
            .expect("should exist")
            .load(Relaxed);
        assert_eq!(val, 2);
    }

    #[test]
    fn rate_limit_allowed_increments() {
        let m = RateCacheMetrics::new();
        let domain = CompactString::from("test.com");
        m.record_rate_limit_allowed(&domain);
        let val = m
            .rate_limit_allowed
            .get(&domain)
            .expect("should exist")
            .load(Relaxed);
        assert_eq!(val, 1);
    }

    #[test]
    fn cache_hit_increments() {
        let m = RateCacheMetrics::new();
        let domain = CompactString::from("test.com");
        m.record_cache_hit(&domain);
        m.record_cache_hit(&domain);
        m.record_cache_hit(&domain);
        let val = m
            .cache_hits
            .get(&domain)
            .expect("should exist")
            .load(Relaxed);
        assert_eq!(val, 3);
    }

    #[test]
    fn cache_miss_increments() {
        let m = RateCacheMetrics::new();
        let domain = CompactString::from("test.com");
        m.record_cache_miss(&domain);
        let val = m
            .cache_misses
            .get(&domain)
            .expect("should exist")
            .load(Relaxed);
        assert_eq!(val, 1);
    }

    #[test]
    fn cache_bytes_add_remove() {
        let m = RateCacheMetrics::new();
        m.add_cache_bytes(1000);
        m.add_cache_bytes(500);
        assert_eq!(m.cache_stored_bytes.load(Relaxed), 1500);
        m.remove_cache_bytes(300);
        assert_eq!(m.cache_stored_bytes.load(Relaxed), 1200);
    }

    #[test]
    fn render_empty_produces_no_data() {
        let m = RateCacheMetrics::new();
        let mut out = String::new();
        m.render(&mut out);
        assert!(!out.contains("domain="), "no data lines for empty metrics");
    }

    #[test]
    fn render_rate_limit_format() {
        let m = RateCacheMetrics::new();
        let domain = CompactString::from("app.io");
        m.record_rate_limit_rejected(&domain);
        m.record_rate_limit_allowed(&domain);
        m.record_rate_limit_allowed(&domain);

        let mut out = String::new();
        m.render(&mut out);
        assert!(out.contains("dwaar_rate_limit_rejected_total{domain=\"app.io\"} 1"));
        assert!(out.contains("dwaar_rate_limit_allowed_total{domain=\"app.io\"} 2"));
    }

    #[test]
    fn render_cache_format() {
        let m = RateCacheMetrics::new();
        let domain = CompactString::from("cdn.io");
        m.record_cache_hit(&domain);
        m.add_cache_bytes(4096);

        let mut out = String::new();
        m.render(&mut out);
        assert!(out.contains("dwaar_cache_hits_total{domain=\"cdn.io\"} 1"));
        assert!(out.contains("dwaar_cache_stored_bytes 4096"));
    }

    #[test]
    fn is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RateCacheMetrics>();
    }
}
