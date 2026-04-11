// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! First-party analytics — JS serving, beacon collection, in-memory aggregation.
//!
//! This crate provides the analytics script served at `/_dwaar/a.js` and
//! (in future issues) the beacon endpoint and aggregation engine.

/// The analytics JavaScript, compiled into the binary at build time.
///
/// Served at `/_dwaar/a.js` by dwaar-core's `request_filter()`.
/// The script collects page metadata and Web Vitals, then sends a
/// beacon to `/_dwaar/collect` on page exit.
pub const ANALYTICS_JS: &[u8] = include_bytes!("../assets/analytics.js");

/// Maximum number of distinct domains tracked in per-domain `DashMap`s.
///
/// Shared across [`prometheus`] and [`rate_cache_metrics`] so changing the
/// ceiling in one place can't drift the other into a different limit.
/// Beyond this count new domains are silently dropped to bound memory
/// growth in multi-tenant or wildcard setups.
pub const MAX_TRACKED_DOMAINS: usize = 10_000;

pub mod aggregation;
pub mod auth;
pub mod beacon;
pub mod decompress;
pub mod injector;
pub mod process_metrics;
pub mod prometheus;
pub mod rate_cache_metrics;
pub mod sink;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analytics_js_is_not_empty() {
        assert!(!ANALYTICS_JS.is_empty());
    }

    #[test]
    fn analytics_js_is_valid_utf8() {
        std::str::from_utf8(ANALYTICS_JS).expect("analytics JS must be valid UTF-8");
    }

    #[test]
    fn analytics_js_under_size_budget() {
        // Raw JS must stay under 3500 bytes to meet the <3.5KB gzip target.
        // v0.2.3 raised the budget from 2500 after the beacon HMAC (C-04),
        // Sec-GPC check (L-22), and fetch-keepalive fallback (L-23) were
        // added. Gzipped size remains well under 1.5 KB in practice.
        assert!(
            ANALYTICS_JS.len() < 3500,
            "analytics JS is {} bytes, budget is 3500",
            ANALYTICS_JS.len()
        );
    }
}
