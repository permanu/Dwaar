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

pub mod aggregation;
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
        // Raw JS must stay under 2500 bytes to meet <2.5KB gzip target
        assert!(
            ANALYTICS_JS.len() < 2500,
            "analytics JS is {} bytes, budget is 2500",
            ANALYTICS_JS.len()
        );
    }
}
