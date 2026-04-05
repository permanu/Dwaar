// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Per-IP, per-route rate limiting using `pingora-limits`.
//!
//! Wraps a single [`Rate`] instance (1-second sliding window, ~32 KB)
//! that tracks all IP+domain pairs via composite keys. The estimator
//! uses a Count-Min Sketch internally — one instance handles thousands
//! of unique keys with bounded memory.

use std::time::Duration;

use std::fmt::Write;

use bytes::Bytes;
use compact_str::CompactString;
use pingora_limits::rate::{PROPORTIONAL_RATE_ESTIMATE_CALC_FN as RATE_ESTIMATE_FN, Rate};

use crate::plugin::{DwaarPlugin, PluginAction, PluginCtx, PluginResponse};

/// Rate limiter backed by a sliding-window estimator.
///
/// Thread-safe: `Rate` uses atomics internally. Wrap in `Arc` and share
/// across all Pingora worker threads.
pub struct RateLimiter {
    rate: Rate,
}

impl RateLimiter {
    /// Create a rate limiter with a 1-second estimation window.
    ///
    /// Uses the default estimator config (4 hashes × 1024 slots ≈ 32 KB).
    /// Sufficient for up to ~1000 unique IP:domain keys before collision
    /// rates increase noticeably.
    pub fn new() -> Self {
        Self {
            rate: Rate::new(Duration::from_secs(1)),
        }
    }

    /// Record one request and check whether the rate exceeds the limit.
    ///
    /// Returns `true` if within the limit (allow), `false` if exceeded (reject).
    ///
    /// Uses `rate_with(RATE_ESTIMATE_FN)` for a proper sliding-window estimate
    /// that interpolates between current and previous intervals. This avoids
    /// the one-second lag of the plain `rate()` method.
    pub fn check(&self, key: &str, limit: u32) -> bool {
        self.rate.observe(&key, 1);
        let current_rate = self
            .rate
            .rate_with(&key, RATE_ESTIMATE_FN);
        current_rate <= f64::from(limit)
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimiter")
            .field("interval", &"1s")
            .finish_non_exhaustive()
    }
}

/// Plugin wrapper that enforces per-IP, per-route rate limits.
///
/// Priority 20 — runs after bot detection so the bot flag is available.
/// Reads `rate_limit_rps` and `route_domain` from `PluginCtx` (populated
/// by the proxy engine before the chain runs).
#[derive(Debug)]
pub struct RateLimitPlugin {
    limiter: RateLimiter,
}

impl RateLimitPlugin {
    pub fn new() -> Self {
        Self {
            limiter: RateLimiter::new(),
        }
    }
}

impl Default for RateLimitPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl DwaarPlugin for RateLimitPlugin {
    fn name(&self) -> &'static str {
        "rate-limit"
    }

    fn priority(&self) -> u16 {
        20
    }

    fn on_request(&self, _req: &pingora_http::RequestHeader, ctx: &mut PluginCtx) -> PluginAction {
        let Some(limit) = ctx.rate_limit_rps else {
            return PluginAction::Continue;
        };
        let Some(ip) = ctx.client_ip else {
            return PluginAction::Continue;
        };
        let Some(ref domain) = ctx.route_domain else {
            return PluginAction::Continue;
        };

        // Composite key: "{ip}:{domain}" for per-route isolation.
        // CompactString inlines up to 24 bytes, avoiding heap allocation for
        // short IP:domain combos; falls back to heap for longer keys.
        let mut key = CompactString::with_capacity(64);
        let _ = write!(key, "{ip}:{domain}");
        if self.limiter.check(&key, limit) {
            return PluginAction::Continue;
        }

        PluginAction::Respond(PluginResponse {
            status: 429,
            headers: vec![
                ("Retry-After", "1".to_string()),
                ("Content-Length", "0".to_string()),
            ],
            body: Bytes::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn within_limit_returns_true() {
        let rl = RateLimiter::new();
        assert!(rl.check("192.168.1.1:example.com", 100));
    }

    #[test]
    fn exceeding_limit_returns_false() {
        let rl = RateLimiter::new();
        let key = "10.0.0.1:api.example.com";
        for _ in 0..200 {
            rl.check(key, 10);
        }
        assert!(!rl.check(key, 10));
    }

    #[test]
    fn different_keys_are_isolated() {
        let rl = RateLimiter::new();
        let key_a = "10.0.0.1:api.example.com";
        let key_b = "10.0.0.1:web.example.com";

        for _ in 0..200 {
            rl.check(key_a, 10);
        }

        assert!(rl.check(key_b, 100));
    }

    #[test]
    fn rate_limiter_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RateLimiter>();
    }
}
