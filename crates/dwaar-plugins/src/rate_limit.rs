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
        let current_rate = self.rate.rate_with(&key, RATE_ESTIMATE_FN);
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
/// Priority 15 — runs after bot detection (priority 10) so the bot flag is
/// available, and BEFORE under-attack mode (priority 20) so challenge-page
/// responses and proof-of-work solutions are themselves rate-limited. Without
/// this ordering an attacker could flood the challenge endpoint with unlimited
/// solution submissions (L-14).
///
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
        15
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

        // L-15: canonicalize IPv4-mapped IPv6 addresses (`::ffff:1.2.3.4`) back
        // to their IPv4 form BEFORE building the rate-limit key. Without this,
        // an attacker speaking dual-stack could double their allowance by
        // alternating between the two wire formats, which hash to different
        // keys in the composite. `Ipv6Addr::to_canonical` (stable since 1.75)
        // returns the IPv4 form when the address is an IPv4-mapped v6 and
        // leaves native v6 unchanged.
        let canonical_ip = match ip {
            std::net::IpAddr::V6(v6) => v6.to_canonical(),
            v4 @ std::net::IpAddr::V4(_) => v4,
        };

        // Composite key: "{ip}:{domain}" for per-route isolation.
        // CompactString inlines up to 24 bytes, avoiding heap allocation for
        // short IP:domain combos; falls back to heap for longer keys.
        let mut key = CompactString::with_capacity(64);
        let _ = write!(key, "{canonical_ip}:{domain}");
        if self.limiter.check(&key, limit) {
            return PluginAction::Continue;
        }

        ctx.rate_limited = true;
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

    #[test]
    fn rate_limit_runs_before_under_attack() {
        // L-14: rate limiting must be enforced on challenge responses, so its
        // plugin priority must be strictly lower (runs earlier) than under-attack.
        use crate::plugin::DwaarPlugin;
        use crate::under_attack::UnderAttackPlugin;
        let rl = RateLimitPlugin::new();
        let ua = UnderAttackPlugin::new(b"secret".to_vec());
        assert!(
            rl.priority() < ua.priority(),
            "rate-limit priority ({}) must be < under-attack priority ({})",
            rl.priority(),
            ua.priority()
        );
    }

    #[test]
    fn rate_limited_response_wins_over_under_attack_challenge() {
        // End-to-end check that the ordering is wired through PluginChain, not
        // just the static priority numbers: a rate-limited request inside a
        // chain containing both plugins must receive a 429, never the 200
        // under-attack challenge page.
        use crate::plugin::{DwaarPlugin, PluginChain, PluginCtx};
        use crate::under_attack::UnderAttackPlugin;

        let chain = PluginChain::new(vec![
            Box::new(UnderAttackPlugin::new(b"test-secret".to_vec())) as Box<dyn DwaarPlugin>,
            Box::new(RateLimitPlugin::new()) as Box<dyn DwaarPlugin>,
        ]);

        let req = pingora_http::RequestHeader::build("GET", b"/", None).expect("req");

        // Burn the per-second budget so the next call exceeds the limit.
        let mut resp = None;
        for _ in 0..50 {
            let mut ctx = PluginCtx {
                client_ip: Some("10.0.0.7".parse().expect("valid ip")),
                route_domain: Some("example.com".into()),
                rate_limit_rps: Some(1),
                under_attack: true,
                ..PluginCtx::default()
            };
            resp = chain.run_request(&req, &mut ctx);
            // Once rate_limit trips, the 429 must beat the under-attack 200.
            if let Some(r) = &resp
                && r.status == 429
            {
                assert!(ctx.rate_limited);
                return;
            }
        }
        panic!("rate_limit never short-circuited within 50 requests: last {resp:?}");
    }

    #[test]
    fn ipv4_mapped_ipv6_collapses_to_ipv4_key() {
        // L-15: `::ffff:127.0.0.1` and `127.0.0.1` must hash to the same key,
        // so a dual-stack client cannot double its rate-limit allowance.
        use std::net::IpAddr;
        let v4: IpAddr = "127.0.0.1".parse().expect("v4");
        let v6_mapped: IpAddr = "::ffff:127.0.0.1".parse().expect("v6 mapped");

        let canonical = |ip: IpAddr| -> String {
            let normalised = match ip {
                IpAddr::V6(v6) => v6.to_canonical(),
                v @ IpAddr::V4(_) => v,
            };
            format!("{normalised}:example.com")
        };

        assert_eq!(canonical(v4), canonical(v6_mapped));
        assert_eq!(canonical(v4), "127.0.0.1:example.com");
    }
}
