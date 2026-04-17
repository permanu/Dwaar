// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Per-domain control-plane registries consulted by the proxy hot path.
//!
//! These registries sit alongside the main [`RouteTable`](crate::route::RouteTable)
//! and let the control plane install orthogonal routing behaviours without
//! rewriting the primary upstream selector:
//!
//! * [`SplitRegistry`] — weighted traffic splits (canary / blue-green).
//! * [`MirrorRegistry`] — fire-and-forget request duplication (shadow traffic).
//! * [`HeaderRuleRegistry`] — per-domain header-match overrides (more specific
//!   than a split, so header rules win on conflict).
//!
//! All three registries are hot-reloaded through [`ArcSwap`]; swaps are
//! allocation-free for readers. The proxy performs an `O(1)` `HashMap`
//! lookup on each request — only traversed when the domain has a split /
//! mirror / header rule installed.
//!
//! ## Crate layout
//!
//! The registries live in `dwaar-core` (instead of `dwaar-grpc`) because the
//! proxy hot path — which belongs to `dwaar-core` — needs direct access to
//! them without taking a circular dependency on the control-plane crate.
//! `dwaar-grpc` wraps these types with protobuf-aware constructors.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;

/// Per-upstream weight entry inside a traffic split.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeightedEntry {
    /// Backend address, e.g. `"10.0.0.1:8080"`.
    pub upstream_addr: String,
    /// Weight 0–100. The sum across entries in a split must equal 100.
    pub weight: u32,
    /// Deploy ID this entry corresponds to (echoed back in `RouteEvent`).
    pub deploy_id: String,
}

/// Compiled traffic-split configuration for a single domain.
#[derive(Debug, Clone)]
pub struct SplitConfig {
    pub domain: String,
    /// Ordered entries. Weighted selection is `O(n)` over this vec —
    /// typical splits have 2–3 entries, so a sorted-cumulative scan is
    /// faster than building a lookup table per request.
    pub entries: Vec<WeightedEntry>,
    /// `"canary"` | `"blue_green"` | `"shadow"` — surfaced to Permanu for audit.
    pub strategy: String,
}

impl SplitConfig {
    /// Pick an upstream address using a pre-rolled random value in `[0, 100)`.
    ///
    /// Accepting the roll as an argument keeps this pure (easy to test) and
    /// lets callers share an `fastrand` source. Returns `None` only when
    /// `entries` is empty — validation is expected to reject that case.
    pub fn choose_with_roll(&self, roll: u32) -> Option<&WeightedEntry> {
        if self.entries.is_empty() {
            return None;
        }
        let mut acc: u32 = 0;
        for entry in &self.entries {
            acc = acc.saturating_add(entry.weight);
            if roll < acc {
                return Some(entry);
            }
        }
        // Fallback: weights sum to 100 so we should always hit above; if
        // rounding drifts past, return the last. Defensive only.
        self.entries.last()
    }

    /// Convenience: choose using a freshly rolled thread-local RNG in
    /// `[0, 100)`. Used in proxy dispatch hot path.
    pub fn choose(&self) -> Option<&WeightedEntry> {
        let roll = fastrand::u32(0..100);
        self.choose_with_roll(roll)
    }
}

/// Mirror (fire-and-forget request duplication) configuration.
#[derive(Debug, Clone)]
pub struct MirrorConfig {
    pub source_domain: String,
    pub mirror_to: String,
    /// Sample rate in basis points, `10_000` = 100 %.
    pub sample_rate_bps: u32,
}

impl MirrorConfig {
    /// Whether this request should be mirrored given a pre-rolled value in
    /// `[0, 10_000)`. Pure for testability.
    pub fn should_mirror_with_roll(&self, roll: u32) -> bool {
        self.sample_rate_bps > 0 && roll < self.sample_rate_bps
    }

    /// Draw a fresh basis-point roll and decide whether to mirror.
    pub fn should_mirror(&self) -> bool {
        if self.sample_rate_bps == 0 {
            return false;
        }
        self.should_mirror_with_roll(fastrand::u32(0..10_000))
    }

    /// Parsed mirror address. `None` when `mirror_to` is malformed — the
    /// registry rejects malformed addresses on insertion, so this should
    /// only ever return `Some` for installed configs.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        self.mirror_to.parse().ok()
    }
}

/// Per-domain header-match override rule.
///
/// When every `(name, value)` in `header_match` matches an incoming
/// request's headers, the proxy routes to `upstream_addr` instead of the
/// domain's default upstream. Header rules are strictly more specific than
/// traffic splits — when both are installed for the same domain the header
/// rule wins.
#[derive(Debug, Clone)]
pub struct HeaderRuleConfig {
    pub domain: String,
    /// Case-insensitive header name → required value. An empty map matches
    /// every request (effectively an unconditional override) — the registry
    /// API does not forbid it, but callers SHOULD supply at least one pair.
    pub header_match: HashMap<String, String>,
    /// Override upstream address.
    pub upstream_addr: String,
}

impl HeaderRuleConfig {
    /// Whether this rule matches the supplied request-header set.
    ///
    /// Matching is case-insensitive on header names and case-sensitive on
    /// values — mirroring the semantics of HTTP header routing in other
    /// proxies (Envoy, NGINX `map`).
    pub fn matches<F>(&self, mut lookup: F) -> bool
    where
        F: FnMut(&str) -> Option<String>,
    {
        for (name, expected) in &self.header_match {
            match lookup(name) {
                Some(actual) if actual == *expected => {}
                _ => return false,
            }
        }
        true
    }

    /// Parsed override upstream address, or `None` if malformed.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        self.upstream_addr.parse().ok()
    }
}

/// Shared registry of per-domain traffic splits.
#[derive(Debug)]
pub struct SplitRegistry {
    splits: ArcSwap<HashMap<String, SplitConfig>>,
}

impl SplitRegistry {
    pub fn new() -> Self {
        Self {
            splits: ArcSwap::from_pointee(HashMap::new()),
        }
    }

    /// Install / replace a split for `cfg.domain`.
    pub fn upsert(&self, cfg: SplitConfig) {
        let mut next = HashMap::clone(&self.splits.load());
        next.insert(cfg.domain.clone(), cfg);
        self.splits.store(Arc::new(next));
    }

    /// Remove a split by domain. Returns `true` when something was removed.
    pub fn remove(&self, domain: &str) -> bool {
        let current = self.splits.load();
        if !current.contains_key(domain) {
            return false;
        }
        let mut next = HashMap::clone(&current);
        let removed = next.remove(domain).is_some();
        self.splits.store(Arc::new(next));
        removed
    }

    /// Clone-free: pick an upstream for `domain` on the request hot path.
    ///
    /// The returned entry is owned (cloned) so callers can drop the
    /// `ArcSwap` guard immediately. Traffic splits are small (2–3 entries
    /// of ~60 bytes each) so the clone cost is negligible.
    pub fn choose(&self, domain: &str) -> Option<WeightedEntry> {
        self.splits.load().get(domain).and_then(|cfg| {
            let roll = fastrand::u32(0..100);
            cfg.choose_with_roll(roll).cloned()
        })
    }

    /// Read-only snapshot suitable for tests and admin dumps.
    pub fn snapshot_for(&self, domain: &str) -> Option<SplitConfig> {
        self.splits.load().get(domain).cloned()
    }

    pub fn len(&self) -> usize {
        self.splits.load().len()
    }

    pub fn is_empty(&self) -> bool {
        self.splits.load().is_empty()
    }
}

impl Default for SplitRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared registry of per-domain mirror targets.
#[derive(Debug)]
pub struct MirrorRegistry {
    mirrors: ArcSwap<HashMap<String, MirrorConfig>>,
}

impl MirrorRegistry {
    pub fn new() -> Self {
        Self {
            mirrors: ArcSwap::from_pointee(HashMap::new()),
        }
    }

    pub fn upsert(&self, cfg: MirrorConfig) {
        let mut next = HashMap::clone(&self.mirrors.load());
        next.insert(cfg.source_domain.clone(), cfg);
        self.mirrors.store(Arc::new(next));
    }

    pub fn remove(&self, domain: &str) -> bool {
        let current = self.mirrors.load();
        if !current.contains_key(domain) {
            return false;
        }
        let mut next = HashMap::clone(&current);
        let removed = next.remove(domain).is_some();
        self.mirrors.store(Arc::new(next));
        removed
    }

    pub fn snapshot_for(&self, domain: &str) -> Option<MirrorConfig> {
        self.mirrors.load().get(domain).cloned()
    }

    pub fn len(&self) -> usize {
        self.mirrors.load().len()
    }

    pub fn is_empty(&self) -> bool {
        self.mirrors.load().is_empty()
    }
}

impl Default for MirrorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared registry of per-domain header-match overrides.
#[derive(Debug)]
pub struct HeaderRuleRegistry {
    rules: ArcSwap<HashMap<String, HeaderRuleConfig>>,
}

impl HeaderRuleRegistry {
    pub fn new() -> Self {
        Self {
            rules: ArcSwap::from_pointee(HashMap::new()),
        }
    }

    pub fn upsert(&self, cfg: HeaderRuleConfig) {
        let mut next = HashMap::clone(&self.rules.load());
        next.insert(cfg.domain.clone(), cfg);
        self.rules.store(Arc::new(next));
    }

    pub fn remove(&self, domain: &str) -> bool {
        let current = self.rules.load();
        if !current.contains_key(domain) {
            return false;
        }
        let mut next = HashMap::clone(&current);
        let removed = next.remove(domain).is_some();
        self.rules.store(Arc::new(next));
        removed
    }

    pub fn snapshot_for(&self, domain: &str) -> Option<HeaderRuleConfig> {
        self.rules.load().get(domain).cloned()
    }

    pub fn len(&self) -> usize {
        self.rules.load().len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.load().is_empty()
    }
}

impl Default for HeaderRuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split(domain: &str, entries: &[(&str, u32, &str)]) -> SplitConfig {
        SplitConfig {
            domain: domain.to_string(),
            entries: entries
                .iter()
                .map(|(a, w, d)| WeightedEntry {
                    upstream_addr: (*a).to_string(),
                    weight: *w,
                    deploy_id: (*d).to_string(),
                })
                .collect(),
            strategy: "canary".to_string(),
        }
    }

    #[test]
    fn split_choose_respects_weight_boundaries() {
        let cfg = split(
            "api.example.com",
            &[("127.0.0.1:1001", 30, "a"), ("127.0.0.1:1002", 70, "b")],
        );
        assert_eq!(cfg.choose_with_roll(0).expect("pick").deploy_id, "a");
        assert_eq!(cfg.choose_with_roll(29).expect("pick").deploy_id, "a");
        assert_eq!(cfg.choose_with_roll(30).expect("pick").deploy_id, "b");
        assert_eq!(cfg.choose_with_roll(99).expect("pick").deploy_id, "b");
    }

    #[test]
    fn split_registry_roundtrip() {
        let reg = SplitRegistry::new();
        assert!(reg.is_empty());
        reg.upsert(split("api.example.com", &[("127.0.0.1:1", 100, "d")]));
        assert_eq!(reg.len(), 1);
        assert!(reg.snapshot_for("api.example.com").is_some());
        assert!(reg.choose("api.example.com").is_some());
        assert!(reg.choose("unknown.example.com").is_none());
        assert!(reg.remove("api.example.com"));
        assert!(reg.is_empty());
        assert!(!reg.remove("api.example.com"));
    }

    #[test]
    fn mirror_boundary_checks() {
        let cfg = MirrorConfig {
            source_domain: "api.example.com".into(),
            mirror_to: "127.0.0.1:9".into(),
            sample_rate_bps: 100,
        };
        assert!(cfg.should_mirror_with_roll(0));
        assert!(cfg.should_mirror_with_roll(99));
        assert!(!cfg.should_mirror_with_roll(100));
        assert!(!cfg.should_mirror_with_roll(10_000));
    }

    #[test]
    fn mirror_zero_rate_never_mirrors() {
        let cfg = MirrorConfig {
            source_domain: "api.example.com".into(),
            mirror_to: "127.0.0.1:9".into(),
            sample_rate_bps: 0,
        };
        assert!(!cfg.should_mirror_with_roll(0));
        assert!(!cfg.should_mirror_with_roll(5_000));
    }

    #[test]
    fn mirror_registry_roundtrip() {
        let reg = MirrorRegistry::new();
        reg.upsert(MirrorConfig {
            source_domain: "api.example.com".into(),
            mirror_to: "127.0.0.1:9".into(),
            sample_rate_bps: 10_000,
        });
        assert_eq!(reg.len(), 1);
        let snap = reg.snapshot_for("api.example.com").expect("recorded");
        assert_eq!(snap.sample_rate_bps, 10_000);
        assert!(reg.remove("api.example.com"));
        assert!(reg.is_empty());
    }

    #[test]
    fn header_rule_matches_all_pairs() {
        let mut hm = HashMap::new();
        hm.insert("x-env".to_string(), "canary".to_string());
        hm.insert("x-version".to_string(), "v2".to_string());
        let rule = HeaderRuleConfig {
            domain: "api.example.com".into(),
            header_match: hm,
            upstream_addr: "127.0.0.1:9001".into(),
        };
        let good = |name: &str| match name.to_ascii_lowercase().as_str() {
            "x-env" => Some("canary".to_string()),
            "x-version" => Some("v2".to_string()),
            _ => None,
        };
        assert!(rule.matches(good));

        let wrong = |name: &str| match name.to_ascii_lowercase().as_str() {
            "x-env" => Some("stable".to_string()),
            "x-version" => Some("v2".to_string()),
            _ => None,
        };
        assert!(!rule.matches(wrong));

        let missing = |name: &str| match name.to_ascii_lowercase().as_str() {
            "x-env" => Some("canary".to_string()),
            _ => None,
        };
        assert!(!rule.matches(missing));
    }

    #[test]
    fn header_rule_registry_roundtrip() {
        let reg = HeaderRuleRegistry::new();
        let mut hm = HashMap::new();
        hm.insert("x-env".to_string(), "canary".to_string());
        reg.upsert(HeaderRuleConfig {
            domain: "api.example.com".into(),
            header_match: hm,
            upstream_addr: "127.0.0.1:9001".into(),
        });
        assert_eq!(reg.len(), 1);
        let snap = reg.snapshot_for("api.example.com").expect("recorded");
        assert_eq!(snap.upstream_addr, "127.0.0.1:9001");
        assert!(reg.remove("api.example.com"));
        assert!(reg.is_empty());
    }

    #[test]
    fn empty_split_choose_returns_none() {
        let cfg = SplitConfig {
            domain: "x".into(),
            entries: Vec::new(),
            strategy: "canary".into(),
        };
        assert!(cfg.choose_with_roll(0).is_none());
    }
}
