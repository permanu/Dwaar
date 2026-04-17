// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Routing state owned by the gRPC control plane.
//!
//! Dwaar's existing [`RouteTable`](dwaar_core::route::RouteTable) is the
//! hot-path lookup — one domain, one upstream. Wheel #2 introduces two
//! orthogonal concepts on top of it:
//!
//! * **Traffic splitting** — one domain fanned out across multiple weighted
//!   upstreams (canary / blue-green / shadow).
//! * **Request mirroring** — fire-and-forget duplication of incoming
//!   requests to a secondary upstream for black-box testing.
//!
//! Rather than extending `Route` (which would ripple through 17 call-sites
//! that construct `Route` literals), we keep these as side registries
//! keyed by domain. The proxy's hot path remains a single
//! `RouteTable::resolve` call; split/mirror dispatch is a second O(1)
//! lookup, only traversed when a split or mirror exists.
//!
//! Both registries are hot-reloaded through [`ArcSwap`]; swaps are
//! allocation-free for readers.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::pb;

/// Per-upstream weight entry in a traffic split.
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
    /// Ordered entries. Weighted selection is O(n) over this vec —
    /// typical splits have 2–3 entries, so a sorted-cumulative scan is
    /// faster than building a lookup table per request.
    pub entries: Vec<WeightedEntry>,
    /// `"canary"` | `"blue_green"` | `"shadow"` — surfaced to Permanu for audit.
    pub strategy: String,
}

impl SplitConfig {
    /// Build from a protobuf `SplitTraffic` command, validating inputs.
    ///
    /// Returns `Err(reason)` when the command is malformed — caller should
    /// reply with `CommandAck { status: "rejected", error_message: reason }`.
    pub fn from_pb(cmd: &pb::SplitTraffic) -> Result<Self, String> {
        if cmd.domain.is_empty() {
            return Err("domain is empty".to_string());
        }
        if !dwaar_core::route::is_valid_domain(&cmd.domain) {
            return Err(format!("invalid domain: {}", cmd.domain));
        }
        if cmd.upstreams.is_empty() {
            return Err("split requires at least one upstream".to_string());
        }

        let mut entries = Vec::with_capacity(cmd.upstreams.len());
        let mut sum: u32 = 0;
        for (idx, wu) in cmd.upstreams.iter().enumerate() {
            let route = wu
                .route
                .as_ref()
                .ok_or_else(|| format!("upstream[{idx}] missing route"))?;
            if route.upstream_addr.is_empty() {
                return Err(format!("upstream[{idx}] has empty address"));
            }
            if route.upstream_addr.parse::<std::net::SocketAddr>().is_err() {
                return Err(format!(
                    "upstream[{idx}] address not parseable: {}",
                    route.upstream_addr
                ));
            }
            sum = sum.saturating_add(wu.weight);
            entries.push(WeightedEntry {
                upstream_addr: route.upstream_addr.clone(),
                weight: wu.weight,
                deploy_id: route.deploy_id.clone(),
            });
        }

        if sum != 100 {
            return Err(format!(
                "weights must sum to 100 (got {sum} across {} entries)",
                entries.len()
            ));
        }

        let strategy = if cmd.strategy.is_empty() {
            "canary".to_string()
        } else {
            cmd.strategy.clone()
        };

        Ok(Self {
            domain: cmd.domain.to_lowercase(),
            entries,
            strategy,
        })
    }

    /// Pick an upstream address using a pre-rolled random value in `[0, 100)`.
    ///
    /// Accepting the roll as an argument keeps this pure (easy to test) and
    /// lets callers share an `fastrand` source. Returns `None` only when
    /// `entries` is empty — which `from_pb` rejects, but defended here.
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
        // floating-point-style rounding drifts us past, return the last.
        self.entries.last()
    }

    /// Convenience: choose using a freshly rolled thread-local RNG in
    /// `[0, 100)`. Used in proxy dispatch hot path in Week 4 — kept here so
    /// all weighted-choice logic lives in one place.
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
    pub fn from_pb(cmd: &pb::MirrorRequest) -> Result<Self, String> {
        if cmd.source_domain.is_empty() {
            return Err("source_domain is empty".to_string());
        }
        if !dwaar_core::route::is_valid_domain(&cmd.source_domain) {
            return Err(format!("invalid source_domain: {}", cmd.source_domain));
        }
        if cmd.mirror_to.is_empty() {
            return Err("mirror_to is empty".to_string());
        }
        if cmd.mirror_to.parse::<std::net::SocketAddr>().is_err() {
            return Err(format!(
                "mirror_to is not a valid socket address: {}",
                cmd.mirror_to
            ));
        }
        if cmd.sample_rate_bps > 10_000 {
            return Err(format!(
                "sample_rate_bps must be in [0, 10000], got {}",
                cmd.sample_rate_bps
            ));
        }

        Ok(Self {
            source_domain: cmd.source_domain.to_lowercase(),
            mirror_to: cmd.mirror_to.clone(),
            sample_rate_bps: cmd.sample_rate_bps,
        })
    }

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
}

/// Shared registry of per-domain traffic splits. Readers hold a snapshot
/// via `load()`; writers swap atomically via `store()` (copy-on-write).
#[derive(Debug)]
pub struct RouteRegistry {
    splits: ArcSwap<HashMap<String, SplitConfig>>,
}

impl RouteRegistry {
    pub fn new() -> Self {
        Self {
            splits: ArcSwap::from_pointee(HashMap::new()),
        }
    }

    /// Install / replace a split for `cfg.domain`.
    pub fn upsert_split(&self, cfg: SplitConfig) {
        let mut next = HashMap::clone(&self.splits.load());
        next.insert(cfg.domain.clone(), cfg);
        self.splits.store(Arc::new(next));
    }

    /// Remove a split by domain. Returns `true` when something was removed.
    pub fn remove_split(&self, domain: &str) -> bool {
        let current = self.splits.load();
        if !current.contains_key(domain) {
            return false;
        }
        let mut next = HashMap::clone(&current);
        let removed = next.remove(domain).is_some();
        self.splits.store(Arc::new(next));
        removed
    }

    /// Read-only snapshot suitable for the proxy hot path.
    pub fn snapshot_for(&self, domain: &str) -> Option<SplitConfig> {
        self.splits.load().get(domain).cloned()
    }

    /// Return the number of installed splits — used by tests + metrics.
    pub fn len(&self) -> usize {
        self.splits.load().len()
    }

    /// Whether no splits are installed.
    pub fn is_empty(&self) -> bool {
        self.splits.load().is_empty()
    }
}

impl Default for RouteRegistry {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn route(domain: &str, addr: &str, deploy: &str) -> pb::Route {
        pb::Route {
            deploy_id: deploy.to_string(),
            release_name: String::new(),
            domain: domain.to_string(),
            upstream_addr: addr.to_string(),
            tls: false,
            header_match: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn split_from_pb_accepts_valid_100_sum() {
        let cmd = pb::SplitTraffic {
            ack_id: "a".into(),
            domain: "api.example.com".into(),
            upstreams: vec![
                pb::WeightedUpstream {
                    route: Some(route("api.example.com", "127.0.0.1:1001", "d1")),
                    weight: 40,
                },
                pb::WeightedUpstream {
                    route: Some(route("api.example.com", "127.0.0.1:1002", "d2")),
                    weight: 60,
                },
            ],
            strategy: "canary".into(),
        };
        let cfg = SplitConfig::from_pb(&cmd).expect("valid split");
        assert_eq!(cfg.domain, "api.example.com");
        assert_eq!(cfg.entries.len(), 2);
        assert_eq!(cfg.strategy, "canary");
    }

    #[test]
    fn split_from_pb_rejects_bad_sum() {
        let cmd = pb::SplitTraffic {
            ack_id: "a".into(),
            domain: "api.example.com".into(),
            upstreams: vec![pb::WeightedUpstream {
                route: Some(route("api.example.com", "127.0.0.1:1001", "d1")),
                weight: 99,
            }],
            strategy: String::new(),
        };
        let err = SplitConfig::from_pb(&cmd).expect_err("bad sum");
        assert!(err.contains("sum to 100"));
    }

    #[test]
    fn split_from_pb_rejects_empty_domain() {
        let cmd = pb::SplitTraffic {
            ack_id: "a".into(),
            domain: String::new(),
            upstreams: vec![pb::WeightedUpstream {
                route: Some(route("", "127.0.0.1:1001", "d1")),
                weight: 100,
            }],
            strategy: String::new(),
        };
        assert!(SplitConfig::from_pb(&cmd).is_err());
    }

    #[test]
    fn split_from_pb_rejects_bad_upstream_addr() {
        let cmd = pb::SplitTraffic {
            ack_id: "a".into(),
            domain: "api.example.com".into(),
            upstreams: vec![pb::WeightedUpstream {
                route: Some(route("api.example.com", "not-an-addr", "d1")),
                weight: 100,
            }],
            strategy: String::new(),
        };
        assert!(SplitConfig::from_pb(&cmd).is_err());
    }

    #[test]
    fn split_choose_distributes_by_weight() {
        let cfg = SplitConfig {
            domain: "api.example.com".to_string(),
            entries: vec![
                WeightedEntry {
                    upstream_addr: "127.0.0.1:1001".into(),
                    weight: 30,
                    deploy_id: "a".into(),
                },
                WeightedEntry {
                    upstream_addr: "127.0.0.1:1002".into(),
                    weight: 70,
                    deploy_id: "b".into(),
                },
            ],
            strategy: "canary".into(),
        };
        // Deterministic boundary checks.
        assert_eq!(cfg.choose_with_roll(0).expect("pick").deploy_id, "a");
        assert_eq!(cfg.choose_with_roll(29).expect("pick").deploy_id, "a");
        assert_eq!(cfg.choose_with_roll(30).expect("pick").deploy_id, "b");
        assert_eq!(cfg.choose_with_roll(99).expect("pick").deploy_id, "b");
    }

    #[test]
    fn route_registry_upsert_and_remove() {
        let reg = RouteRegistry::new();
        assert!(reg.is_empty());
        reg.upsert_split(SplitConfig {
            domain: "api.example.com".into(),
            entries: vec![WeightedEntry {
                upstream_addr: "127.0.0.1:1".into(),
                weight: 100,
                deploy_id: "d".into(),
            }],
            strategy: "canary".into(),
        });
        assert_eq!(reg.len(), 1);
        assert!(reg.snapshot_for("api.example.com").is_some());
        assert!(reg.remove_split("api.example.com"));
        assert!(reg.is_empty());
        assert!(!reg.remove_split("api.example.com"));
    }

    #[test]
    fn mirror_from_pb_validates() {
        let ok = MirrorConfig::from_pb(&pb::MirrorRequest {
            ack_id: "a".into(),
            source_domain: "api.example.com".into(),
            mirror_to: "127.0.0.1:9999".into(),
            sample_rate_bps: 5_000,
        })
        .expect("valid");
        assert_eq!(ok.sample_rate_bps, 5_000);

        let bad_rate = MirrorConfig::from_pb(&pb::MirrorRequest {
            ack_id: "a".into(),
            source_domain: "api.example.com".into(),
            mirror_to: "127.0.0.1:9999".into(),
            sample_rate_bps: 20_000,
        });
        assert!(bad_rate.is_err());

        let bad_addr = MirrorConfig::from_pb(&pb::MirrorRequest {
            ack_id: "a".into(),
            source_domain: "api.example.com".into(),
            mirror_to: "not-an-addr".into(),
            sample_rate_bps: 10_000,
        });
        assert!(bad_addr.is_err());
    }

    #[test]
    fn mirror_should_mirror_boundaries() {
        let cfg = MirrorConfig {
            source_domain: "api.example.com".into(),
            mirror_to: "127.0.0.1:9".into(),
            sample_rate_bps: 100, // 1%
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
}
