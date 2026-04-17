// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Protobuf adapters for the control-plane registries that live in
//! [`dwaar_core::registries`].
//!
//! Dwaar's existing [`RouteTable`](dwaar_core::route::RouteTable) is the
//! hot-path lookup — one domain, one upstream. Wheel #2 introduces three
//! orthogonal concepts on top of it:
//!
//! * **Traffic splitting** — one domain fanned out across multiple weighted
//!   upstreams (canary / blue-green / shadow).
//! * **Request mirroring** — fire-and-forget duplication of incoming
//!   requests to a secondary upstream for black-box testing.
//! * **Header rules** — per-domain header-match overrides that trump the
//!   default upstream when every matcher pair is present.
//!
//! The registries themselves live in `dwaar-core` so the proxy hot path can
//! consult them without taking a circular dependency on this crate. This
//! module re-exports them for callers that already depend on `dwaar-grpc`
//! and adds protobuf-aware constructors keyed on the generated `pb::*` types.

use std::collections::HashMap;

pub use dwaar_core::registries::{
    HeaderRuleConfig, HeaderRuleRegistry, MirrorConfig, MirrorRegistry, SplitConfig, SplitRegistry,
    WeightedEntry,
};

use crate::pb;

/// Back-compat alias — pre-Week-4 code referenced the registry as
/// `RouteRegistry`. The registry is named `SplitRegistry` now (matches its
/// contents). Keep the alias so downstream crates compile through the rename.
pub type RouteRegistry = SplitRegistry;

/// Build a [`SplitConfig`] from a protobuf `SplitTraffic` command,
/// validating inputs.
///
/// Returns `Err(reason)` when the command is malformed — caller should
/// reply with `CommandAck { status: "rejected", error_message: reason }`.
pub fn split_from_pb(cmd: &pb::SplitTraffic) -> Result<SplitConfig, String> {
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

    Ok(SplitConfig {
        domain: cmd.domain.to_lowercase(),
        entries,
        strategy,
    })
}

/// Build a [`MirrorConfig`] from a protobuf `MirrorRequest` command.
pub fn mirror_from_pb(cmd: &pb::MirrorRequest) -> Result<MirrorConfig, String> {
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

    Ok(MirrorConfig {
        source_domain: cmd.source_domain.to_lowercase(),
        mirror_to: cmd.mirror_to.clone(),
        sample_rate_bps: cmd.sample_rate_bps,
    })
}

/// Build a [`HeaderRuleConfig`] from a protobuf `SetHeaderRule` command.
///
/// The pb message carries a single `(header_name, header_value)` pair and
/// an `action` — Week 4 scope is limited to `action == "set"` (the only
/// variant that produces a routing override). `append` / `remove` parse
/// successfully but are translated as single-pair matches; higher-arity
/// multi-header rules land in a later wheel.
///
/// `upstream_addr` is NOT carried by the protobuf today — the contract says
/// header rules override the domain's resolved upstream with a target the
/// caller has already installed via `AddRoute`. To keep the handler
/// decoupled from route-table lookups here, callers that want to enforce a
/// different upstream must surface the address alongside (see the handler
/// in `service.rs`). For Week 4 we stash `header_value` in `upstream_addr`
/// when `action == "route_to"` — a soft extension of the existing enum that
/// avoids another protobuf churn.
pub fn header_rule_from_pb(cmd: &pb::SetHeaderRule) -> Result<HeaderRuleConfig, String> {
    if cmd.domain.is_empty() {
        return Err("domain is empty".to_string());
    }
    if !dwaar_core::route::is_valid_domain(&cmd.domain) {
        return Err(format!("invalid domain: {}", cmd.domain));
    }
    if cmd.header_name.is_empty() {
        return Err("header_name is empty".to_string());
    }

    // `action` selects interpretation:
    //   "route_to" — `header_value` is the override upstream address (Week 4)
    //   "set"       — carry the pair forward as a match; upstream_addr is
    //                 taken from the route table by the handler.
    //
    // Only `route_to` is wired end-to-end for Week 4; `set`/`append`/`remove`
    // without an override address are rejected so the caller gets a clear
    // error instead of silent no-op behaviour.
    let upstream_addr = match cmd.action.as_str() {
        "route_to" => {
            if cmd.header_value.parse::<std::net::SocketAddr>().is_err() {
                return Err(format!(
                    "header_value must be a socket address for action=route_to, got: {}",
                    cmd.header_value
                ));
            }
            cmd.header_value.clone()
        }
        other => {
            return Err(format!(
                "action '{other}' not implemented — supported: route_to",
            ));
        }
    };

    let mut header_match = HashMap::new();
    header_match.insert(cmd.header_name.to_ascii_lowercase(), String::new());

    // For `route_to` the header match is "presence with empty expected value"
    // unless a real expected value is supplied. The pb field doesn't carry it
    // today; we encode "presence" by comparing against an empty string that
    // the proxy treats as `*` (any value). Week 4 scope permits this — the
    // richer pb shape comes in a follow-up wheel.
    //
    // Concretely, when the stored expected value is empty we accept any
    // non-empty header value; see `HeaderRuleConfig::matches` + the proxy
    // lookup closure in `proxy.rs`.
    Ok(HeaderRuleConfig {
        domain: cmd.domain.to_lowercase(),
        header_match,
        upstream_addr,
    })
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
        let cfg = split_from_pb(&cmd).expect("valid split");
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
        let err = split_from_pb(&cmd).expect_err("bad sum");
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
        assert!(split_from_pb(&cmd).is_err());
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
        assert!(split_from_pb(&cmd).is_err());
    }

    #[test]
    fn mirror_from_pb_validates() {
        let ok = mirror_from_pb(&pb::MirrorRequest {
            ack_id: "a".into(),
            source_domain: "api.example.com".into(),
            mirror_to: "127.0.0.1:9999".into(),
            sample_rate_bps: 5_000,
        })
        .expect("valid");
        assert_eq!(ok.sample_rate_bps, 5_000);

        let bad_rate = mirror_from_pb(&pb::MirrorRequest {
            ack_id: "a".into(),
            source_domain: "api.example.com".into(),
            mirror_to: "127.0.0.1:9999".into(),
            sample_rate_bps: 20_000,
        });
        assert!(bad_rate.is_err());

        let bad_addr = mirror_from_pb(&pb::MirrorRequest {
            ack_id: "a".into(),
            source_domain: "api.example.com".into(),
            mirror_to: "not-an-addr".into(),
            sample_rate_bps: 10_000,
        });
        assert!(bad_addr.is_err());
    }

    #[test]
    fn header_rule_from_pb_route_to_accepts_socket_addr() {
        let cfg = header_rule_from_pb(&pb::SetHeaderRule {
            ack_id: "h".into(),
            domain: "api.example.com".into(),
            header_name: "X-Env".into(),
            header_value: "127.0.0.1:9001".into(),
            action: "route_to".into(),
        })
        .expect("valid");
        assert_eq!(cfg.upstream_addr, "127.0.0.1:9001");
        assert!(cfg.header_match.contains_key("x-env"));
    }

    #[test]
    fn header_rule_from_pb_rejects_unsupported_action() {
        let err = header_rule_from_pb(&pb::SetHeaderRule {
            ack_id: "h".into(),
            domain: "api.example.com".into(),
            header_name: "X-Env".into(),
            header_value: "canary".into(),
            action: "set".into(),
        })
        .expect_err("should reject");
        assert!(err.contains("not implemented"));
    }

    #[test]
    fn header_rule_from_pb_rejects_bad_address() {
        let err = header_rule_from_pb(&pb::SetHeaderRule {
            ack_id: "h".into(),
            domain: "api.example.com".into(),
            header_name: "X-Env".into(),
            header_value: "not-an-addr".into(),
            action: "route_to".into(),
        })
        .expect_err("should reject");
        assert!(err.contains("socket address"));
    }

    #[test]
    fn header_rule_from_pb_rejects_empty_domain() {
        let err = header_rule_from_pb(&pb::SetHeaderRule {
            ack_id: "h".into(),
            domain: String::new(),
            header_name: "X-Env".into(),
            header_value: "127.0.0.1:9001".into(),
            action: "route_to".into(),
        })
        .expect_err("should reject");
        assert!(err.contains("domain is empty"));
    }
}
