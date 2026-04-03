// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! `IngressClass` ownership checking and `dwaar.dev/*` annotation parsing.
//!
//! ## `IngressClass` filtering
//!
//! `is_owned_by_dwaar` checks whether an Ingress should be managed by this
//! controller. Two conventions are supported:
//! - `spec.ingressClassName` (Kubernetes 1.18+, preferred).
//! - `kubernetes.io/ingress.class` annotation (legacy, still common).
//!
//! When neither is set and `class_name` is `None`, we manage everything
//! (single-controller cluster mode).
//!
//! ## Annotation parsing
//!
//! Annotations are how operators configure per-Ingress behaviours without
//! modifying the core Ingress spec. We read only `dwaar.dev/*` annotations;
//! any `dwaar.dev/*` key we do not recognise is logged as a warning.
//!
//! Recognised annotations:
//! | Annotation                    | Type        | Effect |
//! |-------------------------------|-------------|--------|
//! | `dwaar.dev/rate-limit`        | `u32` req/s | Apply rate limiting at the proxy |
//! | `dwaar.dev/tls-redirect`      | `bool`      | HTTP → HTTPS redirect |
//! | `dwaar.dev/upstream-proto`    | `"h2"/"http"` | Force upstream protocol |
//! | `dwaar.dev/under-attack`      | `bool`      | Enable challenge/captcha mode |
//! | `dwaar.dev/ip-filter-allow`   | CIDR list   | Allowlist — deny everything else |
//! | `dwaar.dev/ip-filter-deny`    | CIDR list   | Denylist — allow everything else |

use std::net::IpAddr;
use std::str::FromStr;

use k8s_openapi::api::networking::v1::{Ingress, IngressClass, IngressClassSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Api, PostParams};
use tracing::{info, warn};

use crate::error::AnnotationError;

// The annotation prefix for all Dwaar-specific annotations.
const DWAAR_PREFIX: &str = "dwaar.dev/";

// Legacy annotation key used before `spec.ingressClassName` was introduced.
const LEGACY_CLASS_ANNOTATION: &str = "kubernetes.io/ingress.class";

/// The upstream protocol hint parsed from `dwaar.dev/upstream-proto`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamProto {
    Http,
    H2,
}

/// All Dwaar-specific annotations extracted from one Ingress.
///
/// Fields are `None` when the corresponding annotation is absent.
/// Callers should treat `None` as "use the default behaviour".
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DwaarAnnotations {
    /// Maximum requests per second forwarded to the upstream (rate limiting).
    pub rate_limit: Option<u32>,
    /// When `true`, the proxy issues an HTTP 301 to HTTPS for all plaintext requests.
    pub tls_redirect: Option<bool>,
    /// Force a specific application protocol on the upstream connection.
    pub upstream_proto: Option<UpstreamProto>,
    /// Activate under-attack mode (challenge / JavaScript proof-of-work before forwarding).
    pub under_attack: Option<bool>,
    /// CIDRs that are explicitly allowed. When non-empty, all other IPs are denied.
    pub ip_filter_allow: Vec<CidrBlock>,
    /// CIDRs that are explicitly denied. All other IPs are allowed.
    pub ip_filter_deny: Vec<CidrBlock>,
}

/// A parsed CIDR block (e.g. `192.168.0.0/24`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CidrBlock {
    /// The network address.
    pub addr: IpAddr,
    /// The prefix length (0–32 for IPv4, 0–128 for IPv6).
    pub prefix_len: u8,
}

impl std::fmt::Display for CidrBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

impl FromStr for CidrBlock {
    type Err = AnnotationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr_part, prefix_part) =
            s.split_once('/')
                .ok_or_else(|| AnnotationError::InvalidValue {
                    annotation: "cidr".to_string(),
                    value: s.to_string(),
                    reason: "expected addr/prefix format".to_string(),
                })?;

        let addr = addr_part
            .parse::<IpAddr>()
            .map_err(|_| AnnotationError::InvalidValue {
                annotation: "cidr".to_string(),
                value: s.to_string(),
                reason: format!("'{addr_part}' is not a valid IP address"),
            })?;

        let prefix_len = prefix_part
            .parse::<u8>()
            .map_err(|_| AnnotationError::InvalidValue {
                annotation: "cidr".to_string(),
                value: s.to_string(),
                reason: format!("'{prefix_part}' is not a valid prefix length"),
            })?;

        let max_prefix = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max_prefix {
            return Err(AnnotationError::InvalidValue {
                annotation: "cidr".to_string(),
                value: s.to_string(),
                reason: format!("prefix length {prefix_len} exceeds maximum {max_prefix}"),
            });
        }

        Ok(CidrBlock { addr, prefix_len })
    }
}

/// Return `true` if this Ingress should be managed by this controller.
///
/// Checks `spec.ingressClassName` first (the v1.18+ field), then falls back to
/// the legacy `kubernetes.io/ingress.class` annotation. When `class_name` is
/// `None`, we manage all Ingresses (single-controller mode).
pub fn is_owned_by_dwaar(ingress: &Ingress, class_name: Option<&str>) -> bool {
    let Some(class_name) = class_name else {
        return true; // no filter — own everything
    };

    // Check spec.ingressClassName (preferred since Kubernetes 1.18).
    let spec_class = ingress
        .spec
        .as_ref()
        .and_then(|s| s.ingress_class_name.as_deref());

    if let Some(sc) = spec_class {
        return sc == class_name;
    }

    // Fall back to the legacy annotation.
    ingress
        .metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get(LEGACY_CLASS_ANNOTATION))
        .is_some_and(|v| v == class_name)
}

/// Create the `IngressClass` resource on startup if it does not already exist.
///
/// This is a best-effort operation — a `409 Conflict` (already exists) is
/// silently ignored. Other errors are returned so the caller can decide whether
/// to abort or proceed.
pub async fn ensure_ingress_class(
    client: &Api<IngressClass>,
    class_name: &str,
) -> Result<(), kube::Error> {
    let ic = IngressClass {
        metadata: ObjectMeta {
            name: Some(class_name.to_string()),
            ..Default::default()
        },
        spec: Some(IngressClassSpec {
            // The controller field is a free-form URI identifying this implementation.
            controller: Some(format!("dwaar.dev/{class_name}")),
            ..Default::default()
        }),
    };

    match client.create(&PostParams::default(), &ic).await {
        Ok(_) => {
            info!(class_name, "IngressClass created");
            Ok(())
        }
        Err(kube::Error::Api(ae)) if ae.code == 409 => {
            // Already exists from a previous startup — nothing to do.
            info!(class_name, "IngressClass already exists");
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Parse all `dwaar.dev/*` annotations from an Ingress.
///
/// Unknown `dwaar.dev/*` keys produce a warning rather than an error so that
/// forward-compatibility is maintained — an operator running a newer config
/// against an older controller will see a warning, not a crash.
pub fn parse_annotations(ingress: &Ingress) -> DwaarAnnotations {
    let Some(annotations) = ingress.metadata.annotations.as_ref() else {
        return DwaarAnnotations::default();
    };

    let mut out = DwaarAnnotations::default();

    for (key, value) in annotations {
        // Only process our own prefix.
        let Some(suffix) = key.strip_prefix(DWAAR_PREFIX) else {
            continue;
        };

        match suffix {
            "rate-limit" => {
                out.rate_limit = parse_u32(key, value);
            }
            "tls-redirect" => {
                out.tls_redirect = parse_bool(key, value);
            }
            "upstream-proto" => {
                out.upstream_proto = parse_upstream_proto(key, value);
            }
            "under-attack" => {
                out.under_attack = parse_bool(key, value);
            }
            "ip-filter-allow" => {
                out.ip_filter_allow = parse_cidrs(key, value);
            }
            "ip-filter-deny" => {
                out.ip_filter_deny = parse_cidrs(key, value);
            }
            unknown => {
                warn!(annotation = %key, "unknown dwaar.dev/* annotation — ignoring");
                let _ = unknown; // explicit discard to aid future readers
            }
        }
    }

    out
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

fn parse_u32(annotation: &str, value: &str) -> Option<u32> {
    if let Ok(n) = value.trim().parse::<u32>() {
        Some(n)
    } else {
        warn!(annotation, value, "expected u32 — ignoring");
        None
    }
}

fn parse_bool(annotation: &str, value: &str) -> Option<bool> {
    match value.trim().to_lowercase().as_str() {
        "true" | "1" | "yes" => Some(true),
        "false" | "0" | "no" => Some(false),
        _ => {
            warn!(annotation, value, "expected bool (true/false) — ignoring");
            None
        }
    }
}

fn parse_upstream_proto(annotation: &str, value: &str) -> Option<UpstreamProto> {
    match value.trim() {
        "h2" => Some(UpstreamProto::H2),
        "http" => Some(UpstreamProto::Http),
        _ => {
            warn!(annotation, value, "expected 'h2' or 'http' — ignoring");
            None
        }
    }
}

/// Parse a comma-separated list of CIDR blocks.
///
/// Invalid individual entries are skipped with a warning rather than discarding
/// the entire list — a single typo should not negate the operator's intent for
/// all other valid CIDRs in the same annotation.
fn parse_cidrs(annotation: &str, value: &str) -> Vec<CidrBlock> {
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|cidr| match cidr.parse::<CidrBlock>() {
            Ok(c) => Some(c),
            Err(e) => {
                warn!(annotation, cidr, error = %e, "invalid CIDR — skipping");
                None
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use k8s_openapi::api::networking::v1::{Ingress, IngressSpec};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    use super::*;

    // Build an Ingress with the given spec class name and/or legacy annotation.
    fn make_ingress(spec_class: Option<&str>, legacy_annotation: Option<&str>) -> Ingress {
        let mut annotations = BTreeMap::new();
        if let Some(ann) = legacy_annotation {
            annotations.insert(LEGACY_CLASS_ANNOTATION.to_string(), ann.to_string());
        }

        Ingress {
            metadata: ObjectMeta {
                name: Some("test-ingress".to_string()),
                namespace: Some("default".to_string()),
                annotations: if annotations.is_empty() {
                    None
                } else {
                    Some(annotations)
                },
                ..Default::default()
            },
            spec: Some(IngressSpec {
                ingress_class_name: spec_class.map(ToString::to_string),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    // Build an Ingress with arbitrary annotations.
    fn make_ingress_with_annotations(annotations: BTreeMap<String, String>) -> Ingress {
        Ingress {
            metadata: ObjectMeta {
                name: Some("ann-ingress".to_string()),
                namespace: Some("default".to_string()),
                annotations: Some(annotations),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    // ── IngressClass filtering ───────────────────────────────────────────────

    #[test]
    fn no_filter_owns_everything() {
        // class_name = None → manage all Ingresses regardless of class field.
        let ingress = make_ingress(None, None);
        assert!(is_owned_by_dwaar(&ingress, None));
    }

    #[test]
    fn spec_class_matches_filter() {
        let ingress = make_ingress(Some("dwaar"), None);
        assert!(is_owned_by_dwaar(&ingress, Some("dwaar")));
    }

    #[test]
    fn spec_class_mismatch_rejected() {
        let ingress = make_ingress(Some("nginx"), None);
        assert!(!is_owned_by_dwaar(&ingress, Some("dwaar")));
    }

    #[test]
    fn legacy_annotation_matches_filter() {
        // No spec.ingressClassName → fall back to annotation.
        let ingress = make_ingress(None, Some("dwaar"));
        assert!(is_owned_by_dwaar(&ingress, Some("dwaar")));
    }

    #[test]
    fn legacy_annotation_mismatch_rejected() {
        let ingress = make_ingress(None, Some("traefik"));
        assert!(!is_owned_by_dwaar(&ingress, Some("dwaar")));
    }

    #[test]
    fn no_class_set_and_filter_active_returns_false() {
        // Neither spec.ingressClassName nor the legacy annotation is set,
        // but the controller is configured to only handle "dwaar" class.
        let ingress = make_ingress(None, None);
        assert!(!is_owned_by_dwaar(&ingress, Some("dwaar")));
    }

    #[test]
    fn spec_class_takes_priority_over_annotation() {
        // spec.ingressClassName = "dwaar", annotation = "nginx".
        // The spec field wins.
        let mut annotations = BTreeMap::new();
        annotations.insert(LEGACY_CLASS_ANNOTATION.to_string(), "nginx".to_string());
        let ingress = Ingress {
            metadata: ObjectMeta {
                annotations: Some(annotations),
                ..Default::default()
            },
            spec: Some(IngressSpec {
                ingress_class_name: Some("dwaar".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(is_owned_by_dwaar(&ingress, Some("dwaar")));
    }

    // ── Annotation parsing ───────────────────────────────────────────────────

    #[test]
    fn no_annotations_returns_defaults() {
        let ingress = make_ingress(None, None);
        let ann = parse_annotations(&ingress);
        assert_eq!(ann, DwaarAnnotations::default());
    }

    #[test]
    fn rate_limit_parsed() {
        let mut a = BTreeMap::new();
        a.insert("dwaar.dev/rate-limit".to_string(), "100".to_string());
        let ann = parse_annotations(&make_ingress_with_annotations(a));
        assert_eq!(ann.rate_limit, Some(100));
    }

    #[test]
    fn tls_redirect_true() {
        let mut a = BTreeMap::new();
        a.insert("dwaar.dev/tls-redirect".to_string(), "true".to_string());
        let ann = parse_annotations(&make_ingress_with_annotations(a));
        assert_eq!(ann.tls_redirect, Some(true));
    }

    #[test]
    fn tls_redirect_false() {
        let mut a = BTreeMap::new();
        a.insert("dwaar.dev/tls-redirect".to_string(), "false".to_string());
        let ann = parse_annotations(&make_ingress_with_annotations(a));
        assert_eq!(ann.tls_redirect, Some(false));
    }

    #[test]
    fn upstream_proto_h2() {
        let mut a = BTreeMap::new();
        a.insert("dwaar.dev/upstream-proto".to_string(), "h2".to_string());
        let ann = parse_annotations(&make_ingress_with_annotations(a));
        assert_eq!(ann.upstream_proto, Some(UpstreamProto::H2));
    }

    #[test]
    fn upstream_proto_http() {
        let mut a = BTreeMap::new();
        a.insert("dwaar.dev/upstream-proto".to_string(), "http".to_string());
        let ann = parse_annotations(&make_ingress_with_annotations(a));
        assert_eq!(ann.upstream_proto, Some(UpstreamProto::Http));
    }

    #[test]
    fn under_attack_parsed() {
        let mut a = BTreeMap::new();
        a.insert("dwaar.dev/under-attack".to_string(), "true".to_string());
        let ann = parse_annotations(&make_ingress_with_annotations(a));
        assert_eq!(ann.under_attack, Some(true));
    }

    #[test]
    fn ip_filter_allow_parsed() {
        let mut a = BTreeMap::new();
        a.insert(
            "dwaar.dev/ip-filter-allow".to_string(),
            "10.0.0.0/8, 192.168.1.0/24".to_string(),
        );
        let ann = parse_annotations(&make_ingress_with_annotations(a));
        assert_eq!(ann.ip_filter_allow.len(), 2);
        assert_eq!(ann.ip_filter_allow[0].to_string(), "10.0.0.0/8");
        assert_eq!(ann.ip_filter_allow[1].to_string(), "192.168.1.0/24");
    }

    #[test]
    fn ip_filter_deny_parsed() {
        let mut a = BTreeMap::new();
        a.insert(
            "dwaar.dev/ip-filter-deny".to_string(),
            "203.0.113.0/24".to_string(),
        );
        let ann = parse_annotations(&make_ingress_with_annotations(a));
        assert_eq!(ann.ip_filter_deny.len(), 1);
    }

    #[test]
    fn invalid_rate_limit_ignored() {
        let mut a = BTreeMap::new();
        a.insert(
            "dwaar.dev/rate-limit".to_string(),
            "not-a-number".to_string(),
        );
        let ann = parse_annotations(&make_ingress_with_annotations(a));
        assert_eq!(ann.rate_limit, None);
    }

    #[test]
    fn invalid_bool_ignored() {
        let mut a = BTreeMap::new();
        a.insert("dwaar.dev/tls-redirect".to_string(), "maybe".to_string());
        let ann = parse_annotations(&make_ingress_with_annotations(a));
        assert_eq!(ann.tls_redirect, None);
    }

    #[test]
    fn invalid_upstream_proto_ignored() {
        let mut a = BTreeMap::new();
        a.insert("dwaar.dev/upstream-proto".to_string(), "grpc".to_string());
        let ann = parse_annotations(&make_ingress_with_annotations(a));
        assert_eq!(ann.upstream_proto, None);
    }

    #[test]
    fn invalid_cidr_skipped_valid_kept() {
        let mut a = BTreeMap::new();
        // One invalid, one valid
        a.insert(
            "dwaar.dev/ip-filter-allow".to_string(),
            "not-a-cidr, 10.0.0.0/8".to_string(),
        );
        let ann = parse_annotations(&make_ingress_with_annotations(a));
        // Invalid CIDR is skipped; valid one is kept.
        assert_eq!(ann.ip_filter_allow.len(), 1);
        assert_eq!(ann.ip_filter_allow[0].to_string(), "10.0.0.0/8");
    }

    #[test]
    fn unknown_annotation_does_not_panic() {
        // An unknown dwaar.dev/* annotation should be logged and skipped.
        let mut a = BTreeMap::new();
        a.insert("dwaar.dev/future-feature".to_string(), "value".to_string());
        let ann = parse_annotations(&make_ingress_with_annotations(a));
        // All fields remain default.
        assert_eq!(ann, DwaarAnnotations::default());
    }

    #[test]
    fn non_dwaar_annotations_ignored() {
        let mut a = BTreeMap::new();
        a.insert(
            "nginx.ingress.kubernetes.io/rewrite-target".to_string(),
            "/".to_string(),
        );
        let ann = parse_annotations(&make_ingress_with_annotations(a));
        assert_eq!(ann, DwaarAnnotations::default());
    }

    // ── CIDR parsing ─────────────────────────────────────────────────────────

    #[test]
    fn cidr_ipv4_parses() {
        let cidr: CidrBlock = "192.168.0.0/16".parse().expect("valid CIDR");
        assert_eq!(cidr.prefix_len, 16);
        assert!(matches!(cidr.addr, IpAddr::V4(_)));
    }

    #[test]
    fn cidr_ipv6_parses() {
        let cidr: CidrBlock = "2001:db8::/32".parse().expect("valid CIDR");
        assert_eq!(cidr.prefix_len, 32);
        assert!(matches!(cidr.addr, IpAddr::V6(_)));
    }

    #[test]
    fn cidr_bad_prefix_length_rejected() {
        let result: Result<CidrBlock, _> = "10.0.0.0/33".parse();
        assert!(result.is_err(), "prefix /33 is invalid for IPv4");
    }

    #[test]
    fn cidr_missing_slash_rejected() {
        let result: Result<CidrBlock, _> = "10.0.0.0".parse();
        assert!(result.is_err());
    }

    #[test]
    fn cidr_bad_addr_rejected() {
        let result: Result<CidrBlock, _> = "999.999.999.999/24".parse();
        assert!(result.is_err());
    }
}
