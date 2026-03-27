// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Parse Docker container labels into Dwaar routes.
//!
//! Extracts `dwaar.*` labels from a Docker inspect JSON response and
//! validates them into a [`Route`]. Invalid labels are rejected with
//! a descriptive error — the caller decides whether to warn or skip.

use std::net::{IpAddr, SocketAddr};

use dwaar_core::route::{Route, is_valid_domain};
use tracing::warn;

/// Parsed result from a Docker container's labels + network settings.
#[derive(Debug)]
pub struct ContainerRoute {
    pub container_id: String,
    pub route: Route,
}

/// Try to build a Route from a Docker inspect JSON response.
///
/// Returns `None` if required labels are missing or invalid.
/// Logs a warning for each validation failure.
pub fn parse_container(inspect: &serde_json::Value) -> Option<ContainerRoute> {
    let id = inspect.get("Id")?.as_str()?.to_string();
    let labels = inspect.pointer("/Config/Labels")?;

    let domain = labels.get("dwaar.domain")?.as_str()?;
    if !is_valid_domain(domain) {
        warn!(container_id = %id, domain, "invalid dwaar.domain label — skipping");
        return None;
    }

    let port_str = labels.get("dwaar.port")?.as_str()?;
    let port: u16 = match port_str.parse() {
        Ok(p) if p > 0 => p,
        _ => {
            warn!(container_id = %id, port = port_str, "invalid dwaar.port label — skipping");
            return None;
        }
    };

    let tls = labels
        .get("dwaar.tls")
        .and_then(|v| v.as_str())
        == Some("true");

    let rate_limit_rps = labels
        .get("dwaar.rate_limit")
        .and_then(|v| v.as_str())
        .and_then(|v| {
            let rps: u32 = v.parse().ok()?;
            if rps > 0 { Some(rps) } else { None }
        });

    let ip = resolve_container_ip(inspect, &id)?;
    let upstream = SocketAddr::new(ip, port);

    Some(ContainerRoute {
        container_id: id,
        route: Route::new(domain, upstream, tls, rate_limit_rps),
    })
}

/// Extract the container's IP address from network settings.
///
/// Prefers `bridge` network. Falls back to the first available network.
/// Returns `127.0.0.1` for host-networking (empty IP string or no networks).
fn resolve_container_ip(inspect: &serde_json::Value, container_id: &str) -> Option<IpAddr> {
    let networks = inspect.pointer("/NetworkSettings/Networks")?.as_object()?;

    if networks.is_empty() {
        return Some(IpAddr::from([127, 0, 0, 1]));
    }

    // Prefer bridge network
    if let Some(bridge) = networks.get("bridge") {
        match extract_ip(bridge, container_id) {
            Ok(Some(ip)) => return Some(ip),
            Err(()) => return None, // malformed IP is a hard error
            Ok(None) => {}          // empty IP, try other networks
        }
    }

    // Fall back to first network with a valid IP
    for (_name, network) in networks {
        match extract_ip(network, container_id) {
            Ok(Some(ip)) => return Some(ip),
            Err(()) => return None,
            Ok(None) => {}
        }
    }

    // All networks had empty IPs — host networking variant
    Some(IpAddr::from([127, 0, 0, 1]))
}

/// Returns `Ok(Some(ip))` for a valid IP, `Ok(None)` for an empty string
/// (normal for host networking), or `Err(())` for a malformed IP.
fn extract_ip(network: &serde_json::Value, container_id: &str) -> Result<Option<IpAddr>, ()> {
    let Some(ip_str) = network.get("IPAddress").and_then(|v| v.as_str()) else {
        return Ok(None);
    };
    if ip_str.is_empty() {
        return Ok(None);
    }
    if let Ok(ip) = ip_str.parse::<IpAddr>() {
        Ok(Some(ip))
    } else {
        warn!(container_id, ip = ip_str, "failed to parse container IP");
        Err(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_inspect(domain: &str, port: &str, ip: &str) -> serde_json::Value {
        json!({
            "Id": "abc123def456",
            "Config": {
                "Labels": {
                    "dwaar.domain": domain,
                    "dwaar.port": port
                }
            },
            "NetworkSettings": {
                "Networks": {
                    "bridge": {
                        "IPAddress": ip
                    }
                }
            }
        })
    }

    #[test]
    fn valid_labels_parse_to_route() {
        let inspect = make_inspect("api.example.com", "8080", "172.17.0.2");
        let cr = parse_container(&inspect).expect("should parse");
        assert_eq!(cr.route.domain, "api.example.com");
        assert_eq!(cr.route.upstream.port(), 8080);
        assert_eq!(cr.route.upstream.ip().to_string(), "172.17.0.2");
        assert!(!cr.route.tls);
        assert_eq!(cr.route.rate_limit_rps, None);
        assert_eq!(cr.container_id, "abc123def456");
    }

    #[test]
    fn missing_domain_returns_none() {
        let inspect = json!({
            "Id": "abc123",
            "Config": { "Labels": { "dwaar.port": "8080" } },
            "NetworkSettings": { "Networks": { "bridge": { "IPAddress": "172.17.0.2" } } }
        });
        assert!(parse_container(&inspect).is_none());
    }

    #[test]
    fn missing_port_returns_none() {
        let inspect = json!({
            "Id": "abc123",
            "Config": { "Labels": { "dwaar.domain": "example.com" } },
            "NetworkSettings": { "Networks": { "bridge": { "IPAddress": "172.17.0.2" } } }
        });
        assert!(parse_container(&inspect).is_none());
    }

    #[test]
    fn invalid_domain_rejected() {
        let inspect = make_inspect("../../../etc/shadow", "8080", "172.17.0.2");
        assert!(parse_container(&inspect).is_none());
    }

    #[test]
    fn port_zero_rejected() {
        let inspect = make_inspect("example.com", "0", "172.17.0.2");
        assert!(parse_container(&inspect).is_none());
    }

    #[test]
    fn port_out_of_range_rejected() {
        let inspect = make_inspect("example.com", "70000", "172.17.0.2");
        assert!(parse_container(&inspect).is_none());
    }

    #[test]
    fn tls_label_sets_flag() {
        let mut inspect = make_inspect("example.com", "443", "172.17.0.2");
        inspect["Config"]["Labels"]["dwaar.tls"] = json!("true");
        let cr = parse_container(&inspect).expect("should parse");
        assert!(cr.route.tls);
    }

    #[test]
    fn rate_limit_label_sets_rps() {
        let mut inspect = make_inspect("example.com", "8080", "172.17.0.2");
        inspect["Config"]["Labels"]["dwaar.rate_limit"] = json!("100");
        let cr = parse_container(&inspect).expect("should parse");
        assert_eq!(cr.route.rate_limit_rps, Some(100));
    }

    #[test]
    fn empty_ip_falls_back_to_localhost() {
        let inspect = make_inspect("example.com", "8080", "");
        let cr = parse_container(&inspect).expect("should parse");
        assert_eq!(cr.route.upstream.ip().to_string(), "127.0.0.1");
    }

    #[test]
    fn malformed_ip_returns_none() {
        let inspect = make_inspect("example.com", "8080", "not-an-ip");
        assert!(parse_container(&inspect).is_none());
    }

    #[test]
    fn host_networking_no_networks() {
        let inspect = json!({
            "Id": "abc123",
            "Config": { "Labels": { "dwaar.domain": "example.com", "dwaar.port": "8080" } },
            "NetworkSettings": { "Networks": {} }
        });
        let cr = parse_container(&inspect).expect("should parse");
        assert_eq!(cr.route.upstream.ip().to_string(), "127.0.0.1");
    }
}
