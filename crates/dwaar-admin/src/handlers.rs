// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Admin API endpoint handlers.

use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use dashmap::DashMap;
use dwaar_analytics::aggregation::DomainMetrics;
use dwaar_analytics::aggregation::snapshot::AnalyticsSnapshot;
use dwaar_core::route::{Route, RouteTable, is_valid_route_key};
use serde::Deserialize;

/// Request body for `POST /routes`.
#[derive(Debug, Deserialize)]
pub struct CreateRouteRequest {
    pub domain: String,
    pub upstream: String,
    pub tls: bool,
    /// Which component owns this route (e.g. "dwaar-ingress").
    /// Used by reconcilers to identify their own routes.
    #[serde(default)]
    pub source: Option<String>,
}

/// Build the health check response body.
pub fn health(start_time: &Instant) -> String {
    let uptime = start_time.elapsed().as_secs();
    format!(r#"{{"status":"ok","uptime_secs":{uptime}}}"#)
}

/// Outcome of validating a Dwaarfile source string for the `POST /reload`
/// pre-flight check.
///
/// The admin API parses the config file in-process before notifying the
/// config watcher. When parsing fails we surface the full
/// `ParseError::Display` output to the caller so they see the same error
/// message the CLI would produce — including line numbers, suggestions,
/// and the optional `accepted_format` hint.
#[derive(Debug)]
pub enum ConfigValidation {
    /// The source parsed successfully — the watcher can be notified.
    Ok,
    /// The source failed to parse. Contains the status code and the full
    /// `Display` output of the error as the response body.
    Err { status: u16, body: String },
}

/// Validate a Dwaarfile source string and return the response-ready
/// `ConfigValidation` outcome.
///
/// Returns `Ok` when the source parses cleanly. Returns `Err { status: 400 }`
/// for all parse errors — currently the parser does not distinguish syntax
/// errors from semantic ones, so everything is surfaced as HTTP 400.
#[must_use]
pub fn validate_config_source(src: &str) -> ConfigValidation {
    match dwaar_config::parser::parse(src) {
        Ok(_) => ConfigValidation::Ok,
        Err(e) => ConfigValidation::Err {
            status: 400,
            body: format!("{e}"),
        },
    }
}

/// List all routes as JSON array.
pub fn list_routes(route_table: &ArcSwap<RouteTable>) -> Result<String, String> {
    let table = route_table.load();
    let routes = table.all_routes();
    serde_json::to_string(&routes).map_err(|e| format!("serialize error: {e}"))
}

/// Add or update a route. Returns the created route as JSON.
pub fn add_route(route_table: &ArcSwap<RouteTable>, body: &[u8]) -> Result<String, String> {
    let req: CreateRouteRequest =
        serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;

    if !is_valid_route_key(&req.domain) {
        return Err(format!("invalid domain: {}", req.domain));
    }

    let upstream: std::net::SocketAddr = req
        .upstream
        .parse()
        .map_err(|e| format!("invalid upstream address: {e}"))?;

    let route = Route::with_source(&req.domain, upstream, req.tls, None, req.source);

    route_table.rcu(|current| {
        let mut routes = current.all_routes();
        routes.retain(|r| r.domain != route.domain);
        routes.push(route.clone());
        Arc::new(RouteTable::new(routes))
    });

    tracing::info!(
        target: "dwaar::admin::audit",
        action = "route_add",
        principal = "admin",
        resource = %route.domain,
        "admin mutation"
    );
    serde_json::to_string(&route).map_err(|e| format!("serialize error: {e}"))
}

/// Get analytics snapshot for a single domain.
/// Returns None if the domain has no metrics.
pub fn get_domain_analytics(
    metrics: &DashMap<String, DomainMetrics>,
    domain: &str,
) -> Option<String> {
    let entry = metrics.get(domain)?;
    let snapshot = AnalyticsSnapshot::from_metrics(domain, &entry);
    serde_json::to_string(&snapshot).ok()
}

/// Get analytics snapshots for all tracked domains.
pub fn list_all_analytics(metrics: &DashMap<String, DomainMetrics>) -> Result<String, String> {
    let snapshots: Vec<AnalyticsSnapshot> = metrics
        .iter()
        .map(|entry| AnalyticsSnapshot::from_metrics(entry.key(), entry.value()))
        .collect();
    serde_json::to_string(&snapshots).map_err(|e| format!("serialize error: {e}"))
}

/// Delete a route by domain. Returns the deleted domain or None if not found.
pub fn delete_route(route_table: &ArcSwap<RouteTable>, domain: &str) -> Option<String> {
    let domain_lower = domain.to_lowercase();
    let mut existed = false;

    // Atomically filter the route inside rcu — the closure may retry on
    // CAS failure, but the last execution (the one that commits) sets
    // `existed` to its final correct value.
    route_table.rcu(|current| {
        let old_routes = current.all_routes();
        let old_len = old_routes.len();
        let routes: Vec<Route> = old_routes
            .into_iter()
            .filter(|r| r.domain != domain_lower)
            .collect();
        existed = routes.len() < old_len;
        Arc::new(RouteTable::new(routes))
    });

    if existed {
        tracing::info!(
            target: "dwaar::admin::audit",
            action = "route_delete",
            principal = "admin",
            resource = %domain_lower,
            "admin mutation"
        );
    }
    existed.then_some(domain_lower)
}

/// Purge a single cache entry by host/path key.
///
/// The key format is `{host}/{path}` — extracted from the PURGE URL.
/// We reconstruct a GET cache key (caching only applies to GET requests).
pub async fn purge_cache_key(
    storage: &'static (dyn pingora_cache::storage::Storage + Sync),
    key_str: &str,
) -> bool {
    use pingora_cache::storage::PurgeType;
    use pingora_cache::trace::Span;

    let (host, path) = key_str.split_once('/').unwrap_or((key_str, "/"));
    let path = if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    };
    let cache_key = dwaar_core::cache::build_cache_key(host, &path, "GET");
    let compact = cache_key.to_compact();

    // Inactive span — admin API doesn't participate in distributed tracing.
    let span = Span::inactive();
    let handle = span.handle();

    let purged = storage
        .purge(&compact, PurgeType::Invalidation, &handle)
        .await
        .unwrap_or(false);

    if purged {
        tracing::info!(
            target: "dwaar::admin::audit",
            action = "cache_purge",
            principal = "admin",
            resource = %key_str,
            "admin mutation"
        );
    }
    purged
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashmap::DashMap;
    use dwaar_analytics::aggregation::DomainMetrics;
    use std::net::SocketAddr;

    fn make_table(routes: Vec<Route>) -> Arc<ArcSwap<RouteTable>> {
        Arc::new(ArcSwap::from_pointee(RouteTable::new(routes)))
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[test]
    fn health_response_format() {
        let start = Instant::now();
        let json = health(&start);
        assert!(json.contains("\"status\":\"ok\""));
        assert!(json.contains("\"uptime_secs\":"));
    }

    #[test]
    fn list_routes_returns_json_array() {
        let table = make_table(vec![
            Route::new("a.com", addr(1000), false, None),
            Route::new("b.com", addr(2000), true, None),
        ]);
        let json = list_routes(&table).expect("should serialize");
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn add_route_creates_new_entry() {
        let table = make_table(vec![]);
        let body = br#"{"domain":"new.example.com","upstream":"127.0.0.1:3000","tls":true}"#;
        let result = add_route(&table, body);
        assert!(result.is_ok());
        assert_eq!(table.load().len(), 1);
        assert!(table.load().resolve("new.example.com").is_some());
    }

    #[test]
    fn add_route_upserts_existing() {
        let table = make_table(vec![Route::new("exist.com", addr(1000), false, None)]);
        let body = br#"{"domain":"exist.com","upstream":"127.0.0.1:2000","tls":true}"#;
        add_route(&table, body).expect("upsert");
        let guard = table.load();
        let route = guard.resolve("exist.com").expect("should exist");
        assert_eq!(route.upstream().expect("has upstream").port(), 2000);
        assert!(route.tls);
    }

    #[test]
    fn add_route_rejects_invalid_domain() {
        let table = make_table(vec![]);
        let body = br#"{"domain":"../evil","upstream":"127.0.0.1:3000","tls":false}"#;
        let result = add_route(&table, body);
        assert!(result.is_err());
    }

    #[test]
    fn add_route_rejects_invalid_upstream() {
        let table = make_table(vec![]);
        let body = br#"{"domain":"valid.com","upstream":"not-an-address","tls":false}"#;
        let result = add_route(&table, body);
        assert!(result.is_err());
    }

    #[test]
    fn delete_route_removes_entry() {
        let table = make_table(vec![
            Route::new("a.com", addr(1000), false, None),
            Route::new("b.com", addr(2000), false, None),
        ]);
        let deleted = delete_route(&table, "a.com");
        assert_eq!(deleted.as_deref(), Some("a.com"));
        assert_eq!(table.load().len(), 1);
        assert!(table.load().resolve("a.com").is_none());
    }

    #[test]
    fn delete_nonexistent_returns_none() {
        let table = make_table(vec![]);
        assert!(delete_route(&table, "ghost.com").is_none());
    }

    fn make_metrics() -> Arc<DashMap<String, DomainMetrics>> {
        let map = Arc::new(DashMap::new());
        let mut dm = DomainMetrics::new();
        dm.ingest_log(&dwaar_analytics::aggregation::AggEvent {
            host: "test.example.com".into(),
            path: "/home".into(),
            status: 200,
            bytes_sent: 1024,
            client_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            country: None,
            referer: None,
            is_bot: false,
        });
        map.insert("test.example.com".to_string(), dm);
        map
    }

    #[test]
    fn get_domain_analytics_returns_snapshot() {
        let metrics = make_metrics();
        let result = get_domain_analytics(&metrics, "test.example.com");
        assert!(result.is_some());
        let json = result.expect("should have analytics");
        assert!(json.contains("\"domain\":\"test.example.com\""));
        assert!(json.contains("\"page_views_1m\""));
    }

    #[test]
    fn get_domain_analytics_unknown_returns_none() {
        let metrics = make_metrics();
        assert!(get_domain_analytics(&metrics, "ghost.com").is_none());
    }

    #[test]
    fn list_all_analytics_returns_array() {
        let metrics = make_metrics();
        let json = list_all_analytics(&metrics).expect("should serialize");
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0]["domain"], "test.example.com");
    }
}
