// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Admin API endpoint handlers.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use dwaar_analytics::aggregation::DomainMetrics;
use dwaar_analytics::aggregation::snapshot::AnalyticsSnapshot;
use dwaar_core::route::{Route, RouteTable, is_valid_route_key};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_SNAPSHOT_SOURCE_LEN: usize = 128;
const ADMIN_CAPABILITIES: &[&str] = &[
    "admin.healthz",
    "admin.metrics.prometheus",
    "routes.list",
    "routes.state",
    "routes.snapshot.apply",
    "metrics.route_status_class",
    "metrics.upstream_health",
    "metrics.upstream_connect_duration",
    "analytics.domain",
    "cache.purge",
];

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

/// Route entry accepted by the desired route snapshot API.
#[derive(Debug, Deserialize)]
pub struct SnapshotRouteRequest {
    pub domain: String,
    pub upstream: String,
    pub tls: bool,
}

/// Request body for `PUT /routes/snapshot`.
#[derive(Debug, Deserialize)]
pub struct ApplyRouteSnapshotRequest {
    /// Controller identity that owns every route in this desired snapshot.
    pub source: String,
    /// Complete desired route set for `source`.
    #[serde(default)]
    pub routes: Vec<SnapshotRouteRequest>,
}

#[derive(Debug, Serialize)]
struct ApplyRouteSnapshotResponse {
    source: String,
    applied: usize,
    removed: usize,
    total_routes: usize,
    route_hash: String,
}

/// Build the health check response body.
pub fn health(start_time: &Instant) -> String {
    let uptime = start_time.elapsed().as_secs();
    format!(r#"{{"status":"ok","uptime_secs":{uptime}}}"#)
}

/// Build the `/healthz` response.
///
/// Returns `200 {"status":"ok"}` while the proxy is running normally,
/// or `503 {"status":"draining"}` once the server enters graceful shutdown.
/// Callers pass `shutting_down = true` during the drain window so the
/// installer's health-check loop can detect the swap boundary.
pub fn healthz(shutting_down: bool) -> (u16, String) {
    if shutting_down {
        (503, r#"{"status":"draining"}"#.to_string())
    } else {
        (200, r#"{"status":"ok"}"#.to_string())
    }
}

/// Build the `/version` response body.
///
/// Returns a JSON object with the binary version, the RFC 3339 `started_at`
/// timestamp, and the current PID. Used by the installer's upgrade-readiness
/// check to confirm the new binary is answering and to verify the PID changed.
pub fn version_info(started_at: SystemTime) -> String {
    let ver = env!("CARGO_PKG_VERSION");
    // SAFETY: getpid() is always safe to call on Unix.
    #[allow(unsafe_code)]
    let pid = unsafe { libc::getpid() };
    let started_rfc3339: DateTime<Utc> = started_at.into();
    serde_json::json!({
        "version": ver,
        "started_at": started_rfc3339.to_rfc3339(),
        "pid": pid,
        "capabilities": ADMIN_CAPABILITIES,
    })
    .to_string()
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

/// Apply a source-owned desired route snapshot.
///
/// Routes owned by other sources are left untouched. Routes currently owned by
/// `source` but absent from the desired snapshot are removed. This gives
/// reconcilers an idempotent drift-correction operation without broad table
/// ownership.
pub fn apply_route_snapshot(
    route_table: &ArcSwap<RouteTable>,
    body: &[u8],
) -> Result<String, String> {
    let req: ApplyRouteSnapshotRequest =
        serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;
    validate_snapshot_source(&req.source)?;

    let mut routes = Vec::with_capacity(req.routes.len());
    let mut domains = HashSet::with_capacity(req.routes.len());
    for route_req in req.routes {
        if !is_valid_route_key(&route_req.domain) {
            return Err(format!("invalid domain: {}", route_req.domain));
        }
        let upstream: std::net::SocketAddr = route_req
            .upstream
            .parse()
            .map_err(|e| format!("invalid upstream address: {e}"))?;
        let route = Route::with_source(
            &route_req.domain,
            upstream,
            route_req.tls,
            None,
            Some(req.source.clone()),
        );
        if !domains.insert(route.domain.clone()) {
            return Err(format!("duplicate domain in snapshot: {}", route.domain));
        }
        routes.push(route);
    }

    routes.sort_by(|a, b| a.domain.cmp(&b.domain));
    let route_hash = hash_route_snapshot(&req.source, &routes);
    let mut removed = 0;
    let mut total_routes = 0;

    route_table.rcu(|current| {
        let old_routes = current.all_routes();
        let desired_domains = domains.clone();
        removed = old_routes
            .iter()
            .filter(|route| {
                route.source() == Some(req.source.as_str())
                    && !desired_domains.contains(&route.domain)
            })
            .count();

        let mut next_routes: Vec<Route> = old_routes
            .into_iter()
            .filter(|route| route.source() != Some(req.source.as_str()))
            .collect();
        next_routes.extend(routes.iter().cloned());
        total_routes = next_routes.len();
        Arc::new(RouteTable::new(next_routes))
    });

    tracing::info!(
        target: "dwaar::admin::audit",
        action = "route_snapshot_apply",
        principal = "admin",
        resource = %req.source,
        applied = routes.len(),
        removed,
        route_hash = %route_hash,
        "admin mutation"
    );

    let response = ApplyRouteSnapshotResponse {
        source: req.source,
        applied: routes.len(),
        removed,
        total_routes,
        route_hash,
    };
    serde_json::to_string(&response).map_err(|e| format!("serialize error: {e}"))
}

fn validate_snapshot_source(source: &str) -> Result<(), String> {
    if source.is_empty() {
        return Err("source is required".to_string());
    }
    if source.len() > MAX_SNAPSHOT_SOURCE_LEN {
        return Err("source too long".to_string());
    }
    if source.bytes().any(|b| b.is_ascii_control()) {
        return Err("source contains control characters".to_string());
    }
    Ok(())
}

fn hash_route_snapshot(source: &str, routes: &[Route]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(source.as_bytes());
    hasher.update(b"\n");
    for route in routes {
        hasher.update(route.domain.as_bytes());
        hasher.update(b"\0");
        if let Some(upstream) = route.upstream() {
            hasher.update(upstream.to_string().as_bytes());
        }
        hasher.update(b"\0");
        hasher.update(if route.tls { b"1" } else { b"0" });
        hasher.update(b"\n");
    }
    hex::encode(hasher.finalize())
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
    fn healthz_returns_ok_when_not_draining() {
        let (status, body) = healthz(false);
        assert_eq!(status, 200);
        assert!(body.contains("\"status\":\"ok\""));
    }

    #[test]
    fn healthz_returns_503_when_draining() {
        let (status, body) = healthz(true);
        assert_eq!(status, 503);
        assert!(body.contains("\"status\":\"draining\""));
    }

    #[test]
    fn version_info_contains_version_pid_started_at() {
        let now = SystemTime::now();
        let json = version_info(now);
        // Version field matches CARGO_PKG_VERSION
        assert!(
            json.contains(env!("CARGO_PKG_VERSION")),
            "version missing from /version response"
        );
        // PID is a positive integer — just check the key exists
        assert!(
            json.contains("\"pid\":"),
            "pid missing from /version response"
        );
        // started_at is present and is an RFC 3339 timestamp
        assert!(
            json.contains("\"started_at\":"),
            "started_at missing from /version response"
        );
    }

    #[test]
    fn version_info_advertises_admin_capabilities() {
        let parsed: serde_json::Value =
            serde_json::from_str(&version_info(SystemTime::now())).expect("parse version");
        let capabilities = parsed["capabilities"]
            .as_array()
            .expect("capabilities should be an array");

        for capability in [
            "admin.healthz",
            "admin.metrics.prometheus",
            "routes.list",
            "routes.state",
            "routes.snapshot.apply",
            "metrics.route_status_class",
            "metrics.upstream_health",
            "metrics.upstream_connect_duration",
            "analytics.domain",
            "cache.purge",
        ] {
            assert!(
                capabilities
                    .iter()
                    .any(|value| value.as_str() == Some(capability)),
                "missing capability {capability}"
            );
        }
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
    fn apply_route_snapshot_replaces_only_owned_routes() {
        let table = make_table(vec![
            Route::with_source(
                "old.example.com",
                addr(1000),
                false,
                None,
                Some("ingress".into()),
            ),
            Route::with_source(
                "keep.example.com",
                addr(2000),
                false,
                None,
                Some("other".into()),
            ),
        ]);
        let body = br#"{
            "source":"ingress",
            "routes":[
                {"domain":"new.example.com","upstream":"127.0.0.1:3000","tls":true}
            ]
        }"#;

        let json = apply_route_snapshot(&table, body).expect("apply snapshot");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse response");

        assert_eq!(parsed["source"], "ingress");
        assert_eq!(parsed["applied"], 1);
        assert_eq!(parsed["removed"], 1);
        assert!(table.load().resolve("old.example.com").is_none());
        assert!(table.load().resolve("new.example.com").is_some());
        assert!(table.load().resolve("keep.example.com").is_some());
    }

    #[test]
    fn apply_route_snapshot_preserves_unowned_and_operator_routes() {
        let table = make_table(vec![
            Route::with_source(
                "stale.example.com",
                addr(1000),
                false,
                None,
                Some("permanu-agent".into()),
            ),
            Route::new("legacy.example.com", addr(2000), false, None),
            Route::with_source(
                "operator.example.com",
                addr(3000),
                true,
                None,
                Some("operator".into()),
            ),
        ]);
        let body = br#"{
            "source":"permanu-agent",
            "routes":[
                {"domain":"fresh.example.com","upstream":"127.0.0.1:4000","tls":true}
            ]
        }"#;

        let json = apply_route_snapshot(&table, body).expect("apply snapshot");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse response");

        assert_eq!(parsed["removed"], 1);
        assert!(table.load().resolve("stale.example.com").is_none());
        assert!(table.load().resolve("fresh.example.com").is_some());
        assert!(table.load().resolve("legacy.example.com").is_some());
        assert!(table.load().resolve("operator.example.com").is_some());
    }

    #[test]
    fn apply_route_snapshot_is_idempotent_and_hash_is_order_stable() {
        let table = make_table(vec![]);
        let first = br#"{
            "source":"ingress",
            "routes":[
                {"domain":"b.example.com","upstream":"127.0.0.1:3002","tls":false},
                {"domain":"a.example.com","upstream":"127.0.0.1:3001","tls":true}
            ]
        }"#;
        let second = br#"{
            "source":"ingress",
            "routes":[
                {"domain":"a.example.com","upstream":"127.0.0.1:3001","tls":true},
                {"domain":"b.example.com","upstream":"127.0.0.1:3002","tls":false}
            ]
        }"#;

        let first_json = apply_route_snapshot(&table, first).expect("first apply");
        let second_json = apply_route_snapshot(&table, second).expect("second apply");
        let first_parsed: serde_json::Value =
            serde_json::from_str(&first_json).expect("parse first");
        let second_parsed: serde_json::Value =
            serde_json::from_str(&second_json).expect("parse second");

        assert_eq!(first_parsed["route_hash"], second_parsed["route_hash"]);
        assert_eq!(second_parsed["applied"], 2);
        assert_eq!(second_parsed["removed"], 0);
        assert_eq!(table.load().len(), 2);
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
            query: None,
            status: 200,
            bytes_sent: 1024,
            client_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            country: None,
            referer: None,
            user_agent: None,
            is_bot: false,
            response_latency_us: 0,
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
