// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Admin API endpoint handlers.

use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use dwaar_core::route::{Route, RouteTable, is_valid_domain};
use serde::Deserialize;

/// Request body for `POST /routes`.
#[derive(Debug, Deserialize)]
pub struct CreateRouteRequest {
    pub domain: String,
    pub upstream: String,
    pub tls: bool,
}

/// Build the health check response body.
pub fn health(start_time: &Instant) -> String {
    let uptime = start_time.elapsed().as_secs();
    format!(r#"{{"status":"ok","uptime_secs":{uptime}}}"#)
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

    if !is_valid_domain(&req.domain) {
        return Err(format!("invalid domain: {}", req.domain));
    }

    let upstream: std::net::SocketAddr = req
        .upstream
        .parse()
        .map_err(|e| format!("invalid upstream address: {e}"))?;

    let route = Route::new(&req.domain, upstream, req.tls);

    route_table.rcu(|current| {
        let mut routes = current.all_routes();
        routes.retain(|r| r.domain != route.domain);
        routes.push(route.clone());
        Arc::new(RouteTable::new(routes))
    });

    serde_json::to_string(&route).map_err(|e| format!("serialize error: {e}"))
}

/// Delete a route by domain. Returns the deleted domain or None if not found.
pub fn delete_route(route_table: &ArcSwap<RouteTable>, domain: &str) -> Option<String> {
    let domain_lower = domain.to_lowercase();
    let table = route_table.load();

    table.resolve(&domain_lower)?;

    route_table.rcu(|current| {
        let routes: Vec<Route> = current
            .all_routes()
            .into_iter()
            .filter(|r| r.domain != domain_lower)
            .collect();
        Arc::new(RouteTable::new(routes))
    });

    Some(domain_lower)
}

#[cfg(test)]
mod tests {
    use super::*;
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
            Route::new("a.com", addr(1000), false),
            Route::new("b.com", addr(2000), true),
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
        let table = make_table(vec![Route::new("exist.com", addr(1000), false)]);
        let body = br#"{"domain":"exist.com","upstream":"127.0.0.1:2000","tls":true}"#;
        add_route(&table, body).expect("upsert");
        let guard = table.load();
        let route = guard.resolve("exist.com").expect("should exist");
        assert_eq!(route.upstream.port(), 2000);
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
            Route::new("a.com", addr(1000), false),
            Route::new("b.com", addr(2000), false),
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
}
