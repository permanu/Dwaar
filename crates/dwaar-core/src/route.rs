// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Domain-to-upstream routing table with wildcard support.
//!
//! The [`RouteTable`] is the hottest data structure in Dwaar — every single
//! HTTP request reads it to determine which backend should handle the request.
//! It wraps a [`HashMap`] for O(1) amortized lookups and is designed to be
//! held behind an [`ArcSwap`](arc_swap::ArcSwap) for lock-free concurrent reads.
//!
//! ## Resolution order
//!
//! Exact match first (`"api.example.com"`), then wildcard fallback
//! (strip the first DNS label, try `"*.example.com"`). If neither
//! matches, returns `None` and the caller returns 502 Bad Gateway.
//!
//! ## Example
//!
//! ```
//! use std::net::SocketAddr;
//! use dwaar_core::route::{Route, RouteTable};
//!
//! let routes = vec![
//!     Route::new("api.example.com", "127.0.0.1:3000".parse().unwrap(), false, None),
//!     Route::new("*.example.com",   "127.0.0.1:8080".parse().unwrap(), false, None),
//! ];
//! let table = RouteTable::new(routes);
//!
//! // Exact match wins
//! assert_eq!(
//!     table.resolve("api.example.com").unwrap().upstream.to_string(),
//!     "127.0.0.1:3000"
//! );
//!
//! // Wildcard catches the rest
//! assert_eq!(
//!     table.resolve("web.example.com").unwrap().upstream.to_string(),
//!     "127.0.0.1:8080"
//! );
//!
//! // No match
//! assert!(table.resolve("other.dev").is_none());
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;

use ahash::RandomState;

/// Validate that a string is a legal hostname or wildcard pattern.
/// Rejects path traversal, null bytes, and non-hostname characters.
pub fn is_valid_domain(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    if s.contains('/') || s.contains("..") || s.contains('\0') {
        return false;
    }
    s.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'*')
    })
}

/// A single routing entry: one domain mapped to one upstream backend.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Route {
    /// The domain pattern this route matches.
    ///
    /// - Exact: `"api.example.com"`
    /// - Wildcard: `"*.example.com"` (matches any single subdomain label)
    pub domain: String,

    /// The backend address to forward matching requests to.
    pub upstream: SocketAddr,

    /// Whether this route expects TLS. When true, plaintext HTTP requests
    /// are redirected to HTTPS. When false, HTTP is served directly.
    pub tls: bool,

    /// Per-IP requests-per-second limit for this route. `None` means no limit.
    pub rate_limit_rps: Option<u32>,
}

impl Route {
    /// Create a new route mapping `domain` to `upstream`.
    pub fn new(domain: &str, upstream: SocketAddr, tls: bool, rate_limit_rps: Option<u32>) -> Self {
        Self {
            domain: domain.to_lowercase(),
            upstream,
            tls,
            rate_limit_rps,
        }
    }
}

/// Fast domain→upstream lookup table with wildcard fallback.
///
/// Internally a `HashMap<String, Route>` keyed by the domain pattern.
/// Exact domains and wildcard patterns (`*.example.com`) live in the
/// same map — the resolution logic tries exact first, then wildcard.
///
/// ## Performance
///
/// - Lookup: O(1) amortized (`HashMap`). At most 2 lookups per request
///   (exact miss → wildcard try).
/// - Construction: O(n) where n = number of routes.
/// - Memory: ~100 bytes per route (domain string + `SocketAddr` + `HashMap` overhead).
///
/// ## Thread safety
///
/// `RouteTable` is `Send + Sync` (all fields are owned). Wrap in
/// `Arc<ArcSwap<RouteTable>>` for concurrent access with atomic swap
/// on config reload.
#[derive(Debug, Clone)]
pub struct RouteTable {
    /// Domain pattern → Route mapping.
    ///
    /// Keys are lowercase domain strings. Both exact domains
    /// (`"api.example.com"`) and wildcard patterns (`"*.example.com"`)
    /// are stored as keys in the same map.
    routes: HashMap<String, Route, RandomState>,
}

impl RouteTable {
    /// Build a route table from a list of routes.
    ///
    /// Domains are normalized to lowercase. If duplicate domains exist,
    /// the last one wins (`HashMap` insert semantics).
    pub fn new(routes: Vec<Route>) -> Self {
        let mut map = HashMap::with_capacity_and_hasher(routes.len(), RandomState::default());
        for route in routes {
            if map.contains_key(&route.domain) {
                tracing::warn!(
                    domain = %route.domain,
                    "duplicate route — later definition wins"
                );
            }
            map.insert(route.domain.clone(), route);
        }
        Self { routes: map }
    }

    /// Look up which backend should handle requests for `host`.
    ///
    /// Tries an exact domain match first, then falls back to wildcard
    /// (`*.example.com`). Returns `None` if nothing matches — the caller
    /// should respond with 502 Bad Gateway.
    ///
    /// The `host` value comes from the HTTP `Host` header. The caller
    /// should strip any port suffix before calling this.
    pub fn resolve(&self, host: &str) -> Option<&Route> {
        // Try the input as-is first. Browsers, curl, and HTTP/2 all send
        // lowercase Host headers, so this almost always succeeds without
        // needing any allocation or byte scanning.
        if let Some(route) = self.resolve_normalized(host) {
            return Some(route);
        }

        // Only allocate a lowercase copy if the direct lookup missed AND
        // the host actually has uppercase chars worth normalizing.
        if host.bytes().any(|b| b.is_ascii_uppercase()) {
            let host_lower = host.to_lowercase();
            return self.resolve_normalized(&host_lower);
        }

        None
    }

    /// Inner resolve assuming `host` is already lowercase.
    fn resolve_normalized(&self, host: &str) -> Option<&Route> {
        // Exact match is the common case — one hash lookup
        if let Some(route) = self.routes.get(host) {
            return Some(route);
        }

        // No exact hit — try wildcard. Strip the first DNS label and
        // prepend "*" to get e.g. "*.example.com". Uses a stack buffer
        // to avoid a heap allocation (DNS names cap at 253 chars).
        let dot_pos = host.find('.')?;
        let suffix = &host[dot_pos..];

        let mut buf = [0u8; 254];
        let wildcard_len = 1 + suffix.len();
        if wildcard_len > buf.len() {
            return None;
        }
        buf[0] = b'*';
        buf[1..wildcard_len].copy_from_slice(suffix.as_bytes());

        let wildcard_key = std::str::from_utf8(&buf[..wildcard_len]).ok()?;
        self.routes.get(wildcard_key)
    }

    /// Returns the number of routes in the table.
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Returns `true` if the table has no routes.
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Returns all routes as a Vec, for serialization and admin API mutations.
    pub fn all_routes(&self) -> Vec<Route> {
        self.routes.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    // ── Exact match ──────────────────────────────────────────

    #[test]
    fn exact_match_returns_correct_route() {
        let table = RouteTable::new(vec![
            Route::new("api.example.com", addr(3000), false, None),
            Route::new("web.example.com", addr(8080), false, None),
        ]);

        let route = table.resolve("api.example.com").expect("should match");
        assert_eq!(route.upstream, addr(3000));
    }

    #[test]
    fn exact_match_is_case_insensitive() {
        let table = RouteTable::new(vec![Route::new("API.Example.COM", addr(3000), false, None)]);

        // Host header arrives in mixed case — should still match
        let route = table.resolve("api.example.com").expect("should match");
        assert_eq!(route.upstream, addr(3000));

        let route = table.resolve("Api.Example.Com").expect("should match");
        assert_eq!(route.upstream, addr(3000));
    }

    // ── Wildcard match ───────────────────────────────────────

    #[test]
    fn wildcard_matches_any_subdomain() {
        let table = RouteTable::new(vec![Route::new("*.example.com", addr(9000), false, None)]);

        let route = table.resolve("api.example.com").expect("should match");
        assert_eq!(route.upstream, addr(9000));

        let route = table.resolve("web.example.com").expect("should match");
        assert_eq!(route.upstream, addr(9000));
    }

    #[test]
    fn exact_match_takes_priority_over_wildcard() {
        let table = RouteTable::new(vec![
            Route::new("api.example.com", addr(3000), false, None),
            Route::new("*.example.com", addr(9000), false, None),
        ]);

        // api.example.com → exact match (port 3000), not wildcard
        let route = table.resolve("api.example.com").expect("should match");
        assert_eq!(route.upstream, addr(3000));

        // web.example.com → no exact match, falls to wildcard (port 9000)
        let route = table.resolve("web.example.com").expect("should match");
        assert_eq!(route.upstream, addr(9000));
    }

    // ── No match ─────────────────────────────────────────────

    #[test]
    fn no_match_returns_none() {
        let table = RouteTable::new(vec![Route::new("api.example.com", addr(3000), false, None)]);

        assert!(table.resolve("other.dev").is_none());
    }

    #[test]
    fn empty_table_returns_none() {
        let table = RouteTable::new(vec![]);
        assert!(table.resolve("anything.com").is_none());
    }

    // ── Edge cases ───────────────────────────────────────────

    #[test]
    fn bare_hostname_without_dot_has_no_wildcard() {
        let table = RouteTable::new(vec![Route::new("*.com", addr(9000), false, None)]);

        // "localhost" has no dot — can't strip a label for wildcard
        assert!(table.resolve("localhost").is_none());
    }

    #[test]
    fn wildcard_does_not_match_deeper_subdomains() {
        let table = RouteTable::new(vec![Route::new("*.example.com", addr(9000), false, None)]);

        // *.example.com should match one level deep only
        // "deep.sub.example.com" — first dot gives "*.sub.example.com", not "*.example.com"
        assert!(table.resolve("deep.sub.example.com").is_none());
    }

    // ── Table properties ─────────────────────────────────────

    #[test]
    fn len_and_is_empty() {
        let empty = RouteTable::new(vec![]);
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);

        let table = RouteTable::new(vec![
            Route::new("a.com", addr(1000), false, None),
            Route::new("b.com", addr(2000), false, None),
        ]);
        assert!(!table.is_empty());
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn route_table_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RouteTable>();
    }

    // ── Route TLS field (ISSUE-016) ──────────────────────────

    #[test]
    fn route_tls_flag() {
        let tls_route = Route::new("example.com", addr(3000), true, None);
        assert!(tls_route.tls);

        let plain_route = Route::new("example.com", addr(3000), false, None);
        assert!(!plain_route.tls);
    }

    // ── all_routes / Serialize ────────────────────────────────

    #[test]
    fn all_routes_returns_all_entries() {
        let table = RouteTable::new(vec![
            Route::new("a.com", addr(1000), false, None),
            Route::new("b.com", addr(2000), true, None),
        ]);
        let routes = table.all_routes();
        assert_eq!(routes.len(), 2);
    }

    #[test]
    fn route_serializes_to_json() {
        let route = Route::new("example.com", addr(3000), true, None);
        let json = serde_json::to_string(&route).expect("serialize");
        assert!(json.contains("\"domain\":\"example.com\""));
        assert!(json.contains("\"tls\":true"));
    }

    // ── Rate limit field (ISSUE-031) ─────────────────────────

    #[test]
    fn route_rate_limit_field() {
        let route = Route::new("example.com", addr(3000), false, Some(100));
        assert_eq!(route.rate_limit_rps, Some(100));

        let unlimited = Route::new("example.com", addr(3000), false, None);
        assert_eq!(unlimited.rate_limit_rps, None);
    }

    #[test]
    fn route_rate_limit_serializes() {
        let route = Route::new("example.com", addr(3000), true, Some(500));
        let json = serde_json::to_string(&route).expect("serialize");
        assert!(json.contains("\"rate_limit_rps\":500"));
    }
}
