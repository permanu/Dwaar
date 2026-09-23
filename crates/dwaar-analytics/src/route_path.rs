// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Low-cardinality request path templates (`route_path`).
//!
//! Permanu's `dwaar.*` metrics carry a `route_path` label next to the route
//! host (contracts v1.1.3, D-061; `agent-protocol.md` 9.5). A raw request
//! path is unbounded, so it is reduced to a template and each route keeps at
//! most [`MAX_ROUTE_PATHS_PER_ROUTE`] distinct templates, first come first
//! kept; any further template is reported as [`ROUTE_PATH_OTHER`].
//!
//! Template rules: the query and fragment are dropped; the path is split on
//! `/` (empty segments are skipped) into at most [`MAX_SEGMENTS`] segments,
//! the last of which becomes `*` when the path is deeper; a segment that is
//! all digits, a UUID, 16 or more hex characters, or longer than 32
//! characters becomes `:id`; everything is lowercased.
//! `/api/users/42/orders?x=1` → `/api/users/:id/orders`.

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

use compact_str::CompactString;
use dashmap::DashMap;

/// Template reported once a route already holds its maximum number of
/// distinct templates. Its meaning never changes.
pub const ROUTE_PATH_OTHER: &str = "other";

/// Distinct templates kept per route (the contract's per-service cap).
pub const MAX_ROUTE_PATHS_PER_ROUTE: usize = 200;

/// Maximum number of path segments in a template; deeper paths end in `*`.
pub const MAX_SEGMENTS: usize = 6;

/// Templates kept across all routes. Bounds memory when many routes exist
/// (up to [`crate::MAX_TRACKED_DOMAINS`]); beyond it every new template is
/// [`ROUTE_PATH_OTHER`].
pub const MAX_ROUTE_PATH_TEMPLATES: usize = 100_000;

/// A segment longer than this (in characters) becomes `:id`.
const MAX_LITERAL_SEGMENT_CHARS: usize = 32;

/// A segment of at least this many hex characters becomes `:id`.
const MIN_HEX_ID_CHARS: usize = 16;

/// Template of a request path (see the module docs).
///
/// Pure; the result has at most `MAX_SEGMENTS` segments of at most
/// `MAX_LITERAL_SEGMENT_CHARS` characters each.
#[must_use]
pub fn route_path_template(path: &str) -> CompactString {
    let end = path.find(['?', '#']).unwrap_or(path.len());
    let segments: Vec<&str> = path[..end].split('/').filter(|s| !s.is_empty()).collect();
    if segments.is_empty() {
        return CompactString::const_new("/");
    }
    let deeper = segments.len() > MAX_SEGMENTS;
    let literal = if deeper {
        MAX_SEGMENTS - 1
    } else {
        segments.len()
    };
    let mut out = CompactString::default();
    for segment in &segments[..literal] {
        out.push('/');
        if is_id_segment(segment) {
            out.push_str(":id");
        } else {
            for c in segment.chars() {
                out.extend(c.to_lowercase());
            }
        }
    }
    if deeper {
        out.push_str("/*");
    }
    out
}

fn is_id_segment(segment: &str) -> bool {
    let chars = segment.chars().count();
    chars > MAX_LITERAL_SEGMENT_CHARS
        || segment.bytes().all(|b| b.is_ascii_digit())
        || (chars >= MIN_HEX_ID_CHARS && segment.bytes().all(|b| b.is_ascii_hexdigit()))
        || is_uuid(segment)
}

fn is_uuid(segment: &str) -> bool {
    let b = segment.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// Per-route registry of the templates seen so far.
///
/// Bounds the `route_path` label: at most [`MAX_ROUTE_PATHS_PER_ROUTE`]
/// templates per route, at most `max_routes` routes and at most `max_total`
/// templates overall; anything beyond is [`ROUTE_PATH_OTHER`]. Kept
/// templates live for the process lifetime. Lookups of known templates take
/// only a shard read lock.
#[derive(Debug)]
pub struct RoutePathRegistry {
    routes: DashMap<CompactString, HashSet<CompactString>>,
    total: AtomicUsize,
    max_routes: usize,
    max_total: usize,
}

impl Default for RoutePathRegistry {
    fn default() -> Self {
        Self::new(crate::MAX_TRACKED_DOMAINS)
    }
}

impl RoutePathRegistry {
    /// A registry tracking at most `max_routes` routes and
    /// [`MAX_ROUTE_PATH_TEMPLATES`] templates.
    #[must_use]
    pub fn new(max_routes: usize) -> Self {
        Self::with_limits(max_routes, MAX_ROUTE_PATH_TEMPLATES)
    }

    /// A registry tracking at most `max_routes` routes and `max_total`
    /// templates across them.
    #[must_use]
    pub fn with_limits(max_routes: usize, max_total: usize) -> Self {
        Self {
            routes: DashMap::new(),
            total: AtomicUsize::new(0),
            max_routes,
            max_total,
        }
    }

    /// The `route_path` label for a request on `route` with `path`: its
    /// template when that is already kept or there is still room, else
    /// [`ROUTE_PATH_OTHER`].
    pub fn resolve(&self, route: &str, path: &str) -> CompactString {
        let template = route_path_template(path);
        if let Some(kept) = self.routes.get(route)
            && kept.contains(&template)
        {
            return template;
        }
        if !self.routes.contains_key(route) && self.routes.len() >= self.max_routes {
            return CompactString::const_new(ROUTE_PATH_OTHER);
        }
        // The shard write lock makes the length check and the insert atomic.
        let mut kept = self.routes.entry(CompactString::from(route)).or_default();
        if kept.contains(&template) {
            return template;
        }
        if kept.len() >= MAX_ROUTE_PATHS_PER_ROUTE || !self.reserve_template() {
            return CompactString::const_new(ROUTE_PATH_OTHER);
        }
        kept.insert(template.clone());
        template
    }

    /// Take one slot of the overall template budget.
    fn reserve_template(&self) -> bool {
        self.total
            .fetch_update(Relaxed, Relaxed, |n| (n < self.max_total).then_some(n + 1))
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_example_templates_the_numeric_id() {
        assert_eq!(
            route_path_template("/api/users/42/orders"),
            "/api/users/:id/orders"
        );
    }

    #[test]
    fn query_and_fragment_are_dropped() {
        assert_eq!(route_path_template("/search?q=secret&x=1"), "/search");
        assert_eq!(route_path_template("/docs/intro#part-2"), "/docs/intro");
        assert_eq!(route_path_template("/a?b#c"), "/a");
    }

    #[test]
    fn root_and_empty_paths_are_slash() {
        assert_eq!(route_path_template("/"), "/");
        assert_eq!(route_path_template(""), "/");
        assert_eq!(route_path_template("/?x=1"), "/");
    }

    #[test]
    fn empty_segments_are_skipped() {
        assert_eq!(route_path_template("/api//users/"), "/api/users");
    }

    #[test]
    fn everything_is_lowercased() {
        assert_eq!(route_path_template("/API/Users"), "/api/users");
    }

    #[test]
    fn uuid_segments_become_id() {
        assert_eq!(
            route_path_template("/orders/3F2504E0-4F89-11D3-9A0C-0305E82C3301/items"),
            "/orders/:id/items"
        );
    }

    #[test]
    fn long_hex_segments_become_id() {
        // 16 hex characters: an id.
        assert_eq!(route_path_template("/c/0123456789abcdef"), "/c/:id");
        // 40-character git SHA.
        assert_eq!(
            route_path_template("/commit/da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            "/commit/:id"
        );
        // 15 hex characters stay literal.
        assert_eq!(
            route_path_template("/c/0123456789abcde"),
            "/c/0123456789abcde"
        );
        // Hex-looking but not all hex stays literal.
        assert_eq!(
            route_path_template("/c/0123456789abcdeg"),
            "/c/0123456789abcdeg"
        );
    }

    #[test]
    fn segments_longer_than_32_chars_become_id() {
        let long = "a-very-long-slug-that-goes-on-and-on"; // 36 chars
        assert!(long.len() > 32);
        assert_eq!(route_path_template(&format!("/blog/{long}")), "/blog/:id");
        let exact = "abcdefghijklmnopqrstuvwxyzabcdeg"; // 32 chars
        assert_eq!(exact.len(), 32);
        assert_eq!(
            route_path_template(&format!("/blog/{exact}")),
            format!("/blog/{exact}")
        );
    }

    #[test]
    fn long_multibyte_segments_count_characters() {
        // 20 characters, 40 bytes: stays literal.
        let s = "é".repeat(20);
        assert_eq!(route_path_template(&format!("/{s}")), format!("/{s}"));
    }

    #[test]
    fn numeric_segments_become_id() {
        assert_eq!(route_path_template("/v1/7/9"), "/v1/:id/:id");
    }

    #[test]
    fn at_most_six_segments_deeper_ones_become_one_star() {
        assert_eq!(route_path_template("/a/b/c/d/e/f"), "/a/b/c/d/e/f");
        assert_eq!(route_path_template("/a/b/c/d/e/f/g"), "/a/b/c/d/e/*");
        assert_eq!(route_path_template("/a/b/c/d/e/f/g/h/i/j"), "/a/b/c/d/e/*");
    }

    #[test]
    fn template_length_is_bounded() {
        let seg = "x".repeat(32);
        let path = format!("/{seg}").repeat(50);
        let t = route_path_template(&path);
        assert_eq!(t.split('/').count(), MAX_SEGMENTS + 1);
        assert!(t.len() <= MAX_SEGMENTS * (MAX_LITERAL_SEGMENT_CHARS + 1));
    }

    #[test]
    fn registry_keeps_first_200_templates_per_route_then_other() {
        let reg = RoutePathRegistry::default();
        for i in 0..MAX_ROUTE_PATHS_PER_ROUTE {
            assert_eq!(
                reg.resolve("app.example.com", &format!("/p{i}")),
                format!("/p{i}")
            );
        }
        assert_eq!(reg.resolve("app.example.com", "/p-new"), ROUTE_PATH_OTHER);
        // Known templates keep resolving to themselves (first come first kept).
        assert_eq!(reg.resolve("app.example.com", "/p0?x=1"), "/p0");
        assert_eq!(reg.resolve("app.example.com", "/p199"), "/p199");
        // Another route has its own budget.
        assert_eq!(reg.resolve("api.example.com", "/p-new"), "/p-new");
    }

    #[test]
    fn templated_ids_share_one_slot() {
        let reg = RoutePathRegistry::default();
        for i in 0..1_000 {
            assert_eq!(
                reg.resolve("app.example.com", &format!("/users/{i}")),
                "/users/:id"
            );
        }
        assert_eq!(reg.resolve("app.example.com", "/other-page"), "/other-page");
    }

    #[test]
    fn routes_beyond_the_route_cap_report_other() {
        let reg = RoutePathRegistry::new(2);
        assert_eq!(reg.resolve("a.example.com", "/x"), "/x");
        assert_eq!(reg.resolve("b.example.com", "/x"), "/x");
        assert_eq!(reg.resolve("c.example.com", "/x"), ROUTE_PATH_OTHER);
        assert_eq!(reg.resolve("a.example.com", "/y"), "/y");
    }

    #[test]
    fn templates_beyond_the_total_cap_report_other() {
        let reg = RoutePathRegistry::with_limits(10, 3);
        assert_eq!(reg.resolve("a.example.com", "/x"), "/x");
        assert_eq!(reg.resolve("a.example.com", "/y"), "/y");
        assert_eq!(reg.resolve("b.example.com", "/x"), "/x");
        assert_eq!(reg.resolve("b.example.com", "/y"), ROUTE_PATH_OTHER);
        assert_eq!(reg.resolve("a.example.com", "/z"), ROUTE_PATH_OTHER);
        assert_eq!(reg.resolve("a.example.com", "/x"), "/x");
    }

    #[test]
    fn concurrent_resolves_never_exceed_the_cap() {
        let reg = std::sync::Arc::new(RoutePathRegistry::default());
        let handles: Vec<_> = (0..8)
            .map(|t| {
                let reg = reg.clone();
                std::thread::spawn(move || {
                    for i in 0..100 {
                        let _ = reg.resolve("app.example.com", &format!("/t{t}/p{i}"));
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("thread");
        }
        let kept = reg
            .routes
            .get("app.example.com")
            .map(|s| s.len())
            .expect("route tracked");
        assert_eq!(kept, MAX_ROUTE_PATHS_PER_ROUTE);
    }
}
