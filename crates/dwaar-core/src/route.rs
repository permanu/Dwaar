// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Domain-to-upstream routing table with path-based handler dispatch.
//!
//! The [`RouteTable`] is the hottest data structure in Dwaar — every single
//! HTTP request reads it to determine which backend should handle the request.
//! It wraps a [`HashMap`] for O(1) amortized domain lookups and is designed to
//! be held behind an [`ArcSwap`](arc_swap::ArcSwap) for lock-free concurrent reads.
//!
//! ## Resolution order
//!
//! 1. **Domain resolution** (O(1)): Exact match first (`"api.example.com"`),
//!    then wildcard fallback (strip the first DNS label, try `"*.example.com"`).
//!    If neither matches, returns `None` and the caller returns 502 Bad Gateway.
//!
//! 2. **Path resolution** (O(n), n = handler blocks per domain): Iterate
//!    handler blocks in config order. For `handle`/`handle_path`, first match
//!    wins. For `route`, all matching blocks execute.
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
//!     table.resolve("api.example.com").unwrap().upstream().expect("has upstream").to_string(),
//!     "127.0.0.1:3000"
//! );
//!
//! // Wildcard catches the rest
//! assert_eq!(
//!     table.resolve("web.example.com").unwrap().upstream().expect("has upstream").to_string(),
//!     "127.0.0.1:8080"
//! );
//!
//! // No match
//! assert!(table.resolve("other.dev").is_none());
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;

use ahash::RandomState;
use compact_str::CompactString;

use crate::template::{CompiledTemplate, TemplateContext, VarSlots};
use regex::Regex;

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

// ── Handler types ────────────────────────────────────────────

/// What produces the response — the terminal action for a matched request.
///
/// Each handler block resolves to exactly one `Handler`. The proxy dispatches
/// based on this: `ReverseProxy` continues to `upstream_peer()`, while future
/// variants like `StaticResponse` and `FileServer` short-circuit in
/// `request_filter()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Handler {
    /// Forward the request to an upstream backend.
    ReverseProxy { upstream: SocketAddr },
    /// Return a fixed response — no upstream contacted. Used by `respond` directive.
    StaticResponse { status: u16, body: bytes::Bytes },
    /// Serve static files from disk. Used by `file_server` directive.
    FileServer {
        root: std::path::PathBuf,
        browse: bool,
    },
    /// Proxy to a `FastCGI` backend (`php-fpm`). Used by `php_fastcgi` directive.
    FastCgi {
        upstream: SocketAddr,
        root: std::path::PathBuf,
    },
}

/// How a handler block was declared, controlling execution semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockKind {
    /// First match wins; path NOT stripped. (Caddy `handle`)
    Handle,
    /// First match wins; matched prefix IS stripped. (Caddy `handle_path`)
    HandlePath,
    /// All matching blocks execute in declaration order. (Caddy `route`)
    Route,
}

/// Compiled path matcher — zero allocation at match time.
///
/// Patterns are compiled from Dwaarfile config at load time.
/// Runtime matching uses only stack operations (`starts_with`, `==`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathMatcher {
    /// Matches any path. Used for catch-all blocks and simple (flat) sites.
    Any,
    /// Exact path match: `/health` matches only `/health`.
    Exact(CompactString),
    /// Prefix match: `/api/` matches `/api/foo`, `/api/bar/baz`.
    /// Stored without the trailing `*` from config syntax.
    Prefix(CompactString),
    /// Suffix match: `*.php` matches `/index.php`, `/admin/login.php`.
    Suffix(CompactString),
}

impl PathMatcher {
    /// Test whether the request path matches this matcher.
    ///
    /// Returns `Some(prefix_len)` on match — the number of bytes of the
    /// path that the matcher consumed. Used by `handle_path` to strip
    /// the prefix. Returns `None` on no match.
    #[inline]
    pub fn matches(&self, path: &str) -> Option<usize> {
        match self {
            PathMatcher::Any => Some(0),
            PathMatcher::Exact(p) => {
                if path == p.as_str() {
                    Some(p.len())
                } else {
                    None
                }
            }
            PathMatcher::Prefix(prefix) => {
                if path.starts_with(prefix.as_str()) {
                    Some(prefix.len())
                } else {
                    None
                }
            }
            PathMatcher::Suffix(suffix) => {
                if path.ends_with(suffix.as_str()) {
                    Some(0)
                } else {
                    None
                }
            }
        }
    }
}

/// One handler block inside a site: a path matcher + middleware + terminal handler.
///
/// Conceptually maps to `handle /api/* { basicauth ...; reverse_proxy ... }`.
/// For flat sites (no explicit handle blocks), there's a single `HandlerBlock`
/// with `PathMatcher::Any` and `BlockKind::Handle`.
/// A URI rewrite rule — compiled from `rewrite` or `uri` directives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RewriteRule {
    /// `rewrite /new-path` — replace the entire URI.
    /// Can contain placeholders like `{path}`, `{uri}`, `{host}` that are
    /// resolved at request time from [`TemplateContext`].
    Replace(CompiledTemplate),
    /// `uri strip_prefix /api` — remove prefix from path.
    StripPrefix(CompactString),
    /// `uri strip_suffix .html` — remove suffix from path.
    StripSuffix(CompactString),
    /// `uri replace /old /new` — substring replacement.
    SubstringReplace {
        find: CompactString,
        replace: CompactString,
    },
}

impl RewriteRule {
    /// Apply this rule to a path, returning the transformed path.
    /// Returns `None` if the rule doesn't match (prefix/suffix not present).
    ///
    /// `ctx` provides request-scoped values for template evaluation.
    /// Pass `None` for rules that don't use templates.
    #[inline]
    pub fn apply(&self, path: &str, ctx: Option<&TemplateContext<'_>>) -> Option<CompactString> {
        match self {
            RewriteRule::Replace(tmpl) => {
                let result = match ctx {
                    Some(c) => tmpl.evaluate_sanitized(c),
                    None => tmpl.evaluate_literals(),
                };
                Some(CompactString::from(result))
            }
            RewriteRule::StripPrefix(prefix) => path.strip_prefix(prefix.as_str()).map(|rest| {
                if rest.is_empty() {
                    CompactString::from("/")
                } else {
                    CompactString::from(rest)
                }
            }),
            RewriteRule::StripSuffix(suffix) => path.strip_suffix(suffix.as_str()).map(|rest| {
                if rest.is_empty() {
                    CompactString::from("/")
                } else {
                    CompactString::from(rest)
                }
            }),
            RewriteRule::SubstringReplace { find, replace } => {
                if path.contains(find.as_str()) {
                    Some(CompactString::from(
                        path.replace(find.as_str(), replace.as_str()),
                    ))
                } else {
                    None
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct HandlerBlock {
    pub kind: BlockKind,
    pub matcher: PathMatcher,
    /// Per-IP rate limit for this block. `None` inherits from site-level.
    pub rate_limit_rps: Option<u32>,
    /// Under Attack Mode for this block.
    pub under_attack: bool,
    /// URI rewrite rules — applied in order before the handler.
    pub rewrites: Vec<RewriteRule>,
    /// HTTP Basic Auth config — pre-compiled credential table.
    pub basic_auth: Option<std::sync::Arc<dwaar_plugins::basic_auth::BasicAuthConfig>>,
    /// Forward auth config — subrequest to external auth service.
    pub forward_auth: Option<std::sync::Arc<dwaar_plugins::forward_auth::ForwardAuthConfig>>,
    /// Compiled `map` directives — evaluated per-request to populate `VarSlots`.
    pub maps: Vec<CompiledMap>,
    /// Compiled `log_append` fields — evaluated per-request for dynamic log entries.
    pub log_append_fields: Vec<(String, CompiledTemplate)>,
    /// Named logger from `log_name` directive.
    pub log_name: Option<String>,
    pub handler: Handler,
}

// ── Compiled Map (ISSUE-056) ──────────────────────────────────────

/// A compiled `map {source} {dest_var} { ... }` directive.
///
/// At request time, evaluates the source template, matches against entries
/// (first match wins), and writes the result to the destination `VarSlot`.
#[derive(Debug, Clone)]
pub struct CompiledMap {
    /// Template that produces the value to match against.
    pub source: CompiledTemplate,
    /// Slot index in `VarSlots` to write the matched value.
    pub dest_slot: u16,
    /// Ordered entries — first match wins. The last entry is often `default`.
    pub entries: Vec<CompiledMapEntry>,
}

impl CompiledMap {
    /// Evaluate this map against the request context.
    ///
    /// Returns the matched value (or the default), or `None` if nothing matches
    /// and there's no default.
    pub fn evaluate(&self, ctx: &TemplateContext<'_>) -> Option<String> {
        let source_val = self.source.evaluate(ctx);
        for entry in &self.entries {
            if entry.matches(&source_val) {
                return Some(entry.value.evaluate(ctx));
            }
        }
        None
    }
}

/// One pattern → value entry inside a [`CompiledMap`].
#[derive(Debug, Clone)]
pub struct CompiledMapEntry {
    /// How to match the evaluated source value.
    pub pattern: CompiledMapPattern,
    /// Template to produce the output value when matched.
    pub value: CompiledTemplate,
    /// Whether this is the `default` fallback entry.
    pub is_default: bool,
}

impl CompiledMapEntry {
    fn matches(&self, input: &str) -> bool {
        match &self.pattern {
            CompiledMapPattern::Exact(e) => e.eq_ignore_ascii_case(input),
            CompiledMapPattern::Regex(re) => re.is_match(input),
            CompiledMapPattern::Default => true,
        }
    }
}

/// How a map entry matches the evaluated source value.
#[derive(Debug, Clone)]
pub enum CompiledMapPattern {
    /// Case-insensitive exact string match.
    Exact(String),
    /// Pre-compiled regular expression.
    Regex(Regex),
    /// Always matches — the `default` fallback.
    Default,
}

// ── Route ────────────────────────────────────────────────────

/// A site: one domain with its handler blocks.
///
/// Replaces the old flat `{ domain, upstream, tls }` model. A domain can
/// now have multiple handler blocks for path-based routing. For backward
/// compatibility, `Route::new()` creates a single catch-all handler block.
///
/// ## Hot-path optimization
///
/// The common case (flat Dwaarfile, single upstream) is optimized: `default_upstream`,
/// `default_rate_limit_rps`, and `default_under_attack` are cached inline to avoid
/// a Vec pointer chase on every request. These are populated at construction time
/// from the first handler block.
#[derive(Debug, Clone)]
pub struct Route {
    /// The domain pattern this route matches.
    pub domain: String,

    /// Whether this route expects TLS.
    pub tls: bool,

    /// Inline cache of the first handler's upstream — avoids a Vec deref on
    /// every request for the common single-handler case. `None` for
    /// file_server-only or respond-only sites.
    default_upstream: Option<SocketAddr>,

    /// Inline cache of the first handler's rate limit.
    default_rate_limit_rps: Option<u32>,

    /// Inline cache of the first handler's `under_attack` flag.
    default_under_attack: bool,

    /// Handler blocks, checked in config-file order. For `handle`/`handle_path`,
    /// first match wins. For `route`, all matching blocks execute.
    ///
    /// Flat sites (no explicit handle blocks) have exactly one entry with
    /// `PathMatcher::Any`.
    pub handlers: Vec<HandlerBlock>,

    /// Default values for user-declared variables (from `vars` directives).
    /// At request time, clone this and populate dynamic vars (from `map`).
    /// Empty when no `vars` or `map` directives are present.
    pub var_defaults: VarSlots,
}

impl Route {
    /// Create a simple single-upstream route (backward-compatible constructor).
    ///
    /// Wraps the upstream in a single `HandlerBlock { Any, ReverseProxy }`.
    /// This is the common case for flat Dwaarfiles with no `handle` blocks.
    pub fn new(domain: &str, upstream: SocketAddr, tls: bool, rate_limit_rps: Option<u32>) -> Self {
        Self {
            domain: domain.to_lowercase(),
            tls,
            default_upstream: Some(upstream),
            default_rate_limit_rps: rate_limit_rps,
            default_under_attack: false,
            handlers: vec![HandlerBlock {
                kind: BlockKind::Handle,
                matcher: PathMatcher::Any,
                rate_limit_rps,
                under_attack: false,
                rewrites: vec![],
                basic_auth: None,
                forward_auth: None,
                maps: vec![],
                log_append_fields: vec![],
                log_name: None,
                handler: Handler::ReverseProxy { upstream },
            }],
            var_defaults: VarSlots::default(),
        }
    }

    /// Build a route from pre-compiled handler blocks (for multi-handler sites).
    ///
    /// Scans handlers for the first `ReverseProxy` to populate `default_upstream`.
    /// Rate limit and under-attack are taken from the first handler block (site-level).
    pub fn with_handlers(
        domain: &str,
        tls: bool,
        handlers: Vec<HandlerBlock>,
        var_defaults: VarSlots,
    ) -> Self {
        let default_upstream = handlers.iter().find_map(|b| match &b.handler {
            Handler::ReverseProxy { upstream } | Handler::FastCgi { upstream, .. } => {
                Some(*upstream)
            }
            Handler::StaticResponse { .. } | Handler::FileServer { .. } => None,
        });
        let first = handlers.first();
        let default_rate_limit_rps = first.and_then(|b| b.rate_limit_rps);
        let default_under_attack = first.is_some_and(|b| b.under_attack);

        Self {
            domain: domain.to_lowercase(),
            tls,
            default_upstream,
            default_rate_limit_rps,
            default_under_attack,
            handlers,
            var_defaults,
        }
    }

    /// The default upstream address — zero-cost inline read for flat routes.
    ///
    /// Returns `None` for sites with no `ReverseProxy` handler (file_server-only).
    #[inline]
    pub fn upstream(&self) -> Option<SocketAddr> {
        self.default_upstream
    }

    /// Site-level rate limit — zero-cost inline read.
    #[inline]
    pub fn rate_limit_rps(&self) -> Option<u32> {
        self.default_rate_limit_rps
    }

    /// Whether Under Attack Mode is enabled — zero-cost inline read.
    #[inline]
    pub fn under_attack(&self) -> bool {
        self.default_under_attack
    }
}

/// Custom serialization to keep admin API JSON output stable.
/// Flattens the handler structure for simple (single-handler) routes.
impl serde::Serialize for Route {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("Route", 5)?;
        s.serialize_field("domain", &self.domain)?;
        s.serialize_field("upstream", &self.upstream().map(|a| a.to_string()))?;
        s.serialize_field("tls", &self.tls)?;
        s.serialize_field("rate_limit_rps", &self.rate_limit_rps())?;
        s.serialize_field("under_attack", &self.under_attack())?;
        s.end()
    }
}

// ── RouteTable ───────────────────────────────────────────────

/// Fast domain→route lookup table with wildcard fallback.
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
        assert_eq!(route.upstream().expect("has upstream"), addr(3000));
    }

    #[test]
    fn exact_match_is_case_insensitive() {
        let table = RouteTable::new(vec![Route::new("API.Example.COM", addr(3000), false, None)]);

        // Host header arrives in mixed case — should still match
        let route = table.resolve("api.example.com").expect("should match");
        assert_eq!(route.upstream().expect("has upstream"), addr(3000));

        let route = table.resolve("Api.Example.Com").expect("should match");
        assert_eq!(route.upstream().expect("has upstream"), addr(3000));
    }

    // ── Wildcard match ───────────────────────────────────────

    #[test]
    fn wildcard_matches_any_subdomain() {
        let table = RouteTable::new(vec![Route::new("*.example.com", addr(9000), false, None)]);

        let route = table.resolve("api.example.com").expect("should match");
        assert_eq!(route.upstream().expect("has upstream"), addr(9000));

        let route = table.resolve("web.example.com").expect("should match");
        assert_eq!(route.upstream().expect("has upstream"), addr(9000));
    }

    #[test]
    fn exact_match_takes_priority_over_wildcard() {
        let table = RouteTable::new(vec![
            Route::new("api.example.com", addr(3000), false, None),
            Route::new("*.example.com", addr(9000), false, None),
        ]);

        // api.example.com → exact match (port 3000), not wildcard
        let route = table.resolve("api.example.com").expect("should match");
        assert_eq!(route.upstream().expect("has upstream"), addr(3000));

        // web.example.com → no exact match, falls to wildcard (port 9000)
        let route = table.resolve("web.example.com").expect("should match");
        assert_eq!(route.upstream().expect("has upstream"), addr(9000));
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
        assert_eq!(route.rate_limit_rps(), Some(100));

        let unlimited = Route::new("example.com", addr(3000), false, None);
        assert_eq!(unlimited.rate_limit_rps(), None);
    }

    #[test]
    fn route_rate_limit_serializes() {
        let route = Route::new("example.com", addr(3000), true, Some(500));
        let json = serde_json::to_string(&route).expect("serialize");
        assert!(json.contains("\"rate_limit_rps\":500"));
    }

    // ── Under Attack Mode field ──────────────────────────────

    #[test]
    fn under_attack_default_false() {
        let route = Route::new("example.com", addr(3000), false, None);
        assert!(!route.under_attack());
    }

    // ── Handler block accessors ──────────────────────────────

    #[test]
    fn upstream_returns_reverse_proxy_addr() {
        let route = Route::new("example.com", addr(3000), false, None);
        assert_eq!(route.upstream().expect("has upstream"), addr(3000));
    }

    // ── PathMatcher ──────────────────────────────────────────

    #[test]
    fn path_matcher_any_matches_everything() {
        let m = PathMatcher::Any;
        assert!(m.matches("/").is_some());
        assert!(m.matches("/api/foo").is_some());
        assert!(m.matches("").is_some());
    }

    #[test]
    fn path_matcher_exact() {
        let m = PathMatcher::Exact(CompactString::from("/health"));
        assert!(m.matches("/health").is_some());
        assert!(m.matches("/health/").is_none());
        assert!(m.matches("/other").is_none());
    }

    #[test]
    fn path_matcher_prefix() {
        let m = PathMatcher::Prefix(CompactString::from("/api/"));
        assert!(m.matches("/api/foo").is_some());
        assert!(m.matches("/api/bar/baz").is_some());
        assert!(m.matches("/api/").is_some());
        assert!(m.matches("/other").is_none());
        assert!(m.matches("/apifoo").is_none());
    }

    #[test]
    fn path_matcher_prefix_returns_matched_length() {
        let m = PathMatcher::Prefix(CompactString::from("/api/"));
        assert_eq!(m.matches("/api/foo"), Some(5)); // "/api/" is 5 bytes
    }

    #[test]
    fn path_matcher_suffix() {
        let m = PathMatcher::Suffix(CompactString::from(".php"));
        assert!(m.matches("/index.php").is_some());
        assert!(m.matches("/admin/login.php").is_some());
        assert!(m.matches("/style.css").is_none());
    }

    // ── RewriteRule ──────────────────────────────────────

    #[test]
    fn rewrite_replace() {
        let tmpl = CompiledTemplate::compile("/new").expect("compile");
        let r = RewriteRule::Replace(tmpl);
        assert_eq!(
            r.apply("/anything", None).expect("matches"),
            CompactString::from("/new")
        );
    }

    #[test]
    fn rewrite_replace_with_placeholder() {
        let tmpl = CompiledTemplate::compile("/api{path}").expect("compile");
        let r = RewriteRule::Replace(tmpl);
        let ctx = TemplateContext {
            host: "example.com",
            method: "GET",
            path: "/v2/users",
            uri: "/v2/users",
            query: "",
            scheme: "https",
            remote_host: "10.0.0.1",
            remote_port: 0,
            request_id: "test-id",
            upstream_host: "",
            upstream_port: 0,
            tls_server_name: "",
            vars: None,
        };
        assert_eq!(
            r.apply("/anything", Some(&ctx)).expect("matches"),
            CompactString::from("/api/v2/users")
        );
    }

    #[test]
    fn rewrite_strip_prefix_matches() {
        let r = RewriteRule::StripPrefix(CompactString::from("/api"));
        assert_eq!(
            r.apply("/api/users", None).expect("matches"),
            CompactString::from("/users")
        );
    }

    #[test]
    fn rewrite_strip_prefix_no_match() {
        let r = RewriteRule::StripPrefix(CompactString::from("/api"));
        assert!(r.apply("/other/path", None).is_none());
    }

    #[test]
    fn rewrite_strip_prefix_exact_gives_root() {
        let r = RewriteRule::StripPrefix(CompactString::from("/api"));
        assert_eq!(
            r.apply("/api", None).expect("matches"),
            CompactString::from("/")
        );
    }

    #[test]
    fn rewrite_strip_suffix() {
        let r = RewriteRule::StripSuffix(CompactString::from(".html"));
        assert_eq!(
            r.apply("/page.html", None).expect("matches"),
            CompactString::from("/page")
        );
    }

    #[test]
    fn rewrite_strip_suffix_no_match() {
        let r = RewriteRule::StripSuffix(CompactString::from(".html"));
        assert!(r.apply("/page.css", None).is_none());
    }

    #[test]
    fn rewrite_substring_replace() {
        let r = RewriteRule::SubstringReplace {
            find: CompactString::from("/v1"),
            replace: CompactString::from("/v2"),
        };
        assert_eq!(
            r.apply("/api/v1/users", None).expect("matches"),
            CompactString::from("/api/v2/users")
        );
    }

    #[test]
    fn rewrite_substring_replace_no_match() {
        let r = RewriteRule::SubstringReplace {
            find: CompactString::from("/v1"),
            replace: CompactString::from("/v2"),
        };
        assert!(r.apply("/api/v3/users", None).is_none());
    }
}
