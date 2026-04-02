// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Per-request context that travels through Pingora's proxy lifecycle.
//!
//! Every HTTP request that Pingora processes gets its own `RequestContext`,
//! created fresh in [`DwaarProxy::new_ctx()`]. Each lifecycle hook
//! (`request_filter`, `upstream_peer`, `response_filter`, `logging`, etc.)
//! receives a `&mut RequestContext` so it can read and write per-request state.
//!
//! ## Why a context struct?
//!
//! Pingora's lifecycle hooks are separate async functions — they can't share
//! local variables. The context is the bridge: `request_filter` populates it,
//! `upstream_peer` reads it, `logging` summarizes it.
//!
//! ## Lifecycle
//!
//! ```text
//! new_ctx()           → start_time + request_id set (Instant::now, UUID v7)
//! request_filter()    → client_ip, host, method, path extracted from Session
//!                       plugin chain runs (bot detect, rate limit, under attack)
//! upstream_peer()     → reads host for routing (ISSUE-010)
//! response_filter()   → plugin chain runs (security headers, compression setup)
//!                       analytics injection setup
//! response_body_filter() → plugin chain runs (compression)
//!                          decompression + analytics injection (core)
//! logging()           → reads start_time to compute duration (ISSUE-019)
//! [drop]              → context freed, request complete
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use compact_str::CompactString;
use dwaar_analytics::decompress::Decompressor;
use dwaar_analytics::injector::HtmlInjector;
use dwaar_plugins::plugin::PluginCtx;
use uuid::Uuid;

use crate::route::{CompiledCopyResponseHeaders, CompiledIntercept};
use crate::template::VarSlots;
use crate::upstream::UpstreamPool;

/// Per-request state shared across all Pingora lifecycle hooks.
///
/// Created once per request by [`DwaarProxy::new_ctx()`], dropped when the
/// request completes.
///
/// # Layout
///
/// Plugin-related state lives in [`PluginCtx`] (identity, bot classification,
/// compressor). Core proxy state (timing, analytics, routing) lives here directly.
///
/// # Allocation budget
///
/// This struct is allocated per-request. Every heap allocation here runs on the
/// hot path. Fields use stack-friendly types where possible:
/// - `request_id`: inline `[u8; 36]` instead of `String` (avoids 1 heap alloc)
/// - `plugin_ctx` fields are populated from request headers (unavoidable allocs)
#[derive(Debug)]
pub struct RequestContext {
    /// When this request started processing. Uses `Instant` (monotonic clock)
    /// because we need elapsed time, not wall-clock time.
    pub start_time: Instant,

    /// UUID v7 request ID stored inline (36 ASCII bytes, no heap allocation).
    request_id_buf: [u8; 36],

    /// Plugin context — carries per-request state that plugins read and write.
    pub plugin_ctx: PluginCtx,

    /// The upstream address selected by route resolution in `request_filter()`.
    pub route_upstream: Option<SocketAddr>,

    /// Whether the matched route requires TLS. Cached here to avoid a second
    /// `ArcSwap` load in `https_redirect_domain()`.
    pub route_tls: bool,

    /// The canonical domain from the matched route. Cached for the HTTPS redirect
    /// Location header without needing a second route table lookup.
    pub route_canonical_domain: Option<String>,

    /// Static response cached from route lookup — for `respond` directive.
    /// Avoids a second `ArcSwap` load (Guardrail #27).
    pub static_response: Option<(u16, bytes::Bytes)>,

    /// Rewritten request path — set by `rewrite`/`uri` directives. If `Some`,
    /// `upstream_request_filter()` uses this instead of the original URI.
    /// The original path stays in `plugin_ctx.path` for logging.
    pub effective_path: Option<CompactString>,

    /// Basic auth config cached from route lookup (Guardrail #27 — no second load).
    pub basic_auth: Option<std::sync::Arc<dwaar_plugins::basic_auth::BasicAuthConfig>>,

    /// Forward auth config cached from route lookup (Guardrail #27).
    pub forward_auth: Option<std::sync::Arc<dwaar_plugins::forward_auth::ForwardAuthConfig>>,

    /// File server config cached from route lookup (Guardrail #27).
    pub file_server: Option<(std::path::PathBuf, bool)>,

    /// `FastCGI` document root cached from route lookup (Guardrail #27).
    pub fastcgi_root: Option<std::path::PathBuf>,

    /// Headers copied from `forward_auth` response to forward to upstream.
    pub forward_auth_headers: Vec<(CompactString, CompactString)>,

    /// HTML script injector for analytics (core, not a plugin).
    pub injector: Option<HtmlInjector>,

    /// Streaming decompressor for compressed HTML responses (core, not a plugin).
    pub decompressor: Option<Decompressor>,

    /// Per-request variable slots (cloned from `route.var_defaults`, populated by map evaluation).
    pub var_slots: Option<VarSlots>,

    /// Intercept rules cached from route lookup (ISSUE-067).
    /// Applied in `response_filter()` to match upstream status and override the response.
    pub intercepts: Vec<CompiledIntercept>,

    /// Body bytes to substitute for the upstream body (set when an intercept fires).
    /// Consumed in the first `response_body_filter()` call, then cleared.
    pub intercept_body: Option<bytes::Bytes>,

    /// Copy response headers config cached from route lookup (ISSUE-067).
    pub copy_response_headers: Option<CompiledCopyResponseHeaders>,

    /// Load-balancing pool for multi-upstream routes (Guardrail #27 — no second `ArcSwap` load).
    ///
    /// `None` for single-upstream routes — they use `route_upstream` directly,
    /// avoiding all pool overhead on the common case.
    pub upstream_pool: Option<Arc<UpstreamPool>>,
}

impl RequestContext {
    /// Create a new context with timing and identity set.
    pub fn new() -> Self {
        // Generate UUID v7 directly into a stack buffer — zero heap allocation.
        let uuid = Uuid::now_v7();
        let mut buf = [0u8; 36];
        uuid.as_hyphenated().encode_lower(&mut buf);

        Self {
            start_time: Instant::now(),
            request_id_buf: buf,
            plugin_ctx: PluginCtx::default(),
            route_upstream: None,
            route_tls: false,
            route_canonical_domain: None,
            static_response: None,
            effective_path: None,
            basic_auth: None,
            forward_auth: None,
            forward_auth_headers: Vec::new(),
            file_server: None,
            fastcgi_root: None,
            injector: None,
            decompressor: None,
            var_slots: None,
            intercepts: Vec::new(),
            intercept_body: None,
            copy_response_headers: None,
            upstream_pool: None,
        }
    }

    /// The request ID as a `&str` (zero-copy from inline buffer).
    pub fn request_id(&self) -> &str {
        // SAFETY: UUID hyphenated encoding is always valid ASCII/UTF-8
        std::str::from_utf8(&self.request_id_buf).expect("UUID is valid UTF-8")
    }
}

impl Default for RequestContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RequestContext>();
    }

    #[test]
    fn new_sets_start_time_and_request_id() {
        let before = Instant::now();
        let ctx = RequestContext::new();
        let after = Instant::now();

        assert!(ctx.start_time >= before);
        assert!(ctx.start_time <= after);

        // UUID v7: 36 chars (8-4-4-4-12)
        assert_eq!(ctx.request_id().len(), 36);
        assert!(
            ctx.request_id()
                .chars()
                .next()
                .unwrap_or(' ')
                .is_ascii_hexdigit()
        );
    }

    #[test]
    fn request_ids_are_unique() {
        let ctx1 = RequestContext::new();
        let ctx2 = RequestContext::new();
        assert_ne!(ctx1.request_id(), ctx2.request_id());
    }

    #[test]
    fn request_ids_are_time_sortable() {
        let ctx1 = RequestContext::new();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let ctx2 = RequestContext::new();
        assert!(ctx2.request_id() > ctx1.request_id());
    }

    #[test]
    fn metadata_fields_start_empty() {
        let ctx = RequestContext::new();
        assert!(ctx.plugin_ctx.client_ip.is_none());
        assert!(ctx.plugin_ctx.host.is_none());
        assert!(ctx.plugin_ctx.method.is_empty());
        assert!(ctx.plugin_ctx.path.is_empty());
        assert!(ctx.route_upstream.is_none());
        assert!(!ctx.route_tls);
        assert!(ctx.route_canonical_domain.is_none());
        assert!(ctx.injector.is_none());
        assert!(ctx.decompressor.is_none());
        assert!(!ctx.plugin_ctx.is_bot);
        assert!(ctx.plugin_ctx.bot_category.is_none());
        assert!(ctx.plugin_ctx.country.is_none());
        assert!(ctx.plugin_ctx.compressor.is_none());
    }
}
