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
use std::sync::atomic::AtomicU32;
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
#[allow(clippy::struct_excessive_bools)] // Protocol flags (tls, websocket, grpc, cache) are independent booleans, not a state machine
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

    /// WebSocket upgrade detected — preserves hop-by-hop headers and skips
    /// analytics injection so Pingora can establish the bidirectional tunnel.
    pub is_websocket: bool,

    /// gRPC request detected — forces HTTP/2 upstream, disables body limits,
    /// skips analytics injection. gRPC has its own compression and framing.
    pub is_grpc: bool,

    /// gRPC-Web mode detected in `request_filter()`. When `Some`, the response
    /// path translates headers and optionally base64-encodes the body back to
    /// the client's expected gRPC-Web format.
    pub grpc_web_mode: Option<crate::grpc_web::GrpcWebMode>,

    /// Max request body size in bytes (ISSUE-069). Enforced in `request_filter()`
    /// (Content-Length) and `request_body_filter()` (chunked streaming).
    /// Default: 10 MB. Set to `u64::MAX` for unlimited.
    pub request_body_max_size: u64,

    /// Accumulated request body bytes received so far (ISSUE-069).
    /// Tracked in `request_body_filter()` for chunked requests.
    pub request_body_received: u64,

    /// Max response body size in bytes (ISSUE-070). Enforced in
    /// `response_body_filter()`. Default: 100 MB. Set to `u64::MAX` for unlimited.
    pub response_body_max_size: u64,

    /// Accumulated response body bytes received so far (ISSUE-070).
    pub response_body_sent: u64,

    /// Active connection counter for the matched route (ISSUE-075).
    /// Decremented in `logging()` when the request completes, enabling
    /// graceful drain when a route is removed during hot-reload.
    pub drain_counter: Option<Arc<AtomicU32>>,

    /// Whether caching is enabled for this request (ISSUE-073).
    pub cache_enabled: bool,

    /// Cache config for this request, cached from route lookup (Guardrail #27).
    pub cache_config: Option<std::sync::Arc<crate::cache::CacheConfig>>,

    /// Cache outcome: "HIT", "MISS", "STALE", or None (cache disabled).
    /// Injected as `X-Cache` response header and logged in `RequestLog`.
    pub cache_status: Option<&'static str>,

    /// Whether the resolved route can be served over QUIC (HTTP/3).
    /// Only `ReverseProxy` and `ReverseProxyPool` handlers are supported by
    /// the QUIC bridge — `FileServer`, `StaticResponse`, `FastCgi` are not.
    /// `Alt-Svc` h3 is only injected when this flag is true to avoid
    /// advertising a protocol the server can't actually serve for this route.
    pub quic_capable: bool,

    /// Trace context parsed/generated in `upstream_request_filter()`.
    pub trace_ctx: Option<crate::trace::TraceContext>,

    /// Upstream response status cached in `response_filter()` for
    /// `response_body_filter()` which doesn't have direct header access.
    pub upstream_status: u16,

    /// Captured upstream error body for 5xx responses (ISSUE-117).
    /// Populated in `response_body_filter`, read in `logging()`.
    pub upstream_error_body: Option<String>,

    /// Name of the plugin that rejected this request (e.g., rate limiting),
    /// surfaced in the access log as `rejected_by`. `&'static str` so no
    /// per-request allocation on the hot path (#128).
    pub rejected_by: Option<&'static str>,

    /// Name of the plugin that blocked this request (e.g., bot detection,
    /// IP filter, under-attack challenge), surfaced in the access log as
    /// `blocked_by`. `&'static str` so no per-request allocation (#128).
    pub blocked_by: Option<&'static str>,

    /// Number of upstream retries performed for this request.
    pub retry_count: u32,

    /// When `lb_policy cookie` selects a backend, this holds the `Set-Cookie`
    /// header value to pin the visitor. Applied in `response_filter()`.
    pub sticky_set_cookie: Option<String>,
}

impl RequestContext {
    /// Create a new context with timing and identity set.
    pub fn new() -> Self {
        // UUID v7 layout: 48-bit unix_ts_ms | 4-bit version | 12-bit rand_a |
        //                 2-bit variant | 62-bit rand_b
        // Using fastrand (~3ns) instead of crypto RNG (~100ns). Request IDs
        // need uniqueness and time-sortability, not cryptographic strength.
        let ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let mut bytes = [0u8; 16];
        fastrand::fill(&mut bytes);
        // Embed timestamp in first 6 bytes (big-endian)
        bytes[0] = (ms >> 40) as u8;
        bytes[1] = (ms >> 32) as u8;
        bytes[2] = (ms >> 24) as u8;
        bytes[3] = (ms >> 16) as u8;
        bytes[4] = (ms >> 8) as u8;
        bytes[5] = ms as u8;
        // Set version (7) and variant (RFC 9562)
        bytes[6] = (bytes[6] & 0x0F) | 0x70; // version 7
        bytes[8] = (bytes[8] & 0x3F) | 0x80; // variant RFC 9562
        let uuid = Uuid::from_bytes(bytes);
        let mut buf = [0u8; 36];
        uuid.as_hyphenated().encode_lower(&mut buf);

        Self {
            start_time: Instant::now(),
            request_id_buf: buf,
            plugin_ctx: PluginCtx::default(),
            route_upstream: None,
            route_tls: false,
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
            is_websocket: false,
            is_grpc: false,
            grpc_web_mode: None,
            request_body_max_size: 10 * 1024 * 1024, // 10 MB default
            request_body_received: 0,
            response_body_max_size: 100 * 1024 * 1024, // 100 MB default
            response_body_sent: 0,
            drain_counter: None,
            cache_enabled: false,
            cache_config: None,
            cache_status: None,
            quic_capable: false,
            trace_ctx: None,
            upstream_status: 0,
            upstream_error_body: None,
            rejected_by: None,
            blocked_by: None,
            retry_count: 0,
            sticky_set_cookie: None,
        }
    }

    /// The request ID as a `&str` (zero-copy from inline buffer).
    pub fn request_id(&self) -> &str {
        // SAFETY: UUID hyphenated encoding is always valid ASCII/UTF-8
        std::str::from_utf8(&self.request_id_buf).expect("UUID is valid UTF-8")
    }
}

impl Default for RequestContext {
    /// Side effects are intentional: every call generates a fresh UUID v7 and
    /// captures the current instant. That's the whole point — each request context
    /// needs a unique identity and a precise start time.
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
        assert!(ctx.injector.is_none());
        assert!(ctx.decompressor.is_none());
        assert!(!ctx.plugin_ctx.is_bot);
        assert!(ctx.plugin_ctx.bot_category.is_none());
        assert!(ctx.plugin_ctx.country.is_none());
        assert!(ctx.plugin_ctx.compressor.is_none());
        assert!(!ctx.is_websocket);
        assert!(!ctx.is_grpc);
    }
}
