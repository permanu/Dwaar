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
//! upstream_peer()     → reads host for routing (ISSUE-010)
//! response_filter()   → reads request_id, writes X-Request-Id header
//! logging()           → reads start_time to compute duration (ISSUE-019)
//! [drop]              → context freed, request complete
//! ```

use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use dwaar_analytics::decompress::Decompressor;
use dwaar_analytics::injector::HtmlInjector;
use uuid::Uuid;

/// Per-request state shared across all Pingora lifecycle hooks.
///
/// Created once per request by [`DwaarProxy::new_ctx()`], dropped when the
/// request completes.
///
/// # Populated in two phases
///
/// **Phase 1 — `new_ctx()`:** Sets `start_time` and `request_id`. These are
/// independent of the HTTP request itself (we generate them before headers
/// are parsed).
///
/// **Phase 2 — `request_filter()`:** Reads the HTTP headers and connection
/// info to fill `client_ip`, `host`, `method`, and `path`.
///
/// # Thread safety
///
/// All fields are owned types (`String`, `Instant`, `Option<IpAddr>`), so
/// `RequestContext` is automatically `Send + Sync`. Pingora requires this
/// because async tasks may move across threads between lifecycle hooks.
#[derive(Debug)]
pub struct RequestContext {
    /// When this request started processing. Used to compute request duration
    /// in the `logging()` hook. Uses `Instant` (monotonic clock) — not
    /// `SystemTime` — because we need elapsed time, not wall-clock time.
    /// NTP adjustments can make `SystemTime` go backwards; `Instant` never does.
    pub start_time: Instant,

    /// Unique identifier for this request. UUID v7 format: the first 48 bits
    /// are a millisecond timestamp, so IDs are **time-sortable**. Sorting
    /// request IDs alphabetically gives chronological order — useful for log
    /// analysis without needing a separate timestamp column.
    pub request_id: String,

    /// The client's IP address, extracted from the TCP socket's peer address.
    /// `None` if the connection has no IP (e.g., Unix domain socket).
    ///
    /// This is the **direct connection IP** — if Dwaar is behind a load
    /// balancer, this will be the LB's IP. ISSUE-007 adds `X-Forwarded-For`
    /// support for the real client IP.
    pub client_ip: Option<IpAddr>,

    /// The `Host` header value from the HTTP request. Used for routing
    /// (ISSUE-010: match host → upstream) and TLS SNI (ISSUE-015).
    /// `None` if the client didn't send a Host header (technically invalid
    /// for HTTP/1.1, but we handle it gracefully).
    pub host: Option<String>,

    /// HTTP method: GET, POST, PUT, DELETE, etc. Stored as a string because
    /// we only need it for logging and analytics, not for branching logic.
    pub method: String,

    /// Request path including query string (e.g., `/api/users?page=2`).
    /// Used for logging, analytics, and URL-based routing.
    pub path: String,

    /// The upstream address selected by route resolution in `upstream_peer()`.
    /// `None` until routing completes. Later phases (logging, analytics) use
    /// this to know which backend handled the request.
    pub route_upstream: Option<SocketAddr>,

    /// HTML script injector for analytics. Created in `response_filter()` when
    /// the response is 2xx text/html. `response_body_filter()` passes body
    /// chunks through this. `None` for non-HTML or non-2xx responses.
    pub injector: Option<HtmlInjector>,

    /// Streaming decompressor for compressed HTML responses. Created in
    /// `response_filter()` when Content-Encoding is detected on HTML responses.
    /// `response_body_filter()` decompresses each chunk before passing to the injector.
    pub decompressor: Option<Decompressor>,

    /// Whether this request was classified as a bot by the `BotDetector`.
    /// Set in `request_filter()`, read in `logging()`.
    pub is_bot: bool,

    /// Bot classification category, if detected. `None` for human traffic.
    pub bot_category: Option<dwaar_plugins::bot_detect::BotCategory>,

    /// Two-letter ISO country code from `GeoIP` lookup (e.g., "US", "IN").
    /// `None` if no `GeoIP` database is loaded or the IP is private/unknown.
    pub country: Option<String>,
}

impl RequestContext {
    /// Create a new context with timing and identity set.
    ///
    /// Called by `DwaarProxy::new_ctx()` for every incoming request.
    /// The remaining fields (`client_ip`, `host`, `method`, `path`) are
    /// populated later in `request_filter()` once the HTTP headers are available.
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            request_id: Uuid::now_v7().to_string(),
            client_ip: None,
            host: None,
            method: String::new(),
            path: String::new(),
            route_upstream: None,
            injector: None,
            decompressor: None,
            is_bot: false,
            bot_category: None,
            country: None,
        }
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

        // start_time should be between before and after
        assert!(ctx.start_time >= before);
        assert!(ctx.start_time <= after);

        // request_id should be a valid UUID v7 (36 chars: 8-4-4-4-12)
        assert_eq!(ctx.request_id.len(), 36);

        // UUID v7 starts with a timestamp — first char is a hex digit
        assert!(
            ctx.request_id
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
        assert_ne!(ctx1.request_id, ctx2.request_id);
    }

    #[test]
    fn request_ids_are_time_sortable() {
        // UUID v7 encodes millisecond timestamp in the first 48 bits.
        // Two IDs created in sequence should sort chronologically.
        let ctx1 = RequestContext::new();
        // Small sleep to ensure different millisecond
        std::thread::sleep(std::time::Duration::from_millis(2));
        let ctx2 = RequestContext::new();
        assert!(ctx2.request_id > ctx1.request_id);
    }

    #[test]
    fn metadata_fields_start_empty() {
        let ctx = RequestContext::new();
        assert!(ctx.client_ip.is_none());
        assert!(ctx.host.is_none());
        assert!(ctx.method.is_empty());
        assert!(ctx.path.is_empty());
        assert!(ctx.route_upstream.is_none());
        assert!(ctx.injector.is_none());
        assert!(ctx.decompressor.is_none());
        assert!(!ctx.is_bot);
        assert!(ctx.bot_category.is_none());
        assert!(ctx.country.is_none());
    }
}
