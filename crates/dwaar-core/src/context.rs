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
use std::time::Instant;

use dwaar_analytics::decompress::Decompressor;
use dwaar_analytics::injector::HtmlInjector;
use dwaar_plugins::plugin::PluginCtx;
use uuid::Uuid;

/// Per-request state shared across all Pingora lifecycle hooks.
///
/// Created once per request by [`DwaarProxy::new_ctx()`], dropped when the
/// request completes.
///
/// # Layout
///
/// Plugin-related state lives in [`PluginCtx`] (identity, bot classification,
/// compressor). Core proxy state (timing, analytics, routing) lives here directly.
#[derive(Debug)]
pub struct RequestContext {
    /// When this request started processing. Uses `Instant` (monotonic clock)
    /// because we need elapsed time, not wall-clock time.
    pub start_time: Instant,

    /// Plugin context — carries per-request state that plugins read and write.
    /// Also holds the `request_id` (UUID v7, time-sortable).
    pub plugin_ctx: PluginCtx,

    /// The upstream address selected by route resolution in `upstream_peer()`.
    pub route_upstream: Option<SocketAddr>,

    /// HTML script injector for analytics (core, not a plugin).
    pub injector: Option<HtmlInjector>,

    /// Streaming decompressor for compressed HTML responses (core, not a plugin).
    pub decompressor: Option<Decompressor>,
}

impl RequestContext {
    /// Create a new context with timing and identity set.
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            plugin_ctx: PluginCtx::new(Uuid::now_v7().to_string()),
            route_upstream: None,
            injector: None,
            decompressor: None,
        }
    }

    /// Convenience accessor for the request ID (lives in `plugin_ctx`).
    pub fn request_id(&self) -> &str {
        &self.plugin_ctx.request_id
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
        assert!(ctx.injector.is_none());
        assert!(ctx.decompressor.is_none());
        assert!(!ctx.plugin_ctx.is_bot);
        assert!(ctx.plugin_ctx.bot_category.is_none());
        assert!(ctx.plugin_ctx.country.is_none());
        assert!(ctx.plugin_ctx.compressor.is_none());
    }
}
