// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Plugin trait, action enum, per-request context, and execution chain.
//!
//! The plugin system decouples features (bot detection, rate limiting,
//! compression, security headers) from the core proxy engine. Each feature
//! becomes a [`DwaarPlugin`] that hooks into three `ProxyHttp` phases:
//!
//! - `on_request` — runs in `request_filter()`, can short-circuit with a response
//! - `on_response` — runs in `response_filter()`, can modify response headers
//! - `on_body` — runs in `response_body_filter()`, can transform body chunks
//!
//! The [`PluginChain`] holds plugins sorted by priority and executes them
//! in order at each phase.

use std::net::IpAddr;

use bytes::Bytes;
use pingora_http::{RequestHeader, ResponseHeader};

use crate::bot_detect::BotCategory;
use crate::compress::ResponseCompressor;

/// Per-request state shared between plugins across lifecycle hooks.
///
/// Populated by the proxy engine before the plugin chain runs. Plugins
/// can read and write fields to communicate (e.g., `BotDetectPlugin` sets
/// `is_bot`, and `RateLimitPlugin` reads it to apply different limits).
///
/// The `request_id` lives in `RequestContext` (inline `[u8; 36]`, zero-alloc).
/// Plugins that need it receive it via method parameters, not by storing a copy.
#[derive(Debug, Default)]
pub struct PluginCtx {
    pub request_id: String,
    pub client_ip: Option<IpAddr>,
    pub host: Option<String>,
    pub method: String,
    pub path: String,

    /// Whether the downstream connection used TLS.
    pub is_tls: bool,

    /// Client's Accept-Encoding header value, for compression negotiation.
    pub accept_encoding: String,

    /// Per-route rate limit (requests/second). Populated from `RouteTable`
    /// before the plugin chain runs. `None` means no limit configured.
    pub rate_limit_rps: Option<u32>,

    /// The canonical domain from the matched route. Used as the rate
    /// limiter key (not the raw Host header, which may have a port suffix).
    pub route_domain: Option<String>,

    /// Whether Under Attack Mode is enabled for this route.
    pub under_attack: bool,

    // -- Fields written by plugins --
    pub is_bot: bool,
    pub bot_category: Option<BotCategory>,
    pub country: Option<String>,
    pub compressor: Option<ResponseCompressor>,
}

impl PluginCtx {
    pub fn new(request_id: String) -> Self {
        Self {
            request_id,
            ..Self::default()
        }
    }
}

/// Data for a short-circuit response produced by a plugin.
#[derive(Debug, Clone)]
pub struct PluginResponse {
    pub status: u16,
    pub headers: Vec<(&'static str, String)>,
    pub body: Bytes,
}

/// What a plugin hook returns to control chain execution.
#[derive(Debug)]
pub enum PluginAction {
    /// Done — pass control to the next plugin in the chain.
    Continue,
    /// Short-circuit: stop the chain, send this response to the client.
    Respond(PluginResponse),
    /// Stop the chain, but continue normal proxy flow (no response sent).
    Skip,
}

/// A composable plugin that hooks into the proxy request lifecycle.
///
/// Implement this trait for each feature (bot detection, rate limiting, etc.).
/// Plugins are registered in a [`PluginChain`] and executed in `priority()` order.
///
/// # Execution model
///
/// - Hooks are **synchronous** — they produce data, the proxy handles async I/O.
/// - `on_request` can return `Respond` to short-circuit (e.g., 429 rate limit).
/// - `on_response` can modify response headers (e.g., add security headers).
/// - `on_body` can transform body chunks (e.g., compression).
/// - Default implementations return `Continue` (no-op), so plugins only
///   override the hooks they care about.
pub trait DwaarPlugin: Send + Sync {
    /// Human-readable name for logging and diagnostics.
    fn name(&self) -> &'static str;

    /// Execution priority — lower values run first.
    fn priority(&self) -> u16;

    /// Called during `request_filter()`. Inspect request headers, populate
    /// context, or short-circuit with a response.
    fn on_request(&self, _req: &RequestHeader, _ctx: &mut PluginCtx) -> PluginAction {
        PluginAction::Continue
    }

    /// Called during `response_filter()`. Modify response headers or set
    /// up per-request state for body processing.
    fn on_response(&self, _resp: &mut ResponseHeader, _ctx: &mut PluginCtx) -> PluginAction {
        PluginAction::Continue
    }

    /// Called during `response_body_filter()` for each body chunk.
    /// Transform the body in-place (e.g., compression).
    fn on_body(
        &self,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
        _ctx: &mut PluginCtx,
    ) -> PluginAction {
        PluginAction::Continue
    }
}

/// Ordered collection of plugins, executed by priority at each proxy phase.
///
/// Plugins are sorted once at construction (startup) and reused for every
/// request — no per-request allocation. The chain is `Send + Sync` so it
/// can be shared across Pingora's worker threads via `Arc`.
pub struct PluginChain {
    plugins: Vec<Box<dyn DwaarPlugin>>,
}

impl PluginChain {
    /// Build a chain from a list of plugins, sorting by priority (ascending).
    pub fn new(mut plugins: Vec<Box<dyn DwaarPlugin>>) -> Self {
        plugins.sort_by_key(|p| p.priority());
        Self { plugins }
    }

    /// Run request hooks in priority order.
    ///
    /// Returns `Some(response)` if a plugin wants to short-circuit the request.
    /// Returns `None` to continue normal proxy flow.
    pub fn run_request(&self, req: &RequestHeader, ctx: &mut PluginCtx) -> Option<PluginResponse> {
        for plugin in &self.plugins {
            match plugin.on_request(req, ctx) {
                PluginAction::Continue => {}
                PluginAction::Respond(resp) => return Some(resp),
                PluginAction::Skip => break,
            }
        }
        None
    }

    /// Run response hooks in priority order.
    ///
    /// Plugins can modify headers but can't short-circuit (the response
    /// is already being built). `Respond` and `Skip` both stop the chain.
    pub fn run_response(&self, resp: &mut ResponseHeader, ctx: &mut PluginCtx) {
        for plugin in &self.plugins {
            match plugin.on_response(resp, ctx) {
                PluginAction::Continue => {}
                PluginAction::Respond(_) | PluginAction::Skip => break,
            }
        }
    }

    /// Run body hooks in priority order for each chunk.
    pub fn run_body(&self, body: &mut Option<Bytes>, end_of_stream: bool, ctx: &mut PluginCtx) {
        for plugin in &self.plugins {
            match plugin.on_body(body, end_of_stream, ctx) {
                PluginAction::Continue => {}
                PluginAction::Respond(_) | PluginAction::Skip => break,
            }
        }
    }

    /// Number of registered plugins.
    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    /// Whether the chain has no plugins.
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }
}

impl std::fmt::Debug for PluginChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.plugins.iter().map(|p| p.name()).collect();
        f.debug_struct("PluginChain")
            .field("plugins", &names)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Test helpers: minimal plugins that record execution order --

    struct RecorderPlugin {
        name: &'static str,
        priority: u16,
        request_action: fn() -> PluginAction,
    }

    impl DwaarPlugin for RecorderPlugin {
        fn name(&self) -> &'static str {
            self.name
        }
        fn priority(&self) -> u16 {
            self.priority
        }
        fn on_request(&self, _req: &RequestHeader, ctx: &mut PluginCtx) -> PluginAction {
            // Append plugin name to path as execution trace
            ctx.path.push_str(self.name);
            ctx.path.push(',');
            (self.request_action)()
        }
        fn on_response(&self, _resp: &mut ResponseHeader, ctx: &mut PluginCtx) -> PluginAction {
            ctx.path.push_str(self.name);
            ctx.path.push(',');
            PluginAction::Continue
        }
        fn on_body(
            &self,
            _body: &mut Option<Bytes>,
            _eos: bool,
            ctx: &mut PluginCtx,
        ) -> PluginAction {
            ctx.path.push_str(self.name);
            ctx.path.push(',');
            PluginAction::Continue
        }
    }

    fn make_req() -> RequestHeader {
        RequestHeader::build("GET", b"/", None).expect("valid request")
    }

    fn make_ctx() -> PluginCtx {
        PluginCtx::new("test-id".to_string())
    }

    // -- Execution order --

    #[test]
    fn chain_executes_in_priority_order() {
        let chain = PluginChain::new(vec![
            Box::new(RecorderPlugin {
                name: "C",
                priority: 30,
                request_action: || PluginAction::Continue,
            }),
            Box::new(RecorderPlugin {
                name: "A",
                priority: 10,
                request_action: || PluginAction::Continue,
            }),
            Box::new(RecorderPlugin {
                name: "B",
                priority: 20,
                request_action: || PluginAction::Continue,
            }),
        ]);

        let req = make_req();
        let mut ctx = make_ctx();
        let result = chain.run_request(&req, &mut ctx);

        assert!(result.is_none());
        assert_eq!(ctx.path, "A,B,C,");
    }

    // -- PluginAction::Respond short-circuits --

    #[test]
    fn respond_action_stops_chain_and_returns_response() {
        let chain = PluginChain::new(vec![
            Box::new(RecorderPlugin {
                name: "first",
                priority: 10,
                request_action: || {
                    PluginAction::Respond(PluginResponse {
                        status: 429,
                        headers: vec![("Retry-After", "1".to_string())],
                        body: Bytes::new(),
                    })
                },
            }),
            Box::new(RecorderPlugin {
                name: "second",
                priority: 20,
                request_action: || PluginAction::Continue,
            }),
        ]);

        let req = make_req();
        let mut ctx = make_ctx();
        let result = chain.run_request(&req, &mut ctx);

        // First plugin ran, second did not
        assert_eq!(ctx.path, "first,");
        let resp = result.expect("should have response");
        assert_eq!(resp.status, 429);
    }

    // -- PluginAction::Skip stops chain without response --

    #[test]
    fn skip_action_stops_chain_without_response() {
        let chain = PluginChain::new(vec![
            Box::new(RecorderPlugin {
                name: "skipper",
                priority: 10,
                request_action: || PluginAction::Skip,
            }),
            Box::new(RecorderPlugin {
                name: "skipped",
                priority: 20,
                request_action: || PluginAction::Continue,
            }),
        ]);

        let req = make_req();
        let mut ctx = make_ctx();
        let result = chain.run_request(&req, &mut ctx);

        assert!(result.is_none());
        assert_eq!(ctx.path, "skipper,");
    }

    // -- Empty chain is a no-op --

    #[test]
    fn empty_chain_returns_none() {
        let chain = PluginChain::new(vec![]);
        let req = make_req();
        let mut ctx = make_ctx();

        assert!(chain.run_request(&req, &mut ctx).is_none());
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);
    }

    // -- Response and body hooks --

    #[test]
    fn response_hooks_execute_in_order() {
        let chain = PluginChain::new(vec![
            Box::new(RecorderPlugin {
                name: "B",
                priority: 20,
                request_action: || PluginAction::Continue,
            }),
            Box::new(RecorderPlugin {
                name: "A",
                priority: 10,
                request_action: || PluginAction::Continue,
            }),
        ]);

        let mut resp = ResponseHeader::build(200, Some(0)).expect("valid response");
        let mut ctx = make_ctx();
        chain.run_response(&mut resp, &mut ctx);
        assert_eq!(ctx.path, "A,B,");
    }

    #[test]
    fn body_hooks_execute_in_order() {
        let chain = PluginChain::new(vec![
            Box::new(RecorderPlugin {
                name: "B",
                priority: 20,
                request_action: || PluginAction::Continue,
            }),
            Box::new(RecorderPlugin {
                name: "A",
                priority: 10,
                request_action: || PluginAction::Continue,
            }),
        ]);

        let mut body = Some(Bytes::from("test"));
        let mut ctx = make_ctx();
        chain.run_body(&mut body, false, &mut ctx);
        assert_eq!(ctx.path, "A,B,");
    }

    // -- PluginCtx defaults --

    #[test]
    fn plugin_ctx_defaults() {
        let ctx = PluginCtx::new("abc-123".to_string());
        assert_eq!(ctx.request_id, "abc-123");
        assert!(ctx.client_ip.is_none());
        assert!(ctx.host.is_none());
        assert!(!ctx.is_bot);
        assert!(!ctx.is_tls);
        assert!(!ctx.under_attack);
        assert!(ctx.compressor.is_none());
    }

    // -- PluginChain is Send + Sync --

    #[test]
    fn chain_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PluginChain>();
    }

    #[test]
    fn plugin_ctx_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PluginCtx>();
    }

    // -- Debug impls --

    #[test]
    fn chain_debug_shows_plugin_names() {
        let chain = PluginChain::new(vec![Box::new(RecorderPlugin {
            name: "test-plugin",
            priority: 10,
            request_action: || PluginAction::Continue,
        })]);
        let debug = format!("{chain:?}");
        assert!(debug.contains("test-plugin"));
    }
}
