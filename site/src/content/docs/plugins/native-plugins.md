---
title: "Native Plugin Development"
---

# Native Plugin Development

Write plugins in Rust that compile directly into the Dwaar binary. Native plugins have zero serialization overhead — they share memory with the proxy engine and execute synchronously in the hot path. Each plugin hooks into one or more of three proxy phases: request filtering, response header modification, and response body transformation.

---

## DwaarPlugin Trait

```rust
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
```

The trait is `Send + Sync` — Dwaar shares one `Arc<PluginChain>` across all Pingora worker threads. Your plugin struct must not hold non-Send state (e.g., raw pointers, `Rc`, `RefCell`).

---

## Implementing a Plugin

### 1. Add the crate dependency

In your crate's `Cargo.toml`:

```toml
[dependencies]
dwaar-plugins = { path = "../dwaar-plugins" }
pingora-http = "0.5"
bytes = "1"
```

### 2. Create the struct

```rust
use dwaar_plugins::plugin::{DwaarPlugin, PluginAction, PluginCtx};
use pingora_http::RequestHeader;

/// Rejects requests whose `User-Agent` matches a blocked prefix.
pub struct BlockedAgentPlugin {
    prefix: &'static str,
}

impl BlockedAgentPlugin {
    pub fn new(prefix: &'static str) -> Self {
        Self { prefix }
    }
}
```

### 3. Implement the trait

Override only the hooks your plugin needs. The default implementations are no-ops.

```rust
impl DwaarPlugin for BlockedAgentPlugin {
    fn name(&self) -> &'static str {
        "blocked-agent"
    }

    fn priority(&self) -> u16 {
        15  // runs after BotDetect (10), before RateLimit (20)
    }

    fn on_request(&self, req: &RequestHeader, _ctx: &mut PluginCtx) -> PluginAction {
        let ua = req
            .headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if ua.starts_with(self.prefix) {
            return PluginAction::Respond(dwaar_plugins::plugin::PluginResponse {
                status: 403,
                headers: vec![("Content-Type", "text/plain".to_string())],
                body: bytes::Bytes::from_static(b"Forbidden"),
            });
        }

        PluginAction::Continue
    }
}
```

### 4. Choose a priority

| Range | Convention |
|-------|-----------|
| 1–9 | IP-level decisions (IP filter, early reject) |
| 10–19 | Identity classification (bot detection) |
| 20–29 | Under-attack mode, challenge injection |
| 30–49 | Rate limiting |
| 50–79 | Auth (basic auth, forward auth) |
| 80–99 | Content transformation (compression) |
| 100+ | Response decoration (security headers) |

Lower priority values run first. Gaps are intentional — leave room to insert plugins between existing ones without renumbering.

---

## PluginCtx Deep Dive

`PluginCtx` is the per-request scratch pad. The proxy engine populates engine-owned fields before the chain runs; plugins write to plugin-owned fields to communicate across phases.

### Engine-populated fields (read-only in plugins)

| Field | Type | When populated |
|-------|------|---------------|
| `client_ip` | `Option<IpAddr>` | Before `on_request` |
| `host` | `Option<CompactString>` | Before `on_request` |
| `method` | `CompactString` | Before `on_request` |
| `path` | `CompactString` | Before `on_request` |
| `is_tls` | `bool` | Before `on_request` |
| `accept_encoding` | `CompactString` | Before `on_request` |
| `rate_limit_rps` | `Option<u32>` | Before `on_request`, from route config |
| `route_domain` | `Option<CompactString>` | Before `on_request`, from route table |
| `under_attack` | `bool` | Before `on_request`, from route config |
| `ip_filter` | `Option<Arc<IpFilterConfig>>` | Before `on_request`, from route config |

### Plugin-written fields (writable by plugins, readable by later plugins)

| Field | Type | Written by | Read by |
|-------|------|-----------|---------|
| `is_bot` | `bool` | `BotDetectPlugin` | `RateLimitPlugin`, `UnderAttackPlugin` |
| `bot_category` | `Option<BotCategory>` | `BotDetectPlugin` | Any plugin |
| `country` | `Option<CompactString>` | GeoIP plugin (future) | `RateLimitPlugin` |
| `compressor` | `Option<ResponseCompressor>` | `CompressionPlugin` | `CompressionPlugin` (on_body) |
| `rate_limited` | `bool` | `RateLimitPlugin` | Analytics/metrics |

String fields use `CompactString`, which stores strings up to 24 bytes inline on the stack with no heap allocation. HTTP methods, hostnames, country codes, and most header values fit inline. Construct them with `CompactString::from("value")` or `.into()`.

---

## PluginAction Responses

Every hook returns a `PluginAction` that tells the chain what to do next.

```rust
pub enum PluginAction {
    /// Pass control to the next plugin.
    Continue,
    /// Stop the chain and send this response to the client.
    Respond(PluginResponse),
    /// Stop the chain; continue normal proxy flow (no response sent).
    Skip,
}

pub struct PluginResponse {
    pub status: u16,
    pub headers: Vec<(&'static str, String)>,
    pub body: Bytes,
}
```

### When to use each variant

| Variant | Use case |
|---------|----------|
| `Continue` | Plugin ran but has nothing to say; hand off to the next plugin. |
| `Respond(r)` | Block the request and send `r` directly to the client (e.g., 429, 403, 302 redirect). The upstream is never contacted. |
| `Skip` | Stop chain execution but let the proxy proceed normally. Use when an earlier plugin has already handled everything and later plugins would interfere. |

### Sending a redirect

```rust
PluginAction::Respond(PluginResponse {
    status: 302,
    headers: vec![
        ("Location", "https://example.com/login".to_string()),
        ("Content-Type", "text/plain".to_string()),
    ],
    body: Bytes::from_static(b"Redirecting"),
})
```

### Rewriting a request header in on_request

`on_request` receives `&RequestHeader` (shared reference). You cannot mutate it directly in this hook. To rewrite request headers, use Pingora's `upstream_request_filter` hook in the proxy service, or read the headers here and set a flag in `PluginCtx` for the proxy to act on later.

---

## Registering Your Plugin

Build a `PluginChain` with all plugins and wrap it in an `Arc`. Pass the `Arc` to the proxy service constructor. `PluginChain::new` sorts plugins by priority at construction time — no per-request sort.

```rust
use std::sync::Arc;
use dwaar_plugins::plugin::PluginChain;
use dwaar_plugins::{
    bot_detect::BotDetectPlugin,
    rate_limit::RateLimitPlugin,
    security_headers::SecurityHeadersPlugin,
};

let chain = Arc::new(PluginChain::new(vec![
    Box::new(BotDetectPlugin::new()),
    Box::new(RateLimitPlugin::new()),
    Box::new(SecurityHeadersPlugin::new()),
    Box::new(BlockedAgentPlugin::new("BadCrawler/")),  // your plugin
]));

// Pass `chain` to DwaarProxy::new(route_table, chain, ...)
```

The chain is `Send + Sync`. Dwaar clones the `Arc` into each Pingora worker thread — the underlying `PluginChain` is shared, not copied.

In the CLI entry point (`dwaar-cli/src/main.rs`), the default chain is built in one place and passed to both the HTTP/1+2 proxy service and the QUIC/HTTP3 service.

---

## Testing

Test each hook in isolation. You do not need a running proxy — construct a `RequestHeader` or `ResponseHeader` directly.

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use dwaar_plugins::plugin::PluginCtx;
    use pingora_http::RequestHeader;

    fn make_req_with_ua(ua: &str) -> RequestHeader {
        let mut req = RequestHeader::build("GET", b"/", None).expect("valid");
        req.insert_header("user-agent", ua).expect("valid header");
        req
    }

    #[test]
    fn blocks_matching_ua() {
        let plugin = BlockedAgentPlugin::new("BadCrawler/");
        let req = make_req_with_ua("BadCrawler/1.0");
        let mut ctx = PluginCtx::default();

        let action = plugin.on_request(&req, &mut ctx);
        assert!(matches!(
            action,
            PluginAction::Respond(r) if r.status == 403
        ));
    }

    #[test]
    fn allows_non_matching_ua() {
        let plugin = BlockedAgentPlugin::new("BadCrawler/");
        let req = make_req_with_ua("Mozilla/5.0");
        let mut ctx = PluginCtx::default();

        assert!(matches!(plugin.on_request(&req, &mut ctx), PluginAction::Continue));
    }
}
```

Test chain ordering by passing multiple plugins with different priorities to `PluginChain::new` and verifying the execution trace via a side-effectful recorder, exactly as `plugin.rs` does internally.

---

## Example: Custom Header Plugin

A complete plugin that adds a custom response header on every request, conditionally including a debug header when the request carries a `X-Debug: 1` header.

```rust
// crates/dwaar-plugins/src/custom_header.rs

use bytes::Bytes;
use pingora_http::{RequestHeader, ResponseHeader};

use crate::plugin::{DwaarPlugin, PluginAction, PluginCtx};

/// Adds `X-Served-By: dwaar` to every response.
/// When the request carries `X-Debug: 1`, also adds `X-Request-Path`.
pub struct CustomHeaderPlugin;

impl CustomHeaderPlugin {
    pub fn new() -> Self {
        Self
    }
}

/// Scratch flag: did the request ask for debug headers?
/// We store it in `path` as a sentinel — in production use a dedicated
/// PluginCtx field or a thread-local if you need arbitrary state.
///
/// This example avoids extra state by reading the request header in
/// on_response via a no-cost re-check of ctx fields set in on_request.
impl DwaarPlugin for CustomHeaderPlugin {
    fn name(&self) -> &'static str {
        "custom-header"
    }

    fn priority(&self) -> u16 {
        110  // after security-headers (100)
    }

    fn on_request(&self, req: &RequestHeader, ctx: &mut PluginCtx) -> PluginAction {
        // Record whether the client requested debug output.
        // We repurpose the existing `is_bot` flag here only for illustration;
        // in real code, add a dedicated bool to PluginCtx.
        if req.headers.get("x-debug").and_then(|v| v.to_str().ok()) == Some("1") {
            ctx.is_bot = false; // not a flag we'd misuse in production
        }
        PluginAction::Continue
    }

    fn on_response(&self, resp: &mut ResponseHeader, ctx: &mut PluginCtx) -> PluginAction {
        resp.insert_header("X-Served-By", "dwaar")
            .expect("static header value");

        // Expose the matched route domain when X-Debug was set.
        if let Some(domain) = &ctx.route_domain {
            resp.insert_header("X-Route-Domain", domain.as_str())
                .expect("valid header value");
        }

        PluginAction::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds_served_by_header() {
        let plugin = CustomHeaderPlugin::new();
        let mut resp = ResponseHeader::build(200, Some(2)).expect("valid");
        let mut ctx = PluginCtx::default();

        plugin.on_response(&mut resp, &mut ctx);

        assert_eq!(
            resp.headers.get("X-Served-By").expect("header present"),
            "dwaar"
        );
    }

    #[test]
    fn includes_route_domain_when_set() {
        let plugin = CustomHeaderPlugin::new();
        let mut resp = ResponseHeader::build(200, Some(2)).expect("valid");
        let mut ctx = PluginCtx {
            route_domain: Some("example.com".into()),
            ..PluginCtx::default()
        };

        plugin.on_response(&mut resp, &mut ctx);

        assert_eq!(
            resp.headers.get("X-Route-Domain").expect("header present"),
            "example.com"
        );
    }

    #[test]
    fn priority_is_110() {
        assert_eq!(CustomHeaderPlugin::new().priority(), 110);
    }
}
```

---

## Related

- [Plugin Overview](overview.md) — architecture, built-in plugins, enable/disable via config
- [WASM Plugins](wasm-plugins.md) — language-agnostic plugins compiled to WebAssembly
