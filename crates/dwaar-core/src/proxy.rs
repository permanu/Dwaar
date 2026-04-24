// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Core proxy implementation — the `ProxyHttp` trait is Dwaar's engine.
//!
//! `DwaarProxy` implements Pingora's [`ProxyHttp`] trait, which defines how
//! every HTTP request is processed. Feature-specific logic (bot detection,
//! rate limiting, compression, security headers, under attack mode) runs
//! through the [`PluginChain`] — the proxy engine itself only handles routing,
//! analytics, ACME challenges, and request logging.

use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use chrono::Utc;
use pingora_cache::cache_control::CacheControl;
use pingora_cache::filters::resp_cacheable;
use pingora_cache::{CacheKey, NoCacheReason, RespCacheable};
use pingora_core::Result;
use pingora_core::upstreams::peer::{ALPN, HttpPeer};
use pingora_error::{Error, ErrorType::HTTPStatus};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{ProxyHttp, Session};
use tracing::{debug, trace, warn};

use bytes::Bytes;
use compact_str::CompactString;
use dwaar_analytics::ANALYTICS_JS;
use dwaar_analytics::aggregation::{AggEvent, AggSender};
use dwaar_analytics::beacon::{self, BeaconEvent, BeaconSender};
use dwaar_analytics::decompress::{Decompressor, Encoding};
use dwaar_analytics::injector::HtmlInjector;
use dwaar_log::{LogSender, RequestLog};
use dwaar_plugins::error_script_injection::{
    csp_allows_injection, ErrorScriptConfig, ErrorScriptInjector,
};
use dwaar_plugins::plugin::PluginChain;
use dwaar_tls::acme::ChallengeSolver;

use crate::context::RequestContext;
use crate::route::RouteTable;
use crate::template::TemplateContext;

/// Headers that `copy_response_headers include` must never strip.
///
/// HTTP's hop-by-hop headers and framing headers (Content-Length,
/// Transfer-Encoding, etc.) are required for correct message framing.
/// Stripping them based on user config would break the HTTP layer.
fn is_essential_header(name: &str) -> bool {
    const ESSENTIAL: &[&str] = &[
        "content-type",
        "content-length",
        "transfer-encoding",
        "connection",
        "date",
        "server",
    ];
    ESSENTIAL.iter().any(|h| name.eq_ignore_ascii_case(h))
}

/// Sanitize a request path for use in a redirect Location header.
/// Prevents CRLF injection and protocol-relative open redirects.
fn sanitize_redirect_path(path: &str) -> String {
    let cleaned: String = path.chars().filter(|c| *c != '\r' && *c != '\n').collect();
    if cleaned.starts_with("//") {
        format!("/{}", cleaned.trim_start_matches('/'))
    } else if cleaned.is_empty() {
        "/".to_string()
    } else {
        cleaned
    }
}

/// Extract a named cookie's value from a `Cookie` header string.
///
/// Parses `key1=val1; key2=val2` format. Returns `None` if the cookie isn't present.
fn extract_cookie_value<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
    cookie_header.split(';').map(str::trim).find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        if k.trim() == name {
            Some(v.trim())
        } else {
            None
        }
    })
}

/// The Dwaar proxy engine.
///
/// Routes requests to upstreams based on the `Host` header, using a lock-free
/// [`RouteTable`]. Feature logic runs through the [`PluginChain`].
#[derive(Debug)]
pub struct DwaarProxy {
    route_table: Arc<ArcSwap<RouteTable>>,
    challenge_solver: Option<Arc<ChallengeSolver>>,
    log_sender: Option<LogSender>,
    beacon_sender: Option<BeaconSender>,
    agg_sender: Option<AggSender>,
    geo_lookup: Option<Arc<dwaar_geo::GeoLookup>>,
    /// Plugin chain — holds all feature plugins sorted by priority.
    plugin_chain: Arc<PluginChain>,
    /// Prometheus metrics registry (ISSUE-072). `None` when `--no-metrics`.
    prometheus: Option<Arc<dwaar_analytics::prometheus::PrometheusMetrics>>,
    /// HTTP cache backend (ISSUE-073, ISSUE-111 hot-reload).
    /// `None` when `--no-cache`. Inner `ArcSwap` holds `None` when no route
    /// has a `cache {}` block; swapped on reload when cache size changes.
    cache_backend: Option<crate::cache::SharedCacheBackend>,
    /// Downstream keepalive timeout in seconds (ISSUE-076). Overrides
    /// Pingora's hardcoded 60s default per keep-alive connection.
    keepalive_secs: u64,
    /// Downstream body read timeout (ISSUE-076). Applied after headers
    /// arrive so slow body senders get disconnected.
    body_timeout: std::time::Duration,
    /// HTTP/3 (QUIC) enabled — when true, `response_filter` injects `Alt-Svc`
    /// to advertise HTTP/3 availability to browsers (ISSUE-079b).
    h3_enabled: bool,
    /// Control-plane hooks populated by the `dwaar-grpc` channel (Wheel #2).
    /// `None` when the gRPC control server isn't running, which keeps the
    /// registry lookups off the hot path entirely for single-node installs.
    control_plane: Option<ControlPlaneHooks>,
    /// Request-outcome callback for anomaly detection (Wheel #2 Week 5).
    /// Invoked in `logging()` with the completed request's status + latency.
    /// `None` disables anomaly emission without touching the proxy hot path.
    outcome_sink: Option<Arc<dyn RequestOutcomeSink>>,
    /// Mirror dispatcher (Wheel #2 Week 4). When set, `request_filter`
    /// consults the mirror registry for the current domain and spawns a
    /// fire-and-forget clone of the request to the mirror target. Mirror
    /// failures NEVER affect the primary response.
    mirror_dispatcher: Option<Arc<dyn MirrorDispatcher>>,
    /// OTLP span exporter — present when `tracing { otlp_endpoint }` is set.
    /// One span is recorded per completed request in `logging()`.
    otlp_exporter: Option<Arc<dwaar_analytics::otel::OtlpExporter>>,
    /// Fraction of requests to sample for tracing `[0.0, 1.0]`. 0.0 = off.
    trace_sample_ratio: f64,
}

/// Registries consulted by the proxy hot path, populated by the gRPC
/// control plane in `dwaar-cli::main`.
///
/// The proxy holds `Arc`s — cloning is free. When no registry is needed
/// (no split / no header rule), the fast path is a plain `RouteTable`
/// lookup with no additional allocations or atomic loads.
#[derive(Clone)]
pub struct ControlPlaneHooks {
    pub splits: Arc<crate::registries::SplitRegistry>,
    pub header_rules: Arc<crate::registries::HeaderRuleRegistry>,
}

impl std::fmt::Debug for ControlPlaneHooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlPlaneHooks")
            .field("splits", &self.splits.len())
            .field("header_rules", &self.header_rules.len())
            .finish()
    }
}

/// Trait objects for decoupling the proxy from the gRPC crate.
///
/// The proxy lives in `dwaar-core` and must not pull in `dwaar-grpc`
/// (which itself depends on `dwaar-core`). The gRPC crate provides
/// implementations of these traits that plug in at startup; unit tests can
/// substitute no-op doubles without wiring gRPC at all.
pub trait RequestOutcomeSink: std::fmt::Debug + Send + Sync {
    /// Record a completed request. Called once per response from
    /// `logging()`. Implementations must be fast enough to run on the hot
    /// path — typically a per-domain detector wrapped in a parking-lot
    /// mutex, which serialises one mutex per domain.
    fn record(&self, domain: &str, status: u16, latency: std::time::Duration);
}

pub trait MirrorDispatcher: std::fmt::Debug + Send + Sync {
    /// Fire a fire-and-forget mirror clone of a completed request. The
    /// dispatcher MUST NOT await the mirror's response on the primary
    /// request's critical path — it SHOULD spawn a detached tokio task.
    fn mirror(&self, domain: &str, method: &str, path: &str, headers: &[(String, String)]);
}

#[allow(clippy::too_many_arguments)]
impl DwaarProxy {
    pub fn new(
        route_table: Arc<ArcSwap<RouteTable>>,
        challenge_solver: Option<Arc<ChallengeSolver>>,
        log_sender: Option<LogSender>,
        beacon_sender: Option<BeaconSender>,
        agg_sender: Option<AggSender>,
        geo_lookup: Option<Arc<dwaar_geo::GeoLookup>>,
        plugin_chain: Arc<PluginChain>,
        prometheus: Option<Arc<dwaar_analytics::prometheus::PrometheusMetrics>>,
        cache_backend: Option<crate::cache::SharedCacheBackend>,
        keepalive_secs: u64,
        body_timeout_secs: u64,
        h3_enabled: bool,
    ) -> Self {
        Self {
            route_table,
            challenge_solver,
            log_sender,
            beacon_sender,
            agg_sender,
            geo_lookup,
            plugin_chain,
            prometheus,
            cache_backend,
            keepalive_secs,
            body_timeout: std::time::Duration::from_secs(body_timeout_secs),
            h3_enabled,
            control_plane: None,
            outcome_sink: None,
            mirror_dispatcher: None,
            otlp_exporter: None,
            trace_sample_ratio: 1.0,
        }
    }

    /// Install the gRPC control-plane registries so Wheel #2 Weeks 4-5
    /// behaviours (traffic splits, header rules, mirror traffic, anomaly
    /// events) run on every request. Safe to call once at startup after
    /// `new()`.
    #[must_use]
    pub fn with_control_plane(mut self, hooks: ControlPlaneHooks) -> Self {
        self.control_plane = Some(hooks);
        self
    }

    /// Register an anomaly-detection sink. The proxy calls `record()` once
    /// per completed request with the final status and wall-clock latency.
    #[must_use]
    pub fn with_outcome_sink(mut self, sink: Arc<dyn RequestOutcomeSink>) -> Self {
        self.outcome_sink = Some(sink);
        self
    }

    /// Register a mirror dispatcher.
    #[must_use]
    pub fn with_mirror_dispatcher(mut self, dispatcher: Arc<dyn MirrorDispatcher>) -> Self {
        self.mirror_dispatcher = Some(dispatcher);
        self
    }

    /// Install the OTLP exporter. When set, one ingress span is recorded per
    /// completed request in `logging()`. The exporter's flush loop runs as a
    /// separate Pingora `BackgroundService` — the proxy only calls `record()`.
    #[must_use]
    pub fn with_otlp_exporter(
        mut self,
        exporter: Arc<dwaar_analytics::otel::OtlpExporter>,
        sample_ratio: f64,
    ) -> Self {
        self.otlp_exporter = Some(exporter);
        self.trace_sample_ratio = sample_ratio.clamp(0.0, 1.0);
        self
    }
}

impl DwaarProxy {
    fn is_tls_connection(session: &Session) -> bool {
        session
            .downstream_session
            .digest()
            .and_then(|d| d.ssl_digest.as_ref())
            .is_some()
    }

    /// Look up the header-rule registry for `domain` and, if every
    /// `(header_name, expected_value)` pair matches the incoming request
    /// headers, return the override upstream address. Returns `None` when
    /// no rule is installed or when the match fails.
    ///
    /// The lookup closure reads case-insensitively and consults
    /// `session.req_header().headers`. A stored expected value of `""` is
    /// interpreted as "accept any non-empty value" (presence match) — this
    /// matches the pb→registry translation in `dwaar-grpc::routing`.
    fn apply_header_rule_override(
        rules: &crate::registries::HeaderRuleRegistry,
        domain: &str,
        session: &Session,
    ) -> Option<SocketAddr> {
        let cfg = rules.snapshot_for(domain)?;
        let req = session.req_header();
        let matched = cfg.matches(|name| {
            req.headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        });
        // "Presence-only" match: when any expected value is empty, require
        // that header to be present with ANY non-empty value. We do that
        // check here because `HeaderRuleConfig::matches` treats empty as an
        // exact-equal on empty, which a real header never is.
        let matched = matched
            || cfg.header_match.iter().all(|(name, expected)| {
                if expected.is_empty() {
                    req.headers
                        .get(name.as_str())
                        .and_then(|v| v.to_str().ok())
                        .is_some_and(|v| !v.is_empty())
                } else {
                    req.headers.get(name.as_str()).and_then(|v| v.to_str().ok())
                        == Some(expected.as_str())
                }
            });
        if !matched {
            return None;
        }
        cfg.socket_addr()
    }

    /// Spawn a fire-and-forget mirror of the current request. The
    /// dispatcher receives method, path, and headers (as a plain vec so it
    /// is cheap to move across a task boundary) and decides internally
    /// whether to mirror based on `sample_rate_bps`. Mirror failures
    /// cannot influence the primary response.
    fn spawn_mirror_request(dispatcher: &dyn MirrorDispatcher, domain: &str, session: &Session) {
        let req = session.req_header();
        let method = req.method.as_str().to_string();
        let path = req
            .uri
            .path_and_query()
            .map_or_else(|| "/".to_string(), std::string::ToString::to_string);
        // Small, bounded vec — capped implicitly by the request header set
        // the proxy already accepted.
        let headers: Vec<(String, String)> = req
            .headers
            .iter()
            .filter_map(|(n, v)| {
                v.to_str()
                    .ok()
                    .map(|s| (n.as_str().to_string(), s.to_string()))
            })
            .collect();
        dispatcher.mirror(domain, &method, &path, &headers);
    }

    fn https_redirect_domain(&self, session: &Session, ctx: &RequestContext) -> Option<String> {
        if Self::is_tls_connection(session) {
            return None;
        }

        // ACME HTTP-01 challenges are GET-only per RFC 8555 §8.3. Gating the
        // bypass by method prevents a cross-protocol request smuggling surface
        // where a non-GET to this prefix would skip the HTTPS redirect.
        if ctx.plugin_ctx.method == "GET"
            && ctx
                .plugin_ctx
                .path
                .starts_with("/.well-known/acme-challenge/")
        {
            return None;
        }

        // Lazily resolve the canonical domain from the route table only when
        // a redirect is actually needed. This avoids a String clone on every
        // non-redirect request. ArcSwap load + resolve is ~1ns lock-free.
        if ctx.route_tls {
            self.route_table
                .load()
                .resolve(ctx.plugin_ctx.host.as_deref().unwrap_or(""))
                .map(|r| r.domain.clone())
        } else {
            None
        }
    }

    async fn send_https_redirect(
        &self,
        session: &mut Session,
        ctx: &RequestContext,
        canonical_domain: &str,
    ) -> Result<bool> {
        let safe_path = sanitize_redirect_path(&ctx.plugin_ctx.path);
        let location = format!("https://{canonical_domain}{safe_path}");

        debug!(
            request_id = %ctx.request_id(),
            location = %location,
            "redirecting HTTP → HTTPS"
        );

        let mut resp = ResponseHeader::build(301, Some(3))?;
        resp.insert_header("Location", &location)
            .map_err(|e| Error::explain(HTTPStatus(500), format!("bad redirect header: {e}")))?;
        resp.insert_header("Content-Length", "0")
            .map_err(|e| Error::explain(HTTPStatus(500), format!("bad header: {e}")))?;
        resp.insert_header("Connection", "close")
            .map_err(|e| Error::explain(HTTPStatus(500), format!("bad header: {e}")))?;

        session.write_response_header(Box::new(resp), true).await?;
        Ok(true)
    }

    async fn handle_beacon(&self, session: &mut Session, ctx: &RequestContext) -> Result<bool> {
        // Cross-origin beacon guard: if the browser sent an Origin header, verify
        // it matches the host we're serving. A missing Origin is allowed — it means
        // the request came from a same-origin context (server-rendered page, curl,
        // etc.) where browsers don't add the header. A present but mismatched Origin
        // is a cross-origin POST from a foreign page and must be rejected.
        if let Some(origin_val) = session.req_header().headers.get("origin") {
            let origin_str = origin_val.to_str().unwrap_or("");
            let expected_host = ctx.plugin_ctx.host.as_deref().unwrap_or("");
            // The Origin header is scheme://host[:port]. We check whether the host
            // portion of the origin contains our expected host rather than doing a
            // full URL parse so we avoid a dependency purely for this guard.
            let host_in_origin = origin_str
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                // Strip any trailing path (origin never has a path, but be safe)
                .split('/')
                .next()
                .unwrap_or("");
            // Compare host ignoring port (e.g. "example.com:3000" matches "example.com").
            let origin_host_no_port = host_in_origin.split(':').next().unwrap_or("");
            if !expected_host.is_empty() && origin_host_no_port != expected_host {
                warn!(
                    request_id = %ctx.request_id(),
                    origin = %origin_str,
                    expected = %expected_host,
                    "beacon rejected: Origin does not match serving host"
                );
                let resp = ResponseHeader::build(403, Some(0))?;
                session.write_response_header(Box::new(resp), true).await?;
                return Ok(true);
            }
        }

        if let Some(ref sender) = self.beacon_sender {
            let mut body = Vec::with_capacity(1024);
            while let Ok(Some(chunk)) = session.downstream_session.read_request_body().await {
                // Reject oversized beacons with 413 — never parse truncated data.
                if body.len().saturating_add(chunk.len()) > beacon::MAX_BEACON_SIZE {
                    let resp = ResponseHeader::build(413, Some(0))?;
                    session.write_response_header(Box::new(resp), true).await?;
                    return Ok(true);
                }
                body.extend_from_slice(&chunk);
            }

            match beacon::parse_beacon(&body) {
                Ok(raw) => {
                    // --- C-04: HMAC verification ---------------------------
                    // Every beacon must carry a server-issued nonce + sig
                    // (see `dwaar_analytics::auth`). Missing or invalid
                    // tokens are silently rejected with 401 at trace level
                    // so repeated failures during an attack don't flood
                    // logs. The Origin check earlier in this handler is
                    // defence-in-depth — HMAC is the authoritative gate.
                    let host = ctx.plugin_ctx.host.clone().unwrap_or_default();
                    let nonce = raw.nonce.as_deref().unwrap_or("");
                    let sig = raw.sig.as_deref().unwrap_or("");
                    if !dwaar_analytics::auth::verify(nonce, sig, &host) {
                        trace!(
                            request_id = %ctx.request_id(),
                            "beacon rejected: HMAC verification failed"
                        );
                        let resp = ResponseHeader::build(401, Some(0))?;
                        session.write_response_header(Box::new(resp), true).await?;
                        return Ok(true);
                    }

                    let client_ip = ctx
                        .plugin_ctx
                        .client_ip
                        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
                    let event = BeaconEvent::from_raw(raw, client_ip, host.to_string());
                    let _ = sender.try_send(event);
                    debug!(request_id = %ctx.request_id(), "beacon collected");
                }
                Err(msg) => {
                    warn!(request_id = %ctx.request_id(), error = %msg, "invalid beacon");
                    let resp = ResponseHeader::build(400, Some(1))?;
                    session.write_response_header(Box::new(resp), true).await?;
                    return Ok(true);
                }
            }
        }

        let resp = ResponseHeader::build(204, Some(0))?;
        session.write_response_header(Box::new(resp), true).await?;
        Ok(true)
    }

    /// Send a static response for the `respond` directive (ISSUE-051).
    async fn send_static_response(session: &mut Session, status: u16, body: Bytes) -> Result<bool> {
        let end_of_body = body.is_empty();
        let mut resp = ResponseHeader::build(status, Some(1))?;
        if !end_of_body {
            let mut cl_buf = itoa::Buffer::new();
            resp.insert_header("Content-Length", cl_buf.format(body.len()))
                .map_err(|e| Error::explain(HTTPStatus(status), format!("bad header: {e}")))?;
        }
        session
            .write_response_header(Box::new(resp), end_of_body)
            .await?;
        if !end_of_body {
            session.write_response_body(Some(body), true).await?;
        }
        Ok(true)
    }

    /// Send a plugin-generated short-circuit response to the client.
    async fn send_plugin_response(
        session: &mut Session,
        plugin_resp: dwaar_plugins::plugin::PluginResponse,
    ) -> Result<bool> {
        let mut resp = ResponseHeader::build(plugin_resp.status, Some(plugin_resp.headers.len()))?;
        for (name, value) in &plugin_resp.headers {
            resp.insert_header(*name, value.as_str()).map_err(|e| {
                Error::explain(
                    HTTPStatus(plugin_resp.status),
                    format!("plugin response header error: {e}"),
                )
            })?;
        }
        let end_of_body = plugin_resp.body.is_empty();
        session
            .write_response_header(Box::new(resp), end_of_body)
            .await?;
        if !end_of_body {
            session
                .write_response_body(Some(plugin_resp.body), true)
                .await?;
        }
        Ok(true)
    }
}

#[async_trait]
#[allow(clippy::too_many_lines)]
impl ProxyHttp for DwaarProxy {
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX {
        RequestContext::new()
    }

    // -- Cache lifecycle hooks (ISSUE-073) ------------------------------------

    /// Enable Pingora's cache subsystem for requests that matched a `cache {}` block.
    /// Called by Pingora after `request_filter()` returns, so `ctx.cache_enabled`
    /// and `ctx.cache_config` are already populated.
    fn request_cache_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        if !ctx.cache_enabled {
            return Ok(());
        }
        let Some(ref shared) = self.cache_backend else {
            return Ok(());
        };
        let guard = shared.load();
        let Some(ref backend) = **guard else {
            return Ok(());
        };
        session.cache.enable(
            backend.storage,
            Some(backend.eviction),
            None, // no predictor
            Some(backend.lock),
            None, // no option overrides
        );
        ctx.cache_status = Some("MISS"); // default; refined by cache_hit_filter
        Ok(())
    }

    /// Build a cache key scoped to host + path + method so that different
    /// virtual hosts never share cache entries.
    fn cache_key_callback(&self, _session: &Session, ctx: &mut Self::CTX) -> Result<CacheKey> {
        let host = ctx.plugin_ctx.host.as_deref().unwrap_or("_unknown_");
        let path = ctx
            .effective_path
            .as_deref()
            .unwrap_or(ctx.plugin_ctx.path.as_str());
        let method = ctx.plugin_ctx.method.as_str();
        Ok(crate::cache::build_cache_key(host, path, method))
    }

    /// Decide whether the upstream response is cacheable by consulting
    /// Cache-Control headers and the per-route defaults.
    fn response_cache_filter(
        &self,
        session: &Session,
        resp: &ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<RespCacheable> {
        let Some(ref cache_cfg) = ctx.cache_config else {
            return Ok(RespCacheable::Uncacheable(NoCacheReason::NeverEnabled));
        };

        let defaults = crate::cache::make_cache_defaults(
            cache_cfg.default_ttl,
            cache_cfg.stale_while_revalidate,
        );
        // `from_resp_headers` expects `&http::response::Parts`; `ResponseHeader`
        // derefs to `Parts` via `AsRef`.
        let cc = CacheControl::from_resp_headers(resp.as_ref());
        let has_auth = session.req_header().headers.contains_key("authorization");
        Ok(resp_cacheable(
            cc.as_ref(),
            resp.clone(),
            has_auth,
            &defaults,
        ))
    }

    /// Serve stale responses per RFC 5861:
    /// - No error → stale-while-revalidate (background refresh in flight)
    /// - Upstream error → stale-if-error (serve stale as fallback)
    fn should_serve_stale(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
        error: Option<&pingora_error::Error>,
    ) -> bool {
        if error.is_none() {
            return ctx
                .cache_config
                .as_ref()
                .is_some_and(|c| c.stale_while_revalidate > 0);
        }
        // On upstream failure, any cache config implies willingness to serve stale
        ctx.cache_config.is_some()
    }

    /// Track cache hits: fresh responses are HIT, stale responses are STALE.
    /// Called by Pingora after a successful cache lookup, before the cached
    /// response is served.
    async fn cache_hit_filter(
        &self,
        _session: &mut Session,
        _meta: &pingora_cache::CacheMeta,
        _hit_handler: &mut pingora_cache::storage::HitHandler,
        is_fresh: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<pingora_cache::ForcedFreshness>>
    where
        Self::CTX: Send + Sync,
    {
        ctx.cache_status = if is_fresh { Some("HIT") } else { Some("STALE") };
        Ok(None)
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        // Slow loris protection (ISSUE-076): override Pingora defaults with
        // user-configured keepalive and body read timeouts. Headers are already
        // read by the time request_filter() runs, so `header` timeout is handled
        // by Pingora's built-in read_timeout during read_request(). The body
        // timeout applies to subsequent reads; keepalive applies between requests.
        session.set_keepalive(Some(self.keepalive_secs));
        session
            .downstream_session
            .set_read_timeout(Some(self.body_timeout));

        // --- Populate core identity fields ---
        ctx.plugin_ctx.client_ip = session
            .client_addr()
            .and_then(|addr| addr.as_inet())
            .map(std::net::SocketAddr::ip);

        ctx.plugin_ctx.is_tls = Self::is_tls_connection(session);

        // --- GeoIP lookup ---
        if let Some(ref geo) = self.geo_lookup
            && let Some(ip) = ctx.plugin_ctx.client_ip
        {
            ctx.plugin_ctx.country = geo.lookup_country(ip).map(CompactString::from);
        }

        // --- HTTP headers ---
        let header = session.req_header();

        ctx.plugin_ctx.host = header
            .headers
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(CompactString::from)
            .or_else(|| {
                header
                    .uri
                    .authority()
                    .map(|a| CompactString::from(a.as_str()))
            });

        ctx.plugin_ctx.method = CompactString::from(header.method.as_str());

        ctx.plugin_ctx.path = header.uri.path_and_query().map_or_else(
            || CompactString::from("/"),
            |pq| CompactString::from(pq.as_str()),
        );

        ctx.plugin_ctx.accept_encoding = header
            .headers
            .get(http::header::ACCEPT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .map_or_else(CompactString::default, CompactString::from);

        // --- WebSocket upgrade detection (ISSUE-068) ---
        // RFC 6455 §4.1: valid handshake has `Upgrade: websocket` (case-insensitive)
        // AND `Connection` header containing "upgrade". Dwaar doesn't validate the
        // full handshake (Sec-WebSocket-Key, version) — upstream decides to accept or reject.
        ctx.is_websocket = header
            .headers
            .get(http::header::UPGRADE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
            && header
                .headers
                .get(http::header::CONNECTION)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| {
                    v.split(',')
                        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
                });

        // gRPC detection (ISSUE-074): Content-Type starting with "application/grpc"
        // covers application/grpc, application/grpc+proto, application/grpc-web.
        // gRPC-Web is detected first so grpc_web_mode is set before is_grpc —
        // both flavors need HTTP/2 upstream and disabled body limits.
        if !ctx.is_websocket {
            let ct_value = header
                .headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok());

            if let Some(ct) = ct_value {
                ctx.grpc_web_mode = crate::grpc_web::detect_mode(ct);
            }
            ctx.is_grpc = ct_value.is_some_and(|ct| ct.starts_with("application/grpc"));
        }

        debug!(
            request_id = %ctx.request_id(),
            client_ip = ?ctx.plugin_ctx.client_ip,
            host = ?ctx.plugin_ctx.host,
            method = %ctx.plugin_ctx.method,
            path = %ctx.plugin_ctx.path,
            is_websocket = ctx.is_websocket,
            is_grpc = ctx.is_grpc,
            "request metadata extracted"
        );

        // --- Populate route-level plugin config ---
        // Look up the route before running plugins so rate_limit_rps and
        // under_attack flags are available to the plugin chain.
        if let Some(ref host) = ctx.plugin_ctx.host {
            let host_stripped = if host.starts_with('[') {
                // IPv6 bracket notation: [::1]:8080
                host.split(']')
                    .next()
                    .unwrap_or(host)
                    .trim_start_matches('[')
            } else {
                // IPv4 or hostname: example.com:8080
                host.rsplit_once(':').map_or(host.as_str(), |(h, _)| h)
            };
            let table = self.route_table.load();
            if let Some(route) = table.resolve(host_stripped) {
                // Route is being drained (removed in a config reload but still
                // has in-flight requests) — reject new connections immediately.
                if route.is_draining() {
                    warn!(
                        request_id = %ctx.request_id(),
                        domain = %route.domain,
                        "route is draining — rejecting new request with 502"
                    );
                    let mut resp = ResponseHeader::build(502, Some(2))?;
                    resp.insert_header("Content-Length", "0")
                        .map_err(|e| Error::explain(HTTPStatus(502), format!("bad header: {e}")))?;
                    resp.insert_header("Connection", "close")
                        .map_err(|e| Error::explain(HTTPStatus(502), format!("bad header: {e}")))?;
                    session.write_response_header(Box::new(resp), true).await?;
                    return Ok(true);
                }

                // Track this request for connection draining (ISSUE-075).
                // Incremented here, decremented in logging() when the request completes.
                route
                    .active_connections
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                ctx.drain_counter = Some(route.active_connections.clone());

                ctx.plugin_ctx.rate_limit_rps = route.rate_limit_rps();
                ctx.plugin_ctx.route_domain = Some(CompactString::from(route.domain.as_str()));
                ctx.plugin_ctx.under_attack = route.under_attack();
                ctx.route_upstream = route.upstream();
                ctx.route_tls = route.tls;

                // Wheel #2 control-plane hooks (Week 4). Consulted in order
                // of specificity: header rules win over traffic splits. Both
                // are no-ops when no matching config is installed — the
                // happy path adds at most two `ArcSwap` loads on this hot
                // line, and only when `control_plane` is wired at startup.
                if let Some(ref cp) = self.control_plane {
                    if let Some(override_addr) =
                        Self::apply_header_rule_override(&cp.header_rules, &route.domain, session)
                    {
                        debug!(
                            request_id = %ctx.request_id(),
                            domain = %route.domain,
                            override_upstream = %override_addr,
                            "header-rule override applied"
                        );
                        ctx.route_upstream = Some(override_addr);
                    } else if let Some(weighted) = cp.splits.choose(route.domain.as_str())
                        && let Ok(addr) = weighted.upstream_addr.parse::<SocketAddr>()
                    {
                        debug!(
                            request_id = %ctx.request_id(),
                            domain = %route.domain,
                            upstream = %addr,
                            deploy_id = %weighted.deploy_id,
                            "traffic split applied"
                        );
                        ctx.route_upstream = Some(addr);
                    }
                }

                // Fire-and-forget mirror clone — Wheel #2 Week 4. The
                // dispatcher itself handles sample_rate_bps + spawns a
                // detached tokio task, so no work runs on the primary
                // response path beyond a single atomic load.
                if let Some(ref dispatcher) = self.mirror_dispatcher {
                    Self::spawn_mirror_request(dispatcher.as_ref(), &route.domain, session);
                }

                // Path-based handler resolution (ISSUE-050).
                // Iterate handler blocks, find the first matching one (handle/handle_path)
                // or run all matching (route). Cache matched handler data in ctx.
                let request_path = ctx.plugin_ctx.path.as_str();
                for block in &route.handlers {
                    let Some(prefix_len) = block.matcher.matches(request_path) else {
                        continue;
                    };

                    // handle_path: strip matched prefix from the effective path
                    if block.kind == crate::route::BlockKind::HandlePath && prefix_len > 0 {
                        let stripped = &request_path[prefix_len..];
                        let effective = if stripped.is_empty() { "/" } else { stripped };
                        ctx.effective_path = Some(CompactString::from(effective));
                    }

                    // Cache handler-specific data (Guardrail #27 — no second ArcSwap load)
                    match &block.handler {
                        crate::route::Handler::StaticResponse { status, body } => {
                            ctx.static_response = Some((*status, body.clone()));
                        }
                        crate::route::Handler::FileServer { root, browse } => {
                            ctx.file_server = Some((root.clone(), *browse));
                        }
                        crate::route::Handler::ReverseProxy { upstream, .. } => {
                            ctx.route_upstream = Some(*upstream);
                            ctx.quic_capable = true;
                        }
                        crate::route::Handler::ReverseProxyPool { pool, .. } => {
                            ctx.quic_capable = true;

                            // Cookie sticky sessions: read _dwaar_sticky cookie and
                            // use it to pin the visitor to a specific backend.
                            if pool.policy() == crate::upstream::LbPolicy::Cookie {
                                let cookie_val = session
                                    .req_header()
                                    .headers
                                    .get("cookie")
                                    .and_then(|v| v.to_str().ok())
                                    .and_then(|cookies| {
                                        extract_cookie_value(
                                            cookies,
                                            crate::upstream::STICKY_COOKIE_NAME,
                                        )
                                    })
                                    .map(String::from);

                                if let Some((addr, needs_set)) =
                                    pool.select_cookie(cookie_val.as_deref())
                                {
                                    ctx.route_upstream = Some(addr);
                                    if needs_set {
                                        ctx.sticky_set_cookie = Some(
                                            crate::upstream::UpstreamPool::sticky_set_cookie(addr),
                                        );
                                    }
                                }
                            } else {
                                ctx.route_upstream = pool.select(ctx.plugin_ctx.client_ip);
                            }

                            ctx.upstream_pool = Some(pool.clone());

                            // Atomically claim the connection slot. `select()` is a
                            // pure read, so a concurrent request may have filled the
                            // last slot between our check and this CAS. If we lose
                            // that race, return 503 now rather than letting the
                            // request hit the backend over its cap.
                            if let Some(addr) = ctx.route_upstream
                                && !pool.acquire_connection(addr)
                            {
                                warn!(
                                    request_id = %ctx.request_id(),
                                    upstream = %addr,
                                    "upstream at max_conns — returning 503"
                                );
                                let mut resp = ResponseHeader::build(503, Some(0))?;
                                resp.insert_header("Content-Length", "0")?;
                                resp.insert_header("Retry-After", "1")?;
                                session.write_response_header(Box::new(resp), true).await?;
                                return Ok(true);
                            }
                        }
                        crate::route::Handler::FastCgi { upstream, root } => {
                            ctx.route_upstream = Some(*upstream);
                            ctx.fastcgi_root = Some(root.clone());
                        }
                    }

                    // Cache auth configs
                    if let Some(ref auth) = block.basic_auth {
                        ctx.basic_auth = Some(auth.clone());
                    }
                    if let Some(ref fwd) = block.forward_auth {
                        ctx.forward_auth = Some(fwd.clone());
                    }

                    // Cache response-phase intercept rules (ISSUE-067).
                    // Cloning a small Vec of compiled structs here is cheaper than
                    // re-loading the ArcSwap in response_filter().
                    if !block.intercepts.is_empty() {
                        ctx.intercepts.clone_from(&block.intercepts);
                    }
                    if let Some(ref crh) = block.copy_response_headers {
                        ctx.copy_response_headers = Some(crh.clone());
                    }

                    // IP filter config (ISSUE-071)
                    if let Some(ref filter) = block.ip_filter {
                        ctx.plugin_ctx.ip_filter = Some(filter.clone());
                    }

                    // Body size limits (ISSUE-069, ISSUE-070)
                    if let Some(limit) = block.request_body_max_size {
                        ctx.request_body_max_size = limit;
                    }
                    if let Some(limit) = block.response_body_max_size {
                        ctx.response_body_max_size = limit;
                    }

                    // Route-config-driven gRPC: trust the block's `is_grpc_route` flag
                    // first, then fall back to the Content-Type header set earlier.
                    // This lets the operator mark a route as gRPC without relying on
                    // clients always sending the correct Content-Type.
                    ctx.is_grpc = block.is_grpc_route
                        || session
                            .req_header()
                            .headers
                            .get("content-type")
                            .and_then(|v| v.to_str().ok())
                            .is_some_and(|ct| ct.starts_with("application/grpc"));

                    // gRPC streaming RPCs are unbounded by nature, but we cap at 1 GiB
                    // rather than u64::MAX to prevent a misconfigured or malicious
                    // client from exhausting memory on a route that happens to send
                    // grpc Content-Type without actually being a controlled gRPC service.
                    if ctx.is_grpc {
                        ctx.request_body_max_size = ctx.request_body_max_size.max(1u64 << 30);
                        ctx.response_body_max_size = ctx.response_body_max_size.max(1u64 << 30);
                    }

                    // Cache config (ISSUE-073) — only for GET requests on matching paths
                    if let Some(ref cache_cfg) = block.cache {
                        let path = ctx.effective_path.as_deref().unwrap_or(request_path);
                        if cache_cfg.path_matches(path)
                            && !ctx.is_websocket
                            && !ctx.is_grpc
                            && ctx.plugin_ctx.method == "GET"
                        {
                            ctx.cache_enabled = true;
                            ctx.cache_config = Some(cache_cfg.clone());
                        }
                    }

                    // Evaluate map directives to populate VarSlots (ISSUE-056).
                    //
                    // Only clone `route.var_defaults` when `maps` is non-empty —
                    // i.e., when we actually need a mutable per-request copy.
                    // With `maps` empty, the consumer below falls back to
                    // `&route.var_defaults` directly, eliminating a per-request
                    // `Vec<Option<CompactString>>` deep clone on routes that
                    // declare `vars` defaults without any `map` rules (#126).
                    if !block.maps.is_empty() {
                        let mut slots = route.var_defaults.clone();
                        let map_tmpl_ctx = TemplateContext {
                            host: ctx.plugin_ctx.host.as_deref().unwrap_or(""),
                            method: ctx.plugin_ctx.method.as_str(),
                            path: request_path,
                            uri: request_path,
                            query: "",
                            scheme: if ctx.route_tls { "https" } else { "http" },
                            remote_host: "",
                            remote_port: 0,
                            request_id: ctx.request_id(),
                            upstream_host: "",
                            upstream_port: 0,
                            tls_server_name: "",
                            vars: None,
                            regex_captures: None,
                            regex_matcher_name: None,
                        };
                        for map in &block.maps {
                            if let Some(val) = map.evaluate(&map_tmpl_ctx) {
                                slots.set(map.dest_slot, CompactString::from(val));
                            }
                        }
                        ctx.var_slots = Some(slots);
                    }

                    // Apply rewrite rules (with template evaluation)
                    if !block.rewrites.is_empty() {
                        let mut path: CompactString =
                            ctx.effective_path.as_deref().unwrap_or(request_path).into();

                        for rule in &block.rewrites {
                            // Build template context from current path state.
                            // Rebuilt per-iteration so the path reference stays valid
                            // after rewrites mutate it.
                            let tmpl_ctx = TemplateContext {
                                host: ctx.plugin_ctx.host.as_deref().unwrap_or(""),
                                method: ctx.plugin_ctx.method.as_str(),
                                path: &path,
                                uri: &path,
                                query: "",
                                scheme: if ctx.route_tls { "https" } else { "http" },
                                remote_host: "",
                                remote_port: 0,
                                request_id: ctx.request_id(),
                                upstream_host: "",
                                upstream_port: 0,
                                tls_server_name: "",
                                // When `map` directives fired, read vars from the mutated
                                // per-request copy on `ctx.var_slots`. Otherwise fall back
                                // to `&route.var_defaults` directly — avoids a per-request
                                // `VarSlots::clone()` on routes that declare `vars` without
                                // any `map` rules (#126). `route.var_defaults` is always
                                // present (possibly empty) so the reference is always valid.
                                vars: ctx.var_slots.as_ref().or(Some(&route.var_defaults)),
                                regex_captures: None,
                                regex_matcher_name: None,
                            };
                            if let Some(rewritten) = rule.apply(&path, Some(&tmpl_ctx)) {
                                path = rewritten;
                            }
                        }
                        ctx.effective_path = Some(path);
                    }

                    // For handle/handle_path: first match wins — stop iterating
                    if block.kind != crate::route::BlockKind::Route {
                        break;
                    }
                }
            }
        }

        // --- Prometheus active connection tracking (ISSUE-072) ---
        if let Some(ref prom) = self.prometheus
            && let Some(ref host) = ctx.plugin_ctx.host
        {
            prom.connection_start(host);
        }

        // --- Request body size check (ISSUE-069) ---
        // Content-Length known: reject immediately without reading body.
        // Chunked requests without Content-Length are tracked in request_body_filter().
        if let Some(cl) = session
            .req_header()
            .headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            && cl > ctx.request_body_max_size
        {
            warn!(
                request_id = %ctx.request_id(),
                content_length = cl,
                limit = ctx.request_body_max_size,
                "request body exceeds limit — returning 413"
            );
            let mut resp = ResponseHeader::build(413, Some(2))?;
            resp.insert_header("Content-Length", "0")
                .map_err(|e| Error::explain(HTTPStatus(413), format!("bad header: {e}")))?;
            resp.insert_header("Connection", "close")
                .map_err(|e| Error::explain(HTTPStatus(413), format!("bad header: {e}")))?;
            session.write_response_header(Box::new(resp), true).await?;
            return Ok(true);
        }

        // --- Run plugin chain (bot detect, rate limit, under attack) ---
        if let Some(plugin_resp) = self
            .plugin_chain
            .run_request(session.req_header(), &mut ctx.plugin_ctx)
        {
            // The rate limiter sets `rate_limited` on ctx — no status code guessing.
            if ctx.plugin_ctx.rate_limited {
                // Surface attribution to the access log (#128). `&'static str`,
                // zero allocation.
                ctx.rejected_by = Some("rate_limit");
                if let Some(ref prom) = self.prometheus
                    && let Some(ref host) = ctx.plugin_ctx.host
                {
                    prom.rate_cache.record_rate_limit_rejected(host);
                }
            }
            debug!(
                request_id = %ctx.request_id(),
                status = plugin_resp.status,
                "plugin chain short-circuited request"
            );
            return Self::send_plugin_response(session, plugin_resp).await;
        }

        // Request passed rate limiting — record allowed metric (ISSUE-114).
        if ctx.plugin_ctx.rate_limit_rps.is_some()
            && let Some(ref prom) = self.prometheus
            && let Some(ref host) = ctx.plugin_ctx.host
        {
            prom.rate_cache.record_rate_limit_allowed(host);
        }

        // --- Basic auth check (ISSUE-046) ---
        // Auth config cached from the single ArcSwap load above (Guardrail #27).
        if let Some(ref auth_config) = ctx.basic_auth {
            let auth_header = session
                .req_header()
                .headers
                .get(http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok());
            if auth_config.verify(auth_header).is_none() {
                debug!(
                    request_id = %ctx.request_id(),
                    "basic auth failed — returning 401"
                );
                let mut resp = ResponseHeader::build(401, Some(2))?;
                resp.insert_header("WWW-Authenticate", auth_config.www_authenticate().as_str())
                    .map_err(|e| Error::explain(HTTPStatus(401), format!("bad header: {e}")))?;
                resp.insert_header("Content-Length", "0")
                    .map_err(|e| Error::explain(HTTPStatus(401), format!("bad header: {e}")))?;
                session.write_response_header(Box::new(resp), true).await?;
                return Ok(true);
            }
        }

        // --- Forward auth check (ISSUE-047) ---
        // Async subrequest to external auth service. Raw TCP HTTP/1.1.
        if let Some(ref fwd_config) = ctx.forward_auth {
            let ip_str = ctx.plugin_ctx.client_ip.map(|ip| ip.to_string());
            let auth_result = fwd_config
                .check(
                    &ctx.plugin_ctx.method,
                    &ctx.plugin_ctx.path,
                    ip_str.as_deref(),
                )
                .await;

            match auth_result {
                dwaar_plugins::forward_auth::AuthResult::Allowed(headers) => {
                    // Store copied headers — applied in upstream_request_filter
                    ctx.forward_auth_headers = headers.into_iter().collect();
                    debug!(
                        request_id = %ctx.request_id(),
                        headers_copied = ctx.forward_auth_headers.len(),
                        "forward auth allowed"
                    );
                }
                dwaar_plugins::forward_auth::AuthResult::Denied { status, body } => {
                    // Log the raw auth body server-side only — never relay it to the
                    // client, which could leak internal error messages or stack traces.
                    if body.is_empty() {
                        debug!(
                            request_id = %ctx.request_id(),
                            status,
                            "forward auth denied"
                        );
                    } else {
                        debug!(
                            request_id = %ctx.request_id(),
                            status,
                            body = %String::from_utf8_lossy(&body),
                            "forward auth denied (auth service body suppressed from client)"
                        );
                    }
                    // Send a generic response body — auth service internals stay server-side.
                    let generic_body: &[u8] = if status == 401 {
                        b"Unauthorized"
                    } else {
                        b"Forbidden"
                    };
                    let mut resp = ResponseHeader::build(status, Some(1))?;
                    let mut cl_buf = itoa::Buffer::new();
                    resp.insert_header("Content-Length", cl_buf.format(generic_body.len()))
                        .map_err(|e| {
                            Error::explain(HTTPStatus(status), format!("bad header: {e}"))
                        })?;
                    resp.insert_header("Content-Type", "text/plain")
                        .map_err(|e| {
                            Error::explain(HTTPStatus(status), format!("bad header: {e}"))
                        })?;
                    session.write_response_header(Box::new(resp), false).await?;
                    session
                        .write_response_body(Some(Bytes::from_static(generic_body)), true)
                        .await?;
                    return Ok(true);
                }
                dwaar_plugins::forward_auth::AuthResult::Error(msg) => {
                    warn!(
                        request_id = %ctx.request_id(),
                        error = %msg,
                        "forward auth service error — returning 502"
                    );
                    let resp = ResponseHeader::build(502, Some(0))?;
                    session.write_response_header(Box::new(resp), true).await?;
                    return Ok(true);
                }
            }
        }

        // --- Static response handler (respond directive, ISSUE-051) ---
        // Populated from the single ArcSwap load above — no second lookup (Guardrail #27).
        if let Some((status, ref body)) = ctx.static_response {
            debug!(
                request_id = %ctx.request_id(),
                status,
                "serving static response"
            );
            return Self::send_static_response(session, status, body.clone()).await;
        }

        // --- File server handler (ISSUE-048) ---
        if let Some((ref root, browse)) = ctx.file_server {
            let request_path = ctx
                .effective_path
                .as_deref()
                .unwrap_or(ctx.plugin_ctx.path.as_str());

            match crate::file_server::serve_file(root, request_path, browse).await {
                crate::file_server::FileResponse::Found {
                    body,
                    content_type,
                    content_length,
                    etag,
                    ..
                } => {
                    debug!(
                        request_id = %ctx.request_id(),
                        path = %request_path,
                        content_type,
                        "serving static file"
                    );
                    let mut resp = ResponseHeader::build(200, Some(4))?;
                    resp.insert_header("Content-Type", content_type)
                        .map_err(|e| Error::explain(HTTPStatus(200), format!("bad header: {e}")))?;
                    let mut cl_buf = itoa::Buffer::new();
                    resp.insert_header("Content-Length", cl_buf.format(content_length))
                        .map_err(|e| Error::explain(HTTPStatus(200), format!("bad header: {e}")))?;
                    resp.insert_header("Accept-Ranges", "bytes")
                        .map_err(|e| Error::explain(HTTPStatus(200), format!("bad header: {e}")))?;
                    if let Some(tag) = etag {
                        resp.insert_header("ETag", &tag).map_err(|e| {
                            Error::explain(HTTPStatus(200), format!("bad header: {e}"))
                        })?;
                    }
                    session.write_response_header(Box::new(resp), false).await?;
                    session.write_response_body(Some(body), true).await?;
                    return Ok(true);
                }
                crate::file_server::FileResponse::DirectoryListing { body } => {
                    let mut resp = ResponseHeader::build(200, Some(2))?;
                    resp.insert_header("Content-Type", "text/html; charset=utf-8")
                        .map_err(|e| Error::explain(HTTPStatus(200), format!("bad header: {e}")))?;
                    let mut cl_buf = itoa::Buffer::new();
                    resp.insert_header("Content-Length", cl_buf.format(body.len()))
                        .map_err(|e| Error::explain(HTTPStatus(200), format!("bad header: {e}")))?;
                    session.write_response_header(Box::new(resp), false).await?;
                    session.write_response_body(Some(body), true).await?;
                    return Ok(true);
                }
                crate::file_server::FileResponse::Forbidden => {
                    let resp = ResponseHeader::build(403, Some(0))?;
                    session.write_response_header(Box::new(resp), true).await?;
                    return Ok(true);
                }
                crate::file_server::FileResponse::NotFound => {
                    let resp = ResponseHeader::build(404, Some(0))?;
                    session.write_response_header(Box::new(resp), true).await?;
                    return Ok(true);
                }
            }
        }

        // --- FastCGI handler (php_fastcgi directive, ISSUE-053) ---
        // Handled entirely here — php-fpm speaks FastCGI, not HTTP, so we bypass
        // Pingora's upstream machinery and write the response directly.
        if let (Some(fcgi_root), Some(upstream)) = (&ctx.fastcgi_root, ctx.route_upstream) {
            let request_path = ctx
                .effective_path
                .as_deref()
                .unwrap_or(ctx.plugin_ctx.path.as_str());
            let (path, query) = request_path.split_once('?').unwrap_or((request_path, ""));
            let client_ip = ctx
                .plugin_ctx
                .client_ip
                .map_or_else(String::new, |ip| ip.to_string());
            let host = ctx.plugin_ctx.host.as_deref().unwrap_or("localhost");

            // Read request body for POST — reject with 413 if it exceeds the limit.
            let mut body_buf = Vec::new();
            while let Ok(Some(chunk)) = session.downstream_session.read_request_body().await {
                body_buf.extend_from_slice(&chunk);
                if body_buf.len() as u64 > ctx.request_body_max_size {
                    let mut resp = ResponseHeader::build(413, Some(0))?;
                    resp.insert_header("Content-Length", "0")?;
                    session.write_response_header(Box::new(resp), true).await?;
                    return Ok(true);
                }
            }

            let fcgi_req = crate::fastcgi::FastCgiRequest {
                upstream,
                root: fcgi_root,
                request_path: path,
                query_string: query,
                method: &ctx.plugin_ctx.method,
                request_body: &body_buf,
                server_name: host,
                remote_addr: &client_ip,
                is_tls: ctx.route_tls,
            };
            match crate::fastcgi::execute(&fcgi_req).await {
                Ok(fcgi_resp) => {
                    debug!(
                        request_id = %ctx.request_id(),
                        status = fcgi_resp.status,
                        "FastCGI response"
                    );
                    let mut resp =
                        ResponseHeader::build(fcgi_resp.status, Some(fcgi_resp.headers.len() + 1))?;
                    for (name, value) in &fcgi_resp.headers {
                        if let (Ok(hn), Ok(hv)) = (
                            http::HeaderName::from_bytes(name.as_bytes()),
                            http::HeaderValue::from_str(value),
                        ) {
                            resp.append_header(hn, hv).map_err(|e| {
                                Error::explain(
                                    HTTPStatus(fcgi_resp.status),
                                    format!("FastCGI header: {e}"),
                                )
                            })?;
                        }
                    }
                    let end_of_body = fcgi_resp.body.is_empty();
                    if !end_of_body {
                        let mut cl_buf = itoa::Buffer::new();
                        resp.insert_header("Content-Length", cl_buf.format(fcgi_resp.body.len()))
                            .map_err(|e| {
                                Error::explain(HTTPStatus(fcgi_resp.status), format!("header: {e}"))
                            })?;
                    }
                    session
                        .write_response_header(Box::new(resp), end_of_body)
                        .await?;
                    if !end_of_body {
                        session
                            .write_response_body(Some(fcgi_resp.body), true)
                            .await?;
                    }
                    return Ok(true);
                }
                Err(msg) => {
                    warn!(
                        request_id = %ctx.request_id(),
                        error = %msg,
                        "FastCGI error — returning 502"
                    );
                    let resp = ResponseHeader::build(502, Some(0))?;
                    session.write_response_header(Box::new(resp), true).await?;
                    return Ok(true);
                }
            }
        }

        // --- Analytics JS serving (ISSUE-024) ---
        if ctx.plugin_ctx.path == "/_dwaar/a.js" {
            debug!(request_id = %ctx.request_id(), "serving analytics JS from memory");
            let mut resp = ResponseHeader::build(200, Some(3))?;
            resp.insert_header("Content-Type", "application/javascript")
                .map_err(|e| Error::explain(HTTPStatus(500), format!("bad header: {e}")))?;
            resp.insert_header("Cache-Control", "public, max-age=86400")
                .map_err(|e| Error::explain(HTTPStatus(500), format!("bad header: {e}")))?;
            let mut cl_buf = itoa::Buffer::new();
            resp.insert_header("Content-Length", cl_buf.format(ANALYTICS_JS.len()))
                .map_err(|e| Error::explain(HTTPStatus(500), format!("bad header: {e}")))?;
            session.write_response_header(Box::new(resp), false).await?;
            session
                .write_response_body(Some(bytes::Bytes::from_static(ANALYTICS_JS)), true)
                .await?;
            return Ok(true);
        }

        // --- Beacon collection (ISSUE-027) ---
        if ctx.plugin_ctx.path == "/_dwaar/collect" && ctx.plugin_ctx.method == "POST" {
            return self.handle_beacon(session, ctx).await;
        }

        // --- ACME HTTP-01 challenge response ---
        if let Some(ref solver) = self.challenge_solver {
            const CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";
            if ctx.plugin_ctx.path.starts_with(CHALLENGE_PREFIX) {
                let token = &ctx.plugin_ctx.path[CHALLENGE_PREFIX.len()..];
                // Pass the source IP so the solver can throttle per-IP
                // bursts during active issuance (audit finding L-05).
                // `None` just bypasses the throttle, which is fine for
                // unit tests and loopback-only sessions that have no
                // downstream IP recorded on the ctx.
                if ChallengeSolver::is_valid_token(token)
                    && let Some(key_auth) = solver.get(token, ctx.plugin_ctx.client_ip)
                {
                    debug!(
                        request_id = %ctx.request_id(),
                        token = %token,
                        "serving ACME challenge response"
                    );
                    let mut resp = ResponseHeader::build(200, Some(1))?;
                    let mut cl_buf = itoa::Buffer::new();
                    resp.insert_header("Content-Length", cl_buf.format(key_auth.len()))
                        .map_err(|e| Error::explain(HTTPStatus(500), format!("bad header: {e}")))?;
                    session.write_response_header(Box::new(resp), false).await?;
                    session
                        .write_response_body(Some(bytes::Bytes::from(key_auth)), true)
                        .await?;
                    return Ok(true);
                }
            }
        }

        // Host header is required for routing
        if ctx.plugin_ctx.host.is_none() {
            warn!(request_id = %ctx.request_id(), "missing Host header — returning 400");
            let resp = ResponseHeader::build(400, Some(1))?;
            session.write_response_header(Box::new(resp), true).await?;
            return Ok(true);
        }

        // --- HTTP→HTTPS redirect (ISSUE-016) ---
        if let Some(canonical_domain) = self.https_redirect_domain(session, ctx) {
            return self
                .send_https_redirect(session, ctx, &canonical_domain)
                .await;
        }

        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        // Exponential backoff between retry attempts — sleep before re-selecting.
        if ctx.retry_count > 0 {
            let delay = crate::upstream::RetryConfig::backoff_delay(ctx.retry_count - 1);
            debug!(
                request_id = %ctx.request_id(),
                attempt = ctx.retry_count,
                delay = ?delay,
                "backoff before retry"
            );
            tokio::time::sleep(delay).await;
        }

        // Use the route resolved in request_filter() to avoid a second ArcSwap load
        let upstream = if let Some(addr) = ctx.route_upstream {
            addr
        } else {
            // Defensive fallback — should not happen in normal flow
            let host = ctx.plugin_ctx.host.as_deref().map_or("", |h| {
                if h.starts_with('[') {
                    h.split(']').next().unwrap_or(h).trim_start_matches('[')
                } else {
                    h.rsplit_once(':').map_or(h, |(host, _)| host)
                }
            });
            let table = self.route_table.load();
            let route = table.resolve(host).ok_or_else(|| {
                warn!(host = %host, request_id = %ctx.request_id(), "no route for host");
                Error::explain(
                    HTTPStatus(502),
                    format!("no route configured for host: {host}"),
                )
            })?;
            let upstream = route.upstream().ok_or_else(|| {
                Error::explain(
                    HTTPStatus(502),
                    format!("no upstream configured for host: {host}"),
                )
            })?;
            ctx.route_upstream = Some(upstream);
            upstream
        };

        // Determine TLS settings from the pool (if this is a pool-backed route).
        // Single-backend routes that were compiled as plain `ReverseProxy` use
        // no TLS by default — transport TLS must be configured explicitly.
        let (use_tls, sni, client_cert_key, trusted_ca) = if let Some(ref pool) = ctx.upstream_pool
        {
            // Find the backend matching the selected address to get its TLS metadata.
            // The address was already selected in request_filter(), so this scan
            // is O(n) on the small backends Vec — not on the hot path.
            let backend = pool.backends.iter().find(|b| b.addr == upstream);
            let tls = backend.is_some_and(|b| b.tls);
            let sni = backend
                .map(|b| b.tls_server_name.clone())
                .unwrap_or_default();
            let ck = backend.and_then(|b| b.client_cert_key.clone());
            let ca = backend.and_then(|b| b.trusted_ca.clone());
            (tls, sni, ck, ca)
        } else {
            (false, String::new(), None, None)
        };

        // Scale-to-zero (ISSUE-082): if the pool has a scale_to_zero config,
        // probe the upstream with a quick TCP connect. If it fails, trigger the
        // wake cycle (coalesced — only one wake command per upstream) and wait
        // for the backend to become reachable before returning the peer.
        if let Some(ref pool) = ctx.upstream_pool
            && let Some(s2z) = pool.scale_to_zero()
        {
            // Quick TCP probe with a short timeout — if the backend is already
            // running this adds only ~1ms. If it's down, we enter the wake path.
            let probe = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                tokio::net::TcpStream::connect(upstream),
            )
            .await;

            // Backend is down if the connect was refused or the probe timed out.
            let is_up = matches!(probe, Ok(Ok(_)));

            if !is_up {
                debug!(
                    request_id = %ctx.request_id(),
                    %upstream,
                    "upstream unreachable, triggering scale-to-zero wake"
                );
                if let Err(e) = s2z.wake_and_wait(upstream).await {
                    warn!(
                        request_id = %ctx.request_id(),
                        %upstream,
                        error = %e,
                        "scale-to-zero wake failed — returning 504"
                    );
                    return Err(Error::explain(
                        HTTPStatus(504),
                        format!("upstream {upstream} failed to wake: {e}"),
                    ));
                }
            }
        }

        debug!(
            upstream = %upstream,
            tls = use_tls,
            mtls = client_cert_key.is_some(),
            request_id = %ctx.request_id(),
            "route resolved"
        );

        let mut peer = HttpPeer::new(upstream, use_tls, sni);
        peer.options.connection_timeout = Some(std::time::Duration::from_secs(10));
        peer.options.read_timeout = Some(std::time::Duration::from_secs(30));
        peer.options.write_timeout = Some(std::time::Duration::from_secs(30));

        // Wire mTLS client cert into the peer (ISSUE-077)
        if let Some(ck) = client_cert_key {
            peer.client_cert_key = Some(ck);
        }
        // Custom CA bundle for upstream server cert verification (ISSUE-077)
        if let Some(ca) = trusted_ca {
            peer.options.ca = Some(ca);
        }

        // Detect dead upstream connections via TCP keepalive probes instead of
        // waiting for read_timeout (30s) on a silently broken connection.
        // Probes start after 60s idle, retry every 10s, give up after 3 failures.
        peer.options.tcp_keepalive = Some(pingora_core::protocols::TcpKeepalive {
            idle: std::time::Duration::from_secs(60),
            interval: std::time::Duration::from_secs(10),
            count: 3,
            #[cfg(target_os = "linux")]
            user_timeout: std::time::Duration::ZERO,
        });

        // Evict idle connections from the pool before the upstream closes them.
        // Set slightly below common upstream keepalive_timeout (nginx default: 75s)
        // to avoid sending requests on connections the upstream is about to close.
        peer.options.idle_timeout = Some(std::time::Duration::from_secs(60));

        // gRPC requires HTTP/2 end-to-end — force h2 ALPN negotiation
        if ctx.is_grpc {
            peer.options.alpn = ALPN::H2;
        }

        Ok(Box::new(peer))
    }

    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut Self::CTX,
        mut e: Box<Error>,
    ) -> Box<Error> {
        let pool = match ctx.upstream_pool {
            Some(ref p) if p.retry_config().is_enabled() => p,
            _ => return e,
        };

        if !crate::upstream::RetryConfig::is_idempotent_method(&ctx.plugin_ctx.method) {
            debug!(
                request_id = %ctx.request_id(),
                method = %ctx.plugin_ctx.method,
                "skipping retry for non-idempotent method"
            );
            return e;
        }

        let retry_cfg = pool.retry_config();
        if ctx.retry_count >= retry_cfg.max_retries {
            return e;
        }

        if !retry_cfg.try_duration.is_zero() && ctx.start_time.elapsed() >= retry_cfg.try_duration {
            return e;
        }

        // Pick a different backend for the next attempt
        if let Some(failed_addr) = ctx.route_upstream
            && let Some(next) = pool.select_excluding(failed_addr)
        {
            ctx.route_upstream = Some(next);
        }

        ctx.retry_count += 1;
        debug!(
            request_id = %ctx.request_id(),
            attempt = ctx.retry_count,
            "marking upstream connect failure as retryable"
        );
        e.set_retry(true);
        e
    }

    fn error_while_proxy(
        &self,
        peer: &HttpPeer,
        session: &mut Session,
        mut e: Box<Error>,
        ctx: &mut Self::CTX,
        client_reused: bool,
    ) -> Box<Error> {
        e = e.more_context(format!("Peer: {peer}"));

        let can_retry = ctx.upstream_pool.as_ref().is_some_and(|p| {
            p.retry_config().is_enabled()
                && crate::upstream::RetryConfig::is_idempotent_method(&ctx.plugin_ctx.method)
                && ctx.retry_count < p.retry_config().max_retries
                && (p.retry_config().try_duration.is_zero()
                    || ctx.start_time.elapsed() < p.retry_config().try_duration)
        });

        if can_retry {
            let buffer_ok = !session.as_ref().retry_buffer_truncated();
            e.retry.decide_reuse(client_reused && buffer_ok);

            if matches!(e.retry, pingora_error::RetryType::Decided(true)) {
                if let Some(ref pool) = ctx.upstream_pool
                    && let Some(failed_addr) = ctx.route_upstream
                    && let Some(next) = pool.select_excluding(failed_addr)
                {
                    ctx.route_upstream = Some(next);
                }
                ctx.retry_count += 1;
                debug!(
                    request_id = %ctx.request_id(),
                    attempt = ctx.retry_count,
                    "retrying after upstream proxy error"
                );
            }
        } else {
            e.retry
                .decide_reuse(client_reused && !session.as_ref().retry_buffer_truncated());
        }

        e
    }

    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        // gRPC-Web text mode: base64-decode request body before forwarding upstream
        if let Some(crate::grpc_web::GrpcWebMode::Text) = ctx.grpc_web_mode
            && let Some(chunk) = body.take()
        {
            match crate::grpc_web::decode_text_body(&chunk) {
                Ok(decoded) => *body = Some(decoded),
                Err(e) => {
                    warn!(
                        request_id = %ctx.request_id(),
                        error = %e,
                        "grpc-web-text base64 decode failed"
                    );
                    return Err(Error::explain(
                        HTTPStatus(400),
                        "invalid grpc-web-text body",
                    ));
                }
            }
        }

        // Track accumulated request body bytes for chunked requests (ISSUE-069).
        // Content-Length requests are already rejected in request_filter(); this
        // catches chunked transfer encoding where the total size isn't known upfront.
        if let Some(chunk) = body.as_ref() {
            ctx.request_body_received += chunk.len() as u64;
            if ctx.request_body_received > ctx.request_body_max_size {
                warn!(
                    request_id = %ctx.request_id(),
                    received = ctx.request_body_received,
                    limit = ctx.request_body_max_size,
                    "chunked request body exceeds limit — aborting"
                );
                return Err(Error::explain(HTTPStatus(413), "request body too large"));
            }
        }
        Ok(())
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        if let Some(ip) = &ctx.plugin_ctx.client_ip {
            // Write IP to a stack buffer — avoids a heap allocation per request.
            // Max IPv6 text representation is 45 bytes (e.g. with zone id).
            let mut ip_buf = [0u8; 45];
            let ip_str = {
                use std::io::Write;
                let mut cursor = std::io::Cursor::new(&mut ip_buf[..]);
                write!(cursor, "{ip}").map_err(|e| {
                    pingora_error::Error::because(
                        pingora_error::ErrorType::InternalError,
                        "IP format failed",
                        e,
                    )
                })?;
                let len = cursor.position() as usize;
                // SAFETY: IpAddr Display only emits ASCII digits, colons, and dots.
                std::str::from_utf8(&ip_buf[..len]).map_err(|e| {
                    pingora_error::Error::because(
                        pingora_error::ErrorType::InternalError,
                        "IP UTF-8 failed",
                        e,
                    )
                })?
            };
            upstream_request.insert_header("X-Real-IP", ip_str)?;

            // Replace (not append) — client-supplied XFF is stripped to prevent
            // IP spoofing. Only the direct connection IP is trusted.
            upstream_request.remove_header("X-Forwarded-For");
            upstream_request.insert_header("X-Forwarded-For", ip_str)?;
        }

        let proto = if Self::is_tls_connection(session) {
            "https"
        } else {
            "http"
        };
        upstream_request.insert_header("X-Forwarded-Proto", proto)?;

        upstream_request.insert_header("X-Request-Id", ctx.request_id())?;

        // W3C Trace Context propagation (ISSUE-112):
        //
        // When the client sends a valid traceparent, Dwaar emits its own ingress
        // span as a child of the client's span (same trace_id, fresh span_id),
        // then injects that as the upstream traceparent so downstream services
        // are children of Dwaar, not of the original client call.
        //
        // When no traceparent is present, generate a fresh trace + span so the
        // downstream service tree is still fully correlated.
        let (trace_ctx, inbound_parent_span_id) =
            if let Some(inbound) = session
                .req_header()
                .headers
                .get("traceparent")
                .and_then(|v| v.to_str().ok())
                .and_then(crate::trace::parse_traceparent)
            {
                // Extract the client's span_id before generating the child context.
                let parent_id = inbound.span_id_bytes();
                let child = crate::trace::generate_child_traceparent(&inbound);
                (child, Some(parent_id))
            } else {
                (crate::trace::generate_traceparent(), None)
            };

        upstream_request.insert_header("traceparent", trace_ctx.traceparent())?;

        // Pass through tracestate if present — we don't parse it, just relay.
        if let Some(ts) = session.req_header().headers.get("tracestate")
            && let Ok(v) = ts.to_str()
        {
            upstream_request.insert_header("tracestate", v)?;
        }

        ctx.trace_ctx = Some(trace_ctx);
        ctx.inbound_parent_span_id = inbound_parent_span_id;

        // Strip hop-by-hop headers (RFC 7230 §6.1)
        // IMPORTANT: Use remove_header(), not headers.remove() — Pingora
        // maintains a case-preserving header_name_map that desyncs on direct mutation.
        for header_name in &[
            "Proxy-Connection",
            "Proxy-Authenticate",
            "Proxy-Authorization",
            "TE",
            "Trailer",
        ] {
            upstream_request.remove_header(*header_name);
        }

        // WebSocket upgrades need Upgrade + Connection preserved for the 101 handshake.
        // Pingora handles the bidirectional tunnel after the upstream sends 101.
        if !ctx.is_websocket {
            upstream_request.remove_header("Upgrade");
        }

        // SECURITY: Strip Authorization header when Dwaar handled basic auth.
        // Prevents plaintext credentials from reaching upstream logs/services.
        if ctx.basic_auth.is_some() {
            upstream_request.remove_header("Authorization");
        }

        // Forward auth headers (ISSUE-047, CVE-2026-30851 mitigation):
        // 1. ALWAYS strip client-supplied values for copy_headers fields first
        // 2. Then set values from auth service response (if any)
        // This prevents clients from injecting e.g. Remote-User to impersonate users.
        if let Some(ref fwd_config) = ctx.forward_auth {
            for header_name in &fwd_config.copy_headers {
                upstream_request.remove_header(header_name.as_str());
            }
            // Use http::HeaderName + HeaderValue for Pingora's 'static requirement
            for (name, value) in &ctx.forward_auth_headers {
                if let (Ok(hn), Ok(hv)) = (
                    http::HeaderName::from_bytes(name.as_bytes()),
                    http::HeaderValue::from_str(value),
                ) {
                    upstream_request.append_header(hn, hv).map_err(|e| {
                        Error::explain(HTTPStatus(500), format!("forward_auth header error: {e}"))
                    })?;
                }
            }
        }

        // Apply rewritten URI to upstream request (rewrite/uri directives, ISSUE-049)
        if let Some(ref effective_path) = ctx.effective_path {
            let uri: http::uri::Uri = effective_path.parse().map_err(|e| {
                Error::explain(HTTPStatus(500), format!("invalid rewritten URI: {e}"))
            })?;
            upstream_request.set_uri(uri);
            debug!(
                request_id = %ctx.request_id(),
                original = %ctx.plugin_ctx.path,
                rewritten = %effective_path,
                "URI rewritten for upstream"
            );
        }

        // gRPC-Web → gRPC header translation: rewrite Content-Type so the
        // upstream sees standard application/grpc instead of grpc-web.
        if ctx.grpc_web_mode.is_some() {
            crate::grpc_web::translate_request_headers(upstream_request)?;
            debug!(
                request_id = %ctx.request_id(),
                "gRPC-Web request headers translated to application/grpc"
            );
        }

        debug!(
            request_id = %ctx.request_id(),
            client_ip = ?ctx.plugin_ctx.client_ip,
            "proxy headers added, hop-by-hop stripped"
        );

        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        // --- Request tracing (ISSUE-006) ---
        upstream_response.insert_header("X-Request-Id", ctx.request_id())?;

        // --- Cookie sticky sessions ---
        if let Some(ref cookie_hdr) = ctx.sticky_set_cookie {
            upstream_response.append_header("Set-Cookie", cookie_hdr)?;
        }

        // gRPC-Web response translation: rewrite Content-Type back and add
        // CORS headers so browser clients can read grpc-status/grpc-message.
        if let Some(mode) = ctx.grpc_web_mode {
            crate::grpc_web::translate_response_headers(upstream_response, mode)?;
            debug!(
                request_id = %ctx.request_id(),
                mode = ?mode,
                "gRPC response headers translated back to gRPC-Web"
            );
        }

        // Advertise HTTP/3 only for routes the QUIC bridge can serve
        // (ReverseProxy and ReverseProxyPool). FileServer, StaticResponse,
        // and FastCgi are not yet supported over H3 (ISSUE-107), so
        // advertising Alt-Svc for those routes would cause clients to
        // attempt QUIC and get a 502.
        if self.h3_enabled && ctx.quic_capable {
            upstream_response.insert_header("Alt-Svc", r#"h3=":443"; ma=86400"#)?;
        }

        // --- Cache status header (ISSUE-073f) ---
        if let Some(status) = ctx.cache_status {
            upstream_response.insert_header("X-Cache", status)?;
        }

        // --- Intercept check (ISSUE-067) ---
        // Run before analytics setup so we operate on the original upstream status.
        // First matching rule wins; empty statuses catches all non-2xx responses.
        let response_status = upstream_response.status.as_u16();
        if !ctx.intercepts.is_empty() {
            // Extract the matching action before touching ctx again — the borrow
            // on ctx.intercepts must end before we can assign ctx.intercept_body.
            let matched = ctx.intercepts.iter().find_map(|intercept| {
                if intercept.matches_status(response_status) {
                    Some((
                        intercept.replace_status,
                        intercept
                            .set_headers
                            .iter()
                            .map(|(n, v)| (
                                compact_str::CompactString::from(n.as_str()),
                                compact_str::CompactString::from(v.as_str()),
                            ))
                            .collect::<Vec<(compact_str::CompactString, compact_str::CompactString)>>(),
                        intercept.replace_body.clone(),
                    ))
                } else {
                    None
                }
            });
            if let Some((new_status, set_headers, replace_body)) = matched {
                if let Some(code) = new_status
                    && let Ok(status) = pingora_http::StatusCode::from_u16(code)
                {
                    upstream_response.set_status(status)?;
                }
                for (name, value) in set_headers {
                    upstream_response.insert_header(name.into_string(), value.into_string())?;
                }
                if let Some(body) = replace_body {
                    // Signal body replacement to response_body_filter().
                    // Remove Content-Length so the new body length is not validated.
                    ctx.intercept_body = Some(body);
                    upstream_response.remove_header("Content-Length");
                }
            }
        }

        // --- Copy response headers filter (ISSUE-067) ---
        // Strip excluded headers and optionally keep only an allowed subset.
        if let Some(ref crh) = ctx.copy_response_headers
            && crh.matches_status(response_status)
        {
            for name in &crh.exclude {
                upstream_response.remove_header(name.as_str());
            }
            if !crh.include.is_empty() {
                // Collect names to strip; cannot mutate while iterating the map.
                let to_remove: Vec<String> = upstream_response
                    .headers
                    .keys()
                    .filter(|k| {
                        let name = k.as_str();
                        !crh.include.iter().any(|i| i.eq_ignore_ascii_case(name))
                            && !is_essential_header(name)
                    })
                    .map(|k| k.as_str().to_owned())
                    .collect();
                for name in &to_remove {
                    upstream_response.remove_header(name.as_str());
                }
            }
        }

        // --- Response body size pre-check (ISSUE-070) ---
        // If the upstream declares Content-Length, we can reject immediately
        // instead of waiting for the body to stream through response_body_filter.
        if let Some(cl) = upstream_response
            .headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            && cl > ctx.response_body_max_size
        {
            warn!(
                request_id = %ctx.request_id(),
                content_length = cl,
                limit = ctx.response_body_max_size,
                "upstream response body exceeds limit — replacing with 502"
            );
            upstream_response.set_status(http::StatusCode::BAD_GATEWAY)?;
            upstream_response.remove_header("Content-Length");
            ctx.intercept_body = Some(bytes::Bytes::from_static(b"upstream response too large"));
        }

        // --- Analytics injection setup (ISSUE-026a + 026c) ---
        // Must run BEFORE the plugin chain so that the compression plugin
        // sees Content-Encoding already stripped (for HTML injection path).
        // Skip for WebSocket upgrades — the 101 response body is a bidirectional
        // stream, not HTML (ISSUE-068).
        let status = upstream_response.status.as_u16();
        ctx.upstream_status = status;
        if !ctx.is_websocket && !ctx.is_grpc && (200..300).contains(&status) {
            let is_html = upstream_response
                .headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|ct| ct.starts_with("text/html"));

            if is_html {
                let encoding = upstream_response
                    .headers
                    .get(http::header::CONTENT_ENCODING)
                    .and_then(|v| v.to_str().ok())
                    .and_then(Encoding::from_header);

                if let Some(enc) = encoding {
                    debug!(
                        request_id = %ctx.request_id(),
                        encoding = ?enc,
                        "compressed HTML detected, enabling decompression + injection"
                    );
                    ctx.decompressor = Some(Decompressor::new(enc));
                    upstream_response.remove_header("Content-Encoding");
                } else {
                    debug!(request_id = %ctx.request_id(), "HTML response detected, enabling script injection");
                }

                // C-04: issue a signed beacon-auth nonce bound to the
                // serving host and embed it in a `<meta>` tag alongside
                // the analytics script. Without the host the injector
                // falls back to an unsigned script tag; that path still
                // injects but the beacon handler will reject posts that
                // lack a valid signature (fail-closed).
                let host = ctx.plugin_ctx.host.as_deref().unwrap_or("");
                ctx.injector = Some(if host.is_empty() {
                    HtmlInjector::new()
                } else {
                    HtmlInjector::new_with_auth(host)
                });
                upstream_response.remove_header("Content-Length");

                // Tier-3 browser error capture: inject the configured error-capture
                // script when the control plane has marked this route for observation.
                // Config is loaded from env per request (cheap — skips on first None).
                if let Some(err_cfg) = ErrorScriptConfig::from_env() {
                    let project_id = upstream_response
                        .headers
                        .get("X-Permanu-Observe-Project")
                        .and_then(|v| v.to_str().ok());

                    if let Some(pid) = project_id {
                        let csp = upstream_response
                            .headers
                            .get("Content-Security-Policy")
                            .and_then(|v| v.to_str().ok());

                        if csp_allows_injection(csp, &err_cfg.origin)
                            && let Some(inj) = ErrorScriptInjector::new(pid, &err_cfg)
                        {
                            debug!(
                                request_id = %ctx.request_id(),
                                project_id = pid,
                                "error-script injection enabled for this response"
                            );
                            ctx.error_script_injector = Some(inj);
                        }
                    }
                }
            }
        }

        // --- Run plugin chain (security headers, compression) ---
        self.plugin_chain
            .run_response(upstream_response, &mut ctx.plugin_ctx);

        Ok(())
    }

    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<std::time::Duration>>
    where
        Self::CTX: Send + Sync,
    {
        // Cap for captured 5xx error body — enough to identify the error type
        // without risking large allocations on fat error pages.
        const ERROR_BODY_CAP: usize = 256;

        // gRPC-Web text mode: base64-encode response body before sending to client
        if let Some(crate::grpc_web::GrpcWebMode::Text) = ctx.grpc_web_mode
            && let Some(chunk) = body.take()
        {
            *body = Some(crate::grpc_web::encode_text_body(&chunk));
        }

        // --- Response body size check (ISSUE-070) ---
        // Track accumulated response bytes. If the upstream sends more than the
        // configured limit, abort the connection and return 502 to the client.
        if let Some(chunk) = body.as_ref() {
            ctx.response_body_sent += chunk.len() as u64;
            if ctx.response_body_sent > ctx.response_body_max_size {
                warn!(
                    request_id = %ctx.request_id(),
                    received = ctx.response_body_sent,
                    limit = ctx.response_body_max_size,
                    "response body exceeds limit — aborting upstream"
                );
                return Err(Error::explain(
                    HTTPStatus(502),
                    "upstream response body too large",
                ));
            }
        }

        // --- Capture 5xx error body for logging (ISSUE-117) ---
        // Capped above at 256 bytes — enough to identify the error type without
        // risking large allocations on fat error pages or binary upstream responses.
        if (500..600).contains(&ctx.upstream_status)
            && let Some(chunk) = body.as_ref()
        {
            let existing = ctx.upstream_error_body.as_ref().map_or(0, String::len);
            if existing < ERROR_BODY_CAP {
                let remaining = ERROR_BODY_CAP - existing;
                let raw_slice = &chunk[..chunk.len().min(remaining)];
                // Only add the truncation marker when the chunk actually overflows
                // the cap so readers know the body was cut short.
                let truncated = chunk.len() > remaining;
                let text = if let Ok(s) = std::str::from_utf8(raw_slice) {
                    if truncated {
                        format!("{s}…")
                    } else {
                        s.to_string()
                    }
                } else {
                    // Non-UTF-8 body: hex encode so the log entry stays valid JSON.
                    let mut hex = String::with_capacity(raw_slice.len() * 2 + 3);
                    for &b in raw_slice {
                        use std::fmt::Write as _;
                        let _ = write!(hex, "{b:02x}");
                    }
                    if truncated {
                        hex.push('…');
                    }
                    hex
                };
                ctx.upstream_error_body
                    .get_or_insert_with(String::new)
                    .push_str(&text);
            }
        }

        // --- Intercept body override (ISSUE-067) ---
        // When an intercept rule has a replacement body, substitute it here
        // and skip all other body processing (analytics injection, compression).
        if let Some(replacement) = ctx.intercept_body.take() {
            *body = Some(replacement);
            return Ok(None);
        }

        // Decompress first (if compressed response) — core analytics
        if let Some(ref mut decompressor) = ctx.decompressor {
            decompressor.decompress(body, end_of_stream);
        }

        // Then inject into the decompressed HTML — core analytics
        if let Some(ref mut injector) = ctx.injector {
            injector.process(body, end_of_stream);
        }

        // Error-capture script injection (tier-3 browser error tracking).
        // Runs after analytics injection so both look for </head> without
        // interfering — analytics injects first, error script second.
        if let Some(ref mut inj) = ctx.error_script_injector {
            inj.process(body, end_of_stream);
        }

        // Run plugin chain body hooks (compression runs here)
        self.plugin_chain
            .run_body(body, end_of_stream, &mut ctx.plugin_ctx);

        Ok(None)
    }

    async fn logging(
        &self,
        session: &mut Session,
        _e: Option<&pingora_error::Error>,
        ctx: &mut Self::CTX,
    ) where
        Self::CTX: Send + Sync,
    {
        // Decrement the route's active connection counter (ISSUE-075).
        // This runs for every request, even failed ones, so the counter
        // stays accurate for drain timeout decisions. Use fetch_update to
        // prevent underflow — a zero counter means no active connections
        // and subtracting further would wrap to u32::MAX.
        if let Some(ref counter) = ctx.drain_counter {
            let _ = counter.fetch_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |n| n.checked_sub(1),
            );
        }

        // Release the upstream connection slot acquired in request_filter().
        // logging() always runs — even on errors — so the counter stays accurate.
        if let Some(ref pool) = ctx.upstream_pool
            && let Some(addr) = ctx.route_upstream
        {
            pool.release_connection(addr);
        }

        let response_time_us = ctx.start_time.elapsed().as_micros() as u64;
        let status = session.response_written().map_or(0, |r| r.status.as_u16());
        let bytes_sent = session.body_bytes_sent() as u64;
        let bytes_received = session.body_bytes_read() as u64;

        // Anomaly detection — Wheel #2 Week 5. The sink owns its own
        // per-domain state; the proxy only records a single observation
        // per completed request and never waits on emission. No sink
        // registered → zero cost.
        if let Some(ref sink) = self.outcome_sink
            && let Some(ref domain) = ctx.plugin_ctx.route_domain
        {
            sink.record(
                domain.as_str(),
                status,
                std::time::Duration::from_micros(response_time_us),
            );
        }

        // Prometheus metrics (ISSUE-072) — recorded before host.take() moves it
        if let Some(ref prom) = self.prometheus
            && let Some(ref host) = ctx.plugin_ctx.host
        {
            prom.record_request(
                host,
                ctx.plugin_ctx.method.as_str(),
                status,
                response_time_us,
                bytes_sent,
                bytes_received,
            );
            prom.connection_end(host);

            // Cache hit/miss counters (ISSUE-114).
            match ctx.cache_status {
                Some("HIT" | "STALE") => prom.rate_cache.record_cache_hit(host),
                Some("MISS") => prom.rate_cache.record_cache_miss(host),
                _ => {}
            }
        }

        // OTLP ingress span — emitted before field moves below so we can
        // borrow method/path/host from ctx without cloning. The None check is
        // a single pointer compare; zero overhead when tracing is disabled.
        if let Some(ref exporter) = self.otlp_exporter
            && let Some(ref trace_ctx) = ctx.trace_ctx
            && (self.trace_sample_ratio >= 1.0
                || fastrand::f64() < self.trace_sample_ratio)
        {
            let scheme = if ctx.plugin_ctx.is_tls { "https" } else { "http" };
            let span_client_ip = ctx
                .plugin_ctx
                .client_ip
                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
            let client_addr = span_client_ip.to_string();
            let upstream_str = ctx
                .route_upstream
                .map_or_else(String::default, |a| a.to_string());
            let tls_version_str = session
                .downstream_session
                .digest()
                .and_then(|d| d.ssl_digest.as_ref())
                .map(|ssl| ssl.version.clone());
            let now_ns = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            let start_ns = now_ns.saturating_sub(response_time_us * 1_000);
            let host_str = ctx.plugin_ctx.host.as_deref().unwrap_or("");

            let meta = crate::trace::IngressSpanMeta {
                trace_ctx,
                parent_span_id: ctx.inbound_parent_span_id,
                method: ctx.plugin_ctx.method.as_str(),
                path: ctx.plugin_ctx.path.as_str(),
                scheme,
                host: host_str,
                client_address: &client_addr,
                upstream: &upstream_str,
                status,
                tls_version: tls_version_str.as_deref(),
                request_body_size: bytes_received,
                response_body_size: bytes_sent,
                start_ns,
                end_ns: now_ns,
            };
            exporter.record(crate::trace::create_ingress_span(&meta));
        }

        let Some(ref sender) = self.log_sender else {
            return;
        };

        // Split path and query without allocating when there's no query string.
        // std::mem::take moves the CompactString out of ctx, avoiding clone.
        let full_path = std::mem::take(&mut ctx.plugin_ctx.path);
        let (path, query) = if let Some(qmark) = full_path.find('?') {
            let (p, q) = full_path.split_at(qmark);
            (CompactString::from(p), Some(CompactString::from(&q[1..])))
        } else {
            (full_path, None)
        };

        // Map HTTP version to &'static str — avoids format!() allocation
        let http_version = match session.req_header().version {
            http::Version::HTTP_09 => "HTTP/0.9",
            http::Version::HTTP_10 => "HTTP/1.0",
            http::Version::HTTP_11 => "HTTP/1.1",
            http::Version::HTTP_2 => "HTTP/2",
            http::Version::HTTP_3 => "HTTP/3",
            _ => "HTTP/unknown",
        };

        // Extract shared fields once — used by both AggEvent and RequestLog.
        // Move where possible, clone only the AggEvent (7 fields) into the
        // log instead of the other way around (saves 4 clones per request).
        let host = ctx.plugin_ctx.host.take().unwrap_or_default();
        let client_ip = ctx
            .plugin_ctx
            .client_ip
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        let country = ctx.plugin_ctx.country.take();
        let referer: Option<CompactString> = session
            .req_header()
            .headers
            .get("referer")
            .and_then(|v| v.to_str().ok())
            .map(CompactString::from);
        // User-Agent is read once here so the analytics aggregator can
        // classify the request into a fixed device bucket. The full UA
        // is also stored on `RequestLog` below — read both from the
        // same header value so the two paths cannot disagree.
        let user_agent: Option<CompactString> = session
            .req_header()
            .headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(CompactString::from);

        if let Some(ref agg) = self.agg_sender {
            // AggEvent fields are Arc<str>: construction pays one Arc alloc per field,
            // but subsequent clones (at the batch boundary) are pointer bumps only.
            // `query` is cloned (not moved) because `RequestLog` below still
            // needs the original — the aggregator reads only the UTM
            // parameters from it and never retains the raw string.
            let event = AggEvent {
                host: Arc::from(host.as_str()),
                path: Arc::from(path.as_str()),
                query: query.as_deref().map(Arc::from),
                status,
                bytes_sent,
                client_ip,
                country: country.as_deref().map(Arc::from),
                referer: referer.as_deref().map(Arc::from),
                user_agent: user_agent.as_deref().map(Arc::from),
                // bot-detect plugin classifies the request on PluginCtx;
                // the aggregator splits bot vs human counters in DomainMetrics.
                is_bot: ctx.plugin_ctx.is_bot,
                // Same value stored on `RequestLog::response_time_us` below —
                // read once above and propagated to both paths so the log
                // stream and the analytics histogram can never disagree on
                // the per-request latency.
                response_latency_us: response_time_us,
            };
            agg.send(event);
        }

        // Request ID: 36 bytes exceeds CompactString's 24-byte inline threshold,
        // so this heap-allocates. Unavoidable because RequestLog uses serde Serialize.
        let request_id = CompactString::from(ctx.request_id());

        let log = RequestLog {
            timestamp: Utc::now(),
            request_id,
            method: std::mem::take(&mut ctx.plugin_ctx.method),
            path,
            query,
            host,
            status,
            response_time_us,
            client_ip,
            user_agent,
            referer,
            bytes_sent,
            bytes_received,
            tls_version: session
                .downstream_session
                .digest()
                .and_then(|d| d.ssl_digest.as_ref())
                .map(|ssl| CompactString::from(&*ssl.version)),
            http_version: CompactString::from(http_version),
            is_bot: ctx.plugin_ctx.is_bot,
            country,
            upstream_addr: ctx.route_upstream.map_or_else(CompactString::default, |a| {
                use std::fmt::Write;
                let mut s = CompactString::default();
                write!(s, "{a}").expect("SocketAddr is valid");
                s
            }),
            upstream_response_time_us: 0,
            cache_status: ctx.cache_status.map(CompactString::from),
            compression: None,
            trace_id: ctx
                .trace_ctx
                .as_ref()
                .map(|t| CompactString::from(t.trace_id())),
            upstream_error_body: ctx.upstream_error_body.take(),
            rejected_by: ctx.rejected_by,
            blocked_by: ctx.blocked_by,
        };

        sender.send(log);
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;
    use crate::route::Route;

    fn make_proxy(routes: Vec<Route>) -> DwaarProxy {
        let table = RouteTable::new(routes);
        let chain = Arc::new(PluginChain::new(vec![]));
        DwaarProxy::new(
            Arc::new(ArcSwap::from_pointee(table)),
            None,
            None,
            None,
            None,
            None,
            chain,
            None,
            None,
            60,    // keepalive_secs
            30,    // body_timeout_secs
            false, // h3_enabled
        )
    }

    #[test]
    fn proxy_holds_route_table() {
        let proxy = make_proxy(vec![Route::new(
            "example.com",
            "127.0.0.1:8080".parse().expect("valid"),
            false,
            None,
        )]);
        let table = proxy.route_table.load();
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn new_ctx_has_request_id_and_timing() {
        let proxy = make_proxy(vec![]);
        let ctx = proxy.new_ctx();

        assert_eq!(ctx.request_id().len(), 36);
        assert!(ctx.start_time.elapsed().as_secs() < 1);
        assert!(ctx.plugin_ctx.client_ip.is_none());
        assert!(ctx.plugin_ctx.host.is_none());
        assert!(ctx.plugin_ctx.method.is_empty());
        assert!(ctx.plugin_ctx.path.is_empty());
        assert!(ctx.route_upstream.is_none());
        assert!(ctx.injector.is_none());
        assert!(ctx.decompressor.is_none());
    }

    #[test]
    fn route_table_can_be_swapped_at_runtime() {
        let addr1: SocketAddr = "127.0.0.1:3000".parse().expect("valid");
        let addr2: SocketAddr = "127.0.0.1:4000".parse().expect("valid");

        let proxy = make_proxy(vec![Route::new("v1.example.com", addr1, false, None)]);

        assert!(proxy.route_table.load().resolve("v1.example.com").is_some());
        assert!(proxy.route_table.load().resolve("v2.example.com").is_none());

        let new_table = RouteTable::new(vec![Route::new("v2.example.com", addr2, false, None)]);
        proxy.route_table.store(Arc::new(new_table));

        assert!(proxy.route_table.load().resolve("v1.example.com").is_none());
        assert!(proxy.route_table.load().resolve("v2.example.com").is_some());
    }

    #[test]
    fn extract_cookie_value_finds_named_cookie() {
        assert_eq!(
            extract_cookie_value("_dwaar_sticky=abc123; session=xyz", "_dwaar_sticky"),
            Some("abc123")
        );
        assert_eq!(
            extract_cookie_value("session=xyz; _dwaar_sticky=abc123", "_dwaar_sticky"),
            Some("abc123")
        );
    }

    #[test]
    fn extract_cookie_value_returns_none_when_absent() {
        assert_eq!(
            extract_cookie_value("session=xyz; other=foo", "_dwaar_sticky"),
            None
        );
    }

    #[test]
    fn extract_cookie_value_handles_empty_header() {
        assert_eq!(extract_cookie_value("", "_dwaar_sticky"), None);
    }
}
