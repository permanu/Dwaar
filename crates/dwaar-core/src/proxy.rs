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

use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use chrono::Utc;
use pingora_core::Result;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::{Error, ErrorType::HTTPStatus};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{ProxyHttp, Session};
use tracing::{debug, warn};

use bytes::Bytes;
use dwaar_analytics::ANALYTICS_JS;
use dwaar_analytics::aggregation::AggSender;
use dwaar_analytics::beacon::{self, BeaconEvent, BeaconSender};
use dwaar_analytics::decompress::{Decompressor, Encoding};
use dwaar_analytics::injector::HtmlInjector;
use dwaar_log::{LogSender, RequestLog};
use dwaar_plugins::plugin::PluginChain;
use dwaar_tls::acme::ChallengeSolver;

use crate::context::RequestContext;
use crate::route::RouteTable;

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
    ) -> Self {
        Self {
            route_table,
            challenge_solver,
            log_sender,
            beacon_sender,
            agg_sender,
            geo_lookup,
            plugin_chain,
        }
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

    fn https_redirect_domain(&self, session: &Session, ctx: &RequestContext) -> Option<String> {
        if Self::is_tls_connection(session) {
            return None;
        }

        if ctx
            .plugin_ctx
            .path
            .starts_with("/.well-known/acme-challenge/")
        {
            return None;
        }

        let host = ctx
            .plugin_ctx
            .host
            .as_deref()
            .map_or("", |h| h.split(':').next().unwrap_or(h));

        let table = self.route_table.load();
        table
            .resolve(host)
            .filter(|route| route.tls)
            .map(|route| route.domain.clone())
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
        if let Some(ref sender) = self.beacon_sender {
            let mut body = Vec::new();
            while let Ok(Some(chunk)) = session.downstream_session.read_request_body().await {
                body.extend_from_slice(&chunk);
                if body.len() > beacon::MAX_BEACON_SIZE {
                    break;
                }
            }

            match beacon::parse_beacon(&body) {
                Ok(raw) => {
                    let client_ip = ctx
                        .plugin_ctx
                        .client_ip
                        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
                    let host = ctx.plugin_ctx.host.clone().unwrap_or_default();
                    let event = BeaconEvent::from_raw(raw, client_ip, host);
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

    /// Send a plugin-generated short-circuit response to the client.
    async fn send_plugin_response(
        session: &mut Session,
        plugin_resp: dwaar_plugins::plugin::PluginResponse,
    ) -> Result<bool> {
        let mut resp = ResponseHeader::build(plugin_resp.status, Some(plugin_resp.headers.len()))?;
        for (name, value) in &plugin_resp.headers {
            resp.insert_header(*name, value).map_err(|e| {
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

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool>
    where
        Self::CTX: Send + Sync,
    {
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
            ctx.plugin_ctx.country = geo.lookup_country(ip);
        }

        // --- HTTP headers ---
        let header = session.req_header();

        ctx.plugin_ctx.host = header
            .headers
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string)
            .or_else(|| header.uri.authority().map(|a| a.as_str().to_string()));

        ctx.plugin_ctx.method = header.method.as_str().to_string();

        ctx.plugin_ctx.path = header
            .uri
            .path_and_query()
            .map_or_else(|| "/".to_string(), |pq| pq.as_str().to_string());

        ctx.plugin_ctx.accept_encoding = header
            .headers
            .get(http::header::ACCEPT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        debug!(
            request_id = %ctx.request_id(),
            client_ip = ?ctx.plugin_ctx.client_ip,
            host = ?ctx.plugin_ctx.host,
            method = %ctx.plugin_ctx.method,
            path = %ctx.plugin_ctx.path,
            "request metadata extracted"
        );

        // --- Populate route-level plugin config ---
        // Look up the route before running plugins so rate_limit_rps and
        // under_attack flags are available to the plugin chain.
        if let Some(ref host) = ctx.plugin_ctx.host {
            let host_stripped = host.split(':').next().unwrap_or(host);
            let table = self.route_table.load();
            if let Some(route) = table.resolve(host_stripped) {
                ctx.plugin_ctx.rate_limit_rps = route.rate_limit_rps;
                ctx.plugin_ctx.route_domain = Some(route.domain.clone());
                ctx.plugin_ctx.under_attack = route.under_attack;
            }
        }

        // --- Run plugin chain (bot detect, rate limit, under attack) ---
        if let Some(plugin_resp) = self
            .plugin_chain
            .run_request(session.req_header(), &mut ctx.plugin_ctx)
        {
            debug!(
                request_id = %ctx.request_id(),
                status = plugin_resp.status,
                "plugin chain short-circuited request"
            );
            return Self::send_plugin_response(session, plugin_resp).await;
        }

        // --- Analytics JS serving (ISSUE-024) ---
        if ctx.plugin_ctx.path == "/_dwaar/a.js" {
            debug!(request_id = %ctx.request_id(), "serving analytics JS from memory");
            let mut resp = ResponseHeader::build(200, Some(3))?;
            resp.insert_header("Content-Type", "application/javascript")
                .map_err(|e| Error::explain(HTTPStatus(500), format!("bad header: {e}")))?;
            resp.insert_header("Cache-Control", "public, max-age=86400")
                .map_err(|e| Error::explain(HTTPStatus(500), format!("bad header: {e}")))?;
            resp.insert_header("Content-Length", ANALYTICS_JS.len().to_string())
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
                if ChallengeSolver::is_valid_token(token)
                    && let Some(key_auth) = solver.get(token)
                {
                    debug!(
                        request_id = %ctx.request_id(),
                        token = %token,
                        "serving ACME challenge response"
                    );
                    let mut resp = ResponseHeader::build(200, Some(1))?;
                    resp.insert_header("Content-Length", key_auth.len().to_string())
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
        let host = ctx
            .plugin_ctx
            .host
            .as_deref()
            .map_or("", |h| h.split(':').next().unwrap_or(h));

        let table = self.route_table.load();
        let route = table.resolve(host).ok_or_else(|| {
            warn!(host = %host, request_id = %ctx.request_id(), "no route for host");
            Error::explain(
                HTTPStatus(502),
                format!("no route configured for host: {host}"),
            )
        })?;

        ctx.route_upstream = Some(route.upstream);

        debug!(
            host = %host,
            upstream = %route.upstream,
            request_id = %ctx.request_id(),
            "route resolved"
        );

        let mut peer = HttpPeer::new(route.upstream, false, String::new());
        peer.options.connection_timeout = Some(std::time::Duration::from_secs(10));
        peer.options.read_timeout = Some(std::time::Duration::from_secs(30));
        peer.options.write_timeout = Some(std::time::Duration::from_secs(30));
        Ok(Box::new(peer))
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
            let ip_str = ip.to_string();
            upstream_request
                .insert_header("X-Real-IP", &ip_str)
                .expect("IP string is valid header value");

            upstream_request.remove_header("X-Forwarded-For");
            upstream_request
                .insert_header("X-Forwarded-For", &ip_str)
                .expect("IP string is valid header value");
        }

        let proto = if Self::is_tls_connection(session) {
            "https"
        } else {
            "http"
        };
        upstream_request
            .insert_header("X-Forwarded-Proto", proto)
            .expect("static header value is valid");

        upstream_request
            .insert_header("X-Request-Id", ctx.request_id())
            .expect("UUID is valid header value");

        // Strip hop-by-hop headers (RFC 7230 §6.1)
        // IMPORTANT: Use remove_header(), not headers.remove() — Pingora
        // maintains a case-preserving header_name_map that desyncs on direct mutation.
        for header_name in &[
            "Proxy-Connection",
            "Proxy-Authenticate",
            "Proxy-Authorization",
            "TE",
            "Trailer",
            "Upgrade",
        ] {
            upstream_request.remove_header(*header_name);
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
        upstream_response
            .insert_header("X-Request-Id", ctx.request_id())
            .expect("UUID is valid header value");

        // --- Analytics injection setup (ISSUE-026a + 026c) ---
        // Must run BEFORE the plugin chain so that the compression plugin
        // sees Content-Encoding already stripped (for HTML injection path).
        let status = upstream_response.status.as_u16();
        if (200..300).contains(&status) {
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

                ctx.injector = Some(HtmlInjector::new());
                upstream_response.remove_header("Content-Length");
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
        // Decompress first (if compressed response) — core analytics
        if let Some(ref mut decompressor) = ctx.decompressor {
            decompressor.decompress(body, end_of_stream);
        }

        // Then inject into the decompressed HTML — core analytics
        if let Some(ref mut injector) = ctx.injector {
            injector.process(body, end_of_stream);
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
        let Some(ref sender) = self.log_sender else {
            return;
        };

        let response_time_us = ctx.start_time.elapsed().as_micros() as u64;
        let status = session.response_written().map_or(0, |r| r.status.as_u16());

        let (path, query) = if let Some(qmark) = ctx.plugin_ctx.path.find('?') {
            (
                ctx.plugin_ctx.path[..qmark].to_string(),
                Some(ctx.plugin_ctx.path[qmark + 1..].to_string()),
            )
        } else {
            (ctx.plugin_ctx.path.clone(), None)
        };

        let log = RequestLog {
            timestamp: Utc::now(),
            request_id: ctx.request_id().to_string(),
            method: ctx.plugin_ctx.method.clone(),
            path,
            query,
            host: ctx.plugin_ctx.host.clone().unwrap_or_default(),
            status,
            response_time_us,
            client_ip: ctx
                .plugin_ctx
                .client_ip
                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
            user_agent: session
                .req_header()
                .headers
                .get("user-agent")
                .and_then(|v| v.to_str().ok())
                .map(ToString::to_string),
            referer: session
                .req_header()
                .headers
                .get("referer")
                .and_then(|v| v.to_str().ok())
                .map(ToString::to_string),
            bytes_sent: session.body_bytes_sent() as u64,
            bytes_received: session.body_bytes_read() as u64,
            tls_version: session
                .downstream_session
                .digest()
                .and_then(|d| d.ssl_digest.as_ref())
                .map(|ssl| ssl.version.to_string()),
            http_version: format!("{:?}", session.req_header().version),
            is_bot: ctx.plugin_ctx.is_bot,
            country: ctx.plugin_ctx.country.clone(),
            upstream_addr: ctx
                .route_upstream
                .map_or_else(String::new, |a| a.to_string()),
            upstream_response_time_us: 0,
            cache_status: None,
            compression: None,
        };

        if let Some(ref agg) = self.agg_sender {
            sender.send(log.clone());
            agg.send(log);
        } else {
            sender.send(log);
        }
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
}
