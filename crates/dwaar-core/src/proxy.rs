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
use compact_str::CompactString;
use dwaar_analytics::ANALYTICS_JS;
use dwaar_analytics::aggregation::{AggEvent, AggSender};
use dwaar_analytics::beacon::{self, BeaconEvent, BeaconSender};
use dwaar_analytics::decompress::{Decompressor, Encoding};
use dwaar_analytics::injector::HtmlInjector;
use dwaar_log::{LogSender, RequestLog};
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
    matches!(
        name.to_ascii_lowercase().as_str(),
        "content-type" | "content-length" | "transfer-encoding" | "connection" | "date" | "server"
    )
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

    fn https_redirect_domain(session: &Session, ctx: &RequestContext) -> Option<String> {
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

        // Use cached route_tls and route_canonical_domain from request_filter()
        // instead of a second ArcSwap load + hash lookup.
        if ctx.route_tls {
            ctx.route_canonical_domain.clone()
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
        if let Some(ref sender) = self.beacon_sender {
            let mut body = Vec::with_capacity(1024);
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
            resp.insert_header("Content-Length", body.len().to_string())
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
                ctx.plugin_ctx.rate_limit_rps = route.rate_limit_rps();
                ctx.plugin_ctx.route_domain = Some(CompactString::from(route.domain.as_str()));
                ctx.plugin_ctx.under_attack = route.under_attack();
                ctx.route_upstream = route.upstream();
                ctx.route_tls = route.tls;
                ctx.route_canonical_domain = Some(route.domain.clone());

                // Path-based handler resolution (ISSUE-050).
                // Iterate handler blocks, find the first matching one (handle/handle_path)
                // or run all matching (route). Cache matched handler data in ctx.
                let request_path = ctx.plugin_ctx.path.clone();
                for block in &route.handlers {
                    let Some(prefix_len) = block.matcher.matches(&request_path) else {
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
                        crate::route::Handler::ReverseProxy { upstream } => {
                            ctx.route_upstream = Some(*upstream);
                        }
                        crate::route::Handler::ReverseProxyPool { pool } => {
                            // Resolve the upstream now using the LB policy.
                            // Cache the selected address in `route_upstream` so
                            // `upstream_peer()` doesn't need to call `select()` again
                            // for single-backend pools.
                            let selected = pool.select(ctx.plugin_ctx.client_ip);
                            ctx.route_upstream = selected.as_ref().map(|s| s.addr);
                            // Always cache the pool so `upstream_peer()` can use the
                            // correct TLS settings even in the single-backend case.
                            ctx.upstream_pool = Some(pool.clone());
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

                    // Evaluate map directives to populate VarSlots (ISSUE-056)
                    if !block.maps.is_empty() || !route.var_defaults.is_empty() {
                        let mut slots = route.var_defaults.clone();
                        if !block.maps.is_empty() {
                            let map_tmpl_ctx = TemplateContext {
                                host: ctx.plugin_ctx.host.as_deref().unwrap_or(""),
                                method: ctx.plugin_ctx.method.as_str(),
                                path: &request_path,
                                uri: &request_path,
                                query: "",
                                scheme: if ctx.route_tls { "https" } else { "http" },
                                remote_host: "",
                                remote_port: 0,
                                request_id: ctx.request_id(),
                                upstream_host: "",
                                upstream_port: 0,
                                tls_server_name: "",
                                vars: None,
                            };
                            for map in &block.maps {
                                if let Some(val) = map.evaluate(&map_tmpl_ctx) {
                                    slots.set(map.dest_slot, CompactString::from(val));
                                }
                            }
                        }
                        ctx.var_slots = Some(slots);
                    }

                    // Apply rewrite rules (with template evaluation)
                    if !block.rewrites.is_empty() {
                        let mut path = ctx
                            .effective_path
                            .as_deref()
                            .unwrap_or(&request_path)
                            .to_string();

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
                                vars: ctx.var_slots.as_ref(),
                            };
                            if let Some(rewritten) = rule.apply(&path, Some(&tmpl_ctx)) {
                                path = rewritten.into_string();
                            }
                        }
                        ctx.effective_path = Some(CompactString::from(path));
                    }

                    // For handle/handle_path: first match wins — stop iterating
                    if block.kind != crate::route::BlockKind::Route {
                        break;
                    }
                }
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
                    debug!(
                        request_id = %ctx.request_id(),
                        status,
                        "forward auth denied"
                    );
                    let mut resp = ResponseHeader::build(status, Some(1))?;
                    let end_of_body = body.is_empty();
                    if !end_of_body {
                        resp.insert_header("Content-Length", body.len().to_string())
                            .map_err(|e| {
                                Error::explain(HTTPStatus(status), format!("bad header: {e}"))
                            })?;
                    }
                    session
                        .write_response_header(Box::new(resp), end_of_body)
                        .await?;
                    if !end_of_body {
                        session
                            .write_response_body(Some(Bytes::from(body)), true)
                            .await?;
                    }
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

            match crate::file_server::serve_file(root, request_path, browse) {
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
                    resp.insert_header("Content-Length", content_length.to_string())
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
                    resp.insert_header("Content-Length", body.len().to_string())
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

            // Read request body for POST
            let mut body_buf = Vec::new();
            while let Ok(Some(chunk)) = session.downstream_session.read_request_body().await {
                body_buf.extend_from_slice(&chunk);
                if body_buf.len() > 10 * 1024 * 1024 {
                    break;
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
                        resp.insert_header("Content-Length", fcgi_resp.body.len().to_string())
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
        if let Some(canonical_domain) = Self::https_redirect_domain(session, ctx) {
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
        // Use the route resolved in request_filter() to avoid a second ArcSwap load
        let upstream = if let Some(addr) = ctx.route_upstream {
            addr
        } else {
            // Defensive fallback — should not happen in normal flow
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
        let (use_tls, sni) = if let Some(ref pool) = ctx.upstream_pool {
            // Re-select from the pool to get TLS metadata for the chosen backend.
            // The address was already selected in request_filter(), so this scan
            // is a O(n) match on the small backends Vec — not on the hot path.
            let tls = pool
                .backends
                .iter()
                .find(|b| b.addr == upstream)
                .is_some_and(|b| b.tls);
            let sni = pool
                .backends
                .iter()
                .find(|b| b.addr == upstream)
                .map(|b| b.tls_server_name.clone())
                .unwrap_or_default();
            (tls, sni)
        } else {
            (false, String::new())
        };

        debug!(
            upstream = %upstream,
            tls = use_tls,
            request_id = %ctx.request_id(),
            "route resolved"
        );

        let mut peer = HttpPeer::new(upstream, use_tls, sni);
        peer.options.connection_timeout = Some(std::time::Duration::from_secs(10));
        peer.options.read_timeout = Some(std::time::Duration::from_secs(30));
        peer.options.write_timeout = Some(std::time::Duration::from_secs(30));

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
            // Write IP to a stack buffer — avoids a heap allocation per request.
            // Max IPv6 text representation is 45 bytes (e.g. with zone id).
            let mut ip_buf = [0u8; 45];
            let ip_str = {
                use std::io::Write;
                let mut cursor = std::io::Cursor::new(&mut ip_buf[..]);
                write!(cursor, "{ip}").expect("IP fits in 45 bytes");
                let len = cursor.position() as usize;
                // SAFETY: IpAddr Display only emits ASCII digits, colons, and dots.
                std::str::from_utf8(&ip_buf[..len]).expect("IP is valid UTF-8")
            };
            upstream_request
                .insert_header("X-Real-IP", ip_str)
                .expect("IP string is valid header value");

            upstream_request.remove_header("X-Forwarded-For");
            upstream_request
                .insert_header("X-Forwarded-For", ip_str)
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
                            .map(|(n, v)| (n.as_str().to_owned(), v.as_str().to_owned()))
                            .collect::<Vec<_>>(),
                        intercept.replace_body.clone(),
                    ))
                } else {
                    None
                }
            });
            if let Some((new_status, set_headers, replace_body)) = matched {
                if let Some(code) = new_status {
                    upstream_response
                        .set_status(
                            pingora_http::StatusCode::from_u16(code)
                                .expect("intercept status must be a valid HTTP code"),
                        )
                        .expect("failed to set intercept status");
                }
                for (name, value) in set_headers {
                    upstream_response
                        .insert_header(name, value)
                        .expect("intercept header name/value must be valid");
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
        let bytes_sent = session.body_bytes_sent() as u64;

        if let Some(ref agg) = self.agg_sender {
            let event = AggEvent {
                host: host.clone(),
                path: path.clone(),
                status,
                bytes_sent,
                client_ip,
                country: country.clone(),
                referer: referer.clone(),
            };
            agg.send(event);
        }

        // Request ID: 36 bytes exceeds CompactString's 24-byte inline threshold.
        // Use a stack buffer write to produce a CompactString without going
        // through an intermediate &str → String → CompactString chain.
        let request_id = {
            let mut s = CompactString::with_capacity(36);
            s.push_str(ctx.request_id());
            s
        };

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
            user_agent: session
                .req_header()
                .headers
                .get("user-agent")
                .and_then(|v| v.to_str().ok())
                .map(CompactString::from),
            referer,
            bytes_sent,
            bytes_received: session.body_bytes_read() as u64,
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
            cache_status: None,
            compression: None,
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
