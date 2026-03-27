// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Core proxy implementation — the `ProxyHttp` trait is Dwaar's engine.
//!
//! `DwaarProxy` implements Pingora's [`ProxyHttp`] trait, which defines how
//! every HTTP request is processed. Pingora calls our lifecycle methods in
//! order: `new_ctx` → `request_filter` → `upstream_peer` →
//! `upstream_request_filter` → `response_filter` → `logging`.
//!
//! ## Implemented hooks
//!
//! - `new_ctx()` — sets `start_time` and `request_id`
//! - `request_filter()` — extracts client IP, host, method, path
//! - `upstream_peer()` — resolves Host header via `RouteTable`, returns 502 on miss
//! - `upstream_request_filter()` — adds proxy headers, strips hop-by-hop
//! - `response_filter()` — adds `X-Request-Id` + security headers
//! - `logging()` — emits structured request log to the batch writer

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
use dwaar_tls::acme::ChallengeSolver;

use crate::context::RequestContext;
use crate::route::RouteTable;

/// Sanitize a request path for use in a redirect Location header.
/// Prevents CRLF injection and protocol-relative open redirects.
fn sanitize_redirect_path(path: &str) -> String {
    // Strip CR/LF to prevent header injection
    let cleaned: String = path.chars().filter(|c| *c != '\r' && *c != '\n').collect();
    // Collapse leading slashes to prevent //evil.com open redirect
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
/// Implements Pingora's `ProxyHttp` to handle every HTTP request that
/// arrives at the proxy. Routes requests to different upstreams based
/// on the `Host` header, using a lock-free [`RouteTable`] for lookups.
#[derive(Debug)]
pub struct DwaarProxy {
    /// Lock-free route table shared across all worker threads.
    /// Readers pay ~1ns (atomic pointer load), writers swap the entire
    /// table atomically on config reload.
    route_table: Arc<ArcSwap<RouteTable>>,
    /// ACME HTTP-01 challenge solver. `None` if no `tls auto` domains.
    challenge_solver: Option<Arc<ChallengeSolver>>,
    /// Non-blocking sender for the batch log writer. `None` disables logging.
    log_sender: Option<LogSender>,
    /// Non-blocking sender for beacon events. `None` disables beacon collection.
    beacon_sender: Option<BeaconSender>,
    /// Non-blocking sender for request log aggregation. `None` disables.
    agg_sender: Option<AggSender>,
    /// Bot detector — classifies User-Agent strings into bot categories.
    bot_detector: Arc<dwaar_plugins::bot_detect::BotDetector>,
    /// Per-IP rate limiter. One instance handles all routes via composite keys.
    rate_limiter: Arc<dwaar_plugins::rate_limit::RateLimiter>,
    /// `GeoIP` lookup for IP → country code. `None` if no database loaded.
    geo_lookup: Option<Arc<dwaar_geo::GeoLookup>>,
}

#[allow(clippy::too_many_arguments)]
impl DwaarProxy {
    /// Create a new proxy backed by the given route table.
    ///
    /// The `ArcSwap` allows hot-reloading routes without restarting
    /// the proxy — config reload code calls `route_table.store(new_table)`.
    pub fn new(
        route_table: Arc<ArcSwap<RouteTable>>,
        challenge_solver: Option<Arc<ChallengeSolver>>,
        log_sender: Option<LogSender>,
        beacon_sender: Option<BeaconSender>,
        agg_sender: Option<AggSender>,
        bot_detector: Arc<dwaar_plugins::bot_detect::BotDetector>,
        rate_limiter: Arc<dwaar_plugins::rate_limit::RateLimiter>,
        geo_lookup: Option<Arc<dwaar_geo::GeoLookup>>,
    ) -> Self {
        Self {
            route_table,
            challenge_solver,
            log_sender,
            beacon_sender,
            agg_sender,
            bot_detector,
            rate_limiter,
            geo_lookup,
        }
    }
}

impl DwaarProxy {
    /// Check whether the downstream connection used TLS.
    ///
    /// Pingora stores an `SslDigest` in the connection digest when TLS
    /// was negotiated. If it's `None`, the client connected over plaintext.
    fn is_tls_connection(session: &Session) -> bool {
        session
            .downstream_session
            .digest()
            .and_then(|d| d.ssl_digest.as_ref())
            .is_some()
    }

    /// Check whether this request should be redirected to HTTPS.
    ///
    /// Returns the route's canonical domain if all three conditions hold:
    /// 1. The connection is plaintext (no TLS)
    /// 2. The path is NOT an ACME HTTP-01 challenge (those must stay on HTTP)
    /// 3. The matched route has TLS enabled
    ///
    /// Returns the canonical domain from the route table — NOT the client's
    /// Host header — so the redirect Location can't be forged by the client.
    fn https_redirect_domain(&self, session: &Session, ctx: &RequestContext) -> Option<String> {
        if Self::is_tls_connection(session) {
            return None;
        }

        // ACME HTTP-01 challenges arrive on port 80 and must be served
        // over plaintext — Let's Encrypt's validation servers expect HTTP
        if ctx.path.starts_with("/.well-known/acme-challenge/") {
            return None;
        }

        let host = ctx
            .host
            .as_deref()
            .map_or("", |h| h.split(':').next().unwrap_or(h));

        let table = self.route_table.load();
        table
            .resolve(host)
            .filter(|route| route.tls)
            .map(|route| route.domain.clone())
    }

    /// Send a 301 redirect from HTTP to HTTPS and short-circuit the request.
    ///
    /// Uses the route's canonical domain for the Location header to prevent
    /// open-redirect attacks via a forged Host header.
    async fn send_https_redirect(
        &self,
        session: &mut Session,
        ctx: &RequestContext,
        canonical_domain: &str,
    ) -> Result<bool> {
        // Sanitize path to prevent header injection (CRLF) and open redirects (//)
        let safe_path = sanitize_redirect_path(&ctx.path);
        let location = format!("https://{canonical_domain}{safe_path}");

        debug!(
            request_id = %ctx.request_id,
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

    /// Handle a `POST /_dwaar/collect` beacon request.
    ///
    /// Reads the body from the downstream, parses the JSON beacon, enriches
    /// it with server-side context, and pushes to the analytics channel.
    /// Always returns a response (204 on success, 400 on bad payload).
    async fn handle_beacon(&self, session: &mut Session, ctx: &RequestContext) -> Result<bool> {
        if let Some(ref sender) = self.beacon_sender {
            // Read the full POST body chunk by chunk (bounded by parse_beacon's 4KB limit)
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
                        .client_ip
                        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
                    let host = ctx.host.clone().unwrap_or_default();
                    let event = BeaconEvent::from_raw(raw, client_ip, host);

                    // Non-blocking — drops the event if the channel is full
                    let _ = sender.try_send(event);

                    debug!(request_id = %ctx.request_id, "beacon collected");
                }
                Err(msg) => {
                    warn!(request_id = %ctx.request_id, error = %msg, "invalid beacon");
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
}

#[async_trait]
#[allow(clippy::too_many_lines)]
impl ProxyHttp for DwaarProxy {
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX {
        RequestContext::new()
    }

    /// Extract per-request metadata and handle HTTP→HTTPS redirects.
    ///
    /// This runs after Pingora has parsed the HTTP headers but before
    /// `upstream_peer()` selects the backend. Two responsibilities:
    ///
    /// 1. Populate `RequestContext` with client IP, host, method, path
    /// 2. If the connection is plaintext and the route wants TLS,
    ///    send a 301 redirect to HTTPS and short-circuit
    ///
    /// Returns `Ok(false)` to continue to the next phase, or `Ok(true)`
    /// if we already sent a response (redirect).
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        // --- Client IP ---
        ctx.client_ip = session
            .client_addr()
            .and_then(|addr| addr.as_inet())
            .map(std::net::SocketAddr::ip);

        // --- GeoIP lookup ---
        if let Some(ref geo) = self.geo_lookup
            && let Some(ip) = ctx.client_ip
        {
            ctx.country = geo.lookup_country(ip);
        }

        // --- HTTP headers ---
        let header = session.req_header();

        // HTTP/1.1 uses Host header, HTTP/2 uses :authority pseudo-header
        ctx.host = header
            .headers
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string)
            .or_else(|| header.uri.authority().map(|a| a.as_str().to_string()));

        ctx.method = header.method.as_str().to_string();

        ctx.path = header
            .uri
            .path_and_query()
            .map_or_else(|| "/".to_string(), |pq| pq.as_str().to_string());

        debug!(
            request_id = %ctx.request_id,
            client_ip = ?ctx.client_ip,
            host = ?ctx.host,
            method = %ctx.method,
            path = %ctx.path,
            "request metadata extracted"
        );

        // --- Rate limiting (ISSUE-031) ---
        // Check before bot detection, analytics, or any other processing to
        // minimize CPU spent on traffic that exceeds the configured limit.
        if let Some(ref host) = ctx.host {
            let host_stripped = host.split(':').next().unwrap_or(host);
            let table = self.route_table.load();
            if let Some(route) = table.resolve(host_stripped)
                && let Some(limit) = route.rate_limit_rps
                && let Some(ip) = ctx.client_ip
            {
                // Composite key: "{ip}:{domain}" for per-route isolation.
                // format!() allocates on the heap — acceptable here since the rate
                // check itself dominates (atomic CAS in Rate::observe). A stack buffer
                // optimization can be done later if benchmarks show this matters.
                let key = format!("{ip}:{}", route.domain);
                if !self.rate_limiter.check(&key, limit) {
                    debug!(
                        request_id = %ctx.request_id,
                        client_ip = %ip,
                        domain = %route.domain,
                        limit = limit,
                        "rate limit exceeded — returning 429"
                    );
                    let mut resp = ResponseHeader::build(429, Some(2))?;
                    resp.insert_header("Retry-After", "1")
                        .map_err(|e| Error::explain(HTTPStatus(429), format!("bad header: {e}")))?;
                    resp.insert_header("Content-Length", "0")
                        .map_err(|e| Error::explain(HTTPStatus(429), format!("bad header: {e}")))?;
                    session.write_response_header(Box::new(resp), true).await?;
                    return Ok(true);
                }
            }
        }

        // --- Bot detection (ISSUE-030) ---
        if let Some(ua) = session.req_header().headers.get(http::header::USER_AGENT)
            && let Ok(ua_str) = ua.to_str()
            && let Some(category) = self.bot_detector.classify(ua_str)
        {
            ctx.is_bot = true;
            ctx.bot_category = Some(category);
            debug!(
                request_id = %ctx.request_id,
                category = category.as_str(),
                "bot detected"
            );
        }

        // --- Analytics JS serving (ISSUE-024) ---
        // Serve the compiled-in analytics script from memory. Same-origin
        // serving avoids ad-blockers and CSP issues. The script is compiled
        // into the binary via include_bytes!() so there's no filesystem I/O.
        if ctx.path == "/_dwaar/a.js" {
            debug!(request_id = %ctx.request_id, "serving analytics JS from memory");
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
        // Intercept analytics beacons sent by the injected JS. Parsed and
        // enriched in handle_beacon(); returns 204 or 400, never forwarded.
        if ctx.path == "/_dwaar/collect" && ctx.method == "POST" {
            return self.handle_beacon(session, ctx).await;
        }

        // --- ACME HTTP-01 challenge response ---
        // Must happen before HTTPS redirect — challenges arrive on port 80.
        // Responds directly from the in-memory solver without touching upstream.
        if let Some(ref solver) = self.challenge_solver {
            const CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";
            if ctx.path.starts_with(CHALLENGE_PREFIX) {
                let token = &ctx.path[CHALLENGE_PREFIX.len()..];
                if ChallengeSolver::is_valid_token(token)
                    && let Some(key_auth) = solver.get(token)
                {
                    debug!(
                        request_id = %ctx.request_id,
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

        // HTTP/1.1 requires a Host header (RFC 7230 §5.4). Without it (and
        // without :authority in HTTP/2), we can't route the request.
        if ctx.host.is_none() {
            warn!(request_id = %ctx.request_id, "missing Host header — returning 400");
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
        // Extract the host, stripping any port suffix (e.g. "example.com:8080" → "example.com")
        let host = ctx
            .host
            .as_deref()
            .map_or("", |h| h.split(':').next().unwrap_or(h));

        // Load the route table — one atomic pointer read, no lock
        let table = self.route_table.load();

        let route = table.resolve(host).ok_or_else(|| {
            warn!(host = %host, request_id = %ctx.request_id, "no route for host");
            Error::explain(
                HTTPStatus(502),
                format!("no route configured for host: {host}"),
            )
        })?;

        ctx.route_upstream = Some(route.upstream);

        debug!(
            host = %host,
            upstream = %route.upstream,
            request_id = %ctx.request_id,
            "route resolved"
        );

        let mut peer = HttpPeer::new(route.upstream, false, String::new());
        peer.options.connection_timeout = Some(std::time::Duration::from_secs(10));
        peer.options.read_timeout = Some(std::time::Duration::from_secs(30));
        peer.options.write_timeout = Some(std::time::Duration::from_secs(30));
        Ok(Box::new(peer))
    }

    /// Add standard proxy headers and strip hop-by-hop headers (ISSUE-007).
    ///
    /// This runs after `upstream_peer()` has selected the backend but before
    /// Pingora sends the request. We modify the request headers that the
    /// **upstream** will see — not the original client request.
    ///
    /// ## Headers added
    ///
    /// - `X-Real-IP`: The client's direct TCP connection IP.
    /// - `X-Forwarded-For`: Appends client IP to the existing chain
    ///   (or creates a new chain if none exists). Preserves any upstream
    ///   proxy IPs that were already in the header.
    /// - `X-Forwarded-Proto`: `https` when the downstream connection is TLS, `http` otherwise.
    /// - `X-Request-Id`: The UUID v7 from the request context.
    ///
    /// ## Headers removed (RFC 7230 §6.1)
    ///
    /// Hop-by-hop headers are meaningful only for a single transport-level
    /// connection — they must not be forwarded to the upstream.
    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        // --- Add proxy identity headers ---

        // X-Real-IP: the direct client IP (not from X-Forwarded-For).
        // Backends use this as the authoritative client IP when they
        // trust the proxy.
        if let Some(ip) = &ctx.client_ip {
            let ip_str = ip.to_string();
            upstream_request
                .insert_header("X-Real-IP", &ip_str)
                .expect("IP string is valid header value");

            // X-Forwarded-For: set to the direct client IP only.
            // We strip any client-supplied XFF to prevent IP spoofing.
            // Trusted proxy chains require explicit trusted_proxies config (not yet implemented).
            upstream_request.remove_header("X-Forwarded-For");
            upstream_request
                .insert_header("X-Forwarded-For", &ip_str)
                .expect("IP string is valid header value");
        }

        // X-Forwarded-Proto: "https" if the client connected over TLS, "http" otherwise.
        let proto = if Self::is_tls_connection(session) {
            "https"
        } else {
            "http"
        };
        upstream_request
            .insert_header("X-Forwarded-Proto", proto)
            .expect("static header value is valid");

        // X-Request-Id: lets the backend correlate its logs with ours.
        upstream_request
            .insert_header("X-Request-Id", &ctx.request_id)
            .expect("UUID is valid header value");

        // --- Strip hop-by-hop headers (RFC 7230 §6.1) ---
        // These headers describe the client→proxy connection and must not
        // leak to the upstream. Pingora handles some of these internally
        // (like Connection and Transfer-Encoding for HTTP/1↔HTTP/2 translation),
        // but we explicitly remove the full set for safety.
        //
        // IMPORTANT: Use remove_header(), not headers.remove(). Pingora
        // maintains a case-preserving header_name_map alongside the HeaderMap.
        // Direct removal from headers causes a desync panic on serialization.
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
            request_id = %ctx.request_id,
            client_ip = ?ctx.client_ip,
            "proxy headers added, hop-by-hop stripped"
        );

        Ok(())
    }

    /// Add security headers and `X-Request-Id` to every response.
    ///
    /// ## Security headers (ISSUE-008)
    ///
    /// These provide a baseline defense against common web attacks. All are
    /// set unconditionally for now. ISSUE-010 (`RouteTable`) will add per-route
    /// toggles so apps that set their own headers can disable specific ones.
    ///
    /// - `Strict-Transport-Security` — prevents HTTPS protocol downgrade
    /// - `X-Content-Type-Options` — prevents MIME type sniffing
    /// - `X-Frame-Options` — prevents clickjacking via iframes
    /// - `Referrer-Policy` — limits referrer info leaked to third parties
    /// - `Server` — replaces upstream's server banner to avoid fingerprinting
    ///
    /// ## Tracing header (ISSUE-006)
    ///
    /// - `X-Request-Id` — lets clients correlate their request with server logs
    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        // --- Security headers (ISSUE-008) ---
        // Each insert_header call uses a static string value, so .expect()
        // is safe — these can never fail at runtime.

        // HSTS: only on TLS connections. Emitting on plain HTTP could break
        // intentionally HTTP-only routes if the response is ever cached.
        if Self::is_tls_connection(session) {
            upstream_response
                .insert_header(
                    "Strict-Transport-Security",
                    "max-age=31536000; includeSubDomains",
                )
                .expect("static header value");
        }

        // Prevent browsers from MIME-sniffing the response body.
        // Without this, a browser might execute uploaded .txt as JavaScript.
        upstream_response
            .insert_header("X-Content-Type-Options", "nosniff")
            .expect("static header value");

        // Prevent the page from being loaded inside an iframe on another domain.
        // SAMEORIGIN = only the same origin can embed. Blocks clickjacking.
        upstream_response
            .insert_header("X-Frame-Options", "SAMEORIGIN")
            .expect("static header value");

        // Control how much URL information is sent in the Referer header.
        // strict-origin-when-cross-origin: send full URL for same-origin,
        // only origin (no path) for cross-origin, nothing for downgrade.
        upstream_response
            .insert_header("Referrer-Policy", "strict-origin-when-cross-origin")
            .expect("static header value");

        // Replace upstream's server banner (e.g., "Apache/2.4.41 (Ubuntu)")
        // to avoid leaking backend technology details to attackers.
        upstream_response
            .insert_header("Server", "Dwaar")
            .expect("static header value");

        // --- Request tracing (ISSUE-006) ---
        upstream_response
            .insert_header("X-Request-Id", &ctx.request_id)
            .expect("UUID is valid header value");

        // --- Analytics injection setup (ISSUE-026a + 026c) ---
        // Detect 2xx HTML responses and prepare the injector. For compressed
        // responses, create a decompressor and strip Content-Encoding so the
        // client receives uncompressed HTML. We remove Content-Length because
        // injection (and decompression) changes the body size.
        let status = upstream_response.status.as_u16();
        if (200..300).contains(&status) {
            let is_html = upstream_response
                .headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|ct| ct.starts_with("text/html"));

            if is_html {
                // Check for Content-Encoding (gzip, br, deflate)
                let encoding = upstream_response
                    .headers
                    .get(http::header::CONTENT_ENCODING)
                    .and_then(|v| v.to_str().ok())
                    .and_then(Encoding::from_header);

                if let Some(enc) = encoding {
                    debug!(
                        request_id = %ctx.request_id,
                        encoding = ?enc,
                        "compressed HTML detected, enabling decompression + injection"
                    );
                    ctx.decompressor = Some(Decompressor::new(enc));
                    upstream_response.remove_header("Content-Encoding");
                } else {
                    debug!(request_id = %ctx.request_id, "HTML response detected, enabling script injection");
                }

                ctx.injector = Some(HtmlInjector::new());
                upstream_response.remove_header("Content-Length");
            }
        }

        // --- Response compression (ISSUE-035) ---
        // Negotiate encoding from client's Accept-Encoding. Compress
        // compressible text responses (HTML, CSS, JS, JSON, SVG).
        // For HTML that went through decompressor→injector, this recompresses.
        let accept_encoding = session
            .req_header()
            .headers
            .get(http::header::ACCEPT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        let content_type = upstream_response
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok());

        let content_encoding = upstream_response
            .headers
            .get(http::header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok());

        let content_length = upstream_response
            .headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        // If we already have a decompressor (HTML injection path), the
        // Content-Encoding was stripped above, so should_compress sees
        // no encoding and will compress the now-decompressed body.
        if !accept_encoding.is_empty() {
            use dwaar_plugins::compress::{negotiate_encoding, should_compress};

            if should_compress(content_type, content_encoding, content_length)
                && let Some(enc) = negotiate_encoding(accept_encoding)
            {
                use dwaar_plugins::compress::ResponseCompressor;

                ctx.compressor = Some(ResponseCompressor::new(enc));
                upstream_response
                    .insert_header("Content-Encoding", enc.header_value())
                    .expect("static header value");
                upstream_response.remove_header("Content-Length");

                debug!(
                    request_id = %ctx.request_id,
                    encoding = enc.header_value(),
                    "response compression enabled"
                );
            }
        }

        Ok(())
    }

    /// Inject analytics script into HTML response bodies (ISSUE-026a).
    ///
    /// Called by Pingora for every chunk of the response body. If the
    /// request context has an active `HtmlInjector`, passes the chunk
    /// through it. The injector modifies the body in-place when it
    /// finds `</head>`.
    ///
    /// Returns `Ok(None)` — no processing delay needed.
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
        // Decompress first (if compressed response)
        if let Some(ref mut decompressor) = ctx.decompressor {
            decompressor.decompress(body, end_of_stream);
        }

        // Then inject into the decompressed HTML
        if let Some(ref mut injector) = ctx.injector {
            injector.process(body, end_of_stream);
        }

        // Finally, compress for the wire (after all modifications)
        if let Some(ref mut compressor) = ctx.compressor {
            compressor.compress(body, end_of_stream);
        }

        Ok(None)
    }

    /// Emit a structured log entry for every completed request.
    ///
    /// Called by Pingora after the response is fully sent (or on fatal error).
    /// Builds a [`RequestLog`] from the request context and session metadata,
    /// then pushes it to the batch writer via the non-blocking [`LogSender`].
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

        // Extract status code from the response (0 if no response was sent)
        let status = session.response_written().map_or(0, |r| r.status.as_u16());

        // Split path and query
        let (path, query) = if let Some(qmark) = ctx.path.find('?') {
            (
                ctx.path[..qmark].to_string(),
                Some(ctx.path[qmark + 1..].to_string()),
            )
        } else {
            (ctx.path.clone(), None)
        };

        let log = RequestLog {
            timestamp: Utc::now(),
            request_id: ctx.request_id.clone(),
            method: ctx.method.clone(),
            path,
            query,
            host: ctx.host.clone().unwrap_or_default(),
            status,
            response_time_us,
            client_ip: ctx
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
            is_bot: ctx.is_bot,
            country: ctx.country.clone(),
            upstream_addr: ctx
                .route_upstream
                .map_or_else(String::new, |a| a.to_string()),
            upstream_response_time_us: 0,
            cache_status: None,
            compression: None,
        };

        // Fan-out: send to log writer and aggregation independently.
        // Clone only when aggregation is enabled to avoid the cost otherwise.
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
    use dwaar_plugins::bot_detect::BotDetector;

    fn make_proxy(routes: Vec<Route>) -> DwaarProxy {
        let table = RouteTable::new(routes);
        let bot_detector = Arc::new(BotDetector::new());
        let rate_limiter = Arc::new(dwaar_plugins::rate_limit::RateLimiter::new());
        DwaarProxy::new(
            Arc::new(ArcSwap::from_pointee(table)),
            None,
            None,
            None,
            None,
            bot_detector,
            rate_limiter,
            None,
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

        assert_eq!(ctx.request_id.len(), 36);
        assert!(ctx.start_time.elapsed().as_secs() < 1);
        assert!(ctx.client_ip.is_none());
        assert!(ctx.host.is_none());
        assert!(ctx.method.is_empty());
        assert!(ctx.path.is_empty());
        assert!(ctx.route_upstream.is_none());
        assert!(ctx.injector.is_none());
        assert!(ctx.decompressor.is_none());
    }

    #[test]
    fn route_table_can_be_swapped_at_runtime() {
        let addr1: SocketAddr = "127.0.0.1:3000".parse().expect("valid");
        let addr2: SocketAddr = "127.0.0.1:4000".parse().expect("valid");

        let proxy = make_proxy(vec![Route::new("v1.example.com", addr1, false, None)]);

        // Initial table has v1
        assert!(proxy.route_table.load().resolve("v1.example.com").is_some());
        assert!(proxy.route_table.load().resolve("v2.example.com").is_none());

        // Swap in a new table with v2 instead — simulates config reload
        let new_table = RouteTable::new(vec![Route::new("v2.example.com", addr2, false, None)]);
        proxy.route_table.store(Arc::new(new_table));

        // Old route gone, new route available
        assert!(proxy.route_table.load().resolve("v1.example.com").is_none());
        assert!(proxy.route_table.load().resolve("v2.example.com").is_some());
    }
}
