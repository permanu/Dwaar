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

use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use pingora_core::Result;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::{Error, ErrorType::HTTPStatus};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{ProxyHttp, Session};
use tracing::{debug, warn};

use crate::context::RequestContext;
use crate::route::RouteTable;

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
}

impl DwaarProxy {
    /// Create a new proxy backed by the given route table.
    ///
    /// The `ArcSwap` allows hot-reloading routes without restarting
    /// the proxy — config reload code calls `route_table.store(new_table)`.
    pub fn new(route_table: Arc<ArcSwap<RouteTable>>) -> Self {
        Self { route_table }
    }
}

#[async_trait]
impl ProxyHttp for DwaarProxy {
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX {
        RequestContext::new()
    }

    /// Extract per-request metadata from the incoming HTTP request.
    ///
    /// This runs after Pingora has parsed the HTTP headers but before
    /// `upstream_peer()` selects the backend. We read:
    /// - Client IP from the TCP socket's peer address
    /// - Host from the `Host` header (or HTTP/2 `:authority` pseudo-header)
    /// - HTTP method (GET, POST, etc.)
    /// - Request path including query string
    ///
    /// Returns `Ok(false)` — meaning "don't short-circuit, continue to the
    /// next lifecycle phase." Returning `Ok(true)` would mean "I already
    /// sent a response, skip everything else."
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        // --- Client IP ---
        // session.client_addr() returns Pingora's SocketAddr enum (Inet or Unix).
        // .as_inet() extracts the std::net::SocketAddr if it's a TCP connection.
        // .map(|addr| addr.ip()) extracts just the IpAddr, discarding the port.
        ctx.client_ip = session
            .client_addr()
            .and_then(|addr| addr.as_inet())
            .map(std::net::SocketAddr::ip);

        // --- HTTP headers ---
        // req_header() gives us the parsed HTTP request. Pingora has already
        // done all the HTTP/1.1 and HTTP/2 parsing by this point.
        let header = session.req_header();

        // HTTP/1.1 sends the hostname in the Host header (RFC 7230 §5.4).
        // HTTP/2 uses the :authority pseudo-header, which Pingora stores in
        // the URI authority — not in the headers map. We check both.
        ctx.host = header
            .headers
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string)
            .or_else(|| header.uri.authority().map(|a| a.as_str().to_string()));

        // --- Method ---
        // .as_str() returns "GET", "POST", etc. as a &str.
        ctx.method = header.method.as_str().to_string();

        // --- Path ---
        // .uri.path() returns just the path component ("/api/users").
        // .uri.path_and_query() includes the query string ("/api/users?page=2").
        // We store path_and_query because analytics and logging need the full URL.
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

        let peer = HttpPeer::new(route.upstream, false, String::new());
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
    /// - `X-Forwarded-Proto`: `http` (ISSUE-015 will set `https` for TLS).
    /// - `X-Request-Id`: The UUID v7 from the request context.
    ///
    /// ## Headers removed (RFC 7230 §6.1)
    ///
    /// Hop-by-hop headers are meaningful only for a single transport-level
    /// connection — they must not be forwarded to the upstream.
    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
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

            // X-Forwarded-For: append client IP to the chain.
            // If the client sent "X-Forwarded-For: 1.2.3.4" (claiming to be
            // behind another proxy), we append our client_ip: "1.2.3.4, 5.6.7.8".
            // This builds a chain: [original client, proxy1, proxy2, ...].
            let xff = upstream_request
                .headers
                .get("X-Forwarded-For")
                .and_then(|v| v.to_str().ok())
                .map_or_else(
                    || ip_str.clone(),
                    |existing| format!("{existing}, {ip_str}"),
                );

            upstream_request
                .insert_header("X-Forwarded-For", &xff)
                .expect("X-Forwarded-For value is valid");
        }

        // X-Forwarded-Proto: always "http" for now since we don't have TLS yet.
        // ISSUE-015 will check the downstream connection and set "https" when
        // the client connected over TLS.
        upstream_request
            .insert_header("X-Forwarded-Proto", "http")
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
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        // --- Security headers (ISSUE-008) ---
        // Each insert_header call uses a static string value, so .expect()
        // is safe — these can never fail at runtime.

        // HSTS: tell browsers to always use HTTPS for this domain.
        // max-age=31536000 = 1 year. includeSubDomains extends to all subdomains.
        // Note: this is safe even before we have TLS (ISSUE-015), because
        // browsers only honor HSTS headers received over HTTPS connections.
        // Over plain HTTP, browsers ignore it per the RFC.
        upstream_response
            .insert_header(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            )
            .expect("static header value");

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

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;
    use crate::route::Route;

    fn make_proxy(routes: Vec<Route>) -> DwaarProxy {
        let table = RouteTable::new(routes);
        DwaarProxy::new(Arc::new(ArcSwap::from_pointee(table)))
    }

    #[test]
    fn proxy_holds_route_table() {
        let proxy = make_proxy(vec![Route::new(
            "example.com",
            "127.0.0.1:8080".parse().expect("valid"),
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
    }

    #[test]
    fn route_table_can_be_swapped_at_runtime() {
        let addr1: SocketAddr = "127.0.0.1:3000".parse().expect("valid");
        let addr2: SocketAddr = "127.0.0.1:4000".parse().expect("valid");

        let proxy = make_proxy(vec![Route::new("v1.example.com", addr1)]);

        // Initial table has v1
        assert!(proxy.route_table.load().resolve("v1.example.com").is_some());
        assert!(proxy.route_table.load().resolve("v2.example.com").is_none());

        // Swap in a new table with v2 instead — simulates config reload
        let new_table = RouteTable::new(vec![Route::new("v2.example.com", addr2)]);
        proxy.route_table.store(Arc::new(new_table));

        // Old route gone, new route available
        assert!(proxy.route_table.load().resolve("v1.example.com").is_none());
        assert!(proxy.route_table.load().resolve("v2.example.com").is_some());
    }
}
