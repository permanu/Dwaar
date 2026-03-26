// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Core proxy implementation — the `ProxyHttp` trait is Dwaar's engine.
//!
//! `DwaarProxy` implements Pingora's [`ProxyHttp`] trait, which defines how
//! every HTTP request is processed. Pingora calls our lifecycle methods in
//! order:
//!
//! 1. `new_ctx()` — create per-request state
//! 2. `early_request_filter()` — before any modules run
//! 3. `request_filter()` — validate, rate-limit, access control
//! 4. `upstream_peer()` — **where should this request go?**
//! 5. `upstream_request_filter()` — modify headers before sending upstream
//! 6. `upstream_response_filter()` — modify response headers from upstream
//! 7. `response_filter()` — modify headers before sending to client
//! 8. `logging()` — emit metrics and access logs
//!
//! ## Implemented hooks
//!
//! - `new_ctx()` — sets `start_time` and `request_id` (ISSUE-005)
//! - `request_filter()` — extracts client IP, host, method, path (ISSUE-006)
//! - `upstream_peer()` — returns the hardcoded upstream (ISSUE-005)
//! - `upstream_request_filter()` — adds proxy headers, strips hop-by-hop (ISSUE-007)
//! - `response_filter()` — adds `X-Request-Id` header (ISSUE-006)
//!
//! ## Later issues
//!
//! - ISSUE-008: `response_filter()` adds security headers
//! - ISSUE-010: `upstream_peer()` uses `RouteTable` instead of hardcoded addr

use std::net::SocketAddr;

use async_trait::async_trait;
use pingora_core::Result;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{ProxyHttp, Session};
use tracing::debug;

use crate::context::RequestContext;

/// The Dwaar proxy engine.
///
/// Implements Pingora's `ProxyHttp` to handle every HTTP request that
/// arrives at the proxy. Currently forwards all traffic to a single
/// upstream; ISSUE-009/010 will replace this with a route table.
#[derive(Debug)]
pub struct DwaarProxy {
    /// The upstream server address to forward all requests to.
    ///
    /// This is a simple `SocketAddr` for now. ISSUE-009 replaces it with
    /// `Arc<ArcSwap<RouteTable>>` for dynamic, per-host routing.
    upstream: SocketAddr,
}

impl DwaarProxy {
    /// Create a new proxy that forwards all traffic to the given upstream.
    ///
    /// # Arguments
    ///
    /// * `upstream` - The backend server address (e.g., `127.0.0.1:8080`)
    pub fn new(upstream: SocketAddr) -> Self {
        Self { upstream }
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

        // --- Host ---
        // In HTTP/1.1, the Host header is mandatory (RFC 7230 §5.4).
        // In HTTP/2, it's the `:authority` pseudo-header.
        // Pingora normalizes both into the header map under "host".
        // .to_str() converts the HeaderValue bytes to &str (fails if not UTF-8).
        ctx.host = header
            .headers
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string);

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
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        debug!(upstream = %self.upstream, "selecting upstream peer");

        let peer = HttpPeer::new(self.upstream, false, String::new());
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

    /// Add the `X-Request-Id` header to every response sent to the client.
    ///
    /// This header lets clients correlate their request with server-side logs.
    /// If a user reports "my request failed," they can include the request ID
    /// and we can find it in our logs instantly.
    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        upstream_response
            .insert_header("X-Request-Id", &ctx.request_id)
            .expect("X-Request-Id header value is always valid ASCII");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_stores_upstream() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().expect("valid addr");
        let proxy = DwaarProxy::new(addr);
        assert_eq!(proxy.upstream, addr);
    }

    #[test]
    fn new_ctx_has_request_id_and_timing() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().expect("valid addr");
        let proxy = DwaarProxy::new(addr);
        let ctx = proxy.new_ctx();

        // request_id should be a 36-char UUID v7
        assert_eq!(ctx.request_id.len(), 36);
        // start_time should be very recent (within 1 second)
        assert!(ctx.start_time.elapsed().as_secs() < 1);
        // Metadata fields should be empty (populated in request_filter)
        assert!(ctx.client_ip.is_none());
        assert!(ctx.host.is_none());
        assert!(ctx.method.is_empty());
        assert!(ctx.path.is_empty());
    }
}
