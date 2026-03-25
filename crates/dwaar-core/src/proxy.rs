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
//! ## ISSUE-005 scope
//!
//! Only `new_ctx()` and `upstream_peer()` are implemented. The upstream is
//! a single `SocketAddr` passed at construction time (Option B from the
//! design discussion — testable, Rob Pike Rule #5: data dominates).
//!
//! Later issues override more hooks:
//! - ISSUE-006: `request_filter()` populates context metadata
//! - ISSUE-007: `upstream_request_filter()` sets proxy headers
//! - ISSUE-008: `response_filter()` adds security headers
//! - ISSUE-010: `upstream_peer()` uses `RouteTable` instead of hardcoded addr

use std::net::SocketAddr;

use async_trait::async_trait;
use pingora_core::Result;
use pingora_core::upstreams::peer::HttpPeer;
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
    /// This is a simple `SocketAddr` for ISSUE-005. ISSUE-009 replaces it
    /// with `Arc<ArcSwap<RouteTable>>` for dynamic, per-host routing.
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

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        debug!(upstream = %self.upstream, "selecting upstream peer");

        // HttpPeer::new takes (address, tls, sni).
        // tls=false: we're forwarding plain HTTP to the upstream for now.
        // sni="": no TLS means no SNI needed.
        // ISSUE-015 adds TLS support with proper SNI from the route config.
        let peer = HttpPeer::new(self.upstream, false, String::new());
        Ok(Box::new(peer))
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
    fn new_ctx_creates_context() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().expect("valid addr");
        let proxy = DwaarProxy::new(addr);
        let _ctx = proxy.new_ctx();
        // Context creation shouldn't panic. Fields tested in context.rs.
    }
}
