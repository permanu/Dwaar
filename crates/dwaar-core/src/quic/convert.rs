// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Header conversion between HTTP/3, Pingora, and HTTP/1.1 types.
//!
//! Also contains route resolution and utility predicates shared across
//! the H3 request pipeline.

use std::net::SocketAddr;

use arc_swap::ArcSwap;
use dwaar_plugins::plugin::PluginCtx;
use pingora_http::{RequestHeader, ResponseHeader};

use crate::route::{Handler, RouteKind, RouteTable};

/// Errors from the h3 request header parsing step.
#[derive(Debug, thiserror::Error)]
pub enum H3ParseError {
    #[error("failed to build RequestHeader: {0}")]
    BuildHeader(String),

    #[error("failed to insert header '{0}': {1}")]
    InsertHeader(String, String),

    #[error("header '{0}' contains non-ASCII bytes")]
    NonAsciiHeader(String),
}

/// Convert an HTTP/3 request into a `pingora_http::RequestHeader`.
///
/// HTTP/3 uses pseudo-headers (`:method`, `:path`, `:authority`, `:scheme`)
/// that don't appear in the `HeaderMap` — they arrive as fields in the
/// `http::Uri` and `http::Method`. This function translates them back into
/// the Host header and request line that Pingora's type system expects.
pub fn h3_to_pingora_headers(
    method: &http::Method,
    uri: &http::Uri,
    headers: &http::HeaderMap,
) -> Result<RequestHeader, H3ParseError> {
    let path_and_query = uri.path_and_query().map_or("/", |pq| pq.as_str());

    let mut pingora_req = RequestHeader::build(method.as_str(), path_and_query.as_bytes(), None)
        .map_err(|e| H3ParseError::BuildHeader(e.to_string()))?;

    // `:authority` becomes the HTTP/1.1 `Host` header.
    let authority = uri
        .authority()
        .map(http::uri::Authority::as_str)
        .or_else(|| headers.get("host").and_then(|v| v.to_str().ok()));

    if let Some(host) = authority {
        pingora_req
            .insert_header("Host", host.to_owned())
            .map_err(|e| H3ParseError::InsertHeader("Host".into(), e.to_string()))?;
    }

    // Copy all non-pseudo regular headers.
    for (name, value) in headers {
        let name_str = name.as_str();
        if name_str.starts_with(':') {
            continue;
        }
        let name_owned = name_str.to_owned();
        let value_owned: String = value
            .to_str()
            .map_err(|_| H3ParseError::NonAsciiHeader(name_owned.clone()))?
            .to_owned();
        pingora_req
            .insert_header(name_owned.clone(), value_owned)
            .map_err(|e| H3ParseError::InsertHeader(name_owned, e.to_string()))?;
    }

    Ok(pingora_req)
}

/// Set `X-Real-IP` and `X-Forwarded-For` to the QUIC peer's address.
///
/// Client-supplied values are never forwarded (agent-protocol 11.1: the
/// agent's pre-authentication limit keys on `X-Real-IP`); without a peer
/// address both are removed. Mirrors the HTTP/1 and HTTP/2 proxy path.
pub fn set_client_ip_headers(headers: &mut http::HeaderMap, client_ip: Option<std::net::IpAddr>) {
    headers.remove("x-real-ip");
    headers.remove("x-forwarded-for");
    let Some(ip) = client_ip else {
        return;
    };
    let ip = ip.to_canonical();
    if let Ok(value) = http::HeaderValue::from_str(&ip.to_string()) {
        headers.insert("x-real-ip", value.clone());
        headers.insert("x-forwarded-for", value);
    }
}

/// Convert a `pingora_http::ResponseHeader` into an `http::Response<()>` for h3.
///
/// h3's `send_response` takes `http::Response<()>` — this builds one from the
/// Pingora type by iterating its header map.
pub fn pingora_resp_to_h3(
    pingora_resp: &ResponseHeader,
    status: u16,
) -> Result<http::Response<()>, String> {
    let mut builder = http::Response::builder().status(status);

    // Reading via Deref is safe — we're not mutating (Guardrail #7).
    for (name, value) in &pingora_resp.headers {
        builder = builder.header(name, value);
    }

    builder.body(()).map_err(|e| e.to_string())
}

/// Build a [`PluginCtx`] from the h3 request components.
///
/// Populates `host`, `method`, `path`, and marks `is_tls = true` — QUIC
/// is always TLS 1.3 so this is unconditional.
pub fn build_plugin_ctx(
    method: &http::Method,
    uri: &http::Uri,
    headers: &http::HeaderMap,
) -> PluginCtx {
    PluginCtx {
        method: compact_str::CompactString::from(method.as_str()),
        path: compact_str::CompactString::from(uri.path()),
        is_tls: true,
        host: uri
            .host()
            .map(compact_str::CompactString::from)
            .or_else(|| {
                headers
                    .get(http::header::HOST)
                    .and_then(|v| v.to_str().ok())
                    .map(compact_str::CompactString::from)
            }),
        ..PluginCtx::default()
    }
}

/// Whether `method` is safe to replay over 0-RTT (idempotent + no side effects).
///
/// RFC 9110 §9.2.1 defines safe methods as those that "do not request that
/// the origin server perform any action other than retrieval."
pub fn is_idempotent_method(method: &http::Method) -> bool {
    matches!(
        *method,
        http::Method::GET | http::Method::HEAD | http::Method::OPTIONS
    )
}

/// Whether a header is a hop-by-hop header that must not be forwarded.
///
/// These headers describe the single-hop connection and lose meaning when
/// the proxy terminates the connection and opens a new one upstream.
pub fn is_hop_by_hop(name: &str) -> bool {
    name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("te")
        || name.eq_ignore_ascii_case("trailer")
        || name.eq_ignore_ascii_case("proxy-authorization")
        || name.eq_ignore_ascii_case("proxy-authenticate")
        || name.eq_ignore_ascii_case("upgrade")
}

/// Look up the upstream address for `host` + `path` in the route table.
///
/// Runs the same path-based handler matching as the HTTP/1-2 proxy path
/// (`proxy.rs` `request_filter`): iterates handler blocks, finds the first
/// whose `PathMatcher` matches the request path, and extracts the upstream.
/// Only `ReverseProxy` and `ReverseProxyPool` handlers are supported over
/// H3 — other handler types return 502.
/// Returns `(addr, upstream_h2)` — the upstream address and whether H2
/// multiplexing is configured for this backend.
pub fn resolve_upstream_addr(
    route_table: &ArcSwap<RouteTable>,
    host: &str,
    path: &str,
) -> Result<(SocketAddr, bool), u16> {
    let table = route_table.load();
    let Some(route) = table.resolve(host) else {
        return Err(502);
    };
    // Webhook routes are served only over HTTP/1.1 and HTTP/2, where the
    // body cap and client-address headers are enforced; 421 makes the
    // client retry on such a connection.
    if route.kind == RouteKind::Webhook {
        return Err(421);
    }

    for block in &route.handlers {
        if block.matcher.matches(path).is_none() {
            continue;
        }
        match &block.handler {
            Handler::ReverseProxy {
                upstream,
                upstream_h2,
                ..
            } => {
                return Ok((*upstream, *upstream_h2));
            }
            Handler::ReverseProxyPool { pool, upstream_h2 } => {
                if let Some(addr) = pool.select(None) {
                    return Ok((addr, *upstream_h2));
                }
                return Err(503);
            }
            _ => return Err(502),
        }
    }

    Err(502)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h3_to_pingora_headers_converts_get() {
        let method = http::Method::GET;
        let uri: http::Uri = "https://example.com/path?q=1".parse().expect("valid URI");
        let headers = http::HeaderMap::new();

        let req = h3_to_pingora_headers(&method, &uri, &headers).expect("conversion ok");
        assert_eq!(req.method, http::Method::GET);
        assert!(req.headers.get("host").is_some());
    }

    #[test]
    fn h3_to_pingora_headers_preserves_custom_headers() {
        let method = http::Method::POST;
        let uri: http::Uri = "https://api.example.com/data".parse().expect("valid URI");
        let mut headers = http::HeaderMap::new();
        headers.insert("x-request-id", "abc123".parse().expect("valid value"));
        headers.insert(
            "content-type",
            "application/json".parse().expect("valid value"),
        );

        let req = h3_to_pingora_headers(&method, &uri, &headers).expect("conversion ok");
        assert!(req.headers.get("x-request-id").is_some());
        assert!(req.headers.get("content-type").is_some());
    }

    #[test]
    fn h3_to_pingora_headers_skips_pseudo_headers() {
        let method = http::Method::GET;
        let uri: http::Uri = "https://example.com/".parse().expect("valid URI");
        let headers = http::HeaderMap::new();

        let req = h3_to_pingora_headers(&method, &uri, &headers).expect("conversion ok");
        assert!(req.headers.get(":path").is_none());
    }

    #[test]
    fn client_address_headers_are_dwaars_over_h3() {
        // agent-protocol 11.1: X-Real-IP is the address Dwaar saw, overwriting
        // any client value — on HTTP/3 as on HTTP/1 and HTTP/2.
        let mut headers = http::HeaderMap::new();
        headers.insert("x-real-ip", "6.6.6.6".parse().expect("value"));
        headers.append("x-forwarded-for", "6.6.6.6".parse().expect("value"));
        headers.append("x-forwarded-for", "7.7.7.7".parse().expect("value"));
        headers.insert("x-custom", "kept".parse().expect("value"));

        set_client_ip_headers(&mut headers, Some("203.0.113.9".parse().expect("ip")));
        let real: Vec<_> = headers.get_all("x-real-ip").iter().collect();
        assert_eq!(real, ["203.0.113.9"]);
        let xff: Vec<_> = headers.get_all("x-forwarded-for").iter().collect();
        assert_eq!(xff, ["203.0.113.9"]);
        assert_eq!(headers.get("x-custom").expect("kept"), "kept");

        // An IPv4-mapped IPv6 peer is reported as IPv4.
        set_client_ip_headers(
            &mut headers,
            Some("::ffff:198.51.100.7".parse().expect("ip")),
        );
        assert_eq!(headers.get("x-real-ip").expect("set"), "198.51.100.7");

        set_client_ip_headers(&mut headers, None);
        assert!(headers.get("x-real-ip").is_none());
        assert!(headers.get("x-forwarded-for").is_none());
    }

    #[test]
    fn idempotent_methods_allowed_on_0rtt() {
        assert!(is_idempotent_method(&http::Method::GET));
        assert!(is_idempotent_method(&http::Method::HEAD));
        assert!(is_idempotent_method(&http::Method::OPTIONS));
    }

    #[test]
    fn non_idempotent_methods_blocked_on_0rtt() {
        assert!(!is_idempotent_method(&http::Method::POST));
        assert!(!is_idempotent_method(&http::Method::PUT));
        assert!(!is_idempotent_method(&http::Method::DELETE));
        assert!(!is_idempotent_method(&http::Method::PATCH));
    }

    #[test]
    fn hop_by_hop_headers_are_filtered() {
        assert!(is_hop_by_hop("connection"));
        assert!(is_hop_by_hop("Transfer-Encoding"));
        assert!(is_hop_by_hop("keep-alive"));
        assert!(!is_hop_by_hop("content-type"));
        assert!(!is_hop_by_hop("x-custom-header"));
    }

    #[test]
    fn h3_refuses_webhook_routes() {
        use crate::route::Route;
        let upstream: SocketAddr = "127.0.0.1:7461".parse().expect("addr");
        let table = ArcSwap::from_pointee(RouteTable::new(vec![
            Route::webhook("hooks.example.com", upstream, true, None),
            Route::new("app.example.com", upstream, true, None),
        ]));
        // 421: the client retries over HTTP/1.1 or HTTP/2, where the webhook
        // body cap and X-Real-IP handling apply.
        assert_eq!(
            resolve_upstream_addr(&table, "hooks.example.com", "/hooks/prj_1"),
            Err(421)
        );
        assert_eq!(
            resolve_upstream_addr(&table, "app.example.com", "/"),
            Ok((upstream, false))
        );
    }
}
