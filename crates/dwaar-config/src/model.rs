// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Typed representation of a parsed Dwaarfile.
//!
//! These structs are the output of the parser and the input to the
//! route table compiler (ISSUE-012). They represent the full config —
//! not just routing, but TLS, headers, redirects, compression, etc.

use std::net::SocketAddr;

/// A fully parsed Dwaarfile — zero or more site blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DwaarConfig {
    pub sites: Vec<SiteBlock>,
}

/// One site block: a domain (or pattern) with its directives.
///
/// ```text
/// api.example.com {
///     reverse_proxy localhost:3000
///     tls auto
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteBlock {
    /// The domain or pattern this block matches.
    /// Examples: `"api.example.com"`, `"*.example.com"`, `":8080"`
    pub address: String,

    /// Directives inside the block, in source order.
    pub directives: Vec<Directive>,
}

/// A single directive inside a site block.
///
/// Each variant maps to a Caddyfile-compatible directive.
/// Unknown directives are captured as `Unknown` for clear error reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Directive {
    /// `reverse_proxy localhost:8080` or `reverse_proxy 10.0.0.1:3000 10.0.0.2:3000`
    ReverseProxy(ReverseProxyDirective),

    /// `tls auto` / `tls off` / `tls internal` / `tls /cert.pem /key.pem`
    Tls(TlsDirective),

    /// `header X-Custom "value"` / `header -Server` (delete)
    Header(HeaderDirective),

    /// `redir /old /new 301`
    Redir(RedirDirective),

    /// `encode gzip` / `encode zstd gzip`
    Encode(EncodeDirective),
}

/// `reverse_proxy` — route requests to one or more upstream backends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReverseProxyDirective {
    /// One or more upstream addresses. Multiple means load-balanced.
    pub upstreams: Vec<UpstreamAddr>,
}

/// An upstream address — either a socket address or a host:port string
/// that may need DNS resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamAddr {
    /// Fully resolved address like `127.0.0.1:8080`
    SocketAddr(SocketAddr),
    /// Host:port that may need resolution, like `backend:8080`
    HostPort(String),
}

/// `tls` — configure TLS behavior for a site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsDirective {
    /// `tls auto` or just omitting tls (default for HTTPS domains)
    Auto,
    /// `tls off` — no TLS, plain HTTP only
    Off,
    /// `tls internal` — use a self-signed cert (dev/testing)
    Internal,
    /// `tls /path/to/cert.pem /path/to/key.pem` — manual cert files
    Manual { cert_path: String, key_path: String },
}

/// `header` — add, set, or remove a response header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderDirective {
    /// `header X-Custom "value"` — set header to value
    Set { name: String, value: String },
    /// `header -Server` — remove header from response
    Delete { name: String },
}

/// `redir` — HTTP redirect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirDirective {
    /// Source path (what to match)
    pub from: String,
    /// Destination URL or path
    pub to: String,
    /// HTTP status code (301, 302, 307, 308). Defaults to 308 like Caddy.
    pub code: u16,
}

/// `encode` — response compression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodeDirective {
    /// Encodings to enable, in preference order.
    /// Valid: "gzip", "zstd", "br" (brotli)
    pub encodings: Vec<String>,
}

impl DwaarConfig {
    /// Create an empty config.
    pub fn new() -> Self {
        Self { sites: Vec::new() }
    }
}

impl Default for DwaarConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config() {
        let config = DwaarConfig::new();
        assert!(config.sites.is_empty());
    }

    #[test]
    fn site_block_with_directives() {
        let site = SiteBlock {
            address: "api.example.com".to_string(),
            directives: vec![
                Directive::ReverseProxy(ReverseProxyDirective {
                    upstreams: vec![UpstreamAddr::SocketAddr(
                        "127.0.0.1:3000".parse().expect("valid"),
                    )],
                }),
                Directive::Tls(TlsDirective::Auto),
            ],
        };

        assert_eq!(site.address, "api.example.com");
        assert_eq!(site.directives.len(), 2);
    }

    #[test]
    fn upstream_addr_variants() {
        let resolved = UpstreamAddr::SocketAddr("127.0.0.1:8080".parse().expect("valid"));
        let named = UpstreamAddr::HostPort("backend:8080".to_string());

        // Both should be representable
        assert!(matches!(resolved, UpstreamAddr::SocketAddr(_)));
        assert!(matches!(named, UpstreamAddr::HostPort(_)));
    }

    #[test]
    fn header_directive_variants() {
        let set = HeaderDirective::Set {
            name: "X-Custom".to_string(),
            value: "hello".to_string(),
        };
        let del = HeaderDirective::Delete {
            name: "Server".to_string(),
        };

        assert!(matches!(set, HeaderDirective::Set { .. }));
        assert!(matches!(del, HeaderDirective::Delete { .. }));
    }

    #[test]
    fn redir_defaults_to_308() {
        let redir = RedirDirective {
            from: "/old".to_string(),
            to: "/new".to_string(),
            code: 308,
        };
        assert_eq!(redir.code, 308);
    }

    #[test]
    fn config_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<DwaarConfig>();
    }
}
