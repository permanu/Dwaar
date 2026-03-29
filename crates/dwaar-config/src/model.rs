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

    /// `rate_limit 100/s`
    RateLimit(RateLimitDirective),

    /// `respond "body" 404` / `respond 204` / `respond "ok"`
    Respond(RespondDirective),

    /// `rewrite /new-path`
    Rewrite(RewriteDirective),

    /// `uri strip_prefix /api` / `uri strip_suffix .html` / `uri replace /old /new`
    Uri(UriDirective),

    /// `basicauth { user hash }` or `basic_auth { user hash }`
    BasicAuth(BasicAuthDirective),

    /// `forward_auth localhost:9091 { uri /api/verify; copy_headers Remote-User }`
    ForwardAuth(ForwardAuthDirective),

    /// `root * /var/www` — sets the filesystem root for `file_server`
    Root(RootDirective),

    /// `file_server` or `file_server browse`
    FileServer(FileServerDirective),

    /// `handle [pattern] { directives }` — first match wins, path NOT stripped
    Handle(HandleDirective),

    /// `handle_path <pattern> { directives }` — first match wins, prefix IS stripped
    HandlePath(HandlePathDirective),

    /// `route [pattern] { directives }` — all matching blocks execute in order
    Route(RouteDirective),

    /// `php_fastcgi localhost:9000` — proxy PHP requests to `FastCGI` backend
    PhpFastcgi(PhpFastcgiDirective),
}

/// `handle` — path-scoped directive block. First match wins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleDirective {
    /// Path pattern to match. `None` = catch-all.
    pub matcher: Option<String>,
    /// Directives inside the block.
    pub directives: Vec<Directive>,
}

/// `handle_path` — like handle but strips the matched prefix from the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandlePathDirective {
    /// Path prefix to match (required).
    pub path_prefix: String,
    /// Directives inside the block.
    pub directives: Vec<Directive>,
}

/// `route` — ordered execution block. All matching blocks run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteDirective {
    /// Path pattern to match. `None` = match all.
    pub matcher: Option<String>,
    /// Directives inside the block.
    pub directives: Vec<Directive>,
}

/// `php_fastcgi` — proxy PHP requests to a `FastCGI` backend (php-fpm).
///
/// Caddy syntax: `php_fastcgi localhost:9000`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhpFastcgiDirective {
    /// `FastCGI` backend address (TCP or Unix socket path).
    pub upstream: UpstreamAddr,
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

/// `rate_limit 100/s` — per-IP rate limiting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitDirective {
    /// Maximum requests per second per IP for this route.
    pub requests_per_second: u32,
}

/// `respond` — return a static response without proxying to upstream.
///
/// Syntax follows Caddy: `respond [body] [status]`
/// - `respond "Not Found" 404` — body + status
/// - `respond 204` — status only (if single arg is a valid 3-digit code)
/// - `respond "ok"` — body only (default status 200)
/// - `respond` — empty body, status 200
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RespondDirective {
    /// HTTP status code. Defaults to 200.
    pub status: u16,
    /// Response body. Empty string means no body.
    pub body: String,
}

/// `basicauth` / `basic_auth` — HTTP Basic Authentication.
///
/// Caddy syntax: `basic_auth [<realm>] { username hash }`
/// Dwaar also accepts `basicauth` (no underscore).
///
/// `Debug` is manually implemented to redact password hashes.
#[derive(Clone, PartialEq, Eq)]
pub struct BasicAuthDirective {
    /// Optional realm name for the `WWW-Authenticate` header.
    pub realm: Option<String>,
    /// Credentials: `(username, bcrypt_hash)` pairs.
    pub credentials: Vec<BasicAuthCredential>,
}

impl std::fmt::Debug for BasicAuthDirective {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BasicAuthDirective")
            .field("realm", &self.realm)
            .field("user_count", &self.credentials.len())
            .field("credentials", &"[REDACTED]")
            .finish()
    }
}

/// A single username + password hash pair.
///
/// `Debug` redacts the hash to prevent accidental credential exposure in logs.
#[derive(Clone, PartialEq, Eq)]
pub struct BasicAuthCredential {
    pub username: String,
    pub password_hash: String,
}

impl std::fmt::Debug for BasicAuthCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BasicAuthCredential")
            .field("username", &self.username)
            .field("password_hash", &"[REDACTED]")
            .finish()
    }
}

/// `forward_auth` — subrequest to external auth service before proxying.
///
/// Caddy syntax: `forward_auth <upstream> { uri /path; copy_headers Header1 Header2 }`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardAuthDirective {
    /// Auth service address (e.g., `authelia:9091` or `127.0.0.1:9091`).
    pub upstream: UpstreamAddr,
    /// URI path to send to the auth service. Defaults to the original request URI.
    pub uri: Option<String>,
    /// Headers to copy from auth response to upstream request.
    pub copy_headers: Vec<String>,
}

/// `root` — set the filesystem root for `file_server`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootDirective {
    /// Filesystem path (e.g., `/var/www/html`).
    pub path: String,
}

/// `file_server` — serve static files from the `root` directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileServerDirective {
    /// Enable directory listing.
    pub browse: bool,
}

/// `rewrite` — replace the request URI sent to upstream.
///
/// `rewrite /new-path` replaces the full URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewriteDirective {
    /// The new URI to send to upstream.
    pub to: String,
}

/// `uri` — partial URI transformation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UriDirective {
    pub operation: UriOperation,
}

/// The specific operation a `uri` directive performs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UriOperation {
    /// `uri strip_prefix /api` — remove prefix from path
    StripPrefix(String),
    /// `uri strip_suffix .html` — remove suffix from path
    StripSuffix(String),
    /// `uri replace /old /new` — substring replacement
    Replace { find: String, replace: String },
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
    fn rate_limit_directive() {
        let rl = RateLimitDirective {
            requests_per_second: 100,
        };
        assert_eq!(rl.requests_per_second, 100);
    }

    #[test]
    fn config_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<DwaarConfig>();
    }
}
