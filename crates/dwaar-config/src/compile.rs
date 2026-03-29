// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Compile a parsed [`DwaarConfig`] into runtime structures.
//!
//! The parser produces rich config (TLS, headers, compression, etc.).
//! This module extracts routing info for the proxy engine and TLS
//! config for the cert store.

use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;

use bytes::Bytes;
use compact_str::CompactString;
use dwaar_core::route::{
    BlockKind, Handler, HandlerBlock, PathMatcher, RewriteRule, Route, RouteTable, is_valid_domain,
};
use tracing::warn;

use crate::model::{
    Directive, DwaarConfig, FileServerDirective, PhpFastcgiDirective, RespondDirective,
    ReverseProxyDirective, RootDirective, TlsDirective, UpstreamAddr, UriOperation,
};
use dwaar_plugins::basic_auth::BasicAuthConfig;
use dwaar_plugins::forward_auth::ForwardAuthConfig;

/// Compile a parsed config into a route table for the proxy engine.
///
/// Each site block produces one `Route`. Sites with `reverse_proxy` get a
/// `Handler::ReverseProxy`; sites with `respond` get a `Handler::StaticResponse`.
/// Sites without a handler directive are skipped with a warning.
#[allow(clippy::too_many_lines)]
pub fn compile_routes(config: &DwaarConfig) -> RouteTable {
    let mut routes = Vec::with_capacity(config.sites.len());

    for site in &config.sites {
        if !is_valid_domain(&site.address) {
            warn!(
                address = %site.address,
                "site address is not a valid hostname, skipping"
            );
            continue;
        }

        let tls = site_has_tls(&site.directives);

        // Check for handle/handle_path/route blocks first — these create multi-handler routes
        let handle_blocks = compile_handle_blocks(&site.directives);
        if !handle_blocks.is_empty() {
            routes.push(Route::with_handlers(&site.address, tls, handle_blocks));
            continue;
        }

        // Flat site (no handle blocks) — extract single handler + site-level middleware
        let rate_limit_rps = find_rate_limit(&site.directives);
        let rewrites = collect_rewrites(&site.directives);
        let basic_auth = compile_basic_auth(&site.directives);
        let forward_auth = compile_forward_auth(&site.directives);

        // Try reverse_proxy first (most common)
        if let Some(rp) = find_reverse_proxy(&site.directives) {
            let Some(addr) = resolve_upstream(&rp.upstreams) else {
                warn!(
                    address = %site.address,
                    "could not resolve any upstream address, skipping"
                );
                continue;
            };
            let handler = HandlerBlock {
                kind: BlockKind::Handle,
                matcher: PathMatcher::Any,
                rate_limit_rps,
                under_attack: false,
                rewrites,
                basic_auth,
                forward_auth,
                handler: Handler::ReverseProxy { upstream: addr },
            };
            routes.push(Route::with_handlers(&site.address, tls, vec![handler]));
            continue;
        }

        // Try respond (static response, no upstream)
        if let Some(resp) = find_respond(&site.directives) {
            let handler = HandlerBlock {
                kind: BlockKind::Handle,
                matcher: PathMatcher::Any,
                rate_limit_rps,
                under_attack: false,
                rewrites,
                basic_auth,
                forward_auth,
                handler: Handler::StaticResponse {
                    status: resp.status,
                    body: Bytes::from(resp.body.clone()),
                },
            };
            routes.push(Route::with_handlers(&site.address, tls, vec![handler]));
            continue;
        }

        // Try file_server (static file serving, no upstream)
        if let Some(fs_directive) = find_file_server(&site.directives) {
            let root_path = find_root(&site.directives).map_or_else(
                || {
                    warn!(address = %site.address, "file_server without root directive, using '.'");
                    PathBuf::from(".")
                },
                |r| PathBuf::from(&r.path),
            );
            let handler = HandlerBlock {
                kind: BlockKind::Handle,
                matcher: PathMatcher::Any,
                rate_limit_rps,
                under_attack: false,
                rewrites,
                basic_auth,
                forward_auth,
                handler: Handler::FileServer {
                    root: root_path,
                    browse: fs_directive.browse,
                },
            };
            routes.push(Route::with_handlers(&site.address, tls, vec![handler]));
            continue;
        }

        // Try php_fastcgi
        if let Some(fcgi) = find_php_fastcgi(&site.directives) {
            let Some(addr) = resolve_upstream(std::slice::from_ref(&fcgi.upstream)) else {
                warn!(address = %site.address, "could not resolve FastCGI upstream, skipping");
                continue;
            };
            let root_path = find_root(&site.directives)
                .map_or_else(|| PathBuf::from("."), |r| PathBuf::from(&r.path));
            let handler = HandlerBlock {
                kind: BlockKind::Handle,
                matcher: PathMatcher::Any,
                rate_limit_rps,
                under_attack: false,
                rewrites,
                basic_auth,
                forward_auth,
                handler: Handler::FastCgi {
                    upstream: addr,
                    root: root_path,
                },
            };
            routes.push(Route::with_handlers(&site.address, tls, vec![handler]));
            continue;
        }

        warn!(
            address = %site.address,
            "site has no handler directive (reverse_proxy, respond, file_server, php_fastcgi), skipping"
        );
    }

    RouteTable::new(routes)
}

/// Per-domain TLS config extracted from the parsed Dwaarfile.
#[derive(Debug, Clone)]
pub struct CompiledTlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

/// Extract TLS configs from the parsed Dwaarfile.
///
/// Returns a map of domain → cert/key paths for sites that have
/// `tls /cert.pem /key.pem` directives. Sites with `tls auto`,
/// `tls off`, or `tls internal` are not included (those are handled
/// by ACME or skipped).
pub fn compile_tls_configs(config: &DwaarConfig) -> HashMap<String, CompiledTlsConfig> {
    let mut tls_configs = HashMap::new();

    for site in &config.sites {
        for directive in &site.directives {
            if let Directive::Tls(TlsDirective::Manual {
                cert_path,
                key_path,
            }) = directive
            {
                tls_configs.insert(
                    site.address.to_lowercase(),
                    CompiledTlsConfig {
                        cert_path: PathBuf::from(cert_path),
                        key_path: PathBuf::from(key_path),
                    },
                );
            }
        }
    }

    tls_configs
}

/// Returns true if any site in the config has a TLS directive
/// that requires a TLS listener (manual certs or auto).
pub fn has_tls_sites(config: &DwaarConfig) -> bool {
    config
        .sites
        .iter()
        .any(|site| site_has_tls(&site.directives))
}

/// Extract domains that use `tls auto` — these need ACME cert provisioning.
pub fn compile_acme_domains(config: &DwaarConfig) -> Vec<String> {
    config
        .sites
        .iter()
        .filter(|site| {
            site.directives
                .iter()
                .any(|d| matches!(d, Directive::Tls(TlsDirective::Auto)))
        })
        .map(|site| site.address.to_lowercase())
        .collect()
}

/// Returns true if a site's directives include a TLS config that
/// isn't explicitly `off`. Sites with `tls auto`, `tls internal`,
/// or `tls /cert /key` all want HTTPS; only `tls off` opts out.
fn site_has_tls(directives: &[Directive]) -> bool {
    directives.iter().any(|d| match d {
        Directive::Tls(TlsDirective::Off) => false,
        Directive::Tls(_) => true,
        _ => false,
    })
}

fn find_reverse_proxy(directives: &[Directive]) -> Option<&ReverseProxyDirective> {
    directives.iter().find_map(|d| match d {
        Directive::ReverseProxy(rp) => Some(rp),
        _ => None,
    })
}

/// Compile `handle`/`handle_path`/`route` blocks into `HandlerBlock`s.
/// Returns empty Vec if the site has no handle blocks (flat site).
fn compile_handle_blocks(directives: &[Directive]) -> Vec<HandlerBlock> {
    let mut blocks = Vec::new();

    for d in directives {
        match d {
            Directive::Handle(h) => {
                let matcher = compile_path_matcher(h.matcher.as_ref());
                if let Some(block) = compile_single_block(BlockKind::Handle, matcher, &h.directives)
                {
                    blocks.push(block);
                }
            }
            Directive::HandlePath(hp) => {
                let matcher = compile_path_matcher(Some(&hp.path_prefix));
                if let Some(block) =
                    compile_single_block(BlockKind::HandlePath, matcher, &hp.directives)
                {
                    blocks.push(block);
                }
            }
            Directive::Route(r) => {
                let matcher = compile_path_matcher(r.matcher.as_ref());
                if let Some(block) = compile_single_block(BlockKind::Route, matcher, &r.directives)
                {
                    blocks.push(block);
                }
            }
            _ => {} // site-level directives outside handle blocks (tls, encode, etc.)
        }
    }

    blocks
}

/// Compile a path pattern string into a `PathMatcher`.
fn compile_path_matcher(pattern: Option<&String>) -> PathMatcher {
    match pattern {
        None => PathMatcher::Any,
        Some(p) if p == "*" => PathMatcher::Any,
        Some(p) if p.ends_with('*') => PathMatcher::Prefix(CompactString::from(&p[..p.len() - 1])),
        Some(p) if p.starts_with('*') => PathMatcher::Suffix(CompactString::from(&p[1..])),
        Some(p) => PathMatcher::Exact(CompactString::from(p.as_str())),
    }
}

/// Compile a single `handle`/`handle_path`/`route` block's inner directives into a `HandlerBlock`.
fn compile_single_block(
    kind: BlockKind,
    matcher: PathMatcher,
    inner_directives: &[Directive],
) -> Option<HandlerBlock> {
    let rate_limit_rps = find_rate_limit(inner_directives);
    let rewrites = collect_rewrites(inner_directives);
    let basic_auth = compile_basic_auth(inner_directives);
    let forward_auth = compile_forward_auth(inner_directives);

    // Find the handler directive inside the block
    let handler = if let Some(rp) = find_reverse_proxy(inner_directives) {
        let addr = resolve_upstream(&rp.upstreams)?;
        Handler::ReverseProxy { upstream: addr }
    } else if let Some(resp) = find_respond(inner_directives) {
        Handler::StaticResponse {
            status: resp.status,
            body: Bytes::from(resp.body.clone()),
        }
    } else if let Some(fs) = find_file_server(inner_directives) {
        let root_path = find_root(inner_directives)
            .map_or_else(|| PathBuf::from("."), |r| PathBuf::from(&r.path));
        Handler::FileServer {
            root: root_path,
            browse: fs.browse,
        }
    } else if let Some(fcgi) = find_php_fastcgi(inner_directives) {
        let addr = resolve_upstream(std::slice::from_ref(&fcgi.upstream))?;
        let root_path = find_root(inner_directives)
            .map_or_else(|| PathBuf::from("."), |r| PathBuf::from(&r.path));
        Handler::FastCgi {
            upstream: addr,
            root: root_path,
        }
    } else {
        warn!("handle block has no handler directive, skipping");
        return None;
    };

    Some(HandlerBlock {
        kind,
        matcher,
        rate_limit_rps,
        under_attack: false,
        rewrites,
        basic_auth,
        forward_auth,
        handler,
    })
}

fn compile_forward_auth(directives: &[Directive]) -> Option<std::sync::Arc<ForwardAuthConfig>> {
    let fa = directives.iter().find_map(|d| match d {
        Directive::ForwardAuth(fa) => Some(fa),
        _ => None,
    })?;

    let upstream = resolve_upstream(std::slice::from_ref(&fa.upstream))?;
    let auth_uri = fa
        .uri
        .as_deref()
        .map_or_else(|| CompactString::from("/"), CompactString::from);
    let copy_headers = fa
        .copy_headers
        .iter()
        .map(|h| CompactString::from(h.as_str()))
        .collect();

    Some(std::sync::Arc::new(ForwardAuthConfig {
        upstream,
        auth_uri,
        copy_headers,
    }))
}

/// Minimum recommended bcrypt cost. Hashes below this get a warning at config load.
const MIN_RECOMMENDED_BCRYPT_COST: u32 = 10;

fn compile_basic_auth(directives: &[Directive]) -> Option<std::sync::Arc<BasicAuthConfig>> {
    let ba = directives.iter().find_map(|d| match d {
        Directive::BasicAuth(ba) => Some(ba),
        _ => None,
    })?;

    // Validate bcrypt cost at compile time — weak hashes get a warning
    for cred in &ba.credentials {
        if let Ok(parts) = cred.password_hash.parse::<bcrypt::HashParts>() {
            if parts.get_cost() < MIN_RECOMMENDED_BCRYPT_COST {
                warn!(
                    username = %cred.username,
                    cost = parts.get_cost(),
                    min_recommended = MIN_RECOMMENDED_BCRYPT_COST,
                    "bcrypt hash cost is below recommended minimum"
                );
            }
        } else {
            warn!(
                username = %cred.username,
                "password hash does not appear to be valid bcrypt"
            );
        }
    }

    let credentials = ba.credentials.iter().map(|c| {
        (
            CompactString::from(c.username.as_str()),
            CompactString::from(c.password_hash.as_str()),
        )
    });
    let realm = ba
        .realm
        .as_deref()
        .map_or_else(CompactString::default, CompactString::from);

    Some(std::sync::Arc::new(BasicAuthConfig::new(
        credentials,
        &realm,
    )))
}

fn collect_rewrites(directives: &[Directive]) -> Vec<RewriteRule> {
    let mut rules = Vec::new();
    for d in directives {
        match d {
            Directive::Rewrite(r) => {
                rules.push(RewriteRule::Replace(CompactString::from(r.to.as_str())));
            }
            Directive::Uri(u) => match &u.operation {
                UriOperation::StripPrefix(p) => {
                    rules.push(RewriteRule::StripPrefix(CompactString::from(p.as_str())));
                }
                UriOperation::StripSuffix(s) => {
                    rules.push(RewriteRule::StripSuffix(CompactString::from(s.as_str())));
                }
                UriOperation::Replace { find, replace } => {
                    rules.push(RewriteRule::SubstringReplace {
                        find: CompactString::from(find.as_str()),
                        replace: CompactString::from(replace.as_str()),
                    });
                }
            },
            _ => {}
        }
    }
    rules
}

fn find_file_server(directives: &[Directive]) -> Option<&FileServerDirective> {
    directives.iter().find_map(|d| match d {
        Directive::FileServer(fs) => Some(fs),
        _ => None,
    })
}

fn find_root(directives: &[Directive]) -> Option<&RootDirective> {
    directives.iter().find_map(|d| match d {
        Directive::Root(r) => Some(r),
        _ => None,
    })
}

fn find_php_fastcgi(directives: &[Directive]) -> Option<&PhpFastcgiDirective> {
    directives.iter().find_map(|d| match d {
        Directive::PhpFastcgi(f) => Some(f),
        _ => None,
    })
}

fn find_respond(directives: &[Directive]) -> Option<&RespondDirective> {
    directives.iter().find_map(|d| match d {
        Directive::Respond(r) => Some(r),
        _ => None,
    })
}

fn find_rate_limit(directives: &[Directive]) -> Option<u32> {
    directives.iter().find_map(|d| match d {
        Directive::RateLimit(rl) => Some(rl.requests_per_second),
        _ => None,
    })
}

/// Resolve the first usable upstream address from the list.
fn resolve_upstream(upstreams: &[UpstreamAddr]) -> Option<SocketAddr> {
    for upstream in upstreams {
        match upstream {
            UpstreamAddr::SocketAddr(addr) => return Some(*addr),
            UpstreamAddr::HostPort(hp) => {
                // DNS resolution — try to resolve host:port to a socket address
                if let Ok(mut addrs) = hp.to_socket_addrs()
                    && let Some(addr) = addrs.next()
                {
                    return Some(addr);
                }
                warn!(upstream = %hp, "DNS resolution failed for upstream");
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;

    fn rp(addr: &str) -> Directive {
        Directive::ReverseProxy(ReverseProxyDirective {
            upstreams: vec![UpstreamAddr::SocketAddr(addr.parse().expect("valid addr"))],
        })
    }

    #[test]
    fn compile_single_site() {
        let config = DwaarConfig {
            sites: vec![SiteBlock {
                address: "example.com".to_string(),
                directives: vec![rp("127.0.0.1:8080")],
            }],
        };

        let table = compile_routes(&config);
        assert_eq!(table.len(), 1);
        let route = table.resolve("example.com").expect("should resolve");
        assert_eq!(
            route.upstream().expect("has upstream"),
            "127.0.0.1:8080".parse::<SocketAddr>().expect("valid")
        );
    }

    #[test]
    fn compile_multiple_sites() {
        let config = DwaarConfig {
            sites: vec![
                SiteBlock {
                    address: "api.example.com".to_string(),
                    directives: vec![rp("127.0.0.1:3000")],
                },
                SiteBlock {
                    address: "web.example.com".to_string(),
                    directives: vec![rp("127.0.0.1:8080")],
                },
                SiteBlock {
                    address: "*.staging.example.com".to_string(),
                    directives: vec![rp("127.0.0.1:9000")],
                },
            ],
        };

        let table = compile_routes(&config);
        assert_eq!(table.len(), 3);
        assert!(table.resolve("api.example.com").is_some());
        assert!(table.resolve("web.example.com").is_some());
        assert!(table.resolve("anything.staging.example.com").is_some());
    }

    #[test]
    fn compile_skips_sites_without_reverse_proxy() {
        let config = DwaarConfig {
            sites: vec![SiteBlock {
                address: "static.example.com".to_string(),
                directives: vec![Directive::Tls(TlsDirective::Auto)],
            }],
        };

        let table = compile_routes(&config);
        assert!(table.is_empty());
    }

    #[test]
    fn compile_resolves_localhost() {
        let config = DwaarConfig {
            sites: vec![SiteBlock {
                address: "example.com".to_string(),
                directives: vec![Directive::ReverseProxy(ReverseProxyDirective {
                    upstreams: vec![UpstreamAddr::HostPort("localhost:8080".to_string())],
                })],
            }],
        };

        let table = compile_routes(&config);
        assert_eq!(table.len(), 1);
        let route = table.resolve("example.com").expect("should resolve");
        // localhost resolves to 127.0.0.1 (or ::1 on some systems)
        assert!(route.upstream().expect("has upstream").port() == 8080);
    }

    #[test]
    fn compile_from_parsed_config() {
        let config = crate::parser::parse(
            r"
            api.example.com {
                reverse_proxy 127.0.0.1:3000
            }
            web.example.com {
                reverse_proxy 127.0.0.1:8080
            }
            ",
        )
        .expect("should parse");

        let table = compile_routes(&config);
        assert_eq!(table.len(), 2);

        let api = table.resolve("api.example.com").expect("api route");
        assert_eq!(api.upstream().expect("has upstream").port(), 3000);

        let web = table.resolve("web.example.com").expect("web route");
        assert_eq!(web.upstream().expect("has upstream").port(), 8080);
    }

    // ── TLS flag propagation (ISSUE-016) ─────────────────────

    #[test]
    fn route_tls_flag_true_for_tls_auto() {
        let config = DwaarConfig {
            sites: vec![SiteBlock {
                address: "secure.example.com".to_string(),
                directives: vec![rp("127.0.0.1:3000"), Directive::Tls(TlsDirective::Auto)],
            }],
        };

        let table = compile_routes(&config);
        let route = table.resolve("secure.example.com").expect("should resolve");
        assert!(route.tls, "tls auto should set route.tls = true");
    }

    #[test]
    fn route_tls_flag_true_for_manual_certs() {
        let config = DwaarConfig {
            sites: vec![SiteBlock {
                address: "manual.example.com".to_string(),
                directives: vec![
                    rp("127.0.0.1:3000"),
                    Directive::Tls(TlsDirective::Manual {
                        cert_path: "/etc/certs/cert.pem".to_string(),
                        key_path: "/etc/certs/key.pem".to_string(),
                    }),
                ],
            }],
        };

        let table = compile_routes(&config);
        let route = table.resolve("manual.example.com").expect("should resolve");
        assert!(route.tls, "manual TLS should set route.tls = true");
    }

    #[test]
    fn route_tls_flag_false_when_tls_off() {
        let config = DwaarConfig {
            sites: vec![SiteBlock {
                address: "plain.example.com".to_string(),
                directives: vec![rp("127.0.0.1:3000"), Directive::Tls(TlsDirective::Off)],
            }],
        };

        let table = compile_routes(&config);
        let route = table.resolve("plain.example.com").expect("should resolve");
        assert!(!route.tls, "tls off should set route.tls = false");
    }

    #[test]
    fn route_tls_flag_false_when_no_tls_directive() {
        let config = DwaarConfig {
            sites: vec![SiteBlock {
                address: "default.example.com".to_string(),
                directives: vec![rp("127.0.0.1:3000")],
            }],
        };

        let table = compile_routes(&config);
        let route = table
            .resolve("default.example.com")
            .expect("should resolve");
        assert!(!route.tls, "no TLS directive should default to tls = false");
    }

    #[test]
    fn mixed_tls_and_non_tls_routes() {
        let config = DwaarConfig {
            sites: vec![
                SiteBlock {
                    address: "secure.example.com".to_string(),
                    directives: vec![rp("127.0.0.1:3000"), Directive::Tls(TlsDirective::Auto)],
                },
                SiteBlock {
                    address: "plain.example.com".to_string(),
                    directives: vec![rp("127.0.0.1:4000")],
                },
            ],
        };

        let table = compile_routes(&config);
        let secure = table.resolve("secure.example.com").expect("secure route");
        let plain = table.resolve("plain.example.com").expect("plain route");

        assert!(secure.tls, "secure route should have tls = true");
        assert!(!plain.tls, "plain route should have tls = false");
    }

    #[test]
    fn compile_acme_domains_extracts_auto_only() {
        let config = DwaarConfig {
            sites: vec![
                SiteBlock {
                    address: "auto.example.com".to_string(),
                    directives: vec![rp("127.0.0.1:3000"), Directive::Tls(TlsDirective::Auto)],
                },
                SiteBlock {
                    address: "manual.example.com".to_string(),
                    directives: vec![
                        rp("127.0.0.1:4000"),
                        Directive::Tls(TlsDirective::Manual {
                            cert_path: "/etc/certs/cert.pem".to_string(),
                            key_path: "/etc/certs/key.pem".to_string(),
                        }),
                    ],
                },
                SiteBlock {
                    address: "plain.example.com".to_string(),
                    directives: vec![rp("127.0.0.1:5000"), Directive::Tls(TlsDirective::Off)],
                },
            ],
        };

        let domains = compile_acme_domains(&config);
        assert_eq!(domains, vec!["auto.example.com"]);
    }

    #[test]
    fn compile_acme_domains_empty_when_no_auto() {
        let config = DwaarConfig {
            sites: vec![SiteBlock {
                address: "manual.example.com".to_string(),
                directives: vec![
                    rp("127.0.0.1:3000"),
                    Directive::Tls(TlsDirective::Manual {
                        cert_path: "/cert.pem".to_string(),
                        key_path: "/key.pem".to_string(),
                    }),
                ],
            }],
        };

        let domains = compile_acme_domains(&config);
        assert!(domains.is_empty());
    }

    // ── Rate limit extraction (ISSUE-031) ───────────────────

    #[test]
    fn compile_route_with_rate_limit() {
        let config = DwaarConfig {
            sites: vec![SiteBlock {
                address: "api.example.com".to_string(),
                directives: vec![
                    rp("127.0.0.1:3000"),
                    Directive::RateLimit(RateLimitDirective {
                        requests_per_second: 100,
                    }),
                ],
            }],
        };
        let table = compile_routes(&config);
        let route = table.resolve("api.example.com").expect("should resolve");
        assert_eq!(route.rate_limit_rps(), Some(100));
    }

    #[test]
    fn compile_route_without_rate_limit() {
        let config = DwaarConfig {
            sites: vec![SiteBlock {
                address: "example.com".to_string(),
                directives: vec![rp("127.0.0.1:8080")],
            }],
        };
        let table = compile_routes(&config);
        let route = table.resolve("example.com").expect("should resolve");
        assert_eq!(route.rate_limit_rps(), None);
    }

    #[test]
    fn compile_from_parsed_rate_limit() {
        let config = crate::parser::parse(
            r"
        api.example.com {
            reverse_proxy 127.0.0.1:3000
            rate_limit 500/s
        }
        ",
        )
        .expect("should parse");
        let table = compile_routes(&config);
        let route = table.resolve("api.example.com").expect("api route");
        assert_eq!(route.rate_limit_rps(), Some(500));
    }

    // ── respond directive (ISSUE-051) ─────────────────────

    #[test]
    fn compile_respond_site() {
        let config = crate::parser::parse(
            r#"
            health.example.com {
                respond "ok" 200
            }
            "#,
        )
        .expect("should parse");
        let table = compile_routes(&config);
        assert_eq!(table.len(), 1);
        let route = table.resolve("health.example.com").expect("should resolve");
        // respond-only site has no upstream
        assert!(route.upstream().is_none());
        // Handler is StaticResponse
        let block = route.handlers.first().expect("has handler");
        assert!(matches!(
            block.handler,
            Handler::StaticResponse { status: 200, .. }
        ));
    }

    #[test]
    fn compile_respond_with_404() {
        let config = crate::parser::parse(
            r#"
            blocked.example.com {
                respond "Forbidden" 403
            }
            "#,
        )
        .expect("should parse");
        let table = compile_routes(&config);
        let route = table
            .resolve("blocked.example.com")
            .expect("should resolve");
        let block = route.handlers.first().expect("has handler");
        if let Handler::StaticResponse { status, ref body } = block.handler {
            assert_eq!(status, 403);
            assert_eq!(body.as_ref(), b"Forbidden");
        } else {
            panic!("expected StaticResponse handler");
        }
    }

    #[test]
    fn compile_site_without_handler_skipped() {
        let config = DwaarConfig {
            sites: vec![SiteBlock {
                address: "no-handler.example.com".to_string(),
                directives: vec![Directive::Tls(TlsDirective::Auto)],
            }],
        };
        let table = compile_routes(&config);
        assert!(table.is_empty());
    }

    // ── rewrite/uri directives (ISSUE-049) ────────────────

    #[test]
    fn compile_rewrite_rule() {
        let config = crate::parser::parse(
            "a.com {\n    reverse_proxy 127.0.0.1:8080\n    rewrite /new\n}\n",
        )
        .expect("should parse");
        let table = compile_routes(&config);
        let route = table.resolve("a.com").expect("should resolve");
        let block = route.handlers.first().expect("has handler");
        assert_eq!(block.rewrites.len(), 1);
        assert!(matches!(&block.rewrites[0], RewriteRule::Replace(p) if p == "/new"));
    }

    #[test]
    fn compile_uri_strip_prefix() {
        let config = crate::parser::parse(
            "a.com {\n    reverse_proxy 127.0.0.1:8080\n    uri strip_prefix /api\n}\n",
        )
        .expect("should parse");
        let table = compile_routes(&config);
        let route = table.resolve("a.com").expect("should resolve");
        let block = route.handlers.first().expect("has handler");
        assert_eq!(block.rewrites.len(), 1);
        assert!(matches!(&block.rewrites[0], RewriteRule::StripPrefix(p) if p == "/api"));
    }

    #[test]
    fn compile_multiple_rewrites() {
        let config = crate::parser::parse(
            "a.com {\n    reverse_proxy 127.0.0.1:8080\n    uri strip_prefix /api\n    uri replace /v1 /v2\n}\n",
        )
        .expect("should parse");
        let table = compile_routes(&config);
        let route = table.resolve("a.com").expect("should resolve");
        let block = route.handlers.first().expect("has handler");
        assert_eq!(block.rewrites.len(), 2);
    }
}
