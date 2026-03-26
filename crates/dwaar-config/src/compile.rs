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

use dwaar_core::route::{Route, RouteTable};
use tracing::warn;

use crate::model::{Directive, DwaarConfig, ReverseProxyDirective, TlsDirective, UpstreamAddr};

/// Compile a parsed config into a route table for the proxy engine.
///
/// Extracts the first `reverse_proxy` upstream from each site block
/// and builds a `RouteTable`. Sites without `reverse_proxy` are
/// skipped with a warning (they might be file_server-only sites later).
///
/// `HostPort` upstreams are resolved via DNS at compile time. If
/// resolution fails, the site is skipped with a warning.
pub fn compile_routes(config: &DwaarConfig) -> RouteTable {
    let mut routes = Vec::with_capacity(config.sites.len());

    for site in &config.sites {
        // Find the first reverse_proxy directive in this site block
        let Some(rp) = find_reverse_proxy(&site.directives) else {
            warn!(
                address = %site.address,
                "site has no reverse_proxy directive, skipping"
            );
            continue;
        };

        // Use the first upstream (load balancing comes later)
        let Some(addr) = resolve_upstream(&rp.upstreams) else {
            warn!(
                address = %site.address,
                "could not resolve any upstream address, skipping"
            );
            continue;
        };

        routes.push(Route::new(&site.address, addr));
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
    config.sites.iter().any(|site| {
        site.directives.iter().any(|d| match d {
            Directive::Tls(TlsDirective::Off) => false,
            Directive::Tls(_) => true,
            _ => false,
        })
    })
}

fn find_reverse_proxy(directives: &[Directive]) -> Option<&ReverseProxyDirective> {
    directives.iter().find_map(|d| match d {
        Directive::ReverseProxy(rp) => Some(rp),
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
            route.upstream,
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
        assert!(route.upstream.port() == 8080);
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
        assert_eq!(api.upstream.port(), 3000);

        let web = table.resolve("web.example.com").expect("web route");
        assert_eq!(web.upstream.port(), 8080);
    }
}
