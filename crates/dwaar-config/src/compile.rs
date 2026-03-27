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

use dwaar_core::route::{Route, RouteTable, is_valid_domain};
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

        if !is_valid_domain(&site.address) {
            warn!(
                address = %site.address,
                "site address is not a valid hostname, skipping"
            );
            continue;
        }

        // Use the first upstream (load balancing comes later)
        let Some(addr) = resolve_upstream(&rp.upstreams) else {
            warn!(
                address = %site.address,
                "could not resolve any upstream address, skipping"
            );
            continue;
        };

        let tls = site_has_tls(&site.directives);
        let rate_limit_rps = find_rate_limit(&site.directives);
        routes.push(Route::new(&site.address, addr, tls, rate_limit_rps));
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
        assert_eq!(route.rate_limit_rps, Some(100));
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
        assert_eq!(route.rate_limit_rps, None);
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
        assert_eq!(route.rate_limit_rps, Some(500));
    }
}
