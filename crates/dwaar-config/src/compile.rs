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
use std::sync::Arc;

use bytes::Bytes;
use compact_str::CompactString;
use dwaar_core::route::{
    BlockKind, CompiledCopyResponseHeaders, CompiledIntercept, CompiledMap, CompiledMapEntry,
    CompiledMapPattern, Handler, HandlerBlock, PathMatcher, RewriteRule, Route, RouteTable,
    is_valid_domain,
};
use dwaar_core::template::{CompiledTemplate, VarRegistry, VarSlots};
use dwaar_core::upstream::{BackendConfig, LbPolicy as CoreLbPolicy, UpstreamPool};
use tracing::warn;

use crate::model::{
    BindDirective, Directive, DwaarConfig, FileServerDirective, HeaderDirective, LbPolicy,
    MapDirective, MapPattern, PhpFastcgiDirective, RespondDirective, ReverseProxyDirective,
    RootDirective, TlsDirective, UpstreamAddr, UriOperation,
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

    warn_pending_global_runtime(config);

    for site in &config.sites {
        if !is_valid_domain(&site.address) {
            warn!(
                address = %site.address,
                "site address is not a valid hostname, skipping"
            );
            continue;
        }

        // Warn about directives that parse but don't have runtime support yet
        warn_pending_runtime(&site.address, &site.directives);
        for d in &site.directives {
            if let Directive::Handle(h) = d {
                warn_pending_runtime(&site.address, &h.directives);
            }
        }

        let tls = site_has_tls(&site.directives);

        // Build variable registry from vars/map directives (ISSUE-055)
        let (var_registry, var_defaults) = compile_vars(&site.directives);

        // Check for handle/handle_path/route blocks first — these create multi-handler routes
        let handle_blocks = compile_handle_blocks(&site.directives, &var_registry);
        if !handle_blocks.is_empty() {
            routes.push(Route::with_handlers(
                &site.address,
                tls,
                handle_blocks,
                var_defaults,
            ));
            continue;
        }

        // Flat site (no handle blocks) — extract single handler + site-level middleware
        let rate_limit_rps = find_rate_limit(&site.directives);
        let ip_filter = compile_ip_filter(&site.directives);
        let request_body_max_size = find_request_body_max_size(&site.directives);
        let response_body_max_size = find_response_body_limit(&site.directives);
        let cache = compile_cache(&site.directives);
        let rewrites = collect_rewrites(&site.directives, &var_registry);
        let basic_auth = compile_basic_auth(&site.directives);
        let forward_auth = compile_forward_auth(&site.directives);
        let is_grpc_route = site.directives.iter().any(|d| matches!(d, Directive::Grpc));

        // Compile response-phase directives shared across all flat-site handler types.
        let intercepts = compile_intercepts(&site.directives);
        let copy_response_headers = compile_copy_response_headers(&site.directives);

        // Try reverse_proxy first (most common)
        if let Some(rp) = find_reverse_proxy(&site.directives) {
            let handler_result = compile_reverse_proxy_handler(rp, &site.address);
            let Some(proxy_handler) = handler_result else {
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
                maps: compile_maps(&site.directives, &var_registry),
                log_append_fields: compile_log_append(&site.directives, &var_registry),
                log_name: find_log_name(&site.directives),
                handler: proxy_handler,
                intercepts: intercepts.clone(),
                copy_response_headers: copy_response_headers.clone(),
                ip_filter: ip_filter.clone(),
                request_body_max_size,
                response_body_max_size,
                cache: cache.clone(),
                is_grpc_route,
            };
            routes.push(Route::with_handlers(
                &site.address,
                tls,
                vec![handler],
                var_defaults,
            ));
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
                maps: compile_maps(&site.directives, &var_registry),
                log_append_fields: compile_log_append(&site.directives, &var_registry),
                log_name: find_log_name(&site.directives),
                handler: Handler::StaticResponse {
                    status: resp.status,
                    body: Bytes::from(resp.body.clone()),
                },
                intercepts: intercepts.clone(),
                copy_response_headers: copy_response_headers.clone(),
                ip_filter: ip_filter.clone(),
                request_body_max_size,
                response_body_max_size,
                cache: cache.clone(),
                is_grpc_route,
            };
            routes.push(Route::with_handlers(
                &site.address,
                tls,
                vec![handler],
                var_defaults,
            ));
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
                maps: compile_maps(&site.directives, &var_registry),
                log_append_fields: compile_log_append(&site.directives, &var_registry),
                log_name: find_log_name(&site.directives),
                handler: Handler::FileServer {
                    root: root_path.canonicalize().unwrap_or(root_path),
                    browse: fs_directive.browse,
                },
                intercepts: intercepts.clone(),
                copy_response_headers: copy_response_headers.clone(),
                ip_filter: ip_filter.clone(),
                request_body_max_size,
                response_body_max_size,
                cache: cache.clone(),
                is_grpc_route,
            };
            routes.push(Route::with_handlers(
                &site.address,
                tls,
                vec![handler],
                var_defaults,
            ));
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
                maps: compile_maps(&site.directives, &var_registry),
                log_append_fields: compile_log_append(&site.directives, &var_registry),
                log_name: find_log_name(&site.directives),
                handler: Handler::FastCgi {
                    upstream: addr,
                    root: root_path,
                },
                intercepts,
                copy_response_headers,
                ip_filter,
                request_body_max_size,
                response_body_max_size,
                cache,
                is_grpc_route,
            };
            routes.push(Route::with_handlers(
                &site.address,
                tls,
                vec![handler],
                var_defaults,
            ));
            continue;
        }

        warn!(
            address = %site.address,
            "site has no handler directive (reverse_proxy, respond, file_server, php_fastcgi), skipping"
        );
    }

    RouteTable::new(routes)
}

fn warn_pending_global_runtime(_config: &DwaarConfig) {
    // Layer 4 runtime is now implemented — no more warnings needed.
    // This function remains as a hook point for future global-level
    // features that are parse-only before their runtime ships.
}

// ── Layer 4 compilation ─────────────────────────────────────────────────

use dwaar_core::l4::{
    CompiledL4Handler, CompiledL4Matcher, CompiledL4Route, CompiledL4Server, L4LoadBalancePolicy,
};

use crate::model::{
    Layer4Config, Layer4Handler, Layer4ListenerWrapper, Layer4Matcher, Layer4MatcherDef,
    Layer4Route,
};

/// Default matching timeout for L4 protocol detection.
const L4_DEFAULT_MATCHING_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Compile parsed L4 config into runtime-ready servers.
pub fn compile_l4_servers(config: &Layer4Config) -> Vec<CompiledL4Server> {
    config
        .servers
        .iter()
        .flat_map(|server| {
            let routes = compile_l4_routes(&server.matchers, &server.routes);
            server.listen.iter().filter_map(move |addr_str| {
                let listen = parse_l4_listen_addr(addr_str)?;
                Some(CompiledL4Server {
                    listen,
                    routes: routes.clone(),
                    matching_timeout: L4_DEFAULT_MATCHING_TIMEOUT,
                })
            })
        })
        .collect()
}

/// Compile listener-wrapper L4 configs into runtime servers.
pub fn compile_l4_wrappers(wrappers: &[Layer4ListenerWrapper]) -> Vec<CompiledL4Server> {
    wrappers
        .iter()
        .filter_map(|wrapper| {
            let listen = parse_l4_listen_addr(&wrapper.listen)?;
            let routes = compile_l4_routes(&wrapper.layer4.matchers, &wrapper.layer4.routes);
            Some(CompiledL4Server {
                listen,
                routes,
                matching_timeout: L4_DEFAULT_MATCHING_TIMEOUT,
            })
        })
        .collect()
}

fn compile_l4_routes(
    matcher_defs: &[Layer4MatcherDef],
    routes: &[Layer4Route],
) -> Vec<CompiledL4Route> {
    routes
        .iter()
        .map(|route| {
            let matchers = route
                .matcher_names
                .iter()
                .filter_map(|name| {
                    matcher_defs
                        .iter()
                        .find(|def| def.name == *name)
                        .map(compile_l4_matcher_def)
                })
                .flatten()
                .collect();
            let handlers = route
                .handlers
                .iter()
                .filter_map(compile_l4_handler)
                .collect();
            CompiledL4Route { matchers, handlers }
        })
        .collect()
}

fn compile_l4_matcher_def(def: &Layer4MatcherDef) -> Vec<CompiledL4Matcher> {
    def.matchers.iter().filter_map(compile_l4_matcher).collect()
}

fn compile_l4_matcher(matcher: &Layer4Matcher) -> Option<CompiledL4Matcher> {
    match matcher {
        Layer4Matcher::Tls { sni, alpn, .. } => Some(CompiledL4Matcher::Tls {
            sni: sni.clone(),
            alpn: alpn.clone(),
        }),
        Layer4Matcher::Http { host, .. } => Some(CompiledL4Matcher::Http { host: host.clone() }),
        Layer4Matcher::Ssh => Some(CompiledL4Matcher::Ssh),
        Layer4Matcher::Postgres => Some(CompiledL4Matcher::Postgres),
        Layer4Matcher::RemoteIp(ranges) => {
            let nets: Vec<ipnet::IpNet> = ranges
                .iter()
                .filter_map(|r| r.parse::<ipnet::IpNet>().ok())
                .collect();
            if nets.is_empty() && !ranges.is_empty() {
                warn!(ranges = ?ranges, "L4 remote_ip: failed to parse some CIDR ranges");
            }
            Some(CompiledL4Matcher::RemoteIp(nets))
        }
        Layer4Matcher::Not(inner) => {
            compile_l4_matcher(inner).map(|m| CompiledL4Matcher::Not(Box::new(m)))
        }
        Layer4Matcher::Unknown { name, .. } => {
            warn!(matcher = %name, "unknown L4 matcher — skipping");
            None
        }
    }
}

/// Default: quarantine after 3 consecutive connect failures.
const L4_DEFAULT_MAX_FAILS: u32 = 3;
/// Default: keep a failing upstream out of rotation for 10 seconds.
const L4_DEFAULT_FAIL_DURATION: std::time::Duration = std::time::Duration::from_secs(10);
/// Default: give up on a connect attempt after 10 seconds.
const L4_DEFAULT_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

fn compile_l4_handler(handler: &Layer4Handler) -> Option<CompiledL4Handler> {
    match handler {
        Layer4Handler::Proxy(p) => {
            let upstreams: Vec<std::net::SocketAddr> = p
                .upstreams
                .iter()
                .filter_map(|u| parse_l4_listen_addr(u))
                .collect();
            if upstreams.is_empty() {
                warn!(raw = ?p.upstreams, "L4 proxy: no valid upstream addresses");
                return None;
            }

            // Extract LB and health options from the generic options list.
            // Options follow caddy-l4 naming conventions:
            //   lb_policy round_robin|least_conn|random|ip_hash
            //   health_interval 10s
            //   health_timeout  5s   (used as connect_timeout)
            //   max_fails       3
            //   fail_duration   10s
            let mut lb_policy = L4LoadBalancePolicy::RoundRobin;
            let mut max_fails = L4_DEFAULT_MAX_FAILS;
            let mut fail_duration = L4_DEFAULT_FAIL_DURATION;
            let mut connect_timeout = L4_DEFAULT_CONNECT_TIMEOUT;

            for opt in &p.options {
                match opt.name.as_str() {
                    "lb_policy" => {
                        lb_policy = match opt.args.first().map(String::as_str) {
                            Some("round_robin" | "roundrobin") => L4LoadBalancePolicy::RoundRobin,
                            Some("least_conn" | "leastconn") => L4LoadBalancePolicy::LeastConn,
                            Some("random") => L4LoadBalancePolicy::Random,
                            Some("ip_hash" | "iphash") => L4LoadBalancePolicy::IpHash,
                            other => {
                                warn!(
                                    value = ?other,
                                    "L4 proxy: unknown lb_policy — defaulting to round_robin"
                                );
                                L4LoadBalancePolicy::RoundRobin
                            }
                        };
                    }
                    "max_fails" => {
                        if let Some(v) = opt
                            .args
                            .first()
                            .and_then(|s: &String| s.parse::<u32>().ok())
                        {
                            max_fails = v;
                        }
                    }
                    "fail_duration" => {
                        if let Some(d) = opt.args.first().and_then(|s| parse_l4_duration(s)) {
                            fail_duration = d;
                        }
                    }
                    // health_timeout is the per-connect deadline for upstream attempts.
                    "health_timeout" | "connect_timeout" => {
                        if let Some(d) = opt.args.first().and_then(|s| parse_l4_duration(s)) {
                            connect_timeout = d;
                        }
                    }
                    // health_interval is only relevant to active health checkers,
                    // which the L4 proxy does not yet support. Recognised but ignored.
                    "health_interval" | "health_uri" => {}
                    other => {
                        warn!(option = %other, "L4 proxy: unrecognised option — ignoring");
                    }
                }
            }

            Some(CompiledL4Handler::new_proxy(
                upstreams,
                lb_policy,
                max_fails,
                fail_duration,
                connect_timeout,
            ))
        }
        Layer4Handler::Tls(tls) => {
            let cert_path = tls
                .options
                .iter()
                .find(|o| o.name == "cert")
                .and_then(|o| o.args.first().cloned());
            let key_path = tls
                .options
                .iter()
                .find(|o| o.name == "key")
                .and_then(|o| o.args.first().cloned());
            Some(CompiledL4Handler::Tls {
                cert_path,
                key_path,
                cert_store: None,
            })
        }
        Layer4Handler::Subroute(sub) => {
            let routes = compile_l4_routes(&sub.matchers, &sub.routes);
            let timeout = sub
                .matching_timeout
                .as_deref()
                .and_then(parse_l4_duration)
                .unwrap_or(L4_DEFAULT_MATCHING_TIMEOUT);
            Some(CompiledL4Handler::Subroute {
                routes,
                matching_timeout: timeout,
            })
        }
        Layer4Handler::Unknown { name, .. } => {
            warn!(handler = %name, "unknown L4 handler — skipping");
            None
        }
    }
}

fn parse_l4_listen_addr(s: &str) -> Option<std::net::SocketAddr> {
    // Bare `:port` binds to [::] (IPv6 any) which is dual-stack on Linux —
    // accepts both IPv4 and IPv6 connections on the same listener.
    let normalized = if s.starts_with(':') {
        format!("[::]{s}")
    } else {
        s.to_string()
    };
    match normalized.parse() {
        Ok(addr) => Some(addr),
        Err(e) => {
            warn!(addr = %s, error = %e, "L4: invalid listen address");
            None
        }
    }
}

fn parse_l4_duration(s: &str) -> Option<std::time::Duration> {
    if let Some(rest) = s.strip_suffix("ms") {
        rest.parse().ok().map(std::time::Duration::from_millis)
    } else if let Some(rest) = s.strip_suffix('s') {
        rest.parse().ok().map(std::time::Duration::from_secs)
    } else if let Some(rest) = s.strip_suffix('m') {
        rest.parse::<u64>()
            .ok()
            .map(|m| std::time::Duration::from_secs(m * 60))
    } else {
        s.parse().ok().map(std::time::Duration::from_secs)
    }
}

// ── HTTP route compilation (continued) ──────────────────────────────────

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

/// The fallback HTTP listen address when no `bind` directive is present.
const DEFAULT_HTTP_BIND: &str = "0.0.0.0:6188";

/// The fallback port appended when a `bind` address has no port.
const DEFAULT_BIND_PORT: u16 = 6188;

/// A compiled listener address extracted from a `bind` directive.
///
/// Distinguishes between TCP sockets (most common) and Unix domain sockets
/// (`unix//tmp/dwaar.sock`). UDS is useful for same-host reverse proxy
/// chaining without the TCP stack overhead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindAddress {
    /// A TCP `ip:port` address (e.g. `"0.0.0.0:8443"`, `"127.0.0.1:80"`).
    Tcp(String),
    /// A Unix domain socket path (e.g. `/tmp/dwaar.sock`).
    Unix(std::path::PathBuf),
}

/// Extract listener addresses from a parsed config.
///
/// Gathers `bind` directives across all site blocks. Multiple sites with `bind`
/// produce a union of all their addresses (deduplication preserves insertion
/// order). The function always returns at least the default TCP address so the
/// caller never has to special-case an empty result.
///
/// Parsing rules for address strings:
/// - `unix/path` or `unix//path` → [`BindAddress::Unix`]
/// - `:port`                     → `BindAddress::Tcp("0.0.0.0:port")`
/// - `ip` (bare IP, no port)     → `BindAddress::Tcp("ip:6188")`
/// - `ip:port`                   → `BindAddress::Tcp("ip:port")`
pub fn extract_bind_addresses(config: &DwaarConfig) -> Vec<BindAddress> {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut addrs: Vec<BindAddress> = Vec::new();

    for site in &config.sites {
        if let Some(bind) = find_bind(&site.directives) {
            for raw in &bind.addresses {
                let addr = parse_bind_address(raw);
                // Deduplicate by canonical string key so that two sites with
                // the same bind don't register the same port twice.
                let key = match &addr {
                    BindAddress::Tcp(s) => s.clone(),
                    BindAddress::Unix(p) => p.to_string_lossy().into_owned(),
                };
                if seen.insert(key) {
                    addrs.push(addr);
                }
            }
        }
    }

    // Fall back to the built-in default when no site specifies bind.
    if addrs.is_empty() {
        addrs.push(BindAddress::Tcp(DEFAULT_HTTP_BIND.to_owned()));
    }

    addrs
}

/// Parse a single bind address token into a [`BindAddress`].
fn parse_bind_address(raw: &str) -> BindAddress {
    // Unix domain socket — Caddy supports both `unix/path` and `unix//abs/path`.
    // Stripping `unix/` gives either `path` (relative) or `/abs/path` (absolute
    // when the original had a double-slash like `unix//tmp/sock`).
    if let Some(after_unix) = raw.strip_prefix("unix/") {
        return BindAddress::Unix(std::path::PathBuf::from(after_unix));
    }

    // `:port` shorthand — listen on all interfaces on the given port.
    if let Some(port_str) = raw.strip_prefix(':') {
        return BindAddress::Tcp(format!("0.0.0.0:{port_str}"));
    }

    // Bracketed IPv6 (with or without port) passes through unchanged:
    // `[::1]:8080` or `[::1]` (port-less bracketed form is unusual but valid).
    if raw.starts_with('[') {
        // If no port bracket present, append the default port.
        if raw.ends_with(']') {
            return BindAddress::Tcp(format!("{raw}:{DEFAULT_BIND_PORT}"));
        }
        return BindAddress::Tcp(raw.to_owned());
    }

    // If there is exactly one colon it is a plain `ip:port` — pass through.
    // More than one colon without brackets is a bare IPv6 address; append port.
    let colon_count = raw.chars().filter(|&c| c == ':').count();
    match colon_count.cmp(&1) {
        std::cmp::Ordering::Equal => BindAddress::Tcp(raw.to_owned()),
        std::cmp::Ordering::Greater => {
            // Bare IPv6 like `::1` or `fe80::1` — wrap and append default port.
            BindAddress::Tcp(format!("[{raw}]:{DEFAULT_BIND_PORT}"))
        }
        std::cmp::Ordering::Less => {
            // Bare IPv4 address or hostname — append default port.
            BindAddress::Tcp(format!("{raw}:{DEFAULT_BIND_PORT}"))
        }
    }
}

/// Find the first `bind` directive in a site's directive list.
fn find_bind(directives: &[Directive]) -> Option<&BindDirective> {
    directives.iter().find_map(|d| match d {
        Directive::Bind(b) => Some(b),
        _ => None,
    })
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
fn compile_handle_blocks(directives: &[Directive], registry: &VarRegistry) -> Vec<HandlerBlock> {
    let mut blocks = Vec::new();

    for d in directives {
        match d {
            Directive::Handle(h) => {
                let matcher = compile_path_matcher(h.matcher.as_ref());
                if let Some(block) =
                    compile_single_block(BlockKind::Handle, matcher, &h.directives, registry)
                {
                    blocks.push(block);
                }
            }
            Directive::HandlePath(hp) => {
                let matcher = compile_path_matcher(Some(&hp.path_prefix));
                if let Some(block) =
                    compile_single_block(BlockKind::HandlePath, matcher, &hp.directives, registry)
                {
                    blocks.push(block);
                }
            }
            Directive::Route(r) => {
                let matcher = compile_path_matcher(r.matcher.as_ref());
                if let Some(block) =
                    compile_single_block(BlockKind::Route, matcher, &r.directives, registry)
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
    registry: &VarRegistry,
) -> Option<HandlerBlock> {
    let rate_limit_rps = find_rate_limit(inner_directives);
    let ip_filter = compile_ip_filter(inner_directives);
    let cache = compile_cache(inner_directives);
    let request_body_max_size = find_request_body_max_size(inner_directives);
    let response_body_max_size = find_response_body_limit(inner_directives);
    let rewrites = collect_rewrites(inner_directives, registry);
    let basic_auth = compile_basic_auth(inner_directives);
    let forward_auth = compile_forward_auth(inner_directives);
    let mut is_grpc_route = false;
    for d in inner_directives {
        if matches!(d, Directive::Grpc) {
            is_grpc_route = true;
            break;
        }
    }

    // Find the handler directive inside the block
    let handler = if let Some(rp) = find_reverse_proxy(inner_directives) {
        compile_reverse_proxy_handler(rp, "handle block")?
    } else if let Some(resp) = find_respond(inner_directives) {
        Handler::StaticResponse {
            status: resp.status,
            body: Bytes::from(resp.body.clone()),
        }
    } else if let Some(fs) = find_file_server(inner_directives) {
        let root_path = find_root(inner_directives)
            .map_or_else(|| PathBuf::from("."), |r| PathBuf::from(&r.path));
        Handler::FileServer {
            root: root_path.canonicalize().unwrap_or(root_path),
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
        maps: compile_maps(inner_directives, registry),
        log_append_fields: compile_log_append(inner_directives, registry),
        log_name: find_log_name(inner_directives),
        handler,
        intercepts: compile_intercepts(inner_directives),
        copy_response_headers: compile_copy_response_headers(inner_directives),
        ip_filter,
        request_body_max_size,
        response_body_max_size,
        cache,
        is_grpc_route,
    })
}

fn compile_forward_auth(directives: &[Directive]) -> Option<std::sync::Arc<ForwardAuthConfig>> {
    let fa = directives.iter().find_map(|d| match d {
        Directive::ForwardAuth(fa) => Some(fa),
        _ => None,
    })?;

    let upstream = resolve_upstream(std::slice::from_ref(&fa.upstream))?;

    // Preserve the original hostname for TLS SNI when the upstream was
    // specified as a DNS name (e.g. `authelia:9091`). Without this, the
    // TLS client would use the resolved IP as SNI, and hostname-based
    // certificates would fail verification.
    let sni_hostname = match &fa.upstream {
        UpstreamAddr::HostPort(hp) => {
            let host = hp.split(':').next().unwrap_or(hp);
            Some(CompactString::from(host))
        }
        UpstreamAddr::SocketAddr(_) => None,
    };

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
        tls: fa.tls,
        sni_hostname,
        allow_plaintext: fa.insecure_plaintext,
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

fn collect_rewrites(directives: &[Directive], registry: &VarRegistry) -> Vec<RewriteRule> {
    let mut rules = Vec::new();
    for d in directives {
        match d {
            Directive::Rewrite(r) => {
                let tmpl = compile_template(&r.to, registry);
                rules.push(RewriteRule::Replace(tmpl));
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

fn compile_ip_filter(
    directives: &[Directive],
) -> Option<std::sync::Arc<dwaar_plugins::ip_filter::IpFilterConfig>> {
    use dwaar_plugins::ip_filter::{CidrTrie, DefaultPolicy, IpAction, IpFilterConfig, parse_cidr};
    let ipf = directives.iter().find_map(|d| match d {
        Directive::IpFilter(f) => Some(f),
        _ => None,
    })?;

    let mut trie = CidrTrie::new();
    for cidr_str in &ipf.allow {
        if let Some((addr, prefix_len)) = parse_cidr(cidr_str) {
            trie.insert(addr, prefix_len, IpAction::Allow);
        } else {
            warn!(cidr = %cidr_str, "invalid CIDR in ip_filter allow, skipping");
        }
    }
    for cidr_str in &ipf.deny {
        if let Some((addr, prefix_len)) = parse_cidr(cidr_str) {
            trie.insert(addr, prefix_len, IpAction::Deny);
        } else {
            warn!(cidr = %cidr_str, "invalid CIDR in ip_filter deny, skipping");
        }
    }

    let default_policy = if ipf.default_allow {
        DefaultPolicy::Allow
    } else {
        DefaultPolicy::Deny
    };

    Some(std::sync::Arc::new(IpFilterConfig {
        trie,
        default_policy,
    }))
}

fn compile_cache(
    directives: &[Directive],
) -> Option<std::sync::Arc<dwaar_core::cache::CacheConfig>> {
    let cache_dir = directives.iter().find_map(|d| match d {
        Directive::Cache(c) => Some(c),
        _ => None,
    })?;

    Some(std::sync::Arc::new(dwaar_core::cache::CacheConfig {
        max_size: cache_dir.max_size.unwrap_or(1_073_741_824) as usize,
        match_paths: cache_dir.match_paths.clone(),
        default_ttl: cache_dir.default_ttl.unwrap_or(3600),
        stale_while_revalidate: cache_dir.stale_while_revalidate.unwrap_or(60),
    }))
}

fn find_request_body_max_size(directives: &[Directive]) -> Option<u64> {
    directives.iter().find_map(|d| match d {
        Directive::RequestBody(rb) => rb.max_size,
        _ => None,
    })
}

fn find_response_body_limit(directives: &[Directive]) -> Option<u64> {
    directives.iter().find_map(|d| match d {
        Directive::ResponseBodyLimit(rbl) => Some(rbl.max_size),
        _ => None,
    })
}

/// Resolve the first usable upstream address from the list.
///
/// `to_socket_addrs` is a blocking syscall (getaddrinfo). We call this from
/// the hot-reload path which runs on the tokio runtime, so we use
/// `block_in_place` to avoid starving other async tasks during DNS lookups.
fn resolve_upstream(upstreams: &[UpstreamAddr]) -> Option<SocketAddr> {
    for upstream in upstreams {
        match upstream {
            UpstreamAddr::SocketAddr(addr) => return Some(*addr),
            UpstreamAddr::HostPort(hp) => {
                let hp_clone = hp.clone();
                let result =
                    tokio::task::block_in_place(|| hp_clone.to_socket_addrs().ok()?.next());
                if let Some(addr) = result {
                    return Some(addr);
                }
                warn!(upstream = %hp, "DNS resolution failed for upstream");
            }
        }
    }
    None
}

/// Resolve all upstreams in the list, logging and skipping unresolvable entries.
///
/// Each `to_socket_addrs` call is a blocking syscall wrapped in `block_in_place`
/// so the tokio executor stays responsive during config compilation.
fn resolve_all_upstreams(upstreams: &[UpstreamAddr]) -> Vec<SocketAddr> {
    upstreams
        .iter()
        .filter_map(|u| match u {
            UpstreamAddr::SocketAddr(addr) => Some(*addr),
            UpstreamAddr::HostPort(hp) => {
                let hp_clone = hp.clone();
                let addr = tokio::task::block_in_place(|| hp_clone.to_socket_addrs().ok()?.next());
                if addr.is_none() {
                    warn!(upstream = %hp, "DNS resolution failed for upstream, skipping");
                }
                addr
            }
        })
        .collect()
}

/// Map a config `LbPolicy` to the runtime `CoreLbPolicy`.
fn map_lb_policy(policy: Option<LbPolicy>) -> CoreLbPolicy {
    match policy {
        None | Some(LbPolicy::RoundRobin) => CoreLbPolicy::RoundRobin,
        Some(LbPolicy::LeastConn) => CoreLbPolicy::LeastConn,
        Some(LbPolicy::Random) => CoreLbPolicy::Random,
        Some(LbPolicy::IpHash) => CoreLbPolicy::IpHash,
    }
}

/// Decide whether `rp` needs a pool (multi-upstream or has block-form options).
///
/// Single upstream + no block-form fields → `Handler::ReverseProxy` (zero overhead).
/// Anything else → `Handler::ReverseProxyPool`.
fn compile_reverse_proxy_handler(rp: &ReverseProxyDirective, location: &str) -> Option<Handler> {
    let is_block_form = rp.lb_policy.is_some()
        || rp.health_uri.is_some()
        || rp.health_interval.is_some()
        || rp.fail_duration.is_some()
        || rp.max_conns.is_some()
        || rp.transport_tls
        || rp.transport_h2
        || rp.tls_server_name.is_some()
        || rp.tls_client_auth.is_some()
        || rp.tls_trusted_ca_certs.is_some()
        || rp.scale_to_zero.is_some();

    if rp.upstreams.len() <= 1 && !is_block_form {
        // Common single-upstream case — zero overhead path.
        let addr = resolve_upstream(&rp.upstreams)?;
        return Some(Handler::ReverseProxy {
            upstream: addr,
            upstream_h2: rp.transport_h2,
        });
    }

    // Multi-upstream or block-form options — build a pool.
    let addrs = resolve_all_upstreams(&rp.upstreams);
    if addrs.is_empty() {
        warn!(location, "reverse_proxy: no resolvable upstreams, skipping");
        return None;
    }

    let policy = map_lb_policy(rp.lb_policy);
    let tls = rp.transport_tls;
    let sni = rp.tls_server_name.clone().unwrap_or_default();

    // Load and validate mTLS client cert+key at config time (Guardrail #18).
    let client_cert_key = if let Some((ref cert_path, ref key_path)) = rp.tls_client_auth {
        match dwaar_tls::mtls::load_client_cert_key(cert_path.as_ref(), key_path.as_ref()) {
            Ok(ck) => Some(Arc::new(ck)),
            Err(e) => {
                warn!(
                    location,
                    cert = %cert_path,
                    error = %e,
                    "failed to load mTLS client cert, skipping site"
                );
                return None;
            }
        }
    } else {
        None
    };

    // Load custom CA bundle for upstream cert verification.
    let trusted_ca = if let Some(ref ca_path) = rp.tls_trusted_ca_certs {
        match dwaar_tls::mtls::load_ca_certs(ca_path.as_ref()) {
            Ok(cas) => Some(cas),
            Err(e) => {
                warn!(
                    location,
                    ca_path = %ca_path,
                    error = %e,
                    "failed to load trusted CA certs, skipping site"
                );
                return None;
            }
        }
    } else {
        None
    };

    let backends = addrs
        .into_iter()
        .map(|addr| BackendConfig {
            addr,
            max_conns: rp.max_conns,
            tls,
            tls_server_name: sni.clone(),
            client_cert_key: client_cert_key.clone(),
            trusted_ca: trusted_ca.clone(),
        })
        .collect();

    let pool = if let Some(ref s2z) = rp.scale_to_zero {
        let s2z_config = dwaar_core::wake::ScaleToZeroConfig::new(
            std::time::Duration::from_secs(s2z.wake_timeout_secs),
            s2z.wake_command.clone(),
        );
        UpstreamPool::new_with_scale_to_zero(
            backends,
            policy,
            rp.health_uri.clone(),
            rp.health_interval,
            s2z_config,
        )
    } else {
        UpstreamPool::new(backends, policy, rp.health_uri.clone(), rp.health_interval)
    };

    Some(Handler::ReverseProxyPool {
        pool: Arc::new(pool),
        upstream_h2: rp.transport_h2,
    })
}

/// Collect all `UpstreamPool`s from a compiled route table for health checking.
///
/// Called once at startup to gather pools that need background health probes.
pub fn collect_pools(table: &dwaar_core::route::RouteTable) -> Vec<Arc<UpstreamPool>> {
    let mut pools = Vec::new();
    for route in table.all_routes() {
        for block in &route.handlers {
            if let Handler::ReverseProxyPool { pool, .. } = &block.handler {
                // Only pools with a health URI need the background checker.
                if pool.has_health_check() {
                    pools.push(pool.clone());
                }
            }
        }
    }
    pools
}

// ── Variable compilation (ISSUE-055) ─────────────────────────

/// Collect `vars` and `map` directives from a site and build a `VarRegistry` + default `VarSlots`.
///
/// Returns `(registry, slots)` where:
/// - `registry` maps variable names → slot indices (used during template compilation)
/// - `slots` holds the static default values (stored on the `Route` for per-request cloning)
///
/// `vars` directives register their key and populate a default value.
/// `map` directives register their `dest_var` but leave the slot empty (filled per-request).
fn compile_vars(directives: &[Directive]) -> (VarRegistry, VarSlots) {
    let mut registry = VarRegistry::new();

    // First pass: register all variable names to assign slots
    for d in directives {
        match d {
            Directive::Vars(v) => {
                registry.register(&v.key);
            }
            Directive::Map(m) => {
                registry.register(&m.dest_var);
            }
            _ => {}
        }
    }

    // Also check inside handle/handle_path/route blocks for nested vars/map
    for d in directives {
        match d {
            Directive::Handle(h) => {
                for inner in &h.directives {
                    match inner {
                        Directive::Vars(v) => {
                            registry.register(&v.key);
                        }
                        Directive::Map(m) => {
                            registry.register(&m.dest_var);
                        }
                        _ => {}
                    }
                }
            }
            Directive::HandlePath(hp) => {
                for inner in &hp.directives {
                    match inner {
                        Directive::Vars(v) => {
                            registry.register(&v.key);
                        }
                        Directive::Map(m) => {
                            registry.register(&m.dest_var);
                        }
                        _ => {}
                    }
                }
            }
            Directive::Route(r) => {
                for inner in &r.directives {
                    match inner {
                        Directive::Vars(v) => {
                            registry.register(&v.key);
                        }
                        Directive::Map(m) => {
                            registry.register(&m.dest_var);
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    // Second pass: populate default values (both top-level and nested in handle blocks)
    let mut slots = VarSlots::with_capacity(registry.len());
    let mut populate_from = |ds: &[Directive]| {
        for d in ds {
            if let Directive::Vars(v) = d
                && let Some(slot) = registry.get(&v.key)
            {
                slots.set(slot, CompactString::from(v.value.as_str()));
            }
        }
    };
    populate_from(directives);
    for d in directives {
        match d {
            Directive::Handle(h) => populate_from(&h.directives),
            Directive::HandlePath(hp) => populate_from(&hp.directives),
            Directive::Route(r) => populate_from(&r.directives),
            _ => {}
        }
    }

    (registry, slots)
}

/// Compile `map` directives into runtime `CompiledMap` structures.
///
/// Each map evaluates a source template per-request, matches against pattern
/// entries (first match wins), and writes the result to a `VarSlot`.
fn compile_maps(directives: &[Directive], registry: &VarRegistry) -> Vec<CompiledMap> {
    let mut maps = Vec::new();
    for d in directives {
        if let Directive::Map(m) = d {
            match compile_one_map(m, registry) {
                Ok(compiled) => maps.push(compiled),
                Err(e) => warn!("map compilation failed: {e}"),
            }
        }
    }
    maps
}

fn compile_one_map(m: &MapDirective, registry: &VarRegistry) -> Result<CompiledMap, String> {
    let source = CompiledTemplate::compile_with_registry(&m.source, registry)
        .map_err(|e| format!("map source template: {e}"))?;

    let dest_slot = registry
        .get(&m.dest_var)
        .ok_or_else(|| format!("map dest_var '{}' not registered", m.dest_var))?;

    let mut entries = Vec::with_capacity(m.entries.len());
    for entry in &m.entries {
        let pattern = match &entry.pattern {
            MapPattern::Exact(e) => CompiledMapPattern::Exact(e.clone()),
            MapPattern::Regex(re) => {
                let compiled = regex::RegexBuilder::new(&format!("(?i)^{re}$"))
                    .size_limit(1 << 20) // 1 MiB NFA budget — blocks pathological patterns like (a+)+$
                    .build()
                    .map_err(|e| format!("map regex '{re}': {e}"))?;
                CompiledMapPattern::Regex(compiled)
            }
            MapPattern::Default => CompiledMapPattern::Default,
        };
        let value = CompiledTemplate::compile_with_registry(&entry.value, registry)
            .map_err(|e| format!("map entry value template: {e}"))?;
        let is_default = matches!(&entry.pattern, MapPattern::Default);
        entries.push(CompiledMapEntry {
            pattern,
            value,
            is_default,
        });
    }

    Ok(CompiledMap {
        source,
        dest_slot,
        entries,
    })
}

/// Compile `log_append` directives into runtime `(field_name, CompiledTemplate)` pairs.
fn compile_log_append(
    directives: &[Directive],
    registry: &VarRegistry,
) -> Vec<(String, CompiledTemplate)> {
    let mut fields = Vec::new();
    for d in directives {
        if let Directive::LogAppend(la) = d {
            for (name, raw_value) in &la.fields {
                match CompiledTemplate::compile_with_registry(raw_value, registry) {
                    Ok(tmpl) => fields.push((name.clone(), tmpl)),
                    Err(e) => warn!("log_append field '{}' template error: {e}", name),
                }
            }
        }
    }
    fields
}

/// Extract the `log_name` from directives, if present.
fn find_log_name(directives: &[Directive]) -> Option<String> {
    for d in directives {
        if let Directive::LogName(ln) = d {
            return Some(ln.name.clone());
        }
    }
    None
}

/// Emit warnings for directives that parse correctly but don't have runtime support yet.
fn warn_pending_runtime(address: &str, directives: &[Directive]) {
    for d in directives {
        match d {
            Directive::Templates(_) => warn!(
                address = %address,
                directive = "templates",
                "directive parsed but not yet implemented by Dwaar, ignoring"
            ),
            Directive::Push(_) => warn!(
                address = %address,
                directive = "push",
                "directive parsed but not yet implemented by Dwaar, ignoring"
            ),
            Directive::AcmeServer(_) => warn!(
                address = %address,
                directive = "acme_server",
                "directive parsed but not yet implemented by Dwaar, ignoring"
            ),
            // Metrics directive recognized — ISSUE-072 handles collection
            // via PrometheusMetrics registry, not per-route config.
            Directive::Tracing(_) => warn!(
                address = %address,
                directive = "tracing",
                "directive parsed but not yet implemented by Dwaar, ignoring"
            ),
            Directive::Fs(_) => warn!(
                address = %address,
                directive = "fs",
                "directive parsed but not yet implemented by Dwaar, ignoring"
            ),
            Directive::Invoke(_) => warn!(
                address = %address,
                directive = "invoke",
                "directive parsed but not yet implemented by Dwaar, ignoring"
            ),
            _ => {}
        }
    }
}

/// Compile a template with optional variable registry support.
///
/// If the registry has registered variables, uses `compile_with_registry` so
/// that `{my_var}` resolves to a `UserVar(slot)` segment. Otherwise, falls
/// back to `CompiledTemplate::compile` for zero-overhead when no variables exist.
fn compile_template(input: &str, registry: &VarRegistry) -> CompiledTemplate {
    if registry.is_empty() {
        match CompiledTemplate::compile(input) {
            Ok(t) => t,
            Err(e) => {
                warn!("invalid template '{input}': {e}");
                CompiledTemplate::compile("/").expect("fallback template")
            }
        }
    } else {
        match CompiledTemplate::compile_with_registry(input, registry) {
            Ok(t) => t,
            Err(e) => {
                warn!("invalid template '{input}': {e}");
                CompiledTemplate::compile("/").expect("fallback template")
            }
        }
    }
}

// ── Intercept / CopyResponseHeaders compilation (ISSUE-067) ─────────────────

/// Compile `intercept` directives into `CompiledIntercept` rules.
///
/// Each `intercept` may carry a nested `respond` for status/body override and
/// `header` directives for header injection. First-match-wins semantics are
/// enforced at runtime in `response_filter()`.
fn compile_intercepts(directives: &[Directive]) -> Vec<CompiledIntercept> {
    directives
        .iter()
        .filter_map(|d| {
            let Directive::Intercept(i) = d else {
                return None;
            };

            // Extract the first nested `respond` for status + body override.
            let (replace_status, replace_body) = i
                .directives
                .iter()
                .find_map(|inner| match inner {
                    Directive::Respond(r) => {
                        Some((Some(r.status), Some(Bytes::from(r.body.clone()))))
                    }
                    _ => None,
                })
                .unwrap_or((None, None));

            // Extract nested `header Name Value` directives for response header injection.
            let set_headers = i
                .directives
                .iter()
                .filter_map(|inner| match inner {
                    Directive::Header(HeaderDirective::Set { name, value }) => Some((
                        CompactString::from(name.as_str()),
                        CompactString::from(value.as_str()),
                    )),
                    _ => None,
                })
                .collect();

            Some(CompiledIntercept {
                statuses: i.statuses.clone(),
                replace_status,
                replace_body,
                set_headers,
            })
        })
        .collect()
}

/// Compile a `copy_response_headers` directive into a `CompiledCopyResponseHeaders`.
///
/// Headers prefixed with `-` are excludes; the rest are includes.
/// Returns `None` when the directive is absent.
fn compile_copy_response_headers(directives: &[Directive]) -> Option<CompiledCopyResponseHeaders> {
    let crh = directives.iter().find_map(|d| match d {
        Directive::CopyResponseHeaders(crh) => Some(crh),
        _ => None,
    })?;

    let mut include = Vec::new();
    let mut exclude = Vec::new();
    for header in &crh.headers {
        if let Some(name) = header.strip_prefix('-') {
            exclude.push(CompactString::from(name));
        } else {
            include.push(CompactString::from(header.as_str()));
        }
    }

    Some(CompiledCopyResponseHeaders {
        statuses: vec![],
        include,
        exclude,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;

    fn rp(addr: &str) -> Directive {
        Directive::ReverseProxy(ReverseProxyDirective {
            upstreams: vec![UpstreamAddr::SocketAddr(addr.parse().expect("valid addr"))],
            lb_policy: None,
            health_uri: None,
            health_interval: None,
            fail_duration: None,
            max_conns: None,
            transport_tls: false,
            transport_h2: false,
            tls_server_name: None,
            tls_client_auth: None,
            tls_trusted_ca_certs: None,
            scale_to_zero: None,
        })
    }

    fn rp_multi(addrs: &[&str]) -> Directive {
        Directive::ReverseProxy(ReverseProxyDirective {
            upstreams: addrs
                .iter()
                .map(|a| UpstreamAddr::SocketAddr(a.parse().expect("valid addr")))
                .collect(),
            lb_policy: Some(LbPolicy::RoundRobin),
            health_uri: None,
            health_interval: None,
            fail_duration: None,
            max_conns: None,
            transport_tls: false,
            transport_h2: false,
            tls_server_name: None,
            tls_client_auth: None,
            tls_trusted_ca_certs: None,
            scale_to_zero: None,
        })
    }

    fn rp_with_health(addr: &str, health_uri: &str) -> Directive {
        Directive::ReverseProxy(ReverseProxyDirective {
            upstreams: vec![UpstreamAddr::SocketAddr(addr.parse().expect("valid addr"))],
            lb_policy: None,
            health_uri: Some(health_uri.to_string()),
            health_interval: Some(5),
            fail_duration: None,
            max_conns: None,
            transport_tls: false,
            transport_h2: false,
            tls_server_name: None,
            tls_client_auth: None,
            tls_trusted_ca_certs: None,
            scale_to_zero: None,
        })
    }

    #[test]
    fn compile_single_site() {
        let config = DwaarConfig {
            global_options: None,
            sites: vec![SiteBlock {
                address: "example.com".to_string(),
                matchers: vec![],
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
            global_options: None,
            sites: vec![
                SiteBlock {
                    address: "api.example.com".to_string(),
                    matchers: vec![],
                    directives: vec![rp("127.0.0.1:3000")],
                },
                SiteBlock {
                    address: "web.example.com".to_string(),
                    matchers: vec![],
                    directives: vec![rp("127.0.0.1:8080")],
                },
                SiteBlock {
                    address: "*.staging.example.com".to_string(),
                    matchers: vec![],
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
            global_options: None,
            sites: vec![SiteBlock {
                address: "static.example.com".to_string(),
                matchers: vec![],
                directives: vec![Directive::Tls(TlsDirective::Auto)],
            }],
        };

        let table = compile_routes(&config);
        assert!(table.is_empty());
    }

    #[test]
    fn compile_resolves_localhost() {
        let config = DwaarConfig {
            global_options: None,
            sites: vec![SiteBlock {
                address: "example.com".to_string(),
                matchers: vec![],
                directives: vec![Directive::ReverseProxy(ReverseProxyDirective {
                    upstreams: vec![UpstreamAddr::HostPort("localhost:8080".to_string())],
                    lb_policy: None,
                    health_uri: None,
                    health_interval: None,
                    fail_duration: None,
                    max_conns: None,
                    transport_tls: false,
                    transport_h2: false,
                    tls_server_name: None,
                    tls_client_auth: None,
                    tls_trusted_ca_certs: None,
                    scale_to_zero: None,
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
            global_options: None,
            sites: vec![SiteBlock {
                address: "secure.example.com".to_string(),
                matchers: vec![],
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
            global_options: None,
            sites: vec![SiteBlock {
                address: "manual.example.com".to_string(),
                matchers: vec![],
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
            global_options: None,
            sites: vec![SiteBlock {
                address: "plain.example.com".to_string(),
                matchers: vec![],
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
            global_options: None,
            sites: vec![SiteBlock {
                address: "default.example.com".to_string(),
                matchers: vec![],
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
            global_options: None,
            sites: vec![
                SiteBlock {
                    address: "secure.example.com".to_string(),
                    matchers: vec![],
                    directives: vec![rp("127.0.0.1:3000"), Directive::Tls(TlsDirective::Auto)],
                },
                SiteBlock {
                    address: "plain.example.com".to_string(),
                    matchers: vec![],
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
            global_options: None,
            sites: vec![
                SiteBlock {
                    address: "auto.example.com".to_string(),
                    matchers: vec![],
                    directives: vec![rp("127.0.0.1:3000"), Directive::Tls(TlsDirective::Auto)],
                },
                SiteBlock {
                    address: "manual.example.com".to_string(),
                    matchers: vec![],
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
                    matchers: vec![],
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
            global_options: None,
            sites: vec![SiteBlock {
                address: "manual.example.com".to_string(),
                matchers: vec![],
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
            global_options: None,
            sites: vec![SiteBlock {
                address: "api.example.com".to_string(),
                matchers: vec![],
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
            global_options: None,
            sites: vec![SiteBlock {
                address: "example.com".to_string(),
                matchers: vec![],
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
            global_options: None,
            sites: vec![SiteBlock {
                address: "no-handler.example.com".to_string(),
                matchers: vec![],
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
        // Verify the Replace rule evaluates to "/new" (literal-only template)
        let result = block.rewrites[0]
            .apply("/anything", None)
            .expect("should match");
        assert_eq!(result, CompactString::from("/new"));
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

    // ── Variable compilation (ISSUE-055) ─────────────────────

    #[test]
    fn compile_vars_directive_creates_slots() {
        let config = DwaarConfig {
            global_options: None,
            sites: vec![SiteBlock {
                address: "example.com".to_string(),
                matchers: vec![],
                directives: vec![
                    rp("127.0.0.1:8080"),
                    Directive::Vars(VarsDirective {
                        key: "env".to_string(),
                        value: "production".to_string(),
                    }),
                ],
            }],
        };
        let table = compile_routes(&config);
        let route = table.resolve("example.com").expect("should resolve");
        assert_eq!(route.var_defaults.len(), 1);
        assert_eq!(route.var_defaults.get(0), Some("production"));
    }

    #[test]
    fn compile_multiple_vars() {
        let config = DwaarConfig {
            global_options: None,
            sites: vec![SiteBlock {
                address: "example.com".to_string(),
                matchers: vec![],
                directives: vec![
                    rp("127.0.0.1:8080"),
                    Directive::Vars(VarsDirective {
                        key: "env".to_string(),
                        value: "staging".to_string(),
                    }),
                    Directive::Vars(VarsDirective {
                        key: "version".to_string(),
                        value: "2".to_string(),
                    }),
                ],
            }],
        };
        let table = compile_routes(&config);
        let route = table.resolve("example.com").expect("should resolve");
        assert_eq!(route.var_defaults.len(), 2);
        // Both slots should have values (order depends on registration)
        assert!(route.var_defaults.get(0).is_some());
        assert!(route.var_defaults.get(1).is_some());
    }

    #[test]
    fn compile_no_vars_gives_empty_slots() {
        let config = DwaarConfig {
            global_options: None,
            sites: vec![SiteBlock {
                address: "example.com".to_string(),
                matchers: vec![],
                directives: vec![rp("127.0.0.1:8080")],
            }],
        };
        let table = compile_routes(&config);
        let route = table.resolve("example.com").expect("should resolve");
        assert!(route.var_defaults.is_empty());
    }

    #[test]
    fn compile_vars_deduplicates_same_key() {
        // Two vars with the same key — last value should win
        let config = DwaarConfig {
            global_options: None,
            sites: vec![SiteBlock {
                address: "example.com".to_string(),
                matchers: vec![],
                directives: vec![
                    rp("127.0.0.1:8080"),
                    Directive::Vars(VarsDirective {
                        key: "env".to_string(),
                        value: "staging".to_string(),
                    }),
                    Directive::Vars(VarsDirective {
                        key: "env".to_string(),
                        value: "production".to_string(),
                    }),
                ],
            }],
        };
        let table = compile_routes(&config);
        let route = table.resolve("example.com").expect("should resolve");
        // Only one slot (deduplicated), last value wins
        assert_eq!(route.var_defaults.len(), 1);
        assert_eq!(route.var_defaults.get(0), Some("production"));
    }

    #[test]
    fn compile_vars_inside_handle_block() {
        let config = crate::parser::parse(
            "a.com {\n    handle /api/* {\n        vars env production\n        reverse_proxy 127.0.0.1:8080\n    }\n    handle {\n        reverse_proxy 127.0.0.1:9090\n    }\n}\n",
        )
        .expect("should parse");
        let table = compile_routes(&config);
        let route = table.resolve("a.com").expect("should resolve");
        // The var should be registered even though it's inside a handle block
        assert_eq!(route.var_defaults.len(), 1);
        assert_eq!(route.var_defaults.get(0), Some("production"));
    }

    #[test]
    fn compile_rewrite_with_user_var() {
        // rewrite target references a user variable
        let config = DwaarConfig {
            global_options: None,
            sites: vec![SiteBlock {
                address: "example.com".to_string(),
                matchers: vec![],
                directives: vec![
                    rp("127.0.0.1:8080"),
                    Directive::Vars(VarsDirective {
                        key: "backend_path".to_string(),
                        value: "/internal/api".to_string(),
                    }),
                    Directive::Rewrite(RewriteDirective {
                        to: "{backend_path}".to_string(),
                    }),
                ],
            }],
        };
        let table = compile_routes(&config);
        let route = table.resolve("example.com").expect("should resolve");
        let block = route.handlers.first().expect("has handler");
        assert_eq!(block.rewrites.len(), 1);

        // Evaluate the rewrite with var defaults
        let ctx = dwaar_core::template::TemplateContext {
            host: "example.com",
            method: "GET",
            path: "/anything",
            uri: "/anything",
            query: "",
            scheme: "https",
            remote_host: "10.0.0.1",
            remote_port: 0,
            request_id: "test-id",
            upstream_host: "",
            upstream_port: 0,
            tls_server_name: "",
            vars: Some(&route.var_defaults),
        };
        let result = block.rewrites[0]
            .apply("/anything", Some(&ctx))
            .expect("should match");
        assert_eq!(result, CompactString::from("/internal/api"));
    }

    #[test]
    fn compile_unknown_var_in_rewrite_is_error() {
        // When no registry, unknown placeholders in rewrite targets should
        // produce warnings and use a fallback (not crash)
        let config = DwaarConfig {
            global_options: None,
            sites: vec![SiteBlock {
                address: "example.com".to_string(),
                matchers: vec![],
                directives: vec![
                    rp("127.0.0.1:8080"),
                    Directive::Rewrite(RewriteDirective {
                        to: "{nonexistent_var}".to_string(),
                    }),
                ],
            }],
        };
        // Should compile without panic — the unknown var produces a warning
        let table = compile_routes(&config);
        assert_eq!(table.len(), 1);
    }

    // ── bind directive extraction (ISSUE-066) ────────────────────────────────

    fn bind(addrs: &[&str]) -> Directive {
        Directive::Bind(BindDirective {
            addresses: addrs.iter().map(std::string::ToString::to_string).collect(),
        })
    }

    fn site_with_bind(host: &str, addrs: &[&str]) -> SiteBlock {
        SiteBlock {
            address: host.to_string(),
            matchers: vec![],
            directives: vec![bind(addrs)],
        }
    }

    #[test]
    fn bind_port_shorthand_expands_to_all_interfaces() {
        let config = DwaarConfig {
            global_options: None,
            sites: vec![site_with_bind("example.com", &[":8443"])],
        };
        let addrs = extract_bind_addresses(&config);
        assert_eq!(addrs, vec![BindAddress::Tcp("0.0.0.0:8443".to_string())]);
    }

    #[test]
    fn bind_bare_ip_appends_default_port() {
        let config = DwaarConfig {
            global_options: None,
            sites: vec![site_with_bind("example.com", &["127.0.0.1"])],
        };
        let addrs = extract_bind_addresses(&config);
        assert_eq!(addrs, vec![BindAddress::Tcp("127.0.0.1:6188".to_string())]);
    }

    #[test]
    fn bind_ip_port_passes_through() {
        let config = DwaarConfig {
            global_options: None,
            sites: vec![site_with_bind("example.com", &["10.0.0.1:9090"])],
        };
        let addrs = extract_bind_addresses(&config);
        assert_eq!(addrs, vec![BindAddress::Tcp("10.0.0.1:9090".to_string())]);
    }

    #[test]
    fn bind_unix_socket_absolute_path() {
        let config = DwaarConfig {
            global_options: None,
            // `unix//tmp/dwaar.sock` → strip `unix/` → `/tmp/dwaar.sock`
            sites: vec![site_with_bind("example.com", &["unix//tmp/dwaar.sock"])],
        };
        let addrs = extract_bind_addresses(&config);
        assert_eq!(
            addrs,
            vec![BindAddress::Unix(std::path::PathBuf::from(
                "/tmp/dwaar.sock"
            ))]
        );
    }

    #[test]
    fn bind_unix_socket_relative_path() {
        let config = DwaarConfig {
            global_options: None,
            sites: vec![site_with_bind("example.com", &["unix/run/dwaar.sock"])],
        };
        let addrs = extract_bind_addresses(&config);
        assert_eq!(
            addrs,
            vec![BindAddress::Unix(std::path::PathBuf::from(
                "run/dwaar.sock"
            ))]
        );
    }

    #[test]
    fn bind_no_directive_returns_default() {
        let config = DwaarConfig {
            global_options: None,
            sites: vec![SiteBlock {
                address: "example.com".to_string(),
                matchers: vec![],
                directives: vec![rp("127.0.0.1:8080")],
            }],
        };
        let addrs = extract_bind_addresses(&config);
        assert_eq!(addrs, vec![BindAddress::Tcp("0.0.0.0:6188".to_string())]);
    }

    #[test]
    fn bind_multiple_addresses_on_one_site() {
        let config = DwaarConfig {
            global_options: None,
            sites: vec![site_with_bind(
                "example.com",
                &["0.0.0.0:80", "0.0.0.0:8080"],
            )],
        };
        let addrs = extract_bind_addresses(&config);
        assert_eq!(addrs.len(), 2);
        assert!(addrs.contains(&BindAddress::Tcp("0.0.0.0:80".to_string())));
        assert!(addrs.contains(&BindAddress::Tcp("0.0.0.0:8080".to_string())));
    }

    #[test]
    fn bind_deduplicates_across_sites() {
        // Two different sites with the same bind address should register only once.
        let config = DwaarConfig {
            global_options: None,
            sites: vec![
                site_with_bind("a.example.com", &["0.0.0.0:80"]),
                site_with_bind("b.example.com", &["0.0.0.0:80"]),
            ],
        };
        let addrs = extract_bind_addresses(&config);
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], BindAddress::Tcp("0.0.0.0:80".to_string()));
    }

    // ── reverse_proxy compilation (ISSUE-065) ────────────────────────────────

    fn make_site(address: &str, directive: Directive) -> SiteBlock {
        SiteBlock {
            address: address.to_string(),
            matchers: vec![],
            directives: vec![directive],
        }
    }

    #[test]
    fn single_upstream_no_block_options_compiles_to_reverse_proxy() {
        let config = DwaarConfig {
            global_options: None,
            sites: vec![make_site("example.com", rp("127.0.0.1:8080"))],
        };
        let table = compile_routes(&config);
        let route = table.resolve("example.com").expect("should resolve");
        let block = route.handlers.first().expect("has handler block");
        assert!(
            matches!(&block.handler, Handler::ReverseProxy { upstream, .. }
                    if *upstream == "127.0.0.1:8080".parse::<SocketAddr>().expect("valid test addr")),
            "single upstream without block options must compile to ReverseProxy"
        );
    }

    #[test]
    fn multi_upstream_compiles_to_reverse_proxy_pool() {
        let config = DwaarConfig {
            global_options: None,
            sites: vec![make_site(
                "example.com",
                rp_multi(&["127.0.0.1:8080", "127.0.0.1:8081"]),
            )],
        };
        let table = compile_routes(&config);
        let route = table.resolve("example.com").expect("should resolve");
        let block = route.handlers.first().expect("has handler block");
        assert!(
            matches!(&block.handler, Handler::ReverseProxyPool { pool, .. } if pool.len() == 2),
            "multi-upstream must compile to ReverseProxyPool"
        );
    }

    #[test]
    fn health_uri_triggers_pool_creation() {
        let config = DwaarConfig {
            global_options: None,
            sites: vec![make_site(
                "example.com",
                rp_with_health("127.0.0.1:8080", "/health"),
            )],
        };
        let table = compile_routes(&config);
        let route = table.resolve("example.com").expect("should resolve");
        let block = route.handlers.first().expect("has handler block");
        assert!(
            matches!(&block.handler, Handler::ReverseProxyPool { .. }),
            "health_uri must trigger pool creation even for single upstream"
        );
    }

    #[test]
    fn collect_pools_finds_health_pools() {
        let config = DwaarConfig {
            global_options: None,
            sites: vec![
                make_site("a.com", rp_with_health("127.0.0.1:8080", "/health")),
                make_site("b.com", rp("127.0.0.1:9090")),
            ],
        };
        let table = compile_routes(&config);
        let pools = collect_pools(&table);
        assert_eq!(
            pools.len(),
            1,
            "only the pool with health_uri should be collected"
        );
    }

    // ── Intercept compilation (ISSUE-067) ────────────────────────

    #[test]
    fn compile_intercept_with_respond_override() {
        let config = DwaarConfig {
            global_options: None,
            sites: vec![SiteBlock {
                address: "example.com".to_string(),
                matchers: vec![],
                directives: vec![
                    rp("127.0.0.1:8080"),
                    Directive::Intercept(InterceptDirective {
                        statuses: vec![404],
                        directives: vec![Directive::Respond(RespondDirective {
                            status: 200,
                            body: "not found page".to_string(),
                        })],
                    }),
                ],
            }],
        };
        let table = compile_routes(&config);
        let route = table.resolve("example.com").expect("should resolve");
        let block = route.handlers.first().expect("has handler block");
        assert_eq!(block.intercepts.len(), 1);
        let rule = &block.intercepts[0];
        assert_eq!(rule.statuses, vec![404]);
        assert_eq!(rule.replace_status, Some(200));
        assert_eq!(
            rule.replace_body.as_deref(),
            Some(b"not found page".as_ref())
        );
    }

    #[test]
    fn compile_intercept_empty_statuses_is_catch_all() {
        let config = DwaarConfig {
            global_options: None,
            sites: vec![SiteBlock {
                address: "example.com".to_string(),
                matchers: vec![],
                directives: vec![
                    rp("127.0.0.1:8080"),
                    Directive::Intercept(InterceptDirective {
                        statuses: vec![],
                        directives: vec![Directive::Respond(RespondDirective {
                            status: 503,
                            body: String::new(),
                        })],
                    }),
                ],
            }],
        };
        let table = compile_routes(&config);
        let route = table.resolve("example.com").expect("should resolve");
        let block = route.handlers.first().expect("has handler block");
        assert_eq!(block.intercepts.len(), 1);
        // Empty statuses = catch all non-2xx at runtime
        assert!(block.intercepts[0].statuses.is_empty());
    }

    #[test]
    fn compile_copy_response_headers_include() {
        let config = DwaarConfig {
            global_options: None,
            sites: vec![SiteBlock {
                address: "example.com".to_string(),
                matchers: vec![],
                directives: vec![
                    rp("127.0.0.1:8080"),
                    Directive::CopyResponseHeaders(CopyResponseHeadersDirective {
                        headers: vec!["X-Custom".to_string(), "X-Other".to_string()],
                    }),
                ],
            }],
        };
        let table = compile_routes(&config);
        let route = table.resolve("example.com").expect("should resolve");
        let block = route.handlers.first().expect("has handler block");
        let crh = block
            .copy_response_headers
            .as_ref()
            .expect("has copy_response_headers");
        assert_eq!(crh.include.len(), 2);
        assert!(crh.exclude.is_empty());
        assert!(crh.include.iter().any(|h| h.as_str() == "X-Custom"));
    }

    #[test]
    fn compile_copy_response_headers_exclude() {
        let config = DwaarConfig {
            global_options: None,
            sites: vec![SiteBlock {
                address: "example.com".to_string(),
                matchers: vec![],
                directives: vec![
                    rp("127.0.0.1:8080"),
                    Directive::CopyResponseHeaders(CopyResponseHeadersDirective {
                        headers: vec!["-Set-Cookie".to_string(), "-Server".to_string()],
                    }),
                ],
            }],
        };
        let table = compile_routes(&config);
        let route = table.resolve("example.com").expect("should resolve");
        let block = route.handlers.first().expect("has handler block");
        let crh = block
            .copy_response_headers
            .as_ref()
            .expect("has copy_response_headers");
        assert!(crh.include.is_empty());
        assert_eq!(crh.exclude.len(), 2);
        // Strip prefix is applied during compile — stored without the '-'
        assert!(crh.exclude.iter().any(|h| h.as_str() == "Set-Cookie"));
        assert!(crh.exclude.iter().any(|h| h.as_str() == "Server"));
    }

    #[test]
    fn compile_no_copy_response_headers_gives_none() {
        let config = DwaarConfig {
            global_options: None,
            sites: vec![SiteBlock {
                address: "example.com".to_string(),
                matchers: vec![],
                directives: vec![rp("127.0.0.1:8080")],
            }],
        };
        let table = compile_routes(&config);
        let route = table.resolve("example.com").expect("should resolve");
        let block = route.handlers.first().expect("has handler block");
        assert!(block.copy_response_headers.is_none());
        assert!(block.intercepts.is_empty());
    }
}
