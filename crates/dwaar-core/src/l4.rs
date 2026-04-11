// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Layer 4 TCP proxy runtime.
//!
//! Implements caddy-l4 compatible TCP proxying: protocol-aware matchers
//! peek at the first packet to detect TLS (SNI/ALPN), HTTP, SSH, Postgres,
//! then route to the matching handler chain. Handlers either forward raw
//! bytes (proxy), terminate TLS, or nest into subroutes.
//!
//! The service binds its own TCP listeners separate from the HTTP proxy
//! and runs as a Pingora `BackgroundService`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::BytesMut;
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

/// Default matching timeout — how long we wait for enough bytes to arrive
/// for protocol detection before dropping the connection.
const DEFAULT_MATCHING_TIMEOUT: Duration = Duration::from_secs(3);

/// Maximum bytes to peek for protocol detection. TLS ClientHello is
/// typically <500 bytes; we allow up to 4 KB to handle large SNI lists.
const MAX_PEEK_BYTES: usize = 4096;

/// Buffer size for the bidirectional splice loop.
const SPLICE_BUF_SIZE: usize = 64 * 1024;

// ── Compiled L4 config (runtime representation) ─────────────────────────

/// A compiled Layer 4 server ready for runtime. One per listen address.
#[derive(Debug, Clone)]
pub struct CompiledL4Server {
    pub listen: SocketAddr,
    pub routes: Vec<CompiledL4Route>,
    pub matching_timeout: Duration,
}

/// A compiled L4 route with pre-resolved matchers and handlers.
#[derive(Debug, Clone)]
pub struct CompiledL4Route {
    pub matchers: Vec<CompiledL4Matcher>,
    pub handlers: Vec<CompiledL4Handler>,
}

/// Protocol matchers compiled from config.
#[derive(Debug, Clone)]
pub enum CompiledL4Matcher {
    /// Match TLS ClientHello. If sni/alpn are empty, matches any TLS.
    Tls {
        sni: Vec<String>,
        alpn: Vec<String>,
    },
    /// Match HTTP request line.
    Http {
        host: Vec<String>,
    },
    /// Match SSH version string (`SSH-`).
    Ssh,
    /// Match PostgreSQL startup message.
    Postgres,
    /// Match source IP against CIDR ranges.
    RemoteIp(Vec<ipnet::IpNet>),
    /// Negate a matcher.
    Not(Box<CompiledL4Matcher>),
}

/// Compiled handlers.
#[derive(Debug, Clone)]
pub enum CompiledL4Handler {
    /// Forward raw bytes to upstream.
    Proxy {
        upstreams: Vec<SocketAddr>,
    },
    /// TLS termination — decrypt then pass to next handler.
    /// Not yet implemented; placeholder for forward compatibility.
    Tls,
    /// Nested routing after decryption.
    Subroute {
        routes: Vec<CompiledL4Route>,
        matching_timeout: Duration,
    },
}

// ── Service ─────────────────────────────────────────────────────────────

/// Background service that runs one or more Layer 4 TCP listeners.
pub struct Layer4Service {
    servers: Vec<CompiledL4Server>,
}

impl std::fmt::Debug for Layer4Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Layer4Service")
            .field("servers", &self.servers.len())
            .finish()
    }
}

impl Layer4Service {
    pub fn new(servers: Vec<CompiledL4Server>) -> Self {
        Self { servers }
    }
}

#[async_trait]
impl BackgroundService for Layer4Service {
    async fn start(&self, shutdown: ShutdownWatch) {
        let mut listeners = Vec::new();

        for server in &self.servers {
            match TcpListener::bind(server.listen).await {
                Ok(listener) => {
                    info!(addr = %server.listen, routes = server.routes.len(), "L4 listener bound");
                    listeners.push((listener, server.clone()));
                }
                Err(e) => {
                    error!(addr = %server.listen, error = %e, "failed to bind L4 listener");
                }
            }
        }

        if listeners.is_empty() {
            warn!("no L4 listeners bound — layer4 service idle");
            return;
        }

        let mut tasks = tokio::task::JoinSet::new();

        for (listener, server) in listeners {
            let shutdown = shutdown.clone();
            let server = Arc::new(server);
            tasks.spawn(async move {
                run_listener(listener, server, shutdown).await;
            });
        }

        // Wait for all listener tasks to complete (on shutdown).
        while tasks.join_next().await.is_some() {}
    }
}

async fn run_listener(
    listener: TcpListener,
    server: Arc<CompiledL4Server>,
    shutdown: ShutdownWatch,
) {
    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, peer)) => {
                        let server = Arc::clone(&server);
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, peer, &server).await {
                                debug!(peer = %peer, error = %e, "L4 connection error");
                            }
                        });
                    }
                    Err(e) => {
                        error!(error = %e, "L4 accept error");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
            _ = shutdown_signal(&shutdown) => {
                info!("L4 listener shutting down");
                return;
            }
        }
    }
}

async fn shutdown_signal(shutdown: &ShutdownWatch) {
    let mut watch = shutdown.clone();
    while !*watch.borrow() {
        if watch.changed().await.is_err() {
            return;
        }
    }
}

// ── Connection handling ─────────────────────────────────────────────────

async fn handle_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    server: &CompiledL4Server,
) -> Result<(), L4Error> {
    // Peek at the first bytes for protocol detection.
    let mut peek_buf = BytesMut::zeroed(MAX_PEEK_BYTES);
    let peeked = tokio::time::timeout(server.matching_timeout, async {
        // Use peek so the bytes remain in the socket buffer for the upstream.
        stream.peek(&mut peek_buf).await
    })
    .await
    .map_err(|_| L4Error::MatchingTimeout)?
    .map_err(L4Error::Io)?;

    let peeked_data = &peek_buf[..peeked];

    // Try each route in order — first match wins.
    for route in &server.routes {
        if route_matches(route, peeked_data, peer) {
            return execute_handlers(&route.handlers, stream, peer, peeked_data).await;
        }
    }

    debug!(peer = %peer, "no L4 route matched — closing connection");
    Ok(())
}

fn route_matches(route: &CompiledL4Route, peeked: &[u8], peer: SocketAddr) -> bool {
    // Empty matchers = catch-all.
    if route.matchers.is_empty() {
        return true;
    }
    // All matchers must match (AND logic within a route).
    route.matchers.iter().all(|m| matcher_matches(m, peeked, peer))
}

fn matcher_matches(matcher: &CompiledL4Matcher, peeked: &[u8], peer: SocketAddr) -> bool {
    match matcher {
        CompiledL4Matcher::Tls { sni, alpn } => {
            match parse_tls_client_hello(peeked) {
                Some(hello) => {
                    // If sni list is empty, match any TLS. Otherwise, SNI must match.
                    let sni_ok = sni.is_empty()
                        || hello
                            .sni
                            .as_ref()
                            .is_some_and(|s| sni.iter().any(|pattern| sni_matches(pattern, s)));
                    let alpn_ok = alpn.is_empty()
                        || hello.alpn.iter().any(|a| alpn.contains(a));
                    sni_ok && alpn_ok
                }
                None => false,
            }
        }
        CompiledL4Matcher::Http { host } => {
            if !looks_like_http(peeked) {
                return false;
            }
            if host.is_empty() {
                return true;
            }
            extract_http_host(peeked)
                .is_some_and(|h| host.iter().any(|pattern| h.eq_ignore_ascii_case(pattern)))
        }
        CompiledL4Matcher::Ssh => peeked.starts_with(b"SSH-"),
        CompiledL4Matcher::Postgres => {
            // PostgreSQL startup message: 4 bytes length + 4 bytes protocol version (196608 = 3.0)
            peeked.len() >= 8 && {
                let version = u32::from_be_bytes([peeked[4], peeked[5], peeked[6], peeked[7]]);
                version == 196_608 // 3.0
            }
        }
        CompiledL4Matcher::RemoteIp(ranges) => {
            let ip = peer.ip();
            ranges.iter().any(|net| net.contains(&ip))
        }
        CompiledL4Matcher::Not(inner) => !matcher_matches(inner, peeked, peer),
    }
}

/// SNI matching with wildcard support: `*.example.com` matches `foo.example.com`
/// but NOT `foo.bar.example.com` (single label only, per RFC 6125 §6.4.3).
fn sni_matches(pattern: &str, sni: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // Must end with `.suffix`, and the part before `.suffix` must be
        // a single label (no dots).
        let sni_lower = sni.to_ascii_lowercase();
        if let Some(prefix) = sni_lower.strip_suffix(suffix) {
            // prefix should be "label." — exactly one dot at the end, none before
            prefix.ends_with('.') && !prefix[..prefix.len() - 1].contains('.')
        } else {
            false
        }
    } else {
        pattern.eq_ignore_ascii_case(sni)
    }
}

// ── Handler execution ───────────────────────────────────────────────────

async fn execute_handlers(
    handlers: &[CompiledL4Handler],
    stream: TcpStream,
    peer: SocketAddr,
    _peeked: &[u8],
) -> Result<(), L4Error> {
    // For the initial implementation, find the first Proxy handler and splice.
    // Handler chaining (tls -> subroute -> proxy) will be added incrementally.
    for handler in handlers {
        match handler {
            CompiledL4Handler::Proxy { upstreams } => {
                if upstreams.is_empty() {
                    return Err(L4Error::NoUpstream);
                }
                // Simple round-robin: pick based on connection source port.
                let idx = peer.port() as usize % upstreams.len();
                let upstream_addr = upstreams[idx];

                debug!(
                    peer = %peer,
                    upstream = %upstream_addr,
                    "L4 proxy: connecting to upstream"
                );

                let upstream = tokio::time::timeout(
                    Duration::from_secs(10),
                    TcpStream::connect(upstream_addr),
                )
                .await
                .map_err(|_| L4Error::UpstreamTimeout(upstream_addr))?
                .map_err(|e| L4Error::UpstreamConnect(upstream_addr, e))?;

                splice(stream, upstream).await?;
                return Ok(());
            }
            CompiledL4Handler::Tls => {
                // TLS termination at L4 level is complex — requires injecting
                // an SSL context mid-stream. Deferred to a follow-up issue.
                warn!(peer = %peer, "L4 TLS handler not yet implemented — dropping connection");
                return Ok(());
            }
            CompiledL4Handler::Subroute { routes, matching_timeout: _ } => {
                // Subroute after TLS termination would re-peek decrypted bytes.
                // Without TLS handler, subroute on raw bytes is just re-matching.
                warn!(peer = %peer, "L4 subroute without TLS not yet useful — skipping");
            }
        }
    }
    Ok(())
}

/// Bidirectional TCP splice: copy bytes in both directions until both sides close.
///
/// When one direction hits EOF, we half-close the corresponding write side
/// so the peer sees EOF too, then let the other direction drain naturally.
/// This handles the common pattern where a client sends a request, closes
/// its write side, the upstream processes and responds, then closes its
/// write side.
async fn splice(client: TcpStream, upstream: TcpStream) -> Result<(), L4Error> {
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut ur, mut uw) = tokio::io::split(upstream);

    let c2u = async {
        let result = tokio::io::copy(&mut cr, &mut uw).await;
        let _ = uw.shutdown().await;
        result
    };

    let u2c = async {
        let result = tokio::io::copy(&mut ur, &mut cw).await;
        let _ = cw.shutdown().await;
        result
    };

    let (c2u_result, u2c_result) = tokio::join!(c2u, u2c);

    if let Err(e) = c2u_result {
        debug!(error = %e, "L4 client→upstream copy error");
    }
    if let Err(e) = u2c_result {
        debug!(error = %e, "L4 upstream→client copy error");
    }

    Ok(())
}

// ── Protocol detection ──────────────────────────────────────────────────

/// Minimal TLS ClientHello fields we care about for matching.
struct TlsClientHello {
    sni: Option<String>,
    alpn: Vec<String>,
}

/// Parse a TLS ClientHello to extract SNI and ALPN.
///
/// Only parses enough to find the extensions we need — doesn't validate
/// the full handshake. Returns None if the bytes don't look like a
/// ClientHello.
fn parse_tls_client_hello(data: &[u8]) -> Option<TlsClientHello> {
    // TLS record: type(1) + version(2) + length(2) + handshake
    if data.len() < 5 || data[0] != 0x16 {
        return None; // Not a TLS handshake record
    }

    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_len.min(MAX_PEEK_BYTES - 5) {
        return None; // Truncated — need more data
    }

    let hs = &data[5..];
    if hs.is_empty() || hs[0] != 0x01 {
        return None; // Not a ClientHello
    }

    // Skip: handshake_type(1) + length(3) + client_version(2) + random(32)
    if hs.len() < 38 {
        return None;
    }
    let mut pos = 38;

    // Skip session_id
    if pos >= hs.len() {
        return None;
    }
    let session_id_len = hs[pos] as usize;
    pos += 1 + session_id_len;

    // Skip cipher_suites
    if pos + 2 > hs.len() {
        return None;
    }
    let cipher_len = u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
    pos += 2 + cipher_len;

    // Skip compression_methods
    if pos >= hs.len() {
        return None;
    }
    let comp_len = hs[pos] as usize;
    pos += 1 + comp_len;

    // Extensions
    if pos + 2 > hs.len() {
        return Some(TlsClientHello {
            sni: None,
            alpn: Vec::new(),
        });
    }
    let ext_total = u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
    pos += 2;

    let ext_end = (pos + ext_total).min(hs.len());
    let mut sni = None;
    let mut alpn = Vec::new();

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([hs[pos], hs[pos + 1]]);
        let ext_len = u16::from_be_bytes([hs[pos + 2], hs[pos + 3]]) as usize;
        pos += 4;

        if pos + ext_len > ext_end {
            break;
        }

        match ext_type {
            0x0000 => {
                // SNI extension
                if ext_len >= 5 {
                    let name_len =
                        u16::from_be_bytes([hs[pos + 3], hs[pos + 4]]) as usize;
                    if pos + 5 + name_len <= ext_end {
                        if let Ok(name) = std::str::from_utf8(&hs[pos + 5..pos + 5 + name_len]) {
                            sni = Some(name.to_lowercase());
                        }
                    }
                }
            }
            0x0010 => {
                // ALPN extension
                if ext_len >= 2 {
                    let list_len =
                        u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
                    let mut apos = pos + 2;
                    let aend = (pos + 2 + list_len).min(ext_end);
                    while apos < aend {
                        let proto_len = hs[apos] as usize;
                        apos += 1;
                        if apos + proto_len <= aend {
                            if let Ok(proto) = std::str::from_utf8(&hs[apos..apos + proto_len]) {
                                alpn.push(proto.to_string());
                            }
                        }
                        apos += proto_len;
                    }
                }
            }
            _ => {}
        }

        pos += ext_len;
    }

    Some(TlsClientHello { sni, alpn })
}

/// Quick check: does this look like an HTTP request?
fn looks_like_http(data: &[u8]) -> bool {
    data.starts_with(b"GET ")
        || data.starts_with(b"POST ")
        || data.starts_with(b"PUT ")
        || data.starts_with(b"DELETE ")
        || data.starts_with(b"HEAD ")
        || data.starts_with(b"OPTIONS ")
        || data.starts_with(b"PATCH ")
        || data.starts_with(b"CONNECT ")
}

/// Extract the Host header value from a peeked HTTP request.
fn extract_http_host(data: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(data).ok()?;
    for line in text.lines().skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some(value) = line.strip_prefix("Host: ").or_else(|| line.strip_prefix("host: ")) {
            // Strip port if present
            return Some(value.split(':').next().unwrap_or(value).trim());
        }
    }
    None
}

// ── Errors ──────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum L4Error {
    #[error("matching timeout — no protocol detected within deadline")]
    MatchingTimeout,
    #[error("I/O error: {0}")]
    Io(std::io::Error),
    #[error("no upstream configured for matched route")]
    NoUpstream,
    #[error("upstream {0} connect timed out")]
    UpstreamTimeout(SocketAddr),
    #[error("upstream {0} connect failed: {1}")]
    UpstreamConnect(SocketAddr, std::io::Error),
}

// ── Compilation helpers (no config model dependency) ────────────────────

/// Parse a listen address like `:8443`, `127.0.0.1:5000`, or `0.0.0.0:443`.
fn parse_listen_addr(s: &str) -> Option<SocketAddr> {
    // Handle `:port` shorthand → `0.0.0.0:port`
    let normalized = if s.starts_with(':') {
        format!("0.0.0.0{s}")
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

/// Parse a duration string like "3s", "500ms", "1m".
fn parse_duration(s: &str) -> Option<Duration> {
    if let Some(rest) = s.strip_suffix("ms") {
        rest.parse().ok().map(Duration::from_millis)
    } else if let Some(rest) = s.strip_suffix('s') {
        rest.parse().ok().map(Duration::from_secs)
    } else if let Some(rest) = s.strip_suffix('m') {
        rest.parse::<u64>().ok().map(|m| Duration::from_secs(m * 60))
    } else {
        s.parse().ok().map(Duration::from_secs)
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // -- Protocol detection --

    #[test]
    fn detect_tls_client_hello() {
        // Minimal TLS 1.2 ClientHello with SNI "example.com"
        let hello = build_test_client_hello("example.com", &["h2", "http/1.1"]);
        let parsed = parse_tls_client_hello(&hello).expect("should parse");
        assert_eq!(parsed.sni.as_deref(), Some("example.com"));
        assert!(parsed.alpn.contains(&"h2".to_string()));
        assert!(parsed.alpn.contains(&"http/1.1".to_string()));
    }

    #[test]
    fn detect_non_tls_returns_none() {
        assert!(parse_tls_client_hello(b"GET / HTTP/1.1\r\n").is_none());
        assert!(parse_tls_client_hello(b"SSH-2.0-OpenSSH").is_none());
        assert!(parse_tls_client_hello(b"").is_none());
    }

    #[test]
    fn detect_http() {
        assert!(looks_like_http(b"GET / HTTP/1.1\r\n"));
        assert!(looks_like_http(b"POST /api HTTP/2\r\n"));
        assert!(!looks_like_http(b"SSH-2.0-OpenSSH"));
        assert!(!looks_like_http(b"\x16\x03\x01"));
    }

    #[test]
    fn detect_ssh() {
        let matcher = CompiledL4Matcher::Ssh;
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        assert!(matcher_matches(&matcher, b"SSH-2.0-OpenSSH_8.9", peer));
        assert!(!matcher_matches(&matcher, b"GET / HTTP/1.1", peer));
    }

    #[test]
    fn detect_postgres() {
        let matcher = CompiledL4Matcher::Postgres;
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        // PostgreSQL v3.0 startup: length(4) + version 196608(4) + params
        let mut msg = vec![0u8; 16];
        msg[0..4].copy_from_slice(&12u32.to_be_bytes()); // length
        msg[4..8].copy_from_slice(&196608u32.to_be_bytes()); // version 3.0
        assert!(matcher_matches(&matcher, &msg, peer));
        assert!(!matcher_matches(&matcher, b"GET /", peer));
    }

    #[test]
    fn extract_http_host_header() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(extract_http_host(req), Some("example.com"));

        let req_port = b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
        assert_eq!(extract_http_host(req_port), Some("example.com"));
    }

    #[test]
    fn remote_ip_matcher() {
        let matcher = CompiledL4Matcher::RemoteIp(vec!["10.0.0.0/8".parse().unwrap()]);
        let peer_match: SocketAddr = "10.0.1.5:12345".parse().unwrap();
        let peer_no_match: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        assert!(matcher_matches(&matcher, b"", peer_match));
        assert!(!matcher_matches(&matcher, b"", peer_no_match));
    }

    #[test]
    fn not_matcher() {
        let matcher = CompiledL4Matcher::Not(Box::new(CompiledL4Matcher::Ssh));
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        assert!(matcher_matches(&matcher, b"GET / HTTP/1.1", peer));
        assert!(!matcher_matches(&matcher, b"SSH-2.0-OpenSSH", peer));
    }

    #[test]
    fn sni_wildcard_matching() {
        assert!(sni_matches("*.example.com", "foo.example.com"));
        assert!(sni_matches("*.example.com", "bar.example.com"));
        assert!(!sni_matches("*.example.com", "example.com"));
        assert!(!sni_matches("*.example.com", "foo.bar.example.com"));
        assert!(sni_matches("example.com", "example.com"));
        assert!(sni_matches("example.com", "Example.Com"));
    }

    #[test]
    fn parse_listen_addr_variants() {
        assert_eq!(
            parse_listen_addr(":8443"),
            Some("0.0.0.0:8443".parse().unwrap())
        );
        assert_eq!(
            parse_listen_addr("127.0.0.1:5000"),
            Some("127.0.0.1:5000".parse().unwrap())
        );
        assert!(parse_listen_addr("invalid").is_none());
    }

    #[test]
    fn route_catch_all_matches_anything() {
        let route = CompiledL4Route {
            matchers: vec![],
            handlers: vec![],
        };
        let peer: SocketAddr = "1.2.3.4:9999".parse().unwrap();
        assert!(route_matches(&route, b"anything", peer));
    }

    // -- Integration test: TCP splice --

    #[tokio::test]
    async fn splice_forwards_bytes_bidirectionally() {
        // Mock upstream: reads all data, echoes it back, then closes.
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut sock, _) = upstream_listener.accept().await.unwrap();
            let mut buf = Vec::new();
            sock.read_to_end(&mut buf).await.unwrap();
            sock.write_all(&buf).await.unwrap();
            sock.shutdown().await.unwrap();
        });

        // Proxy: accepts client, splices to upstream.
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (client, _) = proxy_listener.accept().await.unwrap();
            let upstream = TcpStream::connect(upstream_addr).await.unwrap();
            splice(client, upstream).await.unwrap();
        });

        // Client: send data, half-close write, read response.
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(b"hello layer4").await.unwrap();
        // Half-close write side so upstream sees EOF and echoes.
        client.shutdown().await.unwrap();

        let mut response = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.read_to_end(&mut response),
        )
        .await
        .expect("should not timeout")
        .unwrap();
        assert_eq!(response, b"hello layer4");
    }

    // -- Helper: build a minimal TLS ClientHello --

    fn build_test_client_hello(sni: &str, alpn_protos: &[&str]) -> Vec<u8> {
        let mut extensions = Vec::new();

        // SNI extension (type 0x0000)
        {
            let name_bytes = sni.as_bytes();
            let mut sni_ext = Vec::new();
            // SNI list length
            let entry_len = 3 + name_bytes.len();
            sni_ext.extend_from_slice(&(entry_len as u16).to_be_bytes());
            sni_ext.push(0x00); // host_name type
            sni_ext.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
            sni_ext.extend_from_slice(name_bytes);

            extensions.extend_from_slice(&0x0000u16.to_be_bytes()); // type
            extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes()); // length
            extensions.extend_from_slice(&sni_ext);
        }

        // ALPN extension (type 0x0010)
        if !alpn_protos.is_empty() {
            let mut alpn_list = Vec::new();
            for proto in alpn_protos {
                alpn_list.push(proto.len() as u8);
                alpn_list.extend_from_slice(proto.as_bytes());
            }
            let mut alpn_ext = Vec::new();
            alpn_ext.extend_from_slice(&(alpn_list.len() as u16).to_be_bytes());
            alpn_ext.extend_from_slice(&alpn_list);

            extensions.extend_from_slice(&0x0010u16.to_be_bytes());
            extensions.extend_from_slice(&(alpn_ext.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&alpn_ext);
        }

        // Build handshake body
        let mut handshake = Vec::new();
        handshake.extend_from_slice(&[0x03, 0x03]); // client_version TLS 1.2
        handshake.extend_from_slice(&[0u8; 32]); // random
        handshake.push(0); // session_id length
        handshake.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites length
        handshake.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        handshake.push(1); // compression_methods length
        handshake.push(0); // null compression
        handshake.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        handshake.extend_from_slice(&extensions);

        // Wrap in handshake message
        let mut hs_msg = vec![0x01]; // ClientHello
        let hs_len = handshake.len();
        hs_msg.push(((hs_len >> 16) & 0xFF) as u8);
        hs_msg.push(((hs_len >> 8) & 0xFF) as u8);
        hs_msg.push((hs_len & 0xFF) as u8);
        hs_msg.extend_from_slice(&handshake);

        // Wrap in TLS record
        let mut record = vec![0x16, 0x03, 0x01]; // TLS record, version 1.0
        record.extend_from_slice(&(hs_msg.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs_msg);

        record
    }
}
