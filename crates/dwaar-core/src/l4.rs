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

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use bytes::BytesMut;
use openssl::ssl::{SslAcceptor, SslMethod, SslVerifyMode};
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use dwaar_tls::cert_store::CertStore;

/// Default matching timeout — how long we wait for enough bytes to arrive
/// for protocol detection before dropping the connection.
#[allow(dead_code)] // reserved for per-server timeout default wiring
const DEFAULT_MATCHING_TIMEOUT: Duration = Duration::from_secs(3);

/// Maximum bytes to peek for protocol detection. TLS `ClientHello` is
/// typically <500 bytes; we allow up to 4 KB to handle large SNI lists.
const MAX_PEEK_BYTES: usize = 4096;

/// Buffer size for the bidirectional splice loop.
#[allow(dead_code)] // reserved for future zero-copy splice path
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
    /// Match TLS `ClientHello`. If sni/alpn are empty, matches any TLS.
    Tls { sni: Vec<String>, alpn: Vec<String> },
    /// Match HTTP request line.
    Http { host: Vec<String> },
    /// Match SSH version string (`SSH-`).
    Ssh,
    /// Match `PostgreSQL` startup message.
    Postgres,
    /// Match source IP against CIDR ranges.
    RemoteIp(Vec<ipnet::IpNet>),
    /// Negate a matcher.
    Not(Box<CompiledL4Matcher>),
}

/// Load balancing algorithm for the L4 proxy handler.
///
/// Mirrors the HTTP `LbPolicy` in dwaar-config but is defined here so that
/// dwaar-core stays free of any dwaar-config import (circular dep guardrail).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum L4LoadBalancePolicy {
    /// Distribute connections evenly in turn — default.
    #[default]
    RoundRobin,
    /// Pick the upstream with the fewest active connections.
    LeastConn,
    /// Uniformly random pick.
    Random,
    /// Hash the client IP so the same client always hits the same upstream.
    IpHash,
}

/// Per-upstream passive health state — all fields are atomic so connection
/// handler tasks can update them without locking.
///
/// Passive health means we infer health from real connection outcomes rather
/// than spawning a separate prober. After `max_fails` consecutive connect
/// failures we stop trying that upstream for `fail_duration`. On the next
/// successful connect the counters reset.
#[derive(Debug)]
pub struct L4UpstreamHealth {
    /// Address of the upstream this tracks.
    pub addr: SocketAddr,
    /// Consecutive connect failures since the last success.
    pub consecutive_fails: AtomicU32,
    /// Number of active connections routed to this upstream.
    pub active_conns: AtomicU32,
    /// Timestamp (as secs since UNIX epoch, u64) when the upstream may be
    /// retried after being quarantined. Zero = not quarantined.
    ///
    /// We store epoch-seconds as a u64 to stay lock-free. Precision to the
    /// second is fine for a health quarantine timer.
    pub retry_after_secs: AtomicU64,
}

impl L4UpstreamHealth {
    fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            consecutive_fails: AtomicU32::new(0),
            active_conns: AtomicU32::new(0),
            retry_after_secs: AtomicU64::new(0),
        }
    }

    /// Returns true when the upstream is currently quarantined and should be
    /// skipped. Uses monotonic wall-clock seconds to avoid clock skew issues.
    fn is_quarantined(&self) -> bool {
        let retry_at = self.retry_after_secs.load(Ordering::Relaxed);
        if retry_at == 0 {
            return false;
        }
        // Compare against current epoch secs. Fallback to not-quarantined if
        // the system clock is unavailable (practically impossible, but safe).
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        now < retry_at
    }

    /// Record a successful connect: clear the failure counter and quarantine.
    fn record_success(&self) {
        self.consecutive_fails.store(0, Ordering::Relaxed);
        self.retry_after_secs.store(0, Ordering::Relaxed);
    }

    /// Record a failed connect. Returns `true` if the upstream was just
    /// quarantined (i.e. this was the `max_fails`-th consecutive failure).
    fn record_failure(&self, max_fails: u32, fail_duration: Duration) -> bool {
        let prev = self.consecutive_fails.fetch_add(1, Ordering::Relaxed);
        if prev + 1 >= max_fails {
            // Quarantine: record the earliest time we'll try again.
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            self.retry_after_secs
                .store(now + fail_duration.as_secs(), Ordering::Relaxed);
            true
        } else {
            false
        }
    }
}

/// Compiled handlers.
#[derive(Debug)]
pub enum CompiledL4Handler {
    /// Forward raw bytes to upstream.
    Proxy {
        /// Resolved upstream socket addresses.
        upstreams: Vec<SocketAddr>,
        /// Per-upstream passive health state. Parallel to `upstreams`.
        health: Vec<Arc<L4UpstreamHealth>>,
        /// Load balancing policy — see `L4LoadBalancePolicy`.
        lb_policy: L4LoadBalancePolicy,
        /// Global round-robin counter, shared across all connections to this
        /// handler. Relaxed ordering is sufficient — a slightly stale value
        /// only shifts which upstream gets the connection, not correctness.
        rr_counter: Arc<AtomicU64>,
        /// After this many consecutive connect failures, quarantine the
        /// upstream for `fail_duration`. Defaults to 3.
        max_fails: u32,
        /// How long to quarantine a failing upstream. Defaults to 10 s.
        fail_duration: Duration,
        /// Per-connection connect timeout. Defaults to 10 s.
        connect_timeout: Duration,
    },
    /// TLS termination — decrypt then pass to the next handler in the chain.
    ///
    /// Carries the cert store so the acceptor can look up the right cert for
    /// the SNI hostname parsed from the `ClientHello` peek. We avoid baking in
    /// an `SslAcceptor` because certs are hot-reloadable; the store handles
    /// its own LRU cache.
    Tls {
        /// Injected at runtime in main.rs after compilation. `None` during
        /// the compile phase; the service refuses TLS if still `None` at
        /// accept time.
        cert_store: Option<Arc<CertStore>>,
    },
    /// Nested routing after decryption.
    Subroute {
        routes: Vec<CompiledL4Route>,
        matching_timeout: Duration,
    },
}

// Manual Clone: Arc<AtomicU64> is Clone, Arc<L4UpstreamHealth> is Clone.
impl Clone for CompiledL4Handler {
    fn clone(&self) -> Self {
        match self {
            Self::Proxy {
                upstreams,
                health,
                lb_policy,
                rr_counter,
                max_fails,
                fail_duration,
                connect_timeout,
            } => Self::Proxy {
                upstreams: upstreams.clone(),
                health: health.clone(),
                lb_policy: *lb_policy,
                rr_counter: Arc::clone(rr_counter),
                max_fails: *max_fails,
                fail_duration: *fail_duration,
                connect_timeout: *connect_timeout,
            },
            Self::Tls { cert_store } => Self::Tls {
                cert_store: cert_store.clone(),
            },
            Self::Subroute {
                routes,
                matching_timeout,
            } => Self::Subroute {
                routes: routes.clone(),
                matching_timeout: *matching_timeout,
            },
        }
    }
}

impl CompiledL4Handler {
    /// Construct a `Proxy` handler with all defaults.
    ///
    /// Callers (compile.rs) should use this rather than constructing the
    /// variant directly so that the health Vec is always correctly sized.
    pub fn new_proxy(
        upstreams: Vec<SocketAddr>,
        lb_policy: L4LoadBalancePolicy,
        max_fails: u32,
        fail_duration: Duration,
        connect_timeout: Duration,
    ) -> Self {
        let health = upstreams
            .iter()
            .map(|&addr| Arc::new(L4UpstreamHealth::new(addr)))
            .collect();
        Self::Proxy {
            upstreams,
            health,
            lb_policy,
            rr_counter: Arc::new(AtomicU64::new(0)),
            max_fails,
            fail_duration,
            connect_timeout,
        }
    }
}

// ── Service ─────────────────────────────────────────────────────────────

/// Shared L4 server config behind `ArcSwap`, used by both `Layer4Service`
/// and `ConfigWatcher` for hot-reload.
pub type SharedL4Servers = Arc<arc_swap::ArcSwap<Vec<CompiledL4Server>>>;

/// Background service that runs Layer 4 TCP listeners with hot-reload support.
///
/// On startup, binds all configured listeners. When notified via `reload_notify`,
/// diffs the new config against running listeners: binds new ports, drops removed
/// ports, and swaps routes on existing ports — no restart needed.
pub struct Layer4Service {
    servers: SharedL4Servers,
    reload_notify: Arc<tokio::sync::Notify>,
}

impl std::fmt::Debug for Layer4Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Layer4Service")
            .field("servers", &self.servers.load().len())
            .field("reload_notify", &"Notify")
            .finish()
    }
}

impl Layer4Service {
    pub fn new(servers: SharedL4Servers, reload_notify: Arc<tokio::sync::Notify>) -> Self {
        Self {
            servers,
            reload_notify,
        }
    }
}

/// State for a single running listener — tracks the cancel token so we can
/// stop it on reload when its listen address is removed.
struct LiveListener {
    cancel: tokio_util::sync::CancellationToken,
    /// The server config driving this listener, swappable for route updates.
    server: Arc<arc_swap::ArcSwap<CompiledL4Server>>,
}

#[async_trait]
impl BackgroundService for Layer4Service {
    async fn start(&self, shutdown: ShutdownWatch) {
        let mut live: std::collections::HashMap<SocketAddr, LiveListener> =
            std::collections::HashMap::new();
        let mut tasks = tokio::task::JoinSet::new();

        // Initial bind
        bind_new_listeners(&self.servers.load(), &mut live, &mut tasks, &shutdown);

        if live.is_empty() {
            info!("layer4 service started — no initial listeners, waiting for reload");
        }

        loop {
            tokio::select! {
                () = self.reload_notify.notified() => {
                    let new_servers = self.servers.load();
                    let new_addrs: std::collections::HashSet<SocketAddr> =
                        new_servers.iter().map(|s| s.listen).collect();

                    // Remove listeners for addresses no longer in config
                    live.retain(|addr, ll| {
                        if new_addrs.contains(addr) {
                            true
                        } else {
                            info!(addr = %addr, "L4 listener removed by reload");
                            ll.cancel.cancel();
                            false
                        }
                    });

                    // Update routes on existing listeners, bind new ones
                    for server in new_servers.iter() {
                        if let Some(ll) = live.get(&server.listen) {
                            // Existing listener — swap routes
                            ll.server.store(Arc::new(server.clone()));
                            debug!(addr = %server.listen, "L4 listener routes updated");
                        }
                        // else: new address — bind below
                    }
                    bind_new_listeners(&new_servers, &mut live, &mut tasks, &shutdown);
                }
                _ = tasks.join_next(), if !tasks.is_empty() => {
                    // A listener task completed (cancelled or errored) — no action needed,
                    // it was already removed from `live` by the reload branch.
                }
                () = shutdown_signal(&shutdown) => {
                    info!("L4 service shutting down");
                    // Cancel all listeners
                    for ll in live.values() {
                        ll.cancel.cancel();
                    }
                    // Drain remaining tasks
                    while tasks.join_next().await.is_some() {}
                    return;
                }
            }
        }
    }
}

/// Bind listeners for addresses not already in `live` and spawn accept loops.
fn bind_new_listeners(
    servers: &[CompiledL4Server],
    live: &mut std::collections::HashMap<SocketAddr, LiveListener>,
    tasks: &mut tokio::task::JoinSet<()>,
    shutdown: &ShutdownWatch,
) {
    for server in servers {
        if live.contains_key(&server.listen) {
            continue;
        }
        let addr = server.listen;
        let cancel = tokio_util::sync::CancellationToken::new();
        let server_swap = Arc::new(arc_swap::ArcSwap::from_pointee(server.clone()));

        let cancel_clone = cancel.clone();
        let server_clone = Arc::clone(&server_swap);
        let shutdown = shutdown.clone();

        tasks.spawn(async move {
            match TcpListener::bind(addr).await {
                Ok(listener) => {
                    info!(addr = %addr, "L4 listener bound");
                    run_listener(listener, server_clone, cancel_clone, shutdown).await;
                }
                Err(e) => {
                    error!(addr = %addr, error = %e, "failed to bind L4 listener");
                }
            }
        });

        live.insert(
            addr,
            LiveListener {
                cancel,
                server: server_swap,
            },
        );
    }
}

async fn run_listener(
    listener: TcpListener,
    server: Arc<arc_swap::ArcSwap<CompiledL4Server>>,
    cancel: tokio_util::sync::CancellationToken,
    shutdown: ShutdownWatch,
) {
    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, peer)) => {
                        let server = Arc::clone(&server.load());
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
            () = cancel.cancelled() => {
                info!("L4 listener cancelled by reload");
                return;
            }
            () = shutdown_signal(&shutdown) => {
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
    stream: TcpStream,
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
    route
        .matchers
        .iter()
        .all(|m| matcher_matches(m, peeked, peer))
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
                    let alpn_ok = alpn.is_empty() || hello.alpn.iter().any(|a| alpn.contains(a));
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

// The handler dispatch is inherently wide: each match arm handles a distinct
// protocol path (proxy, TLS termination, subroute) with its own error paths.
// Splitting it would require threading state across functions without clarity gain.
#[allow(clippy::too_many_lines)]
async fn execute_handlers(
    handlers: &[CompiledL4Handler],
    stream: TcpStream,
    peer: SocketAddr,
    peeked: &[u8],
) -> Result<(), L4Error> {
    // Dispatch the first handler, then delegate the tail recursively.
    // Each arm always returns — the handler either completes the connection
    // or hands off the remainder of the chain (Tls, Subroute).
    let Some((idx, handler)) = handlers.iter().enumerate().next() else {
        return Ok(());
    };
    match handler {
        CompiledL4Handler::Proxy {
            upstreams,
            health,
            lb_policy,
            rr_counter,
            max_fails,
            fail_duration,
            connect_timeout,
        } => {
            if upstreams.is_empty() {
                return Err(L4Error::NoUpstream);
            }

            let upstream_addr = select_upstream(upstreams, health, *lb_policy, rr_counter, peer)
                .ok_or(L4Error::AllUpstreamsUnhealthy)?;

            // Find the health slot for the selected upstream so we can
            // record the outcome after the connect attempt.
            let health_slot = health.iter().find(|h| h.addr == upstream_addr);

            debug!(
                peer = %peer,
                upstream = %upstream_addr,
                policy = ?lb_policy,
                "L4 proxy: connecting to upstream"
            );

            match tokio::time::timeout(*connect_timeout, TcpStream::connect(upstream_addr)).await {
                Err(_) => {
                    // Connect timed out — record passive failure.
                    if let Some(slot) = health_slot
                        && slot.record_failure(*max_fails, *fail_duration)
                    {
                        warn!(
                            upstream = %upstream_addr,
                            max_fails,
                            fail_secs = fail_duration.as_secs(),
                            "L4 upstream quarantined after repeated connect timeouts"
                        );
                    }
                    Err(L4Error::UpstreamTimeout(upstream_addr))
                }
                Ok(Err(e)) => {
                    // Connect refused or I/O error — record passive failure.
                    if let Some(slot) = health_slot
                        && slot.record_failure(*max_fails, *fail_duration)
                    {
                        warn!(
                            upstream = %upstream_addr,
                            max_fails,
                            fail_secs = fail_duration.as_secs(),
                            "L4 upstream quarantined after repeated connect failures"
                        );
                    }
                    Err(L4Error::UpstreamConnect(upstream_addr, e))
                }
                Ok(Ok(upstream)) => {
                    // Successful connect — clear any prior failure streak.
                    if let Some(slot) = health_slot {
                        slot.record_success();
                        slot.active_conns.fetch_add(1, Ordering::Relaxed);
                    }

                    let result = splice(stream, upstream).await;

                    if let Some(slot) = health_slot {
                        // Saturating sub prevents underflow if something is
                        // very wrong and release is called twice.
                        slot.active_conns
                            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                                Some(v.saturating_sub(1))
                            })
                            .ok();
                    }

                    result
                }
            }
        }
        CompiledL4Handler::Tls { cert_store } => {
            let Some(cert_store) = cert_store else {
                warn!(peer = %peer, "L4 TLS handler: no cert store injected — dropping connection");
                return Ok(());
            };

            // Build an acceptor using the cert for the SNI we already parsed
            // from the peeked `ClientHello`. The acceptor is built per-connection
            // because each connection may carry a different SNI. CertStore
            // handles its own LRU caching of the parsed cert+key.
            let sni = parse_tls_client_hello(peeked).and_then(|h| h.sni);

            let acceptor = build_ssl_acceptor(cert_store, sni.as_deref(), peer)?;

            // Drive the TLS handshake asynchronously.
            // The `ClientHello` bytes are still in the kernel socket buffer
            // (we only peeked, never consumed) so openssl reads them naturally.
            // `SslStream::new` + `accept()` is the correct tokio-openssl API —
            // there is no free `tokio_openssl::accept` function.
            let ssl = openssl::ssl::Ssl::new(acceptor.context())
                .map_err(|e| L4Error::TlsConfig(e.to_string()))?;
            let mut tls_stream = tokio_openssl::SslStream::new(ssl, stream)
                .map_err(|e| L4Error::TlsConfig(e.to_string()))?;
            tokio::time::timeout(
                Duration::from_secs(10),
                std::pin::Pin::new(&mut tls_stream).accept(),
            )
            .await
            .map_err(|_| L4Error::TlsHandshakeTimeout)?
            .map_err(|e| L4Error::TlsHandshake(e.to_string()))?;

            debug!(peer = %peer, sni = ?sni, "L4 TLS handshake complete");

            // Delegate the remaining handlers to the decrypted stream path.
            let decrypted: Box<dyn RwStream> = Box::new(tls_stream);
            execute_handlers_on_decrypted(&handlers[idx + 1..], decrypted, peer).await
        }
        CompiledL4Handler::Subroute {
            routes,
            matching_timeout,
        } => {
            // Subroute on a raw TCP stream: the bytes were peeked in
            // handle_connection and are still in the kernel socket buffer
            // (peek does not advance the read position). Re-match against
            // nested routes using those same bytes, then delegate.
            let matched = routes.iter().find(|r| route_matches(r, peeked, peer));
            let Some(route) = matched else {
                debug!(
                    peer = %peer,
                    timeout = ?matching_timeout,
                    "L4 subroute: no sub-route matched"
                );
                return Ok(());
            };
            // Box::pin breaks the infinite future size caused by async recursion.
            Box::pin(execute_handlers(&route.handlers, stream, peer, peeked)).await
        }
    }
}

// ── Load balancing ──────────────────────────────────────────────────────

/// Select an upstream address using the configured policy.
///
/// Returns `None` only when every upstream is currently quarantined —
/// the caller will surface this as `AllUpstreamsUnhealthy`.
///
/// Selection is fully lock-free: we read atomic counters with `Relaxed`
/// ordering. A slightly stale count shifts which upstream gets the
/// connection but doesn't break correctness.
fn select_upstream(
    upstreams: &[SocketAddr],
    health: &[Arc<L4UpstreamHealth>],
    policy: L4LoadBalancePolicy,
    rr_counter: &Arc<AtomicU64>,
    peer: SocketAddr,
) -> Option<SocketAddr> {
    if upstreams.is_empty() {
        return None;
    }
    // Single-backend fast path: avoid any selection overhead.
    if upstreams.len() == 1 {
        return if health[0].is_quarantined() {
            None
        } else {
            Some(upstreams[0])
        };
    }

    match policy {
        L4LoadBalancePolicy::RoundRobin => {
            let n = upstreams.len();
            // Advance the counter regardless of health so that the distribution
            // stays even across the healthy set when some upstreams are out.
            let start = rr_counter.fetch_add(1, Ordering::Relaxed) as usize % n;
            find_available_from(upstreams, health, start)
        }
        L4LoadBalancePolicy::LeastConn => {
            // O(n) scan — backend counts are typically small.
            health
                .iter()
                .zip(upstreams.iter())
                .filter(|(h, _)| !h.is_quarantined())
                .min_by_key(|(h, _)| h.active_conns.load(Ordering::Relaxed))
                .map(|(_, &addr)| addr)
        }
        L4LoadBalancePolicy::Random => {
            // Reservoir sampling: O(1) memory, uniform distribution.
            let mut selected: Option<SocketAddr> = None;
            let mut count = 0usize;
            for (h, &addr) in health.iter().zip(upstreams.iter()) {
                if !h.is_quarantined() {
                    count += 1;
                    if fastrand::usize(..count) == 0 {
                        selected = Some(addr);
                    }
                }
            }
            selected
        }
        L4LoadBalancePolicy::IpHash => {
            // FNV-1a over the client IP bytes → deterministic upstream selection.
            // Falls back to round-robin when the client IP is unavailable (rare
            // for TCP — peer addr is always known — but defensive).
            let hash = fnv_hash_ip(peer.ip());
            let n = upstreams.len();
            let start = hash % n;
            find_available_from(upstreams, health, start)
        }
    }
}

/// Walk upstream list from `start`, wrapping around, until a non-quarantined
/// upstream is found. Returns `None` if all are quarantined.
fn find_available_from(
    upstreams: &[SocketAddr],
    health: &[Arc<L4UpstreamHealth>],
    start: usize,
) -> Option<SocketAddr> {
    let n = upstreams.len();
    for offset in 0..n {
        let idx = (start + offset) % n;
        if !health[idx].is_quarantined() {
            return Some(upstreams[idx]);
        }
    }
    None
}

/// FNV-1a hash over an IP address, returning a `usize` for modular indexing.
///
/// FNV-1a: branchless, no deps, avalanche-free at L4 connection rates.
fn fnv_hash_ip(ip: std::net::IpAddr) -> usize {
    const FNV_OFFSET: u64 = 14_695_981_039_346_656_037;
    const FNV_PRIME: u64 = 1_099_511_628_211;
    let mut hash = FNV_OFFSET;
    let apply = |mut h: u64, bytes: &[u8]| -> u64 {
        for &b in bytes {
            h ^= u64::from(b);
            h = h.wrapping_mul(FNV_PRIME);
        }
        h
    };
    hash = match ip {
        std::net::IpAddr::V4(v4) => apply(hash, &v4.octets()),
        std::net::IpAddr::V6(v6) => apply(hash, &v6.octets()),
    };
    hash as usize
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

/// Minimal TLS `ClientHello` fields we care about for matching.
struct TlsClientHello {
    sni: Option<String>,
    alpn: Vec<String>,
}

/// Parse a TLS `ClientHello` to extract SNI and ALPN.
///
/// Only parses enough to find the extensions we need — doesn't validate
/// the full handshake. Returns None if the bytes don't look like a
/// `ClientHello`.
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
                    let name_len = u16::from_be_bytes([hs[pos + 3], hs[pos + 4]]) as usize;
                    if pos + 5 + name_len <= ext_end
                        && let Ok(name) = std::str::from_utf8(&hs[pos + 5..pos + 5 + name_len])
                    {
                        sni = Some(name.to_lowercase());
                    }
                }
            }
            0x0010 => {
                // ALPN extension
                if ext_len >= 2 {
                    let list_len = u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
                    let mut apos = pos + 2;
                    let aend = (pos + 2 + list_len).min(ext_end);
                    while apos < aend {
                        let proto_len = hs[apos] as usize;
                        apos += 1;
                        if apos + proto_len <= aend
                            && let Ok(proto) = std::str::from_utf8(&hs[apos..apos + proto_len])
                        {
                            alpn.push(proto.to_string());
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
        || data.starts_with(b"TRACE ")
}

/// Extract the Host header value from a peeked HTTP request.
///
/// HTTP header field names are case-insensitive per RFC 7230 §3.2, so we match
/// `host:` without allocating by comparing bytes via `eq_ignore_ascii_case`.
fn extract_http_host(data: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(data).ok()?;
    for line in text.lines().skip(1) {
        if line.is_empty() {
            break;
        }
        let bytes = line.as_bytes();
        if bytes.len() < 5 || !bytes[..5].eq_ignore_ascii_case(b"host:") {
            continue;
        }
        // Value starts after "host:" — trim leading whitespace and optional port.
        let value = line[5..].trim_start();
        return Some(value.split(':').next().unwrap_or(value).trim());
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
    #[error("all upstreams are quarantined — no healthy backend available")]
    AllUpstreamsUnhealthy,
    #[error("upstream {0} connect timed out")]
    UpstreamTimeout(SocketAddr),
    #[error("upstream {0} connect failed: {1}")]
    UpstreamConnect(SocketAddr, std::io::Error),
    #[error("TLS handshake timed out")]
    TlsHandshakeTimeout,
    #[error("TLS handshake failed: {0}")]
    TlsHandshake(String),
    #[error("TLS config error: {0}")]
    TlsConfig(String),
    #[error("no certificate found for SNI {0:?}")]
    TlsNoCert(Option<String>),
    #[error("invalid handler chain: {0}")]
    InvalidHandlerChain(String),
}

// ── TLS termination helpers ─────────────────────────────────────────────

/// Trait alias: a type-erased bidirectional async stream.
///
/// `SslStream<TcpStream>` and `PrefixedStream<_>` both implement this.
/// Using a trait object avoids monomorphising the full handler chain for
/// every stream type — acceptable here because we're on the per-connection
/// path, not a tight inner loop.
trait RwStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> RwStream for T {}

/// A stream wrapper that replays a prefix buffer before forwarding reads.
///
/// Used after a `Subroute` handler reads bytes for protocol detection on a
/// decrypted SSL stream (where `peek()` is unavailable). The prefix is
/// drained first, then reads fall through to the inner stream transparently.
struct PrefixedStream<S> {
    /// Bytes already read from the inner stream, waiting to be replayed.
    prefix: Vec<u8>,
    /// Cursor into `prefix` — bytes before `pos` have been consumed.
    pos: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Drain the prefix first. Doing this in poll_read (not in a separate
        // future) avoids an extra allocation and keeps the wrapper zero-copy
        // for the common case where the prefix is small.
        if self.pos < self.prefix.len() {
            let remaining = &self.prefix[self.pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.pos += to_copy;
            return Poll::Ready(Ok(()));
        }
        // Prefix exhausted — forward to inner stream.
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Execute the handler chain on an already-decrypted TLS stream.
///
/// Called after `Tls` terminates the handshake. At this point the client
/// stream is `SslStream<TcpStream>` wrapped in a trait object. We cannot
/// call `peek()` on it, so `Subroute` does a real `read` into a buffer and
/// wraps the stream in `PrefixedStream` to replay those bytes downstream.
async fn execute_handlers_on_decrypted(
    handlers: &[CompiledL4Handler],
    mut stream: Box<dyn RwStream>,
    peer: SocketAddr,
) -> Result<(), L4Error> {
    // Dispatch the first handler; each arm always returns or delegates the tail.
    let Some(handler) = handlers.first() else {
        return Ok(());
    };
    match handler {
        CompiledL4Handler::Proxy {
            upstreams,
            health,
            lb_policy,
            rr_counter,
            max_fails,
            fail_duration,
            connect_timeout,
        } => {
            if upstreams.is_empty() {
                return Err(L4Error::NoUpstream);
            }
            let upstream_addr = select_upstream(upstreams, health, *lb_policy, rr_counter, peer)
                .ok_or(L4Error::AllUpstreamsUnhealthy)?;

            let health_slot = health.iter().find(|h| h.addr == upstream_addr);

            debug!(
                peer = %peer,
                upstream = %upstream_addr,
                "L4 proxy (post-TLS): connecting to upstream"
            );

            match tokio::time::timeout(*connect_timeout, TcpStream::connect(upstream_addr)).await {
                Err(_) => {
                    if let Some(slot) = health_slot
                        && slot.record_failure(*max_fails, *fail_duration)
                    {
                        warn!(
                            upstream = %upstream_addr,
                            "L4 upstream quarantined after connect timeout (post-TLS)"
                        );
                    }
                    Err(L4Error::UpstreamTimeout(upstream_addr))
                }
                Ok(Err(e)) => {
                    if let Some(slot) = health_slot
                        && slot.record_failure(*max_fails, *fail_duration)
                    {
                        warn!(
                            upstream = %upstream_addr,
                            "L4 upstream quarantined after connect failure (post-TLS)"
                        );
                    }
                    Err(L4Error::UpstreamConnect(upstream_addr, e))
                }
                Ok(Ok(upstream)) => {
                    if let Some(slot) = health_slot {
                        slot.record_success();
                        slot.active_conns.fetch_add(1, Ordering::Relaxed);
                    }
                    let result = copy_bidirectional(stream, upstream).await;
                    if let Some(slot) = health_slot {
                        slot.active_conns
                            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                                Some(v.saturating_sub(1))
                            })
                            .ok();
                    }
                    result
                }
            }
        }

        CompiledL4Handler::Tls { .. } => {
            // Nested TLS after TLS is not a valid config — wrapping an
            // already-decrypted stream in another SSL layer would corrupt
            // the protocol. Fail fast rather than produce undefined behaviour.
            warn!(peer = %peer, "L4: nested Tls handler after TLS — dropping connection");
            Err(L4Error::InvalidHandlerChain(
                "Tls handler cannot follow another Tls handler".into(),
            ))
        }

        CompiledL4Handler::Subroute {
            routes,
            matching_timeout,
        } => {
            // We cannot peek on an SslStream, so we do a real read into a
            // prefix buffer for protocol detection, then replay those bytes
            // via PrefixedStream so the downstream handler sees a complete
            // stream including what we already consumed.
            let mut prefix = vec![0u8; MAX_PEEK_BYTES];
            let n = tokio::time::timeout(*matching_timeout, stream.read(&mut prefix))
                .await
                .map_err(|_| L4Error::MatchingTimeout)?
                .map_err(L4Error::Io)?;
            prefix.truncate(n);

            let matched = routes.iter().find(|r| route_matches(r, &prefix, peer));
            let Some(route) = matched else {
                debug!(peer = %peer, "L4 post-TLS subroute: no sub-route matched");
                return Ok(());
            };

            let prefixed: Box<dyn RwStream> = Box::new(PrefixedStream::new(prefix, stream));

            // Box::pin breaks the infinite future size caused by async recursion.
            Box::pin(execute_handlers_on_decrypted(
                &route.handlers,
                prefixed,
                peer,
            ))
            .await
        }
    }
}

/// Build an `SslAcceptor` for a single TLS handshake.
///
/// We build one per connection, not one per config, because `SslAcceptor`
/// is not cheaply cloneable and cert rotation would require rebuilding it
/// anyway. The `CertStore` handles LRU caching of parsed cert+key, so the
/// only cost here is `SslAcceptor` construction (~microseconds vs handshake
/// latency at ~milliseconds).
fn build_ssl_acceptor(
    cert_store: &Arc<CertStore>,
    sni: Option<&str>,
    peer: SocketAddr,
) -> Result<SslAcceptor, L4Error> {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())
        .map_err(|e| L4Error::TlsConfig(e.to_string()))?;

    // No client cert verification at L4 — mTLS is the HTTP layer's concern.
    builder.set_verify(SslVerifyMode::NONE);

    let cached = sni.and_then(|name| cert_store.get(name)).ok_or_else(|| {
        warn!(peer = %peer, sni = ?sni, "L4 TLS: no cert for SNI — dropping");
        L4Error::TlsNoCert(sni.map(str::to_owned))
    })?;

    builder
        .set_certificate(&cached.cert)
        .map_err(|e| L4Error::TlsConfig(e.to_string()))?;
    builder
        .set_private_key(&cached.key)
        .map_err(|e| L4Error::TlsConfig(e.to_string()))?;
    // Verify key matches cert — gives a clean error before the handshake
    // rather than a cryptic SSL alert mid-connection.
    builder
        .check_private_key()
        .map_err(|e| L4Error::TlsConfig(format!("cert/key mismatch: {e}")))?;

    Ok(builder.build())
}

/// Bidirectional copy between a decrypted client stream and a raw upstream.
///
/// Mirrors `splice` but works on `Box<dyn RwStream>` (post-TLS) instead of
/// two `TcpStream`s.
async fn copy_bidirectional(client: Box<dyn RwStream>, upstream: TcpStream) -> Result<(), L4Error> {
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
        debug!(error = %e, "L4 client→upstream copy error (post-TLS)");
    }
    if let Err(e) = u2c_result {
        debug!(error = %e, "L4 upstream→client copy error (post-TLS)");
    }
    Ok(())
}

// ── Compilation helpers (no config model dependency) ────────────────────

/// Parse a listen address like `:8443`, `127.0.0.1:5000`, or `0.0.0.0:443`.
#[allow(dead_code)] // used in tests and compile.rs (not yet wired)
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
#[allow(dead_code)] // used in tests and compile.rs (not yet wired)
fn parse_duration(s: &str) -> Option<Duration> {
    if let Some(rest) = s.strip_suffix("ms") {
        rest.parse().ok().map(Duration::from_millis)
    } else if let Some(rest) = s.strip_suffix('s') {
        rest.parse().ok().map(Duration::from_secs)
    } else if let Some(rest) = s.strip_suffix('m') {
        rest.parse::<u64>()
            .ok()
            .map(|m| Duration::from_secs(m * 60))
    } else {
        s.parse().ok().map(Duration::from_secs)
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)] // unwrap() is idiomatic in test code
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
        assert!(looks_like_http(b"TRACE / HTTP/1.1\r\n"));
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
        msg[4..8].copy_from_slice(&196_608_u32.to_be_bytes()); // version 3.0
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
    fn extract_http_host_is_case_insensitive() {
        // RFC 7230 §3.2: header field names are case-insensitive.
        let upper = b"GET / HTTP/1.1\r\nHOST: example.com\r\n\r\n";
        assert_eq!(extract_http_host(upper), Some("example.com"));

        let mixed = b"GET / HTTP/1.1\r\nhOsT: example.com\r\n\r\n";
        assert_eq!(extract_http_host(mixed), Some("example.com"));

        let lower = b"GET / HTTP/1.1\r\nhost: example.com\r\n\r\n";
        assert_eq!(extract_http_host(lower), Some("example.com"));

        let titled = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(extract_http_host(titled), Some("example.com"));

        // With port, mixed case.
        let mixed_port = b"GET / HTTP/1.1\r\nHOST: example.com:8443\r\n\r\n";
        assert_eq!(extract_http_host(mixed_port), Some("example.com"));
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

    // -- Load balancing --

    fn make_proxy_handler(ports: &[u16], policy: L4LoadBalancePolicy) -> CompiledL4Handler {
        let upstreams: Vec<SocketAddr> = ports
            .iter()
            .map(|&p| format!("127.0.0.1:{p}").parse().unwrap())
            .collect();
        CompiledL4Handler::new_proxy(
            upstreams,
            policy,
            3,
            Duration::from_secs(10),
            Duration::from_secs(10),
        )
    }

    fn peer(port: u16) -> SocketAddr {
        format!("1.2.3.4:{port}").parse().unwrap()
    }

    #[test]
    fn round_robin_distributes_evenly() {
        let handler = make_proxy_handler(&[8080, 8081, 8082], L4LoadBalancePolicy::RoundRobin);
        let CompiledL4Handler::Proxy {
            upstreams,
            health,
            lb_policy,
            ref rr_counter,
            ..
        } = handler
        else {
            panic!("expected Proxy");
        };
        let mut counts = [0usize; 3];
        let ports = [8080u16, 8081, 8082];
        for _ in 0..30 {
            let sel = select_upstream(&upstreams, &health, lb_policy, rr_counter, peer(9000))
                .expect("should select");
            if let Some(idx) = ports.iter().position(|&p| sel.port() == p) {
                counts[idx] += 1;
            }
        }
        assert_eq!(counts, [10, 10, 10], "round-robin must distribute evenly");
    }

    #[test]
    fn round_robin_skips_quarantined() {
        let handler = make_proxy_handler(&[8080, 8081, 8082], L4LoadBalancePolicy::RoundRobin);
        let CompiledL4Handler::Proxy {
            upstreams,
            health,
            lb_policy,
            ref rr_counter,
            ..
        } = handler
        else {
            panic!("expected Proxy");
        };
        // Force 8081 (index 1) into quarantine.
        health[1].record_failure(1, Duration::from_secs(60));
        for _ in 0..20 {
            let sel = select_upstream(&upstreams, &health, lb_policy, rr_counter, peer(9000))
                .expect("should select a healthy upstream");
            assert_ne!(
                sel.port(),
                8081,
                "quarantined upstream must not be selected"
            );
        }
    }

    #[test]
    fn least_conn_picks_fewest_active() {
        let handler = make_proxy_handler(&[8080, 8081, 8082], L4LoadBalancePolicy::LeastConn);
        let CompiledL4Handler::Proxy {
            upstreams,
            health,
            lb_policy,
            ref rr_counter,
            ..
        } = handler
        else {
            panic!("expected Proxy");
        };
        // Simulate load: 8080 has 5, 8081 has 3, 8082 has 0.
        health[0].active_conns.store(5, Ordering::Relaxed);
        health[1].active_conns.store(3, Ordering::Relaxed);
        let sel = select_upstream(&upstreams, &health, lb_policy, rr_counter, peer(9000))
            .expect("should select");
        assert_eq!(sel.port(), 8082, "least-conn should pick 8082 (0 active)");
    }

    #[test]
    fn least_conn_skips_quarantined() {
        let handler = make_proxy_handler(&[8080, 8081], L4LoadBalancePolicy::LeastConn);
        let CompiledL4Handler::Proxy {
            upstreams,
            health,
            lb_policy,
            ref rr_counter,
            ..
        } = handler
        else {
            panic!("expected Proxy");
        };
        // 8080 has 0 conns but is quarantined.
        health[0].record_failure(1, Duration::from_secs(60));
        let sel = select_upstream(&upstreams, &health, lb_policy, rr_counter, peer(9000))
            .expect("should select");
        assert_eq!(sel.port(), 8081);
    }

    #[test]
    fn random_selects_only_from_configured_backends() {
        let handler = make_proxy_handler(&[8080, 8081, 8082], L4LoadBalancePolicy::Random);
        let CompiledL4Handler::Proxy {
            upstreams,
            health,
            lb_policy,
            ref rr_counter,
            ..
        } = handler
        else {
            panic!("expected Proxy");
        };
        let valid_ports = [8080u16, 8081, 8082];
        for _ in 0..50 {
            let sel = select_upstream(&upstreams, &health, lb_policy, rr_counter, peer(9000))
                .expect("should always select one");
            assert!(
                valid_ports.contains(&sel.port()),
                "random must pick a configured backend"
            );
        }
    }

    #[test]
    fn random_skips_quarantined() {
        let handler = make_proxy_handler(&[8080, 8081], L4LoadBalancePolicy::Random);
        let CompiledL4Handler::Proxy {
            upstreams,
            health,
            lb_policy,
            ref rr_counter,
            ..
        } = handler
        else {
            panic!("expected Proxy");
        };
        health[0].record_failure(1, Duration::from_secs(60));
        for _ in 0..30 {
            let sel = select_upstream(&upstreams, &health, lb_policy, rr_counter, peer(9000))
                .expect("should select");
            assert_eq!(sel.port(), 8081);
        }
    }

    #[test]
    fn ip_hash_is_deterministic_for_same_client_ip() {
        let handler = make_proxy_handler(&[8080, 8081, 8082], L4LoadBalancePolicy::IpHash);
        let CompiledL4Handler::Proxy {
            upstreams,
            health,
            lb_policy,
            ref rr_counter,
            ..
        } = handler
        else {
            panic!("expected Proxy");
        };
        // Same source IP → same upstream every time.
        let client = peer(54321);
        let first = select_upstream(&upstreams, &health, lb_policy, rr_counter, client)
            .expect("should select");
        for _ in 0..20 {
            let sel = select_upstream(&upstreams, &health, lb_policy, rr_counter, client)
                .expect("should select");
            assert_eq!(sel, first, "ip_hash must be deterministic");
        }
    }

    #[test]
    fn ip_hash_different_ips_can_land_on_different_upstreams() {
        let handler = make_proxy_handler(&[8080, 8081, 8082], L4LoadBalancePolicy::IpHash);
        let CompiledL4Handler::Proxy {
            upstreams,
            health,
            lb_policy,
            ref rr_counter,
            ..
        } = handler
        else {
            panic!("expected Proxy");
        };
        let mut seen_ports = std::collections::HashSet::new();
        // Different client IPs → different FNV hash values → expect multiple upstreams hit.
        // We use addresses with varying octets so the hash produces different mod-3 results.
        let clients: &[SocketAddr] = &[
            "1.2.3.4:9000".parse().unwrap(),
            "10.0.0.1:9000".parse().unwrap(),
            "172.16.0.5:9000".parse().unwrap(),
            "192.168.1.100:9000".parse().unwrap(),
            "8.8.8.8:9000".parse().unwrap(),
            "1.1.1.1:9000".parse().unwrap(),
            "100.64.0.1:9000".parse().unwrap(),
            "203.0.113.42:9000".parse().unwrap(),
        ];
        for &client in clients {
            if let Some(sel) = select_upstream(&upstreams, &health, lb_policy, rr_counter, client) {
                seen_ports.insert(sel.port());
            }
        }
        assert!(
            seen_ports.len() > 1,
            "ip_hash should spread different client IPs across upstreams"
        );
    }

    #[test]
    fn all_quarantined_returns_none() {
        let handler = make_proxy_handler(&[8080, 8081], L4LoadBalancePolicy::RoundRobin);
        let CompiledL4Handler::Proxy {
            upstreams,
            health,
            lb_policy,
            ref rr_counter,
            ..
        } = handler
        else {
            panic!("expected Proxy");
        };
        health[0].record_failure(1, Duration::from_secs(60));
        health[1].record_failure(1, Duration::from_secs(60));
        assert!(
            select_upstream(&upstreams, &health, lb_policy, rr_counter, peer(9000)).is_none(),
            "all upstreams quarantined must return None"
        );
    }

    // -- Passive health tracking --

    #[test]
    fn record_failure_quarantines_after_max_fails() {
        let slot = L4UpstreamHealth::new("127.0.0.1:8080".parse().unwrap());
        assert!(!slot.is_quarantined());
        // Two failures below max_fails=3 should not quarantine.
        assert!(!slot.record_failure(3, Duration::from_secs(30)));
        assert!(!slot.is_quarantined());
        assert!(!slot.record_failure(3, Duration::from_secs(30)));
        assert!(!slot.is_quarantined());
        // Third failure hits max_fails → quarantine.
        assert!(slot.record_failure(3, Duration::from_secs(30)));
        assert!(slot.is_quarantined());
    }

    #[test]
    fn record_success_clears_quarantine() {
        let slot = L4UpstreamHealth::new("127.0.0.1:8080".parse().unwrap());
        slot.record_failure(1, Duration::from_secs(30));
        assert!(slot.is_quarantined());
        slot.record_success();
        assert!(!slot.is_quarantined());
        assert_eq!(slot.consecutive_fails.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn quarantine_expires_after_fail_duration() {
        let slot = L4UpstreamHealth::new("127.0.0.1:8080".parse().unwrap());
        // Set retry_after to 1 second ago — quarantine should have expired.
        let past = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            .saturating_sub(1);
        slot.retry_after_secs.store(past, Ordering::Relaxed);
        assert!(
            !slot.is_quarantined(),
            "quarantine must expire after fail_duration"
        );
    }

    // -- Subroute integration test --

    /// Verifies the raw-TCP subroute handler end-to-end.
    ///
    /// Two nested routes inside a subroute:
    ///   1. `Http { host: ["api.example.com"] }` → proxy to upstream A (echo)
    ///   2. catch-all                             → proxy to upstream B (sends "WRONG")
    ///
    /// Sending `Host: api.example.com` must land on upstream A, and upstream A
    /// must receive the full original request (peek bytes stay in kernel buffer).
    #[tokio::test]
    async fn subroute_matches_http_host_and_proxies_full_request() {
        // Upstream A: echoes every byte it receives, then closes.
        let upstream_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = upstream_a.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = upstream_a.accept().await.unwrap();
            let mut buf = Vec::new();
            sock.read_to_end(&mut buf).await.unwrap();
            sock.write_all(&buf).await.unwrap();
            sock.shutdown().await.unwrap();
        });

        // Upstream B: must NOT be reached by this test.
        let upstream_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let wrong_addr = upstream_b.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = upstream_b.accept().await {
                let _ = sock.write_all(b"WRONG\r\n").await;
            }
        });

        let handlers = vec![CompiledL4Handler::Subroute {
            routes: vec![
                CompiledL4Route {
                    matchers: vec![CompiledL4Matcher::Http {
                        host: vec!["api.example.com".to_string()],
                    }],
                    handlers: vec![CompiledL4Handler::new_proxy(
                        vec![echo_addr],
                        L4LoadBalancePolicy::RoundRobin,
                        3,
                        Duration::from_secs(10),
                        Duration::from_secs(5),
                    )],
                },
                CompiledL4Route {
                    matchers: vec![],
                    handlers: vec![CompiledL4Handler::new_proxy(
                        vec![wrong_addr],
                        L4LoadBalancePolicy::RoundRobin,
                        3,
                        Duration::from_secs(10),
                        Duration::from_secs(5),
                    )],
                },
            ],
            matching_timeout: Duration::from_secs(1),
        }];

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, peer) = proxy.accept().await.unwrap();
            // Peek so bytes remain in kernel buffer for the handler chain.
            let mut peek_buf = BytesMut::zeroed(MAX_PEEK_BYTES);
            let n = conn.peek(&mut peek_buf).await.unwrap();
            let peeked = &peek_buf[..n];
            if let Err(e) = execute_handlers(&handlers, conn, peer, peeked).await {
                tracing::error!("handler error in test: {e}");
            }
        });

        let request =
            b"GET /v1/items HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 0\r\n\r\n";
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(request).await.unwrap();
        client.shutdown().await.unwrap();

        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut response))
            .await
            .expect("timed out waiting for subroute echo response")
            .unwrap();

        assert!(
            response.starts_with(b"GET /v1/items HTTP/1.1"),
            "upstream A should echo full request; got: {:?}",
            std::str::from_utf8(&response).unwrap_or("<binary>"),
        );
        assert!(
            response
                .windows(b"api.example.com".len())
                .any(|w| w == b"api.example.com"),
            "Host header must appear in echoed bytes",
        );
        assert_ne!(
            &response[..6.min(response.len())],
            b"WRONG\r",
            "must not route to upstream B"
        );
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

    // -- PrefixedStream unit test --

    #[tokio::test]
    async fn prefixed_stream_replays_prefix_then_forwards() {
        // The prefix bytes should be emitted first, then the inner stream.
        // This verifies that subroute protocol re-detection sees the full
        // decrypted payload even after the first `read` consumed some bytes.
        let inner = tokio::io::BufReader::new(std::io::Cursor::new(b"world"));
        let mut ps = PrefixedStream::new(b"hello ".to_vec(), inner);

        let mut buf = Vec::new();
        ps.read_to_end(&mut buf).await.expect("read_to_end");
        assert_eq!(buf, b"hello world");
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
