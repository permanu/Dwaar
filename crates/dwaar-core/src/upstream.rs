// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Runtime upstream pool — load balancing, connection limiting, health tracking.
//!
//! `UpstreamPool` holds a fixed slice of backends compiled from config. All
//! selection logic is lock-free: atomics for counters and health flags so that
//! every request can pick an upstream without touching a mutex.
//!
//! ## Design rationale (Four Pillars)
//!
//! | Pillar | Decision |
//! |---|---|
//! | Performance | `AtomicU64`/`AtomicBool`/`AtomicU32` — no mutex on hot path |
//! | Reliability | All-unhealthy returns `None`; caller generates 502 |
//! | Security | `max_conns` enforced atomically before accepting new work |
//! | Competitive Parity | Round-robin, least-conn, random, ip-hash match nginx/Caddy |

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use pingora_core::OrErr;
use pingora_core::services::background::BackgroundService;
use tracing::{debug, warn};

use crate::wake::ScaleToZeroConfig;

/// Which algorithm the pool uses to pick a backend on each request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LbPolicy {
    RoundRobin,
    LeastConn,
    Random,
    IpHash,
}

/// A pool of upstream backends with load balancing and health tracking.
///
/// Created once at config compile time and placed behind an `Arc` so the proxy
/// and health-checker share the same atomic state.
#[derive(Debug)]
pub struct UpstreamPool {
    pub(crate) backends: Vec<Backend>,
    policy: LbPolicy,
    /// Monotonically increasing counter — wrapped on overflow (2^64 >> backend count).
    counter: AtomicU64,
    /// HTTP path polled by the health checker. `None` disables health checking.
    pub(crate) health_uri: Option<String>,
    /// Seconds between health polls.
    pub(crate) health_interval: Duration,
    /// Scale-to-zero config (ISSUE-082). When set, the proxy will attempt to wake
    /// a sleeping backend on upstream connection failure instead of returning 502.
    pub(crate) scale_to_zero: Option<Arc<ScaleToZeroConfig>>,
}

/// One backend server inside the pool.
#[derive(Debug)]
pub(crate) struct Backend {
    pub(crate) addr: SocketAddr,
    /// `true` when the backend is considered reachable.
    pub(crate) healthy: AtomicBool,
    /// Number of connections currently in-flight to this backend.
    pub(crate) active_conns: AtomicU32,
    /// Connection cap. `None` = unlimited.
    pub(crate) max_conns: Option<u32>,
    /// Connect over TLS to this specific backend.
    pub(crate) tls: bool,
    /// SNI hostname for TLS. Empty string = use `addr.ip()` as SNI.
    pub(crate) tls_server_name: String,
    /// Client cert+key for mTLS handshake with this backend (ISSUE-077).
    pub(crate) client_cert_key: Option<Arc<pingora_core::utils::tls::CertKey>>,
    /// Custom CA certs for verifying this backend's server cert (ISSUE-077).
    pub(crate) trusted_ca: Option<Arc<pingora_core::protocols::tls::CaType>>,
}

/// The result of a successful backend selection.
#[derive(Debug, Clone)]
pub struct SelectedUpstream {
    pub addr: SocketAddr,
    pub tls: bool,
    pub sni: String,
    /// Client cert+key for mTLS (ISSUE-077). `None` for plain TLS.
    pub client_cert_key: Option<Arc<pingora_core::utils::tls::CertKey>>,
    /// Custom CA for upstream server cert verification (ISSUE-077).
    pub trusted_ca: Option<Arc<pingora_core::protocols::tls::CaType>>,
}

impl UpstreamPool {
    /// Build a pool from already-resolved backend descriptors.
    ///
    /// `health_uri` enables periodic HTTP health polling; `None` disables it.
    /// `health_interval` defaults to 10 s when `None` is passed.
    pub fn new(
        backends: Vec<BackendConfig>,
        policy: LbPolicy,
        health_uri: Option<String>,
        health_interval: Option<u64>,
    ) -> Self {
        let compiled = backends
            .into_iter()
            .map(|b| Backend {
                addr: b.addr,
                healthy: AtomicBool::new(true),
                active_conns: AtomicU32::new(0),
                max_conns: b.max_conns,
                tls: b.tls,
                tls_server_name: b.tls_server_name,
                client_cert_key: b.client_cert_key,
                trusted_ca: b.trusted_ca,
            })
            .collect();

        Self {
            backends: compiled,
            policy,
            counter: AtomicU64::new(0),
            health_uri,
            health_interval: Duration::from_secs(health_interval.unwrap_or(10)),
            scale_to_zero: None,
        }
    }

    /// Build a pool with scale-to-zero support (ISSUE-082).
    ///
    /// Same as `new()` but attaches a `ScaleToZeroConfig` that enables
    /// wake-on-first-request when the upstream is unreachable.
    pub fn new_with_scale_to_zero(
        backends: Vec<BackendConfig>,
        policy: LbPolicy,
        health_uri: Option<String>,
        health_interval: Option<u64>,
        scale_to_zero: ScaleToZeroConfig,
    ) -> Self {
        let mut pool = Self::new(backends, policy, health_uri, health_interval);
        pool.scale_to_zero = Some(Arc::new(scale_to_zero));
        pool
    }

    /// Returns the scale-to-zero config, if configured for this pool.
    pub fn scale_to_zero(&self) -> Option<&Arc<ScaleToZeroConfig>> {
        self.scale_to_zero.as_ref()
    }

    /// Returns `true` if this pool has a health check URI configured.
    ///
    /// Used by `dwaar-config` to decide which pools need a background health prober.
    pub fn has_health_check(&self) -> bool {
        self.health_uri.is_some()
    }

    /// Pick an upstream backend for the current request.
    ///
    /// Returns `None` only when every backend is either unhealthy or at its
    /// connection limit — the caller should respond with 502.
    ///
    /// # Single-backend fast path
    ///
    /// When the pool has exactly one backend we skip the atomic counter increment
    /// and the Vec scan entirely. This is the common case for most Dwaarfiles.
    pub fn select(&self, client_ip: Option<std::net::IpAddr>) -> Option<SelectedUpstream> {
        if self.backends.is_empty() {
            return None;
        }
        if self.backends.len() == 1 {
            return self.select_single();
        }

        match self.policy {
            LbPolicy::RoundRobin => self.select_round_robin(),
            LbPolicy::LeastConn => self.select_least_conn(),
            LbPolicy::Random => self.select_random(),
            LbPolicy::IpHash => self.select_ip_hash(client_ip),
        }
    }

    /// Fast path: single-backend pool — no selection overhead at all.
    ///
    /// This is a pure read: it does not increment `active_conns`. The caller is
    /// responsible for calling `acquire_connection()` (which does the atomic CAS
    /// increment) and `release_connection()` to bracket the request lifetime.
    fn select_single(&self) -> Option<SelectedUpstream> {
        let b = &self.backends[0];
        if !b.healthy.load(Ordering::Relaxed) {
            return None;
        }
        if let Some(max) = b.max_conns
            && b.active_conns.load(Ordering::Acquire) >= max
        {
            return None;
        }
        Some(SelectedUpstream {
            addr: b.addr,
            tls: b.tls,
            sni: b.tls_server_name.clone(),
            client_cert_key: b.client_cert_key.clone(),
            trusted_ca: b.trusted_ca.clone(),
        })
    }

    /// Round-robin: atomically advance the global counter and mod by healthy count.
    ///
    /// We iterate from the selected index, wrapping around, until we find a
    /// backend that is both healthy and under its connection cap. This handles
    /// the case where the initially-selected backend is temporarily unavailable
    /// without changing the distribution for the common all-healthy case.
    fn select_round_robin(&self) -> Option<SelectedUpstream> {
        let n = self.backends.len();
        let start = self.counter.fetch_add(1, Ordering::Relaxed) as usize % n;
        self.find_available_from(start)
    }

    /// Least-conn: iterate and pick the backend with the lowest active-conn count.
    ///
    /// We scan once (O(n)) — acceptable because backend counts are typically small
    /// (< 32) and the scan is cache-hot. Relaxed loads are fine: a slightly stale
    /// count won't cause correctness issues, only minor suboptimality.
    ///
    /// This is a pure read: it does not increment `active_conns`. The caller is
    /// responsible for calling `acquire_connection()` / `release_connection()`.
    fn select_least_conn(&self) -> Option<SelectedUpstream> {
        let best = self
            .backends
            .iter()
            .filter(|b| {
                b.healthy.load(Ordering::Relaxed)
                    && b.max_conns
                        .is_none_or(|max| b.active_conns.load(Ordering::Relaxed) < max)
            })
            .min_by_key(|b| b.active_conns.load(Ordering::Relaxed))?;

        Some(SelectedUpstream {
            addr: best.addr,
            tls: best.tls,
            sni: best.tls_server_name.clone(),
            client_cert_key: best.client_cert_key.clone(),
            trusted_ca: best.trusted_ca.clone(),
        })
    }

    /// Random: choose a uniformly random healthy backend.
    ///
    /// This is a pure read: it does not increment `active_conns`. The caller is
    /// responsible for calling `acquire_connection()` / `release_connection()`.
    fn select_random(&self) -> Option<SelectedUpstream> {
        let available: Vec<_> = self
            .backends
            .iter()
            .filter(|b| {
                b.healthy.load(Ordering::Relaxed)
                    && b.max_conns
                        .is_none_or(|max| b.active_conns.load(Ordering::Relaxed) < max)
            })
            .collect();

        if available.is_empty() {
            return None;
        }

        let b = available[fastrand::usize(..available.len())];
        Some(SelectedUpstream {
            addr: b.addr,
            tls: b.tls,
            sni: b.tls_server_name.clone(),
            client_cert_key: b.client_cert_key.clone(),
            trusted_ca: b.trusted_ca.clone(),
        })
    }

    /// IP-hash: hash the client IP and pick a backend deterministically.
    ///
    /// Falls back to round-robin when no client IP is available.
    fn select_ip_hash(&self, client_ip: Option<std::net::IpAddr>) -> Option<SelectedUpstream> {
        let Some(ip) = client_ip else {
            return self.select_round_robin();
        };

        // FNV-1a over the raw IP bytes — cheap and distribution is good enough for LB
        let hash = fnv_hash_ip(ip);
        let n = self.backends.len();
        let start = hash % n;
        self.find_available_from(start)
    }

    /// Starting from `start`, scan the pool in order until an available backend is found.
    ///
    /// This is a pure read: it does not increment `active_conns`. The caller is
    /// responsible for calling `acquire_connection()` / `release_connection()`.
    fn find_available_from(&self, start: usize) -> Option<SelectedUpstream> {
        let n = self.backends.len();
        for offset in 0..n {
            let b = &self.backends[(start + offset) % n];
            if !b.healthy.load(Ordering::Relaxed) {
                continue;
            }
            if let Some(max) = b.max_conns
                && b.active_conns.load(Ordering::Acquire) >= max
            {
                continue;
            }
            return Some(SelectedUpstream {
                addr: b.addr,
                tls: b.tls,
                sni: b.tls_server_name.clone(),
                client_cert_key: b.client_cert_key.clone(),
                trusted_ca: b.trusted_ca.clone(),
            });
        }
        None
    }

    /// Mark a backend as healthy (called by `HealthChecker` after a successful probe).
    pub fn mark_healthy(&self, addr: SocketAddr) {
        for b in &self.backends {
            if b.addr == addr {
                let was_unhealthy = !b.healthy.swap(true, Ordering::Relaxed);
                if was_unhealthy {
                    debug!(%addr, "backend marked healthy");
                }
                return;
            }
        }
    }

    /// Mark a backend as unhealthy (called by `HealthChecker` after a failed probe,
    /// or by `upstream_peer()` when a connection is refused).
    pub fn mark_unhealthy(&self, addr: SocketAddr) {
        for b in &self.backends {
            if b.addr == addr {
                let was_healthy = b.healthy.swap(false, Ordering::Relaxed);
                if was_healthy {
                    warn!(%addr, "backend marked unhealthy");
                }
                return;
            }
        }
    }

    /// Increment the active-connection counter for a backend.
    ///
    /// Returns `false` if the backend is at `max_conns` and the increment was
    /// rejected — the caller should try another backend or return 502.
    pub fn acquire_connection(&self, addr: SocketAddr) -> bool {
        for b in &self.backends {
            if b.addr == addr {
                if let Some(max) = b.max_conns {
                    // Compare-and-swap loop to atomically check + increment
                    let mut current = b.active_conns.load(Ordering::Relaxed);
                    loop {
                        if current >= max {
                            return false;
                        }
                        match b.active_conns.compare_exchange_weak(
                            current,
                            current + 1,
                            Ordering::AcqRel,
                            Ordering::Relaxed,
                        ) {
                            Ok(_) => return true,
                            Err(actual) => current = actual,
                        }
                    }
                } else {
                    b.active_conns.fetch_add(1, Ordering::Relaxed);
                    return true;
                }
            }
        }
        // Unknown addr — don't block it
        true
    }

    /// Decrement the active-connection counter when a request completes.
    pub fn release_connection(&self, addr: SocketAddr) {
        for b in &self.backends {
            if b.addr == addr {
                // Saturating sub prevents underflow if release is called without acquire
                b.active_conns
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                        Some(v.saturating_sub(1))
                    })
                    .ok();
                return;
            }
        }
    }

    /// The address of the first backend — used for the `default_upstream` inline
    /// cache on `Route`, so the common single-upstream path stays zero-overhead.
    pub fn first_addr(&self) -> Option<SocketAddr> {
        self.backends.first().map(|b| b.addr)
    }

    /// Number of configured backends.
    pub fn len(&self) -> usize {
        self.backends.len()
    }

    /// Returns `true` if the pool has no backends.
    pub fn is_empty(&self) -> bool {
        self.backends.is_empty()
    }
}

/// Configuration for one backend, passed to `UpstreamPool::new`.
#[derive(Debug)]
pub struct BackendConfig {
    pub addr: SocketAddr,
    pub max_conns: Option<u32>,
    pub tls: bool,
    pub tls_server_name: String,
    /// Pre-loaded client cert+key for mTLS (ISSUE-077). Compiled at config time.
    pub client_cert_key: Option<Arc<pingora_core::utils::tls::CertKey>>,
    /// Pre-loaded CA certs for upstream server verification (ISSUE-077).
    pub trusted_ca: Option<Arc<pingora_core::protocols::tls::CaType>>,
}

// ── FNV-1a IP hash ────────────────────────────────────────────────────────────

/// FNV-1a hash of an IP address, returning a `usize` for indexing.
///
/// FNV-1a is chosen because it's branchless, avalanche-free at low latency,
/// and has no dependencies. Distribution across backends is uniform in practice.
fn fnv_hash_ip(ip: std::net::IpAddr) -> usize {
    const FNV_OFFSET: u64 = 14_695_981_039_346_656_037;
    const FNV_PRIME: u64 = 1_099_511_628_211;

    // octets() returns a stack-allocated fixed array, so this is zero-allocation.
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

// ── HealthChecker ─────────────────────────────────────────────────────────────

/// Background service that periodically probes backends and updates their health.
///
/// Uses Pingora's `BackgroundService` so it runs inside Pingora's own tokio
/// runtime — no `tokio::spawn` needed before `run_forever()`.
///
/// Per Guardrail #20: all async background work must be a `BackgroundService`,
/// never a raw `tokio::spawn`.
pub struct HealthChecker {
    /// Pools are moved in via `Mutex<Option<…>>` so `start()` can take ownership
    /// from `&self` — Pingora calls `start()` exactly once.
    pools: std::sync::Mutex<Option<Vec<Arc<UpstreamPool>>>>,
}

impl std::fmt::Debug for HealthChecker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HealthChecker").finish_non_exhaustive()
    }
}

impl HealthChecker {
    /// Create a new checker with the given pools.
    pub fn new(pools: Vec<Arc<UpstreamPool>>) -> Self {
        Self {
            pools: std::sync::Mutex::new(Some(pools)),
        }
    }
}

#[async_trait]
impl BackgroundService for HealthChecker {
    async fn start(&self, mut shutdown: pingora_core::server::ShutdownWatch) {
        // Take ownership of pools from the Mutex — this runs exactly once.
        let pools = self
            .pools
            .lock()
            .expect("HealthChecker lock not poisoned")
            .take()
            .unwrap_or_default();

        // Filter to pools that have a health URI configured.
        let active: Vec<Arc<UpstreamPool>> = pools
            .into_iter()
            .filter(|p| p.health_uri.is_some())
            .collect();

        if active.is_empty() {
            debug!("health checker: no pools with health_uri configured, exiting");
            return;
        }

        // Derive a common poll interval — use the smallest interval across all pools.
        let interval = active
            .iter()
            .map(|p| p.health_interval)
            .min()
            .unwrap_or(Duration::from_secs(10));

        loop {
            // Probe all backends across all pools.
            for pool in &active {
                let Some(ref uri) = pool.health_uri else {
                    continue;
                };
                for backend in &pool.backends {
                    let addr = backend.addr;
                    let probe_uri = uri.clone();
                    match probe_backend(addr, &probe_uri).await {
                        Ok(status) if (200..300).contains(&status) => {
                            pool.mark_healthy(addr);
                        }
                        Ok(status) => {
                            warn!(%addr, status, "health probe returned non-2xx, marking unhealthy");
                            pool.mark_unhealthy(addr);
                        }
                        Err(e) => {
                            warn!(%addr, error = %e, "health probe failed, marking unhealthy");
                            pool.mark_unhealthy(addr);
                        }
                    }
                }
            }

            // Wait for `interval` or shutdown signal.
            tokio::select! {
                () = tokio::time::sleep(interval) => {}
                _ = shutdown.changed() => {
                    debug!("health checker: shutdown signal received");
                    return;
                }
            }
        }
    }
}

/// Send an HTTP GET to `addr/<uri>` and return the response status code.
///
/// Uses a plain tokio TCP connection and hand-crafted minimal HTTP/1.1 request
/// so we avoid pulling in `reqwest` (forbidden by Guardrail dependency policy).
/// This is health-check code, not hot-path — a small allocation here is fine.
async fn probe_backend(
    addr: SocketAddr,
    uri: &str,
) -> Result<u16, Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    // 5-second connect + read budget is generous for a health probe.
    let mut stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr))
        .await
        .map_err(|_| "connect timed out")?
        .or_err(
            pingora_error::ErrorType::ConnectTimedout,
            "health probe connect",
        )?;

    let host = addr.to_string();
    let request = format!("GET {uri} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");

    tokio::time::timeout(Duration::from_secs(5), stream.write_all(request.as_bytes()))
        .await
        .map_err(|_| "write timed out")?
        .or_err(pingora_error::ErrorType::WriteError, "health probe write")?;

    // Read just enough to parse the status line — `HTTP/1.1 200 OK\r\n` is ~17 bytes.
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .map_err(|_| "read timed out")?
        .or_err(pingora_error::ErrorType::ReadError, "health probe read")?;

    // Parse "HTTP/1.x NNN ..." — we only need the status code.
    let response = std::str::from_utf8(&buf[..n])?;
    let status = response
        .split_whitespace()
        .nth(1)
        .ok_or("missing status code")?
        .parse::<u16>()?;

    Ok(status)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn make_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    fn make_pool(ports: &[u16], policy: LbPolicy) -> UpstreamPool {
        let backends = ports
            .iter()
            .map(|&p| BackendConfig {
                addr: make_addr(p),
                max_conns: None,
                tls: false,
                tls_server_name: String::new(),
                client_cert_key: None,
                trusted_ca: None,
            })
            .collect();
        UpstreamPool::new(backends, policy, None, None)
    }

    fn make_pool_with_max(port: u16, max_conns: u32) -> UpstreamPool {
        UpstreamPool::new(
            vec![BackendConfig {
                addr: make_addr(port),
                max_conns: Some(max_conns),
                tls: false,
                tls_server_name: String::new(),
                client_cert_key: None,
                trusted_ca: None,
            }],
            LbPolicy::RoundRobin,
            None,
            None,
        )
    }

    // ── single-backend fast path ──────────────────────────────────────────────

    #[test]
    fn single_backend_fast_path_returns_backend() {
        let pool = make_pool(&[8080], LbPolicy::RoundRobin);
        let sel = pool.select(None).expect("should select");
        assert_eq!(sel.addr, make_addr(8080));
    }

    #[test]
    fn single_backend_unhealthy_returns_none() {
        let pool = make_pool(&[8080], LbPolicy::RoundRobin);
        pool.mark_unhealthy(make_addr(8080));
        assert!(pool.select(None).is_none());
    }

    #[test]
    fn all_backends_unhealthy_returns_none() {
        let pool = make_pool(&[8080, 8081, 8082], LbPolicy::RoundRobin);
        pool.mark_unhealthy(make_addr(8080));
        pool.mark_unhealthy(make_addr(8081));
        pool.mark_unhealthy(make_addr(8082));
        assert!(pool.select(None).is_none());
    }

    // ── round-robin ───────────────────────────────────────────────────────────

    #[test]
    fn round_robin_distributes_evenly() {
        let pool = make_pool(&[8080, 8081, 8082], LbPolicy::RoundRobin);
        let mut counts = [0usize; 3];
        let ports = [8080u16, 8081, 8082];

        for _ in 0..30 {
            let sel = pool.select(None).expect("should select");
            if let Some(idx) = ports.iter().position(|&p| make_addr(p) == sel.addr) {
                counts[idx] += 1;
            }
        }

        // Each backend should get exactly 10 requests (30 / 3)
        assert_eq!(counts, [10, 10, 10], "round-robin must distribute evenly");
    }

    #[test]
    fn round_robin_skips_unhealthy_backend() {
        let pool = make_pool(&[8080, 8081, 8082], LbPolicy::RoundRobin);
        pool.mark_unhealthy(make_addr(8081));

        for _ in 0..20 {
            let sel = pool.select(None).expect("should select");
            assert_ne!(
                sel.addr,
                make_addr(8081),
                "unhealthy backend must not be selected"
            );
        }
    }

    // ── least-conn ────────────────────────────────────────────────────────────

    #[test]
    fn least_conn_picks_backend_with_fewest_connections() {
        let pool = make_pool(&[8080, 8081, 8082], LbPolicy::LeastConn);

        // Artificially load backend 8080 with 5 conns and 8081 with 3 conns
        pool.backends[0].active_conns.store(5, Ordering::Relaxed);
        pool.backends[1].active_conns.store(3, Ordering::Relaxed);
        // backend 8082 has 0 connections

        let sel = pool.select(None).expect("should select");
        assert_eq!(
            sel.addr,
            make_addr(8082),
            "least-conn should pick 8082 (0 conns)"
        );
    }

    #[test]
    fn least_conn_skips_unhealthy() {
        let pool = make_pool(&[8080, 8081], LbPolicy::LeastConn);
        pool.backends[0].active_conns.store(0, Ordering::Relaxed); // 8080 has 0 conns
        pool.mark_unhealthy(make_addr(8080));

        let sel = pool.select(None).expect("should select");
        assert_eq!(sel.addr, make_addr(8081));
    }

    // ── random ────────────────────────────────────────────────────────────────

    #[test]
    fn random_selects_valid_backend() {
        let pool = make_pool(&[8080, 8081, 8082], LbPolicy::Random);
        let ports = [8080u16, 8081, 8082];

        for _ in 0..50 {
            let sel = pool.select(None).expect("should always select one");
            assert!(
                ports.contains(&sel.addr.port()),
                "random must select a configured backend"
            );
        }
    }

    #[test]
    fn random_skips_unhealthy() {
        let pool = make_pool(&[8080, 8081], LbPolicy::Random);
        pool.mark_unhealthy(make_addr(8080));

        for _ in 0..30 {
            let sel = pool.select(None).expect("should select");
            assert_eq!(sel.addr, make_addr(8081));
        }
    }

    // ── ip-hash ───────────────────────────────────────────────────────────────

    #[test]
    fn ip_hash_is_deterministic_for_same_ip() {
        let pool = make_pool(&[8080, 8081, 8082], LbPolicy::IpHash);
        let ip = Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));

        let first = pool.select(ip).expect("should select").addr;
        for _ in 0..20 {
            let sel = pool.select(ip).expect("should select").addr;
            assert_eq!(sel, first, "ip_hash must be deterministic for same IP");
        }
    }

    #[test]
    fn ip_hash_falls_back_to_rr_without_ip() {
        let pool = make_pool(&[8080, 8081], LbPolicy::IpHash);
        // Should not panic — falls back to round-robin
        assert!(pool.select(None).is_some());
    }

    // ── connection limit enforcement ──────────────────────────────────────────

    #[test]
    fn connection_limit_blocks_selection() {
        let pool = make_pool_with_max(8080, 2);
        pool.backends[0].active_conns.store(2, Ordering::Relaxed);
        assert!(
            pool.select(None).is_none(),
            "pool at max_conns should return None"
        );
    }

    #[test]
    fn acquire_release_roundtrip() {
        let pool = make_pool_with_max(8080, 2);
        assert!(pool.acquire_connection(make_addr(8080)));
        assert!(pool.acquire_connection(make_addr(8080)));
        // At cap now
        assert!(!pool.acquire_connection(make_addr(8080)));
        // Release one and try again
        pool.release_connection(make_addr(8080));
        assert!(pool.acquire_connection(make_addr(8080)));
    }

    #[test]
    fn release_does_not_underflow() {
        let pool = make_pool(&[8080], LbPolicy::RoundRobin);
        // Release without acquire — must not panic or wrap around
        pool.release_connection(make_addr(8080));
        assert_eq!(pool.backends[0].active_conns.load(Ordering::Relaxed), 0);
    }

    // ── health mark ───────────────────────────────────────────────────────────

    #[test]
    fn mark_healthy_unhealthy_toggle() {
        let pool = make_pool(&[8080], LbPolicy::RoundRobin);
        assert!(pool.select(None).is_some());

        pool.mark_unhealthy(make_addr(8080));
        assert!(pool.select(None).is_none());

        pool.mark_healthy(make_addr(8080));
        assert!(pool.select(None).is_some());
    }

    // ── metadata ─────────────────────────────────────────────────────────────

    #[test]
    fn first_addr_returns_first_backend() {
        let pool = make_pool(&[8080, 8081], LbPolicy::RoundRobin);
        assert_eq!(pool.first_addr(), Some(make_addr(8080)));
    }

    #[test]
    fn empty_pool_returns_none() {
        let pool = UpstreamPool::new(vec![], LbPolicy::RoundRobin, None, None);
        assert!(pool.select(None).is_none());
        assert!(pool.first_addr().is_none());
        assert!(pool.is_empty());
    }
}
