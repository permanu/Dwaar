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

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use parking_lot::Mutex;
use pingora_core::OrErr;
use pingora_core::services::background::BackgroundService;
use tracing::{debug, info, warn};

use crate::wake::ScaleToZeroConfig;

/// Which algorithm the pool uses to pick a backend on each request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LbPolicy {
    RoundRobin,
    LeastConn,
    Random,
    IpHash,
    /// Cookie-based sticky sessions — pin visitors via `_dwaar_sticky` cookie.
    Cookie,
}

/// Retry configuration for upstream connection/response failures.
///
/// Zero-size when retries are disabled (the default), so pools that don't
/// use retry pay no memory overhead.
#[derive(Debug, Clone, Copy)]
pub struct RetryConfig {
    /// Max retry attempts (0 = disabled).
    pub max_retries: u32,
    /// Total wall-clock budget for all retries. `Duration::ZERO` = no time limit.
    pub try_duration: Duration,
}

impl RetryConfig {
    /// No retries — the default. Compiles to a zero-check on the hot path.
    pub const DISABLED: Self = Self {
        max_retries: 0,
        try_duration: Duration::ZERO,
    };

    /// Whether retry is actually enabled.
    pub const fn is_enabled(&self) -> bool {
        self.max_retries > 0
    }

    /// Whether the given HTTP method is safe to retry (idempotent).
    /// POST, PUT, DELETE, and PATCH are not retried by default.
    pub fn is_idempotent_method(method: &str) -> bool {
        matches!(method, "GET" | "HEAD" | "OPTIONS")
    }

    /// Exponential backoff delay for the given attempt (0-indexed).
    /// 50ms, 100ms, 200ms, 400ms, ... capped at 2s.
    pub fn backoff_delay(attempt: u32) -> Duration {
        let base_ms = 50u64;
        let delay_ms = base_ms.saturating_mul(1u64 << attempt.min(5));
        Duration::from_millis(delay_ms.min(2000))
    }
}

/// Name of the sticky session cookie set by `lb_policy cookie`.
pub const STICKY_COOKIE_NAME: &str = "_dwaar_sticky";

/// Cookie attributes appended to the Set-Cookie header for sticky sessions.
const STICKY_COOKIE_ATTRS: &str = "; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400";

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
    /// Retry config for upstream failures. Zero-overhead when disabled.
    pub(crate) retry_config: RetryConfig,
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
    /// Last observed health-probe failure reason (ISSUE-127). Populated by the
    /// health checker on a failed probe and cleared on a successful one, so the
    /// WARN log emitted on healthy→unhealthy transition carries an operator-
    /// actionable reason string.
    ///
    /// Guarded by `parking_lot::Mutex` (Guardrail #58) — set/cleared only on the
    /// health-check path, never on the request hot path.
    pub(crate) last_error: Mutex<Option<String>>,
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
                last_error: Mutex::new(None),
            })
            .collect();

        Self {
            backends: compiled,
            policy,
            counter: AtomicU64::new(0),
            health_uri,
            health_interval: Duration::from_secs(health_interval.unwrap_or(10)),
            scale_to_zero: None,
            retry_config: RetryConfig::DISABLED,
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

    /// Set retry configuration on this pool (builder-style).
    #[must_use]
    pub fn with_retry_config(mut self, config: RetryConfig) -> Self {
        self.retry_config = config;
        self
    }

    /// Returns the retry configuration for this pool.
    pub fn retry_config(&self) -> &RetryConfig {
        &self.retry_config
    }

    /// Returns the load balancing policy for this pool.
    pub fn policy(&self) -> LbPolicy {
        self.policy
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
    pub fn select(&self, client_ip: Option<std::net::IpAddr>) -> Option<SocketAddr> {
        if self.backends.is_empty() {
            return None;
        }
        if self.backends.len() == 1 {
            return self.select_single();
        }

        match self.policy {
            // Cookie falls back to round-robin when called via select() without
            // a cookie value; the caller should use select_cookie() instead.
            LbPolicy::RoundRobin | LbPolicy::Cookie => self.select_round_robin(),
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
    fn select_single(&self) -> Option<SocketAddr> {
        let b = &self.backends[0];
        if !b.healthy.load(Ordering::Relaxed) {
            return None;
        }
        if let Some(max) = b.max_conns
            && b.active_conns.load(Ordering::Acquire) >= max
        {
            return None;
        }
        Some(b.addr)
    }

    /// Round-robin: atomically advance the global counter and mod by healthy count.
    ///
    /// We iterate from the selected index, wrapping around, until we find a
    /// backend that is both healthy and under its connection cap. This handles
    /// the case where the initially-selected backend is temporarily unavailable
    /// without changing the distribution for the common all-healthy case.
    fn select_round_robin(&self) -> Option<SocketAddr> {
        let n = self.backends.len();
        // Guard against empty pool — `% n` panics on n == 0. The public
        // `select()` already returns None before reaching here, but this inner
        // guard makes the function independently safe if the call path changes.
        // See #170.
        if n == 0 {
            return None;
        }
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
    fn select_least_conn(&self) -> Option<SocketAddr> {
        let best = self
            .backends
            .iter()
            .filter(|b| {
                b.healthy.load(Ordering::Relaxed)
                    && b.max_conns
                        .is_none_or(|max| b.active_conns.load(Ordering::Relaxed) < max)
            })
            .min_by_key(|b| b.active_conns.load(Ordering::Relaxed))?;

        Some(best.addr)
    }

    /// Random: choose a uniformly random healthy backend.
    ///
    /// Uses reservoir sampling (O(1) memory) instead of collecting into a Vec.
    /// This is a pure read: it does not increment `active_conns`. The caller is
    /// responsible for calling `acquire_connection()` / `release_connection()`.
    fn select_random(&self) -> Option<SocketAddr> {
        let mut selected: Option<&Backend> = None;
        let mut count = 0usize;

        for b in &self.backends {
            if b.healthy.load(Ordering::Relaxed)
                && b.max_conns
                    .is_none_or(|max| b.active_conns.load(Ordering::Relaxed) < max)
            {
                count += 1;
                if fastrand::usize(..count) == 0 {
                    selected = Some(b);
                }
            }
        }

        Some(selected?.addr)
    }

    /// IP-hash: hash the client IP and pick a backend deterministically.
    ///
    /// Falls back to round-robin when no client IP is available.
    fn select_ip_hash(&self, client_ip: Option<std::net::IpAddr>) -> Option<SocketAddr> {
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
    fn find_available_from(&self, start: usize) -> Option<SocketAddr> {
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
            return Some(b.addr);
        }
        None
    }

    /// Cookie-based sticky session selection.
    ///
    /// If `cookie_value` is `Some`, hash it to pick a backend deterministically.
    /// Falls back to round-robin if the pinned backend is unhealthy or at capacity.
    /// Returns `(selected_addr, needs_set_cookie)` — the bool is `true` when the
    /// response should include a `Set-Cookie` header (no cookie was sent, or the
    /// pinned backend was unavailable and a new one was chosen).
    pub fn select_cookie(&self, cookie_value: Option<&str>) -> Option<(SocketAddr, bool)> {
        if self.backends.is_empty() {
            return None;
        }
        if self.backends.len() == 1 {
            let addr = self.select_single()?;
            let needs_set = cookie_value.is_none();
            return Some((addr, needs_set));
        }

        if let Some(val) = cookie_value {
            let hash = fnv_hash_bytes(val.as_bytes());
            let n = self.backends.len();
            let idx = hash % n;
            let b = &self.backends[idx];

            if b.healthy.load(Ordering::Relaxed)
                && b.max_conns
                    .is_none_or(|max| b.active_conns.load(Ordering::Acquire) < max)
            {
                return Some((b.addr, false));
            }

            // Pinned backend unavailable — fall through to round-robin and re-stick
            let addr = self.select_round_robin()?;
            Some((addr, true))
        } else {
            let addr = self.select_round_robin()?;
            Some((addr, true))
        }
    }

    /// Compute a stable sticky cookie value for a backend address.
    ///
    /// Uses FNV-1a of the `addr` string representation so that
    /// adding/removing other backends doesn't invalidate existing sessions.
    pub fn backend_sticky_hash(addr: SocketAddr) -> String {
        let s = addr.to_string();
        let hash = fnv_hash_bytes(s.as_bytes());
        format!("{hash:016x}")
    }

    /// Format a `Set-Cookie` header value for sticky sessions.
    pub fn sticky_set_cookie(addr: SocketAddr) -> String {
        let val = Self::backend_sticky_hash(addr);
        format!("{STICKY_COOKIE_NAME}={val}{STICKY_COOKIE_ATTRS}")
    }

    /// Select a different backend than the one that just failed, for retry.
    ///
    /// Advances the round-robin counter so the next healthy backend is chosen,
    /// excluding `failed_addr` if possible.
    pub fn select_excluding(&self, failed_addr: SocketAddr) -> Option<SocketAddr> {
        if self.backends.is_empty() {
            return None;
        }
        let n = self.backends.len();
        let start = self.counter.fetch_add(1, Ordering::Relaxed) as usize % n;
        for offset in 0..n {
            let b = &self.backends[(start + offset) % n];
            if b.addr == failed_addr {
                continue;
            }
            if !b.healthy.load(Ordering::Relaxed) {
                continue;
            }
            if let Some(max) = b.max_conns
                && b.active_conns.load(Ordering::Acquire) >= max
            {
                continue;
            }
            return Some(b.addr);
        }
        // All other backends exhausted — allow the original as last resort
        self.find_available_from(start)
    }

    /// Mark a backend as healthy (called by `HealthChecker` after a successful probe).
    ///
    /// On an unhealthy→healthy transition this logs at `INFO` and clears any
    /// previously stored `last_error` (ISSUE-127). No-op on repeat transitions.
    pub fn mark_healthy(&self, addr: SocketAddr) {
        for b in &self.backends {
            if b.addr == addr {
                // `Release` here pairs with `Acquire` loads in the selection path so
                // a thread that observes `healthy = true` also observes the
                // `last_error` clear below.
                let previous = b.healthy.swap(true, Ordering::Release);
                if previous {
                    debug!(%addr, "backend already healthy");
                } else {
                    // false → true: transition
                    *b.last_error.lock() = None;
                    let masked = mask_addr(&addr);
                    info!(
                        upstream = %masked,
                        "upstream transitioned to healthy",
                    );
                }
                return;
            }
        }
    }

    /// Mark a backend as unhealthy (called by `HealthChecker` after a failed
    /// probe, or by `upstream_peer()` when a connection is refused).
    ///
    /// On a healthy→unhealthy transition this logs at `WARN` with the stored
    /// `last_error` as the reason (ISSUE-127). No-op on repeat transitions.
    ///
    /// The upstream address is masked before logging (M-08) so shared log
    /// sinks can't be used to map internal network topology. Operators who
    /// need the unmasked address can correlate via the ops-only metrics
    /// endpoint, which emits full socket addresses over an authenticated
    /// channel.
    pub fn mark_unhealthy(&self, addr: SocketAddr) {
        for b in &self.backends {
            if b.addr == addr {
                let previous = b.healthy.swap(false, Ordering::Release);
                if previous {
                    // true → false: transition
                    let err_str = b.last_error.lock().clone();
                    let masked = mask_addr(&addr);
                    warn!(
                        upstream = %masked,
                        reason = %err_str.as_deref().unwrap_or("<no details>"),
                        "upstream transitioned to unhealthy",
                    );
                } else {
                    debug!(%addr, "backend already unhealthy");
                }
                return;
            }
        }
    }

    /// Record a failure reason for a backend, so that a subsequent
    /// `mark_unhealthy` on the same backend has an operator-actionable reason to
    /// emit in its WARN log (ISSUE-127). Called by the health probe before it
    /// calls `mark_unhealthy`.
    ///
    /// Safe to call repeatedly — the most recent error wins.
    pub fn record_probe_error(&self, addr: SocketAddr, reason: String) {
        for b in &self.backends {
            if b.addr == addr {
                *b.last_error.lock() = Some(reason);
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

// ── Log masking (M-08) ────────────────────────────────────────────────────────

/// Render a [`SocketAddr`] with the host portion partially masked for safe
/// inclusion in operator logs (M-08).
///
/// The goal is to preserve enough context for an operator running the proxy
/// to correlate a transition warning with a specific subnet, without leaking
/// the full internal topology into shared log sinks. For IPv4 we keep only
/// the first octet; for IPv6 we keep the first three hextets (/48 prefix).
/// The port is always retained — it identifies the service, not the host.
///
/// Examples:
/// - `10.0.0.5:8080` → `10.x.x.x:8080`
/// - `[2001:db8:abcd::1]:443` → `2001:db8:abcd::/48:443`
fn mask_addr(addr: &SocketAddr) -> String {
    match addr.ip() {
        IpAddr::V4(v4) => {
            let [a, _, _, _] = v4.octets();
            format!("{a}.x.x.x:{}", addr.port())
        }
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            format!(
                "{:x}:{:x}:{:x}::/48:{}",
                segs[0],
                segs[1],
                segs[2],
                addr.port()
            )
        }
    }
}

// ── FNV-1a hashing ───────────────────────────────────────────────────────────

/// FNV-1a hash of an arbitrary byte slice, returning a `usize` for indexing.
fn fnv_hash_bytes(bytes: &[u8]) -> usize {
    const FNV_OFFSET: u64 = 14_695_981_039_346_656_037;
    const FNV_PRIME: u64 = 1_099_511_628_211;

    let mut hash = FNV_OFFSET;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash as usize
}

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
///
/// The pool list is behind `ArcSwap` so that `ConfigWatcher` can swap in a new
/// set of pools on hot-reload without restarting this service.
pub struct HealthChecker {
    pools: Arc<ArcSwap<Vec<Arc<UpstreamPool>>>>,
}

impl std::fmt::Debug for HealthChecker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HealthChecker").finish_non_exhaustive()
    }
}

impl HealthChecker {
    /// Create a new checker with a shared, hot-swappable pool list.
    pub fn new(pools: Arc<ArcSwap<Vec<Arc<UpstreamPool>>>>) -> Self {
        Self { pools }
    }
}

#[async_trait]
impl BackgroundService for HealthChecker {
    async fn start(&self, mut shutdown: pingora_core::server::ShutdownWatch) {
        loop {
            // Reload the pool list from ArcSwap on every tick so hot-reloaded
            // pools are picked up without restarting the service.
            let all_pools = self.pools.load();
            let active: Vec<Arc<UpstreamPool>> = all_pools
                .iter()
                .filter(|p| p.health_uri.is_some())
                .cloned()
                .collect();

            if active.is_empty() {
                // No pools need health checking right now. Sleep with a default
                // interval and re-check after reload might have added some.
                tokio::select! {
                    () = tokio::time::sleep(Duration::from_secs(10)) => { continue; }
                    _ = shutdown.changed() => {
                        debug!("health checker: shutdown signal received");
                        return;
                    }
                }
            }

            // Derive poll interval from the smallest configured across active pools.
            let interval = active
                .iter()
                .map(|p| p.health_interval)
                .min()
                .unwrap_or(Duration::from_secs(10));

            // Probe all backends across all active pools.
            for pool in &active {
                let Some(ref uri) = pool.health_uri else {
                    continue;
                };
                for backend in &pool.backends {
                    let addr = backend.addr;
                    match probe_backend(addr, uri).await {
                        Ok(status) if (200..300).contains(&status) => {
                            pool.mark_healthy(addr);
                        }
                        Ok(status) => {
                            // Record the reason *before* mark_unhealthy so the
                            // transition WARN log carries it (ISSUE-127).
                            pool.record_probe_error(addr, format!("non-2xx status {status}"));
                            debug!(%addr, status, "health probe returned non-2xx, marking unhealthy");
                            pool.mark_unhealthy(addr);
                        }
                        Err(e) => {
                            pool.record_probe_error(addr, e.to_string());
                            debug!(%addr, error = %e, "health probe failed, marking unhealthy");
                            pool.mark_unhealthy(addr);
                        }
                    }
                }
            }

            // Wait for the poll interval or shutdown signal.
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

    // Read at least the status line — loop to handle partial reads.
    let mut buf = [0u8; 64];
    let mut total = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match tokio::time::timeout_at(deadline, stream.read(&mut buf[total..])).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                total += n;
                // We have enough once we see \r\n (end of status line) or buffer is full.
                if buf[..total].windows(2).any(|w| w == b"\r\n") || total >= buf.len() {
                    break;
                }
            }
            Ok(Err(e)) => return Err(Box::new(e)),
            Err(_) => return Err("read timed out".into()),
        }
    }

    // Parse "HTTP/1.x NNN ..." — we only need the status code.
    let response = std::str::from_utf8(&buf[..total])?;
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
        assert_eq!(sel, make_addr(8080));
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
            if let Some(idx) = ports.iter().position(|&p| make_addr(p) == sel) {
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
                sel,
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
            sel,
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
        assert_eq!(sel, make_addr(8081));
    }

    // ── random ────────────────────────────────────────────────────────────────

    #[test]
    fn random_selects_valid_backend() {
        let pool = make_pool(&[8080, 8081, 8082], LbPolicy::Random);
        let ports = [8080u16, 8081, 8082];

        for _ in 0..50 {
            let sel = pool.select(None).expect("should always select one");
            assert!(
                ports.contains(&sel.port()),
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
            assert_eq!(sel, make_addr(8081));
        }
    }

    // ── ip-hash ───────────────────────────────────────────────────────────────

    #[test]
    fn ip_hash_is_deterministic_for_same_ip() {
        let pool = make_pool(&[8080, 8081, 8082], LbPolicy::IpHash);
        let ip = Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));

        let first = pool.select(ip).expect("should select");
        for _ in 0..20 {
            let sel = pool.select(ip).expect("should select");
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

    /// Simulates the proxy lifecycle: select → acquire → (request) → release.
    /// Verifies that `active_conns` tracks correctly through the full cycle and
    /// that `max_conns` is enforced after acquire.
    #[test]
    fn proxy_lifecycle_select_acquire_release() {
        let pool = make_pool_with_max(8080, 2);
        let addr = make_addr(8080);

        // Lifecycle 1: select → acquire → release
        let sel = pool.select(None).expect("should select");
        assert_eq!(sel, addr);
        assert!(
            pool.acquire_connection(addr),
            "first acquire should succeed"
        );
        assert_eq!(pool.backends[0].active_conns.load(Ordering::Relaxed), 1);

        // Lifecycle 2: second concurrent request
        assert!(
            pool.acquire_connection(addr),
            "second acquire should succeed"
        );
        assert_eq!(pool.backends[0].active_conns.load(Ordering::Relaxed), 2);

        // Lifecycle 3: at cap — third acquire must fail (503 in proxy)
        assert!(
            !pool.acquire_connection(addr),
            "third acquire should be rejected at max=2"
        );

        // First request completes
        pool.release_connection(addr);
        assert_eq!(pool.backends[0].active_conns.load(Ordering::Relaxed), 1);

        // Now a new request can acquire again
        assert!(
            pool.acquire_connection(addr),
            "should succeed after release"
        );
        assert_eq!(pool.backends[0].active_conns.load(Ordering::Relaxed), 2);

        // Clean up both
        pool.release_connection(addr);
        pool.release_connection(addr);
        assert_eq!(pool.backends[0].active_conns.load(Ordering::Relaxed), 0);
    }

    /// Verifies that concurrent threads cannot exceed `max_conns` via the
    /// acquire CAS loop.
    #[test]
    fn concurrent_acquire_respects_max_conns() {
        use std::sync::Arc;
        let pool = Arc::new(make_pool_with_max(8080, 4));
        let addr = make_addr(8080);
        let barrier = Arc::new(std::sync::Barrier::new(32));

        let handles: Vec<_> = (0..32)
            .map(|_| {
                let pool = pool.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    pool.acquire_connection(addr)
                })
            })
            .collect();

        let acquired = handles
            .into_iter()
            .filter_map(|h| h.join().ok().filter(|&ok| ok))
            .count();

        assert_eq!(
            acquired, 4,
            "exactly max_conns threads should have acquired"
        );
        assert_eq!(pool.backends[0].active_conns.load(Ordering::Relaxed), 4);
    }

    // ── health mark ───────────────────────────────────────────────────────────

    // ── ISSUE-127: transition logs + last_error ───────────────────────────────

    #[test]
    fn record_probe_error_surfaces_in_backend_last_error() {
        let pool = make_pool(&[8080], LbPolicy::RoundRobin);
        let addr = make_addr(8080);

        // No error stored initially.
        assert!(pool.backends[0].last_error.lock().is_none());

        pool.record_probe_error(addr, "connect refused".to_string());
        assert_eq!(
            pool.backends[0].last_error.lock().as_deref(),
            Some("connect refused")
        );

        // Recording a newer error overwrites the previous one.
        pool.record_probe_error(addr, "timed out".to_string());
        assert_eq!(
            pool.backends[0].last_error.lock().as_deref(),
            Some("timed out")
        );
    }

    #[test]
    fn mark_healthy_clears_last_error_on_transition() {
        let pool = make_pool(&[8080], LbPolicy::RoundRobin);
        let addr = make_addr(8080);

        // Seed an error, flip to unhealthy, then recover.
        pool.record_probe_error(addr, "connect refused".to_string());
        pool.mark_unhealthy(addr);
        assert!(!pool.backends[0].healthy.load(Ordering::Acquire));
        assert!(pool.backends[0].last_error.lock().is_some());

        pool.mark_healthy(addr);
        assert!(pool.backends[0].healthy.load(Ordering::Acquire));
        assert!(
            pool.backends[0].last_error.lock().is_none(),
            "last_error should be cleared on unhealthy→healthy transition"
        );
    }

    #[test]
    fn repeat_mark_unhealthy_is_idempotent() {
        let pool = make_pool(&[8080], LbPolicy::RoundRobin);
        let addr = make_addr(8080);

        pool.record_probe_error(addr, "first".to_string());
        pool.mark_unhealthy(addr);
        // Second call must not panic or overwrite state in surprising ways.
        pool.record_probe_error(addr, "second".to_string());
        pool.mark_unhealthy(addr);
        assert!(!pool.backends[0].healthy.load(Ordering::Acquire));
        assert_eq!(
            pool.backends[0].last_error.lock().as_deref(),
            Some("second")
        );
    }

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

    // ── mask_addr (M-08) ────────────────────────────────────────────────────

    #[test]
    fn mask_addr_ipv4_keeps_first_octet_and_port() {
        let addr: SocketAddr = "10.0.0.5:8080"
            .parse()
            .expect("literal socket addr must parse");
        assert_eq!(mask_addr(&addr), "10.x.x.x:8080");

        let addr: SocketAddr = "192.168.1.42:443"
            .parse()
            .expect("literal socket addr must parse");
        assert_eq!(mask_addr(&addr), "192.x.x.x:443");

        // Edge: 0.0.0.0 still renders cleanly.
        let addr: SocketAddr = "0.0.0.0:1".parse().expect("literal socket addr must parse");
        assert_eq!(mask_addr(&addr), "0.x.x.x:1");
    }

    #[test]
    fn mask_addr_ipv6_keeps_48_prefix_and_port() {
        let addr: SocketAddr = "[2001:db8:abcd::1]:443"
            .parse()
            .expect("literal socket addr must parse");
        assert_eq!(mask_addr(&addr), "2001:db8:abcd::/48:443");

        // Loopback collapses to all-zero prefix, still no trailing host bits.
        let addr: SocketAddr = "[::1]:8080"
            .parse()
            .expect("literal socket addr must parse");
        assert_eq!(mask_addr(&addr), "0:0:0::/48:8080");

        // Full-form global address.
        let addr: SocketAddr = "[2606:4700:4700::1111]:53"
            .parse()
            .expect("literal socket addr must parse");
        assert_eq!(mask_addr(&addr), "2606:4700:4700::/48:53");
    }

    #[test]
    fn mask_addr_never_contains_tail_octets() {
        // Regression guard: masked output must not contain any of the
        // trailing-octet values from the original address.
        let addr: SocketAddr = "10.11.12.13:9000"
            .parse()
            .expect("literal socket addr must parse");
        let masked = mask_addr(&addr);
        assert!(!masked.contains("11"));
        assert!(!masked.contains("12"));
        assert!(!masked.contains("13"));
        assert!(masked.contains("9000"));
    }

    // ── cookie sticky sessions ───────────────────────────────────────────────

    #[test]
    fn select_cookie_returns_same_backend_for_same_value() {
        let pool = make_pool(&[8080, 8081, 8082], LbPolicy::Cookie);
        let cookie = UpstreamPool::backend_sticky_hash(make_addr(8081));

        let (first, needs_set) = pool.select_cookie(Some(&cookie)).expect("should select");
        assert!(!needs_set, "existing cookie should not need re-setting");

        for _ in 0..20 {
            let (sel, _) = pool.select_cookie(Some(&cookie)).expect("should select");
            assert_eq!(
                sel, first,
                "same cookie must always select the same backend"
            );
        }
    }

    #[test]
    fn select_cookie_falls_back_when_pinned_unhealthy() {
        let pool = make_pool(&[8080, 8081], LbPolicy::Cookie);
        let cookie = UpstreamPool::backend_sticky_hash(make_addr(8080));

        // Verify it initially selects 8080
        let (sel, _) = pool.select_cookie(Some(&cookie)).expect("should select");
        assert_eq!(sel, make_addr(8080));

        // Mark 8080 unhealthy — should fall back and request re-sticky
        pool.mark_unhealthy(make_addr(8080));
        let (sel, needs_set) = pool.select_cookie(Some(&cookie)).expect("should select");
        assert_eq!(sel, make_addr(8081), "should fall back to healthy backend");
        assert!(needs_set, "should need to set a new cookie after fallback");
    }

    #[test]
    fn select_cookie_no_cookie_returns_with_set_flag() {
        let pool = make_pool(&[8080, 8081], LbPolicy::Cookie);
        let (_, needs_set) = pool.select_cookie(None).expect("should select");
        assert!(needs_set, "absent cookie must trigger Set-Cookie");
    }

    #[test]
    fn sticky_set_cookie_has_correct_format() {
        let cookie = UpstreamPool::sticky_set_cookie(make_addr(8080));
        assert!(cookie.starts_with("_dwaar_sticky="));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(cookie.contains("Max-Age=86400"));
        assert!(cookie.contains("Path=/"));
    }

    #[test]
    fn backend_sticky_hash_is_stable() {
        let h1 = UpstreamPool::backend_sticky_hash(make_addr(8080));
        let h2 = UpstreamPool::backend_sticky_hash(make_addr(8080));
        assert_eq!(h1, h2, "hash must be deterministic");

        // Different backends produce different hashes
        let h3 = UpstreamPool::backend_sticky_hash(make_addr(8081));
        assert_ne!(h1, h3, "different backends must have different hashes");
    }

    // ── retry ────────────────────────────────────────────────────────────────

    #[test]
    fn retry_skips_non_idempotent_methods() {
        assert!(RetryConfig::is_idempotent_method("GET"));
        assert!(RetryConfig::is_idempotent_method("HEAD"));
        assert!(RetryConfig::is_idempotent_method("OPTIONS"));
        assert!(!RetryConfig::is_idempotent_method("POST"));
        assert!(!RetryConfig::is_idempotent_method("PUT"));
        assert!(!RetryConfig::is_idempotent_method("DELETE"));
        assert!(!RetryConfig::is_idempotent_method("PATCH"));
    }

    #[test]
    fn retry_backoff_grows_exponentially_with_cap() {
        assert_eq!(RetryConfig::backoff_delay(0), Duration::from_millis(50));
        assert_eq!(RetryConfig::backoff_delay(1), Duration::from_millis(100));
        assert_eq!(RetryConfig::backoff_delay(2), Duration::from_millis(200));
        assert_eq!(RetryConfig::backoff_delay(3), Duration::from_millis(400));
        assert_eq!(RetryConfig::backoff_delay(4), Duration::from_millis(800));
        assert_eq!(RetryConfig::backoff_delay(5), Duration::from_millis(1600));
        // min(5) clamps the shift, so attempt 6+ stays at 1600ms
        assert_eq!(RetryConfig::backoff_delay(6), Duration::from_millis(1600));
        assert_eq!(RetryConfig::backoff_delay(100), Duration::from_millis(1600));
    }

    #[test]
    fn retry_config_disabled_by_default() {
        let cfg = RetryConfig::DISABLED;
        assert!(!cfg.is_enabled());
        assert_eq!(cfg.max_retries, 0);
    }

    #[test]
    fn select_excluding_skips_failed_backend() {
        let pool = make_pool(&[8080, 8081, 8082], LbPolicy::RoundRobin);

        // Call select_excluding enough times to verify we never get 8081
        for _ in 0..20 {
            let sel = pool
                .select_excluding(make_addr(8081))
                .expect("should select");
            assert_ne!(
                sel,
                make_addr(8081),
                "excluded backend must not be returned"
            );
        }
    }

    #[test]
    fn select_excluding_falls_back_when_all_others_unhealthy() {
        let pool = make_pool(&[8080, 8081], LbPolicy::RoundRobin);
        pool.mark_unhealthy(make_addr(8081));

        // Only 8080 is healthy, and we're excluding it — last resort should
        // still return it via find_available_from fallback.
        // Wait: 8080 is the failed addr. 8081 is unhealthy.
        // select_excluding(8080) should skip 8080, try 8081 (unhealthy), then
        // fall back via find_available_from which includes 8080 again.
        let sel = pool.select_excluding(make_addr(8080));
        // If the only available is the failed one, find_available_from returns it
        assert_eq!(sel, Some(make_addr(8080)));
    }

    #[test]
    fn retry_config_enabled_with_retries() {
        let cfg = RetryConfig {
            max_retries: 3,
            try_duration: Duration::from_secs(30),
        };
        assert!(cfg.is_enabled());
    }

    #[test]
    fn pool_with_retry_config() {
        let pool = make_pool(&[8080, 8081], LbPolicy::RoundRobin).with_retry_config(RetryConfig {
            max_retries: 3,
            try_duration: Duration::from_secs(30),
        });
        assert!(pool.retry_config().is_enabled());
        assert_eq!(pool.retry_config().max_retries, 3);
    }

    // ── regression: issue #170 ───────────────────────────────────────────────

    #[test]
    fn round_robin_empty_pool_returns_none() {
        // Regression for issue #170: select_round_robin() previously computed
        // `counter % backends.len()` without checking len > 0, causing a
        // division-by-zero panic on an empty pool. The guard in select() caught
        // this for callers going through the public API, but select_round_robin()
        // itself was unguarded — reachable if the call path ever changes.
        let pool = UpstreamPool::new(vec![], LbPolicy::RoundRobin, None, None);
        // Call the inner method directly to verify it is independently safe.
        assert!(pool.select_round_robin().is_none());
    }
}
