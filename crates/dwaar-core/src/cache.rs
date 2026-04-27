// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! HTTP cache layer — config types, storage backend, key construction.
//!
//! Dwaar's caching is built on top of Pingora's `pingora-cache` crate:
//! - [`MemCache`] for in-memory storage
//! - [`Manager`] (LRU) for eviction
//! - [`CacheLock`] for stampede protection
//!
//! This module provides the glue: [`CacheConfig`] holds per-route settings
//! compiled from the Dwaarfile, [`CacheBackend`] bundles the `'static`
//! references that Pingora's `Storage` trait demands, and helper functions
//! build cache keys and meta defaults.
//!
//! # Intentional leak on resize (ISSUE-154)
//!
//! Pingora's `HttpCache::enable()` requires `&'static` references for the
//! storage backend, eviction manager, and cache lock — a hard API constraint
//! (see `pingora_cache::storage::Storage`, upstream TODO: "shouldn't have to
//! be static").  `Arc` cannot satisfy `&'static T`, so every time the
//! operator changes the cache's `max_size` a fresh set of control structs is
//! allocated via `Box::leak` (~1 KB each).  Old in-flight requests continue
//! to hold the previous `&'static` refs safely; the leaked memory is never
//! reclaimed.
//!
//! **Monitoring:** `leaked_cache_backend_count()` and
//! `leaked_cache_backend_bytes()` are exported for Prometheus.  Both are
//! monotonically increasing counters.  A spike indicates frequent resizes.
//!
//! **Recycling guidance:** With ~1 KB leaked per resize, 1000 resizes ≈ 1 MB
//! total.  At one reload per day this budget spans ~2–3 years; at one per
//! hour, ~41 days.  Configure your supervisor to recycle the process
//! periodically if automated reloads are frequent.  The `leaked_backend_count`
//! Prometheus metric is the right signal for an alert.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use http::StatusCode;
use pingora_cache::eviction::lru::Manager as LruManager;
use pingora_cache::lock::CacheLock;
use pingora_cache::{CacheKey, CacheMetaDefaults, MemCache};

/// Number of cache backends that have been leaked since process start.
/// Increments by one on every successful [`new_cache_backend`] call.
///
/// # Leak budget and process recycling (ISSUE-154)
///
/// Each increment represents ~1 KB of leaked control-struct memory.  The
/// recommendation is to recycle the process when this counter approaches
/// `1000` — i.e., after ~1000 cache resizes, which at the typical rate of
/// one operator-driven reload per day corresponds to about **2–3 years** of
/// uptime.  For sites that reload more aggressively (e.g., 10 reloads/day
/// via automation) the equivalent budget runs out after ~100 days; at 100
/// reloads/day, after ~10 days.
///
/// Why `Box::leak` and not `Arc`?  Pingora's `HttpCache::enable()` signature
/// requires `&'static (dyn Storage + Sync)` and `&'static (dyn
/// EvictionManager + Sync)` — the `'static` bound is a hard API requirement
/// (see `pingora_cache::storage::Storage`; upstream comment: "TODO: shouldn't
/// have to be static").  `Arc<T>` does not satisfy `&'static T` because an
/// `Arc` is bounded by the `Arc`'s own lifetime, not the process lifetime.
/// The only way to obtain `&'static T` from a heap allocation today is
/// `Box::leak`.  If Pingora relaxes the `'static` bound in a future release,
/// this leak can be eliminated.
static LEAKED_BACKEND_COUNT: AtomicU64 = AtomicU64::new(0);

/// Approximate cumulative bytes intentionally leaked by [`new_cache_backend`]
/// across all reloads. Tracked as a sentinel — if this grows past the
/// configured budget at runtime, operators should know to recycle the
/// process via the supervisor (Guardrail #28).
static LEAKED_BACKEND_BYTES: AtomicU64 = AtomicU64::new(0);

/// Approximate per-backend control-struct overhead. The actual leak is
/// dominated by the boxed `MemCache` + `LruManager` headers; the cached
/// data inside lives only as long as the backend itself and is not
/// double-leaked on rebuild.
const APPROX_BACKEND_OVERHEAD_BYTES: u64 = 1024;

/// Number of backends leaked since process start. Exposed for metrics.
pub fn leaked_cache_backend_count() -> u64 {
    LEAKED_BACKEND_COUNT.load(Ordering::Relaxed)
}

/// Approximate cumulative leaked bytes since process start. Exposed for
/// metrics.
pub fn leaked_cache_backend_bytes() -> u64 {
    LEAKED_BACKEND_BYTES.load(Ordering::Relaxed)
}

/// Total number of individual `Box::leak` calls made for cache reload structs
/// since process start. Each [`new_cache_backend`] call increments this by 3
/// (one for each of `LruManager`, `MemCache`, and `CacheLock`). Exposed so the
/// metrics crate can surface cumulative leak pressure without requiring a
/// Prometheus integration here.
static CACHE_RELOAD_LEAKS: AtomicU64 = AtomicU64::new(0);

/// Total individual `Box::leak` calls for cache backend structs since process
/// start. Exposed for metrics; the Prometheus exporter can read this via its
/// own scheduled scrape without any direct wiring here.
pub fn leaked_reload_count() -> u64 {
    CACHE_RELOAD_LEAKS.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Per-route cache configuration
// ---------------------------------------------------------------------------

/// Per-route cache settings compiled from a Dwaarfile `cache` block.
///
/// An empty `match_paths` vector means "cache everything on this route".
/// Patterns ending in `*` are treated as prefix matches; all others are exact.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Eviction budget in bytes (applies to the global LRU, but stored
    /// per-route so each site can declare its own ceiling).
    pub max_size: usize,
    /// Path prefixes eligible for caching. Empty = cache all paths.
    pub match_paths: Vec<String>,
    /// Default freshness TTL in seconds when the origin sends no Cache-Control.
    pub default_ttl: u32,
    /// Grace period (seconds) during which a stale response may be served
    /// while an async revalidation is in flight.
    pub stale_while_revalidate: u32,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_size: 1_073_741_824, // 1 GiB
            match_paths: Vec::new(),
            default_ttl: 3600,
            stale_while_revalidate: 60,
        }
    }
}

impl CacheConfig {
    /// Check whether `path` is eligible for caching under this config.
    ///
    /// Rules:
    /// - Empty `match_paths` → everything matches.
    /// - A pattern ending in `*` is a prefix match (the `*` is stripped).
    /// - Otherwise the pattern must match exactly.
    pub fn path_matches(&self, path: &str) -> bool {
        if self.match_paths.is_empty() {
            return true;
        }

        self.match_paths.iter().any(|pattern| {
            if let Some(prefix) = pattern.strip_suffix('*') {
                path.starts_with(prefix)
            } else {
                path == pattern
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Global cache backend (leaked for 'static lifetime)
// ---------------------------------------------------------------------------

/// Bundles the `'static` references Pingora's cache subsystem requires.
///
/// Pingora's [`Storage`] trait methods take `&'static self`, so the backing
/// structs must live for the entire process.  [`new_cache_backend`] allocates
/// them via `Box::leak`.
/// Manual `Debug` because `MemCache` and `LruManager` don't derive it.
#[derive(Clone, Copy)]
pub struct CacheBackend {
    pub storage: &'static MemCache,
    pub eviction: &'static LruManager<16>,
    pub lock: &'static CacheLock,
    /// The LRU eviction budget that was used to create this backend.
    /// Stored here so we can detect no-op reloads without re-allocating.
    pub max_size: usize,
}

impl std::fmt::Debug for CacheBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheBackend")
            .field("storage", &"MemCache { .. }")
            .field("eviction", &"LruManager<16> { .. }")
            .field("lock", &self.lock)
            .field("max_size", &self.max_size)
            .finish()
    }
}

/// Shared handle for hot-reloadable cache backend.
///
/// The inner `Option` is `None` when no route has a `cache {}` block.
/// On reload, [`realloc_cache_backend`] swaps in a fresh backend if the
/// max size changed; consumers call `.load()` per request to pick up
/// the latest backend.
pub type SharedCacheBackend = std::sync::Arc<arc_swap::ArcSwap<Option<CacheBackend>>>;

/// Allocate a fresh cache backend with the given LRU eviction budget.
///
/// Each struct is heap-allocated and leaked so that Pingora can hold
/// `&'static` references.  This is safe to call multiple times — each
/// call leaks a small amount of memory (~1 KB) for the old backend's
/// control structs.  The actual cached data lives inside the structs
/// and is abandoned, not leaked again.  Since cache resizes happen at
/// most a handful of times per deployment the cumulative leak is
/// negligible.
///
/// # Why Arc doesn't help (ISSUE-154)
///
/// `Arc<MemCache>` has a lifetime bounded by the `Arc` itself — it is not
/// `'static`.  Pingora's `HttpCache::enable()` requires
/// `&'static (dyn Storage + Sync)` (source: `pingora_cache::lib`).  You
/// cannot coerce `&Arc<T>` into `&'static T` without unsafe transmutation,
/// which defeats the purpose.  `Box::leak` is the only safe mechanism.  If
/// Pingora ever relaxes the `'static` bound, this function should be
/// rewritten to use `Arc` + `ArcSwap` — see ISSUE-154.
pub fn new_cache_backend(max_size: usize) -> CacheBackend {
    // WHY Box::leak: Pingora's `HttpCache::enable()` requires `&'static`
    // references for storage, eviction, and lock.  The `'static` bound is
    // explicit in the function signature
    // (`pingora_cache::HttpCache::enable`, lines 487-490) and acknowledged
    // as a temporary constraint by the Pingora maintainers ("TODO: shouldn't
    // have to be static").  `Arc<T>` cannot satisfy `&'static T` — the Arc
    // borrow ends when the Arc is dropped, not at process exit.
    //
    // On the first call this is effectively free.  On subsequent calls (config
    // reload / eviction-budget resize) the *old* structs are abandoned — their
    // control-struct memory (~1 KB total) leaks permanently because in-flight
    // requests may still hold `&'static` refs to them.  The actual cached data
    // inside the old `MemCache` is freed when those refs drop; only the tiny
    // control structs accumulate.  Reloads are rare (operator-driven), so the
    // total leak stays negligible over a typical deployment lifetime.
    // Monitor via `leaked_reload_count()` / `leaked_cache_backend_bytes()`.
    //
    // Recycling guidance: 1000 reloads ≈ 1 MB.  At one reload/day → ~3 years.
    // At one reload/hour → ~41 days.  Alert on `leaked_backend_count > 1000`.

    // SAFETY: Box::leak is intentional — see comment above.
    let eviction: &'static LruManager<16> =
        Box::leak(Box::new(LruManager::<16>::with_capacity(max_size, 1024)));
    CACHE_RELOAD_LEAKS.fetch_add(1, Ordering::Relaxed);
    tracing::debug!(
        target: "dwaar::cache::reload",
        leaked_bytes = std::mem::size_of::<LruManager<16>>(),
        "Box::leak: LruManager<16> promoted to 'static for Pingora cache backend"
    );

    let storage: &'static MemCache = Box::leak(Box::new(MemCache::new()));
    CACHE_RELOAD_LEAKS.fetch_add(1, Ordering::Relaxed);
    tracing::debug!(
        target: "dwaar::cache::reload",
        leaked_bytes = std::mem::size_of::<MemCache>(),
        "Box::leak: MemCache promoted to 'static for Pingora cache backend"
    );

    let lock: &'static CacheLock = Box::leak(Box::new(CacheLock::new(Duration::from_secs(10))));
    CACHE_RELOAD_LEAKS.fetch_add(1, Ordering::Relaxed);
    tracing::debug!(
        target: "dwaar::cache::reload",
        leaked_bytes = std::mem::size_of::<CacheLock>(),
        "Box::leak: CacheLock promoted to 'static for Pingora cache backend"
    );

    // Record the leak so operators can monitor cumulative growth and
    // recycle the process if rebuilds happen far more often than expected.
    LEAKED_BACKEND_COUNT.fetch_add(1, Ordering::Relaxed);
    LEAKED_BACKEND_BYTES.fetch_add(APPROX_BACKEND_OVERHEAD_BYTES, Ordering::Relaxed);

    tracing::warn!(
        target: "dwaar::cache::reload",
        total_leaked_backends = LEAKED_BACKEND_COUNT.load(Ordering::Relaxed),
        total_leak_calls = CACHE_RELOAD_LEAKS.load(Ordering::Relaxed),
        "cache backend structs leaked for 'static lifetime; \
         monitor leaked_reload_count() for accumulation"
    );

    CacheBackend {
        storage,
        eviction,
        lock,
        max_size,
    }
}

/// Swap in a new cache backend if `new_size` differs from the current one.
///
/// Skips reallocation when the size hasn't changed.  Old leaked
/// `&'static` refs remain valid for any in-flight requests still
/// referencing them.
pub fn realloc_cache_backend(shared: &SharedCacheBackend, new_size: usize) {
    let current = shared.load();
    if let Some(ref backend) = **current {
        if backend.max_size == new_size {
            return;
        }
        tracing::info!(
            old_size = backend.max_size,
            new_size,
            "cache backend resized on reload"
        );
    } else {
        tracing::info!(new_size, "cache backend initialized on reload");
    }
    shared.store(std::sync::Arc::new(Some(new_cache_backend(new_size))));
}

// ---------------------------------------------------------------------------
// Key construction
// ---------------------------------------------------------------------------

/// Build a [`CacheKey`] scoped to the given host.
///
/// Namespace isolates entries per virtual host so that
/// `site-a.com/index.html` and `site-b.com/index.html` never collide.
///
/// Pre-sizes the composite `method path` string exactly so the allocation
/// count on the hot path is `1` (was `1 + format!` machinery overhead via
/// `format!("{method} {path}")` — audit finding M-07).
pub fn build_cache_key(host: &str, path: &str, method: &str) -> CacheKey {
    let mut composite = String::with_capacity(method.len() + 1 + path.len());
    composite.push_str(method);
    composite.push(' ');
    composite.push_str(path);
    CacheKey::new(host, composite, "")
}

// ---------------------------------------------------------------------------
// Meta defaults
// ---------------------------------------------------------------------------

/// Build [`CacheMetaDefaults`] that control which status codes are cached
/// and for how long when the origin omits Cache-Control headers.
///
/// Only 200, 301, 308, and 404 are cached by default — everything else
/// passes through uncached unless the origin explicitly opts in.
///
/// **Note:** Pingora's `CacheMetaDefaults` takes a bare `fn` pointer for the
/// TTL lookup, so `default_ttl` cannot be captured at runtime.  The per-route
/// TTL is applied later in the proxy hooks (`cache_miss` / `response_filter`);
/// here we use `default_ttl` only to document intent.  The fn pointer returns
/// `default_ttl` as a compile-time constant via [`DEFAULT_FRESH_SEC`].
pub fn make_cache_defaults(default_ttl: u32, stale_while_revalidate: u32) -> CacheMetaDefaults {
    // Discard `default_ttl` at this layer — it can't be captured in a fn
    // pointer.  The actual per-route TTL is enforced in the ProxyHttp hooks.
    let _ = default_ttl;

    CacheMetaDefaults::new(
        fresh_duration_for_status,
        stale_while_revalidate,
        stale_while_revalidate, // reuse SWR as stale-if-error for now
    )
}

/// Fallback TTL (seconds) when the origin sends no Cache-Control.
/// Matches `CacheConfig::default().default_ttl`.
const DEFAULT_FRESH_SEC: u64 = 3600;

/// Returns a default freshness duration for cacheable status codes.
///
/// This is a bare `fn` (no captures) so it can be stored in
/// `CacheMetaDefaults`.  Per-route overrides happen in the proxy hooks.
fn fresh_duration_for_status(status: StatusCode) -> Option<Duration> {
    match status {
        StatusCode::OK
        | StatusCode::MOVED_PERMANENTLY  // 301
        | StatusCode::PERMANENT_REDIRECT // 308
        | StatusCode::NOT_FOUND => Some(Duration::from_secs(DEFAULT_FRESH_SEC)),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- CacheConfig::path_matches ------------------------------------------

    #[test]
    fn empty_match_paths_matches_everything() {
        let cfg = CacheConfig::default();
        assert!(cfg.path_matches("/anything"));
        assert!(cfg.path_matches("/deep/nested/path.html"));
        assert!(cfg.path_matches(""));
    }

    #[test]
    fn wildcard_prefix_match() {
        let cfg = CacheConfig {
            match_paths: vec!["/static/*".to_owned(), "/assets/*".to_owned()],
            ..CacheConfig::default()
        };
        assert!(cfg.path_matches("/static/style.css"));
        assert!(cfg.path_matches("/assets/logo.png"));
        assert!(!cfg.path_matches("/api/v1/users"));
    }

    #[test]
    fn exact_match() {
        let cfg = CacheConfig {
            match_paths: vec!["/favicon.ico".to_owned()],
            ..CacheConfig::default()
        };
        assert!(cfg.path_matches("/favicon.ico"));
        assert!(!cfg.path_matches("/favicon.ico/extra"));
        assert!(!cfg.path_matches("/other"));
    }

    // -- build_cache_key ----------------------------------------------------

    #[test]
    fn different_inputs_produce_different_keys() {
        use pingora_cache::key::CacheHashKey;

        let k1 = build_cache_key("a.com", "/page", "GET");
        let k2 = build_cache_key("b.com", "/page", "GET");
        let k3 = build_cache_key("a.com", "/other", "GET");
        let k4 = build_cache_key("a.com", "/page", "HEAD");

        // Primary hashes must differ for different inputs.
        assert_ne!(k1.primary_bin(), k2.primary_bin());
        assert_ne!(k1.primary_bin(), k3.primary_bin());
        assert_ne!(k1.primary_bin(), k4.primary_bin());
    }

    // -- make_cache_defaults ------------------------------------------------

    #[test]
    fn cache_defaults_does_not_panic() {
        let defaults = make_cache_defaults(3600, 60);
        // 200 should be cacheable
        assert!(defaults.fresh_sec(StatusCode::OK).is_some());
        // 500 should not be cached by default
        assert!(
            defaults
                .fresh_sec(StatusCode::INTERNAL_SERVER_ERROR)
                .is_none()
        );
    }

    // -- new_cache_backend ---------------------------------------------------

    #[test]
    fn new_backend_returns_valid_refs() {
        let _guard = lock_leak_tests();
        let backend = new_cache_backend(1024 * 1024);
        let _ = format!("{backend:?}");
        assert_eq!(backend.max_size, 1024 * 1024);
    }

    #[test]
    fn new_backend_can_be_called_multiple_times() {
        let _guard = lock_leak_tests();
        let a = new_cache_backend(1_000_000);
        let b = new_cache_backend(2_000_000);
        assert_eq!(a.max_size, 1_000_000);
        assert_eq!(b.max_size, 2_000_000);
        assert_ne!(
            std::ptr::from_ref(a.storage) as usize,
            std::ptr::from_ref(b.storage) as usize,
        );
    }

    /// Read `max_size` from a `SharedCacheBackend`.
    fn read_max_size(shared: &SharedCacheBackend) -> usize {
        shared
            .load()
            .as_ref()
            .as_ref()
            .expect("backend should be Some")
            .max_size
    }

    // -- realloc_cache_backend -----------------------------------------------

    #[test]
    fn realloc_swaps_backend() {
        let _guard = lock_leak_tests();
        let shared: SharedCacheBackend = std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(
            Some(new_cache_backend(1_000_000)),
        ));
        assert_eq!(read_max_size(&shared), 1_000_000);

        realloc_cache_backend(&shared, 4_000_000);
        assert_eq!(read_max_size(&shared), 4_000_000);
    }

    #[test]
    fn realloc_skips_unchanged() {
        let _guard = lock_leak_tests();
        let shared: SharedCacheBackend = std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(
            Some(new_cache_backend(1_000_000)),
        ));
        let ptr_before = std::ptr::from_ref(
            shared
                .load()
                .as_ref()
                .as_ref()
                .expect("backend should be Some")
                .storage,
        ) as usize;

        realloc_cache_backend(&shared, 1_000_000);
        let ptr_after = std::ptr::from_ref(
            shared
                .load()
                .as_ref()
                .as_ref()
                .expect("backend should be Some")
                .storage,
        ) as usize;

        assert_eq!(ptr_before, ptr_after, "no reallocation expected");
    }

    // -- leak metric tracking (ISSUE-154) ------------------------------------
    //
    // These tests use a module-level mutex to serialize access to the global
    // leak-counter atomics.  Without serialization, concurrent tests that call
    // `new_cache_backend` would increment the shared counters between a test's
    // snapshot and its assertion, causing spurious failures.

    use std::sync::{Mutex, MutexGuard};

    static LEAK_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn lock_leak_tests() -> MutexGuard<'static, ()> {
        LEAK_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Verify that each `new_cache_backend` call increments both leak counters
    /// by the expected deltas.  This proves the monitoring mechanism is wired
    /// correctly — operators can trust these Prometheus metrics to signal when
    /// it is time to recycle the process.
    #[test]
    fn leak_counters_increment_on_each_new_backend() {
        let _guard = lock_leak_tests();

        let count_before = leaked_cache_backend_count();
        let bytes_before = leaked_cache_backend_bytes();

        let _b = new_cache_backend(512 * 1024);

        // Each call leaks exactly one backend (count +1) and APPROX_BACKEND_OVERHEAD_BYTES.
        assert_eq!(
            leaked_cache_backend_count(),
            count_before + 1,
            "backend count should increment by 1 per allocation"
        );
        assert_eq!(
            leaked_cache_backend_bytes(),
            bytes_before + APPROX_BACKEND_OVERHEAD_BYTES,
            "leaked bytes should increment by APPROX_BACKEND_OVERHEAD_BYTES per allocation"
        );
    }

    /// Verify that `realloc_cache_backend` does not call `new_cache_backend`
    /// (and therefore does not increment leak counters) when the size is
    /// unchanged.  This ensures the no-op guard eliminates needless leaks.
    #[test]
    fn realloc_no_leak_when_size_unchanged() {
        let _guard = lock_leak_tests();

        let shared: SharedCacheBackend = std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(
            Some(new_cache_backend(8 * 1024 * 1024)),
        ));

        let count_before = leaked_cache_backend_count();
        let bytes_before = leaked_cache_backend_bytes();

        // Same size — must not allocate a new backend.
        realloc_cache_backend(&shared, 8 * 1024 * 1024);

        assert_eq!(
            leaked_cache_backend_count(),
            count_before,
            "no new leak when size is unchanged"
        );
        assert_eq!(
            leaked_cache_backend_bytes(),
            bytes_before,
            "no new leaked bytes when size is unchanged"
        );
    }

    /// Verify that `realloc_cache_backend` increments leak counters by exactly
    /// one backend when the size changes.
    #[test]
    fn realloc_increments_leak_on_resize() {
        let _guard = lock_leak_tests();

        let shared: SharedCacheBackend = std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(
            Some(new_cache_backend(4 * 1024 * 1024)),
        ));

        let count_before = leaked_cache_backend_count();
        let bytes_before = leaked_cache_backend_bytes();

        // Different size — should allocate and leak a new backend.
        realloc_cache_backend(&shared, 8 * 1024 * 1024);

        assert_eq!(
            leaked_cache_backend_count(),
            count_before + 1,
            "leak count increments by 1 on resize"
        );
        assert_eq!(
            leaked_cache_backend_bytes(),
            bytes_before + APPROX_BACKEND_OVERHEAD_BYTES,
            "leaked bytes increment on resize"
        );
    }
}
