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

use std::time::Duration;

use http::StatusCode;
use pingora_cache::eviction::lru::Manager as LruManager;
use pingora_cache::lock::CacheLock;
use pingora_cache::{CacheKey, CacheMetaDefaults, MemCache};

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
pub fn new_cache_backend(max_size: usize) -> CacheBackend {
    let eviction = Box::leak(Box::new(LruManager::<16>::with_capacity(max_size, 1024)));
    let storage = Box::leak(Box::new(MemCache::new()));
    let lock = Box::leak(Box::new(CacheLock::new(Duration::from_secs(10))));

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
pub fn build_cache_key(host: &str, path: &str, method: &str) -> CacheKey {
    CacheKey::new(host, format!("{method} {path}"), "")
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
        let backend = new_cache_backend(1024 * 1024);
        let _ = format!("{backend:?}");
        assert_eq!(backend.max_size, 1024 * 1024);
    }

    #[test]
    fn new_backend_can_be_called_multiple_times() {
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
        let shared: SharedCacheBackend =
            std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(Some(new_cache_backend(
                1_000_000,
            ))));
        assert_eq!(read_max_size(&shared), 1_000_000);

        realloc_cache_backend(&shared, 4_000_000);
        assert_eq!(read_max_size(&shared), 4_000_000);
    }

    #[test]
    fn realloc_skips_unchanged() {
        let shared: SharedCacheBackend =
            std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(Some(new_cache_backend(
                1_000_000,
            ))));
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
}
