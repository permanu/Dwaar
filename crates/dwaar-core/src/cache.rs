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
//! One process-lifetime backend satisfies Pingora's static-reference API.
//! Reloads retain that backend. Capacity changes require a controlled restart;
//! they never abandon a populated cache or allocate another backend.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use http::StatusCode;
use pingora_cache::eviction::lru::Manager as LruManager;
use pingora_cache::lock::CacheLock;
use pingora_cache::{CacheKey, CacheMetaDefaults, MemCache};

static PROCESS_CACHE: OnceLock<CacheBackend> = OnceLock::new();
static LEAKED_BACKEND_COUNT: AtomicU64 = AtomicU64::new(0);
static LEAKED_BACKEND_BYTES: AtomicU64 = AtomicU64::new(0);
static CACHE_RELOAD_LEAKS: AtomicU64 = AtomicU64::new(0);
const BACKEND_CONTROL_STRUCT_BYTES: u64 = (std::mem::size_of::<MemCache>()
    + std::mem::size_of::<LruManager<16>>()
    + std::mem::size_of::<CacheLock>()) as u64;

/// Legacy allocation counter. It is bounded to one backend per process.
pub fn leaked_cache_backend_count() -> u64 {
    LEAKED_BACKEND_COUNT.load(Ordering::Relaxed)
}
/// Inline control structs only; this is not a resident-memory estimate.
/// Use `cache_admitted_bytes` for the live eviction-accounted cache contents.
pub fn leaked_cache_backend_bytes() -> u64 {
    LEAKED_BACKEND_BYTES.load(Ordering::Relaxed)
}
/// Legacy static allocation count, bounded to three per process.
pub fn leaked_reload_count() -> u64 {
    CACHE_RELOAD_LEAKS.load(Ordering::Relaxed)
}

pub fn cache_admitted_bytes() -> usize {
    use pingora_cache::eviction::EvictionManager;
    PROCESS_CACHE
        .get()
        .map_or(0, |backend| backend.eviction.total_size())
}

pub fn cache_capacity_bytes() -> usize {
    PROCESS_CACHE.get().map_or(0, |backend| backend.max_size)
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
/// On reload, [`realloc_cache_backend`] rejects a changed capacity.
/// Consumers continue to use the original storage until process restart.
pub type SharedCacheBackend = std::sync::Arc<arc_swap::ArcSwap<Option<CacheBackend>>>;

/// Return the single process-lifetime backend. The first initialization fixes
/// its capacity; subsequent calls retain the same storage and health of cache.
pub fn new_cache_backend(max_size: usize) -> CacheBackend {
    *PROCESS_CACHE.get_or_init(|| {
        let eviction = Box::leak(Box::new(LruManager::<16>::with_capacity(max_size, 1024)));
        let storage = Box::leak(Box::new(MemCache::new()));
        let lock = Box::leak(Box::new(CacheLock::new(Duration::from_secs(10))));
        LEAKED_BACKEND_COUNT.store(1, Ordering::Relaxed);
        LEAKED_BACKEND_BYTES.store(BACKEND_CONTROL_STRUCT_BYTES, Ordering::Relaxed);
        CACHE_RELOAD_LEAKS.store(3, Ordering::Relaxed);
        CacheBackend {
            storage,
            eviction,
            lock,
            max_size,
        }
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheRestartRequired {
    pub active_size: usize,
    pub requested_size: usize,
}

/// Capacity is immutable. A first enable can initialize the single backend;
/// a later capacity change is rejected without replacing populated storage.
pub fn realloc_cache_backend(
    shared: &SharedCacheBackend,
    new_size: usize,
) -> Result<(), CacheRestartRequired> {
    let current = shared.load();
    if let Some(backend) = **current {
        return if backend.max_size == new_size {
            Ok(())
        } else {
            Err(CacheRestartRequired {
                active_size: backend.max_size,
                requested_size: new_size,
            })
        };
    }
    let backend = new_cache_backend(new_size);
    if backend.max_size != new_size {
        return Err(CacheRestartRequired {
            active_size: backend.max_size,
            requested_size: new_size,
        });
    }
    shared.store(std::sync::Arc::new(Some(backend)));
    Ok(())
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
    let mut composite = String::with_capacity(method.len() + 4 + path.len());
    composite.push_str("v2 ");
    composite.push_str(method);
    composite.push(' ');
    composite.push_str(path);
    CacheKey::new(host, composite, "")
}

/// Credential-bearing requests bypass both lookup and admission.
pub fn request_may_use_shared_cache(headers: &http::HeaderMap) -> bool {
    if headers.contains_key("authorization") || headers.contains_key("cookie") {
        return false;
    }
    if headers.get_all("pragma").iter().any(|value| {
        value.to_str().is_ok_and(|value| {
            value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("no-cache"))
        })
    }) {
        return false;
    }
    pingora_cache::cache_control::CacheControl::from_headers_named("cache-control", headers)
        .is_none_or(|control| {
            !control.has_key("no-store")
                && !control.has_key("no-cache")
                && control.max_age().ok().flatten() != Some(0)
        })
}

/// Until variant keys are supported, Vary and Set-Cookie responses are never
/// admitted. Origin freshness takes precedence over the configured fallback.
pub fn cache_response(
    response: &pingora_http::ResponseHeader,
    config: &CacheConfig,
) -> pingora_cache::RespCacheable {
    use pingora_cache::cache_control::CacheControl;
    use pingora_cache::{CacheMeta, NoCacheReason, RespCacheable};
    let refused = || RespCacheable::Uncacheable(NoCacheReason::OriginNotCache);
    if response.headers.contains_key("vary") || response.headers.contains_key("set-cookie") {
        return refused();
    }
    let control = CacheControl::from_resp_headers(response.as_ref());
    if control.as_ref().is_some_and(|control| {
        control.has_key("no-store") || control.has_key("private") || control.has_key("no-cache")
    }) {
        return refused();
    }
    let defaults = make_cache_defaults(config.default_ttl, config.stale_while_revalidate);
    let result = pingora_cache::filters::resp_cacheable(
        control.as_ref(),
        response.clone(),
        false,
        &defaults,
    );
    let RespCacheable::Cacheable(meta) = result else {
        return result;
    };
    let origin_ttl = control
        .as_ref()
        .is_some_and(|control| control.has_key("max-age") || control.has_key("s-maxage"))
        || response.headers.contains_key("expires");
    let mut ttl = if origin_ttl {
        meta.fresh_sec()
    } else {
        u64::from(config.default_ttl)
    };
    if !response.headers.contains_key("expires")
        && let Some(age) = response.headers.get("age")
    {
        let Ok(age) = age.to_str().unwrap_or("").parse::<u64>() else {
            return refused();
        };
        ttl = ttl.saturating_sub(age);
    }
    if ttl == 0 {
        return refused();
    }
    let Some(fresh_until) = meta.created().checked_add(Duration::from_secs(ttl)) else {
        return refused();
    };
    RespCacheable::Cacheable(CacheMeta::new(
        fresh_until,
        meta.created(),
        meta.stale_while_revalidate_sec(),
        meta.stale_if_error_sec(),
        meta.response_header_copy(),
    ))
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

    #[test]
    fn credential_and_variant_responses_are_never_shared() {
        let config = CacheConfig::default();
        for name in ["authorization", "cookie"] {
            let mut request = http::HeaderMap::new();
            request.insert(name, http::HeaderValue::from_static("fixture"));
            assert!(!request_may_use_shared_cache(&request));
        }
        for name in ["set-cookie", "vary"] {
            let mut response = pingora_http::ResponseHeader::build(200, None).expect("response");
            response.insert_header(name, "fixture").expect("header");
            assert!(matches!(
                cache_response(&response, &config),
                pingora_cache::RespCacheable::Uncacheable(_)
            ));
        }
    }

    #[test]
    fn configured_default_ttl_is_applied_to_metadata() {
        let response = pingora_http::ResponseHeader::build(200, None).expect("response");
        let config = CacheConfig {
            default_ttl: 7,
            ..CacheConfig::default()
        };
        let pingora_cache::RespCacheable::Cacheable(meta) = cache_response(&response, &config)
        else {
            panic!("cacheable response refused")
        };
        assert_eq!(meta.fresh_sec(), 7);
    }

    #[test]
    fn origin_ttl_and_age_are_respected_and_private_directives_are_refused() {
        let config = CacheConfig {
            default_ttl: 7,
            ..CacheConfig::default()
        };
        for control in [
            "private",
            "private=\"x-private\"",
            "no-cache",
            "no-store",
            "max-age=0",
        ] {
            let mut response = pingora_http::ResponseHeader::build(200, None).expect("response");
            response
                .insert_header("cache-control", control)
                .expect("header");
            assert!(matches!(
                cache_response(&response, &config),
                pingora_cache::RespCacheable::Uncacheable(_)
            ));
        }
        let mut response = pingora_http::ResponseHeader::build(200, None).expect("response");
        response
            .insert_header("cache-control", "public, max-age=10")
            .expect("header");
        response.insert_header("age", "3").expect("header");
        let pingora_cache::RespCacheable::Cacheable(meta) = cache_response(&response, &config)
        else {
            panic!("cacheable response")
        };
        assert_eq!(meta.fresh_sec(), 7);
    }

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

    #[test]
    fn process_backend_is_shared_and_resize_is_refused() {
        let first = new_cache_backend(1024 * 1024);
        let second = new_cache_backend(first.max_size + 1);
        assert!(std::ptr::eq(first.storage, second.storage));
        assert_eq!(first.max_size, second.max_size);
        assert_eq!(leaked_cache_backend_count(), 1);
        assert_eq!(leaked_reload_count(), 3);
        assert_eq!(leaked_cache_backend_bytes(), BACKEND_CONTROL_STRUCT_BYTES);
        let shared: SharedCacheBackend =
            std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(Some(first)));
        assert!(realloc_cache_backend(&shared, first.max_size).is_ok());
        for offset in 1..100 {
            assert!(realloc_cache_backend(&shared, first.max_size + offset).is_err());
            assert!(std::ptr::eq(
                shared.load().as_ref().as_ref().expect("backend").storage,
                first.storage
            ));
        }
        assert_eq!(leaked_cache_backend_count(), 1);
    }
}
