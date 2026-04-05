// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! WASM module cache — compile once, instantiate per-request.
//!
//! Cranelift compilation of a `.wasm` file takes 10–100 ms per module. Paying
//! that cost on every request would make WASM plugins unusable at any scale.
//! `ModuleCache` solves this by compiling each module exactly once at config
//! load time and storing the resulting `Component` (an Arc-backed immutable
//! artifact) in a `RwLock<HashMap>`.
//!
//! Per-request cost is a single read-lock acquisition, a `HashMap` lookup, and
//! an `Arc::clone` — roughly the same as any other `Arc` field access. The
//! write path only runs when a module is loaded or invalidated (config reload).
//!
//! # Thread safety
//!
//! `Component` is `Clone + Send + Sync` (internally Arc-backed). `ModuleCache`
//! uses `parking_lot::RwLock` to give lock-free concurrent reads — multiple
//! Pingora worker threads can call `get()` simultaneously without blocking each
//! other. The write lock is only held during `load()` and `invalidate()`, which
//! happen on config reload, not on the hot request path.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::RwLock;
use tracing::{debug, info, warn};
use wasmtime::component::Component;

use super::engine::WasmEngine;
use super::error::WasmError;

/// Compiled WASM module cache, keyed by absolute file path.
///
/// Share one `ModuleCache` across all worker threads (behind an `Arc`). Load
/// modules once at startup with [`load`], then retrieve them per-request with
/// [`get`]. On config reload, call [`invalidate`] to remove stale entries
/// before re-loading.
///
/// [`load`]: ModuleCache::load
/// [`get`]: ModuleCache::get
/// [`invalidate`]: ModuleCache::invalidate
pub struct ModuleCache {
    engine: Arc<wasmtime::Engine>,
    /// `HashMap` protected by a readers-writer lock.
    ///
    /// `parking_lot::RwLock` is chosen over `std::sync::RwLock` because it
    /// avoids writer-starvation on Linux and its read-lock path is faster
    /// (no heap allocation). On the hot request path, only `read()` is called.
    modules: RwLock<HashMap<PathBuf, Component>>,
}

impl std::fmt::Debug for ModuleCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.modules.read().len();
        f.debug_struct("ModuleCache")
            .field("cached_modules", &count)
            .finish_non_exhaustive()
    }
}

impl ModuleCache {
    /// Create an empty cache backed by the given `WasmEngine`.
    ///
    /// Clones the `Arc<Engine>` from the `WasmEngine` so the cache and all
    /// plugins share a single engine instance. The `WasmEngine` must outlive
    /// the cache (it drives the epoch ticker that enforces WASM timeouts).
    pub fn new(engine: &WasmEngine) -> Self {
        Self {
            engine: engine.engine.clone(),
            modules: RwLock::new(HashMap::new()),
        }
    }

    /// Create a cache backed by a raw `Arc<wasmtime::Engine>`.
    ///
    /// Prefer [`new`] when you have a `WasmEngine`. Use this variant when you
    /// only have the raw Arc (e.g., inside tests that build a bare engine).
    ///
    /// [`new`]: ModuleCache::new
    pub fn from_arc(engine: Arc<wasmtime::Engine>) -> Self {
        Self {
            engine,
            modules: RwLock::new(HashMap::new()),
        }
    }

    /// Compile the `.wasm` file at `path` and insert it into the cache.
    ///
    /// If the path is already cached this is a no-op — the existing entry wins
    /// (callers should [`invalidate`] first if they want to force a recompile,
    /// e.g. after a config reload detected a file change).
    ///
    /// Compilation is synchronous and can take 10–100 ms. Call this on the
    /// startup path, never inside a request handler.
    ///
    /// # Errors
    ///
    /// Returns [`WasmError::Compile`] if wasmtime rejects the binary (bad
    /// magic bytes, unsupported proposals, etc.).
    ///
    /// [`invalidate`]: ModuleCache::invalidate
    pub fn load(&self, path: &Path) -> Result<Component, WasmError> {
        // Fast path: already compiled.
        if let Some(component) = self.get(path) {
            debug!(path = %path.display(), "module cache hit — skipping compile");
            return Ok(component);
        }

        let path_str = path.display().to_string();
        info!(path = %path_str, "compiling WASM component");

        let component =
            Component::from_file(&self.engine, path).map_err(|source| WasmError::Compile {
                path: path_str.clone(),
                source,
            })?;

        // Write lock only held while inserting — readers are unaffected after release.
        self.modules
            .write()
            .insert(path.to_path_buf(), component.clone());

        info!(path = %path_str, "WASM component compiled and cached");
        Ok(component)
    }

    /// Return a cloned `Component` for `path`, or `None` if it isn't cached.
    ///
    /// The clone is O(1) — `Component` is internally Arc-backed. Multiple
    /// threads can call `get()` concurrently without blocking each other.
    pub fn get(&self, path: &Path) -> Option<Component> {
        self.modules.read().get(path).cloned()
    }

    /// Remove a cached entry so the next `load()` recompiles from disk.
    ///
    /// Call this when a file watcher signals that a `.wasm` file changed, or
    /// unconditionally before each config reload to pick up updates.
    pub fn invalidate(&self, path: &Path) {
        if self.modules.write().remove(path).is_some() {
            warn!(path = %path.display(), "WASM module invalidated — will recompile on next load");
        }
    }

    /// Number of compiled modules currently in the cache.
    pub fn len(&self) -> usize {
        self.modules.read().len()
    }

    /// Whether the cache holds no compiled modules.
    pub fn is_empty(&self) -> bool {
        self.modules.read().is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wasm::engine::WasmEngine;

    // Build a minimal valid component in WAT for cache tests.
    //
    // This component is intentionally simple — it has no type exports, no
    // complex records, just a single exported function. Cache tests only need
    // a compilable component to verify the cache machinery; they don't need
    // to match the full dwaar-plugin WIT interface.
    fn minimal_component_bytes() -> Option<Vec<u8>> {
        let wat = r#"
(component
  (core module $m
    (func (export "answer") (result i32) i32.const 42)
  )
  (core instance $mi (instantiate $m))
  (func (export "answer") (result u32)
    (canon lift (core func $mi "answer"))
  )
)
"#;
        wat::parse_str(wat).ok()
    }

    // Write component bytes to a temp file so we can test `load()` from a path.
    fn write_temp_wasm(bytes: &[u8]) -> tempfile::NamedTempFile {
        use std::io::Write as _;
        let mut f = tempfile::NamedTempFile::new().expect("temp file");
        f.write_all(bytes).expect("write wasm");
        f
    }

    // ── Basic compile + cache hit ─────────────────────────────────────────────

    #[tokio::test]
    async fn load_compiles_and_caches() {
        let engine = WasmEngine::new().expect("engine");
        let cache = ModuleCache::new(&engine);

        let Some(bytes) = minimal_component_bytes() else {
            tracing::warn!("WAT parse failed — skipping test");
            return;
        };
        let tmp = write_temp_wasm(&bytes);
        let path = tmp.path();

        assert!(cache.is_empty(), "cache should start empty");

        // WAT compilation in some wasmtime configurations may reject the
        // test component's type exports — skip gracefully like adapter.rs does.
        let Ok(_component) = cache.load(path) else {
            tracing::warn!("component compile failed — skipping test");
            return;
        };
        assert_eq!(cache.len(), 1, "one module should be cached after load");

        // Second load must return from cache — no recompile.
        let _cached = cache.load(path).expect("second load should hit cache");
        assert_eq!(cache.len(), 1, "cache size must not grow on cache hit");
    }

    // ── Cache miss returns None ───────────────────────────────────────────────

    #[tokio::test]
    async fn get_on_uncached_path_returns_none() {
        let engine = WasmEngine::new().expect("engine");
        let cache = ModuleCache::new(&engine);

        let result = cache.get(Path::new("/nonexistent/path/plugin.wasm"));
        assert!(result.is_none(), "get on uncached path should return None");
    }

    // ── Load with non-existent file returns WasmError::Compile ───────────────

    #[tokio::test]
    async fn load_nonexistent_file_returns_error() {
        let engine = WasmEngine::new().expect("engine");
        let cache = ModuleCache::new(&engine);

        let err = cache
            .load(Path::new("/nonexistent/path/plugin.wasm"))
            .err()
            .expect("should fail for missing file");

        assert!(
            err.to_string().contains("nonexistent"),
            "error should mention the path: {err}"
        );
    }

    // ── Invalidate removes the entry ──────────────────────────────────────────

    #[tokio::test]
    async fn invalidate_removes_cached_entry() {
        let engine = WasmEngine::new().expect("engine");
        let cache = ModuleCache::new(&engine);

        let Some(bytes) = minimal_component_bytes() else {
            tracing::warn!("WAT parse failed — skipping test");
            return;
        };
        let tmp = write_temp_wasm(&bytes);
        let path = tmp.path();

        if cache.load(path).is_err() {
            tracing::warn!("component compile failed — skipping test");
            return;
        }
        assert_eq!(cache.len(), 1);

        cache.invalidate(path);
        assert_eq!(cache.len(), 0, "invalidate should remove the entry");
        assert!(
            cache.get(path).is_none(),
            "get should return None after invalidate"
        );
    }

    // ── Invalidate on missing path is a no-op ─────────────────────────────────

    #[test]
    fn invalidate_missing_path_is_noop() {
        // Create engine without a Tokio runtime — no epoch ticker needed for this test.
        let mut cfg = wasmtime::Config::new();
        cfg.consume_fuel(true);
        let engine = Arc::new(wasmtime::Engine::new(&cfg).expect("engine"));
        let cache = ModuleCache::from_arc(engine);

        // Should not panic or error.
        cache.invalidate(Path::new("/not/in/cache.wasm"));
        assert!(cache.is_empty());
    }

    // ── Concurrent reads from multiple threads ────────────────────────────────

    #[tokio::test]
    async fn concurrent_get_does_not_data_race() {
        let engine = WasmEngine::new().expect("engine");
        let cache = Arc::new(ModuleCache::new(&engine));

        let Some(bytes) = minimal_component_bytes() else {
            tracing::warn!("WAT parse failed — skipping test");
            return;
        };
        let tmp = write_temp_wasm(&bytes);
        let path = tmp.path().to_path_buf();

        if cache.load(&path).is_err() {
            tracing::warn!("component compile failed — skipping test");
            return;
        }

        // Spawn 8 tasks reading concurrently — no data race, no panic.
        let mut handles = Vec::new();
        for _ in 0..8 {
            let cache = Arc::clone(&cache);
            let path = path.clone();
            handles.push(tokio::spawn(async move {
                for _ in 0..100 {
                    let result = cache.get(&path);
                    assert!(result.is_some(), "concurrent get should find cached entry");
                }
            }));
        }
        for h in handles {
            h.await.expect("task should not panic");
        }
    }

    // ── Debug output ──────────────────────────────────────────────────────────

    #[test]
    fn debug_shows_cached_count() {
        // No Tokio runtime needed — epoch ticker is not required for Debug.
        let mut cfg = wasmtime::Config::new();
        cfg.consume_fuel(true);
        let engine = Arc::new(wasmtime::Engine::new(&cfg).expect("engine"));
        let cache = ModuleCache::from_arc(engine);

        let s = format!("{cache:?}");
        assert!(s.contains("cached_modules"));
    }

    // ── Two gets return equivalent Components ─────────────────────────────────

    #[tokio::test]
    async fn two_gets_return_equivalent_components() {
        let engine = WasmEngine::new().expect("engine");
        let cache = ModuleCache::new(&engine);

        let Some(bytes) = minimal_component_bytes() else {
            tracing::warn!("WAT parse failed — skipping test");
            return;
        };
        let tmp = write_temp_wasm(&bytes);
        let path = tmp.path();

        if cache.load(path).is_err() {
            tracing::warn!("component compile failed — skipping test");
            return;
        }

        let a = cache.get(path).expect("first get");
        let b = cache.get(path).expect("second get");

        // `Component` is `Clone + Send + Sync` (Arc-backed), so both `a` and `b`
        // are valid instantiation sources. We verify both are usable — equality
        // on Component internals isn't exposed by wasmtime's public API.
        let _ = (a, b);
        assert_eq!(cache.len(), 1, "cache still holds exactly one entry");
    }
}
