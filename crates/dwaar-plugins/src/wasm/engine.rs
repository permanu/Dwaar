// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Wasmtime engine initialization and configuration.
//!
//! [`WasmEngine`] wraps [`wasmtime::Engine`] with the settings required for
//! Dwaar's plugin runtime. Create one instance at startup and share it across
//! all worker threads — `Engine` is internally `Arc`'d so cloning is cheap.

use thiserror::Error;
use wasmtime::{Config, Engine, OptLevel};

/// Errors that can occur while initializing the WASM engine.
#[derive(Debug, Error)]
pub enum EngineError {
    /// Wasmtime rejected the engine configuration.
    ///
    /// This should not happen with our fixed config; it indicates a build
    /// environment incompatibility (e.g., unsupported CPU feature).
    #[error("failed to create wasmtime engine: {0}")]
    Init(String),
}

/// Wasmtime engine configured for Dwaar's plugin runtime.
///
/// Shared across all Pingora worker threads. [`wasmtime::Engine`] is
/// internally reference-counted so `clone()` increments a counter — it does
/// not duplicate compilation state.
#[derive(Clone)]
pub struct WasmEngine {
    inner: Engine,
}

impl std::fmt::Debug for WasmEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Engine has no public debug representation; surface what matters.
        f.debug_struct("WasmEngine").finish_non_exhaustive()
    }
}

impl WasmEngine {
    /// Build a new engine with Dwaar's required settings.
    ///
    /// Call once at process startup, then share the returned value via `Arc`
    /// or by cloning (both are O(1)).
    ///
    /// # Configuration
    ///
    /// - **Speed optimisation** — Cranelift compiles modules at `Speed` level
    ///   so hot plugin paths run at near-native throughput.
    /// - **Component model** — required for WIT-based plugins that use typed
    ///   imports/exports across language boundaries.
    /// - **Epoch interruption** — lets the proxy cancel runaway plugins by
    ///   incrementing the engine epoch from a background task.
    /// - **1 MB memory reservation** — pre-maps virtual address space for the
    ///   default linear memory so the first growth doesn't fault on a hot path.
    pub fn new() -> Result<Self, EngineError> {
        let mut config = Config::new();

        // Cranelift at `Speed` trades slightly longer compile time for faster
        // execution. Modules are compiled once at load time, not per request.
        config.cranelift_opt_level(OptLevel::Speed);

        // Component model is mandatory: plugins are distributed as `.wasm`
        // components with typed WIT interfaces, not raw core modules.
        config.wasm_component_model(true);

        // Epoch interruption is the recommended way to time-limit WASM guests
        // in wasmtime. The proxy increments the epoch on a timer; guests that
        // exceed their budget are trapped instead of blocking the thread.
        config.epoch_interruption(true);

        // Reserve 1 MB of virtual address space up front. Linear memory grows
        // in page-sized increments; pre-mapping avoids a mmap fault on the
        // first allocation in the common path.
        config.memory_reservation(1 << 20);

        let engine = Engine::new(&config).map_err(|e| EngineError::Init(e.to_string()))?;

        Ok(Self { inner: engine })
    }

    /// Return a reference to the underlying [`wasmtime::Engine`].
    ///
    /// Pass this to [`wasmtime::component::Component::new`] when compiling a
    /// plugin module, and to [`wasmtime::Store::new`] when instantiating one.
    pub fn engine(&self) -> &Engine {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_creation_succeeds() {
        WasmEngine::new().expect("engine should initialise with valid config");
    }

    /// `Clone` must compile and both handles must remain independently usable.
    ///
    /// The compile-time check (implicit in the bound below) is what matters;
    /// the runtime check confirms neither clone panics.
    #[test]
    fn engine_is_clone() {
        fn requires_clone<T: Clone>(v: &T) -> T {
            v.clone()
        }
        let a = WasmEngine::new().expect("engine init");
        let b = requires_clone(&a);
        // Both handles must be usable after cloning.
        let _: &Engine = a.engine();
        let _: &Engine = b.engine();
    }

    #[test]
    fn engine_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<WasmEngine>();
    }

    #[test]
    fn engine_accessor_returns_inner() {
        let e = WasmEngine::new().expect("engine init");
        // Verify the accessor compiles and returns something we can use —
        // the real proof is that module compilation later will succeed.
        let _inner: &Engine = e.engine();
    }

    /// Verify epoch interruption is active by confirming `increment_epoch`
    /// exists and doesn't panic — it's a no-op if interruption is disabled,
    /// but it's part of the public API regardless.
    ///
    /// The real enforcement test lives in the store/instance layer (ISSUE-096),
    /// where a deadline is set and a trapped guest confirms the mechanism works
    /// end-to-end.
    #[test]
    fn epoch_interruption_configured() {
        let e = WasmEngine::new().expect("engine init");
        // `increment_epoch` is always safe to call; we just confirm the engine
        // was built without panicking and the method is reachable.
        e.engine().increment_epoch();
    }

    /// Verify the component model is enabled by compiling a minimal WAT
    /// component. A core module would succeed either way; a component (with
    /// the `(component ...)` form) requires the feature to be on.
    #[test]
    fn component_model_enabled() {
        let e = WasmEngine::new().expect("engine init");

        // Minimal valid WAT component — empty, no imports, no exports.
        let wat = "(component)";
        let result = wasmtime::component::Component::new(e.engine(), wat.as_bytes());
        assert!(
            result.is_ok(),
            "component compilation failed — component model may not be enabled"
        );
    }
}
