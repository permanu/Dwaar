// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Shared wasmtime `Engine` for all WASM plugins.
//!
//! One `Engine` is created at startup and shared (via `Arc`) across every
//! plugin and every worker thread. wasmtime's `Engine` is `Send + Sync` and
//! caches compiled code — re-use is essential for performance.
//!
//! Engine configuration:
//! - **Component model** enabled — plugins are wasmtime components built from
//!   WIT definitions (see `bindings.rs`). Host function callbacks tracked in
//!   ISSUE-097.
//! - **Fuel metering** enabled — lets us enforce per-call instruction budgets.
//! - **Epoch interruption** enabled — lets us enforce wall-clock timeouts.
//! - **Async** disabled — plugin hooks are synchronous (called from
//!   Pingora's synchronous filter methods).

use std::sync::Arc;

use thiserror::Error;
use wasmtime::Config;

use super::limits::EpochTicker;

/// Errors that can occur when building the shared engine.
#[derive(Debug, Error)]
pub enum EngineError {
    /// wasmtime rejected the engine configuration.
    #[error("failed to create WASM engine: {0}")]
    Config(#[from] wasmtime::Error),
}

/// The shared wasmtime engine, plus the background epoch-ticker task.
///
/// Clone the `Arc<wasmtime::Engine>` to share it across threads — do NOT
/// create multiple `WasmEngine` instances.
///
/// Drop `WasmEngine` to stop the epoch ticker and clean up.
#[derive(Debug)]
pub struct WasmEngine {
    /// The underlying wasmtime engine (cheap to clone — reference-counted internally).
    pub engine: Arc<wasmtime::Engine>,
    /// Drives epoch interruption — must stay alive as long as the engine runs.
    _ticker: EpochTicker,
}

impl WasmEngine {
    /// Build the shared engine with fuel + epoch interruption enabled.
    ///
    /// Spawns the epoch-ticker background task. Must be called inside a
    /// Tokio runtime (Pingora's `run_forever` satisfies this in production;
    /// `#[tokio::test]` satisfies it in tests).
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Config`] if wasmtime rejects the configuration
    /// (e.g. unsupported CPU target). This should not happen on any
    /// reasonably modern x86-64 or aarch64 host.
    pub fn new() -> Result<Self, EngineError> {
        let mut cfg = Config::new();

        // Fuel metering — wasmtime deducts fuel per instruction.
        // Exhaustion traps the store (fail-open: host continues).
        cfg.consume_fuel(true);

        // Epoch interruption — background task ticks every 1 ms.
        // Each store sets its deadline via `set_epoch_deadline`.
        cfg.epoch_interruption(true);

        // Use Cranelift for native-speed compilation of Wasm modules.
        // Modules are compiled once and cached in the engine.
        cfg.strategy(wasmtime::Strategy::Cranelift);

        let engine = wasmtime::Engine::new(&cfg)?;
        let engine = Arc::new(engine);

        // Spawn the epoch ticker — passes a clone of the engine handle.
        let ticker = EpochTicker::spawn((*engine).clone());

        Ok(Self {
            engine,
            _ticker: ticker,
        })
    }
}
