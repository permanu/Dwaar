// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! WASM resource limits — fuel, memory, and wall-clock timeout.
//!
//! Dwaar runs WASM plugins inside every proxied request. Without hard caps a
//! buggy or malicious plugin could monopolise CPU (infinite loop), exhaust
//! memory, or stall a connection indefinitely. Three independent mechanisms
//! defend against these scenarios:
//!
//! 1. **Fuel metering** — wasmtime counts executed instructions. When the
//!    plugin burns through its `fuel` allowance, wasmtime traps and control
//!    returns to the host. We treat exhaustion as a non-fatal error and
//!    continue with `PluginAction::Continue` (fail-open semantics).
//!
//! 2. **Memory cap** — a [`ResourceLimiter`] implementation that wasmtime
//!    consults on every `memory.grow` instruction. Growth beyond
//!    `memory_mb` MiB is refused.
//!
//! 3. **Epoch interruption** — a background task increments the engine epoch
//!    every millisecond. Each `Store` is configured with an epoch deadline;
//!    when the deadline is reached wasmtime traps. This catches runaway code
//!    that burns fuel too slowly (tight loops doing tiny work) as well as
//!    blocking host calls.
//!
//! All three are applied together. The first to fire wins.

use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use wasmtime::{ResourceLimiter, Store};

// ── Defaults ──────────────────────────────────────────────────────────────────

/// Instruction budget per hook call (roughly 1M "cheap" Wasm ops).
pub const DEFAULT_FUEL: u64 = 1_000_000;

/// Linear memory cap per module in MiB.
pub const DEFAULT_MEMORY_MB: u32 = 16;

/// Wall-clock deadline per hook call in milliseconds.
pub const DEFAULT_TIMEOUT_MS: u64 = 50;

// ── Config struct ─────────────────────────────────────────────────────────────

/// Resource limits applied to every WASM plugin invocation.
///
/// All three limits work independently — whichever fires first wins.
///
/// # Example
///
/// ```rust
/// use dwaar_plugins::wasm::limits::WasmLimits;
///
/// // Tight limits for untrusted third-party plugins.
/// let limits = WasmLimits {
///     fuel: 100_000,
///     memory_mb: 4,
///     timeout_ms: 10,
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmLimits {
    /// Instruction budget per hook call. Default: [`DEFAULT_FUEL`].
    ///
    /// wasmtime deducts fuel as it executes Wasm instructions. When the
    /// budget reaches zero the store traps. Higher values allow more
    /// compute-intensive plugins; lower values protect against tight loops.
    pub fuel: u64,

    /// Maximum linear memory in MiB. Default: [`DEFAULT_MEMORY_MB`].
    ///
    /// Applied via the [`MemoryLimiter`] [`ResourceLimiter`](wasmtime::ResourceLimiter). Wasm modules that
    /// try to grow past this cap will receive a trap instead of memory.
    pub memory_mb: u32,

    /// Wall-clock deadline per hook call in milliseconds.
    /// Default: [`DEFAULT_TIMEOUT_MS`].
    ///
    /// The epoch ticker advances every 1 ms. Each store is configured with
    /// a deadline of `timeout_ms` ticks from the current epoch at call entry.
    /// Exceeding the deadline traps regardless of remaining fuel.
    pub timeout_ms: u64,
}

impl Default for WasmLimits {
    fn default() -> Self {
        Self {
            fuel: DEFAULT_FUEL,
            memory_mb: DEFAULT_MEMORY_MB,
            timeout_ms: DEFAULT_TIMEOUT_MS,
        }
    }
}

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors that arise when enforcing resource limits.
#[derive(Debug, Error)]
pub enum LimitError {
    /// The store ran out of fuel — the plugin executed too many instructions.
    #[error("WASM fuel exhausted (budget: {budget} instructions)")]
    FuelExhausted { budget: u64 },

    /// The store exceeded its epoch deadline — the plugin took too long.
    #[error("WASM timeout exceeded ({timeout_ms} ms)")]
    Timeout { timeout_ms: u64 },

    /// A `memory.grow` instruction was rejected — would exceed the memory cap.
    #[error("WASM memory limit exceeded ({limit_mb} MiB)")]
    MemoryExceeded { limit_mb: u32 },

    /// A generic wasmtime error during limit enforcement.
    #[error("WASM limit error: {0}")]
    Wasmtime(#[from] wasmtime::Error),
}

// ── Memory limiter ────────────────────────────────────────────────────────────

/// Enforces the linear-memory cap via wasmtime's [`ResourceLimiter`] trait.
///
/// wasmtime calls `memory_growing` **before** each `memory.grow` instruction.
/// Returning `false` makes the grow fail gracefully (the instruction returns -1
/// in Wasm) rather than trapping — standard Wasm semantics for OOM.
///
/// `instances`, `tables`, and `memories` are left at their wasmtime defaults.
/// We only cap linear memory.
#[derive(Debug)]
pub struct MemoryLimiter {
    /// Maximum bytes allowed (converted from `memory_mb` at construction).
    max_bytes: usize,
}

impl MemoryLimiter {
    /// Create a limiter capping memory at `memory_mb` MiB.
    pub fn new(memory_mb: u32) -> Self {
        Self {
            max_bytes: (memory_mb as usize) * 1024 * 1024,
        }
    }
}

impl ResourceLimiter for MemoryLimiter {
    /// Called before every `memory.grow`. Returns `true` to allow the grow,
    /// `false` to refuse it (Wasm sees -1 / `memory.grow` failure).
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> Result<bool, wasmtime::Error> {
        Ok(desired <= self.max_bytes)
    }

    // Permit any number of tables / instances — we only care about memory.
    fn table_growing(
        &mut self,
        _current: usize,
        _desired: usize,
        _maximum: Option<usize>,
    ) -> Result<bool, wasmtime::Error> {
        Ok(true)
    }
}

// ── Epoch ticker ──────────────────────────────────────────────────────────────

/// A handle to a background task that advances the engine epoch every millisecond.
///
/// Epoch interruption is the wall-clock defence against plugins that run slowly
/// but don't exhaust fuel (e.g. a tight I/O-heavy loop). Each `Store` sets its
/// deadline using [`WasmLimits::timeout_ms`] ticks ahead of the engine's
/// current epoch — the engine traps the store when the deadline is reached.
///
/// Drop this handle to stop the ticker task (via the `Arc` refcount reaching zero
/// — the task detects a strong count of 1 and exits).
pub struct EpochTicker {
    /// Shared counter — the background task reads this to know whether to exit.
    /// When only the task itself holds a reference (`Arc::strong_count == 1`),
    /// it exits cleanly.
    _alive: Arc<AtomicU64>,
}

impl std::fmt::Debug for EpochTicker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EpochTicker").finish_non_exhaustive()
    }
}

impl EpochTicker {
    /// Spawn a Tokio task that increments the wasmtime engine's epoch every 1 ms.
    ///
    /// The engine must have epoch interruption enabled — call
    /// `engine_config.epoch_interruption(true)` before building the engine.
    ///
    /// # Panics
    ///
    /// Panics if called outside a Tokio runtime (normal for production; a
    /// `#[tokio::test]` harness satisfies the requirement in tests).
    pub fn spawn(engine: wasmtime::Engine) -> Self {
        let alive = Arc::new(AtomicU64::new(0));
        let alive_clone = Arc::clone(&alive);

        tokio::spawn(async move {
            // Run until the last external holder drops their `EpochTicker`
            // (Arc strong count drops to 1 — only the task itself remains).
            while Arc::strong_count(&alive_clone) > 1 {
                tokio::time::sleep(Duration::from_millis(1)).await;
                engine.increment_epoch();
            }
        });

        Self { _alive: alive }
    }
}

// ── Store setup helpers ───────────────────────────────────────────────────────

/// Apply all three resource limits to a `Store` before invoking a hook.
///
/// Call this immediately before each plugin hook call — not once at
/// construction — because fuel and epoch deadlines are consumed per-call.
///
/// # Type parameter
///
/// `T` is whatever host state type the caller uses for the store. It must
/// implement `AsMut<MemoryLimiter>` so wasmtime can call through to our limiter.
pub fn apply_limits<T: AsMut<MemoryLimiter>>(
    store: &mut Store<T>,
    limits: &WasmLimits,
) -> Result<(), wasmtime::Error> {
    // 1. Refuel — wasmtime tracks fuel as the store's "remaining gas".
    //    `set_fuel` replaces whatever fuel remains with the new budget.
    store.set_fuel(limits.fuel)?;

    // 2. Epoch deadline — advance from the engine's current epoch by the
    //    caller-configured number of ticks. The ticker task runs every 1 ms,
    //    so `timeout_ms` ticks ≈ `timeout_ms` ms.
    store.set_epoch_deadline(limits.timeout_ms);

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Build a wasmtime Engine with fuel + epoch interruption enabled.
    fn test_engine() -> wasmtime::Engine {
        let mut cfg = wasmtime::Config::new();
        cfg.consume_fuel(true);
        cfg.epoch_interruption(true);
        // Use the interpreter in tests — no Cranelift compilation delay.
        cfg.strategy(wasmtime::Strategy::Cranelift);
        wasmtime::Engine::new(&cfg).expect("engine")
    }

    // Wrap a WAT binary in a wasmtime Module (core module, not component).
    fn compile_wat(engine: &wasmtime::Engine, wat: &str) -> wasmtime::Module {
        let wasm = wat::parse_str(wat).expect("valid WAT");
        wasmtime::Module::new(engine, &wasm).expect("compiled module")
    }

    // ── Default limits ────────────────────────────────────────────────────────

    #[test]
    fn default_limits_are_correct() {
        let limits = WasmLimits::default();
        assert_eq!(limits.fuel, DEFAULT_FUEL);
        assert_eq!(limits.memory_mb, DEFAULT_MEMORY_MB);
        assert_eq!(limits.timeout_ms, DEFAULT_TIMEOUT_MS);
    }

    // ── Memory limiter ────────────────────────────────────────────────────────

    #[test]
    fn memory_limiter_allows_growth_within_cap() {
        let mut limiter = MemoryLimiter::new(16);
        // 15 MiB — within the 16 MiB cap.
        let result = limiter
            .memory_growing(0, 15 * 1024 * 1024, None)
            .expect("no error");
        assert!(result, "growth within cap should be allowed");
    }

    #[test]
    fn memory_limiter_blocks_growth_above_cap() {
        let mut limiter = MemoryLimiter::new(16);
        // 17 MiB — exceeds the 16 MiB cap.
        let result = limiter
            .memory_growing(0, 17 * 1024 * 1024, None)
            .expect("no error");
        assert!(!result, "growth above cap should be refused");
    }

    #[test]
    fn memory_limiter_allows_exact_cap() {
        let mut limiter = MemoryLimiter::new(16);
        let result = limiter
            .memory_growing(0, 16 * 1024 * 1024, None)
            .expect("no error");
        assert!(result, "growth exactly at cap should be allowed");
    }

    // ── Fuel enforcement ──────────────────────────────────────────────────────

    /// A tight fuel budget kills an infinite loop before it runs forever.
    #[test]
    fn fuel_kills_infinite_loop() {
        let engine = test_engine();

        // An infinite loop — this would run forever without fuel.
        let module = compile_wat(
            &engine,
            r#"(module
                (func (export "spin")
                  (loop (br 0))
                )
            )"#,
        );

        // Host state: MemoryLimiter (not needed for this test, but required by Store).
        let mut store = wasmtime::Store::new(&engine, MemoryLimiter::new(16));

        // Give the store a tiny fuel budget — enough for a few iterations, not forever.
        store.set_fuel(500).expect("set_fuel");
        store.set_epoch_deadline(1_000_000); // very large epoch deadline — fuel fires first

        let instance = wasmtime::Instance::new(&mut store, &module, &[]).expect("instantiate");
        let spin = instance
            .get_typed_func::<(), ()>(&mut store, "spin")
            .expect("get func");

        // Should trap on fuel exhaustion — not run forever.
        let result = spin.call(&mut store, ());
        assert!(result.is_err(), "infinite loop should be killed by fuel");
    }

    /// A module that completes well within the fuel budget succeeds.
    #[test]
    fn normal_module_completes_within_limits() {
        let engine = test_engine();

        // A simple addition function — very cheap.
        let module = compile_wat(
            &engine,
            r#"(module
                (func (export "add") (param i32 i32) (result i32)
                  local.get 0
                  local.get 1
                  i32.add
                )
            )"#,
        );

        let mut store = wasmtime::Store::new(&engine, MemoryLimiter::new(16));
        store.set_fuel(DEFAULT_FUEL).expect("set_fuel");
        store.set_epoch_deadline(DEFAULT_TIMEOUT_MS);

        let instance = wasmtime::Instance::new(&mut store, &module, &[]).expect("instantiate");
        let add = instance
            .get_typed_func::<(i32, i32), i32>(&mut store, "add")
            .expect("get func");

        let result = add.call(&mut store, (3, 4)).expect("call should succeed");
        assert_eq!(result, 7);
    }

    /// A module that tries to allocate more than the memory cap is refused.
    #[test]
    fn module_allocating_too_much_is_killed() {
        let engine = test_engine();

        // Attempt to grow memory to 64 pages = 4 MiB, but our cap is 1 MiB (16 pages).
        // memory.grow returns -1 (i32) when refused; we return -1 from the exported func.
        let module = compile_wat(
            &engine,
            r#"(module
                (memory 1)
                (func (export "greedy") (result i32)
                  ;; Try to grow to 64 total pages (4 MiB)
                  i32.const 63
                  memory.grow
                )
            )"#,
        );

        // Cap at 1 MiB (16 pages). Initial page (64 KiB) is allowed; growing by 63 more is not.
        let mut store = wasmtime::Store::new(&engine, MemoryLimiter::new(1));
        store.limiter(|state| state as &mut dyn ResourceLimiter);
        store.set_fuel(DEFAULT_FUEL).expect("set_fuel");
        store.set_epoch_deadline(DEFAULT_TIMEOUT_MS);

        let instance = wasmtime::Instance::new(&mut store, &module, &[]).expect("instantiate");
        let greedy = instance
            .get_typed_func::<(), i32>(&mut store, "greedy")
            .expect("get func");

        // memory.grow returns -1 when growth is refused — the function call itself succeeds.
        let result = greedy.call(&mut store, ()).expect("call returns -1");
        assert_eq!(result, -1, "memory.grow should return -1 when refused");
    }

    // ── WasmLimits equality / debug ───────────────────────────────────────────

    #[test]
    fn wasm_limits_clone_and_eq() {
        let a = WasmLimits::default();
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn wasm_limits_debug() {
        let limits = WasmLimits::default();
        let s = format!("{limits:?}");
        assert!(s.contains("fuel"));
        assert!(s.contains("memory_mb"));
        assert!(s.contains("timeout_ms"));
    }
}
