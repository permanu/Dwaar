// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! WASM plugin subsystem.
//!
//! Bridges wasmtime's component model into Dwaar's `DwaarPlugin` trait so
//! that compiled `.wasm` files can hook into the request lifecycle without
//! recompiling the proxy binary. Feature-gated behind `wasm`.
//!
//! # Module layout
//!
//! - [`engine`] — shared `WasmEngine` handle (wraps `wasmtime::Engine`)
//! - [`bindings`] — WIT-generated types + host↔plugin conversion helpers
//! - [`limits`] — `WasmLimits` config, `MemoryLimiter`, `EpochTicker`
//! - [`error`] — `WasmError` enum for loading and runtime failures
//! - [`adapter`] — `WasmPlugin` struct implementing `DwaarPlugin`

pub mod adapter;
pub mod bindings;
pub mod cache;
pub mod engine;
pub mod error;
pub mod limits;

pub use adapter::WasmPlugin;
pub use cache::ModuleCache;
pub use engine::{EngineError, WasmEngine};
pub use error::WasmError;
pub use limits::WasmLimits;
