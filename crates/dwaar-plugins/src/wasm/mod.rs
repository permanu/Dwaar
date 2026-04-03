// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! WASM plugin runtime.
//!
//! Enabled via the `wasm` feature flag. Provides the engine, WIT-generated
//! bindings, and (in later issues) the module loader and host functions.

pub mod bindings;
pub mod engine;
pub mod limits;

pub use engine::{EngineError, WasmEngine};
pub use limits::WasmLimits;
