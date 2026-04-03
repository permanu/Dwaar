// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! WASM plugin runtime.
//!
//! Enabled via the `wasm` feature flag. Provides the engine and (in later
//! issues) the module loader and host function bindings.

pub mod engine;

pub use engine::{EngineError, WasmEngine};
