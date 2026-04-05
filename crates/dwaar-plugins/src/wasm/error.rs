// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Error types for the WASM plugin subsystem.

use thiserror::Error;

/// All errors that can arise during WASM plugin loading or invocation.
#[derive(Debug, Error)]
pub enum WasmError {
    /// Wasmtime engine configuration failed.
    #[error("failed to initialise wasmtime engine: {0}")]
    EngineInit(#[source] anyhow::Error),

    /// `.wasm` file could not be compiled (bad bytes, unsupported features).
    #[error("failed to compile WASM component from '{path}': {source}")]
    Compile {
        path: String,
        #[source]
        source: anyhow::Error,
    },

    /// Component instantiation failed (missing exports, link errors).
    #[error("failed to instantiate WASM component '{name}': {source}")]
    Instantiate {
        name: String,
        #[source]
        source: anyhow::Error,
    },

    /// A hook call trapped (WASM runtime error inside the plugin).
    #[error("WASM plugin '{name}' trapped in '{hook}': {source}")]
    Trap {
        name: String,
        hook: &'static str,
        #[source]
        source: anyhow::Error,
    },
}
