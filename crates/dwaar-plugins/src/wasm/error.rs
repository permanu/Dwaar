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
    /// `.wasm` file could not be compiled (bad bytes, unsupported features).
    #[error("failed to compile WASM component from '{path}': {source}")]
    Compile {
        path: String,
        #[source]
        source: anyhow::Error,
    },
}
