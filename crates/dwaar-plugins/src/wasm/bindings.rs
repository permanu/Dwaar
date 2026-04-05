// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! WIT-generated bindings and host↔plugin type conversions.
//!
//! `wasmtime::component::bindgen!` reads the WIT file at compile time and
//! emits Rust types for every record, enum, and exported function in the
//! `dwaar-plugin` world. We isolate the generated code in `generated`
//! to avoid name collisions with Dwaar's native `DwaarPlugin` trait.
//!
//! # Generated layout (wasmtime 29)
//!
//! For a world named `dwaar-plugin` with direct function exports:
//! - `generated::DwaarPlugin` — the binding struct; `instantiate()` + `call_*` methods
//! - `generated::PluginAction`, `generated::RequestInfo`, `generated::ResponseInfo`,
//!   `generated::HeaderEntry` — the WIT record/enum types
//!
//! We re-export these under cleaner names so adapter.rs doesn't have to
//! navigate the internal `generated::` path.

use pingora_http::{RequestHeader, ResponseHeader};

use crate::plugin::PluginAction;

/// Isolated module for bindgen! output to avoid the name clash between the
/// generated `DwaarPlugin` struct and our native `DwaarPlugin` trait.
#[allow(clippy::pedantic)]
mod generated {
    wasmtime::component::bindgen!({
        path: "wit/dwaar-plugin.wit",
        world: "dwaar-plugin",
        async: false,
    });
}

/// The wasmtime-generated world binding struct, re-exported as `WitInstance`
/// to distinguish it from the native `DwaarPlugin` trait.
pub use generated::DwaarPlugin as WitInstance;

/// WIT-generated types for constructing hook call arguments.
///
/// Named `wit_types` (not `types`) to make import sites self-documenting:
/// `wit_types::RequestInfo` reads clearly as "the WIT definition of `RequestInfo`".
pub mod wit_types {
    pub use super::generated::{HeaderEntry, PluginAction, RequestInfo, ResponseInfo};
}

// ---------------------------------------------------------------------------
// Type conversions
// ---------------------------------------------------------------------------

/// Convert the WIT `plugin-action` enum into Dwaar's native `PluginAction`.
///
/// The `respond` variant doesn't yet carry status/body in the WIT — plugins
/// that short-circuit get a 503 stub. Rich response data (status, headers,
/// body) is tracked in ISSUE-097.
pub fn wit_action_to_native(action: wit_types::PluginAction) -> PluginAction {
    match action {
        wit_types::PluginAction::Continue => PluginAction::Continue,
        wit_types::PluginAction::Respond => PluginAction::Respond(crate::plugin::PluginResponse {
            status: 503,
            headers: vec![("content-type", "text/plain".to_string())],
            body: bytes::Bytes::from_static(b"plugin short-circuit"),
        }),
        wit_types::PluginAction::Skip => PluginAction::Skip,
    }
}

/// Build the WIT `list<header-entry>` from a Pingora `RequestHeader`.
///
/// Names are lowercased (HTTP/2 wire convention) so plugins match headers
/// without case folding.
pub fn headers_to_wit(req: &RequestHeader) -> Vec<wit_types::HeaderEntry> {
    req.headers
        .iter()
        .map(|(name, value)| wit_types::HeaderEntry {
            name: name.as_str().to_lowercase(),
            value: value.to_str().unwrap_or("").to_owned(),
        })
        .collect()
}

/// Build the WIT `list<header-entry>` from a Pingora `ResponseHeader`.
pub fn response_headers_to_wit(resp: &ResponseHeader) -> Vec<wit_types::HeaderEntry> {
    resp.headers
        .iter()
        .map(|(name, value)| wit_types::HeaderEntry {
            name: name.as_str().to_lowercase(),
            value: value.to_str().unwrap_or("").to_owned(),
        })
        .collect()
}
