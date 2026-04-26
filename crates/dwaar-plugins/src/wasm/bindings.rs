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
//! # v0.2.3 — Lazy header access (audit finding L-16)
//!
//! The WIT contract no longer ships headers inside `request-info` /
//! `response-info`. Guests fetch headers through host-imported functions
//! declared on the `host` interface. `bindgen!` generates a
//! `dwaar::plugin::host::Host` trait that `PluginState` implements, and an
//! `add_to_linker` helper that registers the host functions on the linker
//! once at plugin construction.
//!
//! # Generated layout (wasmtime 43)
//!
//! For a world named `dwaar-plugin` with direct function exports:
//! - `generated::DwaarPlugin` — the binding struct; `instantiate()` + `call_*` methods
//! - `generated::PluginAction`, `generated::RequestInfo`, `generated::ResponseInfo`
//!   — the WIT record/enum types (no `HeaderEntry` any more)
//! - `generated::dwaar::plugin::host::Host` — the trait every store-data type
//!   must implement to service guest imports
//! - `generated::dwaar::plugin::host::add_to_linker` — host wiring helper;
//!   takes a `D: HasData` type param (`HasSelf<T>` when `T` impls `Host` directly)

use crate::plugin::PluginAction;

/// Isolated module for bindgen! output to avoid the name clash between the
/// generated `DwaarPlugin` struct and our native `DwaarPlugin` trait.
#[allow(clippy::pedantic)]
#[allow(unreachable_pub)]
mod generated {
    wasmtime::component::bindgen!({
        path: "wit/dwaar-plugin.wit",
        world: "dwaar-plugin",
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
    pub use super::generated::{PluginAction, RequestInfo, ResponseInfo};
}

/// Re-export of the bindgen-generated `host::Host` trait. Implemented by
/// `PluginState` in `adapter.rs` to service guest calls to
/// `get-request-header`, `list-request-header-names`, etc. (L-16).
pub use generated::dwaar::plugin::host::Host as HostImports;

/// Re-export of the bindgen-generated `add_to_linker` helper for the `host`
/// import interface. Called once at `WasmPlugin::from_file` construction.
///
/// wasmtime >= 36 signature: `add_to_linker<T, D>(linker, getter)` where
/// `D: HostWithStore`. When `T` directly implements `Host`, pass
/// `HasSelf<T>` as `D`.
pub use generated::dwaar::plugin::host::add_to_linker as add_host_to_linker;

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
            headers: vec![(
                "content-type",
                std::borrow::Cow::Owned("text/plain".to_string()),
            )],
            body: bytes::Bytes::from_static(b"plugin short-circuit"),
        }),
        wit_types::PluginAction::Skip => PluginAction::Skip,
    }
}
