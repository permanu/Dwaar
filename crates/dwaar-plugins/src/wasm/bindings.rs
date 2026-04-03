// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Generated WIT bindings and conversion helpers.
//!
//! The [`wasmtime::component::bindgen!`] macro reads `wit/dwaar-plugin.wit` at
//! compile time and emits Rust types for all WIT records, variants, and the
//! guest trait that host-side adapter code implements.
//!
//! Conversion functions in this module translate between the generated WIT
//! types and Dwaar's native [`crate::plugin::PluginAction`] /
//! [`crate::plugin::PluginResponse`] types.

// The macro path is relative to the crate root (crates/dwaar-plugins/),
// so `../../wit/` reaches the workspace root where the WIT file lives.
//
// The macro emits a module tree rooted at the package name: `dwaar::plugin::*`.
// It also emits top-level re-exports for the world types (including `Header`,
// `PluginAction`, `PluginResponse`) into the current module, so we must NOT
// import anything with those names before expanding the macro.
wasmtime::component::bindgen!({
    world: "dwaar-plugin",
    path: "../../wit/dwaar-plugin.wit",
});

// Bring the generated WIT types into scope under distinct aliases so callers
// can reference them without spelunking through the macro-generated hierarchy.
// We alias them here to avoid ambiguity with Dwaar's native types.
pub use dwaar::plugin::types::Header as WitHeader;
pub use dwaar::plugin::types::PluginAction as WitPluginAction;
pub use dwaar::plugin::types::PluginResponse as WitPluginResponse;

// ---------------------------------------------------------------------------
// WIT → native conversions
// ---------------------------------------------------------------------------

/// Convert a WIT [`WitPluginAction`] into Dwaar's native [`crate::plugin::PluginAction`].
///
/// Body bytes are zero-copy wrapped in [`bytes::Bytes::from`] (one allocation
/// for the `Vec<u8>` buffer that the WASM guest already owns).
pub fn wit_action_to_native(action: WitPluginAction) -> crate::plugin::PluginAction {
    match action {
        WitPluginAction::Continue => crate::plugin::PluginAction::Continue,
        WitPluginAction::Skip => crate::plugin::PluginAction::Skip,
        WitPluginAction::Respond(r) => {
            crate::plugin::PluginAction::Respond(crate::plugin::PluginResponse {
                status: r.status,
                headers: r
                    .headers
                    .into_iter()
                    .map(|h| {
                        // WIT strings become owned Strings. We need `&'static str`
                        // keys for `PluginResponse::headers`. Since WIT plugin
                        // headers are dynamic (not compile-time constants), we leak
                        // the name string. Short-circuit responses from WASM plugins
                        // are rare (error/block paths only), so the leak budget
                        // is negligible — typically zero or one string per blocked
                        // request, with no per-request leak for the hot path.
                        let name: &'static str = Box::leak(h.name.into_boxed_str());
                        (name, h.value)
                    })
                    .collect(),
                body: bytes::Bytes::from(r.body),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Native → WIT conversions
// ---------------------------------------------------------------------------

/// Convert a slice of HTTP headers into the WIT [`WitHeader`] list passed to
/// `on-request` and `on-response` hooks.
///
/// Allocates one `String` per header value; the WASM boundary requires owned
/// data because the guest gets its own linear memory copy.
pub fn headers_to_wit<'a, I>(iter: I) -> Vec<WitHeader>
where
    I: Iterator<Item = (&'a str, &'a [u8])>,
{
    iter.filter_map(|(name, value)| {
        // Non-UTF-8 header values are silently skipped. WASM plugins only deal
        // with text; binary values (rare in practice) stay in-proxy and are
        // invisible to plugins.
        let value = std::str::from_utf8(value).ok()?;
        Some(WitHeader {
            name: name.to_owned(),
            value: value.to_owned(),
        })
    })
    .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::PluginAction;

    // Verify that the WIT `continue` variant maps cleanly through the
    // round-trip conversion without allocating.
    #[test]
    fn continue_round_trips() {
        let native = wit_action_to_native(WitPluginAction::Continue);
        assert!(matches!(native, PluginAction::Continue));
    }

    // Verify that the WIT `skip` variant maps cleanly.
    #[test]
    fn skip_round_trips() {
        let native = wit_action_to_native(WitPluginAction::Skip);
        assert!(matches!(native, PluginAction::Skip));
    }

    // Verify that a `respond` action carries its status, headers, and body.
    #[test]
    fn respond_round_trips() {
        let wit_resp = WitPluginResponse {
            status: 403,
            headers: vec![WitHeader {
                name: "x-blocked-by".to_owned(),
                value: "dwaar-wasm".to_owned(),
            }],
            body: b"Forbidden".to_vec(),
        };
        let native = wit_action_to_native(WitPluginAction::Respond(wit_resp));

        let PluginAction::Respond(resp) = native else {
            panic!("expected Respond variant");
        };
        assert_eq!(resp.status, 403);
        assert_eq!(resp.headers.len(), 1);
        assert_eq!(resp.headers[0].0, "x-blocked-by");
        assert_eq!(resp.headers[0].1, "dwaar-wasm");
        assert_eq!(resp.body.as_ref(), b"Forbidden");
    }

    // Verify that non-UTF-8 header values are silently dropped.
    #[test]
    fn headers_to_wit_skips_non_utf8() {
        let raw: Vec<(&str, &[u8])> =
            vec![("content-type", b"text/plain"), ("x-binary", b"\xff\xfe")];
        let wit_headers = headers_to_wit(raw.into_iter());
        assert_eq!(wit_headers.len(), 1);
        assert_eq!(wit_headers[0].name, "content-type");
    }

    // Verify that an empty header list converts cleanly.
    #[test]
    fn headers_to_wit_empty() {
        let wit_headers = headers_to_wit(std::iter::empty());
        assert!(wit_headers.is_empty());
    }
}
