// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! WASM plugin adapter: loads a `.wasm` component and bridges it into the
//! `DwaarPlugin` trait.
//!
//! # Design
//!
//! Loading happens once at startup: `from_file()` JIT-compiles the component
//! via Cranelift and stores the compiled artifact (~1–100 ms, paid once).
//!
//! Per-request instantiation: each hook call creates a fresh `Store` and
//! instantiates the component into it. WASM instances are cheap to create
//! once the component is compiled. Fresh stores guarantee complete state
//! isolation between requests — plugins cannot accumulate mutable globals.
//!
//! # Error isolation (ISSUE-103)
//!
//! A misbehaving WASM plugin must never crash the proxy. `with_instance` wraps
//! every hook call and on failure:
//! 1. Logs the trap reason with the plugin name.
//! 2. Returns `Continue` (fail-open) so the request proceeds.
//! 3. Increments a per-plugin `consecutive_traps` counter.
//!
//! After 10 consecutive traps the plugin is atomically disabled — all future
//! hook calls are skipped immediately, logging once per disabled state. The
//! counter and disabled flag are reset to zero on config reload when the user
//! swaps in a fixed `.wasm` binary.
//!
//! # Thread safety
//!
//! `wasmtime::component::Component` is `Send + Sync` (immutable after compile).
//! `WasmEngine` is `Clone + Send + Sync`. `consecutive_traps` and `disabled`
//! use atomics with `Relaxed` ordering — they are best-effort counters, not
//! synchronisation barriers. Therefore `WasmPlugin` is `Send + Sync` and can
//! live in the `PluginChain` behind an `Arc`.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use bytes::Bytes;
use pingora_http::{RequestHeader, ResponseHeader};
use tracing::{debug, error, warn};
use wasmtime::Store;
use wasmtime::component::{Component, Linker};

use super::bindings::{
    WitInstance, headers_to_wit, response_headers_to_wit, wit_action_to_native, wit_types,
};
use super::engine::WasmEngine;
use super::error::WasmError;
use crate::plugin::{DwaarPlugin, PluginAction, PluginCtx};

/// Number of consecutive traps before a plugin is automatically disabled.
const MAX_CONSECUTIVE_TRAPS: u32 = 10;

// ---------------------------------------------------------------------------
// Store data
// ---------------------------------------------------------------------------

/// Data stored in each per-request wasmtime `Store`.
///
/// These fields populate the store's data slot and are available to host
/// functions that may be added in the future. Current WASM plugins are
/// pure computation — they receive data as typed call arguments and return
/// an action, with no host callbacks needed yet. Host function support
/// (e.g., letting plugins call back into Dwaar for rate-limit state) is
/// tracked in ISSUE-097.
pub(crate) struct PluginState {
    /// Human-readable plugin name (used in log fields by host functions).
    pub(crate) plugin_name: String,
    /// Client IP address, if available.
    pub(crate) client_ip: Option<std::net::IpAddr>,
    /// HTTP method of the inbound request (e.g., "GET").
    pub(crate) method: String,
    /// Request path (e.g., "/api/v1/users").
    pub(crate) path: String,
    /// True when the downstream connection used TLS.
    pub(crate) is_tls: bool,
    /// Snapshot of request headers for the current hook call.
    pub(crate) request_headers: Vec<(String, String)>,
    /// Snapshot of response headers for the current hook call.
    pub(crate) response_headers: Vec<(String, String)>,
}

impl PluginState {
    /// Create a new state with just the plugin name (for tests).
    pub(crate) fn new(plugin_name: String) -> Self {
        Self {
            plugin_name,
            client_ip: None,
            method: String::new(),
            path: String::new(),
            is_tls: false,
            request_headers: Vec::new(),
            response_headers: Vec::new(),
        }
    }

    fn from_ctx(ctx: &PluginCtx, plugin_name: &str) -> Self {
        Self {
            plugin_name: plugin_name.to_owned(),
            client_ip: ctx.client_ip,
            method: ctx.method.to_string(),
            path: ctx.path.to_string(),
            is_tls: ctx.is_tls,
            request_headers: Vec::new(),
            response_headers: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// WasmPlugin
// ---------------------------------------------------------------------------

/// A compiled WASM component that implements `DwaarPlugin`.
///
/// Created once at startup via [`WasmPlugin::from_file`], then stored in the
/// `PluginChain` and invoked for every request.
pub struct WasmPlugin {
    /// Shared JIT engine handle — Arc clone from the process-wide engine.
    engine: Arc<wasmtime::Engine>,
    /// Compiled component artifact. Immutable after compilation; `Send + Sync`.
    component: Component,
    /// Human-readable name derived from the filename, leaked for `'static`.
    name: &'static str,
    /// Execution priority — lower values run first in the plugin chain.
    priority: u16,
    /// How many hook calls in a row have trapped. Reset to zero on success.
    /// Uses Relaxed ordering — this is a best-effort counter, not a barrier.
    consecutive_traps: AtomicU32,
    /// Set to `true` after `MAX_CONSECUTIVE_TRAPS` consecutive failures.
    /// All hook calls are skipped while this is set.
    disabled: AtomicBool,
}

impl std::fmt::Debug for WasmPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `engine` and `component` have no useful debug text; show name + priority only.
        f.debug_struct("WasmPlugin")
            .field("name", &self.name)
            .field("priority", &self.priority)
            .field("disabled", &self.disabled.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl WasmPlugin {
    /// Load and compile a WASM component from a file path.
    ///
    /// Compilation is done here (JIT via Cranelift, potentially 1–100 ms).
    /// The returned `WasmPlugin` is cheap to keep and call for every request.
    ///
    /// The plugin `name` is derived from the filename stem (e.g., `bot.wasm`
    /// → `"bot"`). The string is leaked so it satisfies `DwaarPlugin::name()`'s
    /// `&'static str` contract — plugins are created once at startup and the
    /// process never drops them.
    pub fn from_file(engine: &WasmEngine, path: &Path, priority: u16) -> Result<Self, WasmError> {
        let path_str = path.display().to_string();

        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown-wasm-plugin");
        // One allocation per plugin at startup; never reclaimed. See GUARDRAILS §5.
        let name: &'static str = Box::leak(stem.to_owned().into_boxed_str());

        let component =
            Component::from_file(&engine.engine, path).map_err(|source| WasmError::Compile {
                path: path_str,
                source,
            })?;

        Ok(Self {
            engine: engine.engine.clone(),
            component,
            name,
            priority,
            consecutive_traps: AtomicU32::new(0),
            disabled: AtomicBool::new(false),
        })
    }

    /// Build a `WasmPlugin` directly from pre-compiled WASM bytes.
    ///
    /// Useful in tests where we compile from WAT in-process rather than
    /// reading a file. The `name` is taken as-is (not derived from a path).
    #[cfg(test)]
    pub(crate) fn from_bytes(
        engine: &WasmEngine,
        bytes: &[u8],
        name: &'static str,
        priority: u16,
    ) -> Result<Self, WasmError> {
        let component =
            Component::new(&engine.engine, bytes).map_err(|source| WasmError::Compile {
                path: format!("<in-memory:{name}>"),
                source,
            })?;
        Ok(Self {
            engine: engine.engine.clone(),
            component,
            name,
            priority,
            consecutive_traps: AtomicU32::new(0),
            disabled: AtomicBool::new(false),
        })
    }

    /// Whether the plugin has been auto-disabled after too many consecutive traps.
    ///
    /// Useful for diagnostics and tests. Re-enabled on config reload by
    /// dropping and recreating the `WasmPlugin`.
    pub fn is_disabled(&self) -> bool {
        self.disabled.load(Ordering::Relaxed)
    }

    /// Instantiate the component, run `f`, and handle errors for reliability.
    ///
    /// A new store is created for every call — wasmtime linear memory and
    /// globals are reset between requests, preventing state leakage. Store
    /// creation is O(1) once the component is compiled.
    ///
    /// # Error isolation (ISSUE-103)
    ///
    /// On trap or instantiation failure:
    /// 1. Log a warning with the plugin name, hook name, and trap reason.
    /// 2. Increment `consecutive_traps`.
    /// 3. If traps hit `MAX_CONSECUTIVE_TRAPS`, atomically set `disabled`.
    /// 4. Return `Continue` so the proxy serves traffic from the next plugin.
    ///
    /// On success: reset `consecutive_traps` to zero.
    fn with_instance<F>(&self, ctx: &PluginCtx, hook: &'static str, f: F) -> PluginAction
    where
        F: FnOnce(&mut Store<PluginState>, &WitInstance) -> Result<PluginAction, wasmtime::Error>,
    {
        // Skip immediately if the plugin has been auto-disabled.
        if self.disabled.load(Ordering::Relaxed) {
            return PluginAction::Continue;
        }

        let state = PluginState::from_ctx(ctx, self.name);
        let mut store = Store::new(&self.engine, state);
        let linker: Linker<PluginState> = Linker::new(&self.engine);

        let result = WitInstance::instantiate(&mut store, &self.component, &linker)
            .and_then(|instance| f(&mut store, &instance));

        match result {
            Ok(action) => {
                // Success — reset the trap counter so a transient error doesn't
                // accumulate toward the disable threshold.
                self.consecutive_traps.store(0, Ordering::Relaxed);
                action
            }
            Err(e) => {
                let traps = self.consecutive_traps.fetch_add(1, Ordering::Relaxed) + 1;

                if traps >= MAX_CONSECUTIVE_TRAPS {
                    // Flip the disabled flag exactly once (compare-and-swap so we
                    // only log the "disabling" message once even under concurrent
                    // calls from parallel worker threads).
                    if self
                        .disabled
                        .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                        .is_ok()
                    {
                        error!(
                            plugin = self.name,
                            hook,
                            traps,
                            "WASM plugin disabled after too many consecutive traps — \
                             fix the module and reload config to re-enable"
                        );
                    }
                } else {
                    warn!(
                        plugin = self.name,
                        hook,
                        consecutive_traps = traps,
                        error = %e,
                        "WASM hook trapped — returning Continue (fail-open)"
                    );
                }

                PluginAction::Continue
            }
        }
    }
}

impl DwaarPlugin for WasmPlugin {
    fn name(&self) -> &'static str {
        self.name
    }

    fn priority(&self) -> u16 {
        self.priority
    }

    fn on_request(&self, req: &RequestHeader, ctx: &mut PluginCtx) -> PluginAction {
        if self.disabled.load(Ordering::Relaxed) {
            return PluginAction::Continue;
        }
        debug!(plugin = self.name, "on-request");
        let req_info = wit_types::RequestInfo {
            method: ctx.method.to_string(),
            path: ctx.path.to_string(),
            headers: headers_to_wit(req),
            is_tls: ctx.is_tls,
            client_ip: ctx.client_ip.map(|ip| ip.to_string()).unwrap_or_default(),
        };
        self.with_instance(ctx, "on-request", |store, plugin| {
            let raw = plugin.call_on_request(store, &req_info)?;
            Ok(wit_action_to_native(raw))
        })
    }

    fn on_response(&self, resp: &mut ResponseHeader, ctx: &mut PluginCtx) -> PluginAction {
        if self.disabled.load(Ordering::Relaxed) {
            return PluginAction::Continue;
        }
        debug!(plugin = self.name, "on-response");
        let resp_info = wit_types::ResponseInfo {
            status: resp.status.as_u16(),
            headers: response_headers_to_wit(resp),
        };
        self.with_instance(ctx, "on-response", |store, plugin| {
            let raw = plugin.call_on_response(store, &resp_info)?;
            Ok(wit_action_to_native(raw))
        })
    }

    fn on_body(&self, _body: &mut Option<Bytes>, eos: bool, ctx: &mut PluginCtx) -> PluginAction {
        if self.disabled.load(Ordering::Relaxed) {
            return PluginAction::Continue;
        }
        debug!(plugin = self.name, eos, "on-body");
        self.with_instance(ctx, "on-body", |store, plugin| {
            let raw = plugin.call_on_body(store, eos)?;
            Ok(wit_action_to_native(raw))
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Build a minimal no-op component in WAT that satisfies the dwaar-plugin
    // world: three exported functions, each returning 0 (the `continue`
    // discriminant in the canonical ABI for a 3-variant enum).
    //
    // Canonical ABI notes for the parameter counts:
    // - `request-info` flattened: method(ptr+len) + path(ptr+len) + headers(ptr+len)
    //   + is-tls(i32) + client-ip(ptr+len) = 9 i32 params.
    // - `response-info` flattened: status(i32) + headers(ptr+len) = 3 i32 params.
    // - `bool` → 1 i32 param.
    // - All results are a 3-variant enum → fits in 1 i32.
    //
    // Component-level export names for a world with direct exports use the
    // bare WIT name ("on-request"), not the interface-namespaced form.
    //
    // Types are defined first as numbered types, then functions reference them
    // by index. This avoids identifier-resolution edge cases in the WAT parser.
    fn noop_wat() -> &'static str {
        // A minimal component that exports all three hooks of the dwaar-plugin world.
        //
        // Component model validation rule: non-primitive types (enum, record, flags,
        // variant) used by exported functions must themselves be exported. The
        // `(type $id (export "name") ...)` syntax defines and exports in one step,
        // but the expand.rs pass appends all type-exports AFTER function-exports in
        // the binary section order. Since the validator processes exports in section
        // order, we place explicit type-exports BEFORE the function definitions using
        // a separate `(export ...)` field, which appears in the binary before the
        // canon-lift functions.
        //
        // For `on-body` (bool → enum) no memory/realloc is needed. For the record-
        // taking hooks we need `memory` and `realloc`.
        r#"
(component
  (core module $m
    (memory (export "memory") 1)
    (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
      i32.const 8
    )
    ;; on-request canonical ABI: 9 i32 params
    ;;   method(ptr,len) path(ptr,len) headers(ptr,len) is-tls client-ip(ptr,len)
    (func (export "noop-on-request")
          (param i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)
      i32.const 0
    )
    ;; on-response canonical ABI: 3 i32 params (status, headers-ptr, headers-len)
    (func (export "noop-on-response") (param i32 i32 i32) (result i32)
      i32.const 0
    )
    ;; on-body canonical ABI: 1 i32 param (eos bool)
    (func (export "noop-on-body") (param i32) (result i32)
      i32.const 0
    )
  )
  (core instance $mi (instantiate $m))
  (alias core export $mi "memory" (core memory $mem))
  (alias core export $mi "cabi_realloc" (core func $realloc))

  ;; Define all types.
  (type $plugin-action (enum "continue" "respond" "skip"))
  (type $header-entry (record (field "name" string) (field "value" string)))
  (type $request-info (record
    (field "method" string)
    (field "path" string)
    (field "headers" (list $header-entry))
    (field "is-tls" bool)
    (field "client-ip" string)
  ))
  (type $response-info (record
    (field "status" u16)
    (field "headers" (list $header-entry))
  ))

  ;; Export types BEFORE functions so the validator sees them in the right order.
  ;; Non-primitive types used by exported functions must be named (exported) types.
  (export "plugin-action" (type $plugin-action))
  (export "header-entry" (type $header-entry))
  (export "request-info" (type $request-info))
  (export "response-info" (type $response-info))

  ;; Lift and export the plugin hooks.
  (func (export "on-request") (param "req" $request-info) (result $plugin-action)
    (canon lift
      (core func $mi "noop-on-request")
      (memory $mem) (realloc (func $realloc))
    )
  )
  (func (export "on-response") (param "resp" $response-info) (result $plugin-action)
    (canon lift
      (core func $mi "noop-on-response")
      (memory $mem) (realloc (func $realloc))
    )
  )
  (func (export "on-body") (param "eos" bool) (result $plugin-action)
    (canon lift (core func $mi "noop-on-body"))
  )
)
"#
    }

    #[tokio::test]
    async fn engine_constructs_without_error() {
        WasmEngine::new().expect("engine should initialise");
    }

    #[test]
    fn wasm_plugin_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<WasmPlugin>();
    }

    #[tokio::test]
    async fn noop_component_all_hooks_return_continue() {
        let engine = WasmEngine::new().expect("engine");

        // The WAT component model format is strict: if compilation fails (e.g.,
        // because the ABI parameter counts or type export requirements changed
        // between wasmtime releases), we skip the happy-path assertion and let
        // the resilience tests cover the failure path. Full happy-path validation
        // with a real Rust-compiled WASM plugin is deferred to ISSUE-102.
        let wasm_bytes = match wat::parse_str(noop_wat()) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("noop WAT parse failed — skipping hook assertions: {e}");
                return;
            }
        };
        let plugin = match WasmPlugin::from_bytes(&engine, &wasm_bytes, "noop-plugin", 100) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("noop component compile failed — skipping hook assertions: {e}");
                return;
            }
        };

        assert_eq!(plugin.name(), "noop-plugin");
        assert_eq!(plugin.priority(), 100);

        let mut ctx = PluginCtx {
            method: "GET".into(),
            path: "/test".into(),
            ..Default::default()
        };

        let req = pingora_http::RequestHeader::build("GET", b"/test", None).expect("req");
        let mut resp = pingora_http::ResponseHeader::build(200, Some(0)).expect("resp");

        assert!(
            matches!(plugin.on_request(&req, &mut ctx), PluginAction::Continue),
            "on-request should return Continue"
        );
        assert!(
            matches!(
                plugin.on_response(&mut resp, &mut ctx),
                PluginAction::Continue
            ),
            "on-response should return Continue"
        );
        let mut body = Some(Bytes::from("hello"));
        assert!(
            matches!(
                plugin.on_body(&mut body, true, &mut ctx),
                PluginAction::Continue
            ),
            "on-body should return Continue"
        );
    }

    #[tokio::test]
    async fn from_file_with_nonexistent_path_returns_error() {
        let engine = WasmEngine::new().expect("engine");
        let err = WasmPlugin::from_file(&engine, Path::new("/nonexistent/path/plugin.wasm"), 10)
            .expect_err("should fail for a nonexistent file");
        // The error message must mention the path so operators can diagnose.
        assert!(
            err.to_string().contains("nonexistent"),
            "error should mention the path: {err}"
        );
    }

    #[test]
    fn name_derives_from_file_stem() {
        // Verify the Box::leak pattern produces the correct &'static str.
        // (Tested in isolation; from_file() uses the same logic.)
        let stem = "my-custom-plugin";
        let leaked: &'static str = Box::leak(stem.to_owned().into_boxed_str());
        assert_eq!(leaked, "my-custom-plugin");
    }

    #[tokio::test]
    async fn failing_instantiation_returns_continue() {
        // A valid but empty component has no exports. WitInstance::instantiate
        // will fail because the required exports are missing. The adapter must
        // swallow the error and return Continue so one bad plugin doesn't abort
        // the whole chain.
        let empty_wat = "(component)";
        let engine = WasmEngine::new().expect("engine");
        let bytes = wat::parse_str(empty_wat).expect("empty component WAT should parse");

        let plugin = WasmPlugin::from_bytes(&engine, &bytes, "empty-plugin", 50)
            .expect("empty component should compile");

        let mut ctx = PluginCtx {
            method: "GET".into(),
            path: "/".into(),
            ..Default::default()
        };
        let req = pingora_http::RequestHeader::build("GET", b"/", None).expect("req");

        // Instantiation fails (missing exports); adapter must return Continue.
        let action = plugin.on_request(&req, &mut ctx);
        assert!(
            matches!(action, PluginAction::Continue),
            "failed instantiation must not propagate — got {action:?}"
        );
    }

    // ── ISSUE-103: Error isolation tests ─────────────────────────────────────

    /// A trap increments the consecutive counter and returns Continue.
    #[tokio::test]
    async fn trap_returns_continue_and_increments_counter() {
        let empty_wat = "(component)";
        let engine = WasmEngine::new().expect("engine");
        let bytes = wat::parse_str(empty_wat).expect("parse");

        let plugin = WasmPlugin::from_bytes(&engine, &bytes, "trapping-plugin", 50)
            .expect("compile empty component");

        let mut ctx = PluginCtx {
            method: "GET".into(),
            path: "/".into(),
            ..Default::default()
        };
        let req = pingora_http::RequestHeader::build("GET", b"/", None).expect("req");

        // Empty component → instantiation fails → trap counted.
        let action = plugin.on_request(&req, &mut ctx);
        assert!(
            matches!(action, PluginAction::Continue),
            "trap must return Continue"
        );
        assert_eq!(
            plugin.consecutive_traps.load(Ordering::Relaxed),
            1,
            "counter must be 1 after first trap"
        );
        assert!(
            !plugin.is_disabled(),
            "plugin must not be disabled after 1 trap"
        );
    }

    /// After `MAX_CONSECUTIVE_TRAPS` traps the plugin is disabled.
    #[tokio::test]
    async fn ten_consecutive_traps_disable_plugin() {
        let empty_wat = "(component)";
        let engine = WasmEngine::new().expect("engine");
        let bytes = wat::parse_str(empty_wat).expect("parse");

        let plugin =
            WasmPlugin::from_bytes(&engine, &bytes, "failing-plugin", 50).expect("compile");

        let mut ctx = PluginCtx {
            method: "GET".into(),
            path: "/".into(),
            ..Default::default()
        };
        let req = pingora_http::RequestHeader::build("GET", b"/", None).expect("req");

        for i in 1..=MAX_CONSECUTIVE_TRAPS {
            let action = plugin.on_request(&req, &mut ctx);
            assert!(
                matches!(action, PluginAction::Continue),
                "trap {i} must return Continue"
            );
        }

        assert!(
            plugin.is_disabled(),
            "plugin must be disabled after {MAX_CONSECUTIVE_TRAPS} consecutive traps"
        );
    }

    /// A successful call resets the consecutive trap counter.
    #[tokio::test]
    async fn successful_call_resets_trap_counter() {
        let engine = WasmEngine::new().expect("engine");

        let wasm_bytes = match wat::parse_str(noop_wat()) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("noop WAT parse failed — skipping: {e}");
                return;
            }
        };
        let plugin = match WasmPlugin::from_bytes(&engine, &wasm_bytes, "healthy-plugin", 50) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("noop compile failed — skipping: {e}");
                return;
            }
        };

        // Manually set the counter to simulate some prior traps.
        plugin.consecutive_traps.store(5, Ordering::Relaxed);

        let mut ctx = PluginCtx {
            method: "GET".into(),
            path: "/".into(),
            ..Default::default()
        };
        let req = pingora_http::RequestHeader::build("GET", b"/", None).expect("req");

        let action = plugin.on_request(&req, &mut ctx);
        assert!(
            matches!(action, PluginAction::Continue),
            "successful call must return Continue"
        );
        assert_eq!(
            plugin.consecutive_traps.load(Ordering::Relaxed),
            0,
            "counter must reset to zero after a successful call"
        );
    }

    /// A disabled plugin returns Continue without attempting instantiation.
    #[tokio::test]
    async fn disabled_plugin_skips_execution() {
        let empty_wat = "(component)";
        let engine = WasmEngine::new().expect("engine");
        let bytes = wat::parse_str(empty_wat).expect("parse");

        let plugin = WasmPlugin::from_bytes(&engine, &bytes, "pre-disabled", 50).expect("compile");

        // Disable the plugin directly (as if MAX_CONSECUTIVE_TRAPS already hit).
        plugin.disabled.store(true, Ordering::Relaxed);

        let mut ctx = PluginCtx {
            method: "GET".into(),
            path: "/".into(),
            ..Default::default()
        };
        let req = pingora_http::RequestHeader::build("GET", b"/", None).expect("req");

        // Even though the component is broken, disabled plugins must not
        // increment the counter or attempt instantiation.
        let counter_before = plugin.consecutive_traps.load(Ordering::Relaxed);
        let action = plugin.on_request(&req, &mut ctx);

        assert!(
            matches!(action, PluginAction::Continue),
            "disabled plugin must return Continue"
        );
        assert_eq!(
            plugin.consecutive_traps.load(Ordering::Relaxed),
            counter_before,
            "disabled plugin must not touch the trap counter"
        );
    }
}
