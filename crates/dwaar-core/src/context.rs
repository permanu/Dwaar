// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Per-request context that travels through Pingora's proxy lifecycle.
//!
//! Every HTTP request that Pingora processes gets its own `RequestContext`,
//! created fresh in [`DwaarProxy::new_ctx()`]. Each lifecycle hook
//! (`request_filter`, `upstream_peer`, `response_filter`, `logging`, etc.)
//! receives a `&mut RequestContext` so it can read and write per-request state.
//!
//! ## Why a context struct?
//!
//! Pingora's lifecycle hooks are separate async functions — they can't share
//! local variables. The context is the bridge: `request_filter` populates it,
//! `upstream_peer` reads it, `logging` summarizes it.
//!
//! ## Design: start minimal, grow incrementally
//!
//! ISSUE-005 (this): empty — just proves the pipeline works.
//! ISSUE-006: adds timing, request ID, client IP, host, method, path.
//! Later issues add analytics flags, plugin state, TLS info, etc.

/// Per-request state shared across all Pingora lifecycle hooks.
///
/// Created once per request by [`DwaarProxy::new_ctx()`], dropped when the
/// request completes. Fields are populated progressively by different hooks.
///
/// # Thread safety
///
/// This struct is `Send + Sync` by default (all fields are owned types).
/// Pingora requires this because async tasks may move across threads.
#[derive(Debug)]
pub struct RequestContext {
    // TODO(arvee): ISSUE-005 starts empty — the struct just needs to exist
    // so Pingora can create and pass it through the lifecycle.
    //
    // ISSUE-006 will add:
    //   pub start_time: Instant,
    //   pub request_id: String,
    //   pub client_ip: Option<IpAddr>,
    //   pub host: Option<String>,
    //   pub method: String,
    //   pub path: String,
}

impl RequestContext {
    /// Create a new empty context for ISSUE-005.
    ///
    /// Later issues will populate fields here (e.g., `Instant::now()` for
    /// timing, `Uuid::now_v7()` for request ID).
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for RequestContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_is_send_and_sync() {
        // Pingora moves contexts across async task boundaries.
        // If this test compiles, the bounds are satisfied.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RequestContext>();
    }

    #[test]
    fn context_default_works() {
        let ctx = RequestContext::default();
        // Just verifying construction doesn't panic.
        // Fields will be tested when they're added in ISSUE-006.
        let _ = format!("{ctx:?}");
    }
}
