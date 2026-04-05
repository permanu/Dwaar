// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Host function implementations for the `dwaar:plugin/host` interface.
//!
//! Wasmtime calls these functions when a WASM guest imports `host` and calls
//! one of its functions (e.g. `get-header`, `log-info`). Each function reads
//! from the `PluginState` stored in the request-scoped `Store`.
//!
//! # Security limits (Guardrail #17)
//!
//! All inputs from the guest are treated as adversarial:
//!
//! - **Header names**: rejected if they contain non-ASCII bytes or control
//!   characters. This prevents CRLF injection through header lookup.
//! - **Header values**: truncated to `MAX_HEADER_VALUE_BYTES` (8 KB) before
//!   returning to the guest. Prevents a malicious guest from requesting huge
//!   values and then holding them in linear memory.
//! - **Log messages**: truncated to `MAX_LOG_MSG_BYTES` (4 KB). Prevents
//!   log amplification — one log call can't produce unbounded I/O.

use crate::wasm::adapter::PluginState;

/// Maximum header value size returned to a guest (bytes).
/// HTTP/1.1 allows up to 8KB per header in common implementations.
pub const MAX_HEADER_VALUE_BYTES: usize = 8 * 1024;

/// Maximum log message size (bytes).
pub const MAX_LOG_MSG_BYTES: usize = 4 * 1024;

/// Returns `true` if `name` is a safe header name: only printable ASCII,
/// no control characters (tab is allowed by HTTP spec, but we reject it
/// here for simplicity — plugins should use canonical header names).
pub(crate) fn is_valid_header_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii() && !b.is_ascii_control())
}

/// Truncate a string to at most `max_bytes` bytes on a UTF-8 character boundary.
///
/// Rather than truncating in the middle of a multi-byte codepoint (which would
/// produce invalid UTF-8), we walk backward from the byte limit until we find a
/// valid boundary. In practice header values and log messages are ASCII, so this
/// almost always returns exactly `max_bytes` bytes.
pub(crate) fn truncate_utf8(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    // Walk backward from max_bytes to find a valid char boundary.
    let mut end = max_bytes;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Host function implementations for the WIT `interface host`.
///
/// wasmtime's `bindgen!` generates a `dwaar::plugin::host::Host` trait that
/// must be implemented on the Store's data type (`PluginState`). The adapter
/// delegates to these free functions so the logic is testable without
/// instantiating a wasmtime Store.
pub mod host_impl {
    use tracing::{info, warn};

    use super::{
        MAX_HEADER_VALUE_BYTES, MAX_LOG_MSG_BYTES, PluginState, is_valid_header_name, truncate_utf8,
    };

    /// Look up a request (or response) header by name.
    ///
    /// Returns `None` if:
    /// - the header name contains non-ASCII or control characters
    /// - the header is not present
    ///
    /// Values are truncated to 8 KB before being returned to the guest.
    pub fn get_header(state: &PluginState, name: &str) -> Option<String> {
        if !is_valid_header_name(name) {
            // Log at debug level — an invalid name from guest code is notable
            // but not worth warning about (could be a dev mistake).
            tracing::debug!(
                plugin = %state.plugin_name,
                header_name = %name,
                "guest requested header with invalid name — rejected"
            );
            return None;
        }

        // Search request headers first, then response headers.
        // Only one of the two will be populated depending on which hook is
        // currently executing (on_request vs on_response).
        let value = state
            .request_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .or_else(|| {
                state
                    .response_headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(name))
                    .map(|(_, v)| v.as_str())
            })?;

        Some(truncate_utf8(value, MAX_HEADER_VALUE_BYTES).to_string())
    }

    /// Return the client IP as a string, or `None` for connections with no IP.
    pub fn get_client_ip(state: &PluginState) -> Option<String> {
        state.client_ip.map(|ip| ip.to_string())
    }

    /// Return the request path (e.g. `/api/users`).
    pub fn get_path(state: &PluginState) -> String {
        state.path.clone()
    }

    /// Return the HTTP method (e.g. `GET`, `POST`).
    pub fn get_method(state: &PluginState) -> String {
        state.method.clone()
    }

    /// Return whether the downstream connection used TLS.
    pub fn is_tls(state: &PluginState) -> bool {
        state.is_tls
    }

    /// Emit an info-level log message from the plugin.
    ///
    /// Truncated to 4 KB. The `plugin` field lets operators filter logs by
    /// plugin name in their log aggregator.
    pub fn log_info(state: &PluginState, msg: &str) {
        let truncated = truncate_utf8(msg, MAX_LOG_MSG_BYTES);
        info!(plugin = %state.plugin_name, "{}", truncated);
    }

    /// Emit a warning-level log message from the plugin.
    ///
    /// Truncated to 4 KB.
    pub fn log_warn(state: &PluginState, msg: &str) {
        let truncated = truncate_utf8(msg, MAX_LOG_MSG_BYTES);
        warn!(plugin = %state.plugin_name, "{}", truncated);
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::str::FromStr;

    use tracing_subscriber::fmt::MakeWriter;

    use crate::wasm::adapter::PluginState;

    use super::host_impl::{
        get_client_ip, get_header, get_method, get_path, is_tls, log_info, log_warn,
    };
    use super::{MAX_HEADER_VALUE_BYTES, MAX_LOG_MSG_BYTES, is_valid_header_name, truncate_utf8};

    fn make_state() -> PluginState {
        let mut state = PluginState::new("test-plugin".into());
        state.request_headers = vec![
            ("Host".into(), "example.com".into()),
            ("Content-Type".into(), "application/json".into()),
            ("X-Custom".into(), "hello world".into()),
        ];
        state.path = "/api/v1/users".into();
        state.method = "GET".into();
        state.is_tls = true;
        state.client_ip = Some(IpAddr::from_str("203.0.113.42").expect("valid IP"));
        state
    }

    // -- get_header --

    #[test]
    fn get_header_returns_value_for_known_header() {
        let state = make_state();
        let result = get_header(&state, "Host");
        assert_eq!(result, Some("example.com".into()));
    }

    #[test]
    fn get_header_is_case_insensitive() {
        let state = make_state();
        let result = get_header(&state, "content-type");
        assert_eq!(result, Some("application/json".into()));
    }

    #[test]
    fn get_header_returns_none_for_missing_header() {
        let state = make_state();
        let result = get_header(&state, "Authorization");
        assert!(result.is_none());
    }

    #[test]
    fn get_header_rejects_name_with_control_chars() {
        let state = make_state();
        // CR in the header name — classic CRLF injection attempt.
        let result = get_header(&state, "Host\r\nX-Injected: evil");
        assert!(result.is_none());
    }

    #[test]
    fn get_header_rejects_non_ascii_name() {
        let state = make_state();
        let result = get_header(&state, "Héader");
        assert!(result.is_none());
    }

    #[test]
    fn get_header_rejects_empty_name() {
        let state = make_state();
        let result = get_header(&state, "");
        assert!(result.is_none());
    }

    #[test]
    fn get_header_truncates_oversized_value() {
        let mut state = PluginState::new("test-plugin".into());
        // 9 KB value — should be truncated to 8 KB.
        let huge_value = "x".repeat(9 * 1024);
        state.request_headers = vec![("X-Big".into(), huge_value)];

        let result = get_header(&state, "X-Big").expect("header present");
        assert_eq!(result.len(), MAX_HEADER_VALUE_BYTES);
    }

    // -- get_client_ip --

    #[test]
    fn get_client_ip_returns_ip_when_set() {
        let state = make_state();
        let result = get_client_ip(&state);
        assert_eq!(result, Some("203.0.113.42".into()));
    }

    #[test]
    fn get_client_ip_returns_none_when_not_set() {
        let state = PluginState::new("test-plugin".into());
        let result = get_client_ip(&state);
        assert!(result.is_none());
    }

    // -- get_path / get_method / is_tls --

    #[test]
    fn get_path_returns_configured_path() {
        let state = make_state();
        assert_eq!(get_path(&state), "/api/v1/users");
    }

    #[test]
    fn get_method_returns_configured_method() {
        let state = make_state();
        assert_eq!(get_method(&state), "GET");
    }

    #[test]
    fn is_tls_returns_configured_flag() {
        let state = make_state();
        assert!(is_tls(&state));

        let mut no_tls = PluginState::new("test".into());
        no_tls.is_tls = false;
        assert!(!is_tls(&no_tls));
    }

    // -- is_valid_header_name --

    #[test]
    fn valid_header_names_accepted() {
        assert!(is_valid_header_name("Host"));
        assert!(is_valid_header_name("X-Custom-Header"));
        assert!(is_valid_header_name("content-type"));
        assert!(is_valid_header_name("X-123-ABC"));
    }

    #[test]
    fn invalid_header_names_rejected() {
        // Null byte
        assert!(!is_valid_header_name("Hea\0der"));
        // Tab (ASCII control)
        assert!(!is_valid_header_name("Hea\tder"));
        // Newline
        assert!(!is_valid_header_name("Hea\nder"));
        // Non-ASCII
        assert!(!is_valid_header_name("Héader"));
        // Empty
        assert!(!is_valid_header_name(""));
    }

    // -- truncate_utf8 --

    #[test]
    fn truncate_utf8_short_string_unchanged() {
        assert_eq!(truncate_utf8("hello", 100), "hello");
    }

    #[test]
    fn truncate_utf8_exact_boundary() {
        let s = "a".repeat(8);
        assert_eq!(truncate_utf8(&s, 8), s.as_str());
    }

    #[test]
    fn truncate_utf8_truncates_at_char_boundary() {
        // "£" is 2 bytes in UTF-8. If max_bytes = 3 and the string is "£x",
        // truncating at byte 3 is fine (£=2 bytes + x=1 byte = 3). But if
        // max_bytes = 1, we must not cut the £ in half.
        let s = "£x";
        let result = truncate_utf8(s, 1);
        // Can't fit £ in 1 byte, so should return empty string.
        assert!(result.is_empty());
    }

    // -- log_info / log_warn (tracing integration) --

    #[test]
    fn log_info_does_not_panic_on_normal_message() {
        let state = make_state();
        // No panic is the contract; structured output is verified in integration tests.
        log_info(&state, "Plugin processing request");
    }

    #[test]
    fn log_warn_does_not_panic_on_normal_message() {
        let state = make_state();
        log_warn(&state, "Suspicious header value detected");
    }

    #[test]
    fn log_info_does_not_panic_on_oversized_message() {
        let state = make_state();
        let huge = "x".repeat(8 * 1024);
        log_info(&state, &huge);
    }

    /// Verify that log messages are capped at `MAX_LOG_MSG_BYTES` characters
    /// before being handed to tracing. We do this by capturing the formatted
    /// output from a test subscriber.
    #[test]
    fn log_output_is_truncated_to_4kb() {
        use std::sync::{Arc, Mutex};

        // Collect all tracing output into a shared buffer.
        #[derive(Clone, Default)]
        struct Buffer(Arc<Mutex<Vec<u8>>>);

        impl<'a> MakeWriter<'a> for Buffer {
            type Writer = BufferWriter;
            fn make_writer(&'a self) -> Self::Writer {
                BufferWriter(Arc::clone(&self.0))
            }
        }

        struct BufferWriter(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for BufferWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("lock").extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let buf = Buffer::default();
        let buf_clone = buf.clone();

        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf_clone)
            .with_max_level(tracing::Level::INFO)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            let state = PluginState::new("test-plugin".into());
            // 5 KB message — should be truncated to 4 KB before logging.
            let huge = "a".repeat(5 * 1024);
            log_info(&state, &huge);
        });

        let output = buf.0.lock().expect("lock");
        let output_str = std::str::from_utf8(&output).expect("utf8");
        // The longest run of consecutive 'a' characters in the output must be
        // exactly MAX_LOG_MSG_BYTES — that's the truncated message body.
        // We check the longest run rather than total count to avoid counting
        // 'a's that appear in module paths like `dwaar_plugins::wasm::...`.
        let longest_run = output_str
            .split(|c: char| c != 'a')
            .map(str::len)
            .max()
            .unwrap_or(0);
        assert_eq!(
            longest_run, MAX_LOG_MSG_BYTES,
            "log message should be truncated to {MAX_LOG_MSG_BYTES} bytes, got longest run {longest_run}"
        );
    }
}
