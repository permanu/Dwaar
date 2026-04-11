// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Safety helpers for the `dwaar:plugin/host` interface.
//!
//! The v0.2.3 WIT contract (audit finding L-16) moved header access into
//! host-imported functions registered on the wasmtime linker. Those host
//! functions live in `adapter.rs` directly on `PluginState`. This module
//! exposes the shared guardrail constants and sanitizer helpers they use
//! so the safety logic is small, testable, and reused consistently.
//!
//! # Guardrails
//!
//! All inputs from the guest are treated as adversarial:
//!
//! - **Header names**: rejected if they contain non-ASCII bytes or control
//!   characters. Prevents CRLF injection through header lookup.
//! - **Header values**: truncated to [`MAX_HEADER_VALUE_BYTES`] (8 KB) before
//!   being returned to the guest. Prevents a malicious guest from requesting
//!   huge values and holding them in linear memory.
//!
//! The log-message size cap (`MAX_LOG_MSG_BYTES`, 4 KB) is retained for
//! future guest-initiated logging; the WIT contract currently does not
//! export log import functions, but the helper is cheap to keep.

/// Maximum header value size returned to a guest (bytes).
/// HTTP/1.1 allows up to 8KB per header in common implementations.
pub const MAX_HEADER_VALUE_BYTES: usize = 8 * 1024;

/// Maximum log message size (bytes).
#[allow(dead_code)]
pub const MAX_LOG_MSG_BYTES: usize = 4 * 1024;

/// Returns `true` if `name` is a safe header name: only printable ASCII,
/// no control characters. Rejects tab for simplicity — plugins should use
/// canonical header names.
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

#[cfg(test)]
mod tests {
    use super::{MAX_HEADER_VALUE_BYTES, is_valid_header_name, truncate_utf8};

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
        // Newline — classic CRLF injection
        assert!(!is_valid_header_name("Hea\nder"));
        // Carriage return
        assert!(!is_valid_header_name("Hea\rder"));
        // Non-ASCII
        assert!(!is_valid_header_name("Héader"));
        // Empty
        assert!(!is_valid_header_name(""));
    }

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
        // "£" is 2 bytes in UTF-8. If max_bytes = 1, we must not cut it in half.
        let s = "£x";
        let result = truncate_utf8(s, 1);
        assert!(result.is_empty());
    }

    #[test]
    fn truncate_utf8_respects_max_header_value_bytes() {
        let big = "x".repeat(10 * 1024);
        let truncated = truncate_utf8(&big, MAX_HEADER_VALUE_BYTES);
        assert_eq!(truncated.len(), MAX_HEADER_VALUE_BYTES);
    }
}
