// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! HTML script injection state machine.
//!
//! Scans response body chunks for `</head>` and injects the analytics
//! `<script>` tag before it. Designed for streaming: each call to
//! [`HtmlInjector::process()`] handles one chunk.
//!
//! ## Security properties
//!
//! - Bounded scan: gives up after 256 KB without `</head>` (no unbounded memory)
//! - Case-insensitive: handles `</head>`, `</HEAD>`, `</Head>`, etc.
//! - No double injection: skips if `/_dwaar/a.js` already present
//! - Only modifies body bytes — caller is responsible for Content-Type and
//!   Content-Length header management

use bytes::{Bytes, BytesMut};

/// Maximum bytes to scan before giving up on finding `</head>`.
const MAX_SCAN_BYTES: usize = 256 * 1024;

/// The script tag injected before `</head>`.
const SCRIPT_TAG: &[u8] = b"<script src=\"/_dwaar/a.js\" defer></script>";

/// Marker to detect double injection.
const ALREADY_INJECTED_MARKER: &[u8] = b"/_dwaar/a.js";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Actively scanning chunks for `</head>`.
    Scanning,
    /// Injection complete — pass through all remaining chunks.
    Done,
    /// Gave up — pass through without injection.
    Skipped,
}

/// Per-request HTML script injector.
///
/// Created when `response_filter()` detects a 2xx `text/html` response.
/// Stored in `RequestContext.injector`. Each call to [`process()`]
/// handles one body chunk from `response_body_filter()`.
#[derive(Debug)]
pub struct HtmlInjector {
    state: State,
    bytes_scanned: usize,
}

impl Default for HtmlInjector {
    fn default() -> Self {
        Self::new()
    }
}

impl HtmlInjector {
    /// Create a new injector in the Scanning state.
    pub fn new() -> Self {
        Self {
            state: State::Scanning,
            bytes_scanned: 0,
        }
    }

    /// Whether the injector is still actively scanning.
    pub fn is_active(&self) -> bool {
        self.state == State::Scanning
    }

    /// Process one body chunk. Modifies `body` in place if injection occurs.
    ///
    /// Call this from `response_body_filter()` for every chunk.
    /// When `end_of_stream` is true and we're still scanning, we
    /// transition to Skipped (the HTML never had `</head>`).
    pub fn process(&mut self, body: &mut Option<Bytes>, end_of_stream: bool) {
        if self.state != State::Scanning {
            return;
        }

        let Some(ref data) = *body else {
            if end_of_stream {
                self.state = State::Skipped;
            }
            return;
        };

        self.bytes_scanned += data.len();
        if self.bytes_scanned > MAX_SCAN_BYTES {
            self.state = State::Skipped;
            return;
        }

        if find_case_insensitive(data, ALREADY_INJECTED_MARKER).is_some() {
            self.state = State::Skipped;
            return;
        }

        if let Some(pos) = find_case_insensitive(data, b"</head>") {
            let mut buf = BytesMut::with_capacity(data.len() + SCRIPT_TAG.len());
            buf.extend_from_slice(&data[..pos]);
            buf.extend_from_slice(SCRIPT_TAG);
            buf.extend_from_slice(&data[pos..]);
            *body = Some(buf.freeze());
            self.state = State::Done;
            return;
        }

        if end_of_stream {
            self.state = State::Skipped;
        }
    }
}

/// Case-insensitive byte search. Returns the byte offset of the first
/// match of `needle` in `haystack`, or `None`.
fn find_case_insensitive(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inject(html: &[u8]) -> Vec<u8> {
        let mut injector = HtmlInjector::new();
        let mut body = Some(Bytes::from(html.to_vec()));
        injector.process(&mut body, true);
        body.map_or_else(Vec::new, |b| b.to_vec())
    }

    #[test]
    fn injects_before_head_close() {
        let result = inject(b"<html><head><title>Test</title></head><body></body></html>");
        let result_str = std::str::from_utf8(&result).expect("valid UTF-8");
        assert!(result_str.contains("<script src=\"/_dwaar/a.js\" defer></script></head>"));
    }

    #[test]
    fn case_insensitive_head_tag() {
        let result = inject(b"<html><head></HEAD><body></body></html>");
        let result_str = std::str::from_utf8(&result).expect("valid UTF-8");
        assert!(result_str.contains("<script src=\"/_dwaar/a.js\" defer></script></HEAD>"));
    }

    #[test]
    fn mixed_case_head_tag() {
        let result = inject(b"<html><head></Head><body></body></html>");
        let result_str = std::str::from_utf8(&result).expect("valid UTF-8");
        assert!(result_str.contains("<script src=\"/_dwaar/a.js\" defer></script></Head>"));
    }

    #[test]
    fn no_head_tag_passes_through() {
        let original = b"<html><body>No head tag here</body></html>";
        let result = inject(original);
        assert_eq!(result, original);
    }

    #[test]
    fn empty_body_passes_through() {
        let mut injector = HtmlInjector::new();
        let mut body: Option<Bytes> = Some(Bytes::new());
        injector.process(&mut body, true);
        assert_eq!(body.expect("body should be Some").len(), 0);
    }

    #[test]
    fn none_body_passes_through() {
        let mut injector = HtmlInjector::new();
        let mut body: Option<Bytes> = None;
        injector.process(&mut body, true);
        assert!(body.is_none());
    }

    #[test]
    fn skips_when_already_injected() {
        let html = b"<html><head><script src=\"/_dwaar/a.js\"></script></head><body></body></html>";
        let result = inject(html);
        assert_eq!(result, html);
    }

    #[test]
    fn skips_after_scan_budget_exceeded() {
        let mut big = vec![b'x'; MAX_SCAN_BYTES + 100];
        big.extend_from_slice(b"</head>");
        let mut injector = HtmlInjector::new();
        let mut body = Some(Bytes::from(big.clone()));
        injector.process(&mut body, true);
        assert!(!injector.is_active());
        assert_eq!(body.expect("body should be Some").len(), big.len());
    }

    #[test]
    fn state_transitions_to_done_after_injection() {
        let mut injector = HtmlInjector::new();
        assert!(injector.is_active());
        let mut body = Some(Bytes::from_static(
            b"<html><head></head><body></body></html>",
        ));
        injector.process(&mut body, true);
        assert!(!injector.is_active());
    }

    #[test]
    fn state_transitions_to_skipped_on_end_without_head() {
        let mut injector = HtmlInjector::new();
        let mut body = Some(Bytes::from_static(b"<html><body>no head</body></html>"));
        injector.process(&mut body, true);
        assert!(!injector.is_active());
    }

    #[test]
    fn pass_through_after_done() {
        let mut injector = HtmlInjector::new();
        let mut body1 = Some(Bytes::from_static(b"<html><head></head>"));
        injector.process(&mut body1, false);
        assert!(!injector.is_active());

        let mut body2 = Some(Bytes::from_static(b"<body>content</body></html>"));
        let original = body2.clone();
        injector.process(&mut body2, true);
        assert_eq!(body2, original);
    }

    #[test]
    fn find_case_insensitive_works() {
        assert_eq!(find_case_insensitive(b"Hello World", b"world"), Some(6));
        assert_eq!(find_case_insensitive(b"Hello World", b"HELLO"), Some(0));
        assert_eq!(find_case_insensitive(b"Hello", b"xyz"), None);
        assert_eq!(find_case_insensitive(b"Hi", b"Hello"), None);
        assert_eq!(find_case_insensitive(b"anything", b""), None);
    }
}
