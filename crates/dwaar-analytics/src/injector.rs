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

/// Carryover buffer size: longest needle (12 bytes) minus 1.
/// Covers both `</head>` (7 bytes) and `/_dwaar/a.js` (12 bytes).
const CARRYOVER_SIZE: usize = 11;

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
    /// Last `CARRYOVER_SIZE` bytes from the previous chunk, held back so we can
    /// detect `</head>` tags split across chunk boundaries without duplicating data.
    carryover: BytesMut,
    /// When `true`, analytics injection is gated on user consent signals (GDPR/CCPA).
    ///
    /// This is a privacy-compliance aid, not a security boundary. When enabled,
    /// `process_with_consent()` checks for DNT and recognised consent cookies before
    /// injecting; without a positive consent signal the response passes through
    /// unmodified. Has no effect on calls to `process()` directly.
    pub respect_consent: bool,
}

impl Default for HtmlInjector {
    fn default() -> Self {
        Self::new()
    }
}

impl HtmlInjector {
    /// Create a new injector in the Scanning state with consent gating disabled.
    pub fn new() -> Self {
        Self {
            state: State::Scanning,
            bytes_scanned: 0,
            carryover: BytesMut::new(),
            respect_consent: false,
        }
    }

    /// Create a new injector with explicit consent-gating configuration.
    ///
    /// When `respect_consent` is `true`, callers must use
    /// [`process_with_consent()`] to supply DNT and cookie signals; injection
    /// will be skipped unless a positive consent signal is present.
    pub fn new_with_consent(respect_consent: bool) -> Self {
        Self {
            state: State::Scanning,
            bytes_scanned: 0,
            carryover: BytesMut::new(),
            respect_consent,
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
            // Flush any held carryover on end of stream
            if end_of_stream {
                if !self.carryover.is_empty() {
                    *body = Some(self.carryover.split().freeze());
                }
                self.state = State::Skipped;
            }
            return;
        };

        // Build search window: held-back carryover bytes + current chunk.
        // The carryover wasn't sent yet, so the combined buffer owns all the data.
        let mut search_buf = std::mem::take(&mut self.carryover);
        search_buf.extend_from_slice(data);

        // Check for double injection
        if find_case_insensitive(&search_buf, ALREADY_INJECTED_MARKER).is_some() {
            *body = Some(search_buf.freeze());
            self.state = State::Skipped;
            return;
        }

        // Search for </head> before checking budget — if it's in this
        // combined buffer, inject regardless of cumulative bytes scanned
        if let Some(pos) = find_case_insensitive(&search_buf, b"</head>") {
            let mut buf = BytesMut::with_capacity(search_buf.len() + SCRIPT_TAG.len());
            buf.extend_from_slice(&search_buf[..pos]);
            buf.extend_from_slice(SCRIPT_TAG);
            buf.extend_from_slice(&search_buf[pos..]);
            *body = Some(buf.freeze());
            self.state = State::Done;
            return;
        }

        // Update budget AFTER search — we already checked this chunk
        self.bytes_scanned += data.len();
        if self.bytes_scanned > MAX_SCAN_BYTES {
            *body = Some(search_buf.freeze());
            self.state = State::Skipped;
            return;
        }

        // Hold back last CARRYOVER_SIZE bytes for boundary detection.
        // They'll be prepended to the next chunk's search window.
        let total_len = search_buf.len();
        if total_len > CARRYOVER_SIZE {
            let split_at = total_len - CARRYOVER_SIZE;
            self.carryover = BytesMut::from(&search_buf[split_at..]);
            *body = Some(search_buf.freeze().slice(..split_at));
        } else {
            // Everything fits in carryover — hold it all, emit empty body
            self.carryover = search_buf;
            *body = Some(Bytes::new());
        }

        if end_of_stream {
            // Flush held carryover alongside any already-emitted bytes
            if !self.carryover.is_empty() {
                let flush = std::mem::take(&mut self.carryover);
                if let Some(existing) = body.take() {
                    let mut combined = BytesMut::with_capacity(existing.len() + flush.len());
                    combined.extend_from_slice(&existing);
                    combined.extend_from_slice(&flush);
                    *body = Some(combined.freeze());
                } else {
                    *body = Some(flush.freeze());
                }
            }
            self.state = State::Skipped;
        }
    }

    /// Process one body chunk with consent-gate enforcement.
    ///
    /// When `respect_consent` is `false` this is identical to calling
    /// [`process()`] directly. When `true`, consent is evaluated first:
    ///
    /// - `dnt == true` (the request carried `DNT: 1`) → pass through, no injection.
    /// - `cookie` contains `dwaar_consent=1` or `analytics_consent=1`
    ///   (semicolon-separated `Cookie` header, case-insensitive key) → inject.
    /// - Otherwise → pass through, no injection.
    pub fn process_with_consent(
        &mut self,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        cookie: Option<&str>,
        dnt: bool,
    ) {
        if !self.respect_consent {
            self.process(body, end_of_stream);
            return;
        }

        if !Self::has_analytics_consent(cookie, dnt) {
            self.state = State::Skipped;
            return;
        }

        self.process(body, end_of_stream);
    }

    /// Returns `true` when the request carries a positive analytics-consent signal.
    ///
    /// Consent is present when ALL of the following hold:
    /// - `dnt` is `false` (no Do Not Track signal)
    /// - `cookie` contains a `dwaar_consent=1` or `analytics_consent=1` pair
    ///   (semicolon-separated; key comparison is case-insensitive)
    fn has_analytics_consent(cookie: Option<&str>, dnt: bool) -> bool {
        if dnt {
            return false;
        }
        let Some(cookie_str) = cookie else {
            return false;
        };
        for pair in cookie_str.split(';') {
            let pair = pair.trim();
            if let Some((key, value)) = pair.split_once('=') {
                let key = key.trim();
                let value = value.trim();
                if (key.eq_ignore_ascii_case("dwaar_consent")
                    || key.eq_ignore_ascii_case("analytics_consent"))
                    && value == "1"
                {
                    return true;
                }
            }
        }
        false
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
        // Two chunks: first exceeds budget, second has </head> but is skipped
        let mut injector = HtmlInjector::new();
        let mut body1 = Some(Bytes::from(vec![b'x'; MAX_SCAN_BYTES + 100]));
        injector.process(&mut body1, false);
        assert!(!injector.is_active());

        let mut body2 = Some(Bytes::from_static(b"</head>"));
        let original = body2.clone();
        injector.process(&mut body2, true);
        assert_eq!(body2, original);
    }

    #[test]
    fn injects_in_chunk_that_crosses_budget() {
        // If </head> is in the same chunk that crosses the budget, inject anyway
        let mut big = vec![b'x'; MAX_SCAN_BYTES + 100];
        big.extend_from_slice(b"</head>");
        let mut injector = HtmlInjector::new();
        let mut body = Some(Bytes::from(big.clone()));
        injector.process(&mut body, true);
        assert!(!injector.is_active());
        // Injection happened: body is bigger than original by SCRIPT_TAG length
        assert_eq!(
            body.expect("body should be Some").len(),
            big.len() + SCRIPT_TAG.len()
        );
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
    fn cross_chunk_head_tag_boundary() {
        // </head> split: chunk1 ends with "</he", chunk2 starts with "ad>"
        let mut injector = HtmlInjector::new();

        let mut body1 = Some(Bytes::from_static(b"<html><head><title>T</title></he"));
        injector.process(&mut body1, false);

        let mut body2 = Some(Bytes::from_static(b"ad><body>content</body></html>"));
        injector.process(&mut body2, false);

        let mut output = Vec::new();
        if let Some(b) = body1 {
            output.extend_from_slice(&b);
        }
        if let Some(b) = body2 {
            output.extend_from_slice(&b);
        }
        let result = std::str::from_utf8(&output).expect("valid UTF-8");
        assert!(
            result.contains("<script src=\"/_dwaar/a.js\" defer></script></head>"),
            "Expected injection, got: {result}"
        );
        assert!(!injector.is_active());
    }

    #[test]
    fn cross_chunk_head_tag_split_at_every_position() {
        let html = b"<html><head></head><body></body></html>";
        let head_start = html
            .windows(7)
            .position(|w| w.eq_ignore_ascii_case(b"</head>"))
            .expect("test HTML must contain </head>");

        for split in head_start + 1..head_start + 7 {
            let mut injector = HtmlInjector::new();
            let mut body1 = Some(Bytes::from(html[..split].to_vec()));
            injector.process(&mut body1, false);

            let mut body2 = Some(Bytes::from(html[split..].to_vec()));
            injector.process(&mut body2, true);

            let mut output = Vec::new();
            if let Some(b) = body1 {
                output.extend_from_slice(&b);
            }
            if let Some(b) = body2 {
                output.extend_from_slice(&b);
            }
            let result = std::str::from_utf8(&output).expect("valid UTF-8");
            assert!(
                result.contains("<script src=\"/_dwaar/a.js\" defer></script></head>"),
                "Failed at split position {split}: {result}"
            );
        }
    }

    #[test]
    fn multi_chunk_no_head_flushes_everything() {
        let mut injector = HtmlInjector::new();
        let mut total_output = 0;

        let mut body1 = Some(Bytes::from_static(b"<html><body>"));
        injector.process(&mut body1, false);
        if let Some(ref b) = body1 {
            total_output += b.len();
        }

        let mut body2 = Some(Bytes::from_static(b"content here"));
        injector.process(&mut body2, false);
        if let Some(ref b) = body2 {
            total_output += b.len();
        }

        let mut body3 = Some(Bytes::from_static(b"</body></html>"));
        injector.process(&mut body3, true);
        if let Some(ref b) = body3 {
            total_output += b.len();
        }

        let total_input = b"<html><body>content here</body></html>".len();
        assert_eq!(
            total_output, total_input,
            "data lost in multi-chunk pass-through"
        );
    }

    #[test]
    fn head_in_second_chunk_no_split() {
        let mut injector = HtmlInjector::new();

        let mut body1 = Some(Bytes::from_static(b"<html><head><title>Title</title>"));
        injector.process(&mut body1, false);

        let mut body2 = Some(Bytes::from_static(b"</head><body></body></html>"));
        injector.process(&mut body2, true);

        let mut output = Vec::new();
        if let Some(b) = body1 {
            output.extend_from_slice(&b);
        }
        if let Some(b) = body2 {
            output.extend_from_slice(&b);
        }
        let result = std::str::from_utf8(&output).expect("valid UTF-8");
        assert!(result.contains("<script src=\"/_dwaar/a.js\" defer></script></head>"));
    }

    #[test]
    fn find_case_insensitive_works() {
        assert_eq!(find_case_insensitive(b"Hello World", b"world"), Some(6));
        assert_eq!(find_case_insensitive(b"Hello World", b"HELLO"), Some(0));
        assert_eq!(find_case_insensitive(b"Hello", b"xyz"), None);
        assert_eq!(find_case_insensitive(b"Hi", b"Hello"), None);
        assert_eq!(find_case_insensitive(b"anything", b""), None);
    }

    // --- consent-gate tests ---

    #[allow(clippy::unnecessary_wraps)] // callers need `Option<Bytes>` for process_with_consent
    fn html_chunk() -> Option<Bytes> {
        Some(Bytes::from_static(
            b"<html><head><title>T</title></head><body></body></html>",
        ))
    }

    #[test]
    fn consent_disabled_injects_unconditionally() {
        let mut injector = HtmlInjector::new_with_consent(false);
        let mut body = html_chunk();
        injector.process_with_consent(&mut body, true, None, false);
        let result = std::str::from_utf8(body.as_ref().expect("body")).expect("utf8");
        assert!(result.contains("/_dwaar/a.js"));
    }

    #[test]
    fn consent_dnt_blocks_injection() {
        let mut injector = HtmlInjector::new_with_consent(true);
        let mut body = html_chunk();
        injector.process_with_consent(&mut body, true, Some("dwaar_consent=1"), true);
        // DNT wins even with a consent cookie present
        let result = body.expect("body");
        assert!(!result.windows(12).any(|w| w == b"/_dwaar/a.js"));
        assert_eq!(injector.state, State::Skipped);
    }

    #[test]
    fn consent_no_cookie_blocks_injection() {
        let mut injector = HtmlInjector::new_with_consent(true);
        let mut body = html_chunk();
        injector.process_with_consent(&mut body, true, None, false);
        let result = body.expect("body");
        assert!(!result.windows(12).any(|w| w == b"/_dwaar/a.js"));
        assert_eq!(injector.state, State::Skipped);
    }

    #[test]
    fn consent_wrong_cookie_blocks_injection() {
        let mut injector = HtmlInjector::new_with_consent(true);
        let mut body = html_chunk();
        injector.process_with_consent(&mut body, true, Some("session=abc; other=1"), false);
        let result = body.expect("body");
        assert!(!result.windows(12).any(|w| w == b"/_dwaar/a.js"));
    }

    #[test]
    fn consent_dwaar_consent_cookie_injects() {
        let mut injector = HtmlInjector::new_with_consent(true);
        let mut body = html_chunk();
        injector.process_with_consent(&mut body, true, Some("dwaar_consent=1"), false);
        let result = std::str::from_utf8(body.as_ref().expect("body")).expect("utf8");
        assert!(result.contains("/_dwaar/a.js"));
    }

    #[test]
    fn consent_analytics_consent_cookie_injects() {
        let mut injector = HtmlInjector::new_with_consent(true);
        let mut body = html_chunk();
        injector.process_with_consent(
            &mut body,
            true,
            Some("session=x; analytics_consent=1"),
            false,
        );
        let result = std::str::from_utf8(body.as_ref().expect("body")).expect("utf8");
        assert!(result.contains("/_dwaar/a.js"));
    }

    #[test]
    fn consent_cookie_key_case_insensitive() {
        let mut injector = HtmlInjector::new_with_consent(true);
        let mut body = html_chunk();
        injector.process_with_consent(&mut body, true, Some("DWAAR_CONSENT=1"), false);
        let result = std::str::from_utf8(body.as_ref().expect("body")).expect("utf8");
        assert!(result.contains("/_dwaar/a.js"));
    }

    #[test]
    fn has_analytics_consent_dnt_overrides_cookie() {
        assert!(!HtmlInjector::has_analytics_consent(
            Some("dwaar_consent=1"),
            true
        ));
    }

    #[test]
    fn has_analytics_consent_no_cookie() {
        assert!(!HtmlInjector::has_analytics_consent(None, false));
    }

    #[test]
    fn has_analytics_consent_positive() {
        assert!(HtmlInjector::has_analytics_consent(
            Some("dwaar_consent=1"),
            false
        ));
        assert!(HtmlInjector::has_analytics_consent(
            Some("analytics_consent=1"),
            false
        ));
    }

    #[test]
    fn respect_consent_field_accessible() {
        let a = HtmlInjector::new();
        assert!(!a.respect_consent);
        let b = HtmlInjector::new_with_consent(true);
        assert!(b.respect_consent);
    }
}
