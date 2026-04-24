// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Error-capture script injection state machine.
//!
//! Scans HTML response body chunks for `</head>` and injects a
//! `<script defer src="https://errors.permanu.com/c.js" data-project="...">` tag
//! before it. Designed for streaming: each call to [`ErrorScriptInjector::process()`]
//! handles one chunk.
//!
//! ## Activation
//!
//! Injection is gated on three conditions, all checked in `proxy.rs` before
//! an `ErrorScriptInjector` is created:
//!
//! 1. `DWAAR_ERROR_INJECTION=on` (default) — feature flag, env var read once at startup.
//! 2. Response `Content-Type` is `text/html` (with or without charset).
//! 3. Upstream set `X-Permanu-Observe-Project: <project-id>` — without a project ID
//!    we have nothing to inject.
//!
//! The injector itself handles:
//! - CSP detection and skip (caller passes the CSP header value before streaming).
//! - Idempotency (already contains `errors.permanu.com/c.js`).
//! - Scan-budget enforcement (64 KB default; skip if `</head>` not found in time).
//!
//! ## Pipeline position
//!
//! ```text
//! upstream chunk → decompress → inject analytics → INJECT ERROR SCRIPT → compress → client
//! ```
//!
//! Error-script injection runs AFTER analytics injection so the two script tags
//! don't interfere (both look for `</head>`; analytics runs first).
//!
//! ## Security properties
//!
//! - Bounded scan: gives up after [`MAX_SCAN_BYTES`] without `</head>`.
//! - Case-insensitive: handles `</head>`, `</HEAD>`, `</Head>`, etc.
//! - No double injection: skips if `errors.permanu.com/c.js` already present.
//! - CSP-aware: skips if `Content-Security-Policy` exists and does NOT include
//!   `errors.permanu.com` in `script-src` (logs a warning for operators).

use bytes::{Bytes, BytesMut};
use tracing::warn;

/// Maximum bytes to scan before giving up on finding `</head>`.
/// 64 KB is enough for virtually all real HTML `<head>` sections.
const MAX_SCAN_BYTES: usize = 64 * 1024;

/// Carryover buffer size: longest needle minus 1.
/// Longest needle: `errors.permanu.com/c.js` = 23 bytes → carryover = 22.
/// `</head>` = 7 bytes → carryover = 6.
/// Use the larger of the two.
const CARRYOVER_SIZE: usize = 22;

/// Marker checked for double-injection detection.
const ALREADY_INJECTED_MARKER: &[u8] = b"errors.permanu.com/c.js";

/// The closing tag we inject before.
const HEAD_CLOSE: &[u8] = b"</head>";

/// Our domain, used for CSP validation.
const OUR_ORIGIN: &str = "errors.permanu.com";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Actively scanning chunks for `</head>`.
    Scanning,
    /// Injection complete — pass through all remaining chunks.
    Done,
    /// Gave up or skipped — pass through without injection.
    Skipped,
}

/// Per-request error-script injector.
///
/// Created in `response_filter()` when:
/// - `DWAAR_ERROR_INJECTION=on`
/// - Response is `text/html`
/// - `X-Permanu-Observe-Project` header is present
/// - CSP (if present) allows `errors.permanu.com` in `script-src`
///
/// Stored in `RequestContext.error_script_injector`. Each call to
/// [`process()`] handles one body chunk from `response_body_filter()`.
#[derive(Debug)]
pub struct ErrorScriptInjector {
    state: State,
    bytes_scanned: usize,
    /// Last `CARRYOVER_SIZE` bytes from the previous chunk, held back so we
    /// can detect needles split across chunk boundaries.
    carryover: BytesMut,
    /// The full `<script ...></script>` tag to inject.
    script_tag: Vec<u8>,
}

impl ErrorScriptInjector {
    /// Build a new injector for the given `project_id`.
    ///
    /// Returns `None` if `project_id` contains characters that would need
    /// HTML escaping (defence-in-depth: project IDs are UUID-class strings).
    pub fn new(project_id: &str) -> Option<Self> {
        // Reject anything that would break the HTML attribute value.
        // Project IDs are alphanumeric + hyphens/underscores only.
        if project_id
            .chars()
            .any(|c| matches!(c, '"' | '\'' | '<' | '>' | '&' | '\n' | '\r'))
        {
            return None;
        }

        let tag = build_script_tag(project_id);
        Some(Self {
            state: State::Scanning,
            bytes_scanned: 0,
            carryover: BytesMut::new(),
            script_tag: tag,
        })
    }

    /// Whether the injector is still actively scanning.
    pub fn is_active(&self) -> bool {
        self.state == State::Scanning
    }

    /// Process one body chunk. Modifies `body` in place if injection occurs.
    ///
    /// Call this from `response_body_filter()` for every chunk.
    /// When `end_of_stream` is true and scanning is still active, transitions
    /// to Skipped (HTML never had `</head>`).
    pub fn process(&mut self, body: &mut Option<Bytes>, end_of_stream: bool) {
        if self.state != State::Scanning {
            return;
        }

        let Some(ref data) = *body else {
            if end_of_stream {
                if !self.carryover.is_empty() {
                    *body = Some(self.carryover.split().freeze());
                }
                self.state = State::Skipped;
            }
            return;
        };

        // Build search window: held carryover + current chunk.
        let mut search_buf = std::mem::take(&mut self.carryover);
        search_buf.extend_from_slice(data);

        // Double-injection check.
        if find_bytes(&search_buf, ALREADY_INJECTED_MARKER).is_some() {
            *body = Some(search_buf.freeze());
            self.state = State::Skipped;
            return;
        }

        // Search for </head> before checking budget.
        if let Some(pos) = find_case_insensitive(&search_buf, HEAD_CLOSE) {
            let mut buf =
                BytesMut::with_capacity(search_buf.len() + self.script_tag.len());
            buf.extend_from_slice(&search_buf[..pos]);
            buf.extend_from_slice(&self.script_tag);
            buf.extend_from_slice(&search_buf[pos..]);
            *body = Some(buf.freeze());
            self.state = State::Done;
            return;
        }

        // Update scan budget.
        self.bytes_scanned += data.len();
        if self.bytes_scanned > MAX_SCAN_BYTES {
            *body = Some(search_buf.freeze());
            self.state = State::Skipped;
            return;
        }

        // Hold back the last CARRYOVER_SIZE bytes for boundary detection.
        let total_len = search_buf.len();
        if total_len > CARRYOVER_SIZE {
            let split_at = total_len - CARRYOVER_SIZE;
            self.carryover = BytesMut::from(&search_buf[split_at..]);
            *body = Some(search_buf.freeze().slice(..split_at));
        } else {
            self.carryover = search_buf;
            *body = Some(Bytes::new());
        }

        if end_of_stream {
            if !self.carryover.is_empty() {
                let flush = std::mem::take(&mut self.carryover);
                if let Some(existing) = body.take() {
                    let mut combined =
                        BytesMut::with_capacity(existing.len() + flush.len());
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
}

/// Build the `<script>` tag for the given project ID.
fn build_script_tag(project_id: &str) -> Vec<u8> {
    let mut tag = Vec::with_capacity(80 + project_id.len());
    tag.extend_from_slice(b"<script defer src=\"https://errors.permanu.com/c.js\" data-project=\"");
    tag.extend_from_slice(project_id.as_bytes());
    tag.extend_from_slice(b"\"></script>");
    tag
}

/// Check whether injection should proceed given the response's CSP header value.
///
/// Returns `true` when injection is safe:
/// - No CSP header → safe (no restriction).
/// - CSP has `script-src` that includes `errors.permanu.com` or `'unsafe-inline'`
///   or a wildcard `*` → safe.
/// - CSP has `script-src` that doesn't include our origin → NOT safe; logs a
///   warning so operators know to add `errors.permanu.com` to their CSP.
/// - CSP has no `script-src` but has a `default-src` → check that instead.
///
/// This is a best-effort check. A strict CSP that blocks our script means
/// the user's browser would block the script anyway, so injection would be
/// pointless and confusing.
pub fn csp_allows_injection(csp: Option<&str>) -> bool {
    let Some(policy) = csp else {
        return true;
    };

    // Extract the relevant source list: prefer `script-src`, fall back to
    // `default-src`.
    let src_list = extract_csp_directive(policy, "script-src")
        .or_else(|| extract_csp_directive(policy, "default-src"));

    let Some(src) = src_list else {
        // No script-src or default-src → unrestricted scripts allowed.
        return true;
    };

    // Check for tokens that permit our script.
    for token in src.split_whitespace() {
        // Wildcard: allows anything.
        if token == "*" {
            return true;
        }
        // 'unsafe-inline' typically coexists with our script being allowed.
        // We're conservative: if unsafe-inline is present, assume our hash/host
        // would be redundant but injection is still harmless.
        if token.eq_ignore_ascii_case("'unsafe-inline'") {
            return true;
        }
        // Our origin explicitly listed, optionally with a path.
        if token
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .starts_with(OUR_ORIGIN)
        {
            return true;
        }
    }

    // CSP exists and doesn't allow our origin.
    warn!(
        csp = policy,
        "error-script injection skipped: Content-Security-Policy does not include \
         errors.permanu.com in script-src. Add 'https://errors.permanu.com' to \
         script-src to enable browser error capture for this app."
    );
    false
}

/// Extract the value of a CSP directive (e.g., `"script-src"`) from a full
/// CSP policy string. Returns the source list (everything after the directive
/// keyword up to the next semicolon), or `None` if the directive isn't present.
fn extract_csp_directive<'a>(policy: &'a str, directive: &str) -> Option<&'a str> {
    for part in policy.split(';') {
        let part = part.trim();
        // Split on first whitespace: "script-src https://... 'nonce-...'"
        if let Some((name, value)) = part.split_once(char::is_whitespace) {
            if name.trim().eq_ignore_ascii_case(directive) {
                return Some(value.trim());
            }
        } else if part.eq_ignore_ascii_case(directive) {
            // Directive present with no sources (e.g., "script-src" alone means block all)
            return Some("");
        }
    }
    None
}

/// Case-insensitive byte search. Returns the byte offset of the first match
/// of `needle` in `haystack`, or `None`.
fn find_case_insensitive(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle))
}

/// Case-sensitive byte search (used for the already-injected marker which
/// contains lowercase ASCII only).
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Read the feature flag from the environment. Called once at proxy startup.
/// Returns `true` (injection enabled) unless `DWAAR_ERROR_INJECTION=off`.
pub fn injection_enabled() -> bool {
    std::env::var("DWAAR_ERROR_INJECTION")
        .map(|v| !v.eq_ignore_ascii_case("off"))
        .unwrap_or(true)
}

#[cfg(test)]
#[allow(unsafe_code)] // set_var/remove_var require unsafe in edition 2024; safe in single-threaded test context
mod tests {
    use super::*;

    // ── Helpers ────────────────────────────────────────────────────────────────

    const PROJECT: &str = "proj-abc-123";

    fn injector() -> ErrorScriptInjector {
        ErrorScriptInjector::new(PROJECT).expect("valid project id")
    }

    fn inject_once(html: &[u8]) -> Vec<u8> {
        let mut inj = injector();
        let mut body = Some(Bytes::from(html.to_vec()));
        inj.process(&mut body, true);
        body.map_or_else(Vec::new, |b| b.to_vec())
    }

    fn expected_tag() -> String {
        format!(
            "<script defer src=\"https://errors.permanu.com/c.js\" data-project=\"{PROJECT}\"></script>"
        )
    }

    // ── Core injection ─────────────────────────────────────────────────────────

    #[test]
    fn injects_before_head_close() {
        let html = b"<html><head><title>Test</title></head><body></body></html>";
        let result = inject_once(html);
        let s = std::str::from_utf8(&result).expect("utf8");
        let tag = expected_tag();
        assert!(
            s.contains(&format!("{tag}</head>")),
            "expected tag before </head>, got: {s}"
        );
    }

    #[test]
    fn injects_before_uppercase_head_close() {
        let html = b"<html><head><title>T</title></HEAD><body></body></html>";
        let result = inject_once(html);
        let s = std::str::from_utf8(&result).expect("utf8");
        let tag = expected_tag();
        // Should inject before the (uppercase) </HEAD> tag.
        assert!(s.contains(&format!("{tag}</HEAD>")), "got: {s}");
    }

    #[test]
    fn injects_before_mixed_case_head_close() {
        let html = b"<html><head></Head><body></body></html>";
        let result = inject_once(html);
        let s = std::str::from_utf8(&result).expect("utf8");
        let tag = expected_tag();
        assert!(s.contains(&format!("{tag}</Head>")), "got: {s}");
    }

    // ── Non-injection cases ────────────────────────────────────────────────────

    #[test]
    fn no_modification_for_non_html() {
        // This test exercises the injector directly; in production,
        // non-HTML responses never get an injector created for them.
        let data = br#"{"key":"value"}"#;
        let result = inject_once(data);
        // No </head> → unchanged.
        assert_eq!(result, data);
    }

    #[test]
    fn no_double_injection() {
        let html = format!(
            "<html><head><script defer src=\"https://errors.permanu.com/c.js\" \
             data-project=\"{PROJECT}\"></script></head><body></body></html>"
        );
        let result = inject_once(html.as_bytes());
        let s = std::str::from_utf8(&result).expect("utf8");
        // The marker appears exactly once.
        assert_eq!(
            s.matches("errors.permanu.com/c.js").count(),
            1,
            "should not double-inject, got: {s}"
        );
    }

    #[test]
    fn no_injection_when_no_head_tag() {
        let html = b"<html><body>No head tag here</body></html>";
        let result = inject_once(html);
        assert_eq!(result, html);
    }

    // ── Feature flag ──────────────────────────────────────────────────────────

    #[test]
    fn injection_enabled_by_default() {
        // Remove the env var if set by another test, then verify default.
        // SAFETY: tests run single-threaded (cargo test --test-threads=1 or
        // within a single test binary). The env var is temporary and restored.
        unsafe { std::env::remove_var("DWAAR_ERROR_INJECTION") };
        assert!(injection_enabled());
    }

    #[test]
    fn injection_disabled_by_env_var() {
        unsafe { std::env::set_var("DWAAR_ERROR_INJECTION", "off") };
        assert!(!injection_enabled());
        unsafe { std::env::remove_var("DWAAR_ERROR_INJECTION") };
    }

    #[test]
    fn injection_enabled_by_env_var_on() {
        unsafe { std::env::set_var("DWAAR_ERROR_INJECTION", "on") };
        assert!(injection_enabled());
        unsafe { std::env::remove_var("DWAAR_ERROR_INJECTION") };
    }

    #[test]
    fn injection_disabled_case_insensitive() {
        unsafe { std::env::set_var("DWAAR_ERROR_INJECTION", "OFF") };
        assert!(!injection_enabled());
        unsafe { std::env::remove_var("DWAAR_ERROR_INJECTION") };
    }

    // ── CSP checks ────────────────────────────────────────────────────────────

    #[test]
    fn csp_none_allows_injection() {
        assert!(csp_allows_injection(None));
    }

    #[test]
    fn csp_with_our_origin_allows_injection() {
        let csp = "default-src 'self'; script-src 'self' https://errors.permanu.com";
        assert!(csp_allows_injection(Some(csp)));
    }

    #[test]
    fn csp_with_wildcard_allows_injection() {
        let csp = "script-src *";
        assert!(csp_allows_injection(Some(csp)));
    }

    #[test]
    fn csp_with_unsafe_inline_allows_injection() {
        let csp = "script-src 'self' 'unsafe-inline'";
        assert!(csp_allows_injection(Some(csp)));
    }

    #[test]
    fn csp_strict_without_our_origin_blocks_injection() {
        let csp = "default-src 'self'; script-src 'self' https://cdn.example.com";
        assert!(!csp_allows_injection(Some(csp)));
    }

    #[test]
    fn csp_with_default_src_fallback() {
        // No script-src; default-src includes our origin.
        let csp = "default-src 'self' https://errors.permanu.com";
        assert!(csp_allows_injection(Some(csp)));
    }

    #[test]
    fn csp_with_restrictive_default_src_blocks() {
        let csp = "default-src 'self'";
        assert!(!csp_allows_injection(Some(csp)));
    }

    #[test]
    fn csp_no_script_src_or_default_src_allows() {
        // Only unrelated directives — no restriction on scripts.
        let csp = "img-src 'self'; style-src 'self'";
        assert!(csp_allows_injection(Some(csp)));
    }

    // ── Missing project ID header → no injection ───────────────────────────────

    #[test]
    fn missing_project_id_means_no_injector_created() {
        // In production, no X-Permanu-Observe-Project header → injector is never
        // created. Here we verify the constructor rejects invalid project IDs.
        assert!(ErrorScriptInjector::new("valid-id-123").is_some());
        assert!(ErrorScriptInjector::new("").is_some()); // empty = valid (caller guards against this)
        assert!(ErrorScriptInjector::new("bad\"id").is_none());
        assert!(ErrorScriptInjector::new("bad<id").is_none());
        assert!(ErrorScriptInjector::new("bad>id").is_none());
        assert!(ErrorScriptInjector::new("bad'id").is_none());
    }

    // ── Size cap ──────────────────────────────────────────────────────────────

    #[test]
    fn skips_when_head_beyond_64kb() {
        // Body that exceeds 64 KB with no </head> → injector gives up.
        let large = vec![b'x'; MAX_SCAN_BYTES + 100];
        let result = inject_once(&large);
        // Result should be the original bytes (no injection, no truncation).
        assert_eq!(result, large);
        // </head> at end: injector already skipped, so it's not injected.
        let mut inj = injector();
        let mut body1 = Some(Bytes::from(vec![b'x'; MAX_SCAN_BYTES + 100]));
        inj.process(&mut body1, false);
        assert!(!inj.is_active());
        let mut body2 = Some(Bytes::from_static(b"</head>"));
        let original = body2.clone();
        inj.process(&mut body2, true);
        assert_eq!(body2, original, "skipped injector must not modify body");
    }

    #[test]
    fn injects_when_head_in_chunk_that_crosses_budget() {
        // The </head> is in the same chunk that crosses the budget → inject anyway.
        let mut big = vec![b'x'; MAX_SCAN_BYTES + 100];
        big.extend_from_slice(b"</head>");
        let result = inject_once(&big);
        let tag = expected_tag();
        let s = std::str::from_utf8(&result).expect("utf8");
        assert!(s.contains(&format!("{tag}</head>")), "should inject despite large chunk");
        assert_eq!(result.len(), big.len() + tag.len());
    }

    // ── Cross-chunk boundary detection ────────────────────────────────────────

    #[test]
    fn detects_head_close_split_across_chunks() {
        // </head> split: chunk1 ends with "</he", chunk2 starts with "ad>"
        let mut inj = injector();
        let mut body1 = Some(Bytes::from_static(b"<html><head><title>T</title></he"));
        inj.process(&mut body1, false);
        let mut body2 = Some(Bytes::from_static(b"ad><body></body></html>"));
        inj.process(&mut body2, true);

        let mut out = Vec::new();
        if let Some(b) = body1 {
            out.extend_from_slice(&b);
        }
        if let Some(b) = body2 {
            out.extend_from_slice(&b);
        }
        let s = std::str::from_utf8(&out).expect("utf8");
        let tag = expected_tag();
        assert!(
            s.contains(&format!("{tag}</head>")),
            "expected injection across boundary, got: {s}"
        );
    }

    #[test]
    fn cross_chunk_split_at_every_position() {
        let html = b"<html><head></head><body></body></html>";
        let head_start = html
            .windows(7)
            .position(|w| w.eq_ignore_ascii_case(b"</head>"))
            .expect("test HTML must contain </head>");

        for split in head_start + 1..head_start + 7 {
            let mut inj = injector();
            let mut body1 = Some(Bytes::from(html[..split].to_vec()));
            inj.process(&mut body1, false);
            let mut body2 = Some(Bytes::from(html[split..].to_vec()));
            inj.process(&mut body2, true);

            let mut out = Vec::new();
            if let Some(b) = body1 {
                out.extend_from_slice(&b);
            }
            if let Some(b) = body2 {
                out.extend_from_slice(&b);
            }
            let s = std::str::from_utf8(&out).expect("utf8");
            let tag = expected_tag();
            assert!(
                s.contains(&format!("{tag}</head>")),
                "failed at split {split}: {s}"
            );
        }
    }

    // ── State machine transitions ──────────────────────────────────────────────

    #[test]
    fn state_done_after_injection() {
        let mut inj = injector();
        assert!(inj.is_active());
        let mut body = Some(Bytes::from_static(b"<html><head></head></html>"));
        inj.process(&mut body, true);
        assert!(!inj.is_active());
    }

    #[test]
    fn state_skipped_on_end_without_head() {
        let mut inj = injector();
        let mut body = Some(Bytes::from_static(b"<html><body>no head</body></html>"));
        inj.process(&mut body, true);
        assert!(!inj.is_active());
        assert_eq!(inj.state, State::Skipped);
    }

    #[test]
    fn pass_through_after_done() {
        let mut inj = injector();
        let mut body1 = Some(Bytes::from_static(b"<html><head></head>"));
        inj.process(&mut body1, false);
        // May or may not be done yet depending on chunk boundary — but once done:
        let mut inj2 = injector();
        let mut b = Some(Bytes::from_static(b"<html><head></head><body></body></html>"));
        inj2.process(&mut b, false);
        // Already processed to done; next chunk passes through.
        if !inj2.is_active() {
            let mut b2 = Some(Bytes::from_static(b"<extra>content</extra>"));
            let original = b2.clone();
            inj2.process(&mut b2, true);
            assert_eq!(b2, original);
        }
    }

    // ── Multi-chunk no-modification data integrity ─────────────────────────────

    #[test]
    fn multi_chunk_no_head_preserves_all_bytes() {
        let mut inj = injector();
        let mut total = 0usize;

        let mut b1 = Some(Bytes::from_static(b"<html><body>"));
        inj.process(&mut b1, false);
        if let Some(ref b) = b1 {
            total += b.len();
        }

        let mut b2 = Some(Bytes::from_static(b"content here"));
        inj.process(&mut b2, false);
        if let Some(ref b) = b2 {
            total += b.len();
        }

        let mut b3 = Some(Bytes::from_static(b"</body></html>"));
        inj.process(&mut b3, true);
        if let Some(ref b) = b3 {
            total += b.len();
        }

        assert_eq!(total, b"<html><body>content here</body></html>".len());
    }

    // ── Script tag shape ──────────────────────────────────────────────────────

    #[test]
    fn script_tag_contains_project_id() {
        let tag = build_script_tag("my-project-99");
        let s = std::str::from_utf8(&tag).expect("utf8");
        assert!(s.contains("data-project=\"my-project-99\""));
        assert!(s.contains("https://errors.permanu.com/c.js"));
        assert!(s.contains("defer"));
    }

    // ── CSP directive extraction ───────────────────────────────────────────────

    #[test]
    fn extract_csp_directive_finds_script_src() {
        let policy = "default-src 'self'; script-src 'self' https://cdn.example.com";
        let val = extract_csp_directive(policy, "script-src").expect("should find");
        assert!(val.contains("cdn.example.com"));
    }

    #[test]
    fn extract_csp_directive_missing_returns_none() {
        let policy = "default-src 'self'";
        assert!(extract_csp_directive(policy, "script-src").is_none());
    }

    #[test]
    fn extract_csp_directive_case_insensitive() {
        let policy = "SCRIPT-SRC 'self' https://errors.permanu.com";
        let val = extract_csp_directive(policy, "script-src").expect("should find case-insensitively");
        assert!(val.contains("errors.permanu.com"));
    }
}
