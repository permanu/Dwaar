// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Error-capture script injection state machine.
//!
//! Scans HTML response body chunks for `</head>` and injects a
//! `<script defer src="..." data-project="...">` tag before it.
//! The script URL is sourced entirely from the `DWAAR_ERROR_SCRIPT_URL`
//! environment variable — no URLs are hardcoded in this module.
//! Designed for streaming: each call to [`ErrorScriptInjector::process()`]
//! handles one chunk.
//!
//! ## Activation
//!
//! Injection is gated on three conditions, all checked in `proxy.rs` before
//! an `ErrorScriptInjector` is created:
//!
//! 1. `DWAAR_ERROR_INJECTION=on` (default) and `DWAAR_ERROR_SCRIPT_URL` set
//!    to a non-empty value — both checked via [`ErrorScriptConfig::from_env()`].
//! 2. Response `Content-Type` is `text/html` (with or without charset).
//! 3. Upstream set `X-Permanu-Observe-Project: <project-id>` — without a project ID
//!    we have nothing to inject.
//!
//! The injector itself handles:
//! - CSP detection and skip (caller passes the CSP header value before streaming).
//! - Idempotency (already contains the configured origin marker).
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
//! - No double injection: skips if the configured origin marker already present.
//! - CSP-aware: skips if `Content-Security-Policy` exists and does NOT include
//!   the configured origin in `script-src` (logs a warning for operators).
//!
//! ## Environment variables
//!
//! | Variable | Default | Description |
//! |---|---|---|
//! | `DWAAR_ERROR_SCRIPT_URL` | _(none)_ | Full URL to the error-capture script, e.g. `https://errors.example.com/c.js`. Required; injection is disabled if absent. |
//! | `DWAAR_ERROR_INJECTION` | `on` | Set to `off` to disable injection globally. |
//! | `DWAAR_ERROR_PROJECT_HEADER` | — | Header the origin app sets to identify its Permanu project (read by proxy.rs). |

use bytes::{Bytes, BytesMut};
use tracing::warn;

/// Maximum bytes to scan before giving up on finding `</head>`.
/// 64 KB is enough for virtually all real HTML `<head>` sections.
const MAX_SCAN_BYTES: usize = 64 * 1024;

/// Carryover buffer size: longest needle minus 1.
/// `</head>` = 7 bytes → carryover needs at least 6.
/// Marker length varies by config; we use 22 as a safe default matching the
/// expected marker pattern `<host>/<path>` (covers up to 23-byte markers).
const CARRYOVER_SIZE: usize = 22;

/// The closing tag we inject before.
const HEAD_CLOSE: &[u8] = b"</head>";

/// Configuration for the error-script injector, sourced entirely from env.
///
/// Loaded per request (cheap — two env reads short-circuit when the feature
/// is disabled). If either `DWAAR_ERROR_INJECTION=off` or
/// `DWAAR_ERROR_SCRIPT_URL` unset/empty, the injector is disabled globally.
#[derive(Debug, Clone)]
pub struct ErrorScriptConfig {
    /// Full URL to the error-capture script, e.g. `https://errors.example.com/c.js`.
    pub script_url: String,
    /// Origin for CSP validation, e.g. `errors.example.com`.
    pub origin: String,
    /// Marker bytes for double-injection detection (origin + path portion).
    pub marker: Vec<u8>,
}

impl ErrorScriptConfig {
    /// Load from env. Returns `None` when the feature is disabled or config is
    /// absent/invalid — callers treat `None` as "skip injection for this request".
    pub fn from_env() -> Option<Self> {
        if std::env::var("DWAAR_ERROR_INJECTION")
            .ok()
            .as_deref()
            .is_some_and(|v| v.eq_ignore_ascii_case("off"))
        {
            return None;
        }
        let url = std::env::var("DWAAR_ERROR_SCRIPT_URL").ok()?;
        if url.trim().is_empty() {
            return None;
        }

        // Derive origin from URL (strip scheme, keep host).
        let without_scheme = url
            .trim_start_matches("https://")
            .trim_start_matches("http://");
        let origin = without_scheme
            .split(['/', ':', '?'])
            .next()
            .map(str::to_string)?;
        if origin.is_empty() {
            return None;
        }

        // Marker = origin + path portion (strip any query string).
        let marker_str = without_scheme.split('?').next()?;
        let marker = marker_str.as_bytes().to_vec();

        Some(Self {
            script_url: url,
            origin,
            marker,
        })
    }
}

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
/// - [`ErrorScriptConfig::from_env()`] returns `Some` (feature enabled + URL configured)
/// - Response is `text/html`
/// - `X-Permanu-Observe-Project` header is present
/// - CSP (if present) allows the configured origin in `script-src`
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
    /// Marker bytes used for double-injection detection.
    marker: Vec<u8>,
}

impl ErrorScriptInjector {
    /// Build a new injector for the given `project_id` and `config`.
    ///
    /// Returns `None` if `project_id` contains characters that would need
    /// HTML escaping (defence-in-depth: project IDs are UUID-class strings).
    pub fn new(project_id: &str, config: &ErrorScriptConfig) -> Option<Self> {
        // Reject anything that would break the HTML attribute value.
        // Project IDs are alphanumeric + hyphens/underscores only.
        if project_id
            .chars()
            .any(|c| matches!(c, '"' | '\'' | '<' | '>' | '&' | '\n' | '\r'))
        {
            return None;
        }

        let tag = build_script_tag(project_id, &config.script_url);
        Some(Self {
            state: State::Scanning,
            bytes_scanned: 0,
            carryover: BytesMut::new(),
            script_tag: tag,
            marker: config.marker.clone(),
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
        if find_bytes(&search_buf, &self.marker).is_some() {
            *body = Some(search_buf.freeze());
            self.state = State::Skipped;
            return;
        }

        // Search for </head> before checking budget.
        if let Some(pos) = find_case_insensitive(&search_buf, HEAD_CLOSE) {
            let mut buf = BytesMut::with_capacity(search_buf.len() + self.script_tag.len());
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
}

/// Build the `<script>` tag for the given project ID and script URL.
fn build_script_tag(project_id: &str, script_url: &str) -> Vec<u8> {
    let mut tag = Vec::with_capacity(40 + project_id.len() + script_url.len());
    tag.extend_from_slice(b"<script defer src=\"");
    tag.extend_from_slice(script_url.as_bytes());
    tag.extend_from_slice(b"\" data-project=\"");
    tag.extend_from_slice(project_id.as_bytes());
    tag.extend_from_slice(b"\"></script>");
    tag
}

/// Check whether injection should proceed given the response's CSP header value
/// and the configured origin.
///
/// Returns `true` when injection is safe:
/// - No CSP header → safe (no restriction).
/// - CSP has `script-src` that includes `origin` or `'unsafe-inline'`
///   or a wildcard `*` → safe.
/// - CSP has `script-src` that doesn't include the configured origin → NOT safe;
///   logs a warning so operators know to add it to their CSP.
/// - CSP has no `script-src` but has a `default-src` → check that instead.
///
/// This is a best-effort check. A strict CSP that blocks the configured script
/// means the user's browser would block the script anyway, so injection would be
/// pointless and confusing.
pub fn csp_allows_injection(csp: Option<&str>, origin: &str) -> bool {
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
        // Configured origin explicitly listed, optionally with a path.
        if token
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .starts_with(origin)
        {
            return true;
        }
    }

    // CSP exists and doesn't allow the configured origin.
    warn!(
        csp = policy,
        origin = origin,
        "error-script injection skipped: Content-Security-Policy does not include \
         the configured origin in script-src. Add it to script-src to enable \
         browser error capture."
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

/// Read the feature flag from the environment. Returns `true` (injection
/// enabled) when `ErrorScriptConfig::from_env()` would return `Some`.
///
/// Note: callers that also need the config should call `ErrorScriptConfig::from_env()`
/// directly rather than calling this function followed by another env read.
pub fn injection_enabled() -> bool {
    ErrorScriptConfig::from_env().is_some()
}

#[cfg(test)]
#[allow(unsafe_code)] // set_var/remove_var require unsafe in edition 2024; safe under ENV_LOCK serialization
mod tests {
    use super::*;
    use std::sync::Mutex;

    // ── Helpers ────────────────────────────────────────────────────────────────

    const PROJECT: &str = "proj-abc-123";

    /// Serializes env-touching tests so `cargo test`'s parallel runner doesn't
    /// race on `DWAAR_ERROR_INJECTION` / `DWAAR_ERROR_SCRIPT_URL`. Every test
    /// that calls `set_var` / `remove_var` must hold the guard for its
    /// duration. Without this, the suite is intermittently red on CI as one
    /// test's `remove_var` can land between another test's `set_var` and its
    /// `from_env()` read.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Convenience for the common pattern. Returns a guard whose Drop releases
    /// the lock at end of scope.
    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        // poisoned -> recover; a previous test panicked but the env state is
        // about to be reset by this test anyway.
        ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn test_config() -> ErrorScriptConfig {
        ErrorScriptConfig {
            script_url: "https://example-errors.test/c.js".to_string(),
            origin: "example-errors.test".to_string(),
            marker: b"example-errors.test/c.js".to_vec(),
        }
    }

    fn injector() -> ErrorScriptInjector {
        ErrorScriptInjector::new(PROJECT, &test_config()).expect("valid project id")
    }

    fn inject_once(html: &[u8]) -> Vec<u8> {
        let mut inj = injector();
        let mut body = Some(Bytes::from(html.to_vec()));
        inj.process(&mut body, true);
        body.map_or_else(Vec::new, |b| b.to_vec())
    }

    fn expected_tag() -> String {
        format!(
            "<script defer src=\"https://example-errors.test/c.js\" data-project=\"{PROJECT}\"></script>"
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
        let cfg = test_config();
        let html = format!(
            "<html><head><script defer src=\"{}\" \
             data-project=\"{PROJECT}\"></script></head><body></body></html>",
            cfg.script_url
        );
        let result = inject_once(html.as_bytes());
        let s = std::str::from_utf8(&result).expect("utf8");
        // The marker appears exactly once.
        assert_eq!(
            s.matches("example-errors.test/c.js").count(),
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
        let _g = env_guard();
        // Remove the env vars if set by another test, then verify default.
        // SAFETY: tests run single-threaded (cargo test --test-threads=1 or
        // within a single test binary). The env var is temporary and restored.
        unsafe {
            std::env::remove_var("DWAAR_ERROR_INJECTION");
            std::env::remove_var("DWAAR_ERROR_SCRIPT_URL");
        }
        // Without DWAAR_ERROR_SCRIPT_URL, injection_enabled returns false.
        assert!(!injection_enabled());
    }

    #[test]
    fn injection_disabled_by_env_var() {
        let _g = env_guard();
        unsafe {
            std::env::set_var("DWAAR_ERROR_INJECTION", "off");
            std::env::set_var("DWAAR_ERROR_SCRIPT_URL", "https://example-errors.test/c.js");
        }
        assert!(!injection_enabled());
        unsafe {
            std::env::remove_var("DWAAR_ERROR_INJECTION");
            std::env::remove_var("DWAAR_ERROR_SCRIPT_URL");
        }
    }

    #[test]
    fn injection_enabled_by_env_var_on() {
        let _g = env_guard();
        unsafe {
            std::env::set_var("DWAAR_ERROR_INJECTION", "on");
            std::env::set_var("DWAAR_ERROR_SCRIPT_URL", "https://example-errors.test/c.js");
        }
        assert!(injection_enabled());
        unsafe {
            std::env::remove_var("DWAAR_ERROR_INJECTION");
            std::env::remove_var("DWAAR_ERROR_SCRIPT_URL");
        }
    }

    #[test]
    fn injection_disabled_case_insensitive() {
        let _g = env_guard();
        unsafe {
            std::env::set_var("DWAAR_ERROR_INJECTION", "OFF");
            std::env::set_var("DWAAR_ERROR_SCRIPT_URL", "https://example-errors.test/c.js");
        }
        assert!(!injection_enabled());
        unsafe {
            std::env::remove_var("DWAAR_ERROR_INJECTION");
            std::env::remove_var("DWAAR_ERROR_SCRIPT_URL");
        }
    }

    // ── CSP checks ────────────────────────────────────────────────────────────

    #[test]
    fn csp_none_allows_injection() {
        assert!(csp_allows_injection(None, "example-errors.test"));
    }

    #[test]
    fn csp_with_our_origin_allows_injection() {
        let csp = "default-src 'self'; script-src 'self' https://example-errors.test";
        assert!(csp_allows_injection(Some(csp), "example-errors.test"));
    }

    #[test]
    fn csp_with_wildcard_allows_injection() {
        let csp = "script-src *";
        assert!(csp_allows_injection(Some(csp), "example-errors.test"));
    }

    #[test]
    fn csp_with_unsafe_inline_allows_injection() {
        let csp = "script-src 'self' 'unsafe-inline'";
        assert!(csp_allows_injection(Some(csp), "example-errors.test"));
    }

    #[test]
    fn csp_strict_without_our_origin_blocks_injection() {
        let csp = "default-src 'self'; script-src 'self' https://cdn.example.com";
        assert!(!csp_allows_injection(Some(csp), "example-errors.test"));
    }

    #[test]
    fn csp_with_default_src_fallback() {
        // No script-src; default-src includes our origin.
        let csp = "default-src 'self' https://example-errors.test";
        assert!(csp_allows_injection(Some(csp), "example-errors.test"));
    }

    #[test]
    fn csp_with_restrictive_default_src_blocks() {
        let csp = "default-src 'self'";
        assert!(!csp_allows_injection(Some(csp), "example-errors.test"));
    }

    #[test]
    fn csp_no_script_src_or_default_src_allows() {
        // Only unrelated directives — no restriction on scripts.
        let csp = "img-src 'self'; style-src 'self'";
        assert!(csp_allows_injection(Some(csp), "example-errors.test"));
    }

    // ── Missing project ID header → no injection ───────────────────────────────

    #[test]
    fn missing_project_id_means_no_injector_created() {
        let cfg = test_config();
        // In production, no X-Permanu-Observe-Project header → injector is never
        // created. Here we verify the constructor rejects invalid project IDs.
        assert!(ErrorScriptInjector::new("valid-id-123", &cfg).is_some());
        assert!(ErrorScriptInjector::new("", &cfg).is_some()); // empty = valid (caller guards against this)
        assert!(ErrorScriptInjector::new("bad\"id", &cfg).is_none());
        assert!(ErrorScriptInjector::new("bad<id", &cfg).is_none());
        assert!(ErrorScriptInjector::new("bad>id", &cfg).is_none());
        assert!(ErrorScriptInjector::new("bad'id", &cfg).is_none());
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
        assert!(
            s.contains(&format!("{tag}</head>")),
            "should inject despite large chunk"
        );
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
        let mut b = Some(Bytes::from_static(
            b"<html><head></head><body></body></html>",
        ));
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
        let cfg = test_config();
        let tag = build_script_tag("my-project-99", &cfg.script_url);
        let s = std::str::from_utf8(&tag).expect("utf8");
        assert!(s.contains("data-project=\"my-project-99\""));
        assert!(s.contains("https://example-errors.test/c.js"));
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
        let policy = "SCRIPT-SRC 'self' https://example-errors.test";
        let val =
            extract_csp_directive(policy, "script-src").expect("should find case-insensitively");
        assert!(val.contains("example-errors.test"));
    }

    // ── ErrorScriptConfig::from_env tests ─────────────────────────────────────

    #[test]
    fn config_from_env_unset_returns_none() {
        let _g = env_guard();
        unsafe {
            std::env::remove_var("DWAAR_ERROR_INJECTION");
            std::env::remove_var("DWAAR_ERROR_SCRIPT_URL");
        }
        assert!(ErrorScriptConfig::from_env().is_none());
    }

    #[test]
    fn config_from_env_empty_returns_none() {
        let _g = env_guard();
        unsafe {
            std::env::remove_var("DWAAR_ERROR_INJECTION");
            std::env::set_var("DWAAR_ERROR_SCRIPT_URL", "");
        }
        assert!(ErrorScriptConfig::from_env().is_none());
        unsafe { std::env::remove_var("DWAAR_ERROR_SCRIPT_URL") };
    }

    #[test]
    fn config_from_env_feature_off_returns_none() {
        let _g = env_guard();
        unsafe {
            std::env::set_var("DWAAR_ERROR_INJECTION", "off");
            std::env::set_var("DWAAR_ERROR_SCRIPT_URL", "https://errors.example.com/c.js");
        }
        assert!(ErrorScriptConfig::from_env().is_none());
        unsafe {
            std::env::remove_var("DWAAR_ERROR_INJECTION");
            std::env::remove_var("DWAAR_ERROR_SCRIPT_URL");
        }
    }

    #[test]
    fn config_derives_origin_from_url() {
        let _g = env_guard();
        unsafe {
            std::env::remove_var("DWAAR_ERROR_INJECTION");
            std::env::set_var("DWAAR_ERROR_SCRIPT_URL", "https://errors.example.com/c.js");
        }
        let cfg = ErrorScriptConfig::from_env().expect("should succeed");
        assert_eq!(cfg.origin, "errors.example.com");
        assert_eq!(cfg.marker, b"errors.example.com/c.js");
        unsafe { std::env::remove_var("DWAAR_ERROR_SCRIPT_URL") };
    }

    #[test]
    fn config_with_port() {
        let _g = env_guard();
        unsafe {
            std::env::remove_var("DWAAR_ERROR_INJECTION");
            std::env::set_var(
                "DWAAR_ERROR_SCRIPT_URL",
                "https://errors.example.com:9000/c.js",
            );
        }
        let cfg = ErrorScriptConfig::from_env().expect("should succeed");
        // Origin strips port (split on ':').
        assert_eq!(cfg.origin, "errors.example.com");
        // Marker includes host:port and path from without_scheme.
        assert_eq!(cfg.marker, b"errors.example.com:9000/c.js");
        unsafe { std::env::remove_var("DWAAR_ERROR_SCRIPT_URL") };
    }
}
