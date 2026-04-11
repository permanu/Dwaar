// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Structured request log entry.
//!
//! Every completed HTTP request produces a `RequestLog` with 20+ fields
//! capturing timing, identity, routing, security, and performance data.
//! Serializes to JSON for piping to log aggregators.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use chrono::{DateTime, Utc};
use compact_str::CompactString;
use serde::{Serialize, Serializer};

/// Stopgap gate for client IP anonymization.
///
/// When `true`, `client_ip` is anonymized at serialization time:
///   - IPv4: last octet zeroed (keeps /24 prefix).
///   - IPv6: segments 3–7 zeroed (keeps /48 prefix).
///
/// A struct field would be the correct long-term home for this flag, but that
/// would require every call site constructing `RequestLog` via struct literal
/// to add the field — breaking callers across all crates. The module-level
/// const avoids that breakage until a builder/default pattern is adopted.
/// When that refactor lands, remove this const and wire the flag through the
/// struct instead.
const ANONYMIZE_CLIENT_IP: bool = true;

// ---------------------------------------------------------------------------
// IP anonymization
// ---------------------------------------------------------------------------

/// Anonymize an IP address for privacy-safe logging.
///
/// IPv4: zeros the last octet, retaining the /24 prefix.
/// IPv6: zeros segments 3–7, retaining the /48 prefix (first 3 segments).
fn anonymize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            IpAddr::V4(Ipv4Addr::new(a, b, c, 0))
        }
        IpAddr::V6(v6) => {
            let [s0, s1, s2, _, _, _, _, _] = v6.segments();
            IpAddr::V6(Ipv6Addr::new(s0, s1, s2, 0, 0, 0, 0, 0))
        }
    }
}

fn serialize_client_ip<S: Serializer>(ip: &IpAddr, s: S) -> Result<S::Ok, S::Error> {
    if ANONYMIZE_CLIENT_IP {
        anonymize_ip(*ip).serialize(s)
    } else {
        ip.serialize(s)
    }
}

// ---------------------------------------------------------------------------
// Query-string redaction
// ---------------------------------------------------------------------------

/// Sensitive query-parameter key names (case-insensitive match).
const REDACT_KEYS: &[&str] = &[
    "token",
    "key",
    "secret",
    "password",
    "api_key",
    "access_token",
    "auth",
];

/// Redact values of sensitive keys in a query string.
///
/// Accepts a full URL path (with or without `?`).  Borrows the original
/// string unchanged when no query is present or no sensitive key is found
/// (common hot path).  Allocates only when at least one value is redacted.
fn redact_query(path: &str) -> std::borrow::Cow<'_, str> {
    // Split at '?': if no query present, borrow as-is.
    let Some((_, query)) = path.split_once('?') else {
        return std::borrow::Cow::Borrowed(path);
    };

    let mut changed = false;
    let parts: Vec<std::borrow::Cow<'_, str>> = query
        .split('&')
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let sensitive = REDACT_KEYS.iter().any(|&kw| k.eq_ignore_ascii_case(kw));
            if sensitive && !v.is_empty() {
                changed = true;
                std::borrow::Cow::Owned(format!("{k}=REDACTED"))
            } else {
                std::borrow::Cow::Borrowed(pair)
            }
        })
        .collect();

    if !changed {
        return std::borrow::Cow::Borrowed(path);
    }

    // Re-join with '?' prefix so the caller can strip it uniformly.
    let mut out = String::with_capacity(query.len() + 1);
    out.push('?');
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        out.push_str(p.as_ref());
    }
    std::borrow::Cow::Owned(out)
}

#[allow(clippy::ref_option)] // serde serialize_with requires &Option<T>
fn serialize_query<S: Serializer>(val: &Option<CompactString>, s: S) -> Result<S::Ok, S::Error> {
    match val {
        None => s.serialize_none(),
        Some(q) => {
            // Synthesize a '?'-prefixed string so redact_query can split on '?'.
            let synthetic = format!("?{}", q.as_str());
            let redacted = redact_query(&synthetic);
            // Strip the leading '?' we added before serializing.
            let out = redacted.trim_start_matches('?');
            s.serialize_some(out)
        }
    }
}

// ---------------------------------------------------------------------------
// Referer redaction (M-24)
// ---------------------------------------------------------------------------

/// Maximum number of raw bytes to keep from a malformed Referer header.
const REFERER_RAW_FALLBACK_LEN: usize = 128;

/// Redact sensitive query parameters from a Referer URL (M-24).
fn redact_referer(raw: &str) -> String {
    let Some((base, query)) = raw.split_once('?') else {
        if raw.len() > REFERER_RAW_FALLBACK_LEN {
            return raw[..REFERER_RAW_FALLBACK_LEN].to_owned();
        }
        return raw.to_owned();
    };
    let synthetic = format!("?{query}");
    let redacted = redact_query(&synthetic);
    let redacted_query = redacted.trim_start_matches('?');
    format!("{base}?{redacted_query}")
}

#[allow(clippy::ref_option)] // serde serialize_with requires &Option<T>
fn serialize_referer<S: Serializer>(val: &Option<CompactString>, s: S) -> Result<S::Ok, S::Error> {
    match val {
        None => s.serialize_none(),
        Some(r) => s.serialize_some(&redact_referer(r.as_str())),
    }
}

// ---------------------------------------------------------------------------
// Upstream error-body sanitization (H-12)
// ---------------------------------------------------------------------------

/// Maximum length of a captured upstream error body after redaction.
const ERROR_BODY_MAX_LEN: usize = 256;

/// Sanitize a captured upstream error body for privacy-safe logging.
///
/// Error bodies routinely contain stack traces, internal IPs, DB
/// credentials, emails, PEM blocks, and API tokens — this helper scrubs
/// those patterns with single-pass byte scans (no regex crate — zero
/// extra binary size) and truncates to [`ERROR_BODY_MAX_LEN`] bytes.
///
/// Patterns redacted: IPv4/IPv6 literals → `IP_REDACTED`, emails →
/// `EMAIL_REDACTED`, `Bearer <token>` (16+ chars) → `TOKEN_REDACTED`,
/// AWS access keys (`AKIA` + 16 alnum) → `AWS_KEY_REDACTED`, PEM blocks
/// → `PEM_REDACTED`.
#[must_use]
pub fn sanitize_error_body(raw: &[u8]) -> String {
    let slice = &raw[..raw.len().min(4096)];
    let text = String::from_utf8_lossy(slice);
    let redacted = redact_common_patterns(&text);
    truncate_utf8(&redacted, ERROR_BODY_MAX_LEN)
}

/// Manual pattern redaction. Order matters: PEM first (contains
/// newlines we don't want re-scanned for tokens), then everything else.
fn redact_common_patterns(input: &str) -> String {
    let mut out = redact_pem_blocks(input);
    out = redact_bearer_tokens(&out);
    out = redact_aws_keys(&out);
    out = redact_emails(&out);
    out = redact_ipv4_literals(&out);
    out = redact_ipv6_literals(&out);
    out
}

fn redact_pem_blocks(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find("-----BEGIN ") {
        out.push_str(&rest[..start]);
        out.push_str("PEM_REDACTED");
        let after = &rest[start..];
        if let Some(end_rel) = after.find("-----END ") {
            // Skip past `-----END ` (9 bytes) and scan for the closing
            // run of dashes — otherwise we'd re-match the opening dashes
            // of the END marker as the closing dashes.
            let label_start = end_rel + 9;
            if let Some(trail_rel) = after[label_start..].find("-----") {
                rest = &after[label_start + trail_rel + 5..];
                continue;
            }
        }
        // Unterminated PEM — drop the rest as opaque material.
        rest = "";
    }
    out.push_str(rest);
    out
}

fn redact_bearer_tokens(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        let remaining = &bytes[i..];
        let is_bearer = remaining.len() >= 7
            && remaining[..6].eq_ignore_ascii_case(b"bearer")
            && remaining[6].is_ascii_whitespace();
        if is_bearer {
            let tok_start = i + 7;
            let mut tok_end = tok_start;
            while tok_end < bytes.len() {
                let b = bytes[tok_end];
                if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' {
                    tok_end += 1;
                } else {
                    break;
                }
            }
            if tok_end - tok_start >= 16 {
                out.push_str("TOKEN_REDACTED");
                i = tok_end;
                continue;
            }
        }
        let ch_start = i;
        i += 1;
        while i < bytes.len() && (bytes[i] & 0b1100_0000) == 0b1000_0000 {
            i += 1;
        }
        out.push_str(&s[ch_start..i]);
    }
    out
}

fn redact_aws_keys(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if i + 20 <= bytes.len() && &bytes[i..i + 4] == b"AKIA" {
            let rest = &bytes[i + 4..i + 20];
            if rest
                .iter()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            {
                out.push_str("AWS_KEY_REDACTED");
                i += 20;
                continue;
            }
        }
        let ch_start = i;
        i += 1;
        while i < bytes.len() && (bytes[i] & 0b1100_0000) == 0b1000_0000 {
            i += 1;
        }
        out.push_str(&s[ch_start..i]);
    }
    out
}

fn redact_emails(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'@' {
            let mut local_start = i;
            while local_start > 0 && is_email_local_byte(bytes[local_start - 1]) {
                local_start -= 1;
            }
            let mut dom_end = i + 1;
            while dom_end < bytes.len() && is_email_domain_byte(bytes[dom_end]) {
                dom_end += 1;
            }
            let local_ok = local_start < i;
            let domain = &bytes[i + 1..dom_end];
            let has_dot = domain.contains(&b'.');
            if local_ok && has_dot && !domain.is_empty() {
                let drop_len = i - local_start;
                out.truncate(out.len() - drop_len);
                out.push_str("EMAIL_REDACTED");
                i = dom_end;
                continue;
            }
        }
        let ch_start = i;
        i += 1;
        while i < bytes.len() && (bytes[i] & 0b1100_0000) == 0b1000_0000 {
            i += 1;
        }
        out.push_str(&s[ch_start..i]);
    }
    out
}

fn is_email_local_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+' | b'%')
}

fn is_email_domain_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-')
}

fn redact_ipv4_literals(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit()
            && !is_alnum_before(bytes, i)
            && let Some(consumed) = match_ipv4(&bytes[i..])
        {
            out.push_str("IP_REDACTED");
            i += consumed;
            continue;
        }
        let ch_start = i;
        i += 1;
        while i < bytes.len() && (bytes[i] & 0b1100_0000) == 0b1000_0000 {
            i += 1;
        }
        out.push_str(&s[ch_start..i]);
    }
    out
}

fn match_ipv4(bytes: &[u8]) -> Option<usize> {
    let mut pos = 0;
    for octet in 0..4 {
        if pos >= bytes.len() || !bytes[pos].is_ascii_digit() {
            return None;
        }
        let mut digits = 0;
        while digits < 3 && pos < bytes.len() && bytes[pos].is_ascii_digit() {
            pos += 1;
            digits += 1;
        }
        if octet < 3 {
            if pos >= bytes.len() || bytes[pos] != b'.' {
                return None;
            }
            pos += 1;
        }
    }
    if pos < bytes.len() && (bytes[pos].is_ascii_digit() || bytes[pos] == b'.') {
        return None;
    }
    Some(pos)
}

fn is_alnum_before(bytes: &[u8], i: usize) -> bool {
    i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'.')
}

fn redact_ipv6_literals(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if is_ipv6_start(bytes, i) {
            let start = i;
            let mut end = i;
            let mut colons = 0;
            while end < bytes.len() {
                let b = bytes[end];
                if b == b':' {
                    colons += 1;
                    end += 1;
                } else if b.is_ascii_hexdigit() {
                    end += 1;
                } else {
                    break;
                }
            }
            if colons >= 2 && end - start >= 4 {
                out.push_str("IP_REDACTED");
                i = end;
                continue;
            }
        }
        let ch_start = i;
        i += 1;
        while i < bytes.len() && (bytes[i] & 0b1100_0000) == 0b1000_0000 {
            i += 1;
        }
        out.push_str(&s[ch_start..i]);
    }
    out
}

fn is_ipv6_start(bytes: &[u8], i: usize) -> bool {
    if i >= bytes.len() {
        return false;
    }
    let b = bytes[i];
    if !(b.is_ascii_hexdigit() || b == b':') {
        return false;
    }
    if i > 0 {
        let prev = bytes[i - 1];
        if prev.is_ascii_alphanumeric() || prev == b':' {
            return false;
        }
    }
    true
}

fn truncate_utf8(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_owned();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_owned()
}

#[allow(clippy::ref_option)] // serde serialize_with requires &Option<T>
fn serialize_error_body<S: Serializer>(val: &Option<String>, s: S) -> Result<S::Ok, S::Error> {
    match val {
        None => s.serialize_none(),
        Some(body) => s.serialize_some(&sanitize_error_body(body.as_bytes())),
    }
}

// ---------------------------------------------------------------------------
// Struct
// ---------------------------------------------------------------------------

/// A complete log entry for one proxied HTTP request.
///
/// Built in the `logging()` callback after the response is sent.
/// All timing is in microseconds for sub-millisecond precision.
///
/// String fields use `CompactString` — stores ≤24 bytes inline without
/// heap allocation. HTTP methods, short paths, hostnames, country codes,
/// TLS versions, and upstream addresses all fit inline.
#[derive(Debug, Clone, Serialize)]
pub struct RequestLog {
    /// When the request arrived (UTC)
    pub timestamp: DateTime<Utc>,

    /// Unique request identifier (UUID v7, time-sortable)
    pub request_id: CompactString,

    /// HTTP method (GET, POST, etc.)
    pub method: CompactString,

    /// Request path (without query string)
    pub path: CompactString,

    /// Query string, if present
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_query"
    )]
    pub query: Option<CompactString>,

    /// Host header value (or :authority for HTTP/2)
    pub host: CompactString,

    /// HTTP response status code
    pub status: u16,

    /// Total time from request received to response sent (microseconds)
    pub response_time_us: u64,

    /// Client's IP address (direct connection, not from X-Forwarded-For)
    #[serde(serialize_with = "serialize_client_ip")]
    pub client_ip: IpAddr,

    /// User-Agent header
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<CompactString>,

    /// Referer header — query string redacted at serialize time (M-24).
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_referer"
    )]
    pub referer: Option<CompactString>,

    /// Response body size in bytes
    pub bytes_sent: u64,

    /// Request body size in bytes
    pub bytes_received: u64,

    /// TLS version (e.g., "TLSv1.3"), None for plaintext
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_version: Option<CompactString>,

    /// HTTP version (e.g., "HTTP/1.1", "HTTP/2")
    pub http_version: CompactString,

    /// Whether the request was classified as a bot
    pub is_bot: bool,

    /// Country code from `GeoIP` lookup (e.g., "US", "IN")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<CompactString>,

    /// Upstream backend address (e.g., "127.0.0.1:8080")
    pub upstream_addr: CompactString,

    /// Time the upstream took to respond (microseconds)
    pub upstream_response_time_us: u64,

    /// Cache status if applicable (e.g., "HIT", "MISS")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_status: Option<CompactString>,

    /// Compression algorithm applied (e.g., "gzip", "br")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compression: Option<CompactString>,

    /// W3C trace ID for distributed tracing correlation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<CompactString>,

    /// First 1KB of upstream response body on 5xx errors.
    /// Enables downstream error tracking without app-level instrumentation.
    ///
    /// Serialization runs [`sanitize_error_body`] so PII and secrets are
    /// scrubbed before the line ever hits disk (H-12).
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_error_body"
    )]
    pub upstream_error_body: Option<String>,

    /// Plugin that rejected the request, if any (e.g., `"rate_limit"`).
    /// `&'static str` — zero per-request allocation (#128).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejected_by: Option<&'static str>,

    /// Plugin that blocked the request, if any (e.g., `"bot_detection"`).
    /// `&'static str` — zero per-request allocation (#128).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_by: Option<&'static str>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn sample_log() -> RequestLog {
        RequestLog {
            timestamp: Utc::now(),
            request_id: "01924f5c-7e2a-7d00-b3f4-deadbeef1234".into(),
            method: "GET".into(),
            path: "/api/users".into(),
            query: Some("page=1&limit=20".into()),
            host: "api.example.com".into(),
            status: 200,
            response_time_us: 1234,
            client_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            user_agent: Some("Mozilla/5.0".into()),
            referer: Some("https://example.com".into()),
            bytes_sent: 4096,
            bytes_received: 256,
            tls_version: Some("TLSv1.3".into()),
            http_version: "HTTP/2".into(),
            is_bot: false,
            country: Some("US".into()),
            upstream_addr: "127.0.0.1:8080".into(),
            upstream_response_time_us: 980,
            cache_status: None,
            compression: Some("gzip".into()),
            trace_id: None,
            upstream_error_body: None,
            rejected_by: None,
            blocked_by: None,
        }
    }

    #[test]
    fn serialize_to_json() {
        let log = sample_log();
        let json = serde_json::to_string(&log).expect("serialize");

        assert!(json.contains("\"method\":\"GET\""));
        assert!(json.contains("\"status\":200"));
        // ANONYMIZE_CLIENT_IP = true: last octet zeroed
        assert!(json.contains("\"client_ip\":\"192.168.1.0\""));
        assert!(json.contains("\"is_bot\":false"));
        assert!(json.contains("\"request_id\":\"01924f5c"));
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let log = sample_log();
        let json = serde_json::to_string(&log).expect("serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");

        assert_eq!(parsed["method"], "GET");
        assert_eq!(parsed["status"], 200);
        assert_eq!(parsed["response_time_us"], 1234);
        assert_eq!(parsed["host"], "api.example.com");
    }

    #[test]
    fn optional_fields_omitted_when_none() {
        let mut log = sample_log();
        log.query = None;
        log.user_agent = None;
        log.referer = None;
        log.tls_version = None;
        log.country = None;
        log.cache_status = None;
        log.compression = None;

        let json = serde_json::to_string(&log).expect("serialize");

        assert!(!json.contains("\"query\""));
        assert!(!json.contains("\"user_agent\""));
        assert!(!json.contains("\"referer\""));
        assert!(!json.contains("\"tls_version\""));
        assert!(!json.contains("\"country\""));
        assert!(!json.contains("\"cache_status\""));
        assert!(!json.contains("\"compression\""));

        // Required fields still present
        assert!(json.contains("\"method\""));
        assert!(json.contains("\"host\""));
        assert!(json.contains("\"status\""));
    }

    #[test]
    fn ipv6_client_ip_serializes() {
        let mut log = sample_log();
        log.client_ip = "2001:db8:85a3::8a2e:370:7334".parse().expect("ipv6");

        let json = serde_json::to_string(&log).expect("serialize");
        // ANONYMIZE_CLIENT_IP = true: segments 3-7 zeroed, keeps /48
        assert!(json.contains("\"client_ip\":\"2001:db8:85a3::\""));
    }

    #[test]
    fn request_log_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RequestLog>();
    }

    #[test]
    fn upstream_error_body_present_on_5xx() {
        let mut log = sample_log();
        log.status = 500;
        log.upstream_error_body = Some("Internal Server Error".to_string());

        let json = serde_json::to_string(&log).expect("serialize");
        assert!(json.contains("\"upstream_error_body\":\"Internal Server Error\""));
    }

    #[test]
    fn upstream_error_body_absent_on_200() {
        let log = sample_log();
        let json = serde_json::to_string(&log).expect("serialize");
        assert!(!json.contains("upstream_error_body"));
    }

    #[test]
    fn trace_id_present_when_set() {
        let mut log = sample_log();
        log.trace_id = Some("4bf92f3577b34da6a3ce929d0e0e4736".into());

        let json = serde_json::to_string(&log).expect("serialize");
        assert!(json.contains("\"trace_id\":\"4bf92f3577b34da6a3ce929d0e0e4736\""));
    }

    #[test]
    fn client_ip_v4_anonymized() {
        let mut log = sample_log();
        log.client_ip = "203.0.113.42".parse().expect("ipv4");
        let json = serde_json::to_string(&log).expect("serialize");
        assert!(json.contains("\"client_ip\":\"203.0.113.0\""));
    }

    #[test]
    fn client_ip_v6_anonymized() {
        let mut log = sample_log();
        log.client_ip = "2001:db8:1234:5678:abcd:ef01:2345:6789"
            .parse()
            .expect("ipv6");
        let json = serde_json::to_string(&log).expect("serialize");
        // Keeps first 3 segments (2001:db8:1234), zeros 3-7
        assert!(json.contains("\"client_ip\":\"2001:db8:1234::\""));
    }

    #[test]
    fn query_sensitive_keys_redacted() {
        let mut log = sample_log();
        log.query = Some("page=1&token=abc123&limit=20".into());
        let json = serde_json::to_string(&log).expect("serialize");
        assert!(json.contains("token=REDACTED"));
        assert!(!json.contains("abc123"));
        assert!(json.contains("page=1"));
        assert!(json.contains("limit=20"));
    }

    #[test]
    fn query_non_sensitive_keys_pass_through() {
        let mut log = sample_log();
        log.query = Some("page=2&sort=asc".into());
        let json = serde_json::to_string(&log).expect("serialize");
        assert!(json.contains("\"query\":\"page=2&sort=asc\""));
    }

    #[test]
    fn query_all_sensitive_variants_redacted() {
        for key in &[
            "token",
            "key",
            "secret",
            "password",
            "api_key",
            "access_token",
            "auth",
            "TOKEN",
            "Password",
        ] {
            let mut log = sample_log();
            log.query = Some(format!("{key}=shouldbegone").into());
            let json = serde_json::to_string(&log).expect("serialize");
            assert!(
                !json.contains("shouldbegone"),
                "key '{key}' was not redacted"
            );
        }
    }

    #[test]
    fn query_none_omitted() {
        let mut log = sample_log();
        log.query = None;
        let json = serde_json::to_string(&log).expect("serialize");
        assert!(!json.contains("\"query\""));
    }

    #[test]
    fn rejected_by_and_blocked_by_omitted_when_none() {
        let log = sample_log();
        let json = serde_json::to_string(&log).expect("serialize");
        assert!(!json.contains("\"rejected_by\""));
        assert!(!json.contains("\"blocked_by\""));
    }

    #[test]
    fn rejected_by_serialized_when_set() {
        let mut log = sample_log();
        log.status = 429;
        log.rejected_by = Some("rate_limit");
        let json = serde_json::to_string(&log).expect("serialize");
        assert!(json.contains("\"rejected_by\":\"rate_limit\""));
        assert!(!json.contains("\"blocked_by\""));
    }

    #[test]
    fn blocked_by_serialized_when_set() {
        let mut log = sample_log();
        log.status = 403;
        log.blocked_by = Some("bot_detection");
        let json = serde_json::to_string(&log).expect("serialize");
        assert!(json.contains("\"blocked_by\":\"bot_detection\""));
        assert!(!json.contains("\"rejected_by\""));
    }

    // H-12 tests -------------------------------------------------------

    #[test]
    fn sanitize_error_body_strips_ipv4() {
        let out = sanitize_error_body(b"connect to 10.0.1.42 failed");
        assert!(!out.contains("10.0.1.42"), "got: {out}");
        assert!(out.contains("IP_REDACTED"));
    }

    #[test]
    fn sanitize_error_body_strips_ipv6() {
        let out = sanitize_error_body(b"origin=2001:db8::1 backend error");
        assert!(!out.contains("2001:db8"), "got: {out}");
        assert!(out.contains("IP_REDACTED"));
    }

    #[test]
    fn sanitize_error_body_strips_email() {
        let out = sanitize_error_body(b"notify alice.bob@corp.example.com about outage");
        assert!(!out.contains("alice.bob@corp"), "got: {out}");
        assert!(out.contains("EMAIL_REDACTED"));
    }

    #[test]
    fn sanitize_error_body_strips_pem_block() {
        let pem = b"cert=-----BEGIN CERTIFICATE-----\nabcDEF\n-----END CERTIFICATE-----\ntail";
        let out = sanitize_error_body(pem);
        assert!(!out.contains("CERTIFICATE"), "got: {out}");
        assert!(!out.contains("abcDEF"), "got: {out}");
        assert!(out.contains("PEM_REDACTED"));
    }

    #[test]
    fn sanitize_error_body_strips_bearer_token() {
        let out = sanitize_error_body(b"Authorization: Bearer abcdef0123456789ZZZ trailing");
        assert!(!out.contains("abcdef0123456789"), "got: {out}");
        assert!(out.contains("TOKEN_REDACTED"));
    }

    #[test]
    fn sanitize_error_body_strips_aws_key() {
        let out = sanitize_error_body(b"key=AKIAIOSFODNN7EXAMPLE used");
        assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"), "got: {out}");
        assert!(out.contains("AWS_KEY_REDACTED"));
    }

    #[test]
    fn sanitize_error_body_multi_pattern_and_truncation() {
        let raw = b"stack trace from 192.168.1.1 contacted support@example.com \
                    with Bearer abcdefghijklmnopqrstuvwxyz inside. \
                    extra padding text to force truncation beyond 256 bytes. \
                    extra padding text to force truncation beyond 256 bytes. \
                    extra padding text to force truncation beyond 256 bytes. \
                    extra padding text to force truncation beyond 256 bytes.";
        let out = sanitize_error_body(raw);
        assert!(!out.contains("192.168.1.1"));
        assert!(!out.contains("support@example.com"));
        assert!(!out.contains("abcdefghijklmnopqrstuvwxyz"));
        assert!(out.len() <= 256);
    }

    #[test]
    fn sanitize_error_body_preserves_plain_text() {
        let out = sanitize_error_body(b"Internal Server Error");
        assert_eq!(out, "Internal Server Error");
    }

    #[test]
    fn sanitize_error_body_handles_non_utf8() {
        let mut bytes: Vec<u8> = b"partial ".to_vec();
        bytes.push(0xFF);
        bytes.extend_from_slice(b" tail");
        let out = sanitize_error_body(&bytes);
        assert!(out.contains("partial"));
        assert!(out.contains("tail"));
    }

    #[test]
    fn upstream_error_body_is_redacted_on_serialize() {
        let mut log = sample_log();
        log.status = 500;
        log.upstream_error_body = Some(
            "db connect 10.2.3.4 failed user=root@prod.internal token=Bearer \
             0123456789abcdefghij pem=-----BEGIN RSA PRIVATE KEY-----\nsecret\n\
             -----END RSA PRIVATE KEY-----"
                .to_owned(),
        );
        let json = serde_json::to_string(&log).expect("serialize");
        assert!(!json.contains("10.2.3.4"));
        assert!(!json.contains("root@prod.internal"));
        assert!(!json.contains("0123456789abcdefghij"));
        assert!(!json.contains("PRIVATE KEY"));
        assert!(json.contains("IP_REDACTED"));
        assert!(json.contains("EMAIL_REDACTED"));
        assert!(json.contains("TOKEN_REDACTED"));
        assert!(json.contains("PEM_REDACTED"));
    }

    // M-24 tests -------------------------------------------------------

    #[test]
    fn referer_sensitive_query_redacted() {
        let mut log = sample_log();
        log.referer = Some("https://example.com/path?token=SECRET&q=hello".into());
        let json = serde_json::to_string(&log).expect("serialize");
        assert!(json.contains("token=REDACTED"));
        assert!(!json.contains("SECRET"));
        assert!(json.contains("q=hello"));
        assert!(json.contains("https://example.com/path"));
    }

    #[test]
    fn referer_without_query_passes_through() {
        let mut log = sample_log();
        log.referer = Some("https://example.com/home".into());
        let json = serde_json::to_string(&log).expect("serialize");
        assert!(json.contains("\"referer\":\"https://example.com/home\""));
    }

    #[test]
    fn referer_malformed_truncated() {
        let mut entry = sample_log();
        let payload = "x".repeat(500);
        entry.referer = Some(payload.clone().into());
        let json = serde_json::to_string(&entry).expect("serialize");
        assert!(!json.contains(&payload));
    }
}
