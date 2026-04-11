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

    /// Referer header
    #[serde(skip_serializing_if = "Option::is_none")]
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
    #[serde(skip_serializing_if = "Option::is_none")]
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
}
