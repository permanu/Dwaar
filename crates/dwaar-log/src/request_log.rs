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

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use compact_str::CompactString;
use serde::Serialize;

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<CompactString>,

    /// Host header value (or :authority for HTTP/2)
    pub host: CompactString,

    /// HTTP response status code
    pub status: u16,

    /// Total time from request received to response sent (microseconds)
    pub response_time_us: u64,

    /// Client's IP address (direct connection, not from X-Forwarded-For)
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
        }
    }

    #[test]
    fn serialize_to_json() {
        let log = sample_log();
        let json = serde_json::to_string(&log).expect("serialize");

        assert!(json.contains("\"method\":\"GET\""));
        assert!(json.contains("\"status\":200"));
        assert!(json.contains("\"client_ip\":\"192.168.1.100\""));
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
        log.client_ip = "::1".parse().expect("ipv6");

        let json = serde_json::to_string(&log).expect("serialize");
        assert!(json.contains("\"client_ip\":\"::1\""));
    }

    #[test]
    fn request_log_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RequestLog>();
    }
}
