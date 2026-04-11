// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Beacon collection — parses and enriches analytics events from the
//! client-side JavaScript beacon sent to `/_dwaar/collect`.
//!
//! ## IP anonymization policy (Guardrail #35, M-22)
//!
//! All analytics IP addresses — whether they arrive via the beacon POST
//! or via the server-side request log — are anonymized to the same prefix
//! before they touch any aggregation structure:
//!
//! - IPv4 → `/24` (zero the last octet)
//! - IPv6 → `/48` (zero segments 3..8, keeping the first three 16-bit
//!   groups = 48 bits of prefix)
//!
//! The canonical function is [`anonymize_ip`]. **Every** caller that
//! inserts an IP into the unique-visitors `HyperLogLog` MUST go through
//! this function — otherwise a single visitor counted via the beacon
//! path would be counted again via the log path (they'd hash differently
//! once one side preserves more entropy than the other).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Anonymize an IP address for GDPR compliance.
///
/// IPv4 → `/24` (zero the last octet).
/// IPv6 → `/48` (zero segments 3..8, keeping the first 48 bits).
///
/// Guardrail #35 (Privacy by Default) makes anonymization mandatory for
/// analytics. Consistency between the beacon path and the server-log
/// path is tracked as issue M-22 — both paths must route through this
/// single function so the `HyperLogLog` unique-visitor count is stable
/// regardless of which path saw a given request first.
pub fn anonymize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let mut octets = v4.octets();
            octets[3] = 0;
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        IpAddr::V6(v6) => {
            // 8 × 16-bit segments. Keeping [0..3] and zeroing [3..8]
            // retains 48 bits of prefix (= /48), matching the client
            // expectations documented in the analytics module header.
            let mut segments = v6.segments();
            for s in &mut segments[3..] {
                *s = 0;
            }
            IpAddr::V6(Ipv6Addr::from(segments))
        }
    }
}

/// Maximum beacon body size in bytes. Rejects payloads larger than this
/// to prevent memory exhaustion from oversized POSTs.
pub const MAX_BEACON_SIZE: usize = 4096;

/// Raw beacon payload as sent by the analytics JavaScript.
/// Short field names match the JS: `u` = URL, `r` = referrer, etc.
#[derive(Debug, Deserialize)]
pub struct RawBeacon {
    /// Page URL (required)
    pub u: String,
    /// Referrer URL
    pub r: Option<String>,
    /// Screen width
    pub sw: Option<u32>,
    /// Screen height
    pub sh: Option<u32>,
    /// Browser language
    pub lg: Option<String>,
    /// Largest Contentful Paint (ms)
    pub lcp: Option<f64>,
    /// Cumulative Layout Shift
    pub cls: Option<f64>,
    /// Interaction to Next Paint (ms)
    pub inp: Option<f64>,
    /// Time on page (ms)
    pub tp: Option<u64>,
    /// HMAC nonce (base64url, issued server-side at page-load time).
    /// Missing/empty on unauthenticated beacons — the server rejects
    /// those in `proxy::handle_beacon` before they reach aggregation.
    #[serde(default)]
    pub nonce: Option<String>,
    /// HMAC signature (hex) corresponding to `nonce`. See `crate::auth`.
    #[serde(default)]
    pub sig: Option<String>,
}

/// Maximum path length retained in `top_pages`. URLs longer than this
/// are truncated at a UTF-8 character boundary. Keeps the bounded
/// counters' working set tiny and prevents a flood of pathological URLs
/// from evicting legitimate entries (C-05).
pub const MAX_PATH_LEN: usize = 512;

/// Maximum referrer host length retained in `referrers`.
pub const MAX_REFERRER_HOST_LEN: usize = 128;

/// Sanitize a client-supplied URL into the path we store in aggregation.
///
/// Rules (C-05):
///
/// 1. Reject anything containing `://` — the field is supposed to be a
///    same-origin path, not an absolute URL to an arbitrary host. The
///    client-side beacon sends `location.href` which IS absolute; we
///    strip the scheme+host here rather than in the JS so the filter is
///    enforced server-side.
/// 2. Reject anything containing control characters or NUL bytes.
/// 3. Truncate at [`MAX_PATH_LEN`] on a UTF-8 boundary.
/// 4. Drop the query string (we aggregate by page, not by query).
///
/// Returns `None` if the URL fails any of the validation rules.
pub fn sanitize_url_to_path(url: &str) -> Option<String> {
    // Fast-path rejection: control bytes (including NUL) are always bogus.
    if url.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return None;
    }

    // Strip scheme+host if present. The client sends `location.href`,
    // so this is the usual shape: `https://example.com/path?q=1`.
    // We keep only the path portion.
    let path_start = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"));

    let path = if let Some(rest) = path_start {
        // After stripping scheme, the first '/' begins the path.
        // If there is none, the URL is just a host → path "/".
        rest.find('/').map_or("/", |i| &rest[i..])
    } else {
        // No scheme. Reject anything that still smells like an
        // absolute URL to prevent `//attacker.com/foo`-style
        // protocol-relative references or nested scheme separators.
        if url.contains("://") || url.starts_with("//") {
            return None;
        }
        url
    };

    // Drop the query string.
    let path = path.split('?').next().unwrap_or(path);

    if path.is_empty() {
        return None;
    }

    // Truncate on a char boundary to honour `MAX_PATH_LEN`.
    let truncated = if path.len() > MAX_PATH_LEN {
        let mut end = MAX_PATH_LEN;
        while end > 0 && !path.is_char_boundary(end) {
            end -= 1;
        }
        &path[..end]
    } else {
        path
    };

    Some(truncated.to_string())
}

/// Sanitize a client-supplied referrer into the host we store in
/// aggregation.
///
/// Returns only the host portion (lowercased, no port, no path) and
/// truncated to [`MAX_REFERRER_HOST_LEN`]. Rejects anything that can't
/// be parsed as a URL or that contains control bytes.
pub fn sanitize_referrer_host(referrer: &str) -> Option<String> {
    if referrer.is_empty() {
        return None;
    }
    if referrer.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return None;
    }

    let without_scheme = referrer
        .strip_prefix("https://")
        .or_else(|| referrer.strip_prefix("http://"))?;

    let host = without_scheme.split('/').next()?;
    let host = host.split(':').next()?; // strip port
    if host.is_empty() {
        return None;
    }

    let lower = host.to_ascii_lowercase();
    if lower.len() > MAX_REFERRER_HOST_LEN {
        // Truncating a hostname changes its semantic meaning entirely —
        // better to drop it than to record a half-domain that could
        // misattribute the referral.
        return None;
    }
    Some(lower)
}

/// Enriched beacon event — the raw beacon plus server-side context.
/// This is what gets pushed to the analytics aggregation pipeline.
#[derive(Debug, Serialize)]
pub struct BeaconEvent {
    /// When the beacon was received (server timestamp)
    pub timestamp: DateTime<Utc>,
    /// Page URL
    pub url: String,
    /// Referrer URL
    pub referrer: Option<String>,
    /// Screen dimensions
    pub screen_width: Option<u32>,
    pub screen_height: Option<u32>,
    /// Browser language
    pub language: Option<String>,
    /// Web Vitals
    pub lcp_ms: Option<f64>,
    pub cls: Option<f64>,
    pub inp_ms: Option<f64>,
    /// Time spent on page (ms)
    pub time_on_page_ms: Option<u64>,
    /// Client IP (from TCP connection, not from beacon)
    pub client_ip: IpAddr,
    /// `GeoIP` country code (if available, populated later)
    pub country: Option<String>,
    /// Whether the client is a known bot
    pub is_bot: bool,
    /// The host/domain this beacon belongs to
    pub host: String,
}

impl BeaconEvent {
    /// Create an enriched event from a raw beacon and server-side context.
    pub fn from_raw(raw: RawBeacon, client_ip: IpAddr, host: String) -> Self {
        Self {
            timestamp: Utc::now(),
            url: raw.u,
            referrer: raw.r,
            screen_width: raw.sw,
            screen_height: raw.sh,
            language: raw.lg,
            lcp_ms: raw.lcp,
            cls: raw.cls,
            inp_ms: raw.inp,
            time_on_page_ms: raw.tp,
            client_ip: anonymize_ip(client_ip),
            country: None, // Populated by GeoIP in ISSUE-034
            is_bot: false, // Populated by bot detection in ISSUE-030
            host,
        }
    }
}

/// Channel sender type for pushing beacon events to the aggregation pipeline.
/// The receiver lives in the analytics aggregation service (ISSUE-028).
pub type BeaconSender = tokio::sync::mpsc::Sender<BeaconEvent>;

/// Create a bounded channel for beacon events.
/// Capacity of 8192 matches the log writer's channel size.
pub fn beacon_channel() -> (BeaconSender, tokio::sync::mpsc::Receiver<BeaconEvent>) {
    tokio::sync::mpsc::channel(8192)
}

/// Parse a raw beacon from JSON bytes. Returns an error message on failure.
pub fn parse_beacon(body: &[u8]) -> Result<RawBeacon, String> {
    if body.is_empty() {
        return Err("empty beacon body".to_string());
    }
    if body.len() > MAX_BEACON_SIZE {
        return Err(format!(
            "beacon body too large: {} bytes (max {})",
            body.len(),
            MAX_BEACON_SIZE
        ));
    }
    serde_json::from_slice(body).map_err(|e| format!("invalid beacon JSON: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn parse_full_beacon() {
        let json = br#"{"u":"https://example.com","r":"https://google.com","sw":1920,"sh":1080,"lg":"en-US","lcp":1234,"cls":0.05,"inp":80,"tp":15000}"#;
        let raw = parse_beacon(json).expect("valid beacon");
        assert_eq!(raw.u, "https://example.com");
        assert_eq!(raw.r.as_deref(), Some("https://google.com"));
        assert_eq!(raw.sw, Some(1920));
        assert_eq!(raw.lcp, Some(1234.0));
        assert_eq!(raw.tp, Some(15000));
    }

    #[test]
    fn parse_minimal_beacon() {
        let json = br#"{"u":"https://example.com"}"#;
        let raw = parse_beacon(json).expect("valid beacon");
        assert_eq!(raw.u, "https://example.com");
        assert!(raw.r.is_none());
        assert!(raw.sw.is_none());
        assert!(raw.lcp.is_none());
    }

    #[test]
    fn parse_empty_body_fails() {
        let result = parse_beacon(b"");
        assert!(result.is_err());
        assert!(result.expect_err("should fail").contains("empty"));
    }

    #[test]
    fn parse_oversized_body_fails() {
        let big = vec![b'x'; MAX_BEACON_SIZE + 1];
        let result = parse_beacon(&big);
        assert!(result.is_err());
        assert!(result.expect_err("should fail").contains("too large"));
    }

    #[test]
    fn parse_invalid_json_fails() {
        let result = parse_beacon(b"not json");
        assert!(result.is_err());
        assert!(result.expect_err("should fail").contains("invalid"));
    }

    #[test]
    fn parse_missing_url_fails() {
        let result = parse_beacon(br#"{"sw":1920}"#);
        assert!(result.is_err());
    }

    #[test]
    fn enrich_beacon_sets_server_fields() {
        let raw = RawBeacon {
            u: "https://example.com".to_string(),
            r: None,
            sw: None,
            sh: None,
            lg: None,
            lcp: None,
            cls: None,
            inp: None,
            tp: None,
            nonce: None,
            sig: None,
        };
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let event = BeaconEvent::from_raw(raw, ip, "example.com".to_string());
        // IP is anonymized to /24 — last octet zeroed
        assert_eq!(event.client_ip, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 0)));
        assert_eq!(event.host, "example.com");
        assert!(!event.is_bot);
        assert!(event.country.is_none());
    }

    #[test]
    fn beacon_event_serializes_to_json() {
        let raw = parse_beacon(br#"{"u":"https://example.com","tp":5000}"#).expect("valid");
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let event = BeaconEvent::from_raw(raw, ip, "example.com".to_string());
        let json = serde_json::to_string(&event).expect("serialize");
        assert!(json.contains("\"url\":\"https://example.com\""));
        assert!(json.contains("\"time_on_page_ms\":5000"));
    }

    // --- M-22: IPv6 anonymization policy ---

    #[test]
    fn ipv6_anonymized_to_48_prefix() {
        let ip: IpAddr = "2001:db8:1:2:3:4:5:6".parse().expect("valid v6");
        let out = anonymize_ip(ip);
        // First three segments preserved (48 bits), rest zeroed.
        let IpAddr::V6(v6) = out else {
            panic!("expected v6")
        };
        let segments = v6.segments();
        assert_eq!(segments[0], 0x2001);
        assert_eq!(segments[1], 0xdb8);
        assert_eq!(segments[2], 0x1);
        for &s in &segments[3..] {
            assert_eq!(s, 0, "segment {s:04x} not zeroed");
        }
    }

    #[test]
    fn anonymize_is_idempotent() {
        // Running the function twice must produce the same output.
        let v4: IpAddr = "1.2.3.4".parse().expect("v4");
        assert_eq!(anonymize_ip(anonymize_ip(v4)), anonymize_ip(v4));

        let v6: IpAddr = "2001:db8:1::1".parse().expect("v6");
        assert_eq!(anonymize_ip(anonymize_ip(v6)), anonymize_ip(v6));
    }

    // --- C-05: beacon URL / referrer sanitization ---

    #[test]
    fn sanitize_url_strips_scheme_and_query() {
        let out = sanitize_url_to_path("https://example.com/about?q=1").expect("ok");
        assert_eq!(out, "/about");
    }

    #[test]
    fn sanitize_url_rejects_absolute_http_outside_scheme_prefix() {
        // A bare "https://evil.com" with no path becomes "/" after strip —
        // we accept that since it resolves to the domain root. The
        // important rejection is embedded schemes.
        assert!(sanitize_url_to_path("javascript://evil").is_none());
        assert!(sanitize_url_to_path("ftp://evil.com/x").is_none());
    }

    #[test]
    fn sanitize_url_rejects_control_chars() {
        assert!(sanitize_url_to_path("/path\x00with\x00nul").is_none());
        assert!(sanitize_url_to_path("/path\nwith\nnewline").is_none());
    }

    #[test]
    fn sanitize_url_rejects_protocol_relative() {
        assert!(sanitize_url_to_path("//attacker.com/foo").is_none());
    }

    #[test]
    fn sanitize_url_truncates_long_path() {
        let mut long = String::from("/");
        long.push_str(&"a".repeat(MAX_PATH_LEN * 2));
        let out = sanitize_url_to_path(&long).expect("truncated");
        assert!(out.len() <= MAX_PATH_LEN);
    }

    #[test]
    fn sanitize_url_accepts_relative_path() {
        assert_eq!(sanitize_url_to_path("/home").as_deref(), Some("/home"));
        assert_eq!(
            sanitize_url_to_path("/home?token=secret").as_deref(),
            Some("/home")
        );
    }

    #[test]
    fn sanitize_referrer_extracts_host() {
        assert_eq!(
            sanitize_referrer_host("https://Google.COM/search?q=x").as_deref(),
            Some("google.com")
        );
        assert_eq!(
            sanitize_referrer_host("http://example.com:8080/path").as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn sanitize_referrer_rejects_garbage() {
        assert!(sanitize_referrer_host("").is_none());
        assert!(sanitize_referrer_host("not a url").is_none());
        assert!(sanitize_referrer_host("ftp://x.com/").is_none());
        assert!(sanitize_referrer_host("https://\x00evil.com/").is_none());
    }

    #[test]
    fn sanitize_referrer_drops_oversized_host() {
        let huge = format!("https://{}/", "a".repeat(MAX_REFERRER_HOST_LEN + 1));
        assert!(sanitize_referrer_host(&huge).is_none());
    }
}
