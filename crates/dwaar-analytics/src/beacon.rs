// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Beacon collection — parses and enriches analytics events from the
//! client-side JavaScript beacon sent to `/_dwaar/collect`.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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
            client_ip,
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
        };
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let event = BeaconEvent::from_raw(raw, ip, "example.com".to_string());
        assert_eq!(event.client_ip, ip);
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
}
