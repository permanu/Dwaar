// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Beacon authentication metrics and rate-limited debug logging.
//!
//! Provides a `BeaconAuthMetrics` counter for Prometheus exposition
//! (`beacon_auth_total{result="accepted|rejected|malformed"}`) and a
//! rate-limited debug logger that emits at most one message per domain
//! per minute to prevent log floods during attacks.

use std::fmt::Write;
use std::net::IpAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Instant;

use compact_str::CompactString;
use dashmap::DashMap;

use crate::auth::AuthRejectReason;

/// Rate-limit window: at most one debug log line per domain per 60 seconds.
const LOG_RATE_LIMIT_SECS: u64 = 60;

/// Maximum number of distinct domains tracked in the rate-limiter map.
/// Bounded to prevent memory exhaustion from attacker-supplied Host headers.
const MAX_RATE_LIMIT_DOMAINS: usize = 10_000;

/// Per-domain rate-limit state for debug logging.
struct DomainLogState {
    last_logged: Instant,
    suppressed: u64,
}

/// Anonymize an IP address by zeroing the host portion.
/// IPv4: /24 (last octet zeroed). IPv6: /48 (last 80 bits zeroed).
fn anonymize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let mut octets = v4.octets();
            octets[3] = 0;
            IpAddr::V4(octets.into())
        }
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            // Zero bytes 6..16 (keep /48 prefix)
            for b in &mut octets[6..] {
                *b = 0;
            }
            IpAddr::V6(octets.into())
        }
    }
}

/// Prometheus counters for beacon authentication outcomes.
///
/// Three result labels: `accepted`, `rejected`, `malformed`.
/// All operations are atomic — no locks, no allocation after init.
/// The rate-limited logger uses a `DashMap<Mutex<_>>` for per-domain
/// suppression tracking.
pub struct BeaconAuthMetrics {
    accepted: AtomicU64,
    rejected: AtomicU64,
    malformed: AtomicU64,

    /// Per-domain rate-limit state for debug log suppression.
    log_rate: DashMap<CompactString, Mutex<DomainLogState>>,
}

impl std::fmt::Debug for BeaconAuthMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BeaconAuthMetrics")
            .field("accepted", &self.accepted.load(Relaxed))
            .field("rejected", &self.rejected.load(Relaxed))
            .field("malformed", &self.malformed.load(Relaxed))
            .finish_non_exhaustive()
    }
}

impl Default for BeaconAuthMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl BeaconAuthMetrics {
    pub fn new() -> Self {
        Self {
            accepted: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            malformed: AtomicU64::new(0),
            log_rate: DashMap::new(),
        }
    }

    /// Record a successful beacon authentication.
    pub fn record_accepted(&self) {
        self.accepted.fetch_add(1, Relaxed);
    }

    /// Record a beacon authentication rejection and emit rate-limited
    /// debug logging.
    ///
    /// The `client_ip` is anonymized before logging. Signature values
    /// are never logged.
    ///
    /// At most one debug log line is emitted per domain per 60 seconds.
    /// When the rate limit fires, the log line includes a count of
    /// suppressed rejections since the last emission.
    pub fn record_rejected(
        &self,
        reason: AuthRejectReason,
        domain: &str,
        client_ip: Option<IpAddr>,
    ) {
        match reason {
            AuthRejectReason::MalformedPayload => {
                self.malformed.fetch_add(1, Relaxed);
            }
            AuthRejectReason::MissingSignatureHeader | AuthRejectReason::SignatureMismatch => {
                self.rejected.fetch_add(1, Relaxed);
            }
        }

        self.maybe_log(reason, domain, client_ip);
    }

    /// Emit a debug log line if the per-domain rate limit allows it.
    fn maybe_log(&self, reason: AuthRejectReason, domain: &str, client_ip: Option<IpAddr>) {
        let key = CompactString::from(domain);
        let now = Instant::now();

        // Fast path: domain already tracked.
        if let Some(entry) = self.log_rate.get(&key) {
            let mut state = entry.lock().expect("poisoned");
            let elapsed = now.duration_since(state.last_logged).as_secs();
            if elapsed < LOG_RATE_LIMIT_SECS {
                state.suppressed += 1;
                return;
            }
            let suppressed = state.suppressed;
            state.last_logged = now;
            state.suppressed = 0;
            // Drop the lock before logging to avoid holding it during I/O.
            drop(state);
            drop(entry);
            Self::emit_log(reason, domain, client_ip, suppressed);
            return;
        }

        // Cold path: first rejection for this domain.
        if self.log_rate.len() >= MAX_RATE_LIMIT_DOMAINS {
            // Bounded — silently drop to prevent memory exhaustion.
            return;
        }

        self.log_rate.insert(
            key,
            Mutex::new(DomainLogState {
                last_logged: now,
                suppressed: 0,
            }),
        );
        Self::emit_log(reason, domain, client_ip, 0);
    }

    /// Emit the actual debug log line via `tracing::debug!`.
    fn emit_log(
        reason: AuthRejectReason,
        domain: &str,
        client_ip: Option<IpAddr>,
        suppressed: u64,
    ) {
        let anon_ip = client_ip
            .map(anonymize_ip)
            .map(|ip| ip.to_string())
            .unwrap_or_default();

        if suppressed > 0 {
            tracing::debug!(
                domain,
                reason = %reason,
                client_ip = %anon_ip,
                suppressed,
                "beacon auth rejected (plus {suppressed} suppressed since last log)"
            );
        } else {
            tracing::debug!(
                domain,
                reason = %reason,
                client_ip = %anon_ip,
                "beacon auth rejected"
            );
        }
    }

    /// Render beacon auth metrics in Prometheus text exposition format.
    pub fn render(&self, out: &mut String) {
        let accepted = self.accepted.load(Relaxed);
        let rejected = self.rejected.load(Relaxed);
        let malformed = self.malformed.load(Relaxed);

        if accepted == 0 && rejected == 0 && malformed == 0 {
            return;
        }

        out.push_str("# HELP dwaar_beacon_auth_total Beacon authentication results.\n");
        out.push_str("# TYPE dwaar_beacon_auth_total counter\n");
        if accepted > 0 {
            let _ = writeln!(
                out,
                "dwaar_beacon_auth_total{{result=\"accepted\"}} {accepted}"
            );
        }
        if rejected > 0 {
            let _ = writeln!(
                out,
                "dwaar_beacon_auth_total{{result=\"rejected\"}} {rejected}"
            );
        }
        if malformed > 0 {
            let _ = writeln!(
                out,
                "dwaar_beacon_auth_total{{result=\"malformed\"}} {malformed}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn record_accepted_increments() {
        let m = BeaconAuthMetrics::new();
        m.record_accepted();
        m.record_accepted();
        assert_eq!(m.accepted.load(Relaxed), 2);
        assert_eq!(m.rejected.load(Relaxed), 0);
        assert_eq!(m.malformed.load(Relaxed), 0);
    }

    #[test]
    fn record_rejected_signature_mismatch() {
        let m = BeaconAuthMetrics::new();
        m.record_rejected(
            AuthRejectReason::SignatureMismatch,
            "example.com",
            Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
        );
        assert_eq!(m.rejected.load(Relaxed), 1);
        assert_eq!(m.malformed.load(Relaxed), 0);
    }

    #[test]
    fn record_rejected_missing_header() {
        let m = BeaconAuthMetrics::new();
        m.record_rejected(AuthRejectReason::MissingSignatureHeader, "a.com", None);
        assert_eq!(m.rejected.load(Relaxed), 1);
    }

    #[test]
    fn record_rejected_malformed() {
        let m = BeaconAuthMetrics::new();
        m.record_rejected(AuthRejectReason::MalformedPayload, "b.com", None);
        assert_eq!(m.malformed.load(Relaxed), 1);
        assert_eq!(m.rejected.load(Relaxed), 0);
    }

    #[test]
    fn render_empty_produces_nothing() {
        let m = BeaconAuthMetrics::new();
        let mut out = String::new();
        m.render(&mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn render_produces_prometheus_format() {
        let m = BeaconAuthMetrics::new();
        m.record_accepted();
        m.record_rejected(AuthRejectReason::SignatureMismatch, "x.com", None);
        m.record_rejected(AuthRejectReason::MalformedPayload, "y.com", None);

        let mut out = String::new();
        m.render(&mut out);
        assert!(out.contains("dwaar_beacon_auth_total{result=\"accepted\"} 1"));
        assert!(out.contains("dwaar_beacon_auth_total{result=\"rejected\"} 1"));
        assert!(out.contains("dwaar_beacon_auth_total{result=\"malformed\"} 1"));
        assert!(out.contains("# HELP dwaar_beacon_auth_total"));
        assert!(out.contains("# TYPE dwaar_beacon_auth_total counter"));
    }

    #[test]
    fn is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<BeaconAuthMetrics>();
    }

    #[test]
    fn rate_limit_suppresses_rapid_logs() {
        let m = BeaconAuthMetrics::new();
        let ip = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

        // First call for "flood.com" — creates entry, logs immediately.
        m.record_rejected(AuthRejectReason::SignatureMismatch, "flood.com", ip);

        // Subsequent calls within the same second — should be suppressed.
        for _ in 0..100 {
            m.record_rejected(AuthRejectReason::SignatureMismatch, "flood.com", ip);
        }

        // The counter should reflect all 101 rejections.
        assert_eq!(m.rejected.load(Relaxed), 101);

        // The rate-limit state should show suppressed count.
        let key = CompactString::from("flood.com");
        let entry = m.log_rate.get(&key).expect("domain tracked");
        let state = entry.lock().expect("poisoned");
        assert_eq!(state.suppressed, 100);
    }

    #[test]
    fn anonymize_ipv4() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42));
        let anon = anonymize_ip(ip);
        assert_eq!(anon, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)));
    }

    #[test]
    fn auth_reject_reason_display() {
        assert_eq!(
            AuthRejectReason::MissingSignatureHeader.to_string(),
            "missing_signature_header"
        );
        assert_eq!(
            AuthRejectReason::MalformedPayload.to_string(),
            "malformed_payload"
        );
        assert_eq!(
            AuthRejectReason::SignatureMismatch.to_string(),
            "signature_mismatch"
        );
    }
}
