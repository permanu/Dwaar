// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! In-memory ACME challenge stores for HTTP-01 and TLS-ALPN-01.
//!
//! HTTP-01 tokens are shared between the ACME service (writes tokens)
//! and the proxy's request filter (reads tokens to respond to
//! validation requests).
//!
//! TLS-ALPN-01 challenge certs are installed into the `CertStore` so
//! the TLS handshake callback can serve them for ALPN `acme-tls/1`
//! connections. Cleaned up after validation completes.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use instant_acme::KeyAuthorization;
use tracing::debug;

use super::AcmeError;
use crate::cert_store::CertStore;

/// Upper bound on the number of pending ACME challenge tokens kept in memory.
///
/// Prevents a compromised or misbehaving ACME directory from flooding the
/// proxy with authorization tokens and exhausting memory. 1024 is generous
/// for realistic parallel issuance — a single typical order holds 1 token,
/// so this gives headroom for hundreds of concurrent orders while capping
/// total RAM use at a few megabytes.
pub const MAX_PENDING_TOKENS: usize = 1024;

/// Sliding-window length for per-IP probe throttling on the ACME challenge
/// endpoint (seconds). Short enough that legitimate retries after a failed
/// ACME validation don't have to wait long; long enough to damp a sustained
/// brute-force probe.
pub const PROBE_WINDOW_SECS: u64 = 60;

/// Maximum probe requests a single source IP may make to the ACME challenge
/// endpoint in one [`PROBE_WINDOW_SECS`] window. Two per second is far above
/// any legitimate validator behaviour (real ACME directories send a handful
/// of requests per challenge) and far below the DashMap-contention level
/// that the audit flagged.
pub const PROBE_MAX_PER_WINDOW: u32 = 120;

/// Cap on distinct IPs tracked in the per-IP probe counter. Prevents an
/// attacker from growing the counter map unboundedly by rotating source
/// addresses. At 10k entries × (16-byte `IpAddr` + 16-byte `ProbeWindow`)
/// the map tops out around 320 KB.
pub const PROBES_MAX_TRACKED_IPS: usize = 10_000;

/// Maximum number of concurrent TLS-ALPN-01 challenges. Mirrors the
/// HTTP-01 cap for the same memory-exhaustion defence.
pub const MAX_PENDING_ALPN_CHALLENGES: usize = 1024;

/// TLS-ALPN-01 challenge certs older than this are stale and can be
/// garbage-collected. One hour is far longer than any ACME validation
/// round-trip, so hitting this means the challenge failed silently.
pub const ALPN_CHALLENGE_TTL: std::time::Duration = std::time::Duration::from_secs(3600);

/// OID for the `acmeIdentifier` extension (1.3.6.1.5.5.7.1.31).
/// RFC 8737 mandates this exact OID for the challenge validation value
/// in the self-signed certificate.
const ACME_IDENTIFIER_OID: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 31];

/// Tracks an in-flight TLS-ALPN-01 challenge so cleanup can remove
/// the temporary cert from the `CertStore` after validation.
#[derive(Debug)]
struct AlpnChallenge {
    installed_at: Instant,
}

/// Per-source-IP probe counter used by [`ChallengeSolver::get`] to throttle
/// the ACME challenge lookup path during active issuance.
///
/// Each window uses two atomics: a Unix-seconds window-start stamp and a
/// count. Both are updated with relaxed ordering — window resets race under
/// contention in a benign way (the losing thread falls through to the
/// counter check, which is safe), matching the admin rate-limiter pattern.
#[derive(Debug)]
struct ProbeWindow {
    window_start: AtomicU64,
    count: AtomicU32,
}

impl ProbeWindow {
    fn new(now: u64) -> Self {
        Self {
            window_start: AtomicU64::new(now),
            count: AtomicU32::new(0),
        }
    }
}

/// Errors produced by the [`ChallengeSolver`].
#[derive(Debug, thiserror::Error)]
pub enum SolverError {
    /// The pending token map is full (>= [`MAX_PENDING_TOKENS`]).
    ///
    /// Callers should treat this as transient and retry after pending
    /// challenges complete (ACME orders free tokens after validation).
    #[error(
        "too many pending ACME challenge tokens (cap is {cap}); refusing to \
         accept new token to prevent memory exhaustion"
    )]
    TooManyPendingTokens { cap: usize },
}

/// Stores pending ACME challenge state for both HTTP-01 (token map) and
/// TLS-ALPN-01 (domain-keyed challenge tracker) flows. Throttles per-IP
/// challenge probes on the HTTP-01 path.
///
/// Thread-safe via `DashMap` — lock-free concurrent reads and writes.
#[derive(Debug)]
pub struct ChallengeSolver {
    pending: DashMap<String, String>,
    /// Per-source-IP sliding-window counter used to throttle the challenge
    /// lookup path while `pending` is non-empty (audit finding L-05).
    probes: DashMap<IpAddr, ProbeWindow>,
    /// Tracks in-flight TLS-ALPN-01 challenges keyed by domain. The actual
    /// cert is written to disk for the `CertStore`; this map exists purely
    /// for cleanup bookkeeping and capacity enforcement.
    alpn_challenges: DashMap<String, AlpnChallenge>,
}

impl ChallengeSolver {
    pub fn new() -> Self {
        Self {
            pending: DashMap::new(),
            probes: DashMap::new(),
            alpn_challenges: DashMap::new(),
        }
    }

    /// Insert a challenge token and its key authorization.
    ///
    /// Returns [`SolverError::TooManyPendingTokens`] if the map is already at
    /// [`MAX_PENDING_TOKENS`] and the token is not already present. Updating
    /// an existing token (re-setting the same key) is always allowed so that
    /// in-flight retries don't spuriously fail.
    pub fn set(&self, token: &str, key_authorization: &str) -> Result<(), SolverError> {
        // Allow updating an existing entry even at cap — this is an in-place
        // mutation, not a growth event, so it cannot exhaust memory further.
        if !self.pending.contains_key(token) && self.pending.len() >= MAX_PENDING_TOKENS {
            return Err(SolverError::TooManyPendingTokens {
                cap: MAX_PENDING_TOKENS,
            });
        }
        self.pending
            .insert(token.to_string(), key_authorization.to_string());
        Ok(())
    }

    /// Look up the key authorization for a token, throttling by source IP
    /// while any challenges are outstanding.
    ///
    /// Two defences stack here for audit finding L-05:
    ///
    /// 1. **Steady-state fast-path**: if no challenges are pending, return
    ///    `None` without touching the `DashMap` at all. Post-issuance spray
    ///    attacks pay only a pointer compare.
    /// 2. **Active-issuance per-IP throttle**: while `pending` is non-empty,
    ///    any single IP may make up to [`PROBE_MAX_PER_WINDOW`] lookups per
    ///    [`PROBE_WINDOW_SECS`] window. Excess probes return `None` without
    ///    hitting `pending` — so sustained brute force from one address
    ///    can't cause `DashMap` shard contention.
    ///
    /// `source_ip` should be the request's remote IP. Pass `None` when the
    /// IP is unknown (unix socket tests, loopback with no `RemoteAddr`) —
    /// those callers bypass the per-IP throttle.
    pub fn get(&self, token: &str, source_ip: Option<IpAddr>) -> Option<String> {
        if self.pending.is_empty() {
            return None;
        }
        if let Some(ip) = source_ip
            && !self.check_probe_allowance(ip)
        {
            return None;
        }
        self.pending.get(token).map(|v| v.value().clone())
    }

    /// Increment the per-IP probe counter for `ip` and return `true` if
    /// the probe is allowed, `false` if it has exceeded
    /// [`PROBE_MAX_PER_WINDOW`] in the current window.
    ///
    /// Amortised O(1). Performs opportunistic cleanup when the tracked-IP
    /// map grows past [`PROBES_MAX_TRACKED_IPS`] to prevent unbounded
    /// growth from rotating-source attackers.
    fn check_probe_allowance(&self, ip: IpAddr) -> bool {
        let now = now_unix();

        // Cheap cleanup path: if the map has grown past cap, drop every
        // expired window in one sweep. DashMap's retain is lock-free per
        // shard; this runs O(N) in the worst case but only once we've
        // crossed the cap, amortised across many probes.
        if self.probes.len() >= PROBES_MAX_TRACKED_IPS {
            self.probes.retain(|_, w| {
                now.saturating_sub(w.window_start.load(Ordering::Relaxed)) < PROBE_WINDOW_SECS
            });
        }

        let entry = self
            .probes
            .entry(ip)
            .or_insert_with(|| ProbeWindow::new(now));
        let window = entry.value();
        let window_start = window.window_start.load(Ordering::Relaxed);
        let elapsed = now.saturating_sub(window_start);

        if elapsed >= PROBE_WINDOW_SECS {
            // Window rolled over — reset atomically. If another thread wins
            // the CAS we simply fall through to the counter check, which
            // remains safe because the winner's reset already bumped count
            // to 1.
            if window
                .window_start
                .compare_exchange(window_start, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                window.count.store(1, Ordering::Relaxed);
                return true;
            }
        }

        let count = window
            .count
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        count <= PROBE_MAX_PER_WINDOW
    }

    /// Remove a token after challenge validation completes.
    pub fn remove(&self, token: &str) {
        self.pending.remove(token);
    }

    /// Number of pending challenges (for diagnostics).
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Validate that a token contains only base64url characters.
    /// ACME tokens use `[A-Za-z0-9_-]`. Rejects empty, slashes,
    /// dots, nulls — prevents path traversal.
    pub fn is_valid_token(token: &str) -> bool {
        !token.is_empty()
            && token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    }

    /// Generate and install a TLS-ALPN-01 challenge cert for `domain`.
    ///
    /// Writes the self-signed cert (with the `acmeIdentifier` extension
    /// containing the SHA-256 of `key_authorization`) to the cert store's
    /// disk directory, then invalidates the cache so the next SNI lookup
    /// picks it up.
    ///
    /// The actual ALPN protocol negotiation (`acme-tls/1`) must be handled
    /// by the TLS accept callback — this method only provisions the cert.
    pub fn install_alpn_challenge(
        &self,
        domain: &str,
        key_authorization: &KeyAuthorization,
        cert_store: &CertStore,
    ) -> Result<(), AcmeError> {
        if self.alpn_challenges.len() >= MAX_PENDING_ALPN_CHALLENGES
            && !self.alpn_challenges.contains_key(domain)
        {
            return Err(AcmeError::AlpnCertGeneration {
                domain: domain.to_string(),
                reason: format!(
                    "too many pending ALPN challenges (cap {MAX_PENDING_ALPN_CHALLENGES})"
                ),
            });
        }

        let (cert_pem, key_pem) = generate_alpn_challenge_cert(domain, key_authorization)?;

        // Write to disk so CertStore can load it through its normal path.
        // Uses the same naming convention as the ACME issuer.
        let cert_dir = cert_store.cert_dir();
        std::fs::create_dir_all(cert_dir).map_err(|e| AcmeError::AlpnCertGeneration {
            domain: domain.to_string(),
            reason: format!("failed to create cert directory: {e}"),
        })?;

        let cert_path = cert_dir.join(format!("{domain}.pem"));
        let key_path = cert_dir.join(format!("{domain}.key"));

        std::fs::write(&cert_path, &cert_pem).map_err(|e| AcmeError::AlpnCertGeneration {
            domain: domain.to_string(),
            reason: format!("failed to write ALPN challenge cert: {e}"),
        })?;
        std::fs::write(&key_path, &key_pem).map_err(|e| AcmeError::AlpnCertGeneration {
            domain: domain.to_string(),
            reason: format!("failed to write ALPN challenge key: {e}"),
        })?;

        // Force the cert store to reload from disk on next lookup
        cert_store.invalidate(domain);

        self.alpn_challenges.insert(
            domain.to_string(),
            AlpnChallenge {
                installed_at: Instant::now(),
            },
        );

        debug!(domain, "TLS-ALPN-01 challenge cert installed");
        Ok(())
    }

    /// Remove a TLS-ALPN-01 challenge cert after validation completes.
    ///
    /// Deletes the temporary cert files from disk and evicts the cached
    /// entry. The next issuance cycle will write the real cert. Safe to
    /// call even if no ALPN challenge was installed (idempotent).
    pub fn remove_alpn_challenge(&self, domain: &str, cert_store: &CertStore) {
        self.alpn_challenges.remove(domain);
        cert_store.invalidate(domain);

        let cert_dir = cert_store.cert_dir();
        let cert_path = cert_dir.join(format!("{domain}.pem"));
        let key_path = cert_dir.join(format!("{domain}.key"));

        // Best-effort deletion — the real cert will overwrite these anyway
        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);

        debug!(domain, "TLS-ALPN-01 challenge cert removed");
    }

    /// Evict ALPN challenges older than [`ALPN_CHALLENGE_TTL`]. Called
    /// periodically to prevent leaked entries from accumulating if a
    /// challenge flow crashes without cleanup.
    pub fn cleanup_stale_alpn_challenges(&self, cert_store: &CertStore) {
        let now = Instant::now();
        let stale: Vec<String> = self
            .alpn_challenges
            .iter()
            .filter(|entry| now.duration_since(entry.value().installed_at) >= ALPN_CHALLENGE_TTL)
            .map(|entry| entry.key().clone())
            .collect();

        for domain in &stale {
            self.remove_alpn_challenge(domain, cert_store);
            debug!(domain, "cleaned up stale ALPN challenge");
        }
    }

    /// Number of pending ALPN challenges (for diagnostics).
    pub fn alpn_challenge_count(&self) -> usize {
        self.alpn_challenges.len()
    }
}

impl Default for ChallengeSolver {
    fn default() -> Self {
        Self::new()
    }
}

/// Current Unix time in whole seconds.
///
/// Monotonicity isn't required — the probe window only needs a rough
/// elapsed-time measurement, and wall-clock drift at the second granularity
/// is irrelevant to the throttle behaviour.
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// Build the ASN.1 DER encoding of the `acmeIdentifier` extension value.
///
/// RFC 8737 s3 requires the extension value to be an ASN.1 OCTET STRING
/// wrapping the raw 32-byte SHA-256 digest:
///   `04 20 <32 bytes of SHA-256 digest>`
fn encode_acme_identifier_der(key_auth_hash: &[u8; 32]) -> Vec<u8> {
    let mut der = Vec::with_capacity(34);
    der.push(0x04); // ASN.1 OCTET STRING tag
    der.push(0x20); // length 32
    der.extend_from_slice(key_auth_hash);
    der
}

/// Generate a self-signed TLS-ALPN-01 challenge certificate.
///
/// Uses `rcgen` to create an EC P-256 cert with:
/// - SAN: the challenged domain
/// - Critical `acmeIdentifier` extension (OID 1.3.6.1.5.5.7.1.31)
///   containing the SHA-256 of the key authorization string
///
/// Returns `(cert_pem, key_pem)` as byte vectors.
fn generate_alpn_challenge_cert(
    domain: &str,
    key_authorization: &KeyAuthorization,
) -> Result<(Vec<u8>, Vec<u8>), AcmeError> {
    use rcgen::{
        CertificateParams, CustomExtension, DistinguishedName, DnType, KeyPair,
        PKCS_ECDSA_P256_SHA256, SanType,
    };

    // instant_acme provides the pre-computed SHA-256 digest via `digest()`
    let digest_ref = key_authorization.digest();
    let digest_bytes: &[u8] = digest_ref.as_ref();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(digest_bytes);
    let acme_id_der = encode_acme_identifier_der(&digest);

    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|e| {
        AcmeError::AlpnCertGeneration {
            domain: domain.to_string(),
            reason: format!("EC key generation failed: {e}"),
        }
    })?;

    // Default validity spans are fine for a challenge cert — the ACME server
    // only checks the extension and SAN, not the dates. Cleanup is driven by
    // the solver's ALPN_CHALLENGE_TTL, not the cert's notAfter.
    let mut params = CertificateParams::default();

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, domain);
    params.distinguished_name = dn;

    params.subject_alt_names = vec![SanType::DnsName(domain.try_into().map_err(
        |e: rcgen::Error| AcmeError::AlpnCertGeneration {
            domain: domain.to_string(),
            reason: format!("invalid SAN domain: {e}"),
        },
    )?)];

    // The acmeIdentifier extension MUST be critical per RFC 8737
    let mut ext = CustomExtension::from_oid_content(ACME_IDENTIFIER_OID, acme_id_der);
    ext.set_criticality(true);
    params.custom_extensions = vec![ext];

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| AcmeError::AlpnCertGeneration {
            domain: domain.to_string(),
            reason: format!("self-signed cert generation failed: {e}"),
        })?;

    Ok((
        cert.pem().into_bytes(),
        key_pair.serialize_pem().into_bytes(),
    ))
}

/// Generate an ALPN challenge cert from a raw SHA-256 digest, bypassing
/// the `KeyAuthorization` type. Test-only — production code goes through
/// `install_alpn_challenge` which holds a real `KeyAuthorization`.
#[cfg(test)]
fn generate_alpn_cert_from_digest(
    domain: &str,
    digest: &[u8; 32],
) -> Result<(Vec<u8>, Vec<u8>), AcmeError> {
    use rcgen::{
        CertificateParams, CustomExtension, DistinguishedName, DnType, KeyPair,
        PKCS_ECDSA_P256_SHA256, SanType,
    };

    let acme_id_der = encode_acme_identifier_der(digest);

    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|e| {
        AcmeError::AlpnCertGeneration {
            domain: domain.to_string(),
            reason: format!("EC key generation failed: {e}"),
        }
    })?;

    let mut params = CertificateParams::default();

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, domain);
    params.distinguished_name = dn;

    params.subject_alt_names = vec![SanType::DnsName(domain.try_into().map_err(
        |e: rcgen::Error| AcmeError::AlpnCertGeneration {
            domain: domain.to_string(),
            reason: format!("invalid SAN domain: {e}"),
        },
    )?)];

    let mut ext = CustomExtension::from_oid_content(ACME_IDENTIFIER_OID, acme_id_der);
    ext.set_criticality(true);
    params.custom_extensions = vec![ext];

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| AcmeError::AlpnCertGeneration {
            domain: domain.to_string(),
            reason: format!("self-signed cert generation failed: {e}"),
        })?;

    Ok((
        cert.pem().into_bytes(),
        key_pair.serialize_pem().into_bytes(),
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn insert_and_get_token() {
        let solver = ChallengeSolver::new();
        solver
            .set("test-token-abc", "key-auth-xyz")
            .expect("set should succeed");
        assert_eq!(
            solver.get("test-token-abc", None).as_deref(),
            Some("key-auth-xyz")
        );
    }

    #[test]
    fn missing_token_returns_none() {
        let solver = ChallengeSolver::new();
        assert!(solver.get("nonexistent", None).is_none());
    }

    #[test]
    fn remove_token() {
        let solver = ChallengeSolver::new();
        solver.set("token", "auth").expect("set should succeed");
        solver.remove("token");
        assert!(solver.get("token", None).is_none());
    }

    #[test]
    fn valid_token_accepts_base64url() {
        assert!(ChallengeSolver::is_valid_token("abc-DEF_012"));
        assert!(ChallengeSolver::is_valid_token("a"));
    }

    #[test]
    fn invalid_token_rejects_bad_chars() {
        assert!(!ChallengeSolver::is_valid_token(""));
        assert!(!ChallengeSolver::is_valid_token("../etc/passwd"));
        assert!(!ChallengeSolver::is_valid_token("token with spaces"));
        assert!(!ChallengeSolver::is_valid_token("token\0null"));
        assert!(!ChallengeSolver::is_valid_token("token/slash"));
    }

    #[tokio::test]
    async fn delayed_cleanup_removes_token() {
        use std::time::Duration;

        let solver = Arc::new(ChallengeSolver::new());
        solver
            .set("cleanup-token", "auth-value")
            .expect("set should succeed");

        // Simulate the cleanup spawn (with a much shorter delay for testing)
        let s = Arc::clone(&solver);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            s.remove("cleanup-token");
        });

        // Token exists immediately
        assert!(solver.get("cleanup-token", None).is_some());

        // Token gone after delay
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(solver.get("cleanup-token", None).is_none());
    }

    #[test]
    fn concurrent_access() {
        use std::thread;

        let solver = Arc::new(ChallengeSolver::new());
        let mut handles = vec![];

        for i in 0..10 {
            let s = Arc::clone(&solver);
            handles.push(thread::spawn(move || {
                let token = format!("token-{i}");
                let auth = format!("auth-{i}");
                s.set(&token, &auth).expect("set should succeed");
                assert_eq!(s.get(&token, None).as_deref(), Some(auth.as_str()));
            }));
        }

        for h in handles {
            h.join().expect("thread panicked");
        }
        assert_eq!(solver.pending_count(), 10);
    }

    #[test]
    fn per_ip_probe_throttle_caps_bursts() {
        use std::net::{IpAddr, Ipv4Addr};

        let solver = ChallengeSolver::new();
        // A token must exist to get past the empty-set fast path so the
        // per-IP throttle actually runs.
        solver.set("real-token", "real-auth").expect("set");

        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

        // The first PROBE_MAX_PER_WINDOW lookups all succeed (and, since
        // the token name doesn't match, all return None via the DashMap
        // miss path — but crucially they were *allowed* through the
        // throttle, not blocked by it).
        for _ in 0..PROBE_MAX_PER_WINDOW {
            let _ = solver.get("unknown", Some(ip));
        }

        // The next lookup against a token that DOES exist must still be
        // throttled back to `None` because this IP has exhausted its
        // per-window budget.
        assert!(
            solver.get("real-token", Some(ip)).is_none(),
            "exhausted-budget IP should be throttled even for a valid token"
        );

        // A different IP is independent and may look up the same token.
        let other = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42));
        assert_eq!(
            solver.get("real-token", Some(other)).as_deref(),
            Some("real-auth"),
            "an unrelated IP must not be affected by another IP's budget"
        );

        // The empty-set fast path is unaffected by the throttle state:
        // an empty solver still returns None immediately regardless of
        // which IP is asking, so steady-state operation costs zero.
        let empty = ChallengeSolver::new();
        assert!(empty.get("anything", Some(ip)).is_none());
    }

    #[test]
    fn per_ip_probe_none_source_ip_bypasses_throttle() {
        let solver = ChallengeSolver::new();
        solver.set("loopback-token", "auth").expect("set");

        // Without a source IP, the throttle is skipped entirely — this
        // keeps unit tests and UDS-only loopback paths working without
        // forcing every caller to synthesise a fake IP.
        for _ in 0..(PROBE_MAX_PER_WINDOW * 3) {
            let _ = solver.get("loopback-token", None);
        }
        assert_eq!(
            solver.get("loopback-token", None).as_deref(),
            Some("auth"),
            "None source_ip must never be throttled"
        );
    }

    #[test]
    fn set_rejects_beyond_capacity() {
        let solver = ChallengeSolver::new();

        // Fill the solver exactly to capacity
        for i in 0..MAX_PENDING_TOKENS {
            let token = format!("cap-token-{i}");
            solver
                .set(&token, "auth")
                .expect("under cap should succeed");
        }
        assert_eq!(solver.pending_count(), MAX_PENDING_TOKENS);

        // One more new token must be rejected
        let err = solver
            .set("overflow-token", "auth")
            .expect_err("beyond cap should fail");
        assert!(matches!(
            err,
            SolverError::TooManyPendingTokens {
                cap: MAX_PENDING_TOKENS
            }
        ));
        assert_eq!(solver.pending_count(), MAX_PENDING_TOKENS);

        // Updating an existing entry stays allowed (no growth, no risk)
        solver
            .set("cap-token-0", "refreshed-auth")
            .expect("updating existing entry at cap should succeed");
        assert_eq!(
            solver.get("cap-token-0", None).as_deref(),
            Some("refreshed-auth")
        );

        // After freeing a slot, a new token fits again
        solver.remove("cap-token-1");
        solver
            .set("fresh-token", "auth")
            .expect("after eviction there is room");
    }

    // ---- TLS-ALPN-01 tests ----

    #[test]
    fn acme_identifier_der_encoding() {
        let digest = [0xAB; 32];
        let der = encode_acme_identifier_der(&digest);

        // ASN.1 OCTET STRING: tag 0x04, length 0x20 (32), then 32 bytes
        assert_eq!(der.len(), 34);
        assert_eq!(der[0], 0x04, "ASN.1 OCTET STRING tag");
        assert_eq!(der[1], 0x20, "length 32");
        assert_eq!(&der[2..], &[0xAB; 32]);
    }

    #[test]
    fn acme_identifier_der_encodes_sha256_correctly() {
        let key_auth = b"test-key-auth";
        let digest = openssl::sha::sha256(key_auth);
        let der = encode_acme_identifier_der(&digest);

        assert_eq!(der.len(), 34);
        assert_eq!(&der[2..], &digest);
    }

    #[test]
    fn generate_alpn_cert_produces_valid_x509() {
        let digest = openssl::sha::sha256(b"fake-key-authorization");
        let (cert_pem, key_pem) = generate_alpn_cert_from_digest("alpn.example.com", &digest)
            .expect("cert generation should succeed");

        let cert = openssl::x509::X509::from_pem(&cert_pem).expect("cert PEM should parse");
        let key =
            openssl::pkey::PKey::private_key_from_pem(&key_pem).expect("key PEM should parse");

        assert!(
            cert.public_key().expect("public key").public_eq(&key),
            "cert and key must match"
        );

        let sans = cert.subject_alt_names().expect("cert should have SANs");
        let san_names: Vec<&str> = sans.iter().filter_map(|n| n.dnsname()).collect();
        assert!(
            san_names.contains(&"alpn.example.com"),
            "SAN must contain the challenged domain"
        );
    }

    #[test]
    fn generate_alpn_cert_has_acme_identifier_extension() {
        let digest = openssl::sha::sha256(b"key-auth-for-extension-test");
        let (cert_pem, _key_pem) = generate_alpn_cert_from_digest("ext.example.com", &digest)
            .expect("cert generation should succeed");

        let cert = openssl::x509::X509::from_pem(&cert_pem).expect("cert PEM should parse");

        // Verify the acmeIdentifier OID (1.3.6.1.5.5.7.1.31) is present
        // in the cert's DER encoding. The OID body is 8 bytes:
        //   2B.06.01.05.05.07.01.1F
        // Wrapped in OBJECT IDENTIFIER tag: 06 08 <body>
        let cert_der = cert.to_der().expect("cert to DER");
        let oid_der: &[u8] = &[0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x1F];

        assert!(
            cert_der.windows(oid_der.len()).any(|w| w == oid_der),
            "cert DER must contain the acmeIdentifier OID (1.3.6.1.5.5.7.1.31)"
        );

        // Verify the SHA-256 digest is embedded in the cert
        assert!(
            cert_der.windows(digest.len()).any(|w| w == digest),
            "cert DER must contain the SHA-256 digest of the key authorization"
        );
    }

    #[test]
    fn install_and_remove_alpn_challenge() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_store = Arc::new(CertStore::new(dir.path(), 100));
        let solver = ChallengeSolver::new();

        let domain = "alpn-test.example.com";
        let digest = openssl::sha::sha256(b"test-key-auth");

        let (cert_pem, key_pem) =
            generate_alpn_cert_from_digest(domain, &digest).expect("cert gen");

        let cert_path = dir.path().join(format!("{domain}.pem"));
        let key_path = dir.path().join(format!("{domain}.key"));
        std::fs::write(&cert_path, &cert_pem).expect("write cert");
        std::fs::write(&key_path, &key_pem).expect("write key");

        // Track it in the solver
        solver.alpn_challenges.insert(
            domain.to_string(),
            AlpnChallenge {
                installed_at: Instant::now(),
            },
        );

        assert_eq!(solver.alpn_challenge_count(), 1);
        assert!(cert_store.get(domain).is_some(), "cert should be loadable");

        // Remove the challenge
        solver.remove_alpn_challenge(domain, &cert_store);

        assert_eq!(solver.alpn_challenge_count(), 0);
        assert!(!cert_path.exists(), "cert file should be deleted");
        assert!(!key_path.exists(), "key file should be deleted");
    }

    #[test]
    fn remove_alpn_challenge_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_store = Arc::new(CertStore::new(dir.path(), 100));
        let solver = ChallengeSolver::new();

        solver.remove_alpn_challenge("nonexistent.example.com", &cert_store);
        assert_eq!(solver.alpn_challenge_count(), 0);
    }

    #[test]
    fn cleanup_stale_alpn_challenges() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_store = Arc::new(CertStore::new(dir.path(), 100));
        let solver = ChallengeSolver::new();

        let domain = "stale.example.com";

        let digest = openssl::sha::sha256(b"stale-auth");
        let (cert_pem, key_pem) =
            generate_alpn_cert_from_digest(domain, &digest).expect("cert gen");
        std::fs::write(dir.path().join(format!("{domain}.pem")), &cert_pem).expect("write");
        std::fs::write(dir.path().join(format!("{domain}.key")), &key_pem).expect("write");

        // Install with a backdated timestamp that exceeds the TTL
        let old_instant = Instant::now()
            .checked_sub(ALPN_CHALLENGE_TTL + std::time::Duration::from_secs(1))
            .expect("subtraction should not underflow in tests");

        solver.alpn_challenges.insert(
            domain.to_string(),
            AlpnChallenge {
                installed_at: old_instant,
            },
        );

        assert_eq!(solver.alpn_challenge_count(), 1);

        solver.cleanup_stale_alpn_challenges(&cert_store);

        assert_eq!(
            solver.alpn_challenge_count(),
            0,
            "stale challenge should be cleaned up"
        );
    }

    #[test]
    fn cleanup_preserves_fresh_alpn_challenges() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_store = Arc::new(CertStore::new(dir.path(), 100));
        let solver = ChallengeSolver::new();

        solver.alpn_challenges.insert(
            "fresh.example.com".to_string(),
            AlpnChallenge {
                installed_at: Instant::now(),
            },
        );

        solver.cleanup_stale_alpn_challenges(&cert_store);

        assert_eq!(
            solver.alpn_challenge_count(),
            1,
            "fresh challenge must not be cleaned up"
        );
    }
}
