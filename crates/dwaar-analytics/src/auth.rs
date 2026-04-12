// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Beacon authentication — HMAC-SHA256 signed nonces (C-04).
//!
//! Analytics beacons are authenticated with a time-bounded, host-bound,
//! HMAC-SHA256 signature. The proxy injects `<meta name="dwaar-beacon-auth"
//! content="<nonce>:<sig>">` into HTML responses. The client-side beacon
//! reads the meta tag and echoes `nonce` + `sig` in the POST body. The
//! server recomputes the signature with the process secret and rejects
//! mismatches.
//!
//! ## Threat model
//!
//! - Attacker goal: poison analytics data by forging beacons.
//! - Attacker capability: full HTTP access to the public beacon endpoint.
//! - Existing defence: Origin header validation rejects cross-origin POSTs.
//! - This module adds: cryptographic proof that the beacon originated from
//!   a page served by this process within the last ~5–10 minutes.
//!
//! ## Scheme
//!
//! - Secret: 32 random bytes from `rand::rng()` (OS-backed CSPRNG),
//!   generated once per process and held in `Zeroizing<[u8; 32]>`.
//! - Window: `unix_seconds / 300` (5-minute buckets).
//! - Signature: HMAC-SHA256(`nonce_bytes || host_bytes || window_be8`).
//! - Wire format: `<base64url_nonce>:<hex_sig>` in a `<meta>` tag.
//! - Verification checks current AND previous window to handle boundary
//!   crossings gracefully (same approach as `under_attack.rs`).
//!
//! ## Replay
//!
//! A 5-minute window plus same-origin Origin validation is sufficient for
//! analytics — the goal is to make poisoning expensive, not impossible.
//! A seen-nonce bloom filter would be overkill for an analytics beacon.
//!
//! ## Constant-time comparison
//!
//! Per Guardrail #30, signature comparison uses `subtle::ConstantTimeEq`
//! applied to the raw 32-byte tags from both the current and previous
//! window. Never `==`.

use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// Number of raw bytes in a beacon nonce (128 bits = 16 bytes).
/// Encoded as base64url → 22 bytes without padding.
pub const NONCE_LEN: usize = 16;

/// Maximum base64url-encoded nonce length we'll accept from clients.
/// Slightly larger than strictly required to tolerate trailing whitespace.
const MAX_NONCE_B64_LEN: usize = 32;

/// Maximum hex signature length we'll accept. SHA-256 = 32 bytes = 64 hex chars.
const SIG_HEX_LEN: usize = 64;

/// Window size in seconds for signature validity. Matches the UAM plugin.
const WINDOW_SECS: u64 = 300;

/// Process-wide beacon HMAC secret.
///
/// Stored in a `OnceLock` so it can be lazily initialized on first use
/// without threading an explicit `Arc<BeaconSecret>` through every layer
/// of the proxy. The secret is generated once per process and remains
/// stable for the process lifetime — restarting the binary invalidates
/// all outstanding nonces, which is acceptable for analytics beacons
/// (the window is already only 5 minutes).
static BEACON_SECRET: OnceLock<Zeroizing<[u8; 32]>> = OnceLock::new();

/// Return the process beacon secret, initializing it on first call.
///
/// The initializer uses `rand::fill()`, which on modern Rust
/// `rand` (0.10+) is an OS-backed CSPRNG (equivalent to `OsRng`).
/// Once initialized, the 32 random bytes are wrapped in `Zeroizing` so
/// the allocation is wiped on process exit.
fn secret() -> &'static [u8; 32] {
    BEACON_SECRET.get_or_init(|| {
        let mut buf = Zeroizing::new(<[u8; 32]>::default());
        rand::fill(&mut buf[..]);
        buf
    })
}

/// Return the current 5-minute window counter.
fn current_window() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() / WINDOW_SECS)
        .unwrap_or(0)
}

/// Compute the HMAC-SHA256 signature for (nonce, host, window) as a
/// fixed-size 32-byte tag. Centralised so signing and verification share
/// the exact same input construction — any divergence would break
/// verification.
fn compute_sig(nonce: &[u8], host: &[u8], window: u64) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret()).expect("HMAC accepts any key length");
    mac.update(nonce);
    mac.update(host);
    mac.update(&window.to_be_bytes());
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

/// A freshly issued beacon authentication token.
///
/// Used at HTML injection time to embed the signed nonce in a `<meta>` tag.
#[derive(Debug, Clone)]
pub struct BeaconAuth {
    /// Random nonce as base64url (no padding).
    pub nonce_b64: String,
    /// HMAC tag as lowercase hex (64 chars).
    pub sig_hex: String,
}

impl BeaconAuth {
    /// Render as the `<meta>` tag content attribute value:
    /// `<nonce_b64>:<sig_hex>`. The injector embeds this as
    /// `<meta name="dwaar-beacon-auth" content="...">`.
    pub fn meta_content(&self) -> String {
        let mut s = String::with_capacity(self.nonce_b64.len() + 1 + self.sig_hex.len());
        s.push_str(&self.nonce_b64);
        s.push(':');
        s.push_str(&self.sig_hex);
        s
    }
}

/// Issue a fresh beacon auth token for the given host.
///
/// Generates 16 random bytes from the OS CSPRNG, computes the HMAC signature
/// against the current 5-minute window, and returns both encoded forms.
pub fn issue(host: &str) -> BeaconAuth {
    let mut nonce: [u8; NONCE_LEN] = Default::default();
    rand::fill(&mut nonce[..]);

    let window = current_window();
    let sig = compute_sig(&nonce, host.as_bytes(), window);

    BeaconAuth {
        nonce_b64: B64.encode(nonce),
        sig_hex: hex::encode(sig),
    }
}

/// Verify a client-supplied (nonce, sig) pair against the given host.
///
/// Accepts signatures issued in either the current OR the previous
/// 5-minute window, matching the UAM challenge convention. This means
/// a beacon can be validly submitted for up to ~10 minutes after the
/// page loaded (worst case: a page loaded at window N, submitted 4:59
/// later in window N+1 is still within the 2-window tolerance).
///
/// Signature comparison uses `subtle::ConstantTimeEq` on the raw 32-byte
/// expected tags per Guardrail #30. Both windows are compared without
/// short-circuiting so timing does not leak which window succeeded.
///
/// All failure paths return `false`. Callers should translate this into
/// a 401 response at `trace!` level so repeated failures under attack
/// don't flood logs.
pub fn verify(nonce_b64: &str, sig_hex: &str, host: &str) -> bool {
    // Length guards first — cheap rejections before any crypto work.
    if nonce_b64.is_empty() || nonce_b64.len() > MAX_NONCE_B64_LEN {
        return false;
    }
    if sig_hex.len() != SIG_HEX_LEN {
        return false;
    }

    // Decode nonce (base64url without padding).
    let Ok(nonce_bytes) = B64.decode(nonce_b64.as_bytes()) else {
        return false;
    };
    if nonce_bytes.len() != NONCE_LEN {
        return false;
    }

    // Decode hex signature into raw bytes.
    let Ok(sig_bytes) = hex::decode(sig_hex) else {
        return false;
    };
    if sig_bytes.len() != 32 {
        return false;
    }

    // Try current window, then previous. Do NOT short-circuit on the
    // current-window mismatch — run both comparisons in constant time to
    // avoid leaking which window succeeded through timing.
    let window = current_window();
    let expected_current = compute_sig(&nonce_bytes, host.as_bytes(), window);
    let expected_prev = compute_sig(&nonce_bytes, host.as_bytes(), window.saturating_sub(1));

    let match_current = expected_current.ct_eq(sig_bytes.as_slice()).unwrap_u8();
    let match_prev = expected_prev.ct_eq(sig_bytes.as_slice()).unwrap_u8();

    (match_current | match_prev) == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_then_verify_round_trip() {
        let auth = issue("example.com");
        assert!(verify(&auth.nonce_b64, &auth.sig_hex, "example.com"));
    }

    #[test]
    fn verify_rejects_wrong_host() {
        let auth = issue("example.com");
        assert!(!verify(&auth.nonce_b64, &auth.sig_hex, "attacker.com"));
    }

    #[test]
    fn verify_rejects_tampered_sig() {
        let auth = issue("example.com");
        // Flip the last hex character
        let mut bad = auth.sig_hex.clone();
        let last = bad.pop().expect("non-empty");
        let flipped = if last == '0' { '1' } else { '0' };
        bad.push(flipped);
        assert!(!verify(&auth.nonce_b64, &bad, "example.com"));
    }

    #[test]
    fn verify_rejects_tampered_nonce() {
        let auth = issue("example.com");
        // Flip a byte in the nonce — decode, mutate, re-encode
        let mut nonce = B64.decode(&auth.nonce_b64).expect("valid b64");
        nonce[0] ^= 0xff;
        let bad_nonce = B64.encode(&nonce);
        assert!(!verify(&bad_nonce, &auth.sig_hex, "example.com"));
    }

    #[test]
    fn verify_rejects_empty() {
        assert!(!verify("", "", "example.com"));
    }

    #[test]
    fn verify_rejects_oversized_nonce() {
        let huge = "x".repeat(MAX_NONCE_B64_LEN + 1);
        let sig = "0".repeat(SIG_HEX_LEN);
        assert!(!verify(&huge, &sig, "example.com"));
    }

    #[test]
    fn verify_rejects_short_sig() {
        let auth = issue("example.com");
        let short = &auth.sig_hex[..32];
        assert!(!verify(&auth.nonce_b64, short, "example.com"));
    }

    #[test]
    fn verify_rejects_non_hex_sig() {
        let auth = issue("example.com");
        let bad = "z".repeat(SIG_HEX_LEN);
        assert!(!verify(&auth.nonce_b64, &bad, "example.com"));
    }

    #[test]
    fn verify_rejects_non_base64_nonce() {
        let sig = "0".repeat(SIG_HEX_LEN);
        assert!(!verify("!!!not-b64!!!", &sig, "example.com"));
    }

    #[test]
    fn meta_content_format() {
        let auth = BeaconAuth {
            nonce_b64: "abc".to_string(),
            sig_hex: "def".to_string(),
        };
        assert_eq!(auth.meta_content(), "abc:def");
    }

    #[test]
    fn secret_is_stable_across_calls() {
        // OnceLock guarantees a single init; sanity-check by signing twice
        // with the same (nonce, host, window) and asserting the sigs match.
        // lgtm[rs/hardcoded-credentials] — test-only fixture, not a production secret
        let nonce = [0u8; NONCE_LEN];
        let sig1 = compute_sig(&nonce, b"example.com", 12345);
        let sig2 = compute_sig(&nonce, b"example.com", 12345);
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn different_hosts_produce_different_sigs() {
        // lgtm[rs/hardcoded-credentials] — test-only fixture, not a production secret
        let nonce = [7u8; NONCE_LEN];
        let a = compute_sig(&nonce, b"example.com", 12345);
        let b = compute_sig(&nonce, b"evil.com", 12345);
        assert_ne!(a, b);
    }

    #[test]
    fn issued_nonce_has_expected_encoded_length() {
        let auth = issue("example.com");
        // 16 raw bytes → ceil(16/3)*4 = 24, minus 2 pad chars for NO_PAD = 22
        assert_eq!(auth.nonce_b64.len(), 22);
        assert_eq!(auth.sig_hex.len(), SIG_HEX_LEN);
    }
}
