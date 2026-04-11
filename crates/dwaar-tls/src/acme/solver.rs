// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! In-memory ACME HTTP-01 challenge token store.
//!
//! Shared between the ACME service (writes tokens) and the proxy's
//! request filter (reads tokens to respond to validation requests).

use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;

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

/// Stores pending ACME HTTP-01 challenge tokens and throttles per-IP
/// challenge probes.
///
/// The ACME service inserts `token → key_authorization` entries when
/// setting up challenges. The proxy checks incoming requests against
/// this map and responds directly for `/.well-known/acme-challenge/{token}`.
///
/// Thread-safe via `DashMap` — lock-free concurrent reads and writes.
#[derive(Debug)]
pub struct ChallengeSolver {
    pending: DashMap<String, String>,
    /// Per-source-IP sliding-window counter used to throttle the challenge
    /// lookup path while `pending` is non-empty (audit finding L-05).
    probes: DashMap<IpAddr, ProbeWindow>,
}

impl ChallengeSolver {
    pub fn new() -> Self {
        Self {
            pending: DashMap::new(),
            probes: DashMap::new(),
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
}
