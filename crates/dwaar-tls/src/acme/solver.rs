// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! In-memory ACME HTTP-01 challenge token store.
//!
//! Shared between the ACME service (writes tokens) and the proxy's
//! request filter (reads tokens to respond to validation requests).

use dashmap::DashMap;

/// Upper bound on the number of pending ACME challenge tokens kept in memory.
///
/// Prevents a compromised or misbehaving ACME directory from flooding the
/// proxy with authorization tokens and exhausting memory. 1024 is generous
/// for realistic parallel issuance — a single typical order holds 1 token,
/// so this gives headroom for hundreds of concurrent orders while capping
/// total RAM use at a few megabytes.
pub const MAX_PENDING_TOKENS: usize = 1024;

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

/// Stores pending ACME HTTP-01 challenge tokens.
///
/// The ACME service inserts `token → key_authorization` entries when
/// setting up challenges. The proxy checks incoming requests against
/// this map and responds directly for `/.well-known/acme-challenge/{token}`.
///
/// Thread-safe via `DashMap` — lock-free concurrent reads and writes.
#[derive(Debug)]
pub struct ChallengeSolver {
    pending: DashMap<String, String>,
}

impl ChallengeSolver {
    pub fn new() -> Self {
        Self {
            pending: DashMap::new(),
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

    /// Look up the key authorization for a token.
    ///
    /// Fast-path returns `None` without hitting the `DashMap` if the
    /// pending set is empty — the common case during steady-state
    /// operation after all certificates are issued. This closes audit
    /// finding L-05 where an attacker could spray
    /// `/.well-known/acme-challenge/<random>` requests and cause
    /// `DashMap` shard contention; now those miss at the cheap
    /// `is_empty` check instead.
    pub fn get(&self, token: &str) -> Option<String> {
        if self.pending.is_empty() {
            return None;
        }
        self.pending.get(token).map(|v| v.value().clone())
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
            solver.get("test-token-abc").as_deref(),
            Some("key-auth-xyz")
        );
    }

    #[test]
    fn missing_token_returns_none() {
        let solver = ChallengeSolver::new();
        assert!(solver.get("nonexistent").is_none());
    }

    #[test]
    fn remove_token() {
        let solver = ChallengeSolver::new();
        solver.set("token", "auth").expect("set should succeed");
        solver.remove("token");
        assert!(solver.get("token").is_none());
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
        assert!(solver.get("cleanup-token").is_some());

        // Token gone after delay
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(solver.get("cleanup-token").is_none());
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
                assert_eq!(s.get(&token).as_deref(), Some(auth.as_str()));
            }));
        }

        for h in handles {
            h.join().expect("thread panicked");
        }
        assert_eq!(solver.pending_count(), 10);
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
        assert_eq!(solver.get("cap-token-0").as_deref(), Some("refreshed-auth"));

        // After freeing a slot, a new token fits again
        solver.remove("cap-token-1");
        solver
            .set("fresh-token", "auth")
            .expect("after eviction there is room");
    }
}
