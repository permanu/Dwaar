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
    pub fn set(&self, token: &str, key_authorization: &str) {
        self.pending
            .insert(token.to_string(), key_authorization.to_string());
    }

    /// Look up the key authorization for a token.
    pub fn get(&self, token: &str) -> Option<String> {
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
    use super::*;

    #[test]
    fn insert_and_get_token() {
        let solver = ChallengeSolver::new();
        solver.set("test-token-abc", "key-auth-xyz");
        assert_eq!(solver.get("test-token-abc").as_deref(), Some("key-auth-xyz"));
    }

    #[test]
    fn missing_token_returns_none() {
        let solver = ChallengeSolver::new();
        assert!(solver.get("nonexistent").is_none());
    }

    #[test]
    fn remove_token() {
        let solver = ChallengeSolver::new();
        solver.set("token", "auth");
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

    #[test]
    fn concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let solver = Arc::new(ChallengeSolver::new());
        let mut handles = vec![];

        for i in 0..10 {
            let s = Arc::clone(&solver);
            handles.push(thread::spawn(move || {
                let token = format!("token-{i}");
                let auth = format!("auth-{i}");
                s.set(&token, &auth);
                assert_eq!(s.get(&token).as_deref(), Some(auth.as_str()));
            }));
        }

        for h in handles {
            h.join().expect("thread panicked");
        }
        assert_eq!(solver.pending_count(), 10);
    }
}
