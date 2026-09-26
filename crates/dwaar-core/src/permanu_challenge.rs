// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Permanu ownership challenge.
//!
//! A registered token for an IP is served at
//! `GET /.well-known/permanu-challenge/<token>` with that token as the body.
//! The same path with an unknown token is 404. No other `/.well-known/` path
//! is claimed.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use parking_lot::RwLock;

/// Path prefix for the Permanu HTTP ownership challenge. The token is the
/// single segment after this prefix.
pub const CHALLENGE_PREFIX: &str = "/.well-known/permanu-challenge/";

/// Longest token Dwaar will store. Ownership proofs are short random strings.
const MAX_TOKEN_LEN: usize = 128;

/// Answer for a request Dwaar owns on the Permanu challenge path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeReply {
    /// HTTP status. `200` when the token is registered for the request IP,
    /// otherwise `404`.
    pub status: u16,
    /// Response body. The token bytes on `200`, empty on `404`.
    pub body: Vec<u8>,
}

/// Rejected challenge token.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChallengeTokenError {
    /// Empty, too long, or not a single `[A-Za-z0-9_-]` segment.
    #[error("invalid permanu challenge token")]
    Invalid,
}

/// Tokens registered with Dwaar, keyed by the IP they prove.
#[derive(Debug, Default)]
pub struct PermanuChallenges {
    tokens: RwLock<HashMap<IpAddr, HashSet<String>>>,
}

impl PermanuChallenges {
    /// Empty store. Nothing is served until [`Self::register`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Remember `token` as the proof for `ip`.
    ///
    /// Registering the same pair again is a no-op.
    ///
    /// # Errors
    ///
    /// Returns [`ChallengeTokenError::Invalid`] when `token` is not one
    /// URL path segment of `[A-Za-z0-9_-]`.
    pub fn register(&self, ip: IpAddr, token: &str) -> Result<(), ChallengeTokenError> {
        if !is_token(token) {
            return Err(ChallengeTokenError::Invalid);
        }
        self.tokens
            .write()
            .entry(ip)
            .or_default()
            .insert(token.to_owned());
        Ok(())
    }

    /// Resolve a request.
    ///
    /// `None` means this is not the Permanu challenge path (including every
    /// other `/.well-known/` path) or the method is not `GET`. `Some` is the
    /// status and body Dwaar should return without contacting an upstream.
    #[must_use]
    pub fn reply(
        &self,
        host: Option<&str>,
        method: &str,
        path_and_query: &str,
    ) -> Option<ChallengeReply> {
        if method != "GET" {
            return None;
        }
        let path = strip_query(path_and_query);
        let token = path.strip_prefix(CHALLENGE_PREFIX)?;
        Some(self.decide(host, token))
    }

    fn decide(&self, host: Option<&str>, token: &str) -> ChallengeReply {
        let Some(ip) = host.and_then(host_ip) else {
            return not_found();
        };
        if is_token(token) && self.contains(ip, token) {
            ChallengeReply {
                status: 200,
                body: token.as_bytes().to_vec(),
            }
        } else {
            not_found()
        }
    }

    fn contains(&self, ip: IpAddr, token: &str) -> bool {
        self.tokens
            .read()
            .get(&ip)
            .is_some_and(|tokens| tokens.contains(token))
    }
}

const fn not_found() -> ChallengeReply {
    ChallengeReply {
        status: 404,
        body: Vec::new(),
    }
}

fn strip_query(path_and_query: &str) -> &str {
    path_and_query
        .split_once('?')
        .map_or(path_and_query, |(path, _query)| path)
}

fn host_ip(host: &str) -> Option<IpAddr> {
    crate::proxy::strip_port_from_host(host).parse().ok()
}

fn is_token(token: &str) -> bool {
    (1..=MAX_TOKEN_LEN).contains(&token.len())
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serves_registered_token_for_ip_and_404s_unknown() {
        let challenges = PermanuChallenges::new();
        let ip: IpAddr = "203.0.113.10".parse().expect("ipv4");
        challenges.register(ip, "perm_7f3a").expect("register");

        let found = challenges
            .reply(
                Some("203.0.113.10"),
                "GET",
                "/.well-known/permanu-challenge/perm_7f3a",
            )
            .expect("challenge path is handled");
        assert_eq!(found.status, 200);
        assert_eq!(found.body, b"perm_7f3a");

        let with_port = challenges
            .reply(
                Some("203.0.113.10:80"),
                "GET",
                "/.well-known/permanu-challenge/perm_7f3a",
            )
            .expect("host and port still identify the IP");
        assert_eq!(with_port.status, 200);
        assert_eq!(with_port.body, b"perm_7f3a");

        let unknown = challenges
            .reply(
                Some("203.0.113.10"),
                "GET",
                "/.well-known/permanu-challenge/not-registered",
            )
            .expect("unknown token is still the challenge path");
        assert_eq!(unknown.status, 404);
        assert!(unknown.body.is_empty());

        let other_ip = challenges
            .reply(
                Some("198.51.100.20"),
                "GET",
                "/.well-known/permanu-challenge/perm_7f3a",
            )
            .expect("challenge path is handled");
        assert_eq!(other_ip.status, 404);

        assert!(
            challenges
                .reply(
                    Some("203.0.113.10"),
                    "GET",
                    "/.well-known/acme-challenge/perm_7f3a",
                )
                .is_none(),
            "no other well-known path is added"
        );
    }
}
