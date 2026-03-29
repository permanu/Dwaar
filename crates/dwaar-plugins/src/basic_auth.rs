// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! HTTP Basic Authentication middleware.
//!
//! Verifies `Authorization: Basic <base64>` headers against a pre-compiled
//! credential table. Uses bcrypt for password hashing with constant-time
//! verification to prevent timing attacks.
//!
//! ## Security properties
//!
//! - **Constant-time on username miss:** When a username doesn't exist, we
//!   still run bcrypt verify against a dummy hash. This prevents timing-based
//!   user enumeration.
//! - **No credential logging:** Passwords and hashes are never logged, even
//!   at trace level.
//! - **Graceful Base64 handling:** Malformed `Authorization` headers produce
//!   401, not 500.

use std::collections::HashMap;
use std::fmt;

use ahash::RandomState;
use compact_str::CompactString;

/// Pre-compiled credential table for fast username lookup.
///
/// Stored in the `HandlerBlock` at config load time. Username lookup is
/// `O(1)` via `HashMap`; password verification is `O(bcrypt_cost)` per request.
///
/// `Debug` is manually implemented to redact hashes — prevents accidental
/// credential exposure in logs, error messages, or crash dumps.
#[derive(Clone)]
pub struct BasicAuthConfig {
    credentials: HashMap<CompactString, CompactString, RandomState>,
    pub realm: CompactString,
    dummy_hash: CompactString,
}

impl fmt::Debug for BasicAuthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BasicAuthConfig")
            .field("realm", &self.realm)
            .field("user_count", &self.credentials.len())
            .field("credentials", &"[REDACTED]")
            .field("dummy_hash", &"[REDACTED]")
            .finish()
    }
}

impl BasicAuthConfig {
    /// Default bcrypt cost for the dummy hash — matches typical production hashes.
    /// If real hashes use cost 12, the dummy verify takes ~equal time, closing
    /// the timing oracle.
    const DUMMY_BCRYPT_COST: u32 = 10;

    /// Build from a list of `(username, bcrypt_hash)` pairs.
    pub fn new(
        credentials: impl IntoIterator<Item = (CompactString, CompactString)>,
        realm: &CompactString,
    ) -> Self {
        let creds: HashMap<CompactString, CompactString, RandomState> =
            credentials.into_iter().collect();

        // Infer cost from the first credential's hash, falling back to the default.
        // This way the dummy hash cost matches the real hashes as closely as possible.
        let cost = creds
            .values()
            .next()
            .and_then(|h| h.as_str().parse::<bcrypt::HashParts>().ok())
            .map_or(Self::DUMMY_BCRYPT_COST, |parts| parts.get_cost());

        // Pre-compute at startup — this runs once per config load, not per request.
        // Panic on failure: bcrypt hashing a dummy string should never fail.
        let dummy_hash = CompactString::from(
            bcrypt::hash("__dwaar_dummy_auth__", cost)
                .expect("bcrypt hash at startup must succeed"),
        );

        Self {
            credentials: creds,
            realm: Self::sanitize_realm(realm),
            dummy_hash,
        }
    }

    /// Verify an `Authorization: Basic <base64>` header value.
    ///
    /// Returns `Some(username)` on success, `None` on any failure.
    /// Failures include: missing header, malformed Base64, wrong credentials.
    /// The return type is intentionally opaque — callers return 401.
    pub fn verify(&self, auth_header: Option<&str>) -> Option<CompactString> {
        use base64::Engine;

        let header = auth_header?;

        // Scheme is case-insensitive per RFC 7617 §2
        if header.len() < 6 || !header[..6].eq_ignore_ascii_case("basic ") {
            return None;
        }
        let encoded = &header[6..];

        // Decode Base64 into a zeroizing buffer — plaintext password is wiped on drop.
        // This prevents the credential from lingering in heap memory after verification.
        let decoded = zeroize::Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .ok()?,
        );

        // All work with the decoded credential happens inside this block.
        // When `decoded` drops at the end of `verify()`, the plaintext is zeroed.
        let decoded_str = std::str::from_utf8(&decoded).ok()?;

        // Split on first colon — password may contain colons
        let (username, password) = decoded_str.split_once(':')?;

        // Lookup username — if missing, verify against dummy hash to prevent
        // timing oracle (bcrypt cost dominates, making both paths take ~equal time)
        let hash = self
            .credentials
            .get(username)
            .map_or(self.dummy_hash.as_str(), CompactString::as_str);

        if bcrypt::verify(password, hash).unwrap_or(false)
            && self.credentials.contains_key(username)
        {
            Some(CompactString::from(username))
        } else {
            None
        }
        // `decoded` (Zeroizing<Vec<u8>>) drops here — plaintext password zeroed
    }

    /// Build the `WWW-Authenticate` header value.
    ///
    /// Realm is sanitized at construction time — no CRLF or quote injection possible.
    pub fn www_authenticate(&self) -> CompactString {
        if self.realm.is_empty() {
            CompactString::from("Basic")
        } else {
            CompactString::from(format!("Basic realm=\"{}\"", self.realm))
        }
    }

    /// Strip characters that could break the quoted-string in WWW-Authenticate.
    fn sanitize_realm(realm: &str) -> CompactString {
        let sanitized: String = realm
            .chars()
            .filter(|c| *c != '"' && *c != '\r' && *c != '\n' && *c != '\\')
            .collect();
        CompactString::from(sanitized)
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;

    use super::*;

    fn make_config() -> BasicAuthConfig {
        // bcrypt hash for "password123" at cost 4 (fast for tests)
        let hash = bcrypt::hash("password123", 4).expect("bcrypt hash");
        BasicAuthConfig::new(
            vec![(
                CompactString::from("admin"),
                CompactString::from(hash.as_str()),
            )],
            &CompactString::from("Restricted"),
        )
    }

    fn encode_basic(user: &str, pass: &str) -> String {
        let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
        format!("Basic {encoded}")
    }

    #[test]
    fn valid_credentials_succeed() {
        let config = make_config();
        let header = encode_basic("admin", "password123");
        let result = config.verify(Some(&header));
        assert!(result.is_some());
        assert_eq!(result.expect("valid credentials"), "admin");
    }

    #[test]
    fn wrong_password_fails() {
        let config = make_config();
        let header = encode_basic("admin", "wrong");
        assert!(config.verify(Some(&header)).is_none());
    }

    #[test]
    fn unknown_user_fails() {
        let config = make_config();
        let header = encode_basic("nobody", "password123");
        assert!(config.verify(Some(&header)).is_none());
    }

    #[test]
    fn missing_header_fails() {
        let config = make_config();
        assert!(config.verify(None).is_none());
    }

    #[test]
    fn malformed_base64_fails() {
        let config = make_config();
        assert!(config.verify(Some("Basic !!!invalid!!!")).is_none());
    }

    #[test]
    fn non_basic_scheme_fails() {
        let config = make_config();
        assert!(config.verify(Some("Bearer token123")).is_none());
    }

    #[test]
    fn missing_colon_fails() {
        let config = make_config();
        let bad = base64::engine::general_purpose::STANDARD.encode("nocolon");
        assert!(config.verify(Some(&format!("Basic {bad}"))).is_none());
    }

    #[test]
    fn password_with_colons() {
        let pass = "pass:with:colons";
        let hash = bcrypt::hash(pass, 4).expect("hash");
        let config = BasicAuthConfig::new(
            vec![(
                CompactString::from("user"),
                CompactString::from(hash.as_str()),
            )],
            &CompactString::new(""),
        );
        let header = encode_basic("user", pass);
        assert!(config.verify(Some(&header)).is_some());
    }

    #[test]
    fn www_authenticate_with_realm() {
        let config = make_config();
        assert_eq!(
            config.www_authenticate().as_str(),
            "Basic realm=\"Restricted\""
        );
    }

    #[test]
    fn www_authenticate_no_realm() {
        let config = BasicAuthConfig::new(
            vec![(
                CompactString::from("u"),
                CompactString::from("$2b$04$dummy"),
            )],
            &CompactString::new(""),
        );
        assert_eq!(config.www_authenticate().as_str(), "Basic");
    }
}
