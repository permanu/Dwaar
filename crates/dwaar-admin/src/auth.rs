// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Bearer token authentication for the admin API.

/// Admin API authenticator. Validates bearer tokens against
/// the `DWAAR_ADMIN_TOKEN` environment variable.
#[derive(Debug)]
pub struct Auth {
    token: Option<zeroize::Zeroizing<String>>,
}

impl Auth {
    /// Create a new authenticator. `None` means no token configured (fail-closed).
    pub fn new(token: Option<String>) -> Self {
        Self {
            token: token.map(zeroize::Zeroizing::new),
        }
    }

    /// Check an `Authorization` header value. Returns `Ok(())` if valid.
    pub fn check(&self, header_value: &str) -> Result<(), &'static str> {
        let expected = self.token.as_deref().ok_or("no admin token configured")?;
        let provided = header_value
            .strip_prefix("Bearer ")
            .ok_or("missing Bearer prefix")?;
        if subtle::ConstantTimeEq::ct_eq(provided.as_bytes(), expected.as_bytes()).into() {
            Ok(())
        } else {
            Err("invalid token")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_token_passes() {
        let auth = Auth::new(Some("secret123".to_string()));
        assert!(auth.check("Bearer secret123").is_ok());
    }

    #[test]
    fn wrong_token_fails() {
        let auth = Auth::new(Some("secret123".to_string()));
        assert!(auth.check("Bearer wrong").is_err());
    }

    #[test]
    fn missing_bearer_prefix_fails() {
        let auth = Auth::new(Some("secret123".to_string()));
        assert!(auth.check("secret123").is_err());
    }

    #[test]
    fn no_token_configured_always_fails() {
        let auth = Auth::new(None);
        assert!(auth.check("Bearer anything").is_err());
    }

    #[test]
    fn empty_header_fails() {
        let auth = Auth::new(Some("secret".to_string()));
        assert!(auth.check("").is_err());
    }
}
