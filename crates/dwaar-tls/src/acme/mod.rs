// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! ACME client for automatic TLS certificate provisioning.
//!
//! Supports Let's Encrypt (primary) with Google Trust Services fallback.
//! Implements three challenge types:
//! - **HTTP-01**: In-memory token store shared with the proxy request filter
//! - **TLS-ALPN-01**: Self-signed challenge certs installed into the cert store
//! - **DNS-01**: TXT records via pluggable DNS providers (for wildcards)

pub mod account;
pub mod error;
pub mod issuer;
pub mod service;
pub mod solver;

use std::time::Duration;

pub use error::AcmeError;
pub use solver::ChallengeSolver;

/// How many days before expiry to trigger renewal.
pub const RENEWAL_WINDOW_DAYS: u32 = 30;

/// Let's Encrypt production ACME directory.
pub const LE_DIRECTORY_URL: &str = "https://acme-v02.api.letsencrypt.org/directory";

/// Let's Encrypt staging (for development — issues untrusted certs).
pub const LE_STAGING_DIRECTORY_URL: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// Google Trust Services ACME directory (fallback CA).
pub const GTS_DIRECTORY_URL: &str = "https://dv.acme-v02.api.pki.goog/directory";

/// Delay between issuing certs for different domains (rate limit courtesy).
pub const INTER_DOMAIN_DELAY: Duration = Duration::from_secs(5);

/// How long to keep challenge tokens after validation completes.
pub const CHALLENGE_CLEANUP_DELAY: Duration = Duration::from_secs(300);

/// Max time to wait for challenge validation before giving up.
pub const CHALLENGE_POLL_TIMEOUT: Duration = Duration::from_secs(90);

/// Combined interval for OCSP refresh + cert renewal (12 hours).
pub const SERVICE_CHECK_INTERVAL: Duration = Duration::from_secs(43_200);

/// Delay between OCSP fetches for different domains.
pub const OCSP_INTER_DOMAIN_DELAY: Duration = Duration::from_secs(1);

/// Returns the LE directory URL, respecting `DWAAR_ACME_STAGING=1` env var.
pub fn le_directory_url() -> &'static str {
    if std::env::var("DWAAR_ACME_STAGING").is_ok_and(|v| v == "1") {
        LE_STAGING_DIRECTORY_URL
    } else {
        LE_DIRECTORY_URL
    }
}
