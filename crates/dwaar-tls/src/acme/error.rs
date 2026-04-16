// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! ACME error types.

use std::time::Duration;

/// Errors from the ACME certificate issuance flow.
#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    #[error("account credentials I/O: {0}")]
    AccountIo(#[source] std::io::Error),

    #[error("account registration failed: {0}")]
    Registration(String),

    #[error("order creation failed: {0}")]
    OrderCreation(String),

    #[error("challenge validation failed for {domain}: {reason}")]
    ChallengeValidation { domain: String, reason: String },

    #[error("challenge timed out after {elapsed:?} for {domain}")]
    ChallengeTimeout { domain: String, elapsed: Duration },

    #[error("CSR finalization failed: {0}")]
    Finalization(String),

    #[error("certificate download failed: {0}")]
    CertDownload(String),

    #[error("certificate write failed: {0}")]
    CertWrite(#[source] std::io::Error),

    #[error("all CAs failed for {domain}: LE={le_error}, GTS={gts_error}")]
    AllCasFailed {
        domain: String,
        le_error: String,
        gts_error: String,
    },

    #[error("DNS-01 challenge failed for {domain}: {reason}")]
    Dns01Failed { domain: String, reason: String },

    #[error("TLS-ALPN-01 challenge cert generation failed for {domain}: {reason}")]
    AlpnCertGeneration { domain: String, reason: String },
}
