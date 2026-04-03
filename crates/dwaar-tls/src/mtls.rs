// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Client certificate loading and validation for mutual TLS (mTLS).
//!
//! Used when a `reverse_proxy` transport block configures `tls_client_auth` —
//! the upstream requires the proxy to present a client certificate during the
//! TLS handshake. Certs and keys are loaded from PEM files at config time,
//! validated for key/cert match (Guardrail #18), and compiled into Pingora's
//! `CertKey` type for injection into `HttpPeer`.

use std::path::Path;
use std::sync::Arc;

use openssl::pkey::PKey;
use openssl::x509::X509;
use pingora_core::protocols::tls::CaType;
use pingora_core::utils::tls::CertKey;
use thiserror::Error;
use tracing::{debug, warn};

#[derive(Error, Debug)]
pub enum MtlsError {
    #[error("failed to read file: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid PEM: {0}")]
    Pem(#[from] openssl::error::ErrorStack),

    #[error("cert PEM contains no certificates")]
    EmptyCert,

    #[error("cert/key mismatch — the private key does not match the certificate's public key")]
    KeyMismatch,

    #[error("certificate is expired")]
    Expired,
}

/// Load a client cert+key pair from PEM files and validate they match.
///
/// Performs all Guardrail #18 checks: cert/key match via public key equality,
/// expiry warning. Returns Pingora's `CertKey` ready for `HttpPeer`.
pub fn load_client_cert_key(cert_path: &Path, key_path: &Path) -> Result<CertKey, MtlsError> {
    let cert_pem = std::fs::read(cert_path)?;
    let key_pem = std::fs::read(key_path)?;

    let certs = X509::stack_from_pem(&cert_pem)?;
    if certs.is_empty() {
        return Err(MtlsError::EmptyCert);
    }

    let key = PKey::private_key_from_pem(&key_pem)?;

    // Guardrail #18: validate cert/key match via public key equality
    let cert_pubkey = certs[0].public_key()?;
    if !cert_pubkey.public_eq(&key) {
        return Err(MtlsError::KeyMismatch);
    }

    // Warn on expiry (still load — operators will see the warning)
    if let Ok(now) = openssl::asn1::Asn1Time::days_from_now(0) {
        if certs[0].not_after() < now {
            warn!(cert = %cert_path.display(), "client certificate is expired");
        } else if let Ok(soon) = openssl::asn1::Asn1Time::days_from_now(30)
            && certs[0].not_after() < soon
        {
            warn!(cert = %cert_path.display(), "client certificate expires within 30 days");
        }
    }

    // Log cert path at info level; key path is never logged (Guardrail #18)
    debug!(cert = %cert_path.display(), "loaded mTLS client certificate");

    Ok(CertKey::new(certs, key))
}

/// Load CA certificates from a PEM bundle for upstream server verification.
///
/// Returns the CA certs as an `Arc<CaType>` ready for `HttpPeer.options.ca`.
pub fn load_ca_certs(ca_path: &Path) -> Result<Arc<CaType>, MtlsError> {
    let ca_pem = std::fs::read(ca_path)?;
    let cas = X509::stack_from_pem(&ca_pem)?;
    if cas.is_empty() {
        return Err(MtlsError::EmptyCert);
    }

    debug!(ca = %ca_path.display(), count = cas.len(), "loaded trusted CA certs");

    Ok(Arc::new(cas.into_boxed_slice()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::generate_self_signed;

    #[test]
    fn load_valid_client_cert() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (cert_pem, key_pem) = generate_self_signed("client.test");

        let cert_path = dir.path().join("client.pem");
        let key_path = dir.path().join("client.key");
        std::fs::write(&cert_path, &cert_pem).expect("write cert");
        std::fs::write(&key_path, &key_pem).expect("write key");

        let result = load_client_cert_key(&cert_path, &key_path);
        assert!(result.is_ok(), "should load valid cert+key pair");
    }

    #[test]
    fn reject_mismatched_cert_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (cert_pem, _) = generate_self_signed("client.test");
        let (_, other_key_pem) = generate_self_signed("other.test");

        let cert_path = dir.path().join("client.pem");
        let key_path = dir.path().join("wrong.key");
        std::fs::write(&cert_path, &cert_pem).expect("write cert");
        std::fs::write(&key_path, &other_key_pem).expect("write key");

        let result = load_client_cert_key(&cert_path, &key_path);
        assert!(result.is_err());
        let err = result.expect_err("should reject mismatched cert/key");
        assert!(matches!(err, MtlsError::KeyMismatch));
    }

    #[test]
    fn reject_empty_cert() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("empty.pem");
        let key_path = dir.path().join("some.key");

        // Write a technically valid PEM file with no certs
        std::fs::write(&cert_path, b"").expect("write empty");
        let (_, key_pem) = generate_self_signed("x.test");
        std::fs::write(&key_path, &key_pem).expect("write key");

        let result = load_client_cert_key(&cert_path, &key_path);
        assert!(result.is_err());
    }

    #[test]
    fn reject_missing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let result = load_client_cert_key(
            &dir.path().join("nonexistent.pem"),
            &dir.path().join("nonexistent.key"),
        );
        assert!(result.is_err());
        let err = result.expect_err("should fail on missing file");
        assert!(matches!(err, MtlsError::Io(_)));
    }

    #[test]
    fn load_ca_certs_valid() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_, _, ca_pem) = crate::test_util::generate_ca_signed("leaf.test");

        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, &ca_pem).expect("write ca");

        let result = load_ca_certs(&ca_path);
        assert!(result.is_ok());
        assert!(!result.expect("loaded").is_empty());
    }

    #[test]
    fn load_ca_certs_empty_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ca_path = dir.path().join("empty.pem");
        std::fs::write(&ca_path, b"").expect("write empty");

        let result = load_ca_certs(&ca_path);
        assert!(result.is_err());
    }
}
