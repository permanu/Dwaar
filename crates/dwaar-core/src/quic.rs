// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! QUIC listener scaffold for HTTP/3 support (ISSUE-079a).
//!
//! Runs a `quinn::Endpoint` as a Pingora `BackgroundService`, accepting
//! QUIC connections over UDP alongside the existing TCP/TLS listeners.
//!
//! Phase 1 accepts and logs connections. Full HTTP/3 request handling
//! through the Pingora proxy engine is deferred to ISSUE-079 Phase 2.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use tracing::{debug, info};

/// Background service that accepts QUIC connections.
///
/// Wraps a `quinn::Endpoint` and runs inside Pingora's runtime (Guardrail #20).
/// The endpoint is stored in a `Mutex<Option<_>>` so `start()` can take
/// ownership from `&self` — Pingora calls `start()` exactly once.
pub struct QuicService {
    endpoint: Mutex<Option<quinn::Endpoint>>,
}

impl std::fmt::Debug for QuicService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicService")
            .field("endpoint", &"<quinn::Endpoint>")
            .finish()
    }
}

impl QuicService {
    /// Create a new QUIC service bound to the given address.
    ///
    /// Loads TLS certs from the same PEM files used by the TCP/TLS listener
    /// (ISSUE-079c — shared cert store). Both OpenSSL (Pingora) and rustls
    /// (quinn) can independently load PEM, so no conversion is needed.
    pub fn new(
        bind_addr: SocketAddr,
        cert_path: &Path,
        key_path: &Path,
    ) -> Result<Self, QuicSetupError> {
        let rustls_config = build_rustls_config(cert_path, key_path)?;
        let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)
            .map_err(|e| QuicSetupError::QuicCrypto(e.to_string()))?;
        let quinn_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));

        let endpoint = quinn::Endpoint::server(quinn_config, bind_addr)
            .map_err(|e| QuicSetupError::Bind(bind_addr, e))?;

        info!(
            listen = %bind_addr,
            protocol = "quic",
            "QUIC endpoint bound"
        );

        Ok(Self {
            endpoint: Mutex::new(Some(endpoint)),
        })
    }
}

#[async_trait]
impl BackgroundService for QuicService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let endpoint = self
            .endpoint
            .lock()
            .expect("QuicService lock poisoned")
            .take()
            .expect("QuicService::start called more than once");

        info!("QUIC listener accepting connections");

        loop {
            tokio::select! {
                incoming = endpoint.accept() => {
                    let Some(connecting) = incoming else {
                        // Endpoint closed — nothing left to accept
                        break;
                    };
                    // Spawn each connection handler inside Pingora's runtime
                    tokio::spawn(async move {
                        match connecting.await {
                            Ok(conn) => {
                                info!(
                                    remote = %conn.remote_address(),
                                    "QUIC connection established"
                                );
                                // Full HTTP/3 request handling is Phase 2 (ISSUE-079 Phase 2).
                                // For now, the connection will idle and eventually close.
                            }
                            Err(e) => {
                                debug!(error = %e, "QUIC connection failed during handshake");
                            }
                        }
                    });
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("QUIC listener shutting down");
                        endpoint.close(quinn::VarInt::from_u32(0), b"server shutting down");
                        break;
                    }
                }
            }
        }
    }
}

/// Load PEM cert and key into a rustls `ServerConfig` for QUIC.
///
/// Uses the same PEM files as Pingora's OpenSSL listener — both libraries
/// parse PEM natively, so the cert store is shared at the filesystem level.
fn build_rustls_config(
    cert_path: &Path,
    key_path: &Path,
) -> Result<rustls::ServerConfig, QuicSetupError> {
    let cert_pem = std::fs::read(cert_path)
        .map_err(|e| QuicSetupError::CertRead(cert_path.to_path_buf(), e))?;
    let key_pem =
        std::fs::read(key_path).map_err(|e| QuicSetupError::KeyRead(key_path.to_path_buf(), e))?;

    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .map_err(QuicSetupError::CertParse)?;

    if certs.is_empty() {
        return Err(QuicSetupError::NoCerts(cert_path.to_path_buf()));
    }

    let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .map_err(QuicSetupError::KeyParse)?
        .ok_or_else(|| QuicSetupError::NoKey(key_path.to_path_buf()))?;

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(QuicSetupError::Rustls)?;

    // ALPN for HTTP/3 — quinn requires this to negotiate the protocol.
    config.alpn_protocols = vec![b"h3".to_vec()];

    Ok(config)
}

/// Errors that can occur during QUIC endpoint setup.
#[derive(Debug, thiserror::Error)]
pub enum QuicSetupError {
    #[error("failed to bind QUIC endpoint to {0}: {1}")]
    Bind(SocketAddr, std::io::Error),

    #[error("failed to read TLS cert from {0}: {1}")]
    CertRead(std::path::PathBuf, std::io::Error),

    #[error("failed to read TLS key from {0}: {1}")]
    KeyRead(std::path::PathBuf, std::io::Error),

    #[error("failed to parse PEM certificates: {0}")]
    CertParse(std::io::Error),

    #[error("no certificates found in {0}")]
    NoCerts(std::path::PathBuf),

    #[error("failed to parse PEM private key: {0}")]
    KeyParse(std::io::Error),

    #[error("no private key found in {0}")]
    NoKey(std::path::PathBuf),

    #[error("rustls configuration error: {0}")]
    Rustls(rustls::Error),

    #[error("QUIC crypto setup error: {0}")]
    QuicCrypto(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quic_setup_error_display() {
        // Verify error messages are human-readable
        let err = QuicSetupError::NoCerts("/etc/certs/cert.pem".into());
        assert!(err.to_string().contains("no certificates found"));
    }

    #[test]
    fn build_rustls_config_rejects_missing_cert() {
        let result = build_rustls_config(
            Path::new("/nonexistent/cert.pem"),
            Path::new("/nonexistent/key.pem"),
        );
        assert!(result.is_err());
        let err = result.expect_err("should fail");
        assert!(
            matches!(err, QuicSetupError::CertRead(..)),
            "expected CertRead error, got: {err}"
        );
    }

    #[test]
    fn build_rustls_config_rejects_missing_key() {
        // Create a temp cert file but no key file
        let dir = tempfile::tempdir().expect("temp dir");
        let cert_path = dir.path().join("cert.pem");
        // Write a minimal (invalid but present) cert PEM to pass the read check
        std::fs::write(&cert_path, "not a real cert").expect("write cert");

        let result = build_rustls_config(&cert_path, Path::new("/nonexistent/key.pem"));
        assert!(result.is_err());
    }
}
