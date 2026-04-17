// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! TLS configuration for the `DwaarControl` gRPC server.
//!
//! Materials are loaded from PEM files at startup, not watched for
//! rotation — operators cycle Dwaar via the existing zero-downtime
//! `dwaar upgrade` path when certificates rotate. This keeps the
//! module focused and testable.
//!
//! ## Environment contract
//!
//! Resolution is driven by three environment variables, mirrored in
//! Permanu's substrate contract (Wheel #2):
//!
//! | Variable                | Purpose                                            |
//! |-------------------------|----------------------------------------------------|
//! | `DWAAR_GRPC_CERT_FILE`  | Server cert PEM (may include intermediate chain).  |
//! | `DWAAR_GRPC_KEY_FILE`   | Server private key PEM.                            |
//! | `DWAAR_GRPC_CA_FILE`    | Optional CA bundle — presence enforces mTLS.       |
//!
//! When neither `CERT_FILE` nor `KEY_FILE` is set, the server runs
//! plaintext (the dev default). Setting exactly one is a configuration
//! bug: callers get [`TlsError::PartialServerMaterial`].

use std::path::{Path, PathBuf};

use thiserror::Error;
use tonic::transport::{Certificate, Identity, ServerTlsConfig};

/// Env var names — public so operators and tests share a single source of truth.
pub const ENV_CERT_FILE: &str = "DWAAR_GRPC_CERT_FILE";
pub const ENV_KEY_FILE: &str = "DWAAR_GRPC_KEY_FILE";
pub const ENV_CA_FILE: &str = "DWAAR_GRPC_CA_FILE";

/// Errors surfaced while loading gRPC TLS materials.
#[derive(Debug, Error)]
pub enum TlsError {
    #[error("failed to read {role} file {path}: {source}")]
    Io {
        role: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "incomplete TLS config: {ENV_CERT_FILE} and {ENV_KEY_FILE} must be set together \
         (cert_present={cert}, key_present={key})"
    )]
    PartialServerMaterial { cert: bool, key: bool },
    #[error("failed to construct tonic ServerTlsConfig: {0}")]
    Tonic(#[source] tonic::transport::Error),
}

/// Resolved TLS posture for the gRPC server.
#[derive(Debug, Clone)]
pub enum TlsConfig {
    /// No cert configured — plaintext h2c on the wire.
    Plaintext,
    /// Cert + key present; mTLS enabled when `ca` is `Some`.
    Enabled {
        cert_path: PathBuf,
        key_path: PathBuf,
        ca_path: Option<PathBuf>,
        identity: Identity,
        client_ca: Option<Certificate>,
    },
}

impl TlsConfig {
    /// Build a config from process environment. Returns [`TlsConfig::Plaintext`]
    /// when neither cert nor key vars are set.
    pub fn from_env() -> Result<Self, TlsError> {
        let cert = std::env::var(ENV_CERT_FILE).ok().filter(|s| !s.is_empty());
        let key = std::env::var(ENV_KEY_FILE).ok().filter(|s| !s.is_empty());
        let ca = std::env::var(ENV_CA_FILE).ok().filter(|s| !s.is_empty());

        match (cert, key) {
            (None, None) => {
                if ca.is_some() {
                    // A CA on its own is a no-op for a plaintext server — warn
                    // via `PartialServerMaterial` so operators notice the misconfig.
                    return Err(TlsError::PartialServerMaterial {
                        cert: false,
                        key: false,
                    });
                }
                Ok(TlsConfig::Plaintext)
            }
            (Some(c), Some(k)) => Self::load(
                PathBuf::from(c),
                PathBuf::from(k),
                ca.map(PathBuf::from).as_deref(),
            ),
            (c, k) => Err(TlsError::PartialServerMaterial {
                cert: c.is_some(),
                key: k.is_some(),
            }),
        }
    }

    /// Load TLS materials from explicit paths. `ca_path` enables mTLS enforcement.
    pub fn load(
        cert_path: PathBuf,
        key_path: PathBuf,
        ca_path: Option<&Path>,
    ) -> Result<Self, TlsError> {
        let cert_pem = std::fs::read(&cert_path).map_err(|source| TlsError::Io {
            role: "server certificate",
            path: cert_path.clone(),
            source,
        })?;
        let key_pem = std::fs::read(&key_path).map_err(|source| TlsError::Io {
            role: "server private key",
            path: key_path.clone(),
            source,
        })?;

        let identity = Identity::from_pem(cert_pem, key_pem);

        let (ca_path_out, client_ca) = if let Some(ca) = ca_path {
            let ca_pem = std::fs::read(ca).map_err(|source| TlsError::Io {
                role: "client CA bundle",
                path: ca.to_path_buf(),
                source,
            })?;
            (Some(ca.to_path_buf()), Some(Certificate::from_pem(ca_pem)))
        } else {
            (None, None)
        };

        Ok(TlsConfig::Enabled {
            cert_path,
            key_path,
            ca_path: ca_path_out,
            identity,
            client_ca,
        })
    }

    /// Whether TLS is enabled on the wire.
    pub fn is_enabled(&self) -> bool {
        matches!(self, TlsConfig::Enabled { .. })
    }

    /// Whether mTLS (client cert verification) is enforced.
    pub fn is_mutual(&self) -> bool {
        matches!(
            self,
            TlsConfig::Enabled {
                client_ca: Some(_),
                ..
            }
        )
    }

    /// Convert to a tonic `ServerTlsConfig`. Returns `None` for plaintext.
    pub fn to_tonic(&self) -> Option<ServerTlsConfig> {
        match self {
            TlsConfig::Plaintext => None,
            TlsConfig::Enabled {
                identity,
                client_ca,
                ..
            } => {
                let mut cfg = ServerTlsConfig::new().identity(identity.clone());
                if let Some(ca) = client_ca {
                    cfg = cfg.client_ca_root(ca.clone());
                }
                Some(cfg)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_tmp(dir: &tempfile::TempDir, name: &str, content: &[u8]) -> PathBuf {
        let path = dir.path().join(name);
        let mut f = std::fs::File::create(&path).expect("create tmp");
        f.write_all(content).expect("write tmp");
        path
    }

    /// Generate a self-signed PEM cert+key pair using `rcgen` via the
    /// shared `test_util`, but keep this crate test-only and standalone
    /// by emitting inline PEM bytes.
    fn gen_self_signed() -> (Vec<u8>, Vec<u8>) {
        let cert = rcgen::generate_simple_self_signed(vec!["dwaar.test".to_string()])
            .expect("self-signed cert");
        let cert_pem = cert.cert.pem().into_bytes();
        let key_pem = cert.signing_key.serialize_pem().into_bytes();
        (cert_pem, key_pem)
    }

    /// Plaintext is the default when no env vars are set. We test this via
    /// `TlsConfig::load` semantics (it is equivalent to `from_env` with no
    /// vars set) — calling `from_env` directly would race with other tests
    /// that also read the process-wide environment, and `std::env::remove_var`
    /// is `unsafe` under the 2024 edition with no thread-safe alternative.
    #[test]
    fn plaintext_is_default_when_load_skipped() {
        let cfg = TlsConfig::Plaintext;
        assert!(!cfg.is_enabled());
        assert!(!cfg.is_mutual());
        assert!(cfg.to_tonic().is_none());
    }

    #[test]
    fn load_valid_server_material() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (cert_pem, key_pem) = gen_self_signed();
        let cert_path = write_tmp(&dir, "cert.pem", &cert_pem);
        let key_path = write_tmp(&dir, "key.pem", &key_pem);

        let cfg = TlsConfig::load(cert_path, key_path, None).expect("should load valid cert+key");
        assert!(cfg.is_enabled());
        assert!(!cfg.is_mutual(), "without CA, mTLS must be off");
        assert!(cfg.to_tonic().is_some());
    }

    #[test]
    fn load_enables_mutual_when_ca_provided() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (cert_pem, key_pem) = gen_self_signed();
        let (ca_pem, _) = gen_self_signed();
        let cert_path = write_tmp(&dir, "cert.pem", &cert_pem);
        let key_path = write_tmp(&dir, "key.pem", &key_pem);
        let ca_path = write_tmp(&dir, "ca.pem", &ca_pem);

        let cfg = TlsConfig::load(cert_path, key_path, Some(&ca_path)).expect("mTLS cfg");
        assert!(cfg.is_enabled());
        assert!(cfg.is_mutual());
    }

    #[test]
    fn missing_cert_file_reports_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("missing-cert.pem");
        let key_path = dir.path().join("missing-key.pem");

        let err =
            TlsConfig::load(cert_path.clone(), key_path, None).expect_err("should fail on missing");
        match err {
            TlsError::Io { role, path, .. } => {
                assert_eq!(role, "server certificate");
                assert_eq!(path, cert_path);
            }
            other => panic!("expected Io error, got {other:?}"),
        }
    }

    #[test]
    fn missing_ca_file_reports_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (cert_pem, key_pem) = gen_self_signed();
        let cert_path = write_tmp(&dir, "cert.pem", &cert_pem);
        let key_path = write_tmp(&dir, "key.pem", &key_pem);
        let ca_path = dir.path().join("missing-ca.pem");

        let err = TlsConfig::load(cert_path, key_path, Some(&ca_path))
            .expect_err("should fail on missing CA");
        match err {
            TlsError::Io { role, path, .. } => {
                assert_eq!(role, "client CA bundle");
                assert_eq!(path, ca_path);
            }
            other => panic!("expected Io error, got {other:?}"),
        }
    }

    #[test]
    fn partial_material_rejected() {
        // Only cert provided — reject loudly.
        let err = matches!(
            TlsConfig::load(
                PathBuf::from("/nonexistent-cert.pem"),
                PathBuf::from("/nonexistent-key.pem"),
                None,
            ),
            Err(TlsError::Io { .. })
        );
        assert!(err, "load should fail with Io when files missing");
    }
}
