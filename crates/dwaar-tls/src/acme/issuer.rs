// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! ACME certificate issuance flow.
//!
//! Orchestrates the full ACME protocol for a single domain:
//! account setup → order → HTTP-01 challenge → finalize → write cert.

use std::path::PathBuf;
use std::sync::Arc;

use instant_acme::{
    Account, AccountCredentials, Authorization, AuthorizationStatus, ChallengeType, Identifier,
    NewAccount, NewOrder, Order, OrderStatus,
};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::x509::X509ReqBuilder;
use tokio::fs;
use tracing::{debug, info};

use super::account::{credentials_path, ensure_acme_dir, load_credentials, save_credentials};
use super::solver::ChallengeSolver;
use super::{AcmeError, CHALLENGE_CLEANUP_DELAY};
use crate::cert_store::CertStore;

/// Manages ACME certificate issuance for one or more domains.
#[derive(Debug)]
pub struct CertIssuer {
    acme_dir: PathBuf,
    cert_dir: PathBuf,
    solver: Arc<ChallengeSolver>,
    cert_store: Arc<CertStore>,
}

impl CertIssuer {
    pub fn new(
        acme_dir: impl Into<PathBuf>,
        cert_dir: impl Into<PathBuf>,
        solver: Arc<ChallengeSolver>,
        cert_store: Arc<CertStore>,
    ) -> Self {
        Self {
            acme_dir: acme_dir.into(),
            cert_dir: cert_dir.into(),
            solver,
            cert_store,
        }
    }

    /// Issue a certificate for `domain` using the given ACME directory URL.
    ///
    /// Returns `Ok(())` on success (cert written to disk, cache invalidated).
    pub async fn issue(
        &self,
        domain: &str,
        directory_url: &str,
        ca_id: &str,
    ) -> Result<(), AcmeError> {
        ensure_acme_dir(&self.acme_dir).await?;

        let account = self.get_or_create_account(directory_url, ca_id).await?;

        info!(domain, ca = ca_id, "starting ACME order");

        let identifier = Identifier::Dns(domain.to_string());
        let mut order = account
            .new_order(&NewOrder {
                identifiers: &[identifier],
            })
            .await
            .map_err(|e| AcmeError::OrderCreation(e.to_string()))?;

        self.solve_challenges(domain, &mut order).await?;
        Self::poll_order_ready(domain, &mut order).await?;

        // Generate a private key and CSR for the domain
        let (private_key_pem, csr_der) =
            generate_key_and_csr(domain).map_err(|e| AcmeError::Finalization(e.to_string()))?;

        order
            .finalize(&csr_der)
            .await
            .map_err(|e| AcmeError::Finalization(e.to_string()))?;

        let cert_chain_pem = Self::poll_certificate(domain, &mut order).await?;

        self.write_cert_files(domain, &cert_chain_pem, &private_key_pem)
            .await?;

        // Invalidate the cert cache so the next TLS handshake picks up the new cert
        self.cert_store.invalidate(domain);

        info!(domain, ca = ca_id, "certificate issued and stored");
        Ok(())
    }

    /// Process all authorizations for the order, setting up HTTP-01 challenges.
    async fn solve_challenges(&self, domain: &str, order: &mut Order) -> Result<(), AcmeError> {
        let authorizations =
            order
                .authorizations()
                .await
                .map_err(|e| AcmeError::ChallengeValidation {
                    domain: domain.to_string(),
                    reason: e.to_string(),
                })?;

        for authz in &authorizations {
            self.solve_single_authz(domain, order, authz).await?;
        }
        Ok(())
    }

    /// Solve a single authorization's HTTP-01 challenge.
    async fn solve_single_authz(
        &self,
        domain: &str,
        order: &mut Order,
        authz: &Authorization,
    ) -> Result<(), AcmeError> {
        match authz.status {
            AuthorizationStatus::Valid => return Ok(()),
            AuthorizationStatus::Pending => {}
            other => {
                return Err(AcmeError::ChallengeValidation {
                    domain: domain.to_string(),
                    reason: format!("unexpected authorization status: {other:?}"),
                });
            }
        }

        let challenge = authz
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Http01)
            .ok_or_else(|| AcmeError::ChallengeValidation {
                domain: domain.to_string(),
                reason: "no HTTP-01 challenge offered by CA".to_string(),
            })?;

        let token = challenge.token.clone();
        let key_auth = order.key_authorization(challenge);

        debug!(domain, token = %token, "setting HTTP-01 challenge token");
        self.solver.set(&token, key_auth.as_str());

        order
            .set_challenge_ready(&challenge.url)
            .await
            .map_err(|e| AcmeError::ChallengeValidation {
                domain: domain.to_string(),
                reason: e.to_string(),
            })?;

        // Schedule delayed cleanup of the challenge token
        let solver = Arc::clone(&self.solver);
        let cleanup_token = token.clone();
        tokio::spawn(async move {
            tokio::time::sleep(CHALLENGE_CLEANUP_DELAY).await;
            solver.remove(&cleanup_token);
        });

        Ok(())
    }

    /// Poll until the order reaches `Ready` or `Valid` status.
    async fn poll_order_ready(domain: &str, order: &mut Order) -> Result<(), AcmeError> {
        let mut attempts = 10_u32;
        loop {
            let state = order
                .refresh()
                .await
                .map_err(|e| AcmeError::ChallengeValidation {
                    domain: domain.to_string(),
                    reason: e.to_string(),
                })?;

            match state.status {
                OrderStatus::Ready | OrderStatus::Valid => return Ok(()),
                OrderStatus::Invalid => {
                    return Err(AcmeError::ChallengeValidation {
                        domain: domain.to_string(),
                        reason: "order became invalid".to_string(),
                    });
                }
                OrderStatus::Pending | OrderStatus::Processing => {
                    attempts =
                        attempts
                            .checked_sub(1)
                            .ok_or_else(|| AcmeError::ChallengeValidation {
                                domain: domain.to_string(),
                                reason: "order did not become ready after polling".to_string(),
                            })?;
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
        }
    }

    /// Poll until the certificate is available for download.
    async fn poll_certificate(_domain: &str, order: &mut Order) -> Result<String, AcmeError> {
        let mut attempts = 10_u32;
        loop {
            if let Some(cert) = order
                .certificate()
                .await
                .map_err(|e| AcmeError::CertDownload(e.to_string()))?
            {
                return Ok(cert);
            }

            attempts = attempts.checked_sub(1).ok_or_else(|| {
                AcmeError::CertDownload("certificate not available after polling".to_string())
            })?;
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    }

    /// Get an existing ACME account or create a new one.
    async fn get_or_create_account(
        &self,
        directory_url: &str,
        ca_id: &str,
    ) -> Result<Account, AcmeError> {
        let creds_path = credentials_path(&self.acme_dir, ca_id);

        // Try loading existing credentials
        if let Ok(json) = load_credentials(&creds_path).await {
            let credentials: AccountCredentials = serde_json::from_str(&json)
                .map_err(|e| AcmeError::Registration(format!("corrupt credentials: {e}")))?;
            let account = Account::from_credentials(credentials)
                .await
                .map_err(|e| AcmeError::Registration(e.to_string()))?;
            debug!(ca = ca_id, "loaded existing ACME account");
            return Ok(account);
        }

        // Create a new account
        info!(ca = ca_id, "creating new ACME account");
        let (account, credentials) = Account::create(
            &NewAccount {
                contact: &[],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory_url,
            None,
        )
        .await
        .map_err(|e| AcmeError::Registration(e.to_string()))?;

        // Persist credentials
        let json = serde_json::to_string(&credentials)
            .map_err(|e| AcmeError::Registration(format!("serialize credentials: {e}")))?;
        save_credentials(&creds_path, &json).await?;

        info!(ca = ca_id, "ACME account created");
        Ok(account)
    }

    /// Write cert chain and private key to disk using atomic rename.
    pub(crate) async fn write_cert_files(
        &self,
        domain: &str,
        cert_pem: &str,
        key_pem: &str,
    ) -> Result<(), AcmeError> {
        let cert_path = self.cert_dir.join(format!("{domain}.pem"));
        let key_path = self.cert_dir.join(format!("{domain}.key"));

        // Ensure cert directory exists
        fs::create_dir_all(&self.cert_dir)
            .await
            .map_err(AcmeError::CertWrite)?;

        atomic_write_pem(&cert_path, cert_pem, 0o644).await?;
        atomic_write_pem(&key_path, key_pem, 0o600).await?;

        debug!(domain, cert = %cert_path.display(), "cert files written");
        Ok(())
    }
}

/// Write a PEM string to disk atomically via a temp file and rename.
///
/// `mode` sets the Unix file permissions (ignored on non-Unix).
async fn atomic_write_pem(
    target: &std::path::Path,
    content: &str,
    #[allow(unused_variables)] mode: u32,
) -> Result<(), AcmeError> {
    let tmp = target.with_extension("tmp");
    fs::write(&tmp, content.as_bytes())
        .await
        .map_err(AcmeError::CertWrite)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(mode);
        fs::set_permissions(&tmp, perms)
            .await
            .map_err(AcmeError::CertWrite)?;
    }

    fs::rename(&tmp, target)
        .await
        .map_err(AcmeError::CertWrite)?;

    Ok(())
}

/// Generate an ECDSA P-256 private key and a DER-encoded CSR for the given domain.
///
/// Returns `(private_key_pem, csr_der)`.
fn generate_key_and_csr(domain: &str) -> Result<(String, Vec<u8>), openssl::error::ErrorStack> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let ec_key = EcKey::generate(&group)?;
    let pkey = PKey::from_ec_key(ec_key)?;

    let mut builder = X509ReqBuilder::new()?;
    builder.set_pubkey(&pkey)?;

    // Set the subject CN to the domain
    let mut name_builder = openssl::x509::X509NameBuilder::new()?;
    name_builder.append_entry_by_text("CN", domain)?;
    let name = name_builder.build();
    builder.set_subject_name(&name)?;

    // Add Subject Alternative Name extension
    let mut extensions = openssl::stack::Stack::new()?;
    let san = openssl::x509::extension::SubjectAlternativeName::new()
        .dns(domain)
        .build(&builder.x509v3_context(None))?;
    extensions.push(san)?;
    builder.add_extensions(&extensions)?;

    builder.sign(&pkey, openssl::hash::MessageDigest::sha256())?;

    let csr_der = builder.build().to_der()?;
    let key_pem = String::from_utf8(pkey.private_key_to_pem_pkcs8()?)
        .expect("PEM output should be valid UTF-8");

    Ok((key_pem, csr_der))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert_store::CertStore;

    #[tokio::test]
    async fn write_cert_files_atomic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_dir = dir.path().join("certs");
        let acme_dir = dir.path().join("acme");

        let solver = Arc::new(ChallengeSolver::new());
        let cert_store = Arc::new(CertStore::new(&cert_dir, 100));

        let issuer = CertIssuer::new(&acme_dir, &cert_dir, solver, cert_store);

        let fake_cert = "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n";
        let fake_key = "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n";

        issuer
            .write_cert_files("test.example.com", fake_cert, fake_key)
            .await
            .expect("write should succeed");

        // Verify files exist with correct content
        let cert_content =
            std::fs::read_to_string(cert_dir.join("test.example.com.pem")).expect("cert file");
        assert_eq!(cert_content, fake_cert);

        let key_content =
            std::fs::read_to_string(cert_dir.join("test.example.com.key")).expect("key file");
        assert_eq!(key_content, fake_key);

        // Verify key file permissions (Unix)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(cert_dir.join("test.example.com.key"))
                .expect("metadata")
                .permissions();
            assert_eq!(perms.mode() & 0o777, 0o600);
        }

        // Verify no .tmp files remain
        assert!(!cert_dir.join("test.example.com.tmp").exists());
    }
}
