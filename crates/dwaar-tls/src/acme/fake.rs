// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Fake ACME issuer for local proofs.
//!
//! Issues a certificate only when the in-memory DNS record matches the
//! claimed address and the HTTP challenge token is the one Dwaar is
//! serving. A miss stores nothing. No socket is bound and no public
//! certificate authority is contacted.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use zeroize::Zeroizing;

use crate::cert_store::CertStore;
use crate::sni::is_valid_sni_hostname;

/// In-memory A and AAAA answers. Lookups never leave the process.
#[derive(Debug, Default, Clone)]
pub struct FakeDns {
    records: HashMap<String, Vec<IpAddr>>,
}

impl FakeDns {
    /// Empty table. No name resolves until [`Self::insert`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
        }
    }

    /// Record that `name` has `address`. A second insert of the same pair is a no-op.
    pub fn insert(&mut self, name: &str, address: IpAddr) {
        let name = normalize_domain(name);
        let addresses = self.records.entry(name).or_default();
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }

    /// `true` when `name` has an A or AAAA record equal to `address`.
    #[must_use]
    pub fn matches(&self, name: &str, address: IpAddr) -> bool {
        let name = normalize_domain(name);
        self.records
            .get(&name)
            .is_some_and(|addresses| addresses.contains(&address))
    }
}

/// The HTTP challenge body Dwaar is serving, read in-process.
///
/// Implementors must not bind a socket. `None` means Dwaar would not
/// answer this host and token with `200`.
pub trait HttpChallenge: Send + Sync {
    /// Body of the `200` challenge response, if Dwaar is serving `token` for `host`.
    fn served_body(&self, host: &str, token: &str) -> Option<Vec<u8>>;
}

/// Why the fake issuer refused to store a certificate.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FakeIssueError {
    /// The name does not have `address` in the fake DNS table.
    #[error("fake DNS does not match {domain}")]
    DnsMismatch { domain: String },

    /// Dwaar is not serving this token for the address.
    #[error("HTTP challenge token is not the one Dwaar is serving for {domain}")]
    ChallengeMismatch { domain: String },

    /// Proofs were not both good, or the name cannot be stored as a file.
    #[error("no certificate stored for {domain}: {reason}")]
    NotStored { domain: String, reason: String },
}

/// Issues locally-signed certificates after a fake DNS and HTTP proof.
///
/// The certificate is a self-signed key this process generates. It is not
/// a `ZeroSSL`, Let's Encrypt, or other public CA certificate.
pub struct FakeIssuer<C> {
    dns: FakeDns,
    challenge: Arc<C>,
    cert_dir: PathBuf,
    cert_store: Arc<CertStore>,
}

impl<C: fmt::Debug> fmt::Debug for FakeIssuer<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeIssuer")
            .field("dns", &self.dns)
            .field("challenge", &self.challenge)
            .field("cert_dir", &self.cert_dir)
            .field("cert_store", &self.cert_store)
            .finish()
    }
}

impl<C: HttpChallenge> FakeIssuer<C> {
    /// Issuer that reads `challenge` and writes under `cert_dir`.
    ///
    /// Does not create `cert_dir` and does not bind a port.
    #[must_use]
    pub fn new(dns: FakeDns, challenge: Arc<C>, cert_dir: impl Into<PathBuf>) -> Self {
        let cert_dir = cert_dir.into();
        let cert_store = Arc::new(CertStore::new(&cert_dir, 16));
        Self {
            dns,
            challenge,
            cert_dir,
            cert_store,
        }
    }

    /// Store the issuer reads after a successful [`Self::issue`].
    #[must_use]
    pub fn cert_store(&self) -> &CertStore {
        &self.cert_store
    }

    /// Certificate directory. Empty until a successful issue.
    #[must_use]
    pub fn cert_dir(&self) -> &Path {
        &self.cert_dir
    }

    /// Store a certificate for `domain` only when both proofs match.
    ///
    /// `address` must be a fake-DNS address for `domain`, and `token` must
    /// be the exact body Dwaar is serving for that address. Otherwise this
    /// returns an error and leaves the certificate directory unchanged.
    ///
    /// # Errors
    ///
    /// [`FakeIssueError::DnsMismatch`] when the fake DNS proof is wrong,
    /// [`FakeIssueError::ChallengeMismatch`] when Dwaar is not serving
    /// `token`, and [`FakeIssueError::NotStored`] when the name must not
    /// become a file. No certificate is written on any of these.
    pub async fn issue(
        &self,
        domain: &str,
        address: IpAddr,
        token: &str,
    ) -> Result<(), FakeIssueError> {
        let domain = normalize_domain(domain);
        if !is_valid_sni_hostname(&domain) {
            return Err(FakeIssueError::NotStored {
                domain,
                reason: "invalid domain name".to_owned(),
            });
        }
        if !self.dns.matches(&domain, address) {
            return Err(FakeIssueError::DnsMismatch { domain });
        }
        let host = challenge_host(address);
        let served = self.challenge.served_body(&host, token);
        if served.as_deref() != Some(token.as_bytes()) {
            return Err(FakeIssueError::ChallengeMismatch { domain });
        }

        let (cert_pem, key_pem) =
            generate_local_cert(&domain).map_err(|reason| FakeIssueError::NotStored {
                domain: domain.clone(),
                reason,
            })?;
        super::issuer::store_cert_pair(&self.cert_dir, &domain, &cert_pem, &key_pem)
            .await
            .map_err(|error| FakeIssueError::NotStored {
                domain: domain.clone(),
                reason: error.to_string(),
            })?;
        self.cert_store.invalidate(&domain);
        Ok(())
    }
}

fn generate_local_cert(domain: &str) -> Result<(String, Zeroizing<String>), String> {
    use rcgen::{
        CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair,
        KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
    };

    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|error| format!("key generation failed: {error}"))?;
    let mut params = CertificateParams::new(vec![domain.to_owned()])
        .map_err(|error| format!("certificate parameters rejected {domain}: {error}"))?;
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, domain);
    name.push(DnType::OrganizationName, "Permanu Fake Issuer");
    params.distinguished_name = name;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let cert = params
        .self_signed(&key_pair)
        .map_err(|error| format!("self-signed certificate failed: {error}"))?;
    Ok((cert.pem(), Zeroizing::new(key_pair.serialize_pem())))
}

fn normalize_domain(domain: &str) -> String {
    let trimmed = domain.trim();
    let without_dot = trimmed.strip_suffix('.').unwrap_or(trimmed);
    without_dot.to_ascii_lowercase()
}

/// Host header Dwaar's challenge parser accepts for `address`.
///
/// IPv6 is bracketed. An unbracketed address is split on `:` by the proxy
/// host parser and would not match the address the token was registered for.
fn challenge_host(address: IpAddr) -> String {
    match address {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => format!("[{ip}]"),
    }
}
