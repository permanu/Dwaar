// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Pingora background service for TLS certificate management.
//!
//! On startup, checks all `tls auto` domains for missing or expiring certs
//! and fetches OCSP responses. Then runs a 12-hour loop to refresh OCSP
//! staples and renew certs within 30 days of expiry.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use openssl::asn1::Asn1Time;
use openssl::x509::X509;
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use tracing::{debug, error, info, warn};

use super::issuer::CertIssuer;
use super::{
    AcmeError, GTS_DIRECTORY_URL, INTER_DOMAIN_DELAY, RENEWAL_WINDOW_DAYS, le_directory_url,
};
use crate::cert_store::CertStore;

/// Background service that provisions/renews ACME certificates and refreshes
/// OCSP staples.
///
/// The domain list is behind `ArcSwap` so that `ConfigWatcher` can swap in a
/// new set of domains on hot-reload without restarting this service.
pub struct TlsBackgroundService {
    domains: Arc<ArcSwap<Vec<String>>>,
    cert_dir: String,
    issuer: Arc<CertIssuer>,
    cert_store: Arc<CertStore>,
    in_flight: tokio::sync::Mutex<HashSet<String>>,
}

impl std::fmt::Debug for TlsBackgroundService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsBackgroundService")
            .field("cert_dir", &self.cert_dir)
            .finish_non_exhaustive()
    }
}

impl TlsBackgroundService {
    pub fn new(
        domains: Arc<ArcSwap<Vec<String>>>,
        cert_dir: &str,
        issuer: Arc<CertIssuer>,
        cert_store: Arc<CertStore>,
    ) -> Self {
        Self {
            domains,
            cert_dir: cert_dir.to_string(),
            issuer,
            cert_store,
            in_flight: tokio::sync::Mutex::new(HashSet::new()),
        }
    }

    /// Check if a domain's cert is missing or expiring within the renewal window.
    async fn needs_issuance(&self, domain: &str) -> bool {
        let cert_path = Path::new(&self.cert_dir).join(format!("{domain}.pem"));

        let Ok(pem_bytes) = tokio::fs::read(&cert_path).await else {
            debug!(domain, "cert file missing — needs issuance");
            return true;
        };

        let cert = match X509::from_pem(&pem_bytes) {
            Ok(c) => c,
            Err(e) => {
                warn!(domain, error = %e, "corrupt cert PEM — needs re-issuance");
                return true;
            }
        };

        let Ok(renewal_threshold) = Asn1Time::days_from_now(RENEWAL_WINDOW_DAYS) else {
            return true;
        };

        if cert.not_after() < renewal_threshold {
            info!(
                domain,
                "cert expires within {RENEWAL_WINDOW_DAYS} days — needs renewal"
            );
            return true;
        }

        false
    }

    /// Try issuing with Let's Encrypt, fall back to Google Trust Services.
    async fn issue_with_fallback(&self, domain: &str) -> Result<(), AcmeError> {
        // Concurrency guard — prevent double-issuance
        {
            let mut in_flight = self.in_flight.lock().await;
            if !in_flight.insert(domain.to_string()) {
                debug!(domain, "issuance already in flight, skipping");
                return Ok(());
            }
        }

        let result = self.try_issue(domain).await;

        // Always remove from in-flight set
        self.in_flight.lock().await.remove(domain);

        result
    }

    async fn try_issue(&self, domain: &str) -> Result<(), AcmeError> {
        let le_url = le_directory_url();

        match self.issuer.issue(domain, le_url, "le").await {
            Ok(()) => Ok(()),
            Err(le_err) => {
                warn!(
                    domain,
                    error = %le_err,
                    "Let's Encrypt failed, trying Google Trust Services"
                );

                self.issuer
                    .issue(domain, GTS_DIRECTORY_URL, "gts")
                    .await
                    .map_err(|gts_err| AcmeError::AllCasFailed {
                        domain: domain.to_string(),
                        le_error: le_err.to_string(),
                        gts_error: gts_err.to_string(),
                    })
            }
        }
    }

    // NOTE: The spec describes exponential retry backoff (1h → 2h → 4h → 8h → 24h cap)
    // and "3 consecutive failures" warnings. This is deferred to a follow-up task.
    // For now, failed domains are retried on the next check cycle (12h later).
    // The fallback CA (GTS) provides immediate retry within a single attempt.

    /// Fetch fresh OCSP responses for all domains with cached certs.
    async fn refresh_ocsp_responses(&self) {
        debug!("OCSP refresh cycle started");

        let domains = self.domains.load();
        for domain in domains.iter() {
            let Some(cached) = self.cert_store.get(domain) else {
                continue;
            };

            let Some(ref issuer) = cached.issuer else {
                debug!(domain, "no issuer in chain, skipping OCSP");
                continue;
            };

            match crate::ocsp::fetch_ocsp_response(domain, &cached.cert, issuer).await {
                Ok(response) => {
                    self.cert_store.update_ocsp(domain, response);
                    info!(domain, "OCSP response refreshed");
                }
                Err(crate::ocsp::OcspError::NoResponder) => {
                    debug!(domain, "cert has no OCSP responder URL");
                }
                Err(crate::ocsp::OcspError::CertRevoked {
                    domain: ref revoked_domain,
                    ref serial,
                }) => {
                    error!(
                        domain = %revoked_domain,
                        serial = %serial,
                        "CERTIFICATE IS REVOKED — not stapling"
                    );
                }
                Err(e) => {
                    warn!(domain, error = %e, "OCSP fetch failed");
                }
            }

            tokio::time::sleep(super::OCSP_INTER_DOMAIN_DELAY).await;
        }
    }

    /// Run the startup scan: issue certs for domains that need them.
    async fn startup_scan(&self) {
        let domains = self.domains.load();
        info!(
            domains = domains.len(),
            "ACME startup scan — checking certificates"
        );

        for domain in domains.iter() {
            if !self.needs_issuance(domain).await {
                continue;
            }

            if let Err(e) = self.issue_with_fallback(domain).await {
                error!(domain, error = %e, "ACME issuance failed");
            }

            tokio::time::sleep(INTER_DOMAIN_DELAY).await;
        }
    }

    /// Run the periodic renewal check.
    async fn daily_renewal(&self) {
        debug!("ACME renewal check");

        // Reload domain list from ArcSwap so hot-reloaded domains are picked up.
        let domains = self.domains.load();
        for domain in domains.iter() {
            if !self.needs_issuance(domain).await {
                continue;
            }

            info!(domain, "renewing certificate");

            if let Err(e) = self.issue_with_fallback(domain).await {
                error!(domain, error = %e, "ACME renewal failed");
            }

            tokio::time::sleep(INTER_DOMAIN_DELAY).await;
        }
    }
}

#[async_trait]
impl BackgroundService for TlsBackgroundService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        self.startup_scan().await;
        self.refresh_ocsp_responses().await;

        loop {
            tokio::select! {
                () = tokio::time::sleep(super::SERVICE_CHECK_INTERVAL) => {
                    self.refresh_ocsp_responses().await;
                    self.daily_renewal().await;
                }
                _ = shutdown.changed() => {
                    info!("TLS background service shutting down");
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acme::issuer::CertIssuer;
    use crate::acme::solver::ChallengeSolver;
    use crate::cert_store::CertStore;
    use crate::test_util::generate_self_signed;

    fn make_service(domains: Vec<String>, cert_dir: &Path) -> TlsBackgroundService {
        let solver = Arc::new(ChallengeSolver::new());
        let cert_store = Arc::new(CertStore::new(cert_dir, 100));
        let issuer = Arc::new(CertIssuer::new(
            cert_dir.join("acme"),
            cert_dir,
            solver,
            Arc::clone(&cert_store),
        ));
        TlsBackgroundService::new(
            Arc::new(ArcSwap::from_pointee(domains)),
            cert_dir.to_str().expect("utf8"),
            issuer,
            cert_store,
        )
    }

    #[tokio::test]
    async fn needs_issuance_when_cert_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let svc = make_service(vec!["missing.example.com".into()], dir.path());
        assert!(svc.needs_issuance("missing.example.com").await);
    }

    #[tokio::test]
    async fn no_issuance_needed_for_valid_cert() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (cert_pem, key_pem) = generate_self_signed("valid.example.com");

        std::fs::write(dir.path().join("valid.example.com.pem"), &cert_pem).expect("write cert");
        std::fs::write(dir.path().join("valid.example.com.key"), &key_pem).expect("write key");

        let svc = make_service(vec!["valid.example.com".into()], dir.path());
        // generate_self_signed creates certs valid for 365 days
        assert!(!svc.needs_issuance("valid.example.com").await);
    }
}
