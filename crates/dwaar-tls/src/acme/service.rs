// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Pingora background service for ACME certificate issuance and renewal.
//!
//! On startup, checks all `tls auto` domains for missing or expiring certs.
//! Then runs a daily loop to renew certs within 30 days of expiry.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use openssl::asn1::Asn1Time;
use openssl::x509::X509;
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use tracing::{debug, error, info, warn};

use super::issuer::CertIssuer;
use super::{
    le_directory_url, AcmeError, DAILY_CHECK_INTERVAL, GTS_DIRECTORY_URL, INTER_DOMAIN_DELAY,
    RENEWAL_WINDOW_DAYS,
};

/// Background service that provisions and renews ACME certificates.
pub struct AcmeService {
    domains: Vec<String>,
    cert_dir: String,
    issuer: Arc<CertIssuer>,
    in_flight: tokio::sync::Mutex<HashSet<String>>,
}

impl std::fmt::Debug for AcmeService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcmeService")
            .field("domains", &self.domains)
            .field("cert_dir", &self.cert_dir)
            .finish_non_exhaustive()
    }
}

impl AcmeService {
    pub fn new(domains: Vec<String>, cert_dir: &str, issuer: Arc<CertIssuer>) -> Self {
        Self {
            domains,
            cert_dir: cert_dir.to_string(),
            issuer,
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
    // For now, failed domains are retried on the next daily check (24h later).
    // The fallback CA (GTS) provides immediate retry within a single attempt.

    /// Run the startup scan: issue certs for domains that need them.
    async fn startup_scan(&self) {
        info!(
            domains = self.domains.len(),
            "ACME startup scan — checking certificates"
        );

        for domain in &self.domains {
            if !self.needs_issuance(domain).await {
                continue;
            }

            if let Err(e) = self.issue_with_fallback(domain).await {
                error!(domain, error = %e, "ACME issuance failed");
            }

            tokio::time::sleep(INTER_DOMAIN_DELAY).await;
        }
    }

    /// Run the daily renewal check.
    async fn daily_renewal(&self) {
        debug!("ACME daily renewal check");

        for domain in &self.domains {
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
impl BackgroundService for AcmeService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        // Startup: immediately provision missing/expiring certs
        self.startup_scan().await;

        // Daily loop: check and renew
        loop {
            tokio::select! {
                () = tokio::time::sleep(DAILY_CHECK_INTERVAL) => {
                    self.daily_renewal().await;
                }
                _ = shutdown.changed() => {
                    info!("ACME service shutting down");
                    return;
                }
            }
        }
    }
}
