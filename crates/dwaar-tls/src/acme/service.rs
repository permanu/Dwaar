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

        // For non-wildcard domains, prefer TLS-ALPN-01 (needs only port 443)
        // over HTTP-01 (needs port 80). Fall back to HTTP-01 if ALPN fails.
        let is_wildcard = domain.starts_with("*.");

        if !is_wildcard {
            match self.issuer.issue_tls_alpn01(domain, le_url, "le").await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    debug!(
                        domain,
                        error = %e,
                        "TLS-ALPN-01 failed, falling back to HTTP-01"
                    );
                }
            }
        }

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

    /// React to an OCSP-confirmed revocation: evict cache, delete on-disk
    /// cert+key, and trigger an immediate re-issuance.
    ///
    /// Deliberately swallows I/O errors and re-issuance errors — the
    /// *primary* safety goal is that the revoked cert stops being served,
    /// and every branch here achieves that. Re-issuance failure is
    /// recoverable: the next renewal cycle (12h) will retry, and the next
    /// handshake for this domain will simply fail with "no cert" instead
    /// of serving a revoked one, which is the correct behaviour.
    async fn handle_revoked_cert(&self, domain: &str) {
        // 1+2: Evict the LRU entry and delete the on-disk files.
        evict_revoked_cert(&self.cert_store, &self.cert_dir, domain).await;

        // 3. Kick off an immediate re-issuance through the normal fallback
        //    chain. This runs inline (not spawned) because the OCSP refresh
        //    loop is already a background task and inline keeps ordering
        //    predictable — no risk of two re-issuance attempts racing.
        match self.issue_with_fallback(domain).await {
            Ok(()) => {
                info!(domain, "revoked cert replaced with freshly issued cert");
            }
            Err(e) => {
                error!(
                    domain,
                    error = %e,
                    "re-issuance after revocation failed — next handshake will have no cert \
                     (safer than serving a revoked cert). Will retry on next renewal cycle."
                );
            }
        }
    }

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
                        "CERTIFICATE IS REVOKED — evicting from cache and re-issuing"
                    );
                    // A revoked cert MUST NOT be served on any subsequent
                    // handshake. Evict from the in-memory LRU (so the next
                    // get() misses), delete the on-disk PEM+key so the next
                    // reload cannot pick up the same revoked bytes, and
                    // kick off an immediate re-issuance via the ACME
                    // fallback chain. We deliberately do not propagate
                    // eviction failures — even a partial cleanup is
                    // strictly safer than continuing to serve the cert.
                    self.handle_revoked_cert(domain).await;
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

/// Evict a revoked cert from both the in-memory LRU and the on-disk
/// cert directory, without triggering re-issuance.
///
/// Factored out of [`TlsBackgroundService::handle_revoked_cert`] so a unit
/// test can exercise the cleanup logic in isolation — the re-issuance leg
/// of revocation handling requires a live ACME directory and is covered
/// by integration tests instead.
///
/// Swallows per-file `NotFound` but logs other I/O errors, because the
/// goal is "revoked bytes must not be reloadable"; a partial delete still
/// meets that goal as long as the LRU entry is gone (since the next
/// `get()` will look on disk and fail).
async fn evict_revoked_cert(cert_store: &CertStore, cert_dir: &str, domain: &str) {
    cert_store.invalidate(domain);

    let (cert_path, key_path) = revoked_cert_paths(cert_dir, domain);

    if let Err(e) = tokio::fs::remove_file(&cert_path).await
        && e.kind() != std::io::ErrorKind::NotFound
    {
        warn!(
            domain,
            path = %cert_path.display(),
            error = %e,
            "failed to delete revoked cert file"
        );
    }
    if let Err(e) = tokio::fs::remove_file(&key_path).await
        && e.kind() != std::io::ErrorKind::NotFound
    {
        warn!(
            domain,
            path = %key_path.display(),
            error = %e,
            "failed to delete revoked key file"
        );
    }
}

/// Compute the `(cert.pem, cert.key)` paths for a domain under `cert_dir`.
///
/// Factored out so that the revoked-cert eviction logic can be exercised
/// by a unit test without stubbing the whole `CertStore` + ACME issuer
/// machinery. The naming convention is owned by the ACME issuer
/// (`write_cert_files`) and mirrored here.
fn revoked_cert_paths(cert_dir: &str, domain: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let base = Path::new(cert_dir);
    (
        base.join(format!("{domain}.pem")),
        base.join(format!("{domain}.key")),
    )
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

    #[test]
    fn revoked_cert_paths_match_issuer_convention() {
        let (cert, key) = revoked_cert_paths("/tmp/certs", "example.com");
        assert_eq!(cert, std::path::PathBuf::from("/tmp/certs/example.com.pem"));
        assert_eq!(key, std::path::PathBuf::from("/tmp/certs/example.com.key"));
    }

    /// End-to-end check of the eviction leg of revocation handling:
    /// seeding a cert on disk + in cache, calling the eviction helper,
    /// and asserting both tiers are empty afterwards. The re-issuance leg
    /// is covered separately by integration tests that can speak to a
    /// live ACME directory — unit tests deliberately skip it so they do
    /// not depend on network or a test ACME server.
    #[tokio::test]
    async fn evict_revoked_cert_clears_cache_and_disk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let domain = "revoked.example.com";

        let (cert_pem, key_pem) = generate_self_signed(domain);
        std::fs::write(dir.path().join(format!("{domain}.pem")), &cert_pem)
            .expect("write cert pem");
        std::fs::write(dir.path().join(format!("{domain}.key")), &key_pem).expect("write key pem");

        let cert_store = CertStore::new(dir.path(), 100);

        // Populate the in-memory LRU by loading the cert once.
        assert!(
            cert_store.get(domain).is_some(),
            "fresh cert should load from disk"
        );
        assert_eq!(cert_store.cached_count(), 1, "LRU should now hold the cert");

        // Trigger the eviction leg of revocation handling.
        evict_revoked_cert(
            &cert_store,
            dir.path().to_str().expect("tempdir utf8"),
            domain,
        )
        .await;

        // LRU is empty.
        assert_eq!(
            cert_store.cached_count(),
            0,
            "LRU entry must be evicted after revocation"
        );

        // On-disk files are gone.
        assert!(
            !dir.path().join(format!("{domain}.pem")).exists(),
            "cert PEM must be deleted from disk"
        );
        assert!(
            !dir.path().join(format!("{domain}.key")).exists(),
            "key PEM must be deleted from disk"
        );

        // A fresh get() miss also returns None (no re-hydration).
        assert!(
            cert_store.get(domain).is_none(),
            "post-eviction lookup must miss"
        );
    }

    /// Eviction must be idempotent — calling it when nothing is cached and
    /// no files exist should complete cleanly without logging filesystem
    /// errors above the `NotFound` threshold.
    #[tokio::test]
    async fn evict_revoked_cert_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_store = CertStore::new(dir.path(), 100);

        evict_revoked_cert(
            &cert_store,
            dir.path().to_str().expect("tempdir utf8"),
            "never-seen.example.com",
        )
        .await;

        assert_eq!(cert_store.cached_count(), 0);
    }
}
