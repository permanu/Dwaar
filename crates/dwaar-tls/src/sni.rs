// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! SNI-based certificate selection during TLS handshake.
//!
//! Implements Pingora's [`TlsAccept`] trait. When a client connects,
//! reads the SNI hostname from the `ClientHello`, looks up the right
//! cert in the [`CertStore`], and injects it into the SSL context.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use openssl::ssl::NameType;
use pingora_core::listeners::TlsAccept;
use pingora_core::protocols::tls::TlsRef;
use pingora_core::tls::ext;
use tracing::{debug, warn};

use crate::cert_store::CertStore;

/// Validate that an SNI hostname is a legal DNS name.
/// Rejects path traversal attempts, null bytes, and other non-hostname characters.
fn is_valid_sni_hostname(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    s.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'*')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

/// Per-domain TLS config from the Dwaarfile `tls` directive.
#[derive(Debug, Clone)]
pub struct DomainTlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

/// Shared, hot-reloadable map of explicit per-domain cert paths.
///
/// `ConfigWatcher` holds a clone of this Arc and swaps in a new map on
/// every successful config reload. `SniResolver` loads the current snapshot
/// on each TLS handshake via `ArcSwap::load()` — zero-copy, lock-free.
pub type DomainConfigMap = Arc<ArcSwap<HashMap<String, DomainTlsConfig>>>;

/// Create an empty [`DomainConfigMap`].
pub fn domain_config_map_empty() -> DomainConfigMap {
    Arc::new(ArcSwap::from_pointee(HashMap::new()))
}

/// SNI-based certificate resolver.
///
/// Holds a reference to the cert store and a shared, live map of
/// domain-specific TLS configs (from `tls /cert /key` directives in the
/// Dwaarfile).  The map is wrapped in `ArcSwap` so that `ConfigWatcher`
/// can swap in a new map on hot-reload without touching this struct.
/// Falls back to a default cert when no SNI is provided (e.g. clients
/// connecting by IP address).
#[derive(Debug)]
pub struct SniResolver {
    cert_store: Arc<CertStore>,
    /// Explicit cert paths — hot-reloadable via shared `ArcSwap`.
    domain_configs: DomainConfigMap,
    /// Domain to use when client doesn't send SNI (IP-based connections)
    default_domain: Option<String>,
}

impl SniResolver {
    /// Create a new resolver.  Domain configs start empty; use
    /// [`add_domain`](Self::add_domain) or [`shared_domain_map`](Self::shared_domain_map)
    /// to populate.
    pub fn new(cert_store: Arc<CertStore>) -> Self {
        Self {
            cert_store,
            domain_configs: domain_config_map_empty(),
            default_domain: None,
        }
    }

    /// Set a fallback domain for connections without SNI.
    /// The first TLS-enabled domain is typically used as the default.
    pub fn set_default_domain(&mut self, domain: &str) {
        self.default_domain = Some(domain.to_lowercase());
    }

    /// Register an explicit cert/key path for a domain.
    ///
    /// This replaces the entire inner map with a new one containing this entry
    /// in addition to any previously added entries — use [`shared_domain_map`]
    /// for bulk updates at startup, and [`ConfigWatcher`] for hot-reload updates.
    pub fn add_domain(&mut self, domain: &str, config: DomainTlsConfig) {
        // Load current map, clone it, insert, store back.
        let mut map = HashMap::clone(&self.domain_configs.load());
        map.insert(domain.to_lowercase(), config);
        self.domain_configs.store(Arc::new(map));
    }

    /// Return a clone of the shared [`DomainConfigMap`].
    ///
    /// Pass this to [`ConfigWatcher::with_sni_domain_map`] so that hot-reload
    /// can update the cert map without restarting.
    pub fn shared_domain_map(&self) -> DomainConfigMap {
        Arc::clone(&self.domain_configs)
    }

    /// Resolve cert for a domain — tries explicit config first,
    /// then wildcard, then default directory layout.
    fn resolve_cert(&self, sni: &str) -> Option<crate::cert_store::CachedCert> {
        if !is_valid_sni_hostname(sni) {
            warn!(sni = %sni, "invalid SNI hostname — rejecting");
            return None;
        }

        let sni_lower = sni.to_lowercase();

        // Load the current domain map — this is a single atomic pointer load,
        // no lock required.
        let configs = self.domain_configs.load();

        // Try explicit cert path for this exact domain
        if let Some(config) = configs.get(&sni_lower) {
            return self
                .cert_store
                .get_or_load(&sni_lower, &config.cert_path, &config.key_path);
        }

        // Try default directory layout for exact domain
        if let Some(cert) = self.cert_store.get(&sni_lower) {
            return Some(cert);
        }

        // Wildcard fallback: strip first label, try *.rest
        if let Some(dot_pos) = sni_lower.find('.') {
            let wildcard = format!("*{}", &sni_lower[dot_pos..]);

            if let Some(config) = configs.get(&wildcard) {
                return self
                    .cert_store
                    .get_or_load(&wildcard, &config.cert_path, &config.key_path);
            }

            return self.cert_store.get(&wildcard);
        }

        None
    }
}

#[async_trait]
impl TlsAccept for SniResolver {
    async fn certificate_callback(&self, ssl: &mut TlsRef) {
        let sni = match ssl.servername(NameType::HOST_NAME) {
            Some(name) => name.to_string(),
            None => {
                // No SNI — use the default domain if configured (handles IP-based connections)
                if let Some(default) = &self.default_domain {
                    debug!("no SNI in handshake, falling back to default domain");
                    default.clone()
                } else {
                    warn!("TLS handshake without SNI and no default domain configured");
                    return;
                }
            }
        };

        let Some(cached) = self.resolve_cert(&sni) else {
            warn!(sni = %sni, "no cert found for SNI hostname");
            return;
        };

        // Inject the cert and key into the SSL context for this handshake
        if let Err(e) = ext::ssl_use_certificate(ssl, &cached.cert) {
            warn!(sni = %sni, error = %e, "failed to set certificate");
            return;
        }

        if let Err(e) = ext::ssl_use_private_key(ssl, &cached.key) {
            warn!(sni = %sni, error = %e, "failed to set private key");
            return;
        }

        // Staple OCSP response if available
        if let Some(ref ocsp_der) = cached.ocsp_response {
            if let Err(e) = ssl.set_ocsp_status(ocsp_der) {
                warn!(sni = %sni, error = %e, "failed to staple OCSP response");
            } else {
                debug!(sni = %sni, "OCSP response stapled to handshake");
            }
        }

        debug!(sni = %sni, "cert loaded for TLS handshake");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sni_resolver_with_explicit_config() {
        let store = Arc::new(CertStore::new("/tmp/nonexistent", 100));
        let mut resolver = SniResolver::new(store);

        resolver.add_domain(
            "example.com",
            DomainTlsConfig {
                cert_path: PathBuf::from("/certs/example.com.pem"),
                key_path: PathBuf::from("/certs/example.com.key"),
            },
        );

        // Domain config is registered — verify the shared map was updated
        assert!(resolver
            .domain_configs
            .load()
            .contains_key("example.com"));
    }

    #[test]
    fn shared_domain_map_reflects_add_domain() {
        let store = Arc::new(CertStore::new("/tmp/nonexistent", 100));
        let mut resolver = SniResolver::new(store);
        let shared = resolver.shared_domain_map();

        resolver.add_domain(
            "test.com",
            DomainTlsConfig {
                cert_path: PathBuf::from("/certs/test.com.pem"),
                key_path: PathBuf::from("/certs/test.com.key"),
            },
        );

        // The shared Arc sees the updated map because both point to the same ArcSwap
        assert!(shared.load().contains_key("test.com"));
    }

    #[test]
    fn hot_reload_via_shared_map() {
        let store = Arc::new(CertStore::new("/tmp/nonexistent", 100));
        let resolver = SniResolver::new(store);
        let shared = resolver.shared_domain_map();

        // Simulate a hot-reload: swap in a new map with a different domain
        let mut new_map = HashMap::new();
        new_map.insert(
            "reloaded.com".to_string(),
            DomainTlsConfig {
                cert_path: PathBuf::from("/certs/reloaded.com.pem"),
                key_path: PathBuf::from("/certs/reloaded.com.key"),
            },
        );
        shared.store(Arc::new(new_map));

        // resolver.domain_configs is the same ArcSwap — load sees the new map
        assert!(resolver
            .domain_configs
            .load()
            .contains_key("reloaded.com"));
    }

    #[test]
    fn wildcard_fallback_in_resolver() {
        let dir = tempfile::tempdir().expect("tempdir");

        // Create a wildcard cert
        let (cert_pem, key_pem) = crate::test_util::generate_self_signed("*.example.com");
        std::fs::write(dir.path().join("*.example.com.pem"), &cert_pem).expect("write cert");
        std::fs::write(dir.path().join("*.example.com.key"), &key_pem).expect("write key");

        let store = Arc::new(CertStore::new(dir.path(), 100));
        let resolver = SniResolver::new(store);

        // api.example.com should fall back to *.example.com
        let cert = resolver.resolve_cert("api.example.com");
        assert!(cert.is_some(), "wildcard cert should match subdomain");
    }

    #[test]
    fn no_cert_returns_none() {
        let store = Arc::new(CertStore::new("/tmp/nonexistent_cert_dir", 100));
        let resolver = SniResolver::new(store);
        assert!(resolver.resolve_cert("unknown.com").is_none());
    }

    #[test]
    fn rejects_path_traversal_sni() {
        assert!(!is_valid_sni_hostname("../../etc/shadow"));
        assert!(!is_valid_sni_hostname("../../../etc/passwd"));
        assert!(!is_valid_sni_hostname(""));
        assert!(!is_valid_sni_hostname(&"a".repeat(254)));
        assert!(is_valid_sni_hostname("example.com"));
        assert!(is_valid_sni_hostname("*.example.com"));
        assert!(is_valid_sni_hostname("sub.domain.example.com"));
    }
}
