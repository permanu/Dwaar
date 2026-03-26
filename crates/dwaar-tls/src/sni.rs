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

use async_trait::async_trait;
use openssl::ssl::NameType;
use pingora_core::listeners::TlsAccept;
use pingora_core::protocols::tls::TlsRef;
use pingora_core::tls::ext;
use tracing::{debug, warn};

use crate::cert_store::CertStore;

/// Per-domain TLS config from the Dwaarfile `tls` directive.
#[derive(Debug, Clone)]
pub struct DomainTlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

/// SNI-based certificate resolver.
///
/// Holds a reference to the cert store and a map of domain-specific
/// TLS configs (from `tls /cert /key` directives in the Dwaarfile).
/// Falls back to the cert store's default directory layout when no
/// explicit paths are configured.
#[derive(Debug)]
pub struct SniResolver {
    cert_store: Arc<CertStore>,
    /// Explicit cert paths from `tls /cert /key` directives
    domain_configs: HashMap<String, DomainTlsConfig>,
}

impl SniResolver {
    pub fn new(cert_store: Arc<CertStore>) -> Self {
        Self {
            cert_store,
            domain_configs: HashMap::new(),
        }
    }

    /// Register an explicit cert/key path for a domain.
    pub fn add_domain(&mut self, domain: &str, config: DomainTlsConfig) {
        self.domain_configs.insert(domain.to_lowercase(), config);
    }

    /// Resolve cert for a domain — tries explicit config first,
    /// then wildcard, then default directory layout.
    fn resolve_cert(&self, sni: &str) -> Option<crate::cert_store::CachedCert> {
        let sni_lower = sni.to_lowercase();

        // Try explicit cert path for this exact domain
        if let Some(config) = self.domain_configs.get(&sni_lower) {
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

            if let Some(config) = self.domain_configs.get(&wildcard) {
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
        let Some(sni_str) = ssl.servername(NameType::HOST_NAME) else {
            warn!("TLS handshake without SNI — no cert to select");
            return;
        };
        let sni = sni_str.to_string();

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

        // Domain config is registered (cert loading will fail since paths don't exist,
        // but the config lookup itself works)
        assert!(resolver.domain_configs.contains_key("example.com"));
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
}
