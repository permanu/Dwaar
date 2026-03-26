// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Certificate store with LRU caching.
//!
//! Loads cert+key PEM files from disk on demand and caches parsed
//! `X509`/`PKey` pairs in a bounded LRU cache. Thread-safe via Mutex.

use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use lru::LruCache;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use tracing::{debug, warn};

/// A cached cert+key pair, ready to inject into an SSL context.
///
/// `Debug` is not derived because `X509` and `PKey` don't implement it.
#[derive(Clone)]
#[allow(missing_debug_implementations)]
pub struct CachedCert {
    pub cert: X509,
    pub key: PKey<Private>,
}

/// Certificate store that loads from filesystem and caches in LRU.
///
/// Thread-safe — multiple TLS handshakes can look up certs concurrently.
/// The Mutex serializes cache access, but TLS handshakes are infrequent
/// enough (~1000/sec max) that this is never a bottleneck.
pub struct CertStore {
    /// Base directory for cert files (e.g. `/etc/dwaar/certs/`)
    cert_dir: PathBuf,
    /// LRU cache: domain → parsed cert+key. Bounded to prevent memory growth.
    cache: Mutex<LruCache<String, CachedCert>>,
}

impl std::fmt::Debug for CertStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertStore")
            .field("cert_dir", &self.cert_dir)
            .finish_non_exhaustive()
    }
}

impl CertStore {
    fn lock_cache(&self) -> std::sync::MutexGuard<'_, LruCache<String, CachedCert>> {
        self.cache.lock().unwrap_or_else(|poisoned| {
            warn!("cert cache mutex was poisoned — recovering");
            poisoned.into_inner()
        })
    }

    /// Create a new cert store loading from `cert_dir` with the given cache capacity.
    pub fn new(cert_dir: impl Into<PathBuf>, capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(1000).expect("nonzero"));
        Self {
            cert_dir: cert_dir.into(),
            cache: Mutex::new(LruCache::new(cap)),
        }
    }

    /// Look up a cert for `domain`. Returns from cache if available,
    /// otherwise loads from disk and caches it.
    pub fn get(&self, domain: &str) -> Option<CachedCert> {
        let mut cache = self.lock_cache();

        // Cache hit — LRU promotes this entry to most-recently-used
        if let Some(cached) = cache.get(domain) {
            debug!(domain, "cert cache hit");
            return Some(cached.clone());
        }
        // Drop the lock before doing disk I/O
        drop(cache);

        // Cache miss — try loading from filesystem
        let cert = self.load_from_disk(domain)?;

        // Re-acquire lock and insert
        let mut cache = self.lock_cache();
        cache.put(domain.to_string(), cert.clone());
        Some(cert)
    }

    /// Load a cert from explicit file paths (for `tls /cert.pem /key.pem` directives).
    /// Caches under the given domain name.
    pub fn get_or_load(
        &self,
        domain: &str,
        cert_path: &Path,
        key_path: &Path,
    ) -> Option<CachedCert> {
        let mut cache = self.lock_cache();

        if let Some(cached) = cache.get(domain) {
            return Some(cached.clone());
        }
        drop(cache);

        let cert = load_pem_pair(cert_path, key_path)?;

        let mut cache = self.lock_cache();
        cache.put(domain.to_string(), cert.clone());
        Some(cert)
    }

    /// Try loading cert/key from the default filesystem layout:
    /// `{cert_dir}/{domain}.pem` and `{cert_dir}/{domain}.key`
    fn load_from_disk(&self, domain: &str) -> Option<CachedCert> {
        let cert_path = self.cert_dir.join(format!("{domain}.pem"));
        let key_path = self.cert_dir.join(format!("{domain}.key"));
        load_pem_pair(&cert_path, &key_path)
    }

    /// Number of cached entries (for diagnostics).
    pub fn cached_count(&self) -> usize {
        self.lock_cache().len()
    }

    /// Evict a domain from the cache so the next `get()` reloads from disk.
    ///
    /// Used by the ACME service after writing a freshly issued cert.
    /// No-op if the domain isn't cached.
    pub fn invalidate(&self, domain: &str) {
        let mut cache = self.lock_cache();
        if cache.pop(domain).is_some() {
            debug!(domain, "cert cache invalidated");
        }
    }
}

/// Read PEM files from disk and parse into `X509` + `PKey`.
fn load_pem_pair(cert_path: &Path, key_path: &Path) -> Option<CachedCert> {
    let cert_pem = match std::fs::read(cert_path) {
        Ok(data) => data,
        Err(e) => {
            warn!(path = %cert_path.display(), error = %e, "failed to read cert file");
            return None;
        }
    };

    let key_pem = match std::fs::read(key_path) {
        Ok(data) => data,
        Err(e) => {
            warn!(path = %key_path.display(), error = %e, "failed to read key file");
            return None;
        }
    };

    let cert = match X509::from_pem(&cert_pem) {
        Ok(c) => c,
        Err(e) => {
            warn!(path = %cert_path.display(), error = %e, "invalid cert PEM");
            return None;
        }
    };

    let key = match PKey::private_key_from_pem(&key_pem) {
        Ok(k) => k,
        Err(e) => {
            warn!(path = %key_path.display(), error = %e, "invalid key PEM");
            return None;
        }
    };

    // Verify the private key matches the certificate's public key
    match cert.public_key() {
        Ok(cert_pubkey) => {
            if !cert_pubkey.public_eq(&key) {
                warn!(
                    cert = %cert_path.display(),
                    key = %key_path.display(),
                    "cert/key mismatch — the private key does not match the certificate"
                );
                return None;
            }
        }
        Err(e) => {
            warn!(cert = %cert_path.display(), error = %e, "failed to extract public key from cert");
            return None;
        }
    }

    // Warn if cert is expired or expiring soon (still load it — the log helps operators diagnose)
    if let Ok(now) = openssl::asn1::Asn1Time::days_from_now(0) {
        if cert.not_after() < now {
            warn!(cert = %cert_path.display(), "certificate is expired");
        } else if let Ok(soon) = openssl::asn1::Asn1Time::days_from_now(30)
            && cert.not_after() < soon
        {
            warn!(cert = %cert_path.display(), "certificate expires within 30 days");
        }
    }

    debug!(cert = %cert_path.display(), "loaded cert from disk");
    Some(CachedCert { cert, key })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::generate_self_signed;

    #[test]
    fn load_and_cache_from_disk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (cert_pem, key_pem) = generate_self_signed("test.example.com");

        std::fs::write(dir.path().join("test.example.com.pem"), &cert_pem).expect("write cert");
        std::fs::write(dir.path().join("test.example.com.key"), &key_pem).expect("write key");

        let store = CertStore::new(dir.path(), 100);

        // First call: cache miss → loads from disk
        assert_eq!(store.cached_count(), 0);
        let cert = store.get("test.example.com").expect("should load");
        assert_eq!(store.cached_count(), 1);

        // Second call: cache hit
        let cert2 = store.get("test.example.com").expect("should be cached");
        assert_eq!(store.cached_count(), 1);

        // Verify it's a valid cert
        assert!(cert.cert.to_pem().is_ok());
        assert!(cert2.cert.to_pem().is_ok());
    }

    #[test]
    fn missing_cert_returns_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = CertStore::new(dir.path(), 100);
        assert!(store.get("nonexistent.com").is_none());
    }

    #[test]
    fn explicit_path_loading() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (cert_pem, key_pem) = generate_self_signed("custom.example.com");

        let cert_path = dir.path().join("my-cert.pem");
        let key_path = dir.path().join("my-key.pem");
        std::fs::write(&cert_path, &cert_pem).expect("write cert");
        std::fs::write(&key_path, &key_pem).expect("write key");

        let store = CertStore::new(dir.path(), 100);
        let cert = store
            .get_or_load("custom.example.com", &cert_path, &key_path)
            .expect("should load from explicit paths");

        assert!(cert.cert.to_pem().is_ok());
        assert_eq!(store.cached_count(), 1);
    }

    #[test]
    fn invalidate_evicts_cached_cert() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (cert_pem, key_pem) = generate_self_signed("evict.example.com");

        std::fs::write(dir.path().join("evict.example.com.pem"), &cert_pem).expect("write cert");
        std::fs::write(dir.path().join("evict.example.com.key"), &key_pem).expect("write key");

        let store = CertStore::new(dir.path(), 100);

        // Load into cache
        store.get("evict.example.com").expect("should load");
        assert_eq!(store.cached_count(), 1);

        // Invalidate removes from cache
        store.invalidate("evict.example.com");
        assert_eq!(store.cached_count(), 0);

        // Next get() reloads from disk
        store.get("evict.example.com").expect("should reload from disk");
        assert_eq!(store.cached_count(), 1);
    }

    #[test]
    fn invalidate_nonexistent_domain_is_noop() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = CertStore::new(dir.path(), 100);
        store.invalidate("ghost.example.com"); // should not panic
        assert_eq!(store.cached_count(), 0);
    }

    #[test]
    fn lru_eviction_works() {
        let dir = tempfile::tempdir().expect("tempdir");

        // Create 3 certs but cache only holds 2
        for i in 0..3 {
            let domain = format!("site{i}.example.com");
            let (cert_pem, key_pem) = generate_self_signed(&domain);
            std::fs::write(dir.path().join(format!("{domain}.pem")), &cert_pem)
                .expect("write cert");
            std::fs::write(dir.path().join(format!("{domain}.key")), &key_pem).expect("write key");
        }

        let store = CertStore::new(dir.path(), 2);

        store.get("site0.example.com").expect("load 0");
        store.get("site1.example.com").expect("load 1");
        assert_eq!(store.cached_count(), 2);

        // Loading a 3rd evicts the LRU (site0)
        store.get("site2.example.com").expect("load 2");
        assert_eq!(store.cached_count(), 2);
    }
}
