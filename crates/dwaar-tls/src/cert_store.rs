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
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use lru::LruCache;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use tracing::{debug, warn};
use zeroize::Zeroize;

use crate::sni::is_valid_sni_hostname;

/// Maximum age a cached OCSP response is allowed to have before we stop
/// stapling it. Matches typical OCSP lifetimes (~7 days for most CAs).
///
/// A stale response is still cryptographically valid but no longer fresh:
/// rather than advertising an obsolete status to clients, we withhold the
/// staple and let the client fetch its own (or skip OCSP entirely). The
/// handshake still succeeds — stapling is a latency optimization, not a
/// security requirement.
pub const MAX_OCSP_AGE: Duration = Duration::from_secs(7 * 24 * 3600);

/// Errors returned by [`CertStore`] lookups.
#[derive(Debug, thiserror::Error)]
pub enum CertStoreError {
    /// Domain name failed SNI / DNS validation — path traversal or malformed input.
    #[error("invalid hostname: {0}")]
    InvalidHostname(String),
}

/// A cached cert+key pair, ready to inject into an SSL context.
///
/// `Debug` is not derived because `X509` and `PKey` don't implement it.
///
/// The OCSP response buffer is zeroized on drop as defense-in-depth. OpenSSL's
/// own cleanup frees the `EVP_PKEY` internals when `PKey` drops (scrubbing the
/// private key via `OPENSSL_cleanse` on modern builds). We cannot reach into
/// the raw key bytes from Rust without re-serializing them — which would
/// defeat the purpose — so we rely on OpenSSL for the key itself and
/// explicitly wipe any auxiliary buffers we hold here.
#[derive(Clone)]
#[allow(missing_debug_implementations)]
pub struct CachedCert {
    pub cert: X509,
    pub key: PKey<Private>,
    pub issuer: Option<X509>,
    pub ocsp_response: Option<Vec<u8>>,
    /// When the OCSP response was last refreshed. `None` means never refreshed
    /// (e.g. freshly loaded from disk with no prior staple). Used by the TLS
    /// stapling path to suppress responses older than [`MAX_OCSP_AGE`].
    pub ocsp_last_refresh: Option<Instant>,
}

impl CachedCert {
    /// True if the cached OCSP response is present and was refreshed within
    /// [`MAX_OCSP_AGE`]. A response loaded from disk (with no `ocsp_last_refresh`)
    /// is considered stale — we only staple what we have proactively refreshed.
    pub fn is_ocsp_fresh(&self) -> bool {
        match (self.ocsp_response.as_ref(), self.ocsp_last_refresh) {
            (Some(_), Some(ts)) => Instant::now().duration_since(ts) < MAX_OCSP_AGE,
            _ => false,
        }
    }
}

impl Drop for CachedCert {
    fn drop(&mut self) {
        // Zero any cached key-derived buffers we retain. OpenSSL's `PKey<Private>`
        // drop already scrubs the `EVP_PKEY` internals; the OCSP response is not
        // key material but it can be tied to a certificate serial, and it's
        // cheap to wipe so we do it as defense-in-depth against heap scraping.
        if let Some(ref mut resp) = self.ocsp_response {
            resp.zeroize();
        }
    }
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
    fn lock_cache(&self) -> parking_lot::MutexGuard<'_, LruCache<String, CachedCert>> {
        // parking_lot::Mutex cannot be poisoned — lock() always succeeds.
        self.cache.lock()
    }

    /// Base directory where cert files are stored.
    pub fn cert_dir(&self) -> &Path {
        &self.cert_dir
    }

    /// Create a new cert store loading from `cert_dir` with the given cache capacity.
    pub fn new(cert_dir: impl Into<PathBuf>, capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(1000).expect("nonzero"));
        Self {
            cert_dir: cert_dir.into(),
            cache: Mutex::new(LruCache::new(cap)),
        }
    }

    /// Cache-only lookup. Returns the cached entry if present, `None` otherwise.
    /// Does not touch the filesystem. Safe to call from any thread, sync or async.
    fn lookup_cached(&self, domain: &str) -> Option<CachedCert> {
        let mut cache = self.lock_cache();
        cache.get(domain).cloned()
    }

    /// Look up a cert for `domain`. Returns from cache if available,
    /// otherwise loads from disk **synchronously** and caches it.
    ///
    /// The synchronous variant is retained for non-hot-path callers (ACME
    /// background tasks, tests). The TLS handshake hot path must use
    /// [`CertStore::get_async`] so the blocking disk read runs on the blocking
    /// pool rather than stalling a tokio runtime thread (H-06).
    ///
    /// Returns `None` if the hostname is invalid (M-10) or the files are
    /// missing. Invalid hostnames are logged at `warn!` so operators see
    /// misuse at the call site.
    pub fn get(&self, domain: &str) -> Option<CachedCert> {
        if !is_valid_sni_hostname(domain) {
            warn!(domain, "CertStore::get refused invalid hostname");
            return None;
        }

        if let Some(cached) = self.lookup_cached(domain) {
            debug!(domain, "cert cache hit");
            return Some(cached);
        }

        // Cache miss — try loading from filesystem (sync I/O).
        let cert = self.load_from_disk(domain)?;

        let mut cache = self.lock_cache();
        cache.put(domain.to_string(), cert.clone());
        Some(cert)
    }

    /// Async variant of [`Self::get`] for the TLS hot path.
    ///
    /// On a cache hit this is lock-free and identical to `get`. On a miss the
    /// blocking PEM read is dispatched via `tokio::task::spawn_blocking` so
    /// the tokio runtime worker is not stalled during a TLS handshake (H-06).
    pub async fn get_async(&self, domain: &str) -> Option<CachedCert> {
        if !is_valid_sni_hostname(domain) {
            warn!(domain, "CertStore::get_async refused invalid hostname");
            return None;
        }

        if let Some(cached) = self.lookup_cached(domain) {
            debug!(domain, "cert cache hit");
            return Some(cached);
        }

        let cert_path = self.cert_dir.join(format!("{domain}.pem"));
        let key_path = self.cert_dir.join(format!("{domain}.key"));
        let cert = load_pem_pair_blocking(cert_path, key_path).await?;

        let mut cache = self.lock_cache();
        cache.put(domain.to_string(), cert.clone());
        Some(cert)
    }

    /// Load a cert from explicit file paths (for `tls /cert.pem /key.pem` directives).
    /// Caches under the given domain name. Synchronous — do not call from the
    /// TLS handshake hot path; use [`Self::get_or_load_async`] instead.
    pub fn get_or_load(
        &self,
        domain: &str,
        cert_path: &Path,
        key_path: &Path,
    ) -> Option<CachedCert> {
        if !is_valid_sni_hostname(domain) {
            warn!(domain, "CertStore::get_or_load refused invalid hostname");
            return None;
        }

        if let Some(cached) = self.lookup_cached(domain) {
            return Some(cached);
        }

        let cert = load_pem_pair(cert_path, key_path)?;

        let mut cache = self.lock_cache();
        cache.put(domain.to_string(), cert.clone());
        Some(cert)
    }

    /// Async variant of [`Self::get_or_load`] that dispatches the blocking PEM
    /// reads onto the tokio blocking pool (H-06).
    pub async fn get_or_load_async(
        &self,
        domain: &str,
        cert_path: PathBuf,
        key_path: PathBuf,
    ) -> Option<CachedCert> {
        if !is_valid_sni_hostname(domain) {
            warn!(
                domain,
                "CertStore::get_or_load_async refused invalid hostname"
            );
            return None;
        }

        if let Some(cached) = self.lookup_cached(domain) {
            return Some(cached);
        }

        let cert = load_pem_pair_blocking(cert_path, key_path).await?;

        let mut cache = self.lock_cache();
        cache.put(domain.to_string(), cert.clone());
        Some(cert)
    }

    /// Try loading cert/key from the default filesystem layout:
    /// `{cert_dir}/{domain}.pem` and `{cert_dir}/{domain}.key`.
    ///
    /// Callers must validate `domain` before invoking — this helper assumes
    /// the input has already been screened by [`is_valid_sni_hostname`].
    fn load_from_disk(&self, domain: &str) -> Option<CachedCert> {
        debug_assert!(
            is_valid_sni_hostname(domain),
            "load_from_disk called with invalid domain: {domain}"
        );
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

    /// Update the cached OCSP response for a domain.
    ///
    /// Uses `peek_mut()` to avoid promoting the entry in the LRU —
    /// OCSP refresh is a background operation and shouldn't affect
    /// eviction order (which should reflect actual handshake traffic).
    /// No-op if the domain isn't cached. Also stamps `ocsp_last_refresh`
    /// with the current [`Instant`] so the stapling path can reject
    /// responses older than [`MAX_OCSP_AGE`] (M-11).
    pub fn update_ocsp(&self, domain: &str, response: Vec<u8>) {
        let mut cache = self.lock_cache();
        if let Some(entry) = cache.peek_mut(domain) {
            entry.ocsp_response = Some(response);
            entry.ocsp_last_refresh = Some(Instant::now());
            debug!(domain, "OCSP response updated in cache");
        }
    }
}

/// `spawn_blocking` wrapper around [`load_pem_pair`] for use from async contexts.
///
/// The TLS handshake callback runs on a tokio worker thread. Reading a PEM
/// file inline there would stall the runtime under high handshake rates. This
/// helper moves the read onto the blocking pool where stalls are expected.
async fn load_pem_pair_blocking(cert_path: PathBuf, key_path: PathBuf) -> Option<CachedCert> {
    tokio::task::spawn_blocking(move || load_pem_pair(&cert_path, &key_path))
        .await
        .unwrap_or_else(|e| {
            warn!(error = %e, "spawn_blocking for PEM load panicked or was cancelled");
            None
        })
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
            // Log cert path (not key path) — Guardrail #18 forbids exposing
            // private key filesystem locations in logs.
            warn!(cert = %cert_path.display(), error = %e, "failed to read key file");
            return None;
        }
    };

    let certs = match X509::stack_from_pem(&cert_pem) {
        Ok(stack) if !stack.is_empty() => stack,
        Ok(_) => {
            warn!(path = %cert_path.display(), "cert PEM file contains no certificates");
            return None;
        }
        Err(e) => {
            warn!(path = %cert_path.display(), error = %e, "invalid cert PEM");
            return None;
        }
    };

    let cert = certs[0].clone();
    let issuer = if certs.len() > 1 {
        Some(certs[1].clone())
    } else {
        None
    };

    let key = match PKey::private_key_from_pem(&key_pem) {
        Ok(k) => k,
        Err(e) => {
            warn!(cert = %cert_path.display(), error = %e, "invalid key PEM");
            return None;
        }
    };

    // Verify the private key matches the certificate's public key
    match cert.public_key() {
        Ok(cert_pubkey) => {
            if !cert_pubkey.public_eq(&key) {
                warn!(
                    cert = %cert_path.display(),
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
    Some(CachedCert {
        cert,
        key,
        issuer,
        ocsp_response: None,
        ocsp_last_refresh: None,
    })
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
        store
            .get("evict.example.com")
            .expect("should reload from disk");
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
    fn load_pem_pair_parses_chain_with_issuer() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (cert_pem, key_pem, ca_pem) = crate::test_util::generate_ca_signed("chain.example.com");

        // Write chain: leaf + issuer concatenated
        let mut chain = cert_pem;
        chain.extend_from_slice(&ca_pem);
        std::fs::write(dir.path().join("chain.example.com.pem"), &chain).expect("write chain");
        std::fs::write(dir.path().join("chain.example.com.key"), &key_pem).expect("write key");

        let store = CertStore::new(dir.path(), 100);
        let cached = store.get("chain.example.com").expect("should load chain");

        assert!(
            cached.issuer.is_some(),
            "issuer should be parsed from chain"
        );
        assert!(cached.ocsp_response.is_none(), "no OCSP response yet");
    }

    #[test]
    fn load_pem_pair_single_cert_has_no_issuer() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (cert_pem, key_pem) = generate_self_signed("single.example.com");

        std::fs::write(dir.path().join("single.example.com.pem"), &cert_pem).expect("write cert");
        std::fs::write(dir.path().join("single.example.com.key"), &key_pem).expect("write key");

        let store = CertStore::new(dir.path(), 100);
        let cached = store.get("single.example.com").expect("should load");

        assert!(
            cached.issuer.is_none(),
            "self-signed has no issuer in chain"
        );
    }

    #[test]
    fn update_ocsp_sets_response_for_cached_domain() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (cert_pem, key_pem) = generate_self_signed("ocsp.example.com");

        std::fs::write(dir.path().join("ocsp.example.com.pem"), &cert_pem).expect("write cert");
        std::fs::write(dir.path().join("ocsp.example.com.key"), &key_pem).expect("write key");

        let store = CertStore::new(dir.path(), 100);
        store.get("ocsp.example.com").expect("load");

        let fake_ocsp = vec![0x30, 0x03, 0x0A, 0x01, 0x00];
        store.update_ocsp("ocsp.example.com", fake_ocsp.clone());

        let cached = store.get("ocsp.example.com").expect("should be cached");
        assert_eq!(cached.ocsp_response.as_deref(), Some(fake_ocsp.as_slice()));
    }

    #[test]
    fn update_ocsp_noop_for_uncached_domain() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = CertStore::new(dir.path(), 100);
        store.update_ocsp("ghost.example.com", vec![1, 2, 3]);
        assert_eq!(store.cached_count(), 0);
    }

    #[test]
    fn update_ocsp_does_not_promote_in_lru() {
        let dir = tempfile::tempdir().expect("tempdir");

        for i in 0..3 {
            let domain = format!("lru{i}.example.com");
            let (cert_pem, key_pem) = generate_self_signed(&domain);
            std::fs::write(dir.path().join(format!("{domain}.pem")), &cert_pem).expect("write");
            std::fs::write(dir.path().join(format!("{domain}.key")), &key_pem).expect("write");
        }

        let store = CertStore::new(dir.path(), 3);
        store.get("lru0.example.com").expect("load 0");
        store.get("lru1.example.com").expect("load 1");
        store.get("lru2.example.com").expect("load 2");

        // Update OCSP for lru0 — should NOT promote it
        store.update_ocsp("lru0.example.com", vec![1]);

        // Load a 4th — should evict lru0 (still oldest)
        let (cert4, key4) = generate_self_signed("lru3.example.com");
        std::fs::write(dir.path().join("lru3.example.com.pem"), &cert4).expect("write");
        std::fs::write(dir.path().join("lru3.example.com.key"), &key4).expect("write");
        store.get("lru3.example.com").expect("load 3");

        assert_eq!(store.cached_count(), 3);
        assert!(store.get("lru1.example.com").is_some(), "lru1 still cached");
        assert!(store.get("lru2.example.com").is_some(), "lru2 still cached");
    }

    #[test]
    fn get_rejects_invalid_hostnames() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = CertStore::new(dir.path(), 100);
        assert!(store.get("../etc/passwd").is_none());
        assert!(store.get("/etc/passwd").is_none());
        assert!(store.get("").is_none());
        assert!(store.get("..").is_none());
        assert!(store.get("host..with..dots").is_none());
        assert_eq!(store.cached_count(), 0, "no invalid entry should be cached");
    }

    #[test]
    fn get_does_not_touch_filesystem_on_cache_hit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (cert_pem, key_pem) = generate_self_signed("cached.example.com");
        let cert_file = dir.path().join("cached.example.com.pem");
        let key_file = dir.path().join("cached.example.com.key");
        std::fs::write(&cert_file, &cert_pem).expect("write cert");
        std::fs::write(&key_file, &key_pem).expect("write key");
        let store = CertStore::new(dir.path(), 100);
        store.get("cached.example.com").expect("initial load");
        std::fs::remove_file(&cert_file).expect("rm cert");
        std::fs::remove_file(&key_file).expect("rm key");
        let hit = store
            .get("cached.example.com")
            .expect("cache hit should still succeed");
        assert!(hit.cert.to_pem().is_ok());
    }

    #[tokio::test]
    async fn get_async_cache_hit_avoids_blocking_pool() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (cert_pem, key_pem) = generate_self_signed("async.example.com");
        let cert_file = dir.path().join("async.example.com.pem");
        let key_file = dir.path().join("async.example.com.key");
        std::fs::write(&cert_file, &cert_pem).expect("write cert");
        std::fs::write(&key_file, &key_pem).expect("write key");
        let store = CertStore::new(dir.path(), 100);
        store.get("async.example.com").expect("prime cache");
        std::fs::remove_file(&cert_file).expect("rm cert");
        std::fs::remove_file(&key_file).expect("rm key");
        let hit = store
            .get_async("async.example.com")
            .await
            .expect("cached lookup should succeed");
        assert!(hit.cert.to_pem().is_ok());
    }

    #[tokio::test]
    async fn get_async_cache_miss_loads_from_disk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (cert_pem, key_pem) = generate_self_signed("async-miss.example.com");
        std::fs::write(dir.path().join("async-miss.example.com.pem"), &cert_pem).expect("cert");
        std::fs::write(dir.path().join("async-miss.example.com.key"), &key_pem).expect("key");
        let store = CertStore::new(dir.path(), 100);
        let cert = store
            .get_async("async-miss.example.com")
            .await
            .expect("should load via blocking pool");
        assert!(cert.cert.to_pem().is_ok());
        assert_eq!(store.cached_count(), 1);
    }

    #[tokio::test]
    async fn get_async_rejects_invalid_hostnames() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = CertStore::new(dir.path(), 100);
        assert!(store.get_async("../etc/passwd").await.is_none());
        assert!(store.get_async("").await.is_none());
    }

    #[test]
    fn update_ocsp_stamps_last_refresh() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (cert_pem, key_pem) = generate_self_signed("fresh.example.com");
        std::fs::write(dir.path().join("fresh.example.com.pem"), &cert_pem).expect("cert");
        std::fs::write(dir.path().join("fresh.example.com.key"), &key_pem).expect("key");
        let store = CertStore::new(dir.path(), 100);
        let cached = store.get("fresh.example.com").expect("load");
        assert!(cached.ocsp_last_refresh.is_none(), "unrefreshed");
        assert!(!cached.is_ocsp_fresh(), "no response → not fresh");
        store.update_ocsp("fresh.example.com", vec![1, 2, 3]);
        let cached = store.get("fresh.example.com").expect("cached");
        assert!(cached.ocsp_last_refresh.is_some(), "timestamp set");
        assert!(cached.is_ocsp_fresh(), "freshly refreshed → fresh");
    }

    #[test]
    fn is_ocsp_fresh_false_for_old_timestamp() {
        let (cert_pem, key_pem) = generate_self_signed("stale.example.com");
        let cert = X509::from_pem(&cert_pem).expect("parse cert");
        let key = PKey::private_key_from_pem(&key_pem).expect("parse key");
        let Some(old_ts) = Instant::now().checked_sub(MAX_OCSP_AGE + Duration::from_secs(1)) else {
            return;
        };
        let cached = CachedCert {
            cert,
            key,
            issuer: None,
            ocsp_response: Some(vec![0xA]),
            ocsp_last_refresh: Some(old_ts),
        };
        assert!(!cached.is_ocsp_fresh(), "older than MAX_OCSP_AGE");
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
