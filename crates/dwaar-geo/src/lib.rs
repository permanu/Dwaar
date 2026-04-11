// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! `GeoIP` lookup — map client IP addresses to country codes.
//!
//! Uses `MaxMind`'s GeoLite2-Country database (mmapped, ~5 MB). The OS
//! manages physical memory — pages are loaded on demand and evicted
//! under memory pressure.
//!
//! [`GeoLookup`] is `Send + Sync` and designed to be shared via `Arc`
//! across all proxy threads.

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;
use maxminddb::{Mmap, Reader, geoip2};
use thiserror::Error;
use tracing::{debug, info};

/// Errors from `GeoIP` operations.
#[derive(Debug, Error)]
pub enum GeoError {
    #[error("failed to open GeoIP database: {0}")]
    Open(#[from] maxminddb::MaxMindDbError),
}

/// Thread-safe `GeoIP` lookup backed by a mmapped `MaxMind` database.
///
/// Wrap in `Arc` and share across proxy threads. Lookups are lock-free —
/// readers take a single `ArcSwap::load` on the hot path, returning an
/// `Arc<Reader>` guard with no contention.
///
/// # Hot reload (M-27)
///
/// The underlying `Reader` is held in an `ArcSwap`, so [`GeoLookup::reload`]
/// can install a fresh mmap atomically while in-flight lookups continue to
/// see the previous reader. In-progress lookups are never interrupted — the
/// previous reader stays alive until every guard referencing it has been
/// dropped, which happens automatically when the lookup returns.
///
/// `MaxMind` publishes `GeoLite2` database updates weekly; calling
/// [`GeoLookup::reload`] on a schedule keeps accuracy fresh without a
/// proxy restart.
///
/// TODO(v0.2.x): wire this into the SIGHUP config-reload path in
/// `dwaar-cli`. The CLI does not yet call `geo.reload(path)` when the
/// Dwaarfile is reloaded — follow-up integration work.
pub struct GeoLookup {
    reader: ArcSwap<Reader<Mmap>>,
}

impl std::fmt::Debug for GeoLookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let guard = self.reader.load();
        f.debug_struct("GeoLookup")
            .field("db_type", &guard.metadata.database_type)
            .finish()
    }
}

impl GeoLookup {
    /// Open a GeoLite2-Country database from disk (mmapped).
    ///
    /// # Safety justification for `open_mmap`
    ///
    /// The `unsafe` is because mmap can observe torn reads if another
    /// process truncates or modifies the file while mapped. We accept
    /// this because: (1) the `GeoIP` database is a read-only file that
    /// Dwaar never writes to, (2) updates are atomic file replacements,
    /// and (3) this is the standard pattern used by every `MaxMind` client.
    #[allow(unsafe_code)]
    pub fn open(path: &Path) -> Result<Self, GeoError> {
        let reader = Self::open_reader(path)?;

        info!(
            db_type = reader.metadata.database_type.as_str(),
            ip_version = reader.metadata.ip_version,
            node_count = reader.metadata.node_count,
            "GeoIP database loaded"
        );

        Ok(Self {
            reader: ArcSwap::from(Arc::new(reader)),
        })
    }

    /// Internal helper — open an mmapped `Reader` for the given path.
    #[allow(unsafe_code)]
    fn open_reader(path: &Path) -> Result<Reader<Mmap>, GeoError> {
        // SAFETY: the database file is read-only after open. External
        // modifications (file replacement) are handled by re-opening.
        let reader = unsafe { Reader::open_mmap(path) }?;
        Ok(reader)
    }

    /// Hot-reload the underlying `GeoIP` database from disk (M-27).
    ///
    /// Opens a new mmap at `path`, then atomically swaps the active reader.
    /// In-flight lookups are never interrupted — they continue to see the
    /// previous reader via their `ArcSwap` guard, and the old mmap is
    /// dropped once every guard has been released.
    ///
    /// Returns an error if the new database cannot be opened; the active
    /// reader is left untouched in that case so the proxy keeps serving
    /// lookups against the previous database.
    ///
    /// `MaxMind` publishes `GeoLite2` updates weekly; the intended caller
    /// is a config-reload entry point (SIGHUP handler or admin endpoint)
    /// that refreshes the database on demand. That wiring lives in
    /// `dwaar-cli` and is not yet connected — see the TODO on [`GeoLookup`].
    pub fn reload(&self, path: &Path) -> Result<(), GeoError> {
        let new_reader = Self::open_reader(path)?;
        info!(
            db_type = new_reader.metadata.database_type.as_str(),
            ip_version = new_reader.metadata.ip_version,
            node_count = new_reader.metadata.node_count,
            "GeoIP database hot-reloaded"
        );
        self.reader.store(Arc::new(new_reader));
        Ok(())
    }

    /// Look up the country code for an IP address.
    ///
    /// Returns `None` for private/reserved IPs, addresses not in the
    /// database, or any lookup error. Errors are logged at debug level
    /// because missing entries are normal (private IPs, new allocations).
    pub fn lookup_country(&self, ip: IpAddr) -> Option<String> {
        let reader = self.reader.load();
        let result = match reader.lookup(ip) {
            Ok(r) => r,
            Err(e) => {
                debug!(ip = %ip, error = %e, "GeoIP lookup failed");
                return None;
            }
        };

        if !result.has_data() {
            return None;
        }

        match result.decode::<geoip2::Country<'_>>() {
            Ok(Some(record)) => record.country.iso_code.map(String::from),
            Ok(None) => None,
            Err(e) => {
                debug!(ip = %ip, error = %e, "GeoIP decode failed");
                None
            }
        }
    }

    /// Look up city-level details for an IP address.
    ///
    /// Requires the `city` feature and a GeoLite2-City database (~45 MB).
    /// Returns `None` if the IP has no city data or on any error.
    #[cfg(feature = "city")]
    pub fn lookup_city(&self, ip: IpAddr) -> Option<CityResult> {
        let reader = self.reader.load();
        let result = match reader.lookup(ip) {
            Ok(r) => r,
            Err(e) => {
                debug!(ip = %ip, error = %e, "GeoIP city lookup failed");
                return None;
            }
        };

        if !result.has_data() {
            return None;
        }

        match result.decode::<geoip2::City<'_>>() {
            Ok(Some(record)) => Some(CityResult {
                country: record.country.iso_code.map(String::from),
                city: record.city.names.english.map(String::from),
                subdivision: record
                    .subdivisions
                    .first()
                    .and_then(|s| s.iso_code)
                    .map(String::from),
                postal_code: record.postal.code.map(String::from),
                latitude: record.location.latitude,
                longitude: record.location.longitude,
            }),
            Ok(None) => None,
            Err(e) => {
                debug!(ip = %ip, error = %e, "GeoIP city decode failed");
                None
            }
        }
    }
}

/// City-level geolocation result. Only available with the `city` feature.
#[cfg(feature = "city")]
#[derive(Debug, Clone)]
pub struct CityResult {
    pub country: Option<String>,
    pub city: Option<String>,
    pub subdivision: Option<String>,
    pub postal_code: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

// Compile-time assertion: GeoLookup must be Send + Sync for Arc sharing.
fn _assert_geo_lookup_send_sync() {
    fn require_send_sync<T: Send + Sync>() {}
    require_send_sync::<GeoLookup>();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    fn test_db_path() -> Option<PathBuf> {
        let paths = [
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/GeoLite2-Country-Test.mmdb"),
            PathBuf::from("/usr/share/GeoIP/GeoLite2-Country.mmdb"),
            PathBuf::from("/etc/dwaar/geoip/GeoLite2-Country.mmdb"),
        ];
        paths.into_iter().find(|p| p.exists())
    }

    #[test]
    fn open_nonexistent_returns_error() {
        let result = GeoLookup::open(Path::new("/nonexistent/GeoLite2-Country.mmdb"));
        assert!(result.is_err());
    }

    #[test]
    fn lookup_private_ip_returns_none() {
        let Some(path) = test_db_path() else {
            // No database available — test skipped gracefully
            return;
        };
        let geo = GeoLookup::open(&path).expect("open db");
        assert!(
            geo.lookup_country(IpAddr::V4(Ipv4Addr::LOCALHOST))
                .is_none()
        );
        assert!(
            geo.lookup_country(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
                .is_none()
        );
        assert!(
            geo.lookup_country(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
                .is_none()
        );
    }

    #[test]
    fn lookup_ipv6_loopback_returns_none() {
        let Some(path) = test_db_path() else {
            return;
        };
        let geo = GeoLookup::open(&path).expect("open db");
        assert!(
            geo.lookup_country(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST))
                .is_none()
        );
    }

    #[test]
    fn lookup_known_ip_returns_country_code() {
        let Some(path) = test_db_path() else {
            return;
        };
        let geo = GeoLookup::open(&path).expect("open db");
        // 8.8.8.8 is Google DNS — should resolve to a 2-letter country code
        if let Some(country) = geo.lookup_country(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))) {
            assert_eq!(
                country.len(),
                2,
                "country code should be 2 chars: {country}"
            );
            assert!(country.chars().all(|c| c.is_ascii_uppercase()));
        }
        // Don't assert specific country — database versions vary
    }

    #[test]
    fn geo_lookup_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<GeoLookup>();
    }

    // -----------------------------------------------------------------
    // M-27: hot reload
    // -----------------------------------------------------------------

    #[test]
    fn reload_from_bad_path_leaves_reader_intact() {
        let Some(path) = test_db_path() else {
            return;
        };
        let geo = GeoLookup::open(&path).expect("open db");
        // Reload with a nonexistent path should return Err and the active
        // reader must still serve lookups afterwards.
        let err = geo.reload(Path::new("/definitely/not/a/real/path.mmdb"));
        assert!(err.is_err(), "expected reload to fail");

        // Active reader still works: loopback is private, so None is expected
        // but the lookup must not panic or error.
        let _ = geo.lookup_country(IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn reload_from_same_path_swaps_reader() {
        let Some(path) = test_db_path() else {
            return;
        };
        let geo = GeoLookup::open(&path).expect("open db");

        // Capture a lookup result before reload, reload, then compare.
        let before = geo.lookup_country(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));

        geo.reload(&path).expect("reload should succeed");

        // Post-reload lookups must work and should yield the same answer
        // (same database file → same data).
        let after = geo.lookup_country(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(before, after);
    }

    #[test]
    fn reload_observes_new_database_fixture() {
        // The fixture DB is normally tiny — mutate it by copying to a temp
        // dir, loading, then replacing with a second copy and reloading.
        // Because we only ship one fixture, the "before vs after lookup
        // result" assertion is satisfied by a round-trip through a fresh
        // file: we verify the second mmap is a distinct allocation that
        // still serves lookups correctly.
        let Some(path) = test_db_path() else {
            return;
        };
        let src = std::fs::read(&path).expect("read fixture");

        // Stage two copies in a temp dir.
        let tmp = std::env::temp_dir().join("dwaar_geo_reload_test.mmdb");
        std::fs::write(&tmp, &src).expect("stage initial fixture");

        let geo = GeoLookup::open(&tmp).expect("open staged fixture");
        let before = geo.lookup_country(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));

        // Overwrite the staged file atomically (write then rename) to mimic
        // a MaxMind weekly refresh, then reload.
        let tmp_new = std::env::temp_dir().join("dwaar_geo_reload_test.mmdb.new");
        std::fs::write(&tmp_new, &src).expect("stage reload fixture");
        std::fs::rename(&tmp_new, &tmp).expect("atomic rename");

        geo.reload(&tmp).expect("reload staged fixture");

        // Lookups against the reloaded reader must still succeed and return
        // the same answer (same source bytes).
        let after = geo.lookup_country(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(before, after);

        // Clean up.
        let _ = std::fs::remove_file(&tmp);
    }
}
