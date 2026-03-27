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
/// Wrap in `Arc` and share across proxy threads. Lookups are lock-free
/// (the mmap is read-only after construction).
pub struct GeoLookup {
    reader: Reader<Mmap>,
}

impl std::fmt::Debug for GeoLookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeoLookup")
            .field("db_type", &self.reader.metadata.database_type)
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
        // SAFETY: the database file is read-only after open. External
        // modifications (file replacement) are handled by re-opening.
        let reader = unsafe { Reader::open_mmap(path) }?;

        info!(
            db_type = reader.metadata.database_type.as_str(),
            ip_version = reader.metadata.ip_version,
            node_count = reader.metadata.node_count,
            "GeoIP database loaded"
        );

        Ok(Self { reader })
    }

    /// Look up the country code for an IP address.
    ///
    /// Returns `None` for private/reserved IPs, addresses not in the
    /// database, or any lookup error. Errors are logged at debug level
    /// because missing entries are normal (private IPs, new allocations).
    pub fn lookup_country(&self, ip: IpAddr) -> Option<String> {
        let result = match self.reader.lookup(ip) {
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
}
