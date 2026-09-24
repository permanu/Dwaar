// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Routes added through the admin API (`POST /routes`, `PUT /routes/snapshot`).
//!
//! They are kept apart from the Dwaarfile's routes so that they survive a
//! config reload (merged over the compiled Dwaarfile table) and, when a state
//! directory is given, a restart: every change is written to
//! `<state-dir>/admin-routes.json` (0600, atomic rename) before it takes
//! effect, and the file is read back at start. A route with `tls: true` on a
//! DNS hostname is added to the ACME domain list, so the certificate is
//! issued without a Dwaarfile entry; an IP address never is (Permanu's
//! IP-only webhook route is `tls: false`, contracts v1.1.5 D-063 #4).

use std::collections::BTreeMap;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::route::{Route, RouteKind, is_valid_domain, is_valid_route_key};

/// File name of the persisted admin routes inside the state directory.
pub const ADMIN_ROUTES_FILE: &str = "admin-routes.json";

/// Larger files are refused at start (a route entry is well under 1 KiB).
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Format version of [`ADMIN_ROUTES_FILE`].
const FILE_VERSION: u32 = 1;

/// One admin-API route as requested and as persisted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminRouteSpec {
    pub domain: String,
    pub upstream: String,
    pub tls: bool,
    /// Which component owns this route (e.g. `permanu-runner`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// `proxy` (default) or `webhook`.
    #[serde(default)]
    pub kind: RouteKind,
}

impl AdminRouteSpec {
    /// Validate the request and build the route.
    ///
    /// A webhook route needs an exact hostname (no wildcard, path or
    /// `_default`) and a loopback upstream: it exists to reach a local
    /// listener (the Permanu agent on `127.0.0.1:7461`), never to expose
    /// another host.
    pub fn build(&self) -> Result<Route, String> {
        let domain = self.domain.as_str();
        if !is_valid_route_key(domain) {
            return Err(format!("invalid domain: {domain}"));
        }
        let upstream: SocketAddr = self
            .upstream
            .parse()
            .map_err(|e| format!("invalid upstream address: {e}"))?;
        match self.kind {
            RouteKind::Proxy => Ok(Route::with_source(
                domain,
                upstream,
                self.tls,
                None,
                self.source.clone(),
            )),
            RouteKind::Webhook => {
                if !is_valid_domain(domain) || domain.contains('*') {
                    return Err(format!("webhook route needs an exact hostname: {domain}"));
                }
                if !upstream.ip().is_loopback() {
                    return Err(format!(
                        "webhook route upstream must be a loopback address: {upstream}"
                    ));
                }
                Ok(Route::webhook(
                    domain,
                    upstream,
                    self.tls,
                    self.source.clone(),
                ))
            }
        }
    }

    /// True when Dwaar should obtain a certificate for this route by ACME.
    #[must_use]
    pub fn needs_acme(&self) -> bool {
        self.tls && is_acme_hostname(&self.domain)
    }
}

/// Top-level names no public CA issues for (RFC 6761, RFC 6762, RFC 8375).
const SPECIAL_USE_SUFFIXES: &[&str] = &[
    ".localhost",
    ".test",
    ".example",
    ".invalid",
    ".local",
    ".home.arpa",
];

/// A name a public CA can issue for over HTTP-01: a valid hostname with at
/// least two labels, not an IP address, wildcard, path key, `_default`,
/// `localhost` or special-use name, and not ending in an all-digit label.
#[must_use]
pub fn is_acme_hostname(domain: &str) -> bool {
    if !is_valid_domain(domain) || domain.contains('*') || domain.parse::<IpAddr>().is_ok() {
        return false;
    }
    let lower = domain.to_ascii_lowercase();
    if lower == "localhost" || SPECIAL_USE_SUFFIXES.iter().any(|s| lower.ends_with(s)) {
        return false;
    }
    let mut labels = lower.rsplit('.');
    let tld = labels.next().unwrap_or("");
    labels.next().is_some() && !tld.bytes().all(|b| b.is_ascii_digit())
}

/// Why an admin-route change was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdminRouteError {
    /// The request is invalid (HTTP 400).
    #[error("{0}")]
    Invalid(String),
    /// The change could not be written to the state directory (HTTP 500);
    /// nothing changed.
    #[error("cannot persist admin routes: {0}")]
    Persist(String),
}

#[derive(Serialize, Deserialize)]
struct FileBody {
    version: u32,
    routes: Vec<AdminRouteSpec>,
}

/// Where the ACME domain list lives and what wakes the TLS service.
struct AcmeLink {
    target: Arc<ArcSwap<Vec<String>>>,
    notify: Arc<tokio::sync::Notify>,
    /// Domains the Dwaarfile needs; the published list is these plus the
    /// admin routes' ACME hostnames.
    config_domains: Mutex<Vec<String>>,
}

/// The admin-API route overlay (see the module docs).
pub struct AdminRoutes {
    path: Option<PathBuf>,
    /// Keyed by the lowercase domain.
    specs: Mutex<BTreeMap<String, AdminRouteSpec>>,
    acme: Option<AcmeLink>,
}

impl std::fmt::Debug for AdminRoutes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminRoutes")
            .field("path", &self.path)
            .field("routes", &self.specs.lock().len())
            .finish_non_exhaustive()
    }
}

impl Default for AdminRoutes {
    fn default() -> Self {
        Self::in_memory()
    }
}

impl AdminRoutes {
    /// An overlay that is never written to disk.
    #[must_use]
    pub fn in_memory() -> Self {
        Self {
            path: None,
            specs: Mutex::new(BTreeMap::new()),
            acme: None,
        }
    }

    /// Open the overlay persisted at `path`, restoring its routes.
    ///
    /// A missing file is an empty overlay. An unreadable or malformed file
    /// is moved aside to `<path>.corrupt` and the overlay starts empty; an
    /// entry that no longer validates is skipped. Both are logged.
    #[must_use]
    pub fn open(path: PathBuf) -> Self {
        let specs = load_specs(&path);
        if !specs.is_empty() {
            info!(
                path = %path.display(),
                routes = specs.len(),
                "admin API routes restored"
            );
        }
        Self {
            path: Some(path),
            specs: Mutex::new(specs),
            acme: None,
        }
    }

    /// Publish ACME hostnames to `target` (the list the TLS service reads)
    /// and wake it through `notify` after every admin-route change.
    #[must_use]
    pub fn with_acme(
        mut self,
        target: Arc<ArcSwap<Vec<String>>>,
        notify: Arc<tokio::sync::Notify>,
    ) -> Self {
        let config_domains = Mutex::new(target.load().as_ref().clone());
        self.acme = Some(AcmeLink {
            target,
            notify,
            config_domains,
        });
        self.publish_acme(&self.specs.lock());
        self
    }

    /// Replace the Dwaarfile's ACME domains (at start and on every reload)
    /// and republish the union with the admin routes' hostnames.
    pub fn set_config_acme_domains(&self, domains: Vec<String>) {
        if let Some(link) = &self.acme {
            *link.config_domains.lock() = domains;
            self.publish_acme(&self.specs.lock());
        }
    }

    /// Add or replace one route. `on_commit` runs with the new route after
    /// the change was persisted, while further changes wait, so the caller
    /// can apply it to the live route table in the same order.
    pub fn upsert(
        &self,
        spec: AdminRouteSpec,
        on_commit: impl FnOnce(&Route),
    ) -> Result<Route, AdminRouteError> {
        let route = spec.build().map_err(AdminRouteError::Invalid)?;
        let mut specs = self.specs.lock();
        let mut next = specs.clone();
        next.insert(route.domain.clone(), spec);
        self.persist(&next)?;
        *specs = next;
        on_commit(&route);
        self.publish_acme(&specs);
        self.wake_acme(&route);
        Ok(route)
    }

    /// Remove the admin route for `domain`, if any. `on_commit` runs after
    /// the change was persisted (also when no admin route matched, so the
    /// caller can remove a Dwaarfile route from the live table).
    pub fn remove<T>(
        &self,
        domain: &str,
        on_commit: impl FnOnce() -> T,
    ) -> Result<T, AdminRouteError> {
        let key = domain.to_lowercase();
        let mut specs = self.specs.lock();
        if specs.contains_key(&key) {
            let mut next = specs.clone();
            next.remove(&key);
            self.persist(&next)?;
            *specs = next;
            self.publish_acme(&specs);
        }
        Ok(on_commit())
    }

    /// Replace every admin route owned by `source` with `desired` (each is
    /// given that source). `on_commit` runs with the built routes after the
    /// change was persisted.
    pub fn replace_source<T>(
        &self,
        source: &str,
        desired: Vec<AdminRouteSpec>,
        on_commit: impl FnOnce(&[Route]) -> T,
    ) -> Result<T, AdminRouteError> {
        let mut built = Vec::with_capacity(desired.len());
        let mut specs_in = Vec::with_capacity(desired.len());
        for mut spec in desired {
            spec.source = Some(source.to_owned());
            let route = spec.build().map_err(AdminRouteError::Invalid)?;
            if built.iter().any(|r: &Route| r.domain == route.domain) {
                return Err(AdminRouteError::Invalid(format!(
                    "duplicate domain in snapshot: {}",
                    route.domain
                )));
            }
            built.push(route);
            specs_in.push(spec);
        }
        let mut specs = self.specs.lock();
        let mut next = specs.clone();
        next.retain(|_, s| s.source.as_deref() != Some(source));
        for (route, spec) in built.iter().zip(specs_in) {
            next.insert(route.domain.clone(), spec);
        }
        self.persist(&next)?;
        *specs = next;
        let out = on_commit(&built);
        self.publish_acme(&specs);
        if let Some(link) = &self.acme {
            link.notify.notify_one();
        }
        Ok(out)
    }

    /// The admin routes, built.
    #[must_use]
    pub fn routes(&self) -> Vec<Route> {
        build_all(&self.specs.lock())
    }

    /// True when any admin route expects TLS.
    #[must_use]
    pub fn has_tls_routes(&self) -> bool {
        self.specs.lock().values().any(|s| s.tls)
    }

    /// The admin routes' ACME hostnames, sorted.
    #[must_use]
    pub fn acme_domains(&self) -> Vec<String> {
        acme_of(&self.specs.lock())
    }

    /// `base` (the compiled Dwaarfile routes) with every admin route laid
    /// over it; an admin route replaces a base route of the same domain.
    #[must_use]
    pub fn merge_into(&self, base: Vec<Route>) -> Vec<Route> {
        merge(base, build_all(&self.specs.lock()))
    }

    /// Like [`Self::merge_into`], but `store` runs while admin-route changes
    /// wait, so a concurrent `POST /routes` cannot be overwritten by a
    /// reload that merged before it.
    pub fn store_merged(&self, base: Vec<Route>, store: impl FnOnce(Vec<Route>)) {
        let specs = self.specs.lock();
        store(merge(base, build_all(&specs)));
    }

    fn persist(&self, specs: &BTreeMap<String, AdminRouteSpec>) -> Result<(), AdminRouteError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let body = FileBody {
            version: FILE_VERSION,
            routes: specs.values().cloned().collect(),
        };
        let json = serde_json::to_vec_pretty(&body)
            .map_err(|e| AdminRouteError::Persist(e.to_string()))?;
        write_atomic(path, &json).map_err(|e| {
            warn!(path = %path.display(), error = %e, "admin routes not persisted");
            AdminRouteError::Persist(e.to_string())
        })
    }

    fn publish_acme(&self, specs: &BTreeMap<String, AdminRouteSpec>) {
        let Some(link) = &self.acme else {
            return;
        };
        let mut domains = link.config_domains.lock().clone();
        for domain in acme_of(specs) {
            if !domains.contains(&domain) {
                domains.push(domain);
            }
        }
        link.target.store(Arc::new(domains));
    }

    fn wake_acme(&self, route: &Route) {
        if let Some(link) = &self.acme
            && route.tls
            && is_acme_hostname(&route.domain)
        {
            // notify_one stores a permit, so a TLS service busy with an
            // issuance still sees the change when it next waits.
            link.notify.notify_one();
        }
    }
}

fn build_all(specs: &BTreeMap<String, AdminRouteSpec>) -> Vec<Route> {
    specs.values().filter_map(|s| s.build().ok()).collect()
}

fn acme_of(specs: &BTreeMap<String, AdminRouteSpec>) -> Vec<String> {
    specs
        .iter()
        .filter(|(_, s)| s.needs_acme())
        .map(|(domain, _)| domain.clone())
        .collect()
}

fn merge(base: Vec<Route>, overlay: Vec<Route>) -> Vec<Route> {
    let mut out: Vec<Route> = base
        .into_iter()
        .filter(|r| !overlay.iter().any(|o| o.domain == r.domain))
        .collect();
    out.extend(overlay);
    out
}

fn load_specs(path: &Path) -> BTreeMap<String, AdminRouteSpec> {
    let mut specs = BTreeMap::new();
    let bytes = match read_capped(path) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return specs,
        Err(e) => {
            set_aside(path, &e.to_string());
            return specs;
        }
    };
    let body: FileBody = match serde_json::from_slice(&bytes) {
        Ok(body) => body,
        Err(e) => {
            set_aside(path, &e.to_string());
            return specs;
        }
    };
    if body.version != FILE_VERSION {
        set_aside(path, &format!("unknown version {}", body.version));
        return specs;
    }
    for spec in body.routes {
        match spec.build() {
            Ok(route) => {
                specs.insert(route.domain, spec);
            }
            Err(e) => warn!(
                path = %path.display(),
                domain = %spec.domain,
                error = %e,
                "persisted admin route skipped"
            ),
        }
    }
    specs
}

fn read_capped(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    use std::io::Read;
    let file = match open_nofollow(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(std::io::Error::other("file too large"));
    }
    Ok(Some(bytes))
}

fn open_nofollow(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

fn set_aside(path: &Path, reason: &str) {
    let aside = path.with_extension("json.corrupt");
    let moved = std::fs::rename(path, &aside).is_ok();
    warn!(
        path = %path.display(),
        reason,
        moved_to = %aside.display(),
        moved,
        "persisted admin routes unreadable — starting without them"
    );
}

/// Write `bytes` to `path` through a 0600 temporary file, fsync and rename.
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let result = (|| {
        let mut file = options.open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)?;
        if let Some(dir) = path.parent()
            && let Ok(d) = std::fs::File::open(dir)
        {
            let _ = d.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(domain: &str, upstream: &str, tls: bool, kind: RouteKind) -> AdminRouteSpec {
        AdminRouteSpec {
            domain: domain.to_owned(),
            upstream: upstream.to_owned(),
            tls,
            source: Some("permanu-runner".to_owned()),
            kind,
        }
    }

    fn domains(routes: &[Route]) -> Vec<String> {
        let mut d: Vec<String> = routes.iter().map(|r| r.domain.clone()).collect();
        d.sort();
        d
    }

    #[test]
    fn acme_hostnames_exclude_ips_wildcards_and_keys() {
        assert!(is_acme_hostname("app.example.com"));
        assert!(is_acme_hostname("web-prod-shop.203-0-113-5.sslip.io"));
        assert!(!is_acme_hostname("203.0.113.5"));
        assert!(!is_acme_hostname("::1"));
        assert!(!is_acme_hostname("*.example.com"));
        assert!(!is_acme_hostname("_default"));
        assert!(!is_acme_hostname("app.example.com/api"));
        assert!(!is_acme_hostname("localhost"));
        assert!(!is_acme_hostname("web.shop.localhost"));
        assert!(!is_acme_hostname("intranet"));
        assert!(!is_acme_hostname("1.2.3.999"));
        // Special-use names no public CA issues for (RFC 6761, RFC 8375).
        assert!(!is_acme_hostname("hooks.qa-u22.test"));
        assert!(!is_acme_hostname("a.example"));
        assert!(!is_acme_hostname("a.invalid"));
        assert!(!is_acme_hostname("printer.local"));
        assert!(!is_acme_hostname("nas.home.arpa"));
    }

    #[test]
    fn needs_acme_only_for_tls_hostnames_of_any_kind() {
        assert!(spec("app.example.com", "172.20.0.4:3000", true, RouteKind::Proxy).needs_acme());
        assert!(
            spec(
                "hooks.example.com",
                "127.0.0.1:7461",
                true,
                RouteKind::Webhook
            )
            .needs_acme()
        );
        // D-063 #4: the IP-only webhook route is plain HTTP, never ACME.
        assert!(!spec("203.0.113.5", "127.0.0.1:7461", false, RouteKind::Webhook).needs_acme());
        assert!(!spec("203.0.113.5", "127.0.0.1:7461", true, RouteKind::Webhook).needs_acme());
        assert!(
            !spec(
                "app.example.com",
                "172.20.0.4:3000",
                false,
                RouteKind::Proxy
            )
            .needs_acme()
        );
    }

    #[test]
    fn build_refuses_invalid_requests() {
        assert!(
            spec("bad domain", "127.0.0.1:1", false, RouteKind::Proxy)
                .build()
                .is_err()
        );
        assert!(
            spec("a.example.com", "nope", false, RouteKind::Proxy)
                .build()
                .is_err()
        );
        assert!(
            spec("h.example.com", "10.0.0.1:7461", true, RouteKind::Webhook)
                .build()
                .is_err()
        );
        assert!(
            spec("*.example.com", "127.0.0.1:7461", true, RouteKind::Webhook)
                .build()
                .is_err()
        );
        let ok = spec("H.Example.com", "127.0.0.1:7461", true, RouteKind::Webhook)
            .build()
            .expect("valid");
        assert_eq!(ok.domain, "h.example.com");
        assert_eq!(ok.kind, RouteKind::Webhook);
    }

    #[test]
    fn routes_survive_a_restart() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(ADMIN_ROUTES_FILE);
        let routes = AdminRoutes::open(path.clone());
        routes
            .upsert(
                spec("app.example.com", "172.20.0.4:3000", true, RouteKind::Proxy),
                |_| {},
            )
            .expect("upsert");
        routes
            .upsert(
                spec("203.0.113.5", "127.0.0.1:7461", false, RouteKind::Webhook),
                |_| {},
            )
            .expect("upsert");

        let restored = AdminRoutes::open(path.clone());
        let built = restored.routes();
        assert_eq!(domains(&built), ["203.0.113.5", "app.example.com"]);
        let hook = built
            .iter()
            .find(|r| r.domain == "203.0.113.5")
            .expect("hook");
        assert_eq!(hook.kind, RouteKind::Webhook);
        assert!(!hook.tls);
        assert_eq!(hook.source(), Some("permanu-runner"));
        let app = built
            .iter()
            .find(|r| r.domain == "app.example.com")
            .expect("app");
        assert!(app.tls);
        assert_eq!(
            app.upstream(),
            Some("172.20.0.4:3000".parse().expect("addr"))
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn removal_and_snapshot_are_persisted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(ADMIN_ROUTES_FILE);
        let routes = AdminRoutes::open(path.clone());
        routes
            .upsert(
                spec("a.example.com", "10.0.0.1:80", false, RouteKind::Proxy),
                |_| {},
            )
            .expect("a");
        let mut other = spec("o.example.com", "10.0.0.2:80", false, RouteKind::Proxy);
        other.source = Some("other".to_owned());
        routes.upsert(other, |_| {}).expect("o");

        let removed = routes.remove("A.EXAMPLE.COM", || true).expect("remove");
        assert!(removed);
        assert_eq!(
            domains(&AdminRoutes::open(path.clone()).routes()),
            ["o.example.com"]
        );

        routes
            .replace_source(
                "permanu-runner",
                vec![
                    spec("b.example.com", "10.0.0.3:80", false, RouteKind::Proxy),
                    spec("c.example.com", "10.0.0.4:80", true, RouteKind::Proxy),
                ],
                |_| (),
            )
            .expect("snapshot");
        routes
            .replace_source(
                "permanu-runner",
                vec![spec("c.example.com", "10.0.0.4:80", true, RouteKind::Proxy)],
                |_| (),
            )
            .expect("snapshot");
        assert_eq!(
            domains(&AdminRoutes::open(path).routes()),
            ["c.example.com", "o.example.com"]
        );
    }

    #[test]
    fn a_failed_write_changes_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("missing-dir").join(ADMIN_ROUTES_FILE);
        let routes = AdminRoutes::open(path);
        let mut committed = false;
        let err = routes
            .upsert(
                spec("a.example.com", "10.0.0.1:80", false, RouteKind::Proxy),
                |_| {
                    committed = true;
                },
            )
            .expect_err("no directory");
        assert!(matches!(err, AdminRouteError::Persist(_)));
        assert!(!committed);
        assert!(routes.routes().is_empty());
    }

    #[test]
    fn invalid_requests_are_not_persisted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(ADMIN_ROUTES_FILE);
        let routes = AdminRoutes::open(path.clone());
        let err = routes
            .upsert(
                spec("h.example.com", "10.0.0.1:7461", true, RouteKind::Webhook),
                |_| {},
            )
            .expect_err("non-loopback webhook");
        assert!(matches!(err, AdminRouteError::Invalid(_)));
        assert!(!path.exists());
    }

    #[test]
    fn corrupt_file_is_set_aside_and_bad_entries_skipped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(ADMIN_ROUTES_FILE);
        std::fs::write(&path, b"{not json").expect("write");
        assert!(AdminRoutes::open(path.clone()).routes().is_empty());
        assert!(dir.path().join("admin-routes.json.corrupt").exists());

        // A tampered webhook entry (non-loopback upstream) is not restored.
        std::fs::write(
            &path,
            br#"{"version":1,"routes":[
                {"domain":"h.example.com","upstream":"10.0.0.9:7461","tls":true,"kind":"webhook"},
                {"domain":"a.example.com","upstream":"10.0.0.1:80","tls":false}
            ]}"#,
        )
        .expect("write");
        assert_eq!(
            domains(&AdminRoutes::open(path).routes()),
            ["a.example.com"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_file_is_not_followed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("elsewhere.json");
        std::fs::write(
            &target,
            br#"{"version":1,"routes":[{"domain":"a.example.com","upstream":"10.0.0.1:80","tls":false}]}"#,
        )
        .expect("write");
        let path = dir.path().join(ADMIN_ROUTES_FILE);
        std::os::unix::fs::symlink(&target, &path).expect("symlink");
        assert!(AdminRoutes::open(path).routes().is_empty());
    }

    #[test]
    fn admin_routes_override_and_merge_over_the_dwaarfile() {
        let routes = AdminRoutes::in_memory();
        routes
            .upsert(
                spec("a.example.com", "10.0.0.9:80", false, RouteKind::Proxy),
                |_| {},
            )
            .expect("a");
        let base = vec![
            Route::new(
                "a.example.com",
                "10.0.0.1:80".parse().expect("addr"),
                false,
                None,
            ),
            Route::new(
                "b.example.com",
                "10.0.0.2:80".parse().expect("addr"),
                false,
                None,
            ),
        ];
        let merged = routes.merge_into(base);
        assert_eq!(domains(&merged), ["a.example.com", "b.example.com"]);
        let a = merged
            .iter()
            .find(|r| r.domain == "a.example.com")
            .expect("a");
        assert_eq!(a.upstream(), Some("10.0.0.9:80".parse().expect("addr")));
    }

    #[test]
    fn acme_list_is_dwaarfile_domains_plus_admin_hostnames() {
        let target = Arc::new(ArcSwap::from_pointee(vec!["site.example.com".to_owned()]));
        let notify = Arc::new(tokio::sync::Notify::new());
        let routes = AdminRoutes::in_memory().with_acme(Arc::clone(&target), Arc::clone(&notify));
        routes
            .upsert(
                spec("app.example.com", "172.20.0.4:3000", true, RouteKind::Proxy),
                |_| {},
            )
            .expect("app");
        routes
            .upsert(
                spec(
                    "hooks.example.com",
                    "127.0.0.1:7461",
                    true,
                    RouteKind::Webhook,
                ),
                |_| {},
            )
            .expect("hooks");
        routes
            .upsert(
                spec("203.0.113.5", "127.0.0.1:7461", false, RouteKind::Webhook),
                |_| {},
            )
            .expect("ip hook");
        assert_eq!(
            target.load().as_ref(),
            &["site.example.com", "app.example.com", "hooks.example.com"]
        );

        routes.set_config_acme_domains(vec!["new.example.com".to_owned()]);
        assert_eq!(
            target.load().as_ref(),
            &["new.example.com", "app.example.com", "hooks.example.com"]
        );

        routes.remove("app.example.com", || ()).expect("remove");
        assert_eq!(
            target.load().as_ref(),
            &["new.example.com", "hooks.example.com"]
        );

        // A TLS hostname added through the admin API wakes the TLS service.
        let woken = tokio_test::block_on(async {
            tokio::time::timeout(std::time::Duration::from_millis(50), notify.notified())
                .await
                .is_ok()
        });
        assert!(woken);
    }
}
