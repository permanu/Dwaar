// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Dwaarfile hot-reload via file watching.
//!
//! Watches the config file for changes, debounces events, and swaps
//! the route table when a valid new config is detected.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use dwaar_core::route::{Route, RouteTable};
use dwaar_tls::sni::DomainConfigMap;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use openssl::hash::MessageDigest;
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use dwaar_core::upstream::UpstreamPool;

use crate::MAX_CONFIG_SIZE;
use crate::compile::{collect_pools, compile_acme_domains, compile_routes, compile_tls_configs};
use crate::parser;

const DEBOUNCE_INTERVAL: Duration = Duration::from_millis(500);

/// Background service that watches the Dwaarfile and hot-reloads on changes.
pub struct ConfigWatcher {
    config_path: PathBuf,
    route_table: Arc<ArcSwap<RouteTable>>,
    last_hash: std::sync::Mutex<[u8; 32]>,
    /// When Docker mode is active, store compiled routes here instead of
    /// writing to `route_table` directly. `DockerWatcher` handles the merge.
    dwaarfile_snapshot: Option<Arc<ArcSwap<Vec<Route>>>>,
    /// Signal `DockerWatcher` to re-merge after a Dwaarfile change.
    config_notify: Option<Arc<tokio::sync::Notify>>,
    /// How long to wait for in-flight requests on removed routes before
    /// force-dropping them (ISSUE-075). Default: 30 seconds.
    drain_timeout: Duration,
    /// Shared map of explicit per-domain cert paths (from `tls /cert /key`
    /// directives).  On reload we swap in a freshly compiled map so that
    /// `SniResolver` picks up new or changed manual TLS entries without
    /// a restart.  `None` when the proxy runs without TLS.
    sni_domain_map: Option<DomainConfigMap>,
    /// Shared pool list for the health checker. Swapped on reload so the
    /// `HealthChecker` picks up new/removed pools without a restart.
    health_pools: Option<Arc<ArcSwap<Vec<Arc<UpstreamPool>>>>>,
    /// Shared ACME domain list. Swapped on reload so `TlsBackgroundService`
    /// picks up new/removed `tls auto` domains without a restart.
    acme_domains: Option<Arc<ArcSwap<Vec<String>>>>,
    /// Shared cache backend (ISSUE-111). On reload, if the max cache size
    /// changed, a new backend is leaked and swapped in.
    cache_backend: Option<dwaar_core::cache::SharedCacheBackend>,
}

impl std::fmt::Debug for ConfigWatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigWatcher")
            .field("config_path", &self.config_path)
            .finish_non_exhaustive()
    }
}

impl ConfigWatcher {
    /// Create a new config watcher.
    ///
    /// `initial_hash` should be the SHA-256 of the config file at startup,
    /// so the first change detection works correctly.
    pub fn new(
        config_path: PathBuf,
        route_table: Arc<ArcSwap<RouteTable>>,
        initial_hash: [u8; 32],
    ) -> Self {
        Self {
            config_path,
            route_table,
            last_hash: std::sync::Mutex::new(initial_hash),
            dwaarfile_snapshot: None,
            config_notify: None,
            drain_timeout: Duration::from_secs(30),
            sni_domain_map: None,
            health_pools: None,
            acme_domains: None,
            cache_backend: None,
        }
    }

    /// Set a custom drain timeout for removed routes (ISSUE-075).
    #[must_use]
    pub fn with_drain_timeout(mut self, timeout: Duration) -> Self {
        self.drain_timeout = timeout;
        self
    }

    /// Set a `Notify` that triggers an immediate config reload (for `POST /reload`).
    #[must_use]
    pub fn with_reload_notify(mut self, notify: Arc<tokio::sync::Notify>) -> Self {
        self.config_notify = Some(notify);
        self
    }

    /// Attach the shared SNI domain-config map so hot-reload keeps explicit
    /// `tls /cert /key` entries in sync.
    ///
    /// Call [`SniResolver::shared_domain_map`] at startup and pass the result
    /// here.  On every successful reload the watcher will swap in a freshly
    /// compiled map.
    #[must_use]
    pub fn with_sni_domain_map(mut self, map: DomainConfigMap) -> Self {
        self.sni_domain_map = Some(map);
        self
    }

    /// Attach the shared health-check pool list so hot-reload swaps in
    /// freshly compiled pools for the `HealthChecker`.
    #[must_use]
    pub fn with_health_pools(mut self, pools: Arc<ArcSwap<Vec<Arc<UpstreamPool>>>>) -> Self {
        self.health_pools = Some(pools);
        self
    }

    /// Attach the shared ACME domain list so hot-reload swaps in freshly
    /// compiled domains for `TlsBackgroundService`.
    #[must_use]
    pub fn with_acme_domains(mut self, domains: Arc<ArcSwap<Vec<String>>>) -> Self {
        self.acme_domains = Some(domains);
        self
    }

    /// Attach the shared cache backend so hot-reload can resize the LRU
    /// eviction budget without a restart (ISSUE-111).
    #[must_use]
    pub fn with_cache_backend(mut self, backend: dwaar_core::cache::SharedCacheBackend) -> Self {
        self.cache_backend = Some(backend);
        self
    }

    /// Enable Docker mode: compiled routes go into the shared snapshot
    /// instead of the route table, and a `Notify` wakes `DockerWatcher`
    /// to re-merge Dwaarfile + Docker routes.
    #[must_use]
    pub fn with_docker_mode(
        mut self,
        snapshot: Arc<ArcSwap<Vec<Route>>>,
        notify: Arc<tokio::sync::Notify>,
    ) -> Self {
        self.dwaarfile_snapshot = Some(snapshot);
        self.config_notify = Some(notify);
        self
    }

    /// Process a file change: hash -> compare -> parse -> compile -> swap.
    fn try_reload(&self, shutdown: &ShutdownWatch) {
        // File I/O is blocking — move it off the async executor so we don't
        // stall other tokio tasks during hot-reload.
        let metadata = match tokio::task::block_in_place(|| std::fs::metadata(&self.config_path)) {
            Ok(m) => m,
            Err(e) => {
                warn!(path = %self.config_path.display(), error = %e, "failed to stat config");
                return;
            }
        };

        if metadata.len() > MAX_CONFIG_SIZE {
            error!(
                path = %self.config_path.display(),
                size = metadata.len(),
                "config file too large, skipping reload"
            );
            return;
        }

        let content =
            match tokio::task::block_in_place(|| std::fs::read_to_string(&self.config_path)) {
                Ok(c) => c,
                Err(e) => {
                    warn!(path = %self.config_path.display(), error = %e, "failed to read config");
                    return;
                }
            };

        // Content hash comparison
        let new_hash = match openssl::hash::hash(MessageDigest::sha256(), content.as_bytes()) {
            Ok(h) => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&h);
                arr
            }
            Err(e) => {
                warn!(error = %e, "failed to hash config content");
                return;
            }
        };

        {
            let last = self
                .last_hash
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if *last == new_hash {
                debug!("config hash unchanged, skipping reload");
                return;
            }
        }

        // Parse
        let config = match parser::parse(&content) {
            Ok(c) => c,
            Err(e) => {
                error!(error = %e, "config parse failed — keeping current config");
                return;
            }
        };

        // Use drain timeout from the new config if specified, else keep the
        // startup default. Computed per-reload since the config might change it.
        let drain_timeout = config
            .global_options
            .as_ref()
            .and_then(|g| g.drain_timeout_secs)
            .map_or(self.drain_timeout, Duration::from_secs);

        // Compile routes
        let new_table = compile_routes(&config);

        // Warn if new table is empty but old had routes
        let old_table = self.route_table.load();
        if new_table.is_empty() && !old_table.is_empty() {
            warn!("new config has zero routes — all traffic will return 502");
        }

        // Check shutdown before swapping
        if *shutdown.borrow() {
            debug!("shutdown in progress, skipping config swap");
            return;
        }

        refresh_sni_map(self.sni_domain_map.as_ref(), &config);

        // Refresh health-check pools from the newly compiled route table.
        if let Some(ref hp) = self.health_pools {
            let pools = collect_pools(&new_table);
            hp.store(Arc::new(pools));
            debug!("health-check pools refreshed");
        }

        // Refresh ACME domain list from the new config.
        if let Some(ref ad) = self.acme_domains {
            let domains = compile_acme_domains(&config);
            ad.store(Arc::new(domains));
            debug!("ACME domain list refreshed");
        }

        refresh_cache_backend(self.cache_backend.as_ref(), &new_table);

        if let Some(ref snapshot) = self.dwaarfile_snapshot {
            // Docker mode: update snapshot, notify DockerWatcher to re-merge
            snapshot.store(Arc::new(new_table.all_routes()));
            if let Some(ref notify) = self.config_notify {
                notify.notify_one();
            }
            info!(path = %self.config_path.display(), "config reloaded — Docker watcher will re-merge");
        } else {
            // Standard mode: write directly to route table
            log_route_diff(&old_table, &new_table);

            // Drain routes that were removed (ISSUE-075): mark them as draining
            // so in-flight requests complete, then let them drop after timeout.
            drain_removed_routes(&old_table, &new_table, drain_timeout);

            self.route_table.store(Arc::new(new_table));
            info!(path = %self.config_path.display(), "config reloaded successfully");
        }

        // Update hash — must run in both branches
        let mut last = self
            .last_hash
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *last = new_hash;
    }
}

#[async_trait]
impl BackgroundService for ConfigWatcher {
    async fn start(&self, shutdown: ShutdownWatch) {
        let (tx, mut rx) = mpsc::channel::<()>(16);

        // Set up file watcher
        let config_path = self.config_path.clone();
        let _watcher = match setup_watcher(&config_path, tx) {
            Ok(w) => w,
            Err(e) => {
                error!(error = %e, "failed to start config file watcher — hot-reload disabled");
                return;
            }
        };

        info!(path = %self.config_path.display(), "config watcher started");

        loop {
            tokio::select! {
                event = rx.recv() => {
                    if event.is_none() {
                        debug!("watcher channel closed");
                        return;
                    }

                    // Phase 1: debounce — wait, then drain extra events
                    tokio::time::sleep(DEBOUNCE_INTERVAL).await;
                    while rx.try_recv().is_ok() {}

                    // Process the change
                    self.try_reload(&shutdown);

                    // Phase 2: drain events that arrived during processing
                    while rx.try_recv().is_ok() {}
                }
                // Admin API reload trigger (POST /reload)
                () = async {
                    match &self.config_notify {
                        Some(n) => n.notified().await,
                        None => std::future::pending().await,
                    }
                } => {
                    info!("config reload triggered via admin API");
                    self.try_reload(&shutdown);
                }
                () = shutdown_signal(&shutdown) => {
                    info!("config watcher shutting down");
                    return;
                }
            }
        }
    }
}

/// Set up the notify file watcher, sending events to the mpsc channel.
fn setup_watcher(
    config_path: &std::path::Path,
    tx: mpsc::Sender<()>,
) -> Result<RecommendedWatcher, notify::Error> {
    let mut watcher = RecommendedWatcher::new(
        move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res
                && matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_))
            {
                let _ = tx.try_send(());
            }
        },
        notify::Config::default(),
    )?;

    // Watch the parent directory (handles atomic rename patterns)
    let parent = config_path.parent().unwrap_or(std::path::Path::new("."));
    watcher.watch(parent, RecursiveMode::NonRecursive)?;

    Ok(watcher)
}

/// Wait until shutdown is signaled.
async fn shutdown_signal(shutdown: &ShutdownWatch) {
    let mut watch = shutdown.clone();
    while !*watch.borrow() {
        if watch.changed().await.is_err() {
            return;
        }
    }
}

/// Log differences between old and new route tables.
/// Mark removed routes as draining and spawn background tasks that wait
/// for in-flight requests to complete (or timeout), then drop them.
///
/// Called during standard-mode config reload. The old route's `draining`
/// flag causes `request_filter()` to reject new connections with 502,
/// while existing requests continue on the cloned `active_connections` counter.
fn drain_removed_routes(old: &RouteTable, new: &RouteTable, timeout: Duration) {
    let new_domains: std::collections::HashSet<&str> = new.domain_keys().collect();

    for domain in old.domain_keys() {
        if new_domains.contains(domain) {
            continue;
        }

        let Some(route) = old.get_exact(domain) else {
            continue;
        };

        route.mark_draining();

        let active = route.active_connections.clone();
        let draining = route.draining.clone();
        let domain_owned = domain.to_owned();

        tokio::spawn(async move {
            let start = tokio::time::Instant::now();
            let poll_interval = Duration::from_millis(100);

            // Wait until all in-flight requests finish or we hit the timeout
            while active.load(std::sync::atomic::Ordering::Relaxed) > 0 {
                if start.elapsed() >= timeout {
                    let remaining = active.load(std::sync::atomic::Ordering::Relaxed);
                    warn!(
                        domain = %domain_owned,
                        remaining_connections = remaining,
                        "drain timeout reached — force-closing"
                    );
                    break;
                }
                tokio::time::sleep(poll_interval).await;
            }

            // Reset draining flag (the route is now fully removed from the table,
            // so this only matters if someone held an Arc reference to it)
            draining.store(false, std::sync::atomic::Ordering::Relaxed);
            info!(domain = %domain_owned, "route drain complete");
        });
    }
}

fn log_route_diff(old: &RouteTable, new: &RouteTable) {
    let old_routes = old.all_routes();
    let new_routes = new.all_routes();

    let old_domains: std::collections::HashSet<&str> =
        old_routes.iter().map(|r| r.domain.as_str()).collect();
    let new_domains: std::collections::HashSet<&str> =
        new_routes.iter().map(|r| r.domain.as_str()).collect();

    for domain in &new_domains {
        if !old_domains.contains(domain) {
            info!(domain, "route added");
        }
    }

    for domain in &old_domains {
        if !new_domains.contains(domain) {
            info!(domain, "route removed");
        }
    }

    // Check for modifications (same domain, different config)
    for new_route in &new_routes {
        if let Some(old_route) = old_routes.iter().find(|r| r.domain == new_route.domain)
            && (old_route.upstream() != new_route.upstream() || old_route.tls != new_route.tls)
        {
            info!(
                domain = %new_route.domain,
                old_upstream = ?old_route.upstream(),
                new_upstream = ?new_route.upstream(),
                "route modified"
            );
        }
    }
}

/// Resize the cache backend if the max cache size in the new route table
/// differs from the current one. Skips reallocation when unchanged.
fn refresh_cache_backend(
    cache_backend: Option<&dwaar_core::cache::SharedCacheBackend>,
    new_table: &RouteTable,
) {
    let Some(cb) = cache_backend else { return };
    let new_max = new_table
        .all_routes()
        .iter()
        .flat_map(|r| r.handlers.iter())
        .filter_map(|h| h.cache.as_ref())
        .map(|c| c.max_size)
        .max();
    if let Some(size) = new_max {
        dwaar_core::cache::realloc_cache_backend(cb, size);
    }
}

/// Swap in a freshly compiled set of explicit TLS cert paths.
///
/// Called on every successful reload so that `SniResolver` picks up new or
/// changed `tls /cert /key` entries. Does nothing when TLS is disabled.
fn refresh_sni_map(sni_map: Option<&DomainConfigMap>, config: &crate::model::DwaarConfig) {
    let Some(map) = sni_map else { return };
    let new_tls = compile_tls_configs(config);
    let domain_map: std::collections::HashMap<String, dwaar_tls::sni::DomainTlsConfig> = new_tls
        .into_iter()
        .map(|(domain, cfg)| {
            (
                domain,
                dwaar_tls::sni::DomainTlsConfig {
                    cert_path: cfg.cert_path,
                    key_path: cfg.key_path,
                },
            )
        })
        .collect();
    map.store(Arc::new(domain_map));
    debug!("SNI domain-config map refreshed");
}

/// Compute SHA-256 hash of file content. Used at startup to seed the watcher.
pub fn hash_content(content: &[u8]) -> [u8; 32] {
    let digest =
        openssl::hash::hash(MessageDigest::sha256(), content).expect("SHA-256 is always available");
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use dwaar_core::route::Route;
    use std::net::SocketAddr;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[test]
    fn hash_content_produces_32_bytes() {
        let hash: [u8; 32] = hash_content(b"hello world");
        // SHA-256("hello world") starts with 0xb9 — verify we got a real hash
        assert_eq!(hash[0], 0xb9, "first byte should be 0xb9");
        assert!(
            !hash.iter().all(|&b| b == 0),
            "hash should not be all zeros"
        );
    }

    #[test]
    fn same_content_same_hash() {
        let h1 = hash_content(b"example.com { reverse_proxy 127.0.0.1:8080 }");
        let h2 = hash_content(b"example.com { reverse_proxy 127.0.0.1:8080 }");
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_content_different_hash() {
        let h1 = hash_content(b"example.com { reverse_proxy 127.0.0.1:8080 }");
        let h2 = hash_content(b"example.com { reverse_proxy 127.0.0.1:9090 }");
        assert_ne!(h1, h2);
    }

    #[test]
    fn route_diff_detects_added() {
        let old = RouteTable::new(vec![Route::new("a.com", addr(1000), false, None)]);
        let new = RouteTable::new(vec![
            Route::new("a.com", addr(1000), false, None),
            Route::new("b.com", addr(2000), false, None),
        ]);
        // Just verify it doesn't panic — log output is tested via tracing-test in integration
        log_route_diff(&old, &new);
    }

    #[test]
    fn route_diff_detects_removed() {
        let old = RouteTable::new(vec![
            Route::new("a.com", addr(1000), false, None),
            Route::new("b.com", addr(2000), false, None),
        ]);
        let new = RouteTable::new(vec![Route::new("a.com", addr(1000), false, None)]);
        log_route_diff(&old, &new);
    }

    #[test]
    fn try_reload_with_invalid_config_preserves_routes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("Dwaarfile");

        // Write a valid config first
        std::fs::write(
            &config_path,
            "a.com {\n    reverse_proxy 127.0.0.1:8080\n}\n",
        )
        .expect("write");
        let initial_hash = hash_content(&std::fs::read(&config_path).expect("read"));

        let table = Arc::new(ArcSwap::from_pointee(RouteTable::new(vec![Route::new(
            "a.com",
            addr(8080),
            false,
            None,
        )])));

        let watcher = ConfigWatcher::new(config_path.clone(), Arc::clone(&table), initial_hash);

        // Write invalid config
        std::fs::write(&config_path, "{{{{ invalid garbage").expect("write bad");

        // Create a shutdown watch (not shut down)
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        watcher.try_reload(&shutdown_rx);

        // Old routes should be preserved
        assert_eq!(table.load().len(), 1);
        assert!(table.load().resolve("a.com").is_some());

        drop(shutdown_tx);
    }

    #[test]
    fn drain_marks_removed_routes() {
        let old_route = Route::new("old.com", addr(1000), false, None);
        let active = old_route.active_connections.clone();
        let draining = old_route.draining.clone();

        let old = RouteTable::new(vec![
            old_route,
            Route::new("kept.com", addr(2000), false, None),
        ]);
        let new = RouteTable::new(vec![Route::new("kept.com", addr(2000), false, None)]);

        // The removed route should be marked as draining after the drain call.
        // We need a tokio runtime for the spawned tasks, but the marking itself
        // happens synchronously before the spawn.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime");
        rt.block_on(async {
            drain_removed_routes(&old, &new, Duration::from_millis(100));
            assert!(draining.load(std::sync::atomic::Ordering::Relaxed));

            // With no active connections, the drain task should complete quickly
            tokio::time::sleep(Duration::from_millis(200)).await;
            // Draining flag resets after completion
            assert!(!draining.load(std::sync::atomic::Ordering::Relaxed));
        });

        // The kept route should NOT be draining
        assert!(!old.get_exact("kept.com").expect("exists").is_draining());
        drop(active);
    }

    #[tokio::test]
    async fn drain_waits_for_active_connections() {
        let old_route = Route::new("slow.com", addr(1000), false, None);
        let active = old_route.active_connections.clone();
        let draining = old_route.draining.clone();

        // Simulate 2 in-flight requests
        active.store(2, std::sync::atomic::Ordering::Relaxed);

        let old = RouteTable::new(vec![old_route]);
        let new = RouteTable::new(vec![]);

        drain_removed_routes(&old, &new, Duration::from_secs(5));
        assert!(draining.load(std::sync::atomic::Ordering::Relaxed));

        // Simulate requests completing
        tokio::time::sleep(Duration::from_millis(50)).await;
        active.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(50)).await;
        active.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);

        // Give the drain task time to notice
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!draining.load(std::sync::atomic::Ordering::Relaxed));
    }

    #[tokio::test]
    async fn drain_timeout_force_closes() {
        let old_route = Route::new("stuck.com", addr(1000), false, None);
        let active = old_route.active_connections.clone();
        let draining = old_route.draining.clone();

        // Simulate a stuck request that never completes
        active.store(1, std::sync::atomic::Ordering::Relaxed);

        let old = RouteTable::new(vec![old_route]);
        let new = RouteTable::new(vec![]);

        drain_removed_routes(&old, &new, Duration::from_millis(200));
        assert!(draining.load(std::sync::atomic::Ordering::Relaxed));

        // After timeout, drain should complete even with active connections
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(!draining.load(std::sync::atomic::Ordering::Relaxed));
        // The counter is still 1, but the route is force-closed
        assert_eq!(active.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    // ── ISSUE-109: health pool hot-reload tests ─────────────────

    #[test]
    fn reload_refreshes_health_pools() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("Dwaarfile");

        // One site with health checks
        let initial = "\
a.com {
    reverse_proxy {
        to 127.0.0.1:8080
        health_uri /health
        health_interval 5
    }
}
";
        std::fs::write(&config_path, initial).expect("write");
        let initial_hash = hash_content(initial.as_bytes());

        let table = Arc::new(ArcSwap::from_pointee(compile_routes(
            &parser::parse(initial).expect("parse"),
        )));
        let health_pools = Arc::new(ArcSwap::from_pointee(collect_pools(&table.load())));
        assert_eq!(health_pools.load().len(), 1, "one pool at startup");

        let watcher = ConfigWatcher::new(config_path.clone(), Arc::clone(&table), initial_hash)
            .with_health_pools(Arc::clone(&health_pools));

        // Add a second site with health checks
        let updated = "\
a.com {
    reverse_proxy {
        to 127.0.0.1:8080
        health_uri /health
        health_interval 5
    }
}
b.com {
    reverse_proxy {
        to 127.0.0.1:9090
        health_uri /ping
        health_interval 10
    }
}
";
        std::fs::write(&config_path, updated).expect("write");
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        watcher.try_reload(&shutdown_rx);

        assert_eq!(health_pools.load().len(), 2, "second pool added after reload");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reload_removes_stale_health_pools() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("Dwaarfile");

        // Two sites with health checks
        let initial = "\
a.com {
    reverse_proxy {
        to 127.0.0.1:8080
        health_uri /health
        health_interval 5
    }
}
b.com {
    reverse_proxy {
        to 127.0.0.1:9090
        health_uri /ping
        health_interval 10
    }
}
";
        std::fs::write(&config_path, initial).expect("write");
        let initial_hash = hash_content(initial.as_bytes());

        let table = Arc::new(ArcSwap::from_pointee(compile_routes(
            &parser::parse(initial).expect("parse"),
        )));
        let health_pools = Arc::new(ArcSwap::from_pointee(collect_pools(&table.load())));
        assert_eq!(health_pools.load().len(), 2, "two pools at startup");

        let watcher = ConfigWatcher::new(config_path.clone(), Arc::clone(&table), initial_hash)
            .with_health_pools(Arc::clone(&health_pools));

        // Remove b.com entirely — needs tokio runtime because removing a
        // route triggers drain_removed_routes which spawns async tasks.
        let updated = "\
a.com {
    reverse_proxy {
        to 127.0.0.1:8080
        health_uri /health
        health_interval 5
    }
}
";
        std::fs::write(&config_path, updated).expect("write");
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        watcher.try_reload(&shutdown_rx);

        assert_eq!(health_pools.load().len(), 1, "stale pool removed after reload");
    }

    // ── ISSUE-110: ACME domain hot-reload tests ─────────────────

    #[test]
    fn reload_refreshes_acme_domains() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("Dwaarfile");

        let initial = "\
a.com {
    tls auto
    reverse_proxy 127.0.0.1:8080
}
";
        std::fs::write(&config_path, initial).expect("write");
        let initial_hash = hash_content(initial.as_bytes());

        let config = parser::parse(initial).expect("parse");
        let table = Arc::new(ArcSwap::from_pointee(compile_routes(&config)));
        let acme_domains = Arc::new(ArcSwap::from_pointee(compile_acme_domains(&config)));
        assert_eq!(acme_domains.load().len(), 1, "one ACME domain at startup");
        assert_eq!(acme_domains.load()[0], "a.com");

        let watcher = ConfigWatcher::new(config_path.clone(), Arc::clone(&table), initial_hash)
            .with_acme_domains(Arc::clone(&acme_domains));

        // Add a second ACME domain
        let updated = "\
a.com {
    tls auto
    reverse_proxy 127.0.0.1:8080
}
b.com {
    tls auto
    reverse_proxy 127.0.0.1:9090
}
";
        std::fs::write(&config_path, updated).expect("write");
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        watcher.try_reload(&shutdown_rx);

        let domains = acme_domains.load();
        assert_eq!(domains.len(), 2, "second ACME domain added after reload");
        assert!(domains.contains(&"a.com".to_string()));
        assert!(domains.contains(&"b.com".to_string()));
    }

    #[test]
    fn reload_removes_stale_acme_domains() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("Dwaarfile");

        let initial = "\
a.com {
    tls auto
    reverse_proxy 127.0.0.1:8080
}
b.com {
    tls auto
    reverse_proxy 127.0.0.1:9090
}
";
        std::fs::write(&config_path, initial).expect("write");
        let initial_hash = hash_content(initial.as_bytes());

        let config = parser::parse(initial).expect("parse");
        let table = Arc::new(ArcSwap::from_pointee(compile_routes(&config)));
        let acme_domains = Arc::new(ArcSwap::from_pointee(compile_acme_domains(&config)));
        assert_eq!(acme_domains.load().len(), 2, "two ACME domains at startup");

        let watcher = ConfigWatcher::new(config_path.clone(), Arc::clone(&table), initial_hash)
            .with_acme_domains(Arc::clone(&acme_domains));

        // Remove b.com's tls auto (just plain reverse_proxy)
        let updated = "\
a.com {
    tls auto
    reverse_proxy 127.0.0.1:8080
}
b.com {
    reverse_proxy 127.0.0.1:9090
}
";
        std::fs::write(&config_path, updated).expect("write");
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        watcher.try_reload(&shutdown_rx);

        let domains = acme_domains.load();
        assert_eq!(domains.len(), 1, "stale ACME domain removed after reload");
        assert_eq!(domains[0], "a.com");
    }

    // ── ISSUE-111: cache sizing hot-reload tests ────────────────

    /// Read `max_size` from a `SharedCacheBackend`.
    fn read_cache_max_size(cb: &dwaar_core::cache::SharedCacheBackend) -> usize {
        cb.load()
            .as_ref()
            .as_ref()
            .expect("cache backend should be Some")
            .max_size
    }

    /// Get the storage pointer identity for change detection.
    fn cache_storage_addr(cb: &dwaar_core::cache::SharedCacheBackend) -> usize {
        std::ptr::from_ref(
            cb.load()
                .as_ref()
                .as_ref()
                .expect("cache backend should be Some")
                .storage,
        ) as usize
    }

    #[test]
    fn reload_resizes_cache_backend() {
        use dwaar_core::cache::{new_cache_backend, SharedCacheBackend};

        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("Dwaarfile");

        let initial = "\
a.com {
    reverse_proxy 127.0.0.1:8080
    cache {
        max_size 1m
    }
}
";
        std::fs::write(&config_path, initial).expect("write");
        let initial_hash = hash_content(initial.as_bytes());

        let config = parser::parse(initial).expect("parse");
        let table = Arc::new(ArcSwap::from_pointee(compile_routes(&config)));

        let cache_backend: SharedCacheBackend =
            Arc::new(ArcSwap::from_pointee(Some(new_cache_backend(1_048_576))));
        assert_eq!(read_cache_max_size(&cache_backend), 1_048_576);

        let watcher = ConfigWatcher::new(config_path.clone(), Arc::clone(&table), initial_hash)
            .with_cache_backend(Arc::clone(&cache_backend));

        // Reload with larger cache
        let updated = "\
a.com {
    reverse_proxy 127.0.0.1:8080
    cache {
        max_size 4m
    }
}
";
        std::fs::write(&config_path, updated).expect("write");
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        watcher.try_reload(&shutdown_rx);

        assert_eq!(
            read_cache_max_size(&cache_backend),
            4_194_304,
            "cache backend should reflect new max_size after reload"
        );
    }

    #[test]
    fn reload_skips_cache_resize_when_unchanged() {
        use dwaar_core::cache::{new_cache_backend, SharedCacheBackend};

        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("Dwaarfile");

        let initial = "\
a.com {
    reverse_proxy 127.0.0.1:8080
    cache {
        max_size 2m
    }
}
";
        std::fs::write(&config_path, initial).expect("write");
        let initial_hash = hash_content(initial.as_bytes());

        let config = parser::parse(initial).expect("parse");
        let table = Arc::new(ArcSwap::from_pointee(compile_routes(&config)));

        let cache_backend: SharedCacheBackend =
            Arc::new(ArcSwap::from_pointee(Some(new_cache_backend(2_097_152))));
        let ptr_before = cache_storage_addr(&cache_backend);

        let watcher = ConfigWatcher::new(config_path.clone(), Arc::clone(&table), initial_hash)
            .with_cache_backend(Arc::clone(&cache_backend));

        // Reload with different route but same cache size
        let updated = "\
a.com {
    reverse_proxy 127.0.0.1:9090
    cache {
        max_size 2m
    }
}
";
        std::fs::write(&config_path, updated).expect("write");
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        watcher.try_reload(&shutdown_rx);

        assert_eq!(
            ptr_before,
            cache_storage_addr(&cache_backend),
            "same cache size should not reallocate"
        );
    }
}
