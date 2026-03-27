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
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use openssl::hash::MessageDigest;
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::MAX_CONFIG_SIZE;
use crate::compile::compile_routes;
use crate::parser;

const DEBOUNCE_INTERVAL: Duration = Duration::from_millis(500);

/// Background service that watches the Dwaarfile and hot-reloads on changes.
pub struct ConfigWatcher {
    config_path: PathBuf,
    route_table: Arc<ArcSwap<RouteTable>>,
    last_hash: std::sync::Mutex<Vec<u8>>,
    /// When Docker mode is active, store compiled routes here instead of
    /// writing to `route_table` directly. `DockerWatcher` handles the merge.
    dwaarfile_snapshot: Option<Arc<ArcSwap<Vec<Route>>>>,
    /// Signal `DockerWatcher` to re-merge after a Dwaarfile change.
    config_notify: Option<Arc<tokio::sync::Notify>>,
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
        initial_hash: Vec<u8>,
    ) -> Self {
        Self {
            config_path,
            route_table,
            last_hash: std::sync::Mutex::new(initial_hash),
            dwaarfile_snapshot: None,
            config_notify: None,
        }
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
        // Read file with size check
        let metadata = match std::fs::metadata(&self.config_path) {
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

        let content = match std::fs::read_to_string(&self.config_path) {
            Ok(c) => c,
            Err(e) => {
                warn!(path = %self.config_path.display(), error = %e, "failed to read config");
                return;
            }
        };

        // Content hash comparison
        let new_hash = match openssl::hash::hash(MessageDigest::sha256(), content.as_bytes()) {
            Ok(h) => h.to_vec(),
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
            && (old_route.upstream != new_route.upstream || old_route.tls != new_route.tls)
        {
            info!(
                domain = %new_route.domain,
                old_upstream = %old_route.upstream,
                new_upstream = %new_route.upstream,
                "route modified"
            );
        }
    }
}

/// Compute SHA-256 hash of file content. Used at startup to seed the watcher.
pub fn hash_content(content: &[u8]) -> Vec<u8> {
    openssl::hash::hash(MessageDigest::sha256(), content)
        .map(|d| d.to_vec())
        .unwrap_or_default()
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
        let hash = hash_content(b"hello world");
        assert_eq!(hash.len(), 32);
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
}
