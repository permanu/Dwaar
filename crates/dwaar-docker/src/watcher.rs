// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Docker socket watcher that runs as a Pingora [`BackgroundService`].
//!
//! Bootstraps existing containers on startup, then streams Docker events
//! to discover new containers (`start`) and remove dead ones (`die`).
//! Docker-discovered routes are merged with Dwaarfile routes into the
//! shared route table, with Dwaarfile routes taking priority on conflict.
//!
//! The event loop is single-threaded within `start()` — all mutations to
//! `docker_routes` and `container_domains` happen sequentially, so
//! `parking_lot::Mutex` never contends (held only for brief map ops).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use dwaar_core::route::{Route, RouteTable};
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use tokio::sync::Notify;
use tracing::{debug, error, info, warn};

use crate::client::{DockerClient, DockerError};
use crate::labels;

/// Watches the Docker daemon for containers with `dwaar.*` labels and
/// maintains a merged route table combining Dwaarfile and Docker routes.
#[derive(Debug)]
pub struct DockerWatcher {
    client: DockerClient,
    route_table: Arc<ArcSwap<RouteTable>>,
    dwaarfile_routes: Arc<ArcSwap<Vec<Route>>>,
    config_notify: Arc<Notify>,
    /// Docker routes keyed by domain. Single-writer (event loop), so the
    /// mutex never contends — it exists only for interior mutability from `&self`.
    docker_routes: parking_lot::Mutex<HashMap<String, Route>>,
    /// Reverse map: container ID -> domain, for efficient cleanup on `die` events.
    container_domains: parking_lot::Mutex<HashMap<String, String>>,
}

impl DockerWatcher {
    pub fn new(
        socket_path: PathBuf,
        route_table: Arc<ArcSwap<RouteTable>>,
        dwaarfile_routes: Arc<ArcSwap<Vec<Route>>>,
        config_notify: Arc<Notify>,
    ) -> Self {
        Self {
            client: DockerClient::new(socket_path),
            route_table,
            dwaarfile_routes,
            config_notify,
            docker_routes: parking_lot::Mutex::new(HashMap::new()),
            container_domains: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    /// Discover all running containers with `dwaar.domain` labels and
    /// populate the internal maps. Called on startup and after reconnection.
    async fn bootstrap(&self) -> Result<(), DockerError> {
        let containers = self.client.list_containers("dwaar.domain").await?;
        info!(count = containers.len(), "bootstrapping Docker containers");

        // Clear stale state from any previous connection
        self.docker_routes.lock().clear();
        self.container_domains.lock().clear();

        for container in &containers {
            let Some(id) = container.get("Id").and_then(|v| v.as_str()) else {
                warn!("container listing entry missing Id field — skipping");
                continue;
            };

            match self.client.inspect_container(id).await {
                Ok(inspect) => {
                    if let Some(cr) = labels::parse_container(&inspect) {
                        debug!(
                            container_id = %cr.container_id,
                            domain = %cr.route.domain,
                            upstream = %cr.route.upstream,
                            "discovered Docker route"
                        );
                        let mut docker = self.docker_routes.lock();
                        let mut domains = self.container_domains.lock();
                        if docker.contains_key(&cr.route.domain) {
                            warn!(
                                domain = %cr.route.domain,
                                container_id = %cr.container_id,
                                "duplicate Docker domain — keeping first container"
                            );
                        } else {
                            domains.insert(cr.container_id.clone(), cr.route.domain.clone());
                            docker.insert(cr.route.domain.clone(), cr.route);
                        }
                    }
                }
                Err(e) => {
                    warn!(container_id = %id, error = %e, "failed to inspect container — skipping");
                }
            }
        }

        self.merge_and_store();
        Ok(())
    }

    /// Handle a container `start` event: inspect, parse labels, add route.
    async fn handle_start(&self, container_id: &str) {
        debug!(container_id, "container start event");

        let inspect = match self.client.inspect_container(container_id).await {
            Ok(v) => v,
            Err(e) => {
                warn!(container_id, error = %e, "failed to inspect started container");
                return;
            }
        };

        let Some(cr) = labels::parse_container(&inspect) else {
            debug!(container_id, "started container has no valid dwaar labels");
            return;
        };

        info!(
            container_id = %cr.container_id,
            domain = %cr.route.domain,
            upstream = %cr.route.upstream,
            "adding Docker route"
        );

        let mut docker = self.docker_routes.lock();
        let mut domains = self.container_domains.lock();

        if docker.contains_key(&cr.route.domain) {
            warn!(
                domain = %cr.route.domain,
                container_id = %cr.container_id,
                "duplicate Docker domain — keeping existing container"
            );
            return;
        }

        domains.insert(cr.container_id.clone(), cr.route.domain.clone());
        docker.insert(cr.route.domain.clone(), cr.route);

        // Drop locks before merge (merge acquires docker_routes lock)
        drop(docker);
        drop(domains);

        self.merge_and_store();
    }

    /// Handle a container `die` event: remove route by container ID.
    fn handle_die(&self, container_id: &str) {
        debug!(container_id, "container die event");

        let domain = {
            let mut domains = self.container_domains.lock();
            domains.remove(container_id)
        };

        let Some(domain) = domain else {
            debug!(container_id, "unknown container died — not tracked");
            return;
        };

        info!(container_id, domain = %domain, "removing Docker route");
        self.docker_routes.lock().remove(&domain);
        self.merge_and_store();
    }

    /// Merge Dwaarfile routes with Docker routes. Dwaarfile wins on conflict.
    fn merge_and_store(&self) {
        let dwaarfile = self.dwaarfile_routes.load();
        let docker = self.docker_routes.lock();

        let dwaarfile_routes: &[Route] = dwaarfile.as_ref();
        let dwaarfile_domains: std::collections::HashSet<&str> =
            dwaarfile_routes.iter().map(|r| r.domain.as_str()).collect();

        let mut merged: Vec<Route> = dwaarfile_routes.to_vec();
        for (domain, route) in docker.iter() {
            if dwaarfile_domains.contains(domain.as_str()) {
                warn!(domain, "Docker route shadowed by Dwaarfile");
            } else {
                merged.push(route.clone());
            }
        }

        let count = merged.len();
        self.route_table.store(Arc::new(RouteTable::new(merged)));
        debug!(routes = count, "route table updated");
    }

    /// Main event loop: bootstrap, stream events, handle reconnection.
    ///
    /// Returns `Ok(())` on clean shutdown, `Err` on stream/connection failure
    /// (caller handles backoff and retry).
    async fn run_loop(&self, shutdown: &ShutdownWatch) -> Result<(), DockerError> {
        self.bootstrap().await?;

        let mut stream = self.client.stream_events().await?;
        info!("connected to Docker event stream");

        loop {
            tokio::select! {
                biased;

                // Shutdown takes highest priority
                () = shutdown_signal(shutdown) => {
                    info!("Docker watcher shutting down");
                    return Ok(());
                }

                // Dwaarfile changed — re-merge with current Docker routes
                () = self.config_notify.notified() => {
                    debug!("Dwaarfile changed — re-merging routes");
                    self.merge_and_store();
                }

                // Next Docker event
                event = stream.next_event() => {
                    match event {
                        Some(Ok(value)) => {
                            self.dispatch_event(&value).await;
                        }
                        Some(Err(e)) => {
                            return Err(e);
                        }
                        None => {
                            // Stream closed (EOF) — treat as reconnectable error
                            return Err(DockerError::Io(std::io::Error::new(
                                std::io::ErrorKind::ConnectionReset,
                                "Docker event stream closed unexpectedly",
                            )));
                        }
                    }
                }
            }
        }
    }

    /// Extract `Action` and `Actor.ID` from a Docker event and dispatch.
    async fn dispatch_event(&self, event: &serde_json::Value) {
        let action = event.get("Action").and_then(|v| v.as_str()).unwrap_or("");
        let actor_id = event
            .pointer("/Actor/ID")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if actor_id.is_empty() {
            warn!("Docker event missing Actor.ID — ignoring");
            return;
        }

        match action {
            "start" => self.handle_start(actor_id).await,
            "die" => self.handle_die(actor_id),
            other => debug!(action = other, "ignoring unfiltered Docker event"),
        }
    }
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

#[async_trait]
impl BackgroundService for DockerWatcher {
    async fn start(&self, shutdown: ShutdownWatch) {
        info!(
            socket = %self.client.socket_path().display(),
            "Docker watcher started"
        );

        let mut backoff = Duration::from_secs(1);
        let max_backoff = Duration::from_secs(30);

        loop {
            if *shutdown.borrow() {
                return;
            }

            match self.run_loop(&shutdown).await {
                Ok(()) => return, // clean shutdown
                Err(e) => {
                    error!(
                        error = %e,
                        backoff_secs = backoff.as_secs(),
                        "Docker watcher error, reconnecting"
                    );

                    // Wait for backoff or shutdown, whichever comes first
                    tokio::select! {
                        biased;
                        () = shutdown_signal(&shutdown) => return,
                        () = tokio::time::sleep(backoff) => {}
                    }

                    backoff = (backoff * 2).min(max_backoff);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn make_watcher() -> DockerWatcher {
        let route_table = Arc::new(ArcSwap::from_pointee(RouteTable::new(vec![])));
        let dwaarfile_routes = Arc::new(ArcSwap::from_pointee(vec![]));
        let config_notify = Arc::new(Notify::new());
        DockerWatcher::new(
            PathBuf::from("/var/run/docker.sock"),
            route_table,
            dwaarfile_routes,
            config_notify,
        )
    }

    #[test]
    fn merge_adds_docker_route() {
        let watcher = make_watcher();
        {
            let mut docker = watcher.docker_routes.lock();
            docker.insert(
                "docker.example.com".to_string(),
                Route::new("docker.example.com", addr(8080), false, None),
            );
        }
        watcher.merge_and_store();
        let table = watcher.route_table.load();
        assert!(table.resolve("docker.example.com").is_some());
    }

    #[test]
    fn merge_dwaarfile_shadows_docker() {
        let watcher = make_watcher();
        watcher
            .dwaarfile_routes
            .store(Arc::new(vec![Route::new(
                "example.com",
                addr(3000),
                true,
                None,
            )]));
        {
            let mut docker = watcher.docker_routes.lock();
            docker.insert(
                "example.com".to_string(),
                Route::new("example.com", addr(9000), false, None),
            );
        }
        watcher.merge_and_store();
        let table = watcher.route_table.load();
        let route = table.resolve("example.com").expect("should resolve");
        assert_eq!(route.upstream.port(), 3000); // Dwaarfile wins
        assert!(route.tls);
    }

    #[test]
    fn handle_die_removes_route() {
        let watcher = make_watcher();
        {
            let mut docker = watcher.docker_routes.lock();
            docker.insert(
                "app.example.com".to_string(),
                Route::new("app.example.com", addr(8080), false, None),
            );
            let mut domains = watcher.container_domains.lock();
            domains.insert("container123".to_string(), "app.example.com".to_string());
        }
        watcher.merge_and_store();
        assert!(
            watcher
                .route_table
                .load()
                .resolve("app.example.com")
                .is_some()
        );

        watcher.handle_die("container123");
        assert!(
            watcher
                .route_table
                .load()
                .resolve("app.example.com")
                .is_none()
        );
    }

    #[test]
    fn handle_die_unknown_container_is_noop() {
        let watcher = make_watcher();
        {
            let mut docker = watcher.docker_routes.lock();
            docker.insert(
                "app.example.com".to_string(),
                Route::new("app.example.com", addr(8080), false, None),
            );
        }
        watcher.merge_and_store();

        // Dying container we don't track shouldn't affect existing routes
        watcher.handle_die("unknown_container");
        assert!(
            watcher
                .route_table
                .load()
                .resolve("app.example.com")
                .is_some()
        );
    }

    #[test]
    fn duplicate_domain_first_wins() {
        let watcher = make_watcher();
        {
            let mut docker = watcher.docker_routes.lock();
            docker.insert(
                "app.com".to_string(),
                Route::new("app.com", addr(8080), false, None),
            );
            let mut domains = watcher.container_domains.lock();
            domains.insert("container1".to_string(), "app.com".to_string());
        }
        // HashMap ensures one entry per domain — inserting again overwrites,
        // but handle_start checks for duplicates before inserting
        watcher.merge_and_store();
        assert_eq!(
            watcher
                .route_table
                .load()
                .resolve("app.com")
                .expect("should resolve")
                .upstream
                .port(),
            8080
        );
    }

    #[test]
    fn merge_preserves_multiple_docker_routes() {
        let watcher = make_watcher();
        {
            let mut docker = watcher.docker_routes.lock();
            docker.insert(
                "a.example.com".to_string(),
                Route::new("a.example.com", addr(8001), false, None),
            );
            docker.insert(
                "b.example.com".to_string(),
                Route::new("b.example.com", addr(8002), true, Some(50)),
            );
        }
        watcher.merge_and_store();
        let table = watcher.route_table.load();
        assert_eq!(table.len(), 2);

        let a = table.resolve("a.example.com").expect("a should resolve");
        assert_eq!(a.upstream.port(), 8001);
        assert!(!a.tls);

        let b = table.resolve("b.example.com").expect("b should resolve");
        assert_eq!(b.upstream.port(), 8002);
        assert!(b.tls);
        assert_eq!(b.rate_limit_rps, Some(50));
    }

    #[test]
    fn merge_combines_dwaarfile_and_docker() {
        let watcher = make_watcher();
        watcher.dwaarfile_routes.store(Arc::new(vec![
            Route::new("static.example.com", addr(3000), true, None),
        ]));
        {
            let mut docker = watcher.docker_routes.lock();
            docker.insert(
                "api.example.com".to_string(),
                Route::new("api.example.com", addr(8080), false, None),
            );
        }
        watcher.merge_and_store();
        let table = watcher.route_table.load();
        assert_eq!(table.len(), 2);
        assert!(table.resolve("static.example.com").is_some());
        assert!(table.resolve("api.example.com").is_some());
    }

    #[test]
    fn empty_maps_produce_empty_table() {
        let watcher = make_watcher();
        watcher.merge_and_store();
        assert!(watcher.route_table.load().is_empty());
    }
}
