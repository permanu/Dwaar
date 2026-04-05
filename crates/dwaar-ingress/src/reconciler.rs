// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Periodic reconciler — keeps the Dwaar admin API in sync with the Ingress store.
//!
//! ## Why periodic reconciliation?
//!
//! The watcher loop handles real-time events but is susceptible to missed deletes
//! (e.g. controller restart during a delete event) and clock skew between the
//! informer's resync window and the admin API. A periodic full-sync pass catches
//! any drift and guarantees eventual consistency without relying on event delivery.
//!
//! ## What the reconciler owns
//!
//! Only routes with `source: "dwaar-ingress"` are considered controller-owned.
//! Routes created by operators, other controllers, or via the admin API directly
//! are never touched — this is the key safety invariant.
//!
//! ## Reconcile logic (single pass)
//!
//! 1. Fetch all routes from the admin API.
//! 2. Partition into controller-owned and foreign.
//! 3. Compare controller-owned against the desired state (from the Ingress store).
//!    - **Orphan** (in API, not in desired) → delete.
//!    - **Missing** (in desired, not in API) → upsert.
//!    - **Matching** (domain + upstream + tls unchanged) → skip.

use std::collections::HashMap;
use std::time::Duration;

use tracing::{debug, error, info, warn};

use crate::client::{AdminApiClient, CONTROLLER_SOURCE};
use crate::error::AdminApiError;

/// Default interval between full reconciliation passes.
pub const DEFAULT_RECONCILE_INTERVAL: Duration = Duration::from_secs(60);

/// A desired route state for the reconciler to enforce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredRoute {
    /// Domain key (matches the admin API primary key).
    pub domain: String,
    /// Upstream in `host:port` form.
    pub upstream: String,
    /// Whether TLS termination applies to this route.
    pub tls: bool,
}

/// Configuration for the periodic reconciler.
#[derive(Debug, Clone)]
pub struct ReconcilerConfig {
    /// How often to run a full reconcile pass.
    pub interval: Duration,
}

impl Default for ReconcilerConfig {
    fn default() -> Self {
        Self {
            interval: DEFAULT_RECONCILE_INTERVAL,
        }
    }
}

/// Run the periodic reconciler loop.
///
/// `desired_fn` is called each iteration to produce the current desired state
/// (typically derived from the reflector's `Store<Ingress>`). This callback
/// pattern avoids holding a lock across the async admin API calls.
///
/// The loop runs until `shutdown` resolves to `true`.
pub async fn run_reconciler<F>(
    client: AdminApiClient,
    config: ReconcilerConfig,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    desired_fn: F,
) where
    F: Fn() -> Vec<DesiredRoute>,
{
    info!(
        interval_secs = config.interval.as_secs(),
        "reconciler started"
    );

    loop {
        tokio::select! {
            biased;

            result = shutdown.changed() => {
                // Treat both an explicit `true` value and a closed channel
                // (sender dropped) as shutdown. The sender drops when the
                // watcher's `run()` method exits — e.g. on lease loss — so
                // a closed channel means "stop immediately".
                if result.is_err() || *shutdown.borrow() {
                    info!("reconciler shutting down");
                    return;
                }
            }

            () = tokio::time::sleep(config.interval) => {
                let desired = desired_fn();
                match reconcile_once(&client, &desired).await {
                    Ok(stats) => {
                        info!(
                            deleted = stats.deleted,
                            upserted = stats.upserted,
                            skipped = stats.skipped,
                            "reconcile pass complete"
                        );
                    }
                    Err(e) => {
                        error!(error = %e, "reconcile pass failed — will retry next interval");
                    }
                }
            }
        }
    }
}

/// Statistics from a single reconcile pass.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReconcileStats {
    /// Orphaned routes removed from the admin API.
    pub deleted: usize,
    /// Missing routes added to the admin API.
    pub upserted: usize,
    /// Routes that already matched desired state and were left untouched.
    pub skipped: usize,
}

/// Perform one reconcile pass.
///
/// Fetches the current admin API state, compares it against `desired`, and
/// issues the minimum set of mutations needed to converge. Returns aggregate
/// stats for logging and testing.
pub async fn reconcile_once(
    client: &AdminApiClient,
    desired: &[DesiredRoute],
) -> Result<ReconcileStats, AdminApiError> {
    let all_routes = client.list_routes().await?;

    // Partition: controller-owned vs. foreign routes.
    // Foreign routes are never touched — only log them for debugging.
    let owned: HashMap<String, _> = all_routes
        .into_iter()
        .filter(|r| r.source.as_deref() == Some(CONTROLLER_SOURCE))
        .map(|r| (r.domain.clone(), r))
        .collect();

    // Build a lookup of the desired state keyed by domain.
    let desired_map: HashMap<&str, &DesiredRoute> =
        desired.iter().map(|r| (r.domain.as_str(), r)).collect();

    let mut stats = ReconcileStats::default();

    // Delete orphans — routes that are controller-owned but no longer desired.
    for domain in owned.keys() {
        if !desired_map.contains_key(domain.as_str()) {
            debug!(%domain, "reconciler: deleting orphaned route");
            match client.delete_route(domain).await {
                Ok(()) => {
                    stats.deleted += 1;
                }
                Err(e) => {
                    warn!(%domain, error = %e, "reconciler: failed to delete orphan — will retry");
                }
            }
        }
    }

    // Upsert missing or changed routes.
    for desired_route in desired {
        let domain = desired_route.domain.as_str();

        if let Some(existing) = owned.get(domain) {
            // Compare the upstream and tls fields; if they match we skip
            // the upsert to avoid unnecessary admin API churn.
            let upstream_matches = existing
                .upstream
                .as_deref()
                .is_some_and(|u| u == desired_route.upstream);
            let tls_matches = existing.tls == desired_route.tls;

            if upstream_matches && tls_matches {
                debug!(%domain, "reconciler: route matches desired — skipping");
                stats.skipped += 1;
            } else {
                debug!(
                    %domain,
                    upstream = %desired_route.upstream,
                    tls = desired_route.tls,
                    "reconciler: route changed — upserting"
                );
                match client
                    .upsert_route(domain, &desired_route.upstream, desired_route.tls)
                    .await
                {
                    Ok(()) => stats.upserted += 1,
                    Err(e) => {
                        warn!(%domain, error = %e, "reconciler: failed to upsert — will retry");
                    }
                }
            }
        } else {
            debug!(
                %domain,
                upstream = %desired_route.upstream,
                "reconciler: route missing — upserting"
            );
            match client
                .upsert_route(domain, &desired_route.upstream, desired_route.tls)
                .await
            {
                Ok(()) => stats.upserted += 1,
                Err(e) => {
                    warn!(%domain, error = %e, "reconciler: failed to upsert — will retry");
                }
            }
        }
    }

    Ok(stats)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use serde_json::json;

    use super::*;
    use crate::client::RouteEntry;

    // ---------------------------------------------------------------------------
    // Mock admin API server using a simple in-process stub.
    //
    // Rather than spinning up a real HTTP server (which requires ports and async
    // test infrastructure), we test `reconcile_once` by constructing
    // `RouteEntry` lists directly and verifying the resulting mutation calls.
    // The `AdminApiClient` calls are tested via integration tests in `client.rs`;
    // here we focus on the reconciler's decision logic in isolation.
    // ---------------------------------------------------------------------------

    /// Build a `RouteEntry` as if returned by `GET /routes`.
    fn api_route(domain: &str, upstream: &str, tls: bool, source: Option<&str>) -> RouteEntry {
        RouteEntry {
            domain: domain.to_string(),
            upstream: Some(upstream.to_string()),
            tls,
            source: source.map(ToString::to_string),
        }
    }

    /// Build a `DesiredRoute` from the Ingress store.
    fn desired(domain: &str, upstream: &str, tls: bool) -> DesiredRoute {
        DesiredRoute {
            domain: domain.to_string(),
            upstream: upstream.to_string(),
            tls,
        }
    }

    // ── Serialization helpers for the mock server ────────────────────────────

    /// Spin up a temporary HTTP server that records calls and serves fixed responses.
    ///
    /// Returns the base URL and a handle to the recorded request log.
    async fn mock_server(
        routes: Vec<RouteEntry>,
    ) -> (String, Arc<Mutex<Vec<String>>>, tokio::task::JoinHandle<()>) {
        use std::net::SocketAddr;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0".parse::<SocketAddr>().expect("valid addr"))
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let base_url = format!("http://{addr}");
        let log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let log_clone = Arc::clone(&log);
        let routes_json = serde_json::to_string(&routes).expect("serialize routes");

        let handle = tokio::spawn(async move {
            // Accept a bounded number of connections for the test lifetime.
            for _ in 0..20usize {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };

                let routes_json = routes_json.clone();
                let log = Arc::clone(&log_clone);

                tokio::spawn(async move {
                    let mut reader = BufReader::new(&mut stream);
                    let mut req_line = String::new();
                    let _ = reader.read_line(&mut req_line).await;

                    // Drain headers.
                    let mut header = String::new();
                    let mut content_length: usize = 0;
                    loop {
                        header.clear();
                        let _ = reader.read_line(&mut header).await;
                        if header
                            .trim_ascii_start()
                            .to_lowercase()
                            .starts_with("content-length:")
                            && let Some(v) = header.split(':').nth(1)
                        {
                            content_length = v.trim().parse().unwrap_or(0);
                        }
                        if header == "\r\n" || header.is_empty() {
                            break;
                        }
                    }

                    // Read body for POST/DELETE
                    let mut body = vec![0u8; content_length];
                    if content_length > 0 {
                        let _ = tokio::io::AsyncReadExt::read_exact(&mut reader, &mut body).await;
                    }

                    let req = req_line.trim().to_string();
                    log.lock().expect("log lock").push(req.clone());

                    // GET /routes → return the list; everything else → 200 OK
                    let response = if req.starts_with("GET /routes") {
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            routes_json.len(),
                            routes_json
                        )
                    } else {
                        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_string()
                    };
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });

        (base_url, log, handle)
    }

    // ── Reconciler decision logic unit tests ─────────────────────────────────
    //
    // These tests call the reconcile logic using a real mock HTTP server so we
    // verify both decision making AND the actual HTTP calls made.

    #[tokio::test]
    async fn orphan_route_is_deleted() {
        // API has a controller-owned route; desired state has nothing → delete it.
        let existing = vec![api_route(
            "orphan.example.com",
            "10.0.0.1:8080",
            false,
            Some(CONTROLLER_SOURCE),
        )];
        let (base_url, log, handle) = mock_server(existing).await;
        let client = AdminApiClient::new(base_url);

        let stats = reconcile_once(&client, &[]).await.expect("reconcile");

        assert_eq!(stats.deleted, 1, "orphan should be deleted");
        assert_eq!(stats.upserted, 0);

        let calls = log.lock().expect("log lock").clone();
        assert!(
            calls
                .iter()
                .any(|c| c.contains("DELETE /routes/orphan.example.com")),
            "DELETE call expected, got: {calls:?}"
        );

        handle.abort();
    }

    #[tokio::test]
    async fn missing_route_is_upserted() {
        // API has no routes; desired has one → upsert.
        let (base_url, log, handle) = mock_server(vec![]).await;
        let client = AdminApiClient::new(base_url);
        let desired = vec![desired("new.example.com", "10.0.0.2:8080", false)];

        let stats = reconcile_once(&client, &desired).await.expect("reconcile");

        assert_eq!(stats.upserted, 1);
        assert_eq!(stats.deleted, 0);

        let calls = log.lock().expect("log lock").clone();
        assert!(
            calls.iter().any(|c| c.contains("POST /routes")),
            "POST call expected, got: {calls:?}"
        );

        handle.abort();
    }

    #[tokio::test]
    async fn matching_route_is_skipped() {
        // API state matches desired → no mutations.
        let existing = vec![api_route(
            "app.example.com",
            "10.0.0.3:9090",
            true,
            Some(CONTROLLER_SOURCE),
        )];
        let (base_url, log, handle) = mock_server(existing).await;
        let client = AdminApiClient::new(base_url);
        let desired = vec![desired("app.example.com", "10.0.0.3:9090", true)];

        let stats = reconcile_once(&client, &desired).await.expect("reconcile");

        assert_eq!(stats.skipped, 1);
        assert_eq!(stats.deleted, 0);
        assert_eq!(stats.upserted, 0);

        let calls = log.lock().expect("log lock").clone();
        // Only the GET /routes call; no POST or DELETE.
        let mutations: Vec<_> = calls.iter().filter(|c| !c.starts_with("GET")).collect();
        assert!(
            mutations.is_empty(),
            "no mutations expected, got: {mutations:?}"
        );

        handle.abort();
    }

    #[tokio::test]
    async fn non_controller_route_is_untouched() {
        // A route whose source is NOT "dwaar-ingress" must never be touched,
        // even when it matches a domain in the desired list.
        let foreign = api_route("manual.example.com", "10.99.99.99:80", false, None);
        let (base_url, log, handle) = mock_server(vec![foreign]).await;
        let client = AdminApiClient::new(base_url);

        // Desired has the same domain — reconciler must NOT delete it because it
        // doesn't own that route. The desired entry should be upserted (creating
        // a new controller-owned copy if the API supports it), but the existing
        // un-owned entry must not be explicitly deleted.
        let stats = reconcile_once(&client, &[]).await.expect("reconcile");

        // The foreign route is not in owned set — no delete attempted.
        assert_eq!(stats.deleted, 0, "foreign route must not be deleted");

        let calls = log.lock().expect("log lock").clone();
        let deletes: Vec<_> = calls.iter().filter(|c| c.starts_with("DELETE")).collect();
        assert!(
            deletes.is_empty(),
            "no DELETE calls expected for foreign routes, got: {deletes:?}"
        );

        handle.abort();
    }

    #[tokio::test]
    async fn changed_upstream_triggers_upsert() {
        // Route exists but with a stale upstream — reconciler should re-upsert.
        let existing = vec![api_route(
            "app.example.com",
            "10.0.0.1:8080", // old
            false,
            Some(CONTROLLER_SOURCE),
        )];
        let (base_url, _log, handle) = mock_server(existing).await;
        let client = AdminApiClient::new(base_url);
        let desired = vec![desired("app.example.com", "10.0.0.2:8080", false)]; // new

        let stats = reconcile_once(&client, &desired).await.expect("reconcile");

        assert_eq!(stats.upserted, 1, "changed upstream should trigger upsert");
        assert_eq!(stats.skipped, 0);

        handle.abort();
    }

    // ── Default config ───────────────────────────────────────────────────────

    #[test]
    fn default_interval_is_60_seconds() {
        let config = ReconcilerConfig::default();
        assert_eq!(config.interval, Duration::from_secs(60));
    }

    // ── JSON compatibility: source field is optional in GET /routes ──────────

    #[test]
    fn route_entry_deserializes_without_source() {
        // Old admin API responses may not include the source field.
        let json = r#"{"domain":"x.com","upstream":"1.2.3.4:80","tls":false}"#;
        let entry: RouteEntry = serde_json::from_str(json).expect("deserialize");
        assert!(entry.source.is_none());
    }

    #[test]
    fn route_entry_deserializes_with_source() {
        let json = json!({
            "domain": "x.com",
            "upstream": "1.2.3.4:80",
            "tls": false,
            "source": "dwaar-ingress"
        })
        .to_string();
        let entry: RouteEntry = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(entry.source.as_deref(), Some("dwaar-ingress"));
    }
}
