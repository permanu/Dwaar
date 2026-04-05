// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Admin API service implementing Pingora's `ServeHttp`.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use dashmap::DashMap;
use dwaar_analytics::aggregation::DomainMetrics;
use dwaar_analytics::prometheus::PrometheusMetrics;
use dwaar_core::route::RouteTable;
use http::Response;
use pingora_core::apps::http_app::ServeHttp;
use pingora_core::protocols::http::ServerSession;
use tokio::sync::Notify;
use tracing::{debug, info, warn};

use crate::auth::Auth;
use crate::handlers;

/// Maximum request body size (64 KB).
const MAX_BODY_SIZE: usize = 65_536;

/// Rate limit: at most this many requests per window before returning 429.
const RATE_LIMIT_MAX: u64 = 60;
/// Rate limit window length in seconds.
const RATE_LIMIT_WINDOW_SECS: u64 = 60;
/// Minimum seconds between consecutive `/reload` triggers.
const RELOAD_COOLDOWN_SECS: u64 = 5;

/// The admin API service.
pub struct AdminService {
    route_table: Arc<ArcSwap<RouteTable>>,
    metrics: Arc<DashMap<String, DomainMetrics>>,
    start_time: Instant,
    auth: Auth,
    /// Notifier to trigger config reload. When signaled, the `ConfigWatcher`
    /// re-reads the Dwaarfile and updates the route table.
    reload_notify: Option<Arc<Notify>>,
    /// Prometheus metrics registry. When set, `GET /metrics` serves the
    /// Prometheus text exposition format.
    prometheus: Option<Arc<PrometheusMetrics>>,
    /// Cache backend for PURGE endpoint (ISSUE-073, ISSUE-111 hot-reload).
    /// Reads from `ArcSwap` per request so it targets the current backend.
    cache_backend: Option<dwaar_core::cache::SharedCacheBackend>,
    /// Number of authenticated requests seen in the current rate-limit window.
    request_count: AtomicU64,
    /// Start of the current rate-limit window as Unix epoch seconds.
    window_start: AtomicU64,
    /// Unix epoch seconds when `/reload` was last successfully triggered.
    last_reload: AtomicU64,
}

impl std::fmt::Debug for AdminService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminService")
            .field("reload_notify", &self.reload_notify.is_some())
            .field("prometheus", &self.prometheus.is_some())
            .field("cache_backend", &self.cache_backend.is_some())
            .finish_non_exhaustive()
    }
}

impl AdminService {
    pub fn new(
        route_table: Arc<ArcSwap<RouteTable>>,
        metrics: Arc<DashMap<String, DomainMetrics>>,
        start_time: Instant,
        admin_token: Option<String>,
    ) -> Self {
        if admin_token.is_none() {
            warn!("DWAAR_ADMIN_TOKEN not set — admin API will reject all authenticated requests");
        }
        Self {
            route_table,
            metrics,
            start_time,
            auth: Auth::new(admin_token),
            reload_notify: None,
            prometheus: None,
            cache_backend: None,
            request_count: AtomicU64::new(0),
            window_start: AtomicU64::new(0),
            last_reload: AtomicU64::new(0),
        }
    }

    /// Set the reload notifier for `POST /reload` support.
    #[must_use]
    pub fn with_reload_notify(mut self, notify: Arc<Notify>) -> Self {
        self.reload_notify = Some(notify);
        self
    }

    /// Enable the Prometheus `/metrics` endpoint.
    #[must_use]
    pub fn with_prometheus(mut self, prom: Arc<PrometheusMetrics>) -> Self {
        self.prometheus = Some(prom);
        self
    }

    /// Attach the shared cache backend for the `PURGE /cache/{host}/{path}` endpoint.
    #[must_use]
    pub fn with_cache_backend(mut self, backend: dwaar_core::cache::SharedCacheBackend) -> Self {
        self.cache_backend = Some(backend);
        self
    }

    /// Check global rate limit. Returns `Err(Response)` with a 429 if the
    /// caller has exceeded 60 authenticated requests per 60-second window.
    ///
    /// Uses a single global counter — the admin API is low-traffic and does
    /// not need per-IP accounting. The window resets atomically when it expires.
    fn check_rate_limit(&self) -> Result<(), Box<Response<Vec<u8>>>> {
        let now = epoch_secs();
        let window = self.window_start.load(Ordering::Relaxed);
        if now.saturating_sub(window) >= RATE_LIMIT_WINDOW_SECS {
            // Try to atomically claim the window reset.
            // If another thread races us, only one succeeds — the loser
            // falls through to the counter check which is safe.
            if self
                .window_start
                .compare_exchange(window, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                self.request_count.store(1, Ordering::Relaxed);
                return Ok(());
            }
        }
        let count = self.request_count.fetch_add(1, Ordering::Relaxed) + 1;
        if count > RATE_LIMIT_MAX {
            return Err(Box::new(json_response(
                429,
                r#"{"error":"rate limit exceeded"}"#,
            )));
        }
        Ok(())
    }
}

/// Check whether a connection came over a Unix domain socket.
/// UDS connections are trusted because access is controlled by filesystem
/// permissions on the socket file — only processes with read/write on the
/// socket can connect.
///
/// Uses `server_addr()` (the local/bound address) because UDS clients
/// connect with unnamed sockets — `client_addr()` returns `None` for
/// them since `getpeername()` yields no path.
fn is_trusted_transport(session: &ServerSession) -> bool {
    session
        .server_addr()
        .and_then(|addr| addr.as_unix())
        .is_some()
}

#[async_trait]
impl ServeHttp for AdminService {
    async fn response(&self, session: &mut ServerSession) -> Response<Vec<u8>> {
        // Extract method/path/auth into owned Strings before any mutable borrows.
        // read_body() takes &mut session, so we can't hold references into req_header().
        let method = session.req_header().method.as_str().to_string();
        let path = session.req_header().uri.path().to_string();
        let auth_header = session
            .req_header()
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        let is_uds = is_trusted_transport(session);
        let source = if is_uds { "uds" } else { "tcp" };
        // Capture peer IP once for logging; unavailable on UDS (unnamed socket).
        let peer_ip = session
            .client_addr()
            .and_then(|a| a.as_inet())
            .map(|a| a.ip().to_string());
        debug!(source, method = %method, path = %path, "admin request");

        // Health check — no auth required
        if method == "GET" && path == "/health" {
            debug!(source, "health check");
            return json_response(200, &handlers::health(&self.start_time));
        }

        // UDS connections are trusted — OS filesystem permissions on the socket
        // file control access. TCP connections require a bearer token.
        if !is_uds && let Err(reason) = self.auth.check(&auth_header) {
            warn!(
                source,
                reason,
                peer = peer_ip.as_deref().unwrap_or("unknown"),
                "admin auth failed"
            );
            return json_response(401, r#"{"error":"unauthorized"}"#);
        }

        // Authenticated path — enforce global rate limit before dispatch.
        if let Err(resp) = self.check_rate_limit() {
            warn!(
                source,
                peer = peer_ip.as_deref().unwrap_or("unknown"),
                "admin rate limit exceeded"
            );
            return *resp;
        }

        self.dispatch(session, &method, &path, source).await
    }
}

impl AdminService {
    /// Route the authenticated request to the appropriate handler.
    #[allow(clippy::too_many_lines)]
    async fn dispatch(
        &self,
        session: &mut ServerSession,
        method: &str,
        path: &str,
        source: &str,
    ) -> Response<Vec<u8>> {
        match (method, path) {
            ("GET", "/routes") => match handlers::list_routes(&self.route_table) {
                Ok(json) => json_response(200, &json),
                Err(e) => json_error(500, &e),
            },
            ("POST", "/routes") => {
                let body = read_body(session, MAX_BODY_SIZE).await;
                match body {
                    Err((status, msg)) => json_error(status, &msg),
                    Ok(data) => match handlers::add_route(&self.route_table, &data) {
                        Ok(json) => {
                            info!(source, "route added/updated via admin API");
                            json_response(201, &json)
                        }
                        Err(e) => json_error(400, &e),
                    },
                }
            }
            ("DELETE", _) if path.starts_with("/routes/") => {
                let domain = path
                    .strip_prefix("/routes/")
                    .unwrap_or("")
                    .trim_end_matches('/');
                if domain.is_empty() {
                    return json_response(400, r#"{"error":"missing domain"}"#);
                }
                match handlers::delete_route(&self.route_table, domain) {
                    Some(deleted) => {
                        info!(source, domain = %deleted, "route deleted via admin API");
                        json_deleted(&deleted)
                    }
                    None => json_response(404, r#"{"error":"route not found"}"#),
                }
            }
            ("GET", "/analytics") => match handlers::list_all_analytics(&self.metrics) {
                Ok(json) => json_response(200, &json),
                Err(e) => json_error(500, &e),
            },
            ("GET", _) if path.starts_with("/analytics/") => {
                let domain = path
                    .strip_prefix("/analytics/")
                    .unwrap_or("")
                    .trim_end_matches('/');
                if domain.is_empty() || !dwaar_core::route::is_valid_domain(domain) {
                    return json_response(400, r#"{"error":"invalid domain"}"#);
                }
                let domain_lower = domain.to_lowercase();
                match handlers::get_domain_analytics(&self.metrics, &domain_lower) {
                    Some(json) => json_response(200, &json),
                    None => json_response(404, r#"{"error":"no analytics for domain"}"#),
                }
            }
            ("GET", "/metrics") => match &self.prometheus {
                Some(prom) => prometheus_response(&prom.render()),
                None => json_response(
                    404,
                    r#"{"error":"metrics not enabled — start with --no-metrics=false"}"#,
                ),
            },
            ("POST", "/reload") => match &self.reload_notify {
                Some(notify) => {
                    let now = epoch_secs();
                    let last = self.last_reload.load(Ordering::Relaxed);
                    let elapsed = now.saturating_sub(last);
                    if last != 0 && elapsed < RELOAD_COOLDOWN_SECS {
                        let remaining = RELOAD_COOLDOWN_SECS - elapsed;
                        return Response::builder()
                            .status(429)
                            .header("Content-Type", "application/json")
                            .header("Retry-After", remaining.to_string())
                            .body(
                                format!(
                                    r#"{{"error":"reload too soon","retry_after":{remaining}}}"#
                                )
                                .into_bytes(),
                            )
                            .expect("valid response");
                    }
                    self.last_reload.store(now, Ordering::Relaxed);
                    notify.notify_waiters();
                    info!(source, "config reload triggered via admin API");
                    json_response(200, r#"{"message":"config reload triggered"}"#)
                }
                None => json_response(
                    501,
                    r#"{"error":"reload not supported — config watcher not active"}"#,
                ),
            },
            ("PURGE", _) if path.starts_with("/cache/") => {
                let key_path = path
                    .strip_prefix("/cache/")
                    .unwrap_or("")
                    .trim_end_matches('/');
                if key_path.is_empty() {
                    return json_response(
                        400,
                        r#"{"error":"missing cache key — use PURGE /cache/{host}/{path}"}"#,
                    );
                }
                let storage = self
                    .cache_backend
                    .as_ref()
                    .and_then(|shared| {
                        let guard = shared.load();
                        guard.as_ref().as_ref().map(|b| b.storage)
                    });
                match storage {
                    Some(storage) => {
                        if handlers::purge_cache_key(storage, key_path).await {
                            info!(source, key = key_path, "cache entry purged");
                            json_response(200, r#"{"purged":true}"#)
                        } else {
                            json_response(404, r#"{"purged":false,"reason":"not found"}"#)
                        }
                    }
                    None => json_response(501, r#"{"error":"cache not enabled"}"#),
                }
            }
            _ => {
                // Add an Allow header so clients know which methods are valid
                // for this endpoint (RFC 9110 §15.5.6 requirement).
                let allow = allowed_methods_for(path);
                Response::builder()
                    .status(405)
                    .header("Content-Type", "application/json")
                    .header("Allow", allow)
                    .body(br#"{"error":"method not allowed"}"#.to_vec())
                    .expect("valid response")
            }
        }
    }
}

/// Return the `Allow` header value for a given path — used in 405 responses.
fn allowed_methods_for(path: &str) -> &'static str {
    if path == "/health" {
        "GET"
    } else if path == "/routes" {
        "GET, POST"
    } else if path.starts_with("/routes/") {
        "DELETE"
    } else if path == "/analytics" || path.starts_with("/analytics/") || path == "/metrics" {
        "GET"
    } else if path == "/reload" {
        "POST"
    } else if path.starts_with("/cache/") {
        "PURGE"
    } else {
        ""
    }
}

/// Build a `{"error": "…"}` JSON response, properly escaping the message.
///
/// Uses `serde_json` to escape any quotes or backslashes in the message so
/// injected strings can't break out of the JSON value.
fn json_error(status: u16, message: &str) -> Response<Vec<u8>> {
    let body = serde_json::json!({"error": message}).to_string();
    json_response(status, &body)
}

/// Build a `{"deleted": "…"}` JSON response, properly escaping the value.
fn json_deleted(domain: &str) -> Response<Vec<u8>> {
    let body = serde_json::json!({"deleted": domain}).to_string();
    json_response(200, &body)
}

/// Build a Prometheus text exposition response.
fn prometheus_response(body: &str) -> Response<Vec<u8>> {
    Response::builder()
        .status(200)
        .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        .body(body.as_bytes().to_vec())
        .expect("valid response")
}

/// Build a JSON HTTP response.
fn json_response(status: u16, body: &str) -> Response<Vec<u8>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .header("Content-Length", body.len())
        .body(body.as_bytes().to_vec())
        .expect("valid response")
}

/// Current Unix epoch time in whole seconds. Used for rate-limit windows and
/// reload cooldown tracking. Monotonicity is not required here — wall-clock
/// time is fine because we only care about elapsed seconds between events.
fn epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Read the request body up to `max_size` bytes.
async fn read_body(session: &mut ServerSession, max_size: usize) -> Result<Vec<u8>, (u16, String)> {
    let mut body = Vec::new();
    loop {
        match session.read_request_body().await {
            Ok(Some(chunk)) => {
                body.extend_from_slice(&chunk);
                if body.len() > max_size {
                    return Err((413, "request body too large".to_string()));
                }
            }
            Ok(None) => return Ok(body),
            Err(e) => return Err((400, format!("failed to read body: {e}"))),
        }
    }
}
