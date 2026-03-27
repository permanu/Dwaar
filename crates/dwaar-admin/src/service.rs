// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Admin API service implementing Pingora's `ServeHttp`.

use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use dashmap::DashMap;
use dwaar_analytics::aggregation::DomainMetrics;
use dwaar_core::route::RouteTable;
use http::Response;
use pingora_core::apps::http_app::ServeHttp;
use pingora_core::protocols::http::ServerSession;
use tracing::{debug, info, warn};

use crate::auth::Auth;
use crate::handlers;

/// Maximum request body size (64 KB).
const MAX_BODY_SIZE: usize = 65_536;

/// The admin API service.
#[allow(missing_debug_implementations)]
pub struct AdminService {
    route_table: Arc<ArcSwap<RouteTable>>,
    metrics: Arc<DashMap<String, DomainMetrics>>,
    start_time: Instant,
    auth: Auth,
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
        }
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
        debug!(source, method = %method, path = %path, "admin request");

        // Health check — no auth required
        if method == "GET" && path == "/health" {
            debug!(source, "health check");
            return json_response(200, &handlers::health(&self.start_time));
        }

        // UDS connections are trusted — OS filesystem permissions on the socket
        // file control access. TCP connections require a bearer token.
        if !is_uds && let Err(reason) = self.auth.check(&auth_header) {
            warn!(source, reason, "admin auth failed");
            return json_response(401, r#"{"error":"unauthorized"}"#);
        }

        match (method.as_str(), path.as_str()) {
            ("GET", "/routes") => match handlers::list_routes(&self.route_table) {
                Ok(json) => json_response(200, &json),
                Err(e) => json_response(500, &format!(r#"{{"error":"{e}"}}"#)),
            },
            ("POST", "/routes") => {
                let body = read_body(session, MAX_BODY_SIZE).await;
                match body {
                    Err((status, msg)) => json_response(status, &format!(r#"{{"error":"{msg}"}}"#)),
                    Ok(data) => match handlers::add_route(&self.route_table, &data) {
                        Ok(json) => {
                            info!(source, "route added/updated via admin API");
                            json_response(201, &json)
                        }
                        Err(e) => json_response(400, &format!(r#"{{"error":"{e}"}}"#)),
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
                        json_response(200, &format!(r#"{{"deleted":"{deleted}"}}"#))
                    }
                    None => json_response(404, r#"{"error":"route not found"}"#),
                }
            }
            ("GET", "/analytics") => match handlers::list_all_analytics(&self.metrics) {
                Ok(json) => json_response(200, &json),
                Err(e) => json_response(500, &format!(r#"{{"error":"{e}"}}"#)),
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
            _ => json_response(405, r#"{"error":"method not allowed"}"#),
        }
    }
}

/// Build a JSON HTTP response.
fn json_response(status: u16, body: &str) -> Response<Vec<u8>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(body.as_bytes().to_vec())
        .expect("valid response")
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
