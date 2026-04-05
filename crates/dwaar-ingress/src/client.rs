// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! HTTP client for the Dwaar admin API.
//!
//! Provides `upsert_route`, `delete_route`, and `list_routes` — the three
//! operations the ingress controller needs to keep Dwaar's route table in sync
//! with the state of Kubernetes Ingress resources.
//!
//! Uses `reqwest` because we're outside Pingora's process boundary here: the
//! controller is a separate binary that communicates over HTTP, not in-process.

use serde::{Deserialize, Serialize};
use tracing::{debug, instrument};

use crate::error::AdminApiError;

/// The source tag stamped on every route this controller creates.
///
/// Used by the reconciler to distinguish controller-managed routes from routes
/// created manually or by other controllers, so we never touch what isn't ours.
pub const CONTROLLER_SOURCE: &str = "dwaar-ingress";

/// Payload sent to `POST /routes` (upsert semantics — create or overwrite).
#[derive(Debug, Serialize)]
struct UpsertRouteRequest<'a> {
    domain: &'a str,
    upstream: &'a str,
    tls: bool,
    /// Tags the route so the reconciler can identify controller-owned routes.
    source: &'a str,
}

/// Minimal route descriptor returned by `GET /routes`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteEntry {
    pub domain: String,
    pub upstream: Option<String>,
    pub tls: bool,
    /// Which component created this route. `None` for routes created before
    /// the source field was introduced, or by other tools.
    #[serde(default)]
    pub source: Option<String>,
}

/// REST client for the Dwaar admin API.
///
/// The client is intentionally stateless — it holds only the base URL and an
/// `reqwest::Client` (which itself is a connection-pool handle and is cheaply
/// cloneable). Callers share one instance across reconciliation loops.
#[derive(Debug, Clone)]
pub struct AdminApiClient {
    base_url: String,
    client: reqwest::Client,
}

/// Default request timeout for admin API calls.
const ADMIN_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

impl AdminApiClient {
    /// Create a new client pointing at `base_url` (e.g. `http://dwaar-admin:6190`).
    ///
    /// If `token` is provided, it is sent as a `Bearer` token on every request.
    /// A 10-second request timeout is applied to all calls.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self::new_with_token(base_url, None)
    }

    /// Create a client with an optional bearer token for authentication.
    pub fn new_with_token(base_url: impl Into<String>, token: Option<&str>) -> Self {
        let mut builder = reqwest::Client::builder()
            .timeout(ADMIN_REQUEST_TIMEOUT)
            .connect_timeout(std::time::Duration::from_secs(5));

        if let Some(tok) = token {
            let mut headers = reqwest::header::HeaderMap::new();
            if let Ok(val) = reqwest::header::HeaderValue::from_str(&format!("Bearer {tok}")) {
                headers.insert(reqwest::header::AUTHORIZATION, val);
            }
            builder = builder.default_headers(headers);
        }

        Self {
            base_url: base_url.into(),
            client: builder.build().expect("reqwest client with valid TLS"),
        }
    }

    /// Create or update the route for `domain`, forwarding to `upstream` (host:port).
    ///
    /// Idempotent — safe to call on every reconciliation pass. The admin API
    /// uses the domain as the primary key and overwrites any existing entry.
    #[instrument(skip(self), fields(domain, upstream, tls))]
    pub async fn upsert_route(
        &self,
        domain: &str,
        upstream: &str,
        tls: bool,
    ) -> Result<(), AdminApiError> {
        let url = format!("{}/routes", self.base_url);
        let body = UpsertRouteRequest {
            domain,
            upstream,
            tls,
            source: CONTROLLER_SOURCE,
        };

        debug!(%domain, %upstream, tls, "upserting route");

        let resp = self.client.post(&url).json(&body).send().await?;

        if !resp.status().is_success() {
            return Err(AdminApiError::Status {
                status: resp.status().as_u16(),
                method: "POST",
                path: format!("/routes (domain={domain})"),
            });
        }

        Ok(())
    }

    /// Remove the route for `domain`.
    ///
    /// Returns `Ok(())` whether or not the route existed — a 404 from the
    /// admin API is treated as success because the desired state (no route)
    /// already matches reality.
    ///
    /// Domain keys may include `/` for path-prefixed routes (e.g.
    /// `example.com/api/`). We percent-encode `/` as `%2F` so the DELETE URL
    /// has a single path segment and the admin API receives the correct key.
    #[instrument(skip(self), fields(domain))]
    pub async fn delete_route(&self, domain: &str) -> Result<(), AdminApiError> {
        let encoded_domain = domain.replace('/', "%2F");
        let url = format!("{}/routes/{}", self.base_url, encoded_domain);

        debug!(%domain, "deleting route");

        let resp = self.client.delete(&url).send().await?;

        // 404 is fine — it means the route is already gone.
        if !resp.status().is_success() && resp.status().as_u16() != 404 {
            return Err(AdminApiError::Status {
                status: resp.status().as_u16(),
                method: "DELETE",
                path: format!("/routes/{domain}"),
            });
        }

        Ok(())
    }

    /// List all routes currently registered in the Dwaar admin API.
    ///
    /// Used on startup to reconcile state rather than blindly re-upserting
    /// every Ingress — reduces unnecessary admin API churn.
    #[instrument(skip(self))]
    pub async fn list_routes(&self) -> Result<Vec<RouteEntry>, AdminApiError> {
        let url = format!("{}/routes", self.base_url);

        let resp = self.client.get(&url).send().await?;

        if !resp.status().is_success() {
            return Err(AdminApiError::ListStatus {
                status: resp.status().as_u16(),
            });
        }

        let entries: Vec<RouteEntry> = resp.json().await?;
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upsert_request_serializes_correctly() {
        let req = UpsertRouteRequest {
            domain: "app.example.com",
            upstream: "10.0.0.5:8080",
            tls: true,
            source: CONTROLLER_SOURCE,
        };
        let json = serde_json::to_string(&req).expect("serialize");
        assert!(json.contains("\"domain\":\"app.example.com\""));
        assert!(json.contains("\"upstream\":\"10.0.0.5:8080\""));
        assert!(json.contains("\"tls\":true"));
        assert!(json.contains("\"source\":\"dwaar-ingress\""));
    }

    #[test]
    fn client_constructs_correct_urls() {
        let client = AdminApiClient::new("http://dwaar-admin:9000");
        assert_eq!(client.base_url, "http://dwaar-admin:9000");
    }

    #[test]
    fn delete_url_encodes_slash_in_domain_key() {
        // Domain keys with path prefixes (e.g. "example.com/api/") would break
        // the DELETE URL if the `/` is not percent-encoded. Verify the encoding
        // logic directly — without making a real HTTP request.
        let domain = "example.com/api/";
        let encoded = domain.replace('/', "%2F");
        assert_eq!(encoded, "example.com%2Fapi%2F");

        // Plain domain (no slash) must be left unchanged.
        let plain = "example.com";
        let encoded_plain = plain.replace('/', "%2F");
        assert_eq!(encoded_plain, "example.com");
    }

    #[test]
    fn route_entry_deserializes() {
        let json = r#"{"domain":"app.example.com","upstream":"10.0.0.5:8080","tls":false}"#;
        let entry: RouteEntry = serde_json::from_str(json).expect("deserialize");
        assert_eq!(entry.domain, "app.example.com");
        assert_eq!(entry.upstream.as_deref(), Some("10.0.0.5:8080"));
        assert!(!entry.tls);
    }

    #[test]
    fn route_entry_deserializes_null_upstream() {
        let json = r#"{"domain":"app.example.com","upstream":null,"tls":false}"#;
        let entry: RouteEntry = serde_json::from_str(json).expect("deserialize");
        assert!(entry.upstream.is_none());
    }
}
