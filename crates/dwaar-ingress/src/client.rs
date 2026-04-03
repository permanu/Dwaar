// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! HTTP client for the Dwaar admin API.
//!
//! Wraps the three operations the ingress controller needs:
//! upsert a route, delete a route, and list existing routes.
//! `reqwest::Client` handles connection pooling and TLS.

use serde::{Deserialize, Serialize};

use crate::error::AdminApiError;

/// A route entry as returned by the admin API list endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteEntry {
    pub domain: String,
    pub upstream: String,
    pub tls: bool,
}

/// Payload sent to `POST /routes` (upsert).
#[derive(Debug, Serialize)]
struct UpsertPayload<'a> {
    domain: &'a str,
    upstream: &'a str,
    tls: bool,
}

/// Thin async wrapper around the Dwaar admin REST API.
///
/// Uses `reqwest::Client` for connection pooling across calls.
#[derive(Debug, Clone)]
pub struct AdminApiClient {
    base_url: String,
    client: reqwest::Client,
}

impl AdminApiClient {
    /// Create a new client pointed at `base_url` (e.g. `http://127.0.0.1:9091`).
    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            client: reqwest::Client::new(),
        }
    }

    /// Upsert a route. Creates or overwrites the entry for `domain`.
    pub async fn upsert_route(
        &self,
        domain: &str,
        upstream: &str,
        tls: bool,
    ) -> Result<(), AdminApiError> {
        let url = format!("{}/routes", self.base_url);
        let payload = UpsertPayload {
            domain,
            upstream,
            tls,
        };

        let resp = self
            .client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(AdminApiError::Transport)?;

        let status = resp.status().as_u16();

        if status == 200 || status == 201 {
            return Ok(());
        }

        let body = resp
            .text()
            .await
            .unwrap_or_else(|_| String::from("<unreadable body>"));
        Err(AdminApiError::Status { status, body })
    }

    /// Remove the route for `domain`. Returns `Ok(())` even if the domain
    /// was not found (idempotent delete).
    pub async fn delete_route(&self, domain: &str) -> Result<(), AdminApiError> {
        let url = format!("{}/routes/{}", self.base_url, domain);
        let resp = self
            .client
            .delete(&url)
            .send()
            .await
            .map_err(AdminApiError::Transport)?;

        let status = resp.status().as_u16();

        // 200 = deleted, 404 = wasn't there — both are success from our perspective
        if status == 200 || status == 404 {
            return Ok(());
        }

        let body = resp
            .text()
            .await
            .unwrap_or_else(|_| String::from("<unreadable body>"));
        Err(AdminApiError::Status { status, body })
    }

    /// Retrieve all routes currently known to the admin API.
    pub async fn list_routes(&self) -> Result<Vec<RouteEntry>, AdminApiError> {
        let url = format!("{}/routes", self.base_url);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(AdminApiError::Transport)?;

        let status = resp.status().as_u16();

        if status != 200 {
            let body = resp
                .text()
                .await
                .unwrap_or_else(|_| String::from("<unreadable body>"));
            return Err(AdminApiError::Status { status, body });
        }

        let routes: Vec<RouteEntry> = resp.json().await.map_err(AdminApiError::Transport)?;
        Ok(routes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_base_url_stored() {
        let c = AdminApiClient::new("http://127.0.0.1:9091".to_string());
        assert_eq!(c.base_url, "http://127.0.0.1:9091");
    }
}
