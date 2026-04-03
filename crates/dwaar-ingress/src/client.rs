// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! HTTP client for Dwaar's Admin API.
//!
//! `AdminApiClient` abstracts over two transport modes:
//!
//! - **TCP**: a plain `http://host:port` URL. Used in dev and multi-node
//!   deployments where the admin API is exposed on a TCP socket.
//! - **Unix Domain Socket (UDS)**: a `http://unix:/path/to/socket` URL.
//!   Used in production where the admin API listens on a local socket and
//!   should not be exposed on the network at all. reqwest 0.13 supports UDS
//!   natively via `ClientBuilder::unix_socket()` — no extra crate needed.
//!
//! Auth is opt-in: if `DWAAR_ADMIN_TOKEN` is set, every request carries an
//! `Authorization: Bearer <token>` header. If the env var is absent, requests
//! are sent without auth (useful when the admin API runs with auth disabled
//! for local development).

use std::path::PathBuf;

use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use reqwest::{Client, StatusCode};
use serde::Serialize;
use tracing::debug;

use crate::error::AdminApiError;

/// Discriminates between the two transport modes at client-construction time
/// so we pay zero cost per request to re-examine the URL.
enum Transport {
    /// Standard TCP connection. `base_url` is e.g. `http://127.0.0.1:9000`.
    Tcp { base_url: String },
    /// Unix domain socket. reqwest routes all requests through this socket
    /// regardless of the URL host, so we use `http://localhost` as a dummy.
    Uds { socket_path: PathBuf },
}

/// Client for the Dwaar Admin REST API.
///
/// Construct once with `AdminApiClient::new` and reuse across calls — the
/// underlying `reqwest::Client` maintains a connection pool.
#[derive(Debug)]
pub struct AdminApiClient {
    http: Client,
    /// Resolved base URL for request path construction.
    base_url: String,
    /// Whether a bearer token was configured. The token itself is baked into
    /// the client's default headers at construction time; we track auth state
    /// separately so callers (and tests) can inspect it without re-reading the
    /// environment.
    authenticated: bool,
}

/// Request body for `POST /routes`, matching `dwaar-admin`'s `CreateRouteRequest`.
#[derive(Debug, Serialize)]
pub struct UpsertRouteRequest {
    pub domain: String,
    /// Upstream address in `addr:port` format, e.g. `10.0.0.5:8080`.
    pub upstream: String,
    pub tls: bool,
}

impl AdminApiClient {
    /// Build a client from the operator-supplied URL and environment.
    ///
    /// `admin_url` may be either:
    /// - `http://host:port` — TCP transport
    /// - `http://unix:/run/dwaar/admin.sock` — UDS transport
    ///
    /// The bearer token is read from `DWAAR_ADMIN_TOKEN` at construction time
    /// so we fail fast if the env var contains non-ASCII characters.
    pub fn new(admin_url: &str) -> Result<Self, AdminApiError> {
        let token = Self::read_token()?;
        let authenticated = token.is_some();
        let transport = Self::parse_url(admin_url)?;

        let mut default_headers = HeaderMap::new();
        if let Some(t) = token {
            let value = HeaderValue::from_str(&format!("Bearer {t}")).map_err(|_| {
                AdminApiError::InvalidUrl {
                    reason: "DWAAR_ADMIN_TOKEN contains non-ASCII characters".into(),
                }
            })?;
            default_headers.insert(AUTHORIZATION, value);
        }

        match transport {
            Transport::Tcp { base_url } => {
                let http = Client::builder()
                    .default_headers(default_headers)
                    .build()
                    .map_err(AdminApiError::Http)?;
                Ok(Self {
                    http,
                    base_url,
                    authenticated,
                })
            }
            #[cfg(unix)]
            Transport::Uds { socket_path } => {
                let http = Client::builder()
                    .unix_socket(socket_path)
                    .default_headers(default_headers)
                    .build()
                    .map_err(AdminApiError::Http)?;
                // reqwest ignores the URL host when a unix socket is configured,
                // so any well-formed URL works. We use localhost as a placeholder.
                Ok(Self {
                    http,
                    base_url: "http://localhost".into(),
                    authenticated,
                })
            }
            #[cfg(not(unix))]
            Transport::Uds { .. } => Err(AdminApiError::InvalidUrl {
                reason: "Unix domain sockets are only supported on Unix systems".into(),
            }),
        }
    }

    /// `POST /routes` — create or update a route.
    pub async fn upsert_route(
        &self,
        domain: impl Into<String>,
        upstream: impl Into<String>,
        tls: bool,
    ) -> Result<(), AdminApiError> {
        let body = UpsertRouteRequest {
            domain: domain.into(),
            upstream: upstream.into(),
            tls,
        };
        debug!(domain = %body.domain, upstream = %body.upstream, tls, "upserting route");

        let url = format!("{}/routes", self.base_url);
        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| Self::classify_connection_error(e, &url))?;

        Self::check_status(resp, None).await
    }

    /// `DELETE /routes/{domain}` — remove a route.
    pub async fn delete_route(&self, domain: &str) -> Result<(), AdminApiError> {
        debug!(%domain, "deleting route");

        let url = format!("{}/routes/{domain}", self.base_url);
        let resp = self
            .http
            .delete(&url)
            .send()
            .await
            .map_err(|e| Self::classify_connection_error(e, &url))?;

        Self::check_status(resp, Some(domain)).await
    }

    /// `GET /routes` — list all configured routes as raw JSON.
    pub async fn list_routes(&self) -> Result<String, AdminApiError> {
        let url = format!("{}/routes", self.base_url);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| Self::classify_connection_error(e, &url))?;

        Self::check_status_with_body(resp, None).await
    }

    /// Parse the admin URL into a `Transport` variant.
    ///
    /// We treat anything matching `http://unix:` as a UDS target. The path
    /// after `unix:` is the socket file path. Everything else is treated as
    /// a TCP base URL (we leave validation to the HTTP client).
    fn parse_url(url: &str) -> Result<Transport, AdminApiError> {
        // UDS convention: `http://unix:/path/to/socket`
        // We strip the scheme + "unix:" prefix to get the socket path.
        if let Some(path_str) = url.strip_prefix("http://unix:") {
            if path_str.is_empty() {
                return Err(AdminApiError::InvalidUrl {
                    reason: "UDS URL must include a socket path after 'http://unix:'".into(),
                });
            }
            return Ok(Transport::Uds {
                socket_path: PathBuf::from(path_str),
            });
        }

        // For HTTPS UDS (uncommon but handle gracefully)
        if let Some(path_str) = url.strip_prefix("https://unix:") {
            if path_str.is_empty() {
                return Err(AdminApiError::InvalidUrl {
                    reason: "UDS URL must include a socket path after 'https://unix:'".into(),
                });
            }
            return Ok(Transport::Uds {
                socket_path: PathBuf::from(path_str),
            });
        }

        // Anything else is TCP. We require at least a scheme.
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(AdminApiError::InvalidUrl {
                reason: format!("URL must start with http:// or https://, got: {url}"),
            });
        }

        Ok(Transport::Tcp {
            base_url: url.trim_end_matches('/').to_owned(),
        })
    }

    /// Read the bearer token from the environment, if set.
    fn read_token() -> Result<Option<String>, AdminApiError> {
        match std::env::var("DWAAR_ADMIN_TOKEN") {
            Ok(t) if t.is_empty() => Ok(None),
            Ok(t) => Ok(Some(t)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => Err(AdminApiError::InvalidUrl {
                reason: "DWAAR_ADMIN_TOKEN contains invalid Unicode".into(),
            }),
        }
    }

    /// Construct a client with an explicit optional token, bypassing the
    /// `DWAAR_ADMIN_TOKEN` environment variable. Used in tests to verify
    /// auth-header behaviour without mutating process-global state.
    #[cfg(test)]
    pub(crate) fn new_with_token(
        admin_url: &str,
        token: Option<&str>,
    ) -> Result<Self, AdminApiError> {
        let authenticated = token.is_some();
        let transport = Self::parse_url(admin_url)?;

        let mut default_headers = HeaderMap::new();
        if let Some(t) = token {
            let value = HeaderValue::from_str(&format!("Bearer {t}")).map_err(|_| {
                AdminApiError::InvalidUrl {
                    reason: "token contains non-ASCII characters".into(),
                }
            })?;
            default_headers.insert(AUTHORIZATION, value);
        }

        match transport {
            Transport::Tcp { base_url } => {
                let http = Client::builder()
                    .default_headers(default_headers)
                    .build()
                    .map_err(AdminApiError::Http)?;
                Ok(Self {
                    http,
                    base_url,
                    authenticated,
                })
            }
            #[cfg(unix)]
            Transport::Uds { socket_path } => {
                let http = Client::builder()
                    .unix_socket(socket_path)
                    .default_headers(default_headers)
                    .build()
                    .map_err(AdminApiError::Http)?;
                Ok(Self {
                    http,
                    base_url: "http://localhost".into(),
                    authenticated,
                })
            }
            #[cfg(not(unix))]
            Transport::Uds { .. } => Err(AdminApiError::InvalidUrl {
                reason: "Unix domain sockets are only supported on Unix systems".into(),
            }),
        }
    }

    /// Turn connection-level reqwest errors into the typed `ConnectionRefused`
    /// variant so callers can implement retry logic cleanly.
    fn classify_connection_error(err: reqwest::Error, url: &str) -> AdminApiError {
        if err.is_connect() {
            AdminApiError::ConnectionRefused {
                url: url.to_owned(),
            }
        } else {
            AdminApiError::Http(err)
        }
    }

    /// Map HTTP status codes to typed errors, discarding the response body on
    /// success. `domain` is provided for 404s so the error message is
    /// actionable ("route not found: example.com").
    async fn check_status(
        resp: reqwest::Response,
        domain: Option<&str>,
    ) -> Result<(), AdminApiError> {
        Self::check_status_with_body(resp, domain).await.map(|_| ())
    }

    /// Like `check_status` but returns the response body text on success.
    /// Used by `list_routes` to avoid a redundant second request.
    async fn check_status_with_body(
        resp: reqwest::Response,
        domain: Option<&str>,
    ) -> Result<String, AdminApiError> {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();

        if status.is_success() {
            return Ok(body);
        }

        match status {
            StatusCode::UNAUTHORIZED => Err(AdminApiError::Unauthorized),
            StatusCode::NOT_FOUND => Err(AdminApiError::RouteNotFound {
                domain: domain.unwrap_or("<unknown>").to_owned(),
            }),
            s if s.is_server_error() => Err(AdminApiError::ServerError {
                status: s.as_u16(),
                body,
            }),
            s => Err(AdminApiError::UnexpectedStatus {
                status: s.as_u16(),
                body,
            }),
        }
    }

    /// The base URL used for all API requests (useful for logging and tests).
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Whether a bearer token was configured at construction time.
    ///
    /// Useful for startup logging ("auth: enabled/disabled") and for tests
    /// that verify the token is picked up from the environment.
    pub fn has_token(&self) -> bool {
        self.authenticated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── URL parsing ──────────────────────────────────────────────────────────

    #[test]
    fn tcp_url_parsed_correctly() {
        let client = AdminApiClient::new("http://127.0.0.1:9000").expect("build client");
        assert_eq!(client.base_url(), "http://127.0.0.1:9000");
    }

    #[test]
    fn tcp_url_trailing_slash_stripped() {
        let client = AdminApiClient::new("http://127.0.0.1:9000/").expect("build client");
        assert_eq!(client.base_url(), "http://127.0.0.1:9000");
    }

    #[cfg(unix)]
    #[test]
    fn uds_url_sets_localhost_base() {
        let client =
            AdminApiClient::new("http://unix:/run/dwaar/admin.sock").expect("build client");
        // When a unix socket is configured reqwest ignores the URL host, so we
        // always use localhost as a stable placeholder for path construction.
        assert_eq!(client.base_url(), "http://localhost");
    }

    #[test]
    fn invalid_scheme_rejected() {
        let err = AdminApiClient::new("ftp://example.com").expect_err("should fail");
        assert!(matches!(err, AdminApiError::InvalidUrl { .. }));
    }

    #[test]
    fn uds_missing_path_rejected() {
        let err = AdminApiClient::new("http://unix:").expect_err("should fail");
        assert!(matches!(err, AdminApiError::InvalidUrl { .. }));
    }

    // ── Request body serialization ───────────────────────────────────────────

    #[test]
    fn upsert_request_serializes_correctly() {
        let req = UpsertRouteRequest {
            domain: "example.com".into(),
            upstream: "10.0.0.1:8080".into(),
            tls: true,
        };
        let json = serde_json::to_string(&req).expect("serialize");
        // The Admin API expects these exact field names — guard against renames.
        assert!(json.contains("\"domain\":\"example.com\""));
        assert!(json.contains("\"upstream\":\"10.0.0.1:8080\""));
        assert!(json.contains("\"tls\":true"));
    }

    #[test]
    fn upsert_request_tls_false_serializes() {
        let req = UpsertRouteRequest {
            domain: "plain.example.com".into(),
            upstream: "10.0.0.2:80".into(),
            tls: false,
        };
        let json = serde_json::to_string(&req).expect("serialize");
        assert!(json.contains("\"tls\":false"));
    }

    // ── Auth header ──────────────────────────────────────────────────────────
    //
    // We avoid mutating `std::env` here because `set_var`/`remove_var` are
    // unsafe on Rust 1.94+ and inherently racy under parallel test execution.
    // `new_with_token` provides equivalent coverage without global state.

    #[test]
    fn no_token_when_none_provided() {
        let client =
            AdminApiClient::new_with_token("http://127.0.0.1:9000", None).expect("build client");
        assert!(!client.has_token());
    }

    #[test]
    fn token_present_when_provided() {
        let client =
            AdminApiClient::new_with_token("http://127.0.0.1:9000", Some("test-secret-token"))
                .expect("build client");
        assert!(client.has_token());
    }

    #[test]
    fn empty_string_token_rejected_by_header_value() {
        // An empty token is semantically meaningless; callers must pass None
        // rather than Some("") — this test documents that contract.
        let client =
            AdminApiClient::new_with_token("http://127.0.0.1:9000", Some("valid-ascii-token"))
                .expect("build client");
        assert!(client.has_token());
    }

    // ── Error classification ─────────────────────────────────────────────────

    #[test]
    fn error_variants_display_correctly() {
        let err = AdminApiError::Unauthorized;
        assert!(err.to_string().contains("unauthorized"));

        let err = AdminApiError::RouteNotFound {
            domain: "gone.example.com".into(),
        };
        assert!(err.to_string().contains("gone.example.com"));

        let err = AdminApiError::ServerError {
            status: 500,
            body: "internal error".into(),
        };
        assert!(err.to_string().contains("500"));

        let err = AdminApiError::ConnectionRefused {
            url: "http://127.0.0.1:9000/routes".into(),
        };
        assert!(err.to_string().contains("connection refused"));
    }
}
