// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Error types for the ingress controller.
//!
//! We distinguish between transient failures (connection refused — the admin
//! API is just restarting) and permanent ones (401 means the token is wrong;
//! retrying won't help). Callers can match on the variant to decide whether to
//! back off or abort immediately.

use thiserror::Error;

/// Every failure mode the `AdminApiClient` can surface.
#[derive(Debug, Error)]
pub enum AdminApiError {
    /// The admin API socket or TCP port refused the connection.
    ///
    /// This is transient — the proxy may still be starting up. The ingress
    /// controller should back off and retry rather than crash.
    #[error("connection refused to admin API at {url}")]
    ConnectionRefused { url: String },

    /// The bearer token was rejected (HTTP 401).
    ///
    /// This is permanent until the operator fixes `DWAAR_ADMIN_TOKEN`.
    #[error("unauthorized: admin API rejected the bearer token")]
    Unauthorized,

    /// The requested route domain does not exist (HTTP 404 on DELETE/GET).
    #[error("route not found: {domain}")]
    RouteNotFound { domain: String },

    /// The admin API returned an unexpected 5xx error.
    #[error("admin API server error ({status}): {body}")]
    ServerError { status: u16, body: String },

    /// Any other HTTP error we didn't anticipate.
    #[error("unexpected HTTP {status} from admin API: {body}")]
    UnexpectedStatus { status: u16, body: String },

    /// A network or serialization error from the underlying HTTP client.
    #[error("HTTP client error: {0}")]
    Http(#[from] reqwest::Error),

    /// The `--admin-url` provided by the operator cannot be parsed or is
    /// missing required components (scheme, host, socket path).
    #[error("invalid admin URL: {reason}")]
    InvalidUrl { reason: String },
}
