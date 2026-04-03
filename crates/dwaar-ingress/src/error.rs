// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Error types for the ingress controller.
//!
//! `AdminApiError` covers HTTP communication with the Dwaar admin API.
//! `WatcherError` covers Kubernetes informer and reconciliation failures.
//! Both use `thiserror` so they compose cleanly in library code without
//! carrying an `anyhow` dependency into the hot reconciliation paths.

/// Errors from the Dwaar admin REST API client.
#[derive(Debug, thiserror::Error)]
pub enum AdminApiError {
    /// The HTTP request itself failed (network error, timeout, etc.).
    #[error("admin API HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// The server returned a non-2xx status for a route mutation.
    #[error("admin API returned {status} for {method} {path}")]
    Status {
        status: u16,
        method: &'static str,
        path: String,
    },

    /// The server returned a non-2xx status during `list_routes`.
    #[error("admin API list_routes returned {status}")]
    ListStatus { status: u16 },

    /// Response body could not be parsed as the expected JSON shape.
    #[error("admin API response parse error: {0}")]
    Parse(#[from] serde_json::Error),
}

/// Errors from annotation parsing.
#[derive(Debug, thiserror::Error)]
pub enum AnnotationError {
    /// An annotation value could not be parsed into the expected type.
    #[error("annotation '{annotation}' has invalid value '{value}': {reason}")]
    InvalidValue {
        annotation: String,
        value: String,
        reason: String,
    },
}

/// Errors from TLS Secret materialisation.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// The referenced Secret was not yet in the reflector store.
    #[error("Secret {namespace}/{name} not found in local store — cache may be warming")]
    SecretNotFound { name: String, namespace: String },

    /// The Secret exists but is missing a required field (`tls.crt` or `tls.key`).
    #[error("Secret {secret} is missing required field '{field}'")]
    MissingField { secret: String, field: String },

    /// A path segment (namespace or secret name) contained unsafe characters.
    #[error("unsafe path segment '{segment}': {reason}")]
    InvalidSegment { segment: String, reason: String },

    /// Writing a PEM file to disk failed.
    #[error("failed to write PEM file {path}: {source}")]
    Io {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
}

/// Errors from the Kubernetes informer / watcher subsystem.
#[derive(Debug, thiserror::Error)]
pub enum WatcherError {
    /// The kube-rs watcher stream emitted an error event.
    #[error("Kubernetes watcher error: {0}")]
    Kube(#[from] kube::Error),

    /// The reflector store is in a transient state and the object is not yet visible.
    #[error("Service {name}/{namespace} not found in local store — cache may be warming")]
    ServiceNotFound { name: String, namespace: String },

    /// An Ingress resource has an incomplete or malformed spec.
    #[error("malformed Ingress {name}: {reason}")]
    MalformedIngress { name: String, reason: String },

    /// Leader election Lease could not be created or renewed.
    #[error("lease operation failed: {0}")]
    Lease(String),
}
