// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Error types for the ingress controller.

use thiserror::Error;

/// Errors that can occur when calling the Dwaar admin API.
///
/// `reqwest::Error` covers transport failures, timeouts, and JSON
/// deserialization failures from `.json()` calls — so we don't need a
/// separate `Deserialize` variant.
#[derive(Debug, Error)]
pub enum AdminApiError {
    /// The HTTP request failed or the response body could not be decoded.
    #[error("HTTP error: {0}")]
    Transport(#[from] reqwest::Error),

    /// The admin API returned a non-2xx status code.
    #[error("admin API returned status {status}: {body}")]
    Status { status: u16, body: String },
}

/// Errors that can occur in the Kubernetes watcher.
#[derive(Debug, Error)]
pub enum WatcherError {
    /// The underlying kube watch stream encountered an error.
    #[error("kube watcher error: {0}")]
    Kube(#[from] kube::Error),

    /// An error was received on the watch stream itself.
    #[error("watch stream error: {0}")]
    Stream(String),
}
