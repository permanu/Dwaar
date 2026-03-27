// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! dwaar-config — Dwaarfile parser and configuration management.
//!
//! Parses Dwaarfile syntax (a superset of Caddyfile) into typed
//! [`model::DwaarConfig`] structs. The parser produces clear error
//! messages with line numbers and typo suggestions.
//!
//! ## Usage
//!
//! ```
//! use dwaar_config::parser;
//!
//! let config = parser::parse(r#"
//!     example.com {
//!         reverse_proxy localhost:8080
//!     }
//! "#).expect("valid config");
//!
//! assert_eq!(config.sites.len(), 1);
//! assert_eq!(config.sites[0].address, "example.com");
//! ```

pub mod compile;
pub mod error;
pub mod format;
pub mod model;
pub mod parser;
mod token;
pub mod watcher;

/// Maximum config file size (10 MB) to prevent OOM on crafted input.
/// Shared between CLI startup and the config watcher.
pub const MAX_CONFIG_SIZE: u64 = 10 * 1024 * 1024;
