// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Docker container auto-discovery via socket API.
//!
//! Watches the Docker daemon for containers with `dwaar.*` labels
//! and creates routes automatically.

pub mod client;
pub mod labels;
