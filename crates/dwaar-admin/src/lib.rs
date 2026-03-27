// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! dwaar-admin — REST API for runtime route management.

pub mod auth;
pub mod handlers;
pub mod service;

pub use service::AdminService;
