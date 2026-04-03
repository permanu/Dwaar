// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! dwaar-ingress — Kubernetes ingress controller for Dwaar.
//!
//! This crate is a binary (`dwaar-ingress`) that watches Kubernetes `Ingress`
//! resources and syncs the declared routes to Dwaar's Admin API. The lib
//! module exists so that integration tests can import `client` and `error`
//! without going through the binary entry point.

pub mod client;
pub mod error;

pub use client::AdminApiClient;
pub use error::AdminApiError;
