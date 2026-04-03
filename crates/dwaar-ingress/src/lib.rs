// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! dwaar-ingress — Kubernetes ingress controller for Dwaar.
//!
//! Watches Ingress, Service, Secret, and `IngressClass` resources and syncs
//! routes to the Dwaar admin API.

pub mod client;
pub mod error;
pub mod health;
pub mod metrics;
pub mod watcher;
