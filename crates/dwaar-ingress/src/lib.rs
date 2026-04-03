// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! dwaar-ingress — Kubernetes ingress controller for Dwaar.
//!
//! Watches Ingress/Service/Secret resources and reconciles them into the Dwaar
//! route table via the admin API. Supports leader election so multiple replicas
//! can run for high availability without routing conflicts.

pub mod annotations;
pub mod client;
pub mod error;
pub mod health;
pub mod leader;
pub mod metrics;
pub mod reconciler;
pub mod tls;
pub mod translator;
pub mod watcher;
