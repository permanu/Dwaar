// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Dwaar Kubernetes Ingress Controller.
//!
//! Watches K8s Ingress, Service, Secret, and IngressClass resources,
//! translates them into Dwaar routes, and syncs via the Admin API.

fn main() {
    // ISSUE-084: CLI args, AdminApiClient, startup logic
    eprintln!("dwaar-ingress: not yet implemented");
    std::process::exit(1);
}
