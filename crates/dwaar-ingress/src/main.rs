// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Dwaar ingress controller binary.
//!
//! Watches Kubernetes `Ingress` resources and syncs the declared routes to the
//! Dwaar Admin API. This is the entry point; the actual watch loop and route
//! sync logic will be built in subsequent issues (ISSUE-085+).

use anyhow::{Context, Result};
use clap::Parser;
use tracing::info;

use dwaar_ingress::AdminApiClient;

/// Default admin API address — unix socket path used in production deployments.
const DEFAULT_ADMIN_URL: &str = "http://unix:/run/dwaar/admin.sock";

/// Dwaar ingress controller — syncs Kubernetes Ingress resources to Dwaar routes.
#[derive(Debug, Parser)]
#[command(name = "dwaar-ingress", version, about)]
struct Args {
    /// Path to the kubeconfig file. Omit to use the in-cluster service account
    /// (the normal case when running inside a Kubernetes pod).
    #[arg(long, env = "KUBECONFIG")]
    kubeconfig: Option<String>,

    /// Base URL of the Dwaar Admin API.
    ///
    /// Use `http://unix:/path/to/socket` for Unix domain socket transport
    /// (the default, recommended for production) or `http://host:port` for
    /// TCP transport (useful during development or in multi-node setups).
    #[arg(long, env = "DWAAR_ADMIN_URL", default_value = DEFAULT_ADMIN_URL)]
    admin_url: String,

    /// Kubernetes namespace to watch. Omit to watch all namespaces (the
    /// default behaviour, matching what most ingress controllers do).
    #[arg(long, env = "DWAAR_NAMESPACE")]
    namespace: Option<String>,

    /// `IngressClass` name to claim. Only Ingress resources whose
    /// `ingressClassName` field matches this value are synced.
    #[arg(long, env = "DWAAR_INGRESS_CLASS", default_value = "dwaar")]
    ingress_class: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    info!(
        admin_url = %args.admin_url,
        namespace = args.namespace.as_deref().unwrap_or("*"),
        ingress_class = %args.ingress_class,
        "starting dwaar-ingress"
    );

    // Validate the admin URL and verify we can build the client. An invalid
    // URL is a configuration error — fail loudly at startup rather than
    // discovering it later when the first Ingress event arrives.
    let _client = AdminApiClient::new(&args.admin_url)
        .context("failed to build Admin API client — check --admin-url")?;

    // The Kubernetes watch loop (ISSUE-085) goes here. For now we confirm
    // the client and config are valid and exit cleanly.
    info!("admin API client ready — watch loop not yet implemented (ISSUE-085)");

    Ok(())
}
