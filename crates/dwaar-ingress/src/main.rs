// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Entry point for the Dwaar Kubernetes ingress controller.
//!
//! Parses CLI args, builds a kube `Client`, wires up the health server,
//! and starts the watcher.  Graceful shutdown is triggered by SIGTERM or
//! SIGINT (Ctrl-C).

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use anyhow::Context as _;
use clap::Parser;
use kube::Client;
use tokio::sync::watch;
use tracing::info;
use tracing_subscriber::EnvFilter;

use dwaar_ingress::client::AdminApiClient;
use dwaar_ingress::health::{ReadinessState, serve as health_serve};
use dwaar_ingress::metrics::IngressMetrics;
use dwaar_ingress::watcher::{IngressWatcher, WatcherConfig};

/// Dwaar Kubernetes ingress controller.
#[derive(Parser, Debug)]
#[command(name = "dwaar-ingress", version, about)]
struct Cli {
    /// Path to a kubeconfig file. Defaults to in-cluster config when omitted.
    #[arg(long, env = "KUBECONFIG")]
    kubeconfig: Option<String>,

    /// Base URL of the Dwaar admin API (e.g. `http://127.0.0.1:9091`).
    #[arg(long, env = "DWAAR_ADMIN_URL", default_value = "http://127.0.0.1:9091")]
    admin_url: String,

    /// Restrict watches to this namespace. Watches all namespaces when omitted.
    #[arg(long, env = "DWAAR_NAMESPACE")]
    namespace: Option<String>,

    /// `IngressClass` name to handle. Handles all classes when omitted.
    #[arg(long, env = "DWAAR_INGRESS_CLASS")]
    ingress_class: Option<String>,

    /// Port for the liveness/readiness/metrics HTTP server.
    #[arg(long, env = "DWAAR_PROBE_PORT", default_value = "8081")]
    probe_port: u16,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Structured JSON logging by default; RUST_LOG controls filter level.
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    info!(
        admin_url = %cli.admin_url,
        namespace = ?cli.namespace,
        ingress_class = ?cli.ingress_class,
        probe_port = cli.probe_port,
        "dwaar-ingress starting"
    );

    // Build the kube client from in-cluster config or kubeconfig file.
    let kube_client = if let Some(ref path) = cli.kubeconfig {
        let config = kube::Config::from_kubeconfig(&kube::config::KubeConfigOptions {
            context: None,
            cluster: None,
            user: None,
        })
        .await
        .with_context(|| format!("loading kubeconfig from {path}"))?;
        Client::try_from(config).context("building kube client from kubeconfig")?
    } else {
        Client::try_default()
            .await
            .context("building in-cluster kube client")?
    };

    let admin_client = AdminApiClient::new(cli.admin_url);

    let watcher_config = WatcherConfig {
        namespace: cli.namespace,
        ingress_class: cli.ingress_class,
    };

    let readiness = ReadinessState::new();
    let metrics = IngressMetrics::new();

    // No leader election in this phase: mark leader as ready immediately.
    // When leader election (ISSUE-095) is added, this flag will be managed
    // by the lease controller.
    readiness.leader_ready.store(true, Ordering::Release);
    metrics.leader_is_leader.set(1);

    // Shutdown channel: broadcast `true` when SIGTERM / SIGINT fires.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Health / readiness / metrics server
    let health_addr = SocketAddr::from(([0, 0, 0, 0], cli.probe_port));
    let health_readiness = readiness.clone();
    let health_metrics = Arc::clone(&metrics);
    tokio::spawn(async move {
        if let Err(e) = health_serve(health_addr, health_readiness, health_metrics).await {
            tracing::error!(error = %e, "health server error");
        }
    });

    // Watcher task
    let watcher = Arc::new(IngressWatcher::new(
        kube_client,
        admin_client,
        watcher_config,
        readiness,
        Arc::clone(&metrics),
    ));

    let watcher_handle = tokio::spawn({
        let watcher = Arc::clone(&watcher);
        let rx = shutdown_rx.clone();
        async move { watcher.run(rx).await }
    });

    // Wait for SIGTERM or SIGINT
    wait_for_shutdown().await;
    info!("shutdown signal received");

    // Signal all tasks to stop
    let _ = shutdown_tx.send(true);

    // Give the watcher task a moment to clean up
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), watcher_handle).await;

    info!("dwaar-ingress stopped");
    Ok(())
}

/// Wait for either SIGTERM (Unix) or CTRL-C.
async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm =
            signal(SignalKind::terminate()).expect("SIGTERM handler registration failed");
        tokio::select! {
            _ = sigterm.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
