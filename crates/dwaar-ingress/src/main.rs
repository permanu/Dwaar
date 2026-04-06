// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! dwaar-ingress binary — Kubernetes ingress controller entry point.
//!
//! Starts the leader election loop, health server, and (on leadership acquisition)
//! the Ingress/Service/Secret watcher that reconciles routes into Dwaar.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::sync::watch;
use tracing::info;
use tracing_subscriber::EnvFilter;

use dwaar_ingress::client::AdminApiClient;
use dwaar_ingress::health::{ReadinessState, serve as health_serve};
use dwaar_ingress::leader::{LeaderConfig, LeaderElector};
use dwaar_ingress::metrics::IngressMetrics;
use dwaar_ingress::watcher::IngressWatcher;

#[derive(Debug, Parser)]
#[command(
    name = "dwaar-ingress",
    about = "Kubernetes ingress controller for Dwaar",
    version
)]
struct Args {
    /// Dwaar admin API base URL (e.g. `http://dwaar-admin:6190`)
    #[arg(long, env = "DWAAR_ADMIN_URL", default_value = "http://127.0.0.1:6190")]
    admin_url: String,

    /// Bearer token for Dwaar admin API authentication
    #[arg(long, env = "DWAAR_ADMIN_TOKEN")]
    admin_token: Option<String>,

    /// Address for the health/readiness server
    #[arg(long, env = "HEALTH_ADDR", default_value = "0.0.0.0:8080")]
    health_addr: SocketAddr,

    /// Only manage Ingresses with this class name (empty = manage all)
    #[arg(long, env = "INGRESS_CLASS")]
    ingress_class: Option<String>,

    /// Namespace to watch (empty = watch all namespaces)
    #[arg(long, env = "WATCH_NAMESPACE")]
    namespace: Option<String>,

    /// Leader election lease name
    #[arg(long, env = "LEASE_NAME", default_value = "dwaar-ingress-leader")]
    lease_name: String,

    /// Namespace where the leader election Lease lives
    #[arg(long, env = "LEASE_NAMESPACE", default_value = "kube-system")]
    lease_namespace: String,

    /// Directory to store TLS PEM files materialised from Kubernetes Secrets
    #[arg(long, env = "CERT_DIR", default_value = "/var/lib/dwaar-ingress/certs")]
    cert_dir: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    let args = Args::parse();

    info!(
        admin_url = %args.admin_url,
        health_addr = %args.health_addr,
        ingress_class = ?args.ingress_class,
        namespace = ?args.namespace,
        cert_dir = %args.cert_dir.display(),
        "dwaar-ingress starting"
    );

    let kube_client = kube::Client::try_default().await.context(
        "failed to build Kubernetes client — check KUBECONFIG / in-cluster service account",
    )?;

    let readiness = ReadinessState::new();
    let metrics = IngressMetrics::new();
    let api_client = AdminApiClient::new_with_token(&args.admin_url, args.admin_token.as_deref());

    // Shutdown channel — broadcast to all subsystems.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Spawn the health server — always runs, even when not leader.
    let health_readiness = readiness.clone();
    let health_metrics = metrics.clone();
    tokio::spawn(async move {
        if let Err(e) = health_serve(args.health_addr, health_readiness, health_metrics).await {
            tracing::error!(error = %e, "health server exited unexpectedly");
        }
    });

    // Wire up SIGTERM / Ctrl-C → graceful shutdown.
    let shutdown_tx_signal = shutdown_tx.clone();
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut sigterm =
                signal(SignalKind::terminate()).expect("SIGTERM handler registration must succeed");
            tokio::select! {
                _ = sigterm.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        info!("shutdown signal received");
        let _ = shutdown_tx_signal.send(true);
    });

    // Leader election config.
    let leader_config = LeaderConfig {
        lease_name: args.lease_name,
        namespace: args.lease_namespace,
        ..LeaderConfig::default()
    };

    let elector = LeaderElector::new(
        leader_config,
        kube_client.clone(),
        readiness.clone(),
        metrics.clone(),
    );

    // Run leader election. The closure starts the watcher when we acquire leadership.
    let kube_client_inner = kube_client.clone();
    let ingress_class = args.ingress_class.clone();
    let namespace = args.namespace.clone();
    let api_client_inner = api_client.clone();
    let readiness_inner = readiness.clone();
    let metrics_inner = metrics.clone();
    let cert_dir = args.cert_dir.clone();
    let shutdown_rx_watcher = shutdown_rx.clone();

    elector
        .run(shutdown_rx, move |lost_rx| {
            let kube = kube_client_inner.clone();
            let class = ingress_class.clone();
            let ns = namespace.clone();
            let api = api_client_inner.clone();
            let rd = readiness_inner.clone();
            let m = metrics_inner.clone();
            let cd = cert_dir.clone();
            let mut done = lost_rx;
            let shutdown = shutdown_rx_watcher.clone();
            async move {
                let watcher = IngressWatcher::new(kube, ns, class, api, rd, m, cd);
                // Run until leadership is lost or process shuts down.
                tokio::select! {
                    res = watcher.run(shutdown) => {
                        if let Err(e) = res {
                            tracing::error!(error = %e, "IngressWatcher exited with error");
                        }
                    }
                    _ = done.changed() => {
                        info!("IngressWatcher stopping — leadership lost");
                    }
                }
            }
        })
        .await;

    info!("dwaar-ingress exiting");
    Ok(())
}
