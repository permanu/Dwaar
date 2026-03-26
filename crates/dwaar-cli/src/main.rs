// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Dwaar CLI entry point.
//!
//! Reads a Dwaarfile, parses it, compiles routes, and starts the
//! Pingora proxy server. Handles CLI args, logging, and signals.

mod cli;

use std::sync::Arc;

use anyhow::{Context, bail};
use arc_swap::ArcSwap;
use pingora_core::server::Server;
use pingora_core::server::configuration::{Opt as PingoraOpt, ServerConf};
use tracing::info;

use cli::{Cli, Commands};
use dwaar_config::compile::compile_routes;
use dwaar_core::proxy::DwaarProxy;

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse_args();

    if let Some(Commands::Version) = &cli.command {
        print_version();
        return Ok(());
    }

    init_logging(&cli);

    info!(
        version = env!("CARGO_PKG_VERSION"),
        config = %cli.config.display(),
        "starting dwaar"
    );

    // Read and parse the Dwaarfile
    let config_path = &cli.config;
    let config_text = std::fs::read_to_string(config_path)
        .with_context(|| format!("failed to read config file: {}", config_path.display()))?;

    let dwaar_config =
        dwaar_config::parser::parse(&config_text).map_err(|e| anyhow::anyhow!("{e}"))?;

    info!(
        sites = dwaar_config.sites.len(),
        path = %config_path.display(),
        "config loaded"
    );

    // Test mode: validate config and exit
    if cli.test {
        info!("config valid");
        return Ok(());
    }

    let pingora_opt = PingoraOpt {
        upgrade: cli.upgrade,
        daemon: cli.daemon,
        nocapture: false,
        test: false,
        conf: None,
    };

    let conf = ServerConf {
        grace_period_seconds: Some(5),
        graceful_shutdown_timeout_seconds: Some(5),
        ..ServerConf::default()
    };

    let mut server = Server::new_with_opt_and_conf(Some(pingora_opt), conf);
    server.bootstrap();

    info!(
        threads = server.configuration.threads,
        work_stealing = server.configuration.work_stealing,
        grace_period = server.configuration.grace_period_seconds,
        "server bootstrapped"
    );

    // Compile parsed config into a route table for the proxy engine
    let route_table = compile_routes(&dwaar_config);
    if route_table.is_empty() {
        bail!("no valid routes found in config — nothing to proxy");
    }
    info!(routes = route_table.len(), "route table compiled");

    let route_table = Arc::new(ArcSwap::from_pointee(route_table));
    let proxy = DwaarProxy::new(route_table);

    let mut proxy_service = pingora_proxy::http_proxy_service(&server.configuration, proxy);
    proxy_service.add_tcp("0.0.0.0:6188");

    info!(listen = "0.0.0.0:6188", "proxy service registered");

    server.add_service(proxy_service);

    info!("entering run loop, waiting for connections or signals");
    server.run_forever();
}

fn print_version() {
    use std::io::Write;
    let _ = writeln!(std::io::stderr(), "dwaar v{}", env!("CARGO_PKG_VERSION"));
}

fn init_logging(cli: &Cli) {
    use tracing_subscriber::EnvFilter;

    let filter =
        EnvFilter::try_from_env("DWAAR_LOG_LEVEL").unwrap_or_else(|_| EnvFilter::new("info"));

    if cli.daemon {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .with_target(false)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .init();
    }
}
