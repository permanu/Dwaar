// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Dwaar CLI entry point.
//!
//! This is the process entry point for the Dwaar proxy. It:
//! 1. Parses CLI arguments (config path, daemon mode, test mode)
//! 2. Initializes structured logging (JSON to stderr)
//! 3. Creates a Pingora Server (process manager)
//! 4. Registers services (proxy, admin, background — added in later issues)
//! 5. Calls `run_forever()` which blocks and handles OS signals

mod cli;

use std::net::SocketAddr;

use pingora_core::server::Server;
use pingora_core::server::configuration::{Opt as PingoraOpt, ServerConf};
use tracing::info;

use cli::{Cli, Commands};
use dwaar_core::proxy::DwaarProxy;

fn main() {
    let cli = Cli::parse_args();

    // Handle subcommands that exit immediately
    if let Some(Commands::Version) = &cli.command {
        print_version();
        return;
    }

    // Initialize structured logging
    init_logging(&cli);

    info!(
        version = env!("CARGO_PKG_VERSION"),
        config = %cli.config.display(),
        "starting dwaar"
    );

    // Test mode: validate config and exit
    // Full config validation will be added in ISSUE-011 (Dwaarfile parser)
    if cli.test {
        info!("config validation not yet implemented, exiting");
        return;
    }

    // Create Pingora server options from our CLI args
    let pingora_opt = PingoraOpt {
        upgrade: cli.upgrade,
        daemon: cli.daemon,
        nocapture: false,
        test: false,
        conf: None,
    };

    // Configure Pingora server with sensible defaults.
    // grace_period_seconds: how long to wait before starting final shutdown
    // graceful_shutdown_timeout_seconds: hard cutoff for draining connections
    let conf = ServerConf {
        grace_period_seconds: Some(5),
        graceful_shutdown_timeout_seconds: Some(5),
        ..ServerConf::default()
    };

    // Create the Pingora server — this is the process manager that owns
    // all services (proxy, admin API, background tasks)
    let mut server = Server::new_with_opt_and_conf(Some(pingora_opt), conf);

    // Bootstrap initializes internals: signal handlers, PID file, Tokio runtimes.
    server.bootstrap();

    info!(
        threads = server.configuration.threads,
        work_stealing = server.configuration.work_stealing,
        grace_period = server.configuration.grace_period_seconds,
        "server bootstrapped"
    );

    // ISSUE-005: Create and register the proxy service.
    // Hardcoded upstream for now — ISSUE-010 replaces with RouteTable.
    let upstream: SocketAddr = "127.0.0.1:8080"
        .parse()
        .expect("hardcoded upstream address must be valid");

    let proxy = DwaarProxy::new(upstream);

    let mut proxy_service = pingora_proxy::http_proxy_service(&server.configuration, proxy);
    proxy_service.add_tcp("0.0.0.0:6188");

    info!(
        listen = "0.0.0.0:6188",
        upstream = %upstream,
        "proxy service registered"
    );

    server.add_service(proxy_service);

    // Future services:
    // ISSUE-017: ACME background service (cert renewal)
    // ISSUE-022: admin API service

    info!("entering run loop, waiting for connections or signals");

    // run_forever() blocks the main thread. It:
    // - Starts all registered services on their own Tokio runtimes
    // - Handles SIGTERM (graceful shutdown) and SIGQUIT (graceful upgrade)
    // - Never returns (the ! return type)
    server.run_forever();
}

/// Print version and exit. Uses stderr to match convention for CLI tools
/// (stdout is for data, stderr is for human messages).
fn print_version() {
    use std::io::Write;
    let _ = writeln!(std::io::stderr(), "dwaar v{}", env!("CARGO_PKG_VERSION"));
}

/// Initialize tracing subscriber for structured logging.
///
/// Log level is controlled by `DWAAR_LOG_LEVEL` env var (default: info).
/// Output format is human-readable for development, JSON for production (--daemon).
fn init_logging(cli: &Cli) {
    use tracing_subscriber::EnvFilter;

    let filter =
        EnvFilter::try_from_env("DWAAR_LOG_LEVEL").unwrap_or_else(|_| EnvFilter::new("info"));

    if cli.daemon {
        // JSON format for daemon mode (machine-readable, parseable by log aggregators)
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .with_target(false)
            .init();
    } else {
        // Human-readable format for interactive use
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .init();
    }
}
