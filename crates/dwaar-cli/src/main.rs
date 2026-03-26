// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Dwaar CLI entry point.
//!
//! Reads a Dwaarfile, parses it, compiles routes and TLS config,
//! and starts the Pingora proxy server with HTTP and optional TLS listeners.

mod cli;

use std::sync::Arc;

use anyhow::{Context, bail};
use arc_swap::ArcSwap;
use pingora_core::listeners::tls::TlsSettings;
use pingora_core::server::Server;
use pingora_core::server::configuration::{Opt as PingoraOpt, ServerConf};
use tracing::info;

use cli::{Cli, Commands};
use dwaar_config::compile::{compile_routes, compile_tls_configs, has_tls_sites};
use dwaar_core::proxy::DwaarProxy;
use dwaar_tls::cert_store::CertStore;
use dwaar_tls::sni::{DomainTlsConfig, SniResolver};

/// Maximum config file size (10 MB) to prevent OOM on crafted input.
const MAX_CONFIG_SIZE: u64 = 10 * 1024 * 1024;

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse_args();

    match &cli.command {
        Some(Commands::Version) => {
            print_version();
            return Ok(());
        }
        Some(Commands::Validate { config }) => {
            init_logging(&cli);
            let path = config.as_ref().unwrap_or(&cli.config);
            return validate_config(path);
        }
        Some(Commands::Fmt { config, check }) => {
            let path = config.as_ref().unwrap_or(&cli.config);
            return fmt_config(path, *check);
        }
        None => {}
    }

    init_logging(&cli);

    info!(
        version = env!("CARGO_PKG_VERSION"),
        config = %cli.config.display(),
        "starting dwaar"
    );

    let config_path = &cli.config;
    let metadata = std::fs::metadata(config_path)
        .with_context(|| format!("failed to stat config file: {}", config_path.display()))?;
    if metadata.len() > MAX_CONFIG_SIZE {
        bail!(
            "config file too large ({} bytes, max {} bytes)",
            metadata.len(),
            MAX_CONFIG_SIZE
        );
    }

    let config_text = std::fs::read_to_string(config_path)
        .with_context(|| format!("failed to read config file: {}", config_path.display()))?;

    let dwaar_config =
        dwaar_config::parser::parse(&config_text).map_err(|e| anyhow::anyhow!("{e}"))?;

    info!(
        sites = dwaar_config.sites.len(),
        path = %config_path.display(),
        "config loaded"
    );

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

    // Compile routes
    let route_table = compile_routes(&dwaar_config);
    if route_table.is_empty() {
        bail!("no valid routes found in config — nothing to proxy");
    }
    info!(routes = route_table.len(), "route table compiled");

    let route_table = Arc::new(ArcSwap::from_pointee(route_table));
    let proxy = DwaarProxy::new(route_table, None);

    let mut proxy_service = pingora_proxy::http_proxy_service(&server.configuration, proxy);

    // Always listen on HTTP
    proxy_service.add_tcp("0.0.0.0:6188");
    info!(
        listen = "0.0.0.0:6188",
        protocol = "http",
        "listener registered"
    );

    if has_tls_sites(&dwaar_config) {
        setup_tls_listener(&dwaar_config, &mut proxy_service)?;
    }

    server.add_service(proxy_service);

    info!("entering run loop, waiting for connections or signals");
    server.run_forever();
}

fn setup_tls_listener(
    config: &dwaar_config::model::DwaarConfig,
    proxy_service: &mut pingora_core::services::listening::Service<
        pingora_proxy::HttpProxy<DwaarProxy>,
    >,
) -> anyhow::Result<()> {
    let tls_configs = compile_tls_configs(config);

    let cert_store = Arc::new(CertStore::new("/etc/dwaar/certs", 1000));
    let mut sni_resolver = SniResolver::new(cert_store);

    if let Some(first_domain) = tls_configs.keys().next() {
        sni_resolver.set_default_domain(first_domain);
    }

    for (domain, tls_config) in &tls_configs {
        sni_resolver.add_domain(
            domain,
            DomainTlsConfig {
                cert_path: tls_config.cert_path.clone(),
                key_path: tls_config.key_path.clone(),
            },
        );
        info!(domain, cert = %tls_config.cert_path.display(), "TLS cert registered");
    }

    let mut tls_settings = TlsSettings::with_callbacks(Box::new(sni_resolver))
        .context("failed to create TLS settings")?;
    tls_settings.enable_h2();

    // Enforce TLS 1.2 minimum — SSLv3, TLS 1.0, and TLS 1.1 have known
    // vulnerabilities and are deprecated by RFC 8996.
    tls_settings
        .set_min_proto_version(Some(pingora_core::tls::ssl::SslVersion::TLS1_2))
        .context("failed to set minimum TLS version")?;

    proxy_service.add_tls_with_settings("0.0.0.0:6189", None, tls_settings);
    info!(
        listen = "0.0.0.0:6189",
        protocol = "https",
        "TLS listener registered"
    );
    Ok(())
}

fn fmt_config(path: &std::path::Path, check: bool) -> anyhow::Result<()> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("failed to stat config file: {}", path.display()))?;
    if metadata.len() > MAX_CONFIG_SIZE {
        bail!(
            "config file too large ({} bytes, max {} bytes)",
            metadata.len(),
            MAX_CONFIG_SIZE
        );
    }

    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config file: {}", path.display()))?;

    let config = dwaar_config::parser::parse(&text).map_err(|e| anyhow::anyhow!("{e}"))?;
    let formatted = dwaar_config::format::format_config(&config);

    if check {
        if text == formatted {
            return Ok(());
        }
        bail!(
            "Dwaarfile is not formatted. Run `dwaar fmt` to fix.\n{}",
            path.display()
        );
    }

    std::fs::write(path, &formatted)
        .with_context(|| format!("failed to write formatted config: {}", path.display()))?;

    Ok(())
}

fn validate_config(path: &std::path::Path) -> anyhow::Result<()> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("failed to stat config file: {}", path.display()))?;
    if metadata.len() > MAX_CONFIG_SIZE {
        bail!(
            "config file too large ({} bytes, max {} bytes)",
            metadata.len(),
            MAX_CONFIG_SIZE
        );
    }

    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config file: {}", path.display()))?;

    let config = dwaar_config::parser::parse(&text).map_err(|e| anyhow::anyhow!("{e}"))?;

    let table = compile_routes(&config);
    info!(
        sites = config.sites.len(),
        routes = table.len(),
        path = %path.display(),
        "config valid"
    );
    Ok(())
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
