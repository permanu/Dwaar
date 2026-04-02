// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Dwaar CLI entry point.
//!
//! Reads a Dwaarfile, parses it, compiles routes and TLS config,
//! and starts the Pingora proxy server with HTTP and optional TLS listeners.

// Use jemalloc globally — eliminates heap fragmentation from per-request
// String alloc/free churn and removes allocator lock contention that
// causes tail latency spikes under high concurrency.
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

mod admin_client;
mod cli;

use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use anyhow::{Context, bail};
use arc_swap::ArcSwap;
use pingora_core::listeners::TcpSocketOptions;
use pingora_core::listeners::tls::TlsSettings;
use pingora_core::server::Server;
use pingora_core::server::configuration::{Opt as PingoraOpt, ServerConf};
use tracing::info;

use cli::{Cli, Commands, WorkerCount};
use dashmap::DashMap;
use dwaar_admin::AdminService;
use dwaar_analytics::aggregation;
use dwaar_analytics::aggregation::service::{AggregationService, RouteValidator};
use dwaar_analytics::beacon;
use dwaar_config::MAX_CONFIG_SIZE;
use dwaar_config::compile::{
    BindAddress, collect_pools, compile_acme_domains, compile_routes, compile_tls_configs,
    extract_bind_addresses, has_tls_sites,
};
use dwaar_config::watcher::{ConfigWatcher, hash_content};
use dwaar_core::proxy::DwaarProxy;
use dwaar_log::{StdoutWriter, channel as log_channel, run_writer};
use dwaar_tls::acme::ChallengeSolver;
use dwaar_tls::acme::issuer::CertIssuer;
use dwaar_tls::acme::service::TlsBackgroundService;
use dwaar_tls::cert_store::CertStore;
use dwaar_tls::sni::{DomainTlsConfig, SniResolver};

/// Returned by `fork_workers` to tell the caller whether it is the supervisor
/// or one of the worker children.
enum WorkerRole {
    Supervisor,
    Worker(usize),
}

/// Fork `count` worker processes and supervise them.
///
/// The supervisor never calls `run_server()`. It loops waiting for children
/// to exit and restarts any that do, so worker crashes don't take the whole
/// process tree down.
///
/// Fork happens before Pingora or tokio are initialized — each child builds
/// its own server from scratch. This is safe because no shared state exists
/// yet.
///
/// # Safety
/// `fork()` must be called before any tokio runtime is created. Forking a
/// multi-threaded process is undefined behaviour; forking here (before Pingora's
/// `run_forever()`) guarantees we are still single-threaded.
#[allow(unsafe_code)]
fn fork_workers(count: usize) -> anyhow::Result<WorkerRole> {
    let mut children: Vec<libc::pid_t> = Vec::with_capacity(count);

    for id in 0..count {
        // SAFETY: fork() before any tokio/Pingora initialisation — single-threaded.
        let pid = unsafe { libc::fork() };
        match pid {
            -1 => {
                let err = std::io::Error::last_os_error();
                tracing::error!(worker = id, error = %err, "fork failed");
                anyhow::bail!("fork failed for worker {id}: {err}");
            }
            0 => {
                // Child — each worker returns immediately and starts its own server.
                return Ok(WorkerRole::Worker(id));
            }
            child_pid => {
                children.push(child_pid);
            }
        }
    }

    info!(workers = count, "supervisor: all worker processes started");

    // Supervisor loop — restart any worker that exits.
    loop {
        let mut status: libc::c_int = 0;
        // SAFETY: standard waitpid call; -1 means "any child".
        let exited_pid = unsafe { libc::waitpid(-1, &raw mut status, 0) };

        if exited_pid <= 0 {
            // No more children left to wait for — all workers must have exited.
            break;
        }

        let reason = if libc::WIFEXITED(status) {
            format!("exit code {}", libc::WEXITSTATUS(status))
        } else if libc::WIFSIGNALED(status) {
            format!("signal {}", libc::WTERMSIG(status))
        } else {
            "unknown".to_string()
        };

        tracing::warn!(
            pid = exited_pid,
            reason,
            "supervisor: worker exited — restarting"
        );

        // Remove the dead PID so we can track the new child.
        children.retain(|&p| p != exited_pid);

        // Restart with a new worker ID derived from slot position.
        let id = children.len(); // rough slot index for log labelling
        // SAFETY: same single-threaded fork guarantee as above.
        let pid = unsafe { libc::fork() };
        match pid {
            -1 => {
                let err = std::io::Error::last_os_error();
                tracing::error!(error = %err, "supervisor: restart fork failed");
            }
            0 => {
                return Ok(WorkerRole::Worker(id));
            }
            child_pid => {
                children.push(child_pid);
            }
        }
    }

    Ok(WorkerRole::Supervisor)
}

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
        Some(Commands::Routes { admin }) => {
            return cmd_routes(admin);
        }
        Some(Commands::Certs { cert_dir }) => {
            return cmd_certs(cert_dir);
        }
        Some(Commands::Reload { admin }) => {
            return cmd_reload(admin);
        }
        Some(Commands::Upgrade { binary, pid_file }) => {
            return cmd_upgrade(binary.as_deref(), pid_file);
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
    let dwaar_config = load_config(config_path)?;
    let drain_timeout = std::time::Duration::from_secs(extract_drain_timeout(&dwaar_config));

    if cli.test {
        info!("config valid");
        return Ok(());
    }

    let cpu_count = std::thread::available_parallelism()
        .map(std::num::NonZero::get)
        .unwrap_or(1);

    let worker_count = match cli.workers {
        WorkerCount::Auto => cpu_count,
        WorkerCount::Count(n) => n,
    };

    // Single-process mode skips forking — same behavior as before.
    if worker_count <= 1 {
        return run_server(&cli, &dwaar_config, config_path, drain_timeout, 0, 1);
    }

    match fork_workers(worker_count)? {
        WorkerRole::Supervisor => Ok(()),
        WorkerRole::Worker(id) => run_server(
            &cli,
            &dwaar_config,
            config_path,
            drain_timeout,
            id,
            worker_count,
        ),
    }
}

#[allow(clippy::too_many_lines)]
fn run_server(
    cli: &Cli,
    dwaar_config: &dwaar_config::model::DwaarConfig,
    config_path: &std::path::Path,
    drain_timeout: std::time::Duration,
    worker_id: usize,
    worker_count: usize,
) -> anyhow::Result<()> {
    let pingora_opt = PingoraOpt {
        upgrade: cli.upgrade,
        daemon: cli.daemon,
        nocapture: false,
        test: false,
        conf: None,
    };

    // Divide CPU threads across workers to avoid oversubscription.
    // Single-process mode gets the full core count (same as before).
    let cpu_count = std::thread::available_parallelism()
        .map(std::num::NonZero::get)
        .unwrap_or(1);
    let threads = (cpu_count / worker_count).max(1);

    let conf = ServerConf {
        threads,
        work_stealing: true,
        upstream_keepalive_pool_size: 256,
        grace_period_seconds: Some(5),
        graceful_shutdown_timeout_seconds: Some(5),
        ..ServerConf::default()
    };

    let mut server = Server::new_with_opt_and_conf(Some(pingora_opt), conf);
    server.bootstrap();

    info!(
        worker_id,
        worker_count,
        threads = server.configuration.threads,
        work_stealing = server.configuration.work_stealing,
        grace_period = server.configuration.grace_period_seconds,
        "server bootstrapped"
    );

    // Compile routes
    let route_table = compile_routes(dwaar_config);
    if route_table.is_empty() {
        bail!("no valid routes found in config — nothing to proxy");
    }
    info!(routes = route_table.len(), "route table compiled");

    // Collect upstream pools that have health URIs before wrapping the table.
    // This must happen before ArcSwap wrapping because collect_pools borrows the table.
    let health_pools = collect_pools(&route_table);

    // Capture initial routes before wrapping — DockerWatcher needs a
    // separate snapshot of Dwaarfile routes for merge operations.
    let initial_routes = route_table.all_routes();

    let route_table = Arc::new(ArcSwap::from_pointee(route_table));

    // Shared state for Docker mode: the snapshot holds compiled Dwaarfile
    // routes, and the Notify wakes DockerWatcher to re-merge after changes.
    let dwaarfile_snapshot: Arc<ArcSwap<Vec<dwaar_core::route::Route>>> =
        Arc::new(ArcSwap::from_pointee(initial_routes));
    let config_notify = Arc::new(tokio::sync::Notify::new());

    let acme_domains = compile_acme_domains(dwaar_config);
    let challenge_solver = if acme_domains.is_empty() {
        None
    } else {
        Some(Arc::new(ChallengeSolver::new()))
    };

    let (log_sender, log_receiver) = if cli.logging_enabled() {
        let (s, r) = log_channel();
        (Some(s), Some(r))
    } else {
        info!("request logging disabled via CLI flag");
        (None, None)
    };

    let (beacon_sender, beacon_receiver, agg_sender, agg_receiver) = if cli.analytics_enabled() {
        let (bs, br) = beacon::beacon_channel();
        let (as_, ar) = aggregation::agg_channel();
        (Some(bs), Some(br), Some(as_), Some(ar))
    } else {
        info!("analytics disabled via CLI flag");
        (None, None, None, None)
    };

    let route_table_for_admin = Arc::clone(&route_table);
    let route_table_for_watcher = Arc::clone(&route_table);
    let route_table_for_docker = Arc::clone(&route_table);
    let route_table_for_agg = Arc::clone(&route_table);

    // GeoIP — load the MaxMind database if present. Not a hard requirement;
    // country enrichment simply won't happen without it.
    let geo_lookup = if cli.geoip_enabled() {
        load_geoip_database()
    } else {
        info!("GeoIP disabled via CLI flag");
        None
    };

    // Build the plugin chain with all built-in plugins, sorted by priority.
    // Under Attack Mode uses a random secret — in production this should
    // come from config or environment for persistence across restarts.
    let plugin_chain = if cli.plugins_enabled() {
        let under_attack_secret: Vec<u8> = {
            use rand::Rng;
            let mut buf = vec![0u8; 32];
            rand::rng().fill_bytes(&mut buf);
            buf
        };
        Arc::new(dwaar_plugins::plugin::PluginChain::new(vec![
            Box::new(dwaar_plugins::bot_detect::BotDetectPlugin::new()),
            Box::new(dwaar_plugins::under_attack::UnderAttackPlugin::new(
                under_attack_secret,
            )),
            Box::new(dwaar_plugins::ip_filter::IpFilterPlugin::new()),
            Box::new(dwaar_plugins::rate_limit::RateLimitPlugin::new()),
            Box::new(dwaar_plugins::compress::CompressionPlugin::new()),
            Box::new(dwaar_plugins::security_headers::SecurityHeadersPlugin::new()),
        ]))
    } else {
        info!("plugins disabled via CLI flag");
        Arc::new(dwaar_plugins::plugin::PluginChain::new(vec![]))
    };

    // Prometheus metrics registry (ISSUE-072)
    let prometheus = if cli.metrics_enabled() {
        Some(std::sync::Arc::new(
            dwaar_analytics::prometheus::PrometheusMetrics::new(),
        ))
    } else {
        None
    };

    // Cache backend (ISSUE-073): find max cache size from all routes, init once.
    let cache_backend = if cli.cache_enabled() {
        let max_cache_size = route_table
            .load()
            .all_routes()
            .iter()
            .flat_map(|r| r.handlers.iter())
            .filter_map(|h| h.cache.as_ref())
            .map(|c| c.max_size)
            .max();

        max_cache_size.map(|size| {
            tracing::info!(max_size_bytes = size, "HTTP cache enabled");
            dwaar_core::cache::init_cache_backend(size)
        })
    } else {
        info!("HTTP cache disabled via CLI flag");
        None
    };

    info!(
        logging = cli.logging_enabled(),
        plugins = cli.plugins_enabled(),
        analytics = cli.analytics_enabled(),
        geoip = cli.geoip_enabled(),
        metrics = cli.metrics_enabled(),
        cache = cli.cache_enabled(),
        "feature flags resolved"
    );

    let proxy = DwaarProxy::new(
        route_table,
        challenge_solver.clone(),
        log_sender,
        beacon_sender,
        agg_sender,
        geo_lookup,
        plugin_chain,
        prometheus.clone(),
        cache_backend,
    );

    let mut proxy_service = pingora_proxy::http_proxy_service(&server.configuration, proxy);

    // Bind listeners from the `bind` directive, falling back to 0.0.0.0:6188
    // when no site specifies one. Multiple workers each bind the same TCP
    // address independently via SO_REUSEPORT — the kernel load-balances across
    // workers without a single accept() bottleneck.
    let bind_addrs = extract_bind_addresses(dwaar_config);
    for addr in &bind_addrs {
        match addr {
            BindAddress::Tcp(a) => {
                if worker_count > 1 {
                    let mut sock_opt = TcpSocketOptions::default();
                    sock_opt.so_reuseport = Some(true);
                    proxy_service.add_tcp_with_settings(a, sock_opt);
                } else {
                    proxy_service.add_tcp(a);
                }
                info!(listen = %a, protocol = "http", "listener registered");
            }
            BindAddress::Unix(path) => {
                proxy_service.add_uds(path.to_str().expect("bind path must be valid UTF-8"), None);
                info!(listen = ?path, protocol = "http/uds", "listener registered");
            }
        }
    }

    let cert_store = Arc::new(CertStore::new("/etc/dwaar/certs", 1000));

    if has_tls_sites(dwaar_config) {
        setup_tls_listener(
            dwaar_config,
            &mut proxy_service,
            &cert_store,
            worker_count > 1,
        )?;
    }

    server.add_service(proxy_service);

    // Shared analytics metrics — created here so both AdminService and
    // AggregationService reference the same DashMap instance.
    let agg_metrics: Arc<DashMap<String, dwaar_analytics::aggregation::DomainMetrics>> =
        Arc::new(DashMap::new());

    // Admin API service
    let admin_token = std::env::var("DWAAR_ADMIN_TOKEN").ok();
    let admin_service = AdminService::new(
        route_table_for_admin,
        Arc::clone(&agg_metrics),
        std::time::Instant::now(),
        admin_token,
    )
    .with_reload_notify(Arc::clone(&config_notify));

    let admin_service = if let Some(ref prom) = prometheus {
        admin_service.with_prometheus(Arc::clone(prom))
    } else {
        admin_service
    };

    let admin_service = if let Some(ref cb) = cache_backend {
        admin_service.with_cache_storage(cb.storage)
    } else {
        admin_service
    };

    let mut admin_listening =
        pingora_core::services::listening::Service::new("admin API".to_string(), admin_service);
    admin_listening.add_tcp("127.0.0.1:6190");

    if let Some(ref socket_path) = cli.admin_socket {
        let path_str = socket_path
            .to_str()
            .context("admin socket path must be valid UTF-8")?;

        // Stale socket cleanup — a leftover file from a crash blocks bind
        match std::fs::remove_file(socket_path) {
            Ok(()) => tracing::debug!("removed stale admin socket"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => bail!("cannot remove stale admin socket {path_str}: {e}"),
        }

        admin_listening.add_uds(path_str, Some(Permissions::from_mode(0o660)));
        info!(socket = path_str, "admin API UDS listener registered");
    }

    server.add_service(admin_listening);
    info!(listen = "127.0.0.1:6190", "admin API registered");

    register_background_services(
        &mut server,
        cli,
        challenge_solver.as_ref(),
        &acme_domains,
        &cert_store,
        log_receiver,
        config_path,
        &route_table_for_watcher,
        &route_table_for_docker,
        &dwaarfile_snapshot,
        &config_notify,
        beacon_receiver,
        agg_receiver,
        &route_table_for_agg,
        &agg_metrics,
        health_pools,
        drain_timeout,
    );

    info!("entering run loop, waiting for connections or signals");
    server.run_forever();
}

#[allow(clippy::too_many_arguments)]
fn register_background_services(
    server: &mut Server,
    cli: &Cli,
    challenge_solver: Option<&Arc<ChallengeSolver>>,
    acme_domains: &[String],
    cert_store: &Arc<CertStore>,
    log_receiver: Option<dwaar_log::LogReceiver>,
    config_path: &std::path::Path,
    route_table: &Arc<ArcSwap<dwaar_core::route::RouteTable>>,
    main_route_table: &Arc<ArcSwap<dwaar_core::route::RouteTable>>,
    dwaarfile_snapshot: &Arc<ArcSwap<Vec<dwaar_core::route::Route>>>,
    config_notify: &Arc<tokio::sync::Notify>,
    beacon_receiver: Option<tokio::sync::mpsc::Receiver<dwaar_analytics::beacon::BeaconEvent>>,
    agg_receiver: Option<aggregation::AggReceiver>,
    route_table_for_agg: &Arc<ArcSwap<dwaar_core::route::RouteTable>>,
    agg_metrics: &Arc<DashMap<String, dwaar_analytics::aggregation::DomainMetrics>>,
    health_pools: Vec<Arc<dwaar_core::upstream::UpstreamPool>>,
    drain_timeout: std::time::Duration,
) {
    // Upstream health checker — only registered when there are pools with health URIs.
    // Per Guardrail #20: all async background work must be a BackgroundService.
    if !health_pools.is_empty() {
        let checker = dwaar_core::upstream::HealthChecker::new(health_pools);
        let health_bg =
            pingora_core::services::background::background_service("health checker", checker);
        server.add_service(health_bg);
        info!("upstream health checker registered");
    }

    // ACME + OCSP background service
    if let Some(solver) = challenge_solver {
        let issuer = Arc::new(CertIssuer::new(
            "/etc/dwaar/acme",
            "/etc/dwaar/certs",
            Arc::clone(solver),
            Arc::clone(cert_store),
        ));
        let tls_service = TlsBackgroundService::new(
            acme_domains.to_vec(),
            "/etc/dwaar/certs",
            issuer,
            Arc::clone(cert_store),
        );

        let bg = pingora_core::services::background::background_service(
            "TLS cert & OCSP manager",
            tls_service,
        );
        server.add_service(bg);
        info!(
            domains = acme_domains.len(),
            "TLS background service registered"
        );
    }

    // Log batch writer — only registered when logging is enabled
    if let Some(receiver) = log_receiver {
        let log_bg = pingora_core::services::background::background_service(
            "log writer",
            LogWriterService {
                receiver: std::sync::Mutex::new(Some(receiver)),
            },
        );
        server.add_service(log_bg);
        info!("log writer registered (JSON lines to stdout)");
    }

    // Config file watcher for hot-reload
    let initial_hash = hash_content(&std::fs::read(config_path).unwrap_or_default());
    let config_watcher = ConfigWatcher::new(
        config_path.to_path_buf(),
        Arc::clone(route_table),
        initial_hash,
    )
    .with_drain_timeout(drain_timeout)
    .with_reload_notify(Arc::clone(config_notify));
    let config_watcher = if cli.docker_socket.is_some() {
        config_watcher.with_docker_mode(Arc::clone(dwaarfile_snapshot), Arc::clone(config_notify))
    } else {
        config_watcher
    };
    let config_bg =
        pingora_core::services::background::background_service("config watcher", config_watcher);
    server.add_service(config_bg);
    info!(path = %config_path.display(), "config watcher registered");

    // Docker container auto-discovery
    if let Some(ref socket_path) = cli.docker_socket {
        let docker_watcher = dwaar_docker::watcher::DockerWatcher::new(
            socket_path.clone(),
            Arc::clone(main_route_table),
            Arc::clone(dwaarfile_snapshot),
            Arc::clone(config_notify),
        );
        let docker_bg = pingora_core::services::background::background_service(
            "Docker watcher",
            docker_watcher,
        );
        server.add_service(docker_bg);
        info!(socket = %socket_path.display(), "Docker watcher registered");
    }

    // Analytics aggregation service — only registered when analytics is enabled
    if let (Some(br), Some(ar)) = (beacon_receiver, agg_receiver) {
        let agg_service = AggregationService::new(
            Arc::clone(agg_metrics),
            LiveRouteValidator(Arc::clone(route_table_for_agg)),
            br,
            ar,
        );
        let agg_bg = pingora_core::services::background::background_service(
            "analytics aggregation",
            AggServiceWrapper {
                inner: Arc::new(agg_service),
            },
        );
        server.add_service(agg_bg);
        info!("analytics aggregation service registered");
    }
}

fn load_config(path: &std::path::Path) -> anyhow::Result<dwaar_config::model::DwaarConfig> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("failed to stat config file: {}", path.display()))?;
    if metadata.len() > MAX_CONFIG_SIZE {
        bail!(
            "config file too large ({} bytes, max {} bytes)",
            metadata.len(),
            MAX_CONFIG_SIZE
        );
    }

    let config_text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config file: {}", path.display()))?;

    let config = dwaar_config::parser::parse(&config_text).map_err(|e| anyhow::anyhow!("{e}"))?;

    info!(
        sites = config.sites.len(),
        path = %path.display(),
        "config loaded"
    );

    Ok(config)
}

/// Extract `drain_timeout` from the parsed config's global options.
/// Defaults to 30 seconds when not specified.
fn extract_drain_timeout(config: &dwaar_config::model::DwaarConfig) -> u64 {
    config
        .global_options
        .as_ref()
        .and_then(|g| g.drain_timeout_secs)
        .unwrap_or(30)
}

fn setup_tls_listener(
    config: &dwaar_config::model::DwaarConfig,
    proxy_service: &mut pingora_core::services::listening::Service<
        pingora_proxy::HttpProxy<DwaarProxy>,
    >,
    cert_store: &Arc<CertStore>,
    use_reuseport: bool,
) -> anyhow::Result<()> {
    let tls_configs = compile_tls_configs(config);

    let mut sni_resolver = SniResolver::new(Arc::clone(cert_store));

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

    // Enable OCSP stapling — OpenSSL requires this callback on the SslContext
    // for set_ocsp_status() to actually send the response to clients.
    tls_settings
        .set_status_callback(|ssl| Ok(ssl.ocsp_status().is_some()))
        .expect("set OCSP status callback");

    let tcp_opt = if use_reuseport {
        let mut opt = TcpSocketOptions::default();
        opt.so_reuseport = Some(true);
        Some(opt)
    } else {
        None
    };

    proxy_service.add_tls_with_settings("0.0.0.0:6189", tcp_opt, tls_settings);
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

// ── CLI subcommands (Phase 12) ──────────────────────────────────────

/// `dwaar routes` — query the admin API and display active routes as a table.
fn cmd_routes(admin_addr: &str) -> anyhow::Result<()> {
    use std::io::Write;

    let resp = admin_client::get(admin_addr, "/routes")?;
    if resp.status != 200 {
        bail!("admin API returned {}: {}", resp.status, resp.body);
    }

    let routes: Vec<serde_json::Value> =
        serde_json::from_str(&resp.body).context("failed to parse routes JSON")?;

    if routes.is_empty() {
        writeln!(std::io::stderr(), "no routes configured")?;
        return Ok(());
    }

    let mut out = std::io::stdout().lock();
    writeln!(
        out,
        "{:<40} {:<25} {:<6} {:<12} {:<8}",
        "DOMAIN", "UPSTREAM", "TLS", "RATE LIMIT", "UAM"
    )?;
    writeln!(out, "{}", "-".repeat(95))?;

    for route in &routes {
        let domain = route["domain"].as_str().unwrap_or("-");
        let upstream = route["upstream"].as_str().unwrap_or("-");
        let tls = if route["tls"].as_bool().unwrap_or(false) {
            "yes"
        } else {
            "no"
        };
        let rate_limit = route["rate_limit_rps"]
            .as_u64()
            .map_or_else(|| "-".to_string(), |r| format!("{r}/s"));
        let uam = if route["under_attack"].as_bool().unwrap_or(false) {
            "on"
        } else {
            "off"
        };

        writeln!(
            out,
            "{domain:<40} {upstream:<25} {tls:<6} {rate_limit:<12} {uam:<8}"
        )?;
    }

    Ok(())
}

/// `dwaar certs` — list managed TLS certificates from the cert store directory.
fn cmd_certs(cert_dir: &std::path::Path) -> anyhow::Result<()> {
    use std::io::Write;

    if !cert_dir.exists() {
        bail!(
            "cert directory not found: {}\nIs Dwaar configured with TLS?",
            cert_dir.display()
        );
    }

    let mut certs = Vec::new();

    for entry in std::fs::read_dir(cert_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "pem" || e == "crt")
            && let Ok(pem_data) = std::fs::read(&path)
            && let Ok(cert_info) = parse_cert_info(&pem_data, &path)
        {
            certs.push(cert_info);
        }
    }

    if certs.is_empty() {
        use std::io::Write;
        writeln!(
            std::io::stderr(),
            "no certificates found in {}",
            cert_dir.display()
        )?;
        return Ok(());
    }

    certs.sort_by(|a, b| a.domain.cmp(&b.domain));

    let mut out = std::io::stdout().lock();
    writeln!(
        out,
        "{:<40} {:<30} {:<12} {:<15}",
        "DOMAIN", "ISSUER", "EXPIRES", "DAYS LEFT"
    )?;
    writeln!(out, "{}", "-".repeat(100))?;

    for cert in &certs {
        let days_str = if cert.days_remaining < 0 {
            "EXPIRED".to_string()
        } else {
            cert.days_remaining.to_string()
        };
        writeln!(
            out,
            "{:<40} {:<30} {:<12} {:<15}",
            cert.domain, cert.issuer, cert.expiry_date, days_str
        )?;
    }

    Ok(())
}

struct CertInfo {
    domain: String,
    issuer: String,
    expiry_date: String,
    days_remaining: i64,
}

/// Parse X.509 info from a PEM file using OpenSSL.
fn parse_cert_info(pem_data: &[u8], path: &std::path::Path) -> anyhow::Result<CertInfo> {
    let cert =
        openssl::x509::X509::from_pem(pem_data).context("failed to parse PEM certificate")?;

    let domain = cert
        .subject_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok())
        .map_or_else(
            || {
                // Fall back to filename
                path.file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown")
                    .to_string()
            },
            |cn| cn.to_string(),
        );

    let issuer = cert
        .issuer_name()
        .entries_by_nid(openssl::nid::Nid::ORGANIZATIONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok())
        .map_or_else(|| "unknown".to_string(), |o| o.to_string());

    // Parse expiry using OpenSSL's ASN1_TIME
    let not_after = cert.not_after();
    let expiry_date = not_after.to_string();

    // Compute days remaining by comparing with current time
    let now = openssl::asn1::Asn1Time::days_from_now(0).context("failed to get current time")?;
    let diff = now.diff(not_after).context("failed to compute time diff")?;
    let days_remaining = i64::from(diff.days);

    Ok(CertInfo {
        domain,
        issuer,
        expiry_date,
        days_remaining,
    })
}

/// `dwaar reload` — trigger config reload on the running instance.
fn cmd_reload(admin_addr: &str) -> anyhow::Result<()> {
    use std::io::Write;

    let resp = admin_client::post(admin_addr, "/reload", "")?;

    match resp.status {
        200 => {
            let body: serde_json::Value =
                serde_json::from_str(&resp.body).unwrap_or(serde_json::Value::Null);
            let mut out = std::io::stdout().lock();
            if let Some(msg) = body["message"].as_str() {
                writeln!(out, "{msg}")?;
            } else {
                writeln!(out, "config reloaded successfully")?;
            }
            Ok(())
        }
        _ => bail!("reload failed ({}): {}", resp.status, resp.body),
    }
}

/// `dwaar upgrade` — zero-downtime binary upgrade via Pingora's FD transfer.
///
/// 1. Reads the PID of the running instance from the PID file
/// 2. Starts a new Dwaar process with `--upgrade` (inherits listeners via FD transfer)
/// 3. Sends SIGQUIT to the old process for graceful shutdown
fn cmd_upgrade(binary: Option<&std::path::Path>, pid_file: &std::path::Path) -> anyhow::Result<()> {
    use std::io::Write;
    let mut out = std::io::stdout().lock();

    // Resolve the binary to use
    let binary_path = match binary {
        Some(p) => p.to_path_buf(),
        None => std::env::current_exe().context("cannot determine current executable path")?,
    };

    if !binary_path.exists() {
        bail!("binary not found: {}", binary_path.display());
    }

    // Read the PID of the old process
    let pid_str = std::fs::read_to_string(pid_file)
        .with_context(|| format!("cannot read PID file: {}", pid_file.display()))?;
    let old_pid: i32 = pid_str
        .trim()
        .parse()
        .with_context(|| format!("invalid PID in {}: {pid_str:?}", pid_file.display()))?;

    writeln!(out, "upgrading dwaar (old PID: {old_pid})")?;

    // Collect the arguments the new process should use — same config as old
    // but with --upgrade to trigger Pingora's FD transfer.
    let mut args: Vec<String> = std::env::args().collect();
    // Remove "upgrade" subcommand and its arguments from the args
    // The new process should run in server mode with --upgrade
    args.truncate(1); // Keep just the binary name placeholder
    args[0] = binary_path.display().to_string();
    args.push("--upgrade".to_string());

    writeln!(
        out,
        "starting new process: {} --upgrade",
        binary_path.display()
    )?;

    let child = std::process::Command::new(&binary_path)
        .arg("--upgrade")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .with_context(|| format!("failed to start new process: {}", binary_path.display()))?;

    writeln!(out, "new process started (PID: {})", child.id())?;

    // Give the new process time to connect to the upgrade socket and
    // receive file descriptors before we signal the old process.
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Send SIGQUIT to the old process for graceful shutdown.
    // SIGQUIT triggers Pingora's graceful drain — it stops accepting new
    // connections and waits for in-flight requests to complete.
    writeln!(out, "sending SIGQUIT to old process (PID: {old_pid})")?;

    // SAFETY: libc::kill sends a signal to a process. The PID was read from
    // a file controlled by the user (the PID file). Sending SIGQUIT to a
    // non-Dwaar process is the user's responsibility (wrong PID file).
    #[allow(unsafe_code)]
    let result = unsafe { libc::kill(old_pid, libc::SIGQUIT) };

    if result != 0 {
        let err = std::io::Error::last_os_error();
        bail!("failed to send SIGQUIT to PID {old_pid}: {err}");
    }

    writeln!(out, "upgrade complete — old process will drain and exit")?;

    Ok(())
}

fn print_version() {
    use std::io::Write;
    let _ = writeln!(std::io::stderr(), "dwaar v{}", env!("CARGO_PKG_VERSION"));
}

/// Wraps the log batch writer as a Pingora `BackgroundService`.
///
/// Needed because `run_writer` is async and requires a tokio runtime.
/// Pingora's `run_forever()` creates the runtime, so we can't call
/// `tokio::spawn` before it. Instead, Pingora runs this service
/// inside its own runtime.
struct LogWriterService {
    receiver: std::sync::Mutex<Option<dwaar_log::LogReceiver>>,
}

#[async_trait::async_trait]
impl pingora_core::services::background::BackgroundService for LogWriterService {
    async fn start(&self, _shutdown: pingora_core::server::ShutdownWatch) {
        // Take the receiver out of the Mutex. start() is called once by Pingora.
        let receiver = self
            .receiver
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();

        if let Some(rx) = receiver {
            run_writer(rx, Box::new(StdoutWriter)).await;
        }
    }
}

/// Route validator that checks the live `ArcSwap<RouteTable>`.
///
/// Used by `AggregationService` to reject metrics for unknown hosts
/// (Guardrail #17: treat all client input as adversarial).
struct LiveRouteValidator(Arc<ArcSwap<dwaar_core::route::RouteTable>>);

impl RouteValidator for LiveRouteValidator {
    fn is_known_host(&self, host: &str) -> bool {
        self.0.load().resolve(host).is_some()
    }
}

/// Wraps `AggregationService` as a Pingora `BackgroundService`.
struct AggServiceWrapper<RT: RouteValidator + 'static> {
    inner: Arc<AggregationService<RT>>,
}

#[async_trait::async_trait]
impl<RT: RouteValidator + 'static> pingora_core::services::background::BackgroundService
    for AggServiceWrapper<RT>
{
    async fn start(&self, shutdown: pingora_core::server::ShutdownWatch) {
        self.inner.run(shutdown).await;
    }
}

/// Try to load a `GeoIP` database from standard paths.
/// Returns `None` if no database is found — country enrichment simply
/// won't happen, which is fine for development or minimal setups.
fn load_geoip_database() -> Option<Arc<dwaar_geo::GeoLookup>> {
    let paths = [
        std::path::PathBuf::from("/etc/dwaar/geoip/GeoLite2-Country.mmdb"),
        std::path::PathBuf::from("/usr/share/GeoIP/GeoLite2-Country.mmdb"),
    ];

    for path in &paths {
        if path.exists() {
            match dwaar_geo::GeoLookup::open(path) {
                Ok(geo) => return Some(Arc::new(geo)),
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "failed to load GeoIP database");
                }
            }
        }
    }

    info!("no GeoIP database found — country enrichment disabled");
    None
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
