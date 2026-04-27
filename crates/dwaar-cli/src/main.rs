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

// Tune jemalloc to prevent Linux THP (Transparent Huge Pages) from inflating
// RSS. Without this, THP promotes jemalloc arenas to 2 MB pages — even a
// 50 KB arena becomes 2 MB of RSS. On a VPS with few routes this alone
// caused 128 MB RSS for a 3 MB heap.
//
// - thp:never        → opt out of THP (biggest win)
// - narenas:2        → 2 arenas instead of 4×cores (work-stealing makes more unnecessary)
// - muzzy_decay_ms   → return freed-but-held pages to OS after 1 s
// - dirty_decay_ms   → return dirty pages after 0.5 s
#[allow(non_upper_case_globals, unsafe_code)]
#[unsafe(export_name = "_rjem_malloc_conf")]
pub static malloc_conf: &[u8] = b"thp:never,narenas:2,muzzy_decay_ms:1000,dirty_decay_ms:500\0";

mod admin_client;
mod auto_update;
mod cli;
mod readiness;
mod self_update;
mod version_check;

use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use anyhow::{Context, bail};
use arc_swap::ArcSwap;
use pingora_core::listeners::TcpSocketOptions;
use pingora_core::listeners::tls::TlsSettings;
use pingora_core::server::Server;
use pingora_core::server::configuration::{Opt as PingoraOpt, ServerConf};
use tracing::{info, warn};

use cli::{Cli, Commands, WorkerCount};
use dashmap::DashMap;
use dwaar_admin::AdminService;
use dwaar_analytics::aggregation;
use dwaar_analytics::aggregation::service::{AggregationService, RouteValidator};
use dwaar_analytics::beacon;
use dwaar_config::MAX_CONFIG_SIZE;
use dwaar_config::compile::{
    BindAddress, collect_pools, compile_acme_domains, compile_routes, compile_tls_configs,
    extract_bind_addresses, extract_tls_bind_addresses, has_tls_sites,
};
use dwaar_config::watcher::{ConfigWatcher, hash_content};
use dwaar_core::proxy::DwaarProxy;
use dwaar_log::{StdoutWriter, channel as log_channel, run_writer};
use dwaar_tls::acme::ChallengeSolver;
use dwaar_tls::acme::issuer::CertIssuer;
use dwaar_tls::acme::service::TlsBackgroundService;
use dwaar_tls::cert_store::CertStore;
use dwaar_tls::sni::{DomainConfigMap, DomainTlsConfig, SniResolver, domain_config_map_empty};

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
fn fork_workers(
    count: usize,
    readiness_target: &readiness::ReadinessTarget,
) -> anyhow::Result<WorkerRole> {
    let mut children: Vec<libc::pid_t> = Vec::with_capacity(count);

    // Spawn each worker via fork_one_worker. Children return immediately;
    // the supervisor collects their PIDs and continues below.
    for id in 0..count {
        match fork_one_worker(id)? {
            ForkOutcome::Worker(worker_id) => return Ok(WorkerRole::Worker(worker_id)),
            ForkOutcome::Supervisor(child_pid) => children.push(child_pid),
        }
    }

    info!(workers = count, "supervisor: all worker processes started");

    // Block until worker 0 passes its readiness probe. Worker 0 is the only
    // child that binds the admin listener, so it is the only one we can probe
    // deterministically.
    probe_worker0_readiness(&children, readiness_target)?;

    // Build reverse mapping so restarts can preserve logical worker IDs.
    let mut pid_to_id: std::collections::HashMap<libc::pid_t, usize> =
        children.iter().enumerate().map(|(i, &p)| (p, i)).collect();

    // Install SIGTERM/SIGINT handlers so the supervisor can relay shutdown to
    // workers when the operator sends a signal.
    install_supervisor_signal_handlers();

    let max_backoff = std::time::Duration::from_secs(30);
    let crash_window = std::time::Duration::from_secs(5);
    let stable_run = std::time::Duration::from_secs(30);
    let mut backoff = std::time::Duration::from_secs(1);
    let mut worker_started: std::collections::HashMap<libc::pid_t, std::time::Instant> = children
        .iter()
        .map(|&p| (p, std::time::Instant::now()))
        .collect();

    Ok(run_supervisor_loop(
        &mut children,
        &mut pid_to_id,
        &mut worker_started,
        &mut backoff,
        max_backoff,
        crash_window,
        stable_run,
        readiness_target,
    ))
}

/// Outcome of a single `fork()` call during initial worker spawning.
enum ForkOutcome {
    /// This process is the supervisor; child has the given PID.
    Supervisor(libc::pid_t),
    /// This process is the new child with the given logical worker ID.
    Worker(usize),
}

/// Fork one worker process with the given logical `id`.
///
/// Returns immediately in both parent and child. The caller must check the
/// variant and either continue the spawn loop (supervisor) or break out and
/// start the server (worker).
///
/// # Safety
/// Must be called before any tokio/threading initialisation. `fork()` in a
/// multi-threaded process is undefined behaviour.
#[allow(unsafe_code)]
fn fork_one_worker(id: usize) -> anyhow::Result<ForkOutcome> {
    // SAFETY: fork() before any tokio/Pingora initialisation — single-threaded.
    let pid = unsafe { libc::fork() };
    match pid {
        -1 => {
            let err = std::io::Error::last_os_error();
            tracing::error!(worker = id, error = %err, "fork failed");
            anyhow::bail!("fork failed for worker {id}: {err}");
        }
        0 => Ok(ForkOutcome::Worker(id)),
        child_pid => Ok(ForkOutcome::Supervisor(child_pid)),
    }
}

/// Probe worker 0's readiness after the initial fork loop.
///
/// Worker 0 is the only child that binds the admin listener; it is therefore
/// the only one we can probe deterministically. Non-zero workers share the
/// public `SO_REUSEPORT` listeners and have no stable endpoint to hit before
/// sibling workers are running, so their `fork()` success is treated as readiness.
///
/// On failure, sends SIGKILL to every child in `children` before returning the
/// error so the caller doesn't leave half-bound processes around.
///
/// # Safety
/// Sends SIGKILL to known child PIDs via `libc::kill` on readiness failure.
#[allow(unsafe_code)]
fn probe_worker0_readiness(
    children: &[libc::pid_t],
    readiness_target: &readiness::ReadinessTarget,
) -> anyhow::Result<()> {
    let Some(&worker0_pid) = children.first() else {
        return Ok(());
    };

    if let Err(e) = readiness::wait_for_child_ready(
        worker0_pid,
        readiness_target,
        readiness::MAX_READINESS_TIMEOUT,
    ) {
        tracing::error!(
            pid = worker0_pid,
            error = %e,
            "supervisor: worker 0 failed readiness probe on initial boot — aborting"
        );
        // Kill every worker we already started so the launcher doesn't
        // leave half-bound processes around.
        for &pid in children {
            // SAFETY: sending SIGKILL to known child PIDs.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
        anyhow::bail!("worker 0 readiness probe failed: {e}");
    }

    info!(
        pid = worker0_pid,
        "supervisor: worker 0 passed readiness probe"
    );
    Ok(())
}

/// Install SIGTERM and SIGINT handlers that set the supervisor shutdown flag.
///
/// The handlers are async-signal-safe: they only write an atomic bool. The
/// supervisor loop reads the flag with `SeqCst` ordering to guarantee the store
/// is observed (H-05: Relaxed is a data race across the signal/main boundary
/// because the C11 memory model provides no happens-before edge there).
///
/// # Safety
/// Installs signal handlers via `libc::signal`. Must be called from the
/// single-threaded supervisor before the wait loop.
#[allow(unsafe_code)]
fn install_supervisor_signal_handlers() {
    // SAFETY: signal handler only sets an atomic flag — async-signal-safe.
    unsafe {
        libc::signal(
            libc::SIGTERM,
            handle_shutdown as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGINT,
            handle_shutdown as *const () as libc::sighandler_t,
        );
    }
}

/// Apply crash-loop backoff for a worker that exited too quickly.
///
/// If the worker lived shorter than `crash_window`, sleeps for `backoff` and
/// doubles it (capped at `max_backoff`). If it ran for at least `stable_run`,
/// resets backoff to 1 s — a long-lived worker is not in a crash loop.
///
/// Returns the (possibly updated) backoff duration.
fn apply_crash_backoff(
    started_at: Option<std::time::Instant>,
    exited_pid: libc::pid_t,
    reason: &str,
    backoff: std::time::Duration,
    crash_window: std::time::Duration,
    stable_run: std::time::Duration,
    max_backoff: std::time::Duration,
) -> std::time::Duration {
    let Some(start) = started_at else {
        return backoff;
    };

    if start.elapsed() < crash_window {
        tracing::warn!(
            pid = exited_pid,
            reason,
            backoff_ms = backoff.as_millis(),
            "supervisor: worker crashed quickly — backing off"
        );
        std::thread::sleep(backoff);
        return (backoff * 2).min(max_backoff);
    }

    if start.elapsed() >= stable_run {
        return std::time::Duration::from_secs(1);
    }

    backoff
}

/// Fork a replacement for a dead worker and register it in the supervisor's
/// tracking state.
///
/// Returns `Ok(Some(WorkerRole::Worker(id)))` when this process is the new
/// child, so the caller can propagate the role immediately. Returns
/// `Ok(None)` in the supervisor once the child has been registered (or
/// dropped after a failed readiness probe).
///
/// # Safety
/// Calls `fork()` — must be invoked from the single-threaded supervisor
/// before any tokio/threading initialisation. Also calls `libc::kill` and
/// `libc::waitpid` to clean up a child that fails its readiness probe.
#[allow(unsafe_code)]
fn restart_worker(
    dead_id: usize,
    readiness_target: &readiness::ReadinessTarget,
    children: &mut Vec<libc::pid_t>,
    pid_to_id: &mut std::collections::HashMap<libc::pid_t, usize>,
    worker_started: &mut std::collections::HashMap<libc::pid_t, std::time::Instant>,
    backoff: &mut std::time::Duration,
    max_backoff: std::time::Duration,
) -> Option<WorkerRole> {
    // SAFETY: same single-threaded fork guarantee as the initial spawn.
    let pid = unsafe { libc::fork() };
    match pid {
        -1 => {
            let err = std::io::Error::last_os_error();
            tracing::error!(error = %err, "supervisor: restart fork failed");
        }
        0 => {
            return Some(WorkerRole::Worker(dead_id));
        }
        child_pid => {
            // Only worker 0 owns the admin listener — its readiness can
            // be verified by connecting to that endpoint. Non-zero worker
            // restarts are accepted as ready on fork() success because
            // they share `SO_REUSEPORT` listeners with their siblings and
            // have no deterministic bind to probe.
            if dead_id == 0 {
                match readiness::wait_for_child_ready(
                    child_pid,
                    readiness_target,
                    readiness::MAX_READINESS_TIMEOUT,
                ) {
                    Ok(()) => {
                        info!(
                            pid = child_pid,
                            worker_id = dead_id,
                            "supervisor: restarted worker passed readiness probe"
                        );
                        children.push(child_pid);
                        pid_to_id.insert(child_pid, dead_id);
                        worker_started.insert(child_pid, std::time::Instant::now());
                    }
                    Err(e) => {
                        // Readiness failed — SIGKILL and fall back to the
                        // normal crash-loop backoff so we don't spin.
                        tracing::warn!(
                            pid = child_pid,
                            worker_id = dead_id,
                            error = %e,
                            "supervisor: restarted worker failed readiness probe — killing"
                        );
                        // SAFETY: SIGKILL to a known child PID.
                        unsafe {
                            libc::kill(child_pid, libc::SIGKILL);
                        }
                        // Reap the zombie so waitpid() above doesn't
                        // double-report it in a later iteration.
                        let mut wstatus: libc::c_int = 0;
                        // SAFETY: blocking wait on the exact PID we just signalled.
                        unsafe {
                            libc::waitpid(child_pid, &raw mut wstatus, 0);
                        }
                        let _ = wstatus;
                        std::thread::sleep(*backoff);
                        *backoff = (*backoff * 2).min(max_backoff);
                    }
                }
            } else {
                children.push(child_pid);
                pid_to_id.insert(child_pid, dead_id);
                worker_started.insert(child_pid, std::time::Instant::now());
            }
        }
    }
    None
}

/// Supervisor wait loop — blocks until all workers have exited.
///
/// Waits for any child to exit via `waitpid(-1, ...)`, applies crash-loop
/// backoff if it died quickly, then forks a replacement. Exits the loop
/// when the shutdown flag is set or `waitpid` returns no more children.
///
/// # Safety
/// Calls `fork()`, `libc::kill`, and `libc::waitpid` — must run in the
/// single-threaded supervisor context (before tokio initialisation in any
/// surviving child).
///
/// H-05: the `SHUTTING_DOWN` load uses `SeqCst` to pair with the `SeqCst`
/// store in the async-signal handler. `Relaxed` is not safe here because
/// the C11 memory model provides no happens-before edge across a signal
/// boundary.
#[allow(unsafe_code)]
#[allow(clippy::too_many_arguments)]
fn run_supervisor_loop(
    children: &mut Vec<libc::pid_t>,
    pid_to_id: &mut std::collections::HashMap<libc::pid_t, usize>,
    worker_started: &mut std::collections::HashMap<libc::pid_t, std::time::Instant>,
    backoff: &mut std::time::Duration,
    max_backoff: std::time::Duration,
    crash_window: std::time::Duration,
    stable_run: std::time::Duration,
    readiness_target: &readiness::ReadinessTarget,
) -> WorkerRole {
    loop {
        // H-05: SeqCst pairs with the SeqCst store in handle_shutdown.
        if SHUTTING_DOWN.load(std::sync::atomic::Ordering::SeqCst) {
            info!("supervisor: shutdown signal received, terminating workers");
            for &pid in children.iter() {
                // SAFETY: sending SIGTERM to known child PIDs.
                unsafe {
                    libc::kill(pid, libc::SIGTERM);
                }
            }
            break;
        }

        let mut status: libc::c_int = 0;
        // SAFETY: standard waitpid call; -1 means "any child".
        let exited_pid = unsafe { libc::waitpid(-1, &raw mut status, 0) };

        if exited_pid <= 0 {
            break;
        }

        let reason = if libc::WIFEXITED(status) {
            format!("exit code {}", libc::WEXITSTATUS(status))
        } else if libc::WIFSIGNALED(status) {
            format!("signal {}", libc::WTERMSIG(status))
        } else {
            "unknown".to_string()
        };

        *backoff = apply_crash_backoff(
            worker_started.get(&exited_pid).copied(),
            exited_pid,
            &reason,
            *backoff,
            crash_window,
            stable_run,
            max_backoff,
        );

        tracing::warn!(
            pid = exited_pid,
            reason,
            "supervisor: worker exited — restarting"
        );

        // Recover the dead worker's logical ID so the replacement keeps it.
        let dead_id = pid_to_id.remove(&exited_pid).unwrap_or(children.len());
        children.retain(|&p| p != exited_pid);
        worker_started.remove(&exited_pid);

        if let Some(role) = restart_worker(
            dead_id,
            readiness_target,
            children,
            pid_to_id,
            worker_started,
            backoff,
            max_backoff,
        ) {
            return role;
        }
    }

    WorkerRole::Supervisor
}

/// Supervisor shutdown flag — set by SIGTERM/SIGINT handler.
static SHUTTING_DOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Set by the SIGUSR2 signal handler. The upgrade-monitor thread polls this
/// flag; on seeing it flip, it spawns the new binary and orchestrates drain.
static UPGRADE_PENDING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Signal handler for SIGTERM/SIGINT — sets shutdown flag.
///
/// H-05: uses `SeqCst` to guarantee the store is observed by the supervisor
/// thread's matching load. `Relaxed` is a data race across the signal /
/// main thread boundary — the C11 memory model provides no happens-before
/// edge there, so the supervisor could spin forever missing the flag.
extern "C" fn handle_shutdown(_sig: libc::c_int) {
    SHUTTING_DOWN.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Signal handler for SIGUSR2 — sets the upgrade-pending flag.
///
/// ASYNC-SIGNAL-SAFE: only writes a single atomic bool — no allocations,
/// no locks, no I/O. The upgrade orchestration logic lives in a background
/// thread that polls `UPGRADE_PENDING` so the heavy work stays off the
/// signal stack entirely.
extern "C" fn handle_sigusr2(_sig: libc::c_int) {
    UPGRADE_PENDING.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Spawn the upgrade-monitor thread and install the SIGUSR2 handler.
///
/// The thread polls `UPGRADE_PENDING` every 100 ms. On seeing it flip:
///   1. Resolves the binary path from `DWAAR_UPGRADE_BINARY` env or `argv[0]`.
///   2. Spawns `<binary> --upgrade [original-args without "upgrade" tokens]`.
///   3. Polls `health_check_url` (from `DWAAR_UPGRADE_HEALTH_URL` or the
///      default `/healthz` on 6663) until 200 or `drain_timeout_secs` elapses.
///   4. On success: sends SIGQUIT to self → Pingora graceful drain + exit.
///   5. On failure: kills the child, resets `UPGRADE_PENDING`, keeps running.
///
/// The upgrade socket path is passed so it can be forwarded to the child via
/// `DWAAR_UPGRADE_SOCK`; the child's Pingora config picks it up automatically.
#[allow(clippy::too_many_lines)]
fn install_sigusr2_handler(drain_timeout_secs: u64, upgrade_sock: String) {
    use std::sync::atomic::Ordering;

    // SAFETY: signal handler only sets an atomic flag — async-signal-safe.
    #[allow(unsafe_code)]
    unsafe {
        libc::signal(
            libc::SIGUSR2,
            handle_sigusr2 as *const () as libc::sighandler_t,
        );
    }

    std::thread::Builder::new()
        .name("upgrade-monitor".into())
        .spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_millis(100));

                if !UPGRADE_PENDING.load(Ordering::SeqCst) {
                    continue;
                }

                // Clear the flag before we start work — if the operator sends
                // SIGUSR2 again mid-upgrade it will queue for the next iteration.
                UPGRADE_PENDING.store(false, Ordering::SeqCst);

                tracing::info!("SIGUSR2 received — starting zero-downtime upgrade");

                // Resolve binary: DWAAR_UPGRADE_BINARY env overrides argv[0].
                // Linux inode semantics: the file at the original path can be
                // replaced with a rename(2) while this process keeps executing
                // from the old mmap. Re-exec'ing argv[0] picks up the new binary
                // from the filesystem without any FD tricks.
                let binary = std::env::var("DWAAR_UPGRADE_BINARY")
                    .map(std::path::PathBuf::from)
                    .or_else(|_| {
                        std::env::current_exe()
                            .with_context(|| "cannot resolve current executable")
                    });
                let binary = match binary {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::error!(error = %e, "upgrade: cannot resolve binary path — aborting");
                        continue;
                    }
                };

                // Forward original args, stripping any existing "upgrade" tokens
                // to avoid accidentally running `dwaar upgrade upgrade`.
                let orig_args: Vec<String> = std::env::args()
                    .skip(1)
                    .filter(|a| a != "upgrade" && a != "--upgrade")
                    .collect();

                tracing::info!(
                    binary = %binary.display(),
                    args = ?orig_args,
                    upgrade_sock = %upgrade_sock,
                    "upgrade: spawning new process"
                );

                let child = std::process::Command::new(&binary)
                    .arg("--upgrade")
                    .args(&orig_args)
                    .env("DWAAR_UPGRADE_SOCK", &upgrade_sock)
                    // Signal to the child that it is a hot-upgrade child so it
                    // connects to the upgrade socket instead of binding fresh.
                    .env("DWAAR_UPGRADE_FROM", "1")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::inherit())
                    .stderr(std::process::Stdio::inherit())
                    .spawn();

                let mut child = match child {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::error!(
                            binary = %binary.display(),
                            error = %e,
                            "upgrade: failed to spawn new process — staying up"
                        );
                        continue;
                    }
                };

                let new_pid = child.id();
                tracing::info!(pid = new_pid, "upgrade: new process started");

                // Health-check loop: poll the new process's /healthz until 200
                // or the drain timeout elapses.
                let health_url = std::env::var("DWAAR_UPGRADE_HEALTH_URL")
                    .unwrap_or_else(|_| "http://127.0.0.1:6663/healthz".to_string());

                let deadline =
                    std::time::Instant::now() + std::time::Duration::from_secs(drain_timeout_secs);
                let mut healthy = false;

                while std::time::Instant::now() < deadline {
                    std::thread::sleep(std::time::Duration::from_millis(500));

                    // Check the child is still alive first.
                    #[allow(unsafe_code)]
                    let still_alive = unsafe {
                        let mut status: libc::c_int = 0;
                        libc::waitpid(new_pid.cast_signed(), &raw mut status, libc::WNOHANG) == 0
                    };
                    if !still_alive {
                        tracing::error!(
                            pid = new_pid,
                            "upgrade: new process exited before becoming healthy — rolling back"
                        );
                        break;
                    }

                    // Simple HTTP GET via the standard library — no tokio
                    // runtime on this thread. We use a raw TCP connection to
                    // avoid pulling in a full HTTP client crate.
                    if check_http_200(&health_url) {
                        healthy = true;
                        break;
                    }
                }

                if healthy {
                    tracing::info!(
                        pid = new_pid,
                        "upgrade: new process is healthy — draining parent"
                    );
                    // Send SIGQUIT to ourselves: Pingora's graceful-upgrade
                    // handler sends FDs over the upgrade socket and exits cleanly.
                    #[allow(unsafe_code)]
                    unsafe {
                        libc::kill(libc::getpid(), libc::SIGQUIT);
                    }
                    // The main thread's `run_forever()` will return after drain.
                    // Our work is done — exit the monitor thread.
                    return;
                }
                // Rollback: kill the unhealthy child and stay up.
                tracing::error!(
                    pid = new_pid,
                    health_url = %health_url,
                    drain_timeout_secs,
                    "upgrade: health check failed — killing new process, parent stays up"
                );
                #[allow(unsafe_code)]
                unsafe {
                    libc::kill(new_pid.cast_signed(), libc::SIGKILL);
                }
                let _ = child.wait();
            }
        })
        .expect("upgrade-monitor thread spawn must not fail");
}

/// Perform a single HTTP GET to `url` and return `true` iff the response
/// status is 200.
///
/// Uses a raw TCP connection with a short connect + read timeout. This runs
/// on the upgrade-monitor thread which has no tokio runtime, so we use
/// blocking I/O. The URL must be `http://` (no TLS) — the internal health
/// endpoint never uses HTTPS.
fn check_http_200(url: &str) -> bool {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    // Parse host:port and path from "http://host:port/path".
    let rest = url.strip_prefix("http://").unwrap_or(url);
    let (hostport, path) = rest.split_once('/').unwrap_or((rest, ""));
    let path = format!("/{path}");

    let Ok(stream) = TcpStream::connect(hostport) else {
        return false;
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap_or(());
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap_or(());
    let mut stream = stream;

    let request = format!("GET {path} HTTP/1.1\r\nHost: {hostport}\r\nConnection: close\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }

    let mut buf = [0u8; 16];
    if stream.read(&mut buf).is_err() {
        return false;
    }
    // HTTP/1.1 200 or HTTP/1.0 200
    buf.starts_with(b"HTTP/1.1 200") || buf.starts_with(b"HTTP/1.0 200")
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
        Some(Commands::SelfUpdate { force }) => {
            return self_update::run(*force);
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

    // One worker, all cores. Multiple workers fragment the upstream connection
    // pool and duplicate background services across processes. A single worker
    // with N Tokio threads uses all cores via work-stealing, shares one pool,
    // and avoids cross-process overhead.
    //
    // Benchmark (10-core, Rust backend, 1000 conns):
    //   1 worker × 10 threads:  57,928 RPS, P99 =  93ms
    //   2 workers × 5 threads:  32,032 RPS, P99 = 204ms
    //   4 workers × 2 threads:  30,668 RPS, P99 = 187ms
    let worker_count = match cli.workers {
        WorkerCount::Auto => 1,
        WorkerCount::Count(n) => n,
    };

    // Generate the UAM secret once here, before any fork, so all worker
    // processes share the same value. Workers that receive a challenge token
    // from a sibling can still validate it — without this, each fork would
    // produce its own secret and tokens would fail across workers.
    //
    // We encode as hex and store in the environment so forked children inherit
    // it automatically via the OS copy-on-write page tables.
    //
    // SAFETY: set_var is unsafe in Rust 2024 because it is not thread-safe.
    // This is called before fork() and before any tokio/Pingora threads exist,
    // so the process is still strictly single-threaded here.
    {
        use rand::Rng;
        let mut buf = [0u8; 32];
        rand::rng().fill_bytes(&mut buf);
        let hex = buf.iter().fold(String::with_capacity(64), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        });
        #[allow(unsafe_code)]
        // SAFETY: see comment above — single-threaded before fork.
        unsafe {
            std::env::set_var("DWAAR_UAM_SECRET", &hex);
        }
    }

    // Single-process mode skips forking — same behavior as before.
    if worker_count <= 1 {
        return run_server(&cli, &dwaar_config, config_path, drain_timeout, 0, 1);
    }

    let readiness_target = readiness::target_from_admin_socket(cli.admin_socket.as_deref());
    match fork_workers(worker_count, &readiness_target)? {
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

/// State produced by compiling the route table and wrapping it in hot-reload
/// handles. Every field here is an `Arc` so callers can freely clone without
/// transferring ownership.
struct RouteState {
    route_table: Arc<ArcSwap<dwaar_core::route::RouteTable>>,
    health_pools: Arc<ArcSwap<Vec<Arc<dwaar_core::upstream::UpstreamPool>>>>,
    dwaarfile_snapshot: Arc<ArcSwap<Vec<dwaar_core::route::Route>>>,
    config_notify: Arc<tokio::sync::Notify>,
    acme_domains: Arc<ArcSwap<Vec<String>>>,
    challenge_solver: Option<Arc<ChallengeSolver>>,
}

/// Per-feature channels and optional subsystems that the proxy and background
/// services both consume. Each field is `Option` — absent when the feature is
/// disabled via CLI flag.
struct FeatureState {
    log_sender: Option<dwaar_log::LogSender>,
    log_receiver: Option<dwaar_log::LogReceiver>,
    beacon_sender: Option<dwaar_analytics::beacon::BeaconSender>,
    beacon_receiver: Option<tokio::sync::mpsc::Receiver<dwaar_analytics::beacon::BeaconEvent>>,
    agg_sender: Option<aggregation::AggSender>,
    agg_receiver: Option<aggregation::AggReceiver>,
    geo_lookup: Option<Arc<dwaar_geo::GeoLookup>>,
    plugin_chain: Arc<dwaar_plugins::plugin::PluginChain>,
    prometheus: Option<Arc<dwaar_analytics::prometheus::PrometheusMetrics>>,
    cache_backend: Option<dwaar_core::cache::SharedCacheBackend>,
}

/// Outputs of the proxy-construction phase: the ready proxy instance and the
/// gRPC service + OTLP exporter that need to be wired into other services.
struct ProxyState {
    proxy: DwaarProxy,
    grpc_service: dwaar_grpc::DwaarControlService,
    otlp_exporter: Option<Arc<dwaar_analytics::otel::OtlpExporter>>,
}

/// Build the `Server` from CLI flags and config, computing thread counts and
/// keepalive sizing from the route hint so we don't oversubscribe on small
/// deployments.
fn build_pingora_server(
    cli: &Cli,
    dwaar_config: &dwaar_config::model::DwaarConfig,
    drain_timeout: std::time::Duration,
    worker_id: usize,
    worker_count: usize,
) -> (Server, String, u64) {
    // `DWAAR_UPGRADE_FROM=1` is an env-var equivalent of `--upgrade` so the
    // installer can set the flag without modifying argv (e.g. when re-exec'ing
    // with execve where changing argv[0] is simpler than injecting flags).
    let is_upgrade = cli.upgrade
        || std::env::var("DWAAR_UPGRADE_FROM")
            .map(|v| v.trim() == "1")
            .unwrap_or(false);

    // `DWAAR_UPGRADE_SOCK` overrides Pingora's default upgrade socket path
    // (`/tmp/pingora_upgrade.sock`). The installer writes this path to the
    // environment so parent and child agree on a single rendezvous point even
    // when multiple Dwaar instances run on the same host (each can use a
    // unique path — e.g. `/run/dwaar/<pid>.sock`).
    let upgrade_sock = std::env::var("DWAAR_UPGRADE_SOCK")
        .unwrap_or_else(|_| "/run/dwaar/upgrade.sock".to_string());

    let pingora_opt = PingoraOpt {
        upgrade: is_upgrade,
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

    // Count configured routes to right-size threads and connection pools.
    // A single L4 proxy doesn't need 8 threads and 512 keepalive slots.
    let has_l4 = dwaar_config
        .global_options
        .as_ref()
        .is_some_and(|g| g.layer4.is_some() || !g.layer4_listener_wrappers.is_empty());
    let route_hint = dwaar_config.sites.len() + usize::from(has_l4);

    let max_useful_threads = match route_hint {
        0..=2 => 2,
        3..=10 => 4,
        _ => cpu_count,
    };
    let threads = (cpu_count / worker_count).max(1).min(max_useful_threads);

    let upstream_keepalive_pool_size = match route_hint {
        0..=5 => 64,
        6..=50 => 256,
        _ => 512,
    };

    // Extract the drain timeout (seconds) for use in the SIGUSR2 handler.
    // We apply it both to Pingora's graceful-shutdown timer and our own
    // watchdog: if the drain takes longer than this, we SIGKILL ourselves.
    let conf_drain_secs: u64 = drain_timeout.as_secs();

    let conf = ServerConf {
        threads,
        work_stealing: true,
        upstream_keepalive_pool_size,
        grace_period_seconds: Some(conf_drain_secs),
        graceful_shutdown_timeout_seconds: Some(conf_drain_secs),
        // Direct Pingora to the rendezvous socket used for FD transfer.
        // The child process calls `Server::new_with_opt_and_conf` with
        // `upgrade: true` and connects to this same socket to receive the
        // listening-fd set, so it never needs to re-bind ports.
        upgrade_sock: upgrade_sock.clone(),
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

    (server, upgrade_sock, conf_drain_secs)
}

/// Compile routes, wrap them in `ArcSwap` hot-reload handles, and initialise
/// ACME domain tracking. The returned `RouteState` is the single source of
/// truth that `FeatureState`, `ProxyState`, and all background services
/// reference via `Arc::clone`.
fn build_route_state(dwaar_config: &dwaar_config::model::DwaarConfig) -> RouteState {
    let has_l4 = dwaar_config
        .global_options
        .as_ref()
        .is_some_and(|g| g.layer4.is_some() || !g.layer4_listener_wrappers.is_empty());

    let route_table = compile_routes(dwaar_config);
    if route_table.is_empty() && !has_l4 {
        warn!("no routes configured — proxy is idle, waiting for config reload");
    }
    info!(routes = route_table.len(), "route table compiled");

    // Collect upstream pools that have health URIs. Wrapped in ArcSwap so
    // ConfigWatcher can swap in new pools on hot-reload.
    let health_pools = Arc::new(ArcSwap::from_pointee(collect_pools(&route_table)));

    // Capture initial routes before wrapping — DockerWatcher needs a
    // separate snapshot of Dwaarfile routes for merge operations.
    let initial_routes = route_table.all_routes();
    let route_table = Arc::new(ArcSwap::from_pointee(route_table));

    // Shared state for Docker mode: the snapshot holds compiled Dwaarfile
    // routes, and the Notify wakes DockerWatcher to re-merge after changes.
    let dwaarfile_snapshot = Arc::new(ArcSwap::from_pointee(initial_routes));
    let config_notify = Arc::new(tokio::sync::Notify::new());

    // ACME domain list — wrapped in ArcSwap so ConfigWatcher can swap in
    // new domains on hot-reload.
    let acme_domains = Arc::new(ArcSwap::from_pointee(compile_acme_domains(dwaar_config)));
    let challenge_solver = if acme_domains.load().is_empty() {
        None
    } else {
        Some(Arc::new(ChallengeSolver::new()))
    };

    RouteState {
        route_table,
        health_pools,
        dwaarfile_snapshot,
        config_notify,
        acme_domains,
        challenge_solver,
    }
}

/// Open log/analytics channels and initialise feature subsystems (`GeoIP`,
/// plugins, Prometheus, HTTP cache) according to CLI feature flags. Each
/// subsystem is independent — a failure in one doesn't affect the others.
fn build_feature_state(
    cli: &Cli,
    route_table: &Arc<ArcSwap<dwaar_core::route::RouteTable>>,
) -> FeatureState {
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

    // GeoIP — load the MaxMind database if present. Not a hard requirement;
    // country enrichment simply won't happen without it.
    let geo_lookup = if cli.geoip_enabled() {
        load_geoip_database()
    } else {
        info!("GeoIP disabled via CLI flag");
        None
    };

    // Build the plugin chain with all built-in plugins, sorted by priority.
    // The UAM secret is inherited from the supervisor via DWAAR_UAM_SECRET so
    // all workers share one secret and can validate each other's tokens. If the
    // env var is absent (e.g. direct invocation in tests) we fall back to a
    // fresh random secret — acceptable for single-process use.
    let plugin_chain = if cli.plugins_enabled() {
        let under_attack_secret: Vec<u8> = std::env::var("DWAAR_UAM_SECRET")
            .ok()
            .and_then(|hex| {
                if hex.len() % 2 != 0 {
                    tracing::warn!("DWAAR_UAM_SECRET has odd length — ignoring");
                    return None;
                }
                (0..hex.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
                    .collect()
            })
            .unwrap_or_else(|| {
                use rand::Rng;
                let mut buf = vec![0u8; 32];
                rand::rng().fill_bytes(&mut buf);
                buf
            });
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
        Some(Arc::new(
            dwaar_analytics::prometheus::PrometheusMetrics::new(),
        ))
    } else {
        None
    };

    // Cache backend (ISSUE-073, ISSUE-111 hot-reload): wrapped in ArcSwap
    // so ConfigWatcher can swap in a resized backend on reload.
    let cache_backend: Option<dwaar_core::cache::SharedCacheBackend> = if cli.cache_enabled() {
        let max_cache_size = route_table
            .load()
            .all_routes()
            .iter()
            .flat_map(|r| r.handlers.iter())
            .filter_map(|h| h.cache.as_ref())
            .map(|c| c.max_size)
            .max();

        let initial = max_cache_size.map(|size| {
            tracing::info!(max_size_bytes = size, "HTTP cache enabled");
            dwaar_core::cache::new_cache_backend(size)
        });
        Some(Arc::new(arc_swap::ArcSwap::from_pointee(initial)))
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

    FeatureState {
        log_sender,
        log_receiver,
        beacon_sender,
        beacon_receiver,
        agg_sender,
        agg_receiver,
        geo_lookup,
        plugin_chain,
        prometheus,
        cache_backend,
    }
}

/// Wire together the gRPC control-plane service, the OTLP span exporter, and
/// the `DwaarProxy` instance. The gRPC service is built first so its split and
/// header-rule registries can be plumbed into the proxy's hot path before any
/// request arrives.
fn build_proxy(
    dwaar_config: &dwaar_config::model::DwaarConfig,
    routes: &RouteState,
    features: FeatureState,
    worker_id: usize,
) -> ProxyState {
    let timeouts = extract_timeouts(dwaar_config);

    let h3_enabled = dwaar_config
        .global_options
        .as_ref()
        .is_some_and(|g| g.h3_enabled);

    let route_table_for_grpc = Arc::clone(&routes.route_table);

    // Build the DwaarControl service up-front so its registries can be
    // shared with DwaarProxy's hot path (Wheel #2 Week 4) AND handed to the
    // gRPC BackgroundService below. The service is cheap to clone — every
    // internal handle is an `Arc` — so both consumers get independent clones.
    let grpc_service = dwaar_grpc::DwaarControlService::new(
        format!("dwaar-worker-{worker_id}"),
        route_table_for_grpc,
    );
    let control_plane_hooks = dwaar_core::proxy::ControlPlaneHooks {
        splits: grpc_service.split_registry(),
        header_rules: grpc_service.header_rule_registry(),
    };
    let mirror_registry = grpc_service.mirror_registry();
    let event_bus = grpc_service.event_bus();

    let mirror_dispatcher = Arc::new(dwaar_grpc::MirrorDispatcherImpl::new(Arc::clone(
        &mirror_registry,
    )));
    let mirror_metrics = mirror_dispatcher.metrics();
    let outcome_sink = Arc::new(dwaar_grpc::AnomalyOutcomeSink::new(Arc::clone(&event_bus)));
    let log_buffer = Arc::new(dwaar_grpc::LogChunkBuffer::new(Arc::clone(&event_bus)));

    // OTLP span exporter — built here so the Arc can be shared with both
    // DwaarProxy (records one span per request in logging()) and the
    // background flush service (drains the ring buffer to the collector).
    // Kept as `None` when the Dwaarfile has no `tracing {}` block.
    let otlp_exporter: Option<Arc<dwaar_analytics::otel::OtlpExporter>> = dwaar_config
        .global_options
        .as_ref()
        .and_then(|g| g.tracing.as_ref())
        .and_then(|t| {
            match dwaar_analytics::otel::OtlpExporter::new(
                &t.otlp_endpoint,
                env!("CARGO_PKG_VERSION"),
            ) {
                Ok(e) => {
                    info!(endpoint = %t.otlp_endpoint, "OTLP span exporter initialised");
                    Some(Arc::new(e))
                }
                Err(e) => {
                    warn!(error = %e, "failed to initialise OTLP exporter — tracing disabled");
                    None
                }
            }
        });
    let otlp_sample_ratio: f64 = dwaar_config
        .global_options
        .as_ref()
        .and_then(|g| g.tracing.as_ref())
        .map_or(1.0, |t| t.sample_ratio);

    let proxy = DwaarProxy::new(dwaar_core::proxy::ProxyConfig {
        route_table: Arc::clone(&routes.route_table),
        challenge_solver: routes.challenge_solver.clone(),
        log_sender: features.log_sender,
        beacon_sender: features.beacon_sender,
        agg_sender: features.agg_sender,
        geo_lookup: features.geo_lookup,
        plugin_chain: Arc::clone(&features.plugin_chain),
        prometheus: features.prometheus.clone(),
        cache_backend: features.cache_backend.clone(),
        keepalive_secs: u64::from(timeouts.keepalive_secs),
        body_timeout_secs: u64::from(timeouts.body_secs),
        h3_enabled,
    })
    .with_control_plane(control_plane_hooks)
    .with_mirror_dispatcher(
        Arc::clone(&mirror_dispatcher) as Arc<dyn dwaar_core::proxy::MirrorDispatcher>
    )
    .with_outcome_sink(Arc::clone(&outcome_sink) as Arc<dyn dwaar_core::proxy::RequestOutcomeSink>);
    let proxy = if let Some(ref exp) = otlp_exporter {
        proxy.with_otlp_exporter(Arc::clone(exp), otlp_sample_ratio)
    } else {
        proxy
    };
    // Hand-off: the admin / metrics wiring consuming `mirror_metrics` and
    // `log_buffer` lands in a follow-up wheel. Explicit drops keep both
    // `Arc`s' ref counts honest for now — cheap atomic decrements.
    drop(mirror_metrics);
    drop(log_buffer);

    ProxyState {
        proxy,
        grpc_service,
        otlp_exporter,
    }
}

/// Return type of `bind_proxy_listeners`: cert store, SNI map, optional OTLP
/// exporter, and the gRPC service handle (all needed by later setup phases).
type ListenerOutputs = (
    Arc<CertStore>,
    DomainConfigMap,
    Option<Arc<dwaar_analytics::otel::OtlpExporter>>,
    dwaar_grpc::DwaarControlService,
);

/// Create the HTTP proxy service, bind all plain-HTTP and TLS listeners, and
/// register the HTTP/3 QUIC listener when enabled. Returns the cert store and
/// SNI domain map so `ConfigWatcher` can swap in new certs on hot-reload.
///
/// The proxy service is added to `server` before returning; QUIC runs as a
/// separate `BackgroundService` alongside it.
fn bind_proxy_listeners(
    server: &mut Server,
    dwaar_config: &dwaar_config::model::DwaarConfig,
    proxy_state: ProxyState,
    routes: &RouteState,
    features_plugin_chain: Arc<dwaar_plugins::plugin::PluginChain>,
    timeouts: &dwaar_config::model::TimeoutsConfig,
    worker_count: usize,
) -> anyhow::Result<ListenerOutputs> {
    let h3_enabled = dwaar_config
        .global_options
        .as_ref()
        .is_some_and(|g| g.h3_enabled);

    let route_table_for_quic = Arc::clone(&routes.route_table);

    let ProxyState {
        proxy,
        grpc_service,
        otlp_exporter,
    } = proxy_state;

    let mut proxy_service = pingora_proxy::http_proxy_service(&server.configuration, proxy);

    // Slow loris protection (ISSUE-076): set max keepalive requests via Pingora's
    // HttpServerOptions. This caps how many requests a single kept-alive connection
    // can serve before Dwaar forces a reconnect — prevents per-connection memory
    // accumulation from long-lived connections.
    {
        use pingora_core::apps::HttpServerOptions;
        let mut opts = HttpServerOptions::default();
        opts.keepalive_request_limit = Some(timeouts.max_requests);
        if let Some(app) = proxy_service.app_logic_mut() {
            app.server_options = Some(opts);
        }
    }

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

    // sni_domain_map is shared between SniResolver (which reads it on every
    // TLS handshake) and ConfigWatcher (which swaps in a new map on reload).
    // When TLS is disabled the map stays empty and is never written to.
    let tls_bind_addrs = extract_tls_bind_addresses(dwaar_config);
    let sni_domain_map: DomainConfigMap = if has_tls_sites(dwaar_config) {
        setup_tls_listener(
            dwaar_config,
            &mut proxy_service,
            &cert_store,
            worker_count > 1,
            &tls_bind_addrs,
        )?
    } else {
        domain_config_map_empty()
    };

    server.add_service(proxy_service);

    // QUIC listener for HTTP/3 (ISSUE-079a). Uses the same PEM cert/key files
    // as the TCP/TLS listener — both OpenSSL and rustls load PEM natively.
    if h3_enabled {
        let tls_configs = compile_tls_configs(dwaar_config);
        if let Some((_domain, tls_cfg)) = tls_configs.iter().next() {
            let quic_addr: std::net::SocketAddr =
                "0.0.0.0:443".parse().expect("static addr is valid");
            match dwaar_core::quic::QuicService::new(
                quic_addr,
                &tls_cfg.cert_path,
                &tls_cfg.key_path,
                route_table_for_quic,
                features_plugin_chain,
                None, // max_streams — use default (100)
            ) {
                Ok(quic_service) => {
                    let quic_bg = pingora_core::services::background::background_service(
                        "QUIC/HTTP3 listener",
                        quic_service,
                    );
                    server.add_service(quic_bg);
                    info!(listen = %quic_addr, protocol = "quic/h3", "QUIC listener registered");
                }
                Err(e) => {
                    // QUIC is optional — warn but don't fail startup
                    tracing::warn!(error = %e, "failed to start QUIC listener, HTTP/3 disabled");
                }
            }
        } else {
            tracing::warn!("h3 enabled but no TLS certs configured — QUIC listener not started");
        }
    }

    Ok((cert_store, sni_domain_map, otlp_exporter, grpc_service))
}

/// Build and register the admin HTTP service. Worker 0 binds both the TCP
/// address and the optional UDS path; other workers skip binding to avoid
/// EADDRINUSE races. Returns the shared `agg_metrics` map so the aggregation
/// background service can write into it.
fn add_admin_service(
    server: &mut Server,
    cli: &Cli,
    routes: &RouteState,
    features_prometheus: Option<&Arc<dwaar_analytics::prometheus::PrometheusMetrics>>,
    cache_backend_for_admin: Option<dwaar_core::cache::SharedCacheBackend>,
    worker_id: usize,
) -> anyhow::Result<Arc<DashMap<String, dwaar_analytics::aggregation::DomainMetrics>>> {
    // Shared analytics metrics — created here so both AdminService and
    // AggregationService reference the same DashMap instance.
    let agg_metrics: Arc<DashMap<String, dwaar_analytics::aggregation::DomainMetrics>> =
        Arc::new(DashMap::new());

    let admin_token = std::env::var("DWAAR_ADMIN_TOKEN").ok();
    let admin_service = AdminService::new(
        Arc::clone(&routes.route_table),
        Arc::clone(&agg_metrics),
        std::time::Instant::now(),
        admin_token,
    )
    .with_reload_notify(Arc::clone(&routes.config_notify));

    let admin_service = if let Some(prom) = features_prometheus {
        admin_service.with_prometheus(Arc::clone(prom))
    } else {
        admin_service
    };

    let admin_service = if let Some(cb) = cache_backend_for_admin {
        admin_service.with_cache_backend(cb)
    } else {
        admin_service
    };

    let mut admin_listening =
        pingora_core::services::listening::Service::new("admin API".to_string(), admin_service);

    // Only worker 0 binds the admin listeners. Other workers must not attempt
    // to bind the same TCP port or UDS path — there is no SO_REUSEPORT here,
    // so every additional bind races to EADDRINUSE or corrupts the socket file.
    if worker_id == 0 {
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

            admin_listening.add_uds(path_str, Some(Permissions::from_mode(0o600)));
            info!(socket = path_str, "admin API UDS listener registered");
        }

        info!(listen = "127.0.0.1:6190", "admin API registered");

        // Write the active admin endpoint to a runtime file so `dwaar reload`
        // can discover it without hardcoded paths. UDS is preferred over TCP.
        let preferred_addr = cli
            .admin_socket
            .as_ref()
            .and_then(|p| p.to_str())
            .unwrap_or("127.0.0.1:6190");
        if let Err(e) = write_admin_addr(preferred_addr) {
            warn!(error = %e, "failed to write admin address file — dwaar reload may need --admin flag");
        }
    }

    server.add_service(admin_listening);
    Ok(agg_metrics)
}

/// Register the gRPC control-plane server and the Layer 4 TCP proxy service.
/// Both run as Pingora `BackgroundService`s so they share the server's
/// shutdown lifecycle. Returns the L4 shared state for hot-reload.
fn add_grpc_and_l4_services(
    server: &mut Server,
    cli: &Cli,
    dwaar_config: &dwaar_config::model::DwaarConfig,
    grpc_service: dwaar_grpc::DwaarControlService,
    cert_store: &Arc<CertStore>,
    worker_id: usize,
) -> anyhow::Result<(dwaar_core::l4::SharedL4Servers, Arc<tokio::sync::Notify>)> {
    use dwaar_config::compile::{compile_l4_servers, compile_l4_wrappers};
    // DwaarControl gRPC server (Wheel #2) — only worker 0 binds. Runs as a
    // Pingora BackgroundService so it shares the server's shutdown watch:
    // a SIGTERM on the Pingora side tears down the gRPC listener alongside
    // the HTTP admin server and the proxy. See [`GrpcBackgroundService`].
    //
    // The service itself was built earlier so its registries are already
    // plumbed into the DwaarProxy hot path.
    if worker_id == 0 && !cli.grpc_addr.trim().is_empty() {
        let grpc_addr: std::net::SocketAddr = cli
            .grpc_addr
            .parse()
            .with_context(|| format!("invalid --grpc-addr: {}", cli.grpc_addr))?;

        let tls_config = dwaar_grpc::TlsConfig::from_env()
            .context("failed to load gRPC TLS configuration from environment")?;

        let grpc_wrapper = GrpcBackgroundService {
            addr: grpc_addr,
            service: grpc_service,
            tls: tls_config,
        };
        let grpc_bg = pingora_core::services::background::background_service(
            "dwaar-grpc control",
            grpc_wrapper,
        );
        server.add_service(grpc_bg);
        info!(listen = %grpc_addr, "dwaar-grpc control server registered");
    }

    // Layer 4 TCP proxy — bind separate listeners for non-HTTP protocols.
    // Shared via ArcSwap so ConfigWatcher can hot-reload L4 config.
    let l4_reload_notify = Arc::new(tokio::sync::Notify::new());

    let mut l4_servers = Vec::new();
    if let Some(l4_cfg) = dwaar_config
        .global_options
        .as_ref()
        .and_then(|g| g.layer4.as_ref())
    {
        l4_servers.extend(compile_l4_servers(l4_cfg));
    }
    if let Some(ref opts) = dwaar_config.global_options
        && !opts.layer4_listener_wrappers.is_empty()
    {
        l4_servers.extend(compile_l4_wrappers(&opts.layer4_listener_wrappers));
    }
    // Inject the shared cert store into any L4 TLS handlers so they
    // can look up certs by SNI at accept time.
    for server_cfg in &mut l4_servers {
        for route in &mut server_cfg.routes {
            for handler in &mut route.handlers {
                if let dwaar_core::l4::CompiledL4Handler::Tls { cert_store: cs, .. } = handler {
                    *cs = Some(Arc::clone(cert_store));
                }
            }
        }
    }

    let count = l4_servers.len();
    let l4_shared = Arc::new(arc_swap::ArcSwap::from_pointee(l4_servers));
    let l4_service =
        dwaar_core::l4::Layer4Service::new(Arc::clone(&l4_shared), Arc::clone(&l4_reload_notify));
    let l4_bg = pingora_core::services::background::background_service("layer4", l4_service);
    server.add_service(l4_bg);
    if count > 0 {
        info!(listeners = count, "layer4 TCP proxy service registered");
    }

    Ok((l4_shared, l4_reload_notify))
}

/// Orchestrate the full server startup sequence. Each phase is a named helper
/// that does one thing; this function threads the outputs between them and
/// hands off to Pingora's `run_forever` once everything is wired.
fn run_server(
    cli: &Cli,
    dwaar_config: &dwaar_config::model::DwaarConfig,
    config_path: &std::path::Path,
    drain_timeout: std::time::Duration,
    worker_id: usize,
    worker_count: usize,
) -> anyhow::Result<()> {
    let (mut server, upgrade_sock, conf_drain_secs) =
        build_pingora_server(cli, dwaar_config, drain_timeout, worker_id, worker_count);

    let routes = build_route_state(dwaar_config);

    let FeatureState {
        log_sender,
        log_receiver,
        beacon_sender,
        beacon_receiver,
        agg_sender,
        agg_receiver,
        geo_lookup,
        plugin_chain,
        prometheus,
        cache_backend,
    } = build_feature_state(cli, &routes.route_table);

    // Clone handles needed by later phases before moving into build_proxy.
    let plugin_chain_for_quic = Arc::clone(&plugin_chain);
    let prometheus_for_admin = prometheus.clone();
    let cache_for_admin = cache_backend.clone();
    let cache_for_watcher = cache_backend.clone();
    let route_table_for_watcher = Arc::clone(&routes.route_table);
    let route_table_for_docker = Arc::clone(&routes.route_table);
    let route_table_for_agg = Arc::clone(&routes.route_table);

    let features_for_proxy = FeatureState {
        log_sender,
        log_receiver: None,
        beacon_sender,
        beacon_receiver: None,
        agg_sender,
        agg_receiver: None,
        geo_lookup,
        plugin_chain,
        prometheus,
        cache_backend,
    };

    let timeouts = extract_timeouts(dwaar_config);
    let proxy_state = build_proxy(dwaar_config, &routes, features_for_proxy, worker_id);

    let (cert_store, sni_domain_map, otlp_exporter, grpc_service) = bind_proxy_listeners(
        &mut server,
        dwaar_config,
        proxy_state,
        &routes,
        plugin_chain_for_quic,
        &timeouts,
        worker_count,
    )?;

    let agg_metrics = add_admin_service(
        &mut server,
        cli,
        &routes,
        prometheus_for_admin.as_ref(),
        cache_for_admin,
        worker_id,
    )?;

    let (l4_shared, l4_reload_notify) = add_grpc_and_l4_services(
        &mut server,
        cli,
        dwaar_config,
        grpc_service,
        &cert_store,
        worker_id,
    )?;

    register_background_services(
        &mut server,
        cli,
        routes.challenge_solver.as_ref(),
        &cert_store,
        log_receiver,
        config_path,
        &route_table_for_watcher,
        &route_table_for_docker,
        &routes.dwaarfile_snapshot,
        &routes.config_notify,
        beacon_receiver,
        agg_receiver,
        &route_table_for_agg,
        &agg_metrics,
        routes.health_pools,
        routes.acme_domains,
        drain_timeout,
        sni_domain_map,
        cache_for_watcher,
        dwaar_config,
        l4_shared,
        l4_reload_notify,
        otlp_exporter,
    );

    // Install the SIGUSR2 handler for zero-downtime graceful upgrades.
    //
    // How the upgrade dance works:
    //
    //   1. Operator (or installer) atomically replaces the binary on disk via
    //      rename(2). Linux inode semantics keep the old binary's open file
    //      descriptor alive until the process exits, so the running parent
    //      continues executing from the old mmap'd pages even after the rename.
    //      Re-exec'ing argv[0] picks up the *new* binary from the filesystem.
    //
    //   2. SIGUSR2 fires → handler records the signal, sets UPGRADE_PENDING.
    //
    //   3. A background thread (spawned below) polls UPGRADE_PENDING, spawns
    //      `<argv[0]> --upgrade [original-args]` (or DWAAR_UPGRADE_BINARY if
    //      set), and waits up to `drain_timeout_secs` for the child's health
    //      check to pass.
    //
    //   4. On success, the parent sends itself SIGQUIT — Pingora's graceful-
    //      shutdown signal — which drains in-flight requests and exits.
    //
    //   5. On failure (health check never passes within the timeout), the
    //      parent kills the child and keeps running.
    //
    // This module-level approach keeps the signal handler itself minimal
    // (just setting an atomic flag, which is signal-safe) and moves the
    // async logic into the background thread.
    install_sigusr2_handler(conf_drain_secs, upgrade_sock);

    info!("entering run loop, waiting for connections or signals");
    server.run_forever();
}

// Flat background-service registration; splitting would make call-sites worse.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn register_background_services(
    server: &mut Server,
    cli: &Cli,
    challenge_solver: Option<&Arc<ChallengeSolver>>,
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
    health_pools: Arc<ArcSwap<Vec<Arc<dwaar_core::upstream::UpstreamPool>>>>,
    acme_domains: Arc<ArcSwap<Vec<String>>>,
    drain_timeout: std::time::Duration,
    sni_domain_map: DomainConfigMap,
    cache_backend: Option<dwaar_core::cache::SharedCacheBackend>,
    config: &dwaar_config::model::DwaarConfig,
    l4_servers: dwaar_core::l4::SharedL4Servers,
    l4_reload_notify: Arc<tokio::sync::Notify>,
    otlp_exporter: Option<Arc<dwaar_analytics::otel::OtlpExporter>>,
) {
    // Upstream health checker — runs as a BackgroundService (Guardrail #20).
    // Always registered; it will sleep if the pool list is empty and wake up
    // when pools are swapped in via hot-reload.
    {
        let checker = dwaar_core::upstream::HealthChecker::new(Arc::clone(&health_pools));
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
            Arc::clone(&acme_domains),
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
            domains = acme_domains.load().len(),
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

    // Shared notify for post-reload eviction. ConfigWatcher fires it after
    // every successful reload; AggregationService listens and drops DashMap
    // entries for domains that are no longer in the route table. #167
    let agg_evict_notify = Arc::new(tokio::sync::Notify::new());

    // Config file watcher for hot-reload
    let initial_hash = hash_content(&std::fs::read(config_path).unwrap_or_default());
    let config_watcher = ConfigWatcher::new(
        config_path.to_path_buf(),
        Arc::clone(route_table),
        initial_hash,
    )
    .with_drain_timeout(drain_timeout)
    .with_reload_notify(Arc::clone(config_notify))
    .with_post_reload_notify(Arc::clone(&agg_evict_notify))
    .with_sni_domain_map(sni_domain_map)
    .with_health_pools(health_pools)
    .with_acme_domains(acme_domains)
    .with_cert_store(Arc::clone(cert_store))
    .with_l4_servers(l4_servers, l4_reload_notify);
    let config_watcher = if let Some(cb) = cache_backend {
        config_watcher.with_cache_backend(cb)
    } else {
        config_watcher
    };
    let config_watcher = if cli.docker_socket.is_some() {
        config_watcher.with_docker_mode(Arc::clone(dwaarfile_snapshot), Arc::clone(config_notify))
    } else {
        config_watcher
    };
    let config_bg =
        pingora_core::services::background::background_service("config watcher", config_watcher);
    server.add_service(config_bg);
    info!(path = %config_path.display(), "config watcher registered");

    // Auto-update background service (opt-in via `auto_update {}` in Dwaarfile).
    if let Some(au) = config
        .global_options
        .as_ref()
        .and_then(|g| g.auto_update.as_ref())
    {
        let svc = auto_update::AutoUpdateService::new(au.clone());
        let bg = pingora_core::services::background::background_service("auto-update", svc);
        server.add_service(bg);
        info!("auto-update service registered (channel: {})", au.channel);
    }

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
        )
        .with_evict_notify(Arc::clone(&agg_evict_notify));
        let agg_bg = pingora_core::services::background::background_service(
            "analytics aggregation",
            AggServiceWrapper {
                inner: Arc::new(agg_service),
            },
        );
        server.add_service(agg_bg);
        info!("analytics aggregation service registered");
    }

    // OTLP background flush loop — drains the ring buffer to the collector.
    // The exporter Arc was initialised before proxy construction so DwaarProxy
    // can call record() on the hot path; here we just register the flush loop.
    if let Some(exporter) = otlp_exporter {
        let otel_bg = pingora_core::services::background::background_service(
            "OTLP exporter",
            OtlpExporterService { exporter },
        );
        server.add_service(otel_bg);
        info!("OTLP exporter background flush service registered");
    }
}

/// Wraps `OtlpExporter` as a Pingora `BackgroundService`.
struct OtlpExporterService {
    exporter: Arc<dwaar_analytics::otel::OtlpExporter>,
}

#[async_trait::async_trait]
impl pingora_core::services::background::BackgroundService for OtlpExporterService {
    async fn start(&self, shutdown: pingora_core::server::ShutdownWatch) {
        self.exporter.run(shutdown).await;
    }
}

/// Wraps the `DwaarControl` gRPC server as a Pingora `BackgroundService`
/// so its lifecycle matches the HTTP admin server's. When Pingora sends
/// shutdown, we translate the watch signal into tonic's graceful-shutdown
/// future so in-flight RPCs complete and the listener socket is released.
struct GrpcBackgroundService {
    addr: std::net::SocketAddr,
    service: dwaar_grpc::DwaarControlService,
    tls: dwaar_grpc::TlsConfig,
}

#[async_trait::async_trait]
impl pingora_core::services::background::BackgroundService for GrpcBackgroundService {
    async fn start(&self, mut shutdown: pingora_core::server::ShutdownWatch) {
        // Adapt Pingora's `ShutdownWatch` (a tokio watch channel) into the
        // single-fire future tonic expects. Fires on the first observable
        // change — that's Pingora's "please drain" signal.
        let shutdown_future = async move {
            let _ = shutdown.changed().await;
        };

        let handle = dwaar_grpc::start_grpc_server_with_shutdown(
            self.addr,
            self.service.clone(),
            self.tls.clone(),
            shutdown_future,
        );

        match handle.await {
            Ok(Ok(())) => info!(addr = %self.addr, "dwaar-grpc: server terminated cleanly"),
            Ok(Err(e)) => {
                warn!(addr = %self.addr, error = %e, "dwaar-grpc: server exited with error");
            }
            Err(e) => {
                warn!(addr = %self.addr, error = %e, "dwaar-grpc: background task join failed");
            }
        }
    }
}

/// Resolve a user-supplied config path to an absolute display form, even
/// when the file itself does not exist. `canonicalize` requires every
/// component to exist on disk, so we canonicalize the parent directory (if
/// we can) and re-attach the filename. Falls back to joining with CWD if
/// neither the parent nor the file resolves.
fn resolve_display_path(path: &std::path::Path) -> std::path::PathBuf {
    if let Ok(canon) = path.canonicalize() {
        return canon;
    }
    // Try to canonicalize the parent directory, then re-attach the filename.
    if let (Some(parent), Some(name)) = (path.parent(), path.file_name()) {
        // An empty parent ("foo") → treat as CWD.
        let parent = if parent.as_os_str().is_empty() {
            std::path::Path::new(".")
        } else {
            parent
        };
        if let Ok(canon_parent) = parent.canonicalize() {
            return canon_parent.join(name);
        }
    }
    // Last resort: join with CWD so the message still shows an absolute path.
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map_or_else(|_| path.to_path_buf(), |cwd| cwd.join(path))
    }
}

fn load_config(path: &std::path::Path) -> anyhow::Result<dwaar_config::model::DwaarConfig> {
    let metadata = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Surface the fully resolved absolute path alongside the CWD so
            // the user can see exactly where dwaar looked. `canonicalize`
            // would fail for a non-existent file, so resolve the parent
            // directory (which may exist) and re-attach the file name.
            let resolved = resolve_display_path(path);
            let cwd = std::env::current_dir()
                .map_or_else(|_| "<unknown>".to_string(), |p| p.display().to_string());
            return Err(anyhow::anyhow!(
                "Config file not found.\n  \
                 Resolved path: {}\n  \
                 Working dir:   {cwd}",
                resolved.display()
            ));
        }
        Err(e) => {
            return Err(anyhow::Error::new(e))
                .with_context(|| format!("failed to stat config file: {}", path.display()));
        }
    };
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

/// Extract connection timeouts from the global options.
/// Returns defaults (matching nginx) when not specified.
fn extract_timeouts(
    config: &dwaar_config::model::DwaarConfig,
) -> dwaar_config::model::TimeoutsConfig {
    config
        .global_options
        .as_ref()
        .and_then(|g| g.timeouts.clone())
        .unwrap_or_default()
}

fn setup_tls_listener(
    config: &dwaar_config::model::DwaarConfig,
    proxy_service: &mut pingora_core::services::listening::Service<
        pingora_proxy::HttpProxy<DwaarProxy>,
    >,
    cert_store: &Arc<CertStore>,
    use_reuseport: bool,
    tls_bind_addrs: &[BindAddress],
) -> anyhow::Result<DomainConfigMap> {
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

    // Keep a handle to the shared domain-config map before moving the resolver
    // into Pingora's TLS machinery.  ConfigWatcher holds a clone of this Arc
    // so it can swap in new explicit cert paths on hot-reload.
    let sni_domain_map = sni_resolver.shared_domain_map();

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

    let tls_listen_addr = match tls_bind_addrs.first() {
        Some(BindAddress::Tcp(a)) => a.as_str(),
        _ => "0.0.0.0:6189",
    };
    proxy_service.add_tls_with_settings(tls_listen_addr, tcp_opt, tls_settings);
    info!(
        listen = tls_listen_addr,
        protocol = "https",
        "TLS listener registered"
    );
    Ok(sni_domain_map)
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

/// Runtime file where the server writes the active admin endpoint on startup.
/// `dwaar reload` reads this to discover the correct address without hardcoding.
const ADMIN_ADDR_FILE: &str = "/tmp/dwaar-admin.addr";

/// Write the active admin endpoint so `dwaar reload` can discover it.
fn write_admin_addr(addr: &str) -> std::io::Result<()> {
    std::fs::write(ADMIN_ADDR_FILE, addr)
}

/// Read the admin endpoint written by the running server.
fn read_admin_addr() -> Option<String> {
    std::fs::read_to_string(ADMIN_ADDR_FILE)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// `dwaar reload` — trigger config reload on the running instance.
///
/// Discovers the admin endpoint in order:
/// 1. If the user passed an explicit `--admin` value, use it directly.
/// 2. Otherwise, read the runtime file written by the server on startup.
/// 3. Fall back to the default TCP address `127.0.0.1:6190`.
fn cmd_reload(admin_addr: &str) -> anyhow::Result<()> {
    use std::io::Write;

    // If the user passed an explicit --admin, use it. Otherwise try discovery.
    let effective_addr = if admin_addr == "127.0.0.1:6190" {
        read_admin_addr().unwrap_or_else(|| admin_addr.to_string())
    } else {
        admin_addr.to_string()
    };

    let resp = admin_client::post(&effective_addr, "/reload", "")?;

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

    // Verify PID file is owned by us and not world-writable to prevent
    // an attacker from substituting an arbitrary PID.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(pid_file)
            .with_context(|| format!("cannot stat PID file: {}", pid_file.display()))?;
        // SAFETY: getuid returns the real user ID of the calling process.
        #[allow(unsafe_code)]
        let uid = unsafe { libc::getuid() };
        if meta.uid() != uid {
            bail!(
                "PID file {} is owned by UID {} (expected {})",
                pid_file.display(),
                meta.uid(),
                uid
            );
        }
        if meta.mode() & 0o002 != 0 {
            bail!(
                "PID file {} is world-writable — refusing to trust its contents",
                pid_file.display()
            );
        }
    }

    // Read the PID of the old process
    let pid_str = std::fs::read_to_string(pid_file)
        .with_context(|| format!("cannot read PID file: {}", pid_file.display()))?;
    let old_pid: i32 = pid_str
        .trim()
        .parse()
        .with_context(|| format!("invalid PID in {}: {pid_str:?}", pid_file.display()))?;

    writeln!(out, "upgrading dwaar (old PID: {old_pid})")?;

    // Preserve original CLI args (--config, --workers, etc.) for the new process.
    let original_args: Vec<String> = std::env::args()
        .skip(1)
        .filter(|a| a != "upgrade" && a != "--upgrade")
        .collect();

    writeln!(
        out,
        "starting new process: {} --upgrade {}",
        binary_path.display(),
        original_args.join(" ")
    )?;

    let child = std::process::Command::new(&binary_path)
        .arg("--upgrade")
        .args(&original_args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .with_context(|| format!("failed to start new process: {}", binary_path.display()))?;

    let new_pid = child.id().cast_signed();
    writeln!(out, "new process started (PID: {new_pid})")?;

    // Poll for up to 10 seconds to verify new process is running.
    for _ in 0..50 {
        std::thread::sleep(std::time::Duration::from_millis(200));
        let mut status: libc::c_int = 0;
        // SAFETY: checking if child is still alive via non-blocking waitpid.
        #[allow(unsafe_code)]
        let result = unsafe { libc::waitpid(new_pid, &raw mut status, libc::WNOHANG) };
        if result != 0 {
            anyhow::bail!("new process (PID {new_pid}) exited before becoming ready");
        }
    }

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

    fn known_hosts(&self) -> Vec<String> {
        // Snapshot the domain keys from the current route table so
        // AggregationService can pre-seed the metrics map at construction.
        // A snapshot is fine here — new domains that arrive via hot-reload
        // will still be gated by is_known_host() and lazily inserted on
        // their first event; the pre-seed only eliminates the stampede for
        // the domains known at startup. #163
        self.0.load().domain_keys().map(str::to_owned).collect()
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
    use tracing_subscriber::filter::LevelFilter;

    // Always use LevelFilter — a single atomic compare per tracing callsite.
    // EnvFilter uses regex-like string matching per callsite per event, which
    // halves throughput (~57 tracing calls/request × 67K RPS = 3.8M evals/sec).
    //
    // Parse level from env: DWAAR_LOG_LEVEL > RUST_LOG > default "info".
    // Only simple levels supported (error/warn/info/debug/trace).
    // Per-crate directives (e.g. "dwaar_core=debug,h2=warn") are not supported
    // in production — use them only for local debugging by patching this code.
    let level_str = std::env::var("DWAAR_LOG_LEVEL")
        .or_else(|_| std::env::var("RUST_LOG"))
        .unwrap_or_else(|_| "info".to_string());

    let level = match level_str.to_ascii_lowercase().as_str() {
        "error" => LevelFilter::ERROR,
        "warn" => LevelFilter::WARN,
        "debug" => LevelFilter::DEBUG,
        "trace" => LevelFilter::TRACE,
        "off" => LevelFilter::OFF,
        // "info" and any unrecognised value both default to INFO
        _ => LevelFilter::INFO,
    };

    if cli.daemon {
        tracing_subscriber::fmt()
            .with_max_level(level)
            .json()
            .with_target(false)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_max_level(level)
            .with_target(false)
            .init();
    }
}

#[cfg(test)]
mod tests {
    /// Smoke test for the `fork_workers` helper split (issue #172a).
    ///
    /// Real `fork()` behaviour is verified by integration / E2E tests. This
    /// test exists to fail loudly if a refactor regression breaks compilation
    /// in subtle ways — e.g. a helper signature changes while the orchestrator
    /// still calls the old one.
    #[test]
    fn fork_workers_compiles_and_helpers_callable() {
        // No-op: the test passes if the file compiles. Issue #172.
    }
}
