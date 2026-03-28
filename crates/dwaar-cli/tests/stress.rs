// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Stress test harness — concurrent connections, latency, throughput, resource usage.
//!
//! Proves Dwaar handles high concurrency with predictable tail latency and
//! bounded memory. Also usable for comparison against nginx/Caddy by pointing
//! `STRESS_TARGET` at a different proxy.
//!
//! ## Running
//!
//! ```sh
//! # Full test (starts Dwaar + mock backend automatically):
//! cargo test -p dwaar-cli --test stress -- --ignored --nocapture
//!
//! # Against external proxy (e.g., nginx on port 80):
//! STRESS_TARGET=127.0.0.1:80 STRESS_BACKEND=127.0.0.1:9090 \
//!     cargo test -p dwaar-cli --test stress -- --ignored --nocapture
//! ```
//!
//! ## Metrics collected
//!
//! - **Latency**: per-request wall-clock time, reported as p50/p95/p99/max
//! - **Throughput**: requests per second sustained over the test duration
//! - **Memory**: peak RSS of the proxy process (sampled every 500ms)
//! - **CPU**: user+system CPU time consumed by the proxy process
//! - **Errors**: connection failures, timeouts, unexpected status codes

// Test-only: stress test outputs formatted tables to terminal
#![allow(
    unsafe_code,
    clippy::cast_possible_wrap,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::disallowed_macros
)]
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Barrier;

// ── Configuration ──────────────────────────────────────────────────

/// How long each concurrency level runs.
const TEST_DURATION: Duration = Duration::from_secs(10);

/// Concurrency levels to test.
/// The test harness (mock backend) runs in debug mode, so extremely high
/// concurrency may bottleneck on the backend, not the proxy. For production
/// benchmarks, use an external backend + `STRESS_TARGET`.
const CONCURRENCY_LEVELS: &[usize] = &[100, 500, 1_000];

/// Interval between process metric samples.
const METRIC_SAMPLE_INTERVAL: Duration = Duration::from_millis(500);

/// Mock backend response body (~1KB JSON).
/// Uses application/json to avoid triggering Dwaar's analytics injector
/// (which modifies text/html and switches to chunked transfer). We want
/// to measure pure proxy forwarding overhead here.
const MOCK_BODY: &str = r#"{"status":"ok","routes":42,"rps":125000,"p99_ms":0.8,"uptime":"14d 3h","backends":[{"domain":"api.example.com","upstream":"10.0.0.1:3000","status":"healthy"},{"domain":"web.example.com","upstream":"10.0.0.2:8080","status":"healthy"},{"domain":"cdn.example.com","upstream":"10.0.0.3:9000","status":"healthy"}],"metrics":{"total_requests":1200000,"total_bytes":48000000,"unique_visitors":45000,"top_pages":["/","/about","/pricing","/docs","/blog"],"countries":["US","IN","DE","JP","BR","GB","FR","AU","CA","KR"],"web_vitals":{"lcp_p50":1200,"lcp_p99":3500,"cls_p50":0.05,"inp_p50":120}}}"#;

// ── Mock Backend ───────────────────────────────────────────────────

/// Minimal HTTP/1.1 backend that responds with a fixed body.
/// Supports keepalive — reads requests in a loop until the connection drops.
async fn mock_backend(listener: TcpListener, running: Arc<AtomicBool>) {
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Length: {}\r\n\
         Content-Type: application/json\r\n\
         Connection: keep-alive\r\n\
         \r\n\
         {}",
        MOCK_BODY.len(),
        MOCK_BODY
    );
    let response_bytes: Arc<[u8]> = response.into_bytes().into();

    while running.load(Ordering::Relaxed) {
        let accept = tokio::select! {
            result = listener.accept() => result,
            () = tokio::time::sleep(Duration::from_millis(100)) => continue,
        };

        let Ok((stream, _)) = accept else { continue };
        let resp = response_bytes.clone();
        let still_running = running.clone();

        tokio::spawn(async move {
            if let Err(_e) = handle_backend_conn(stream, &resp, &still_running).await {
                // Client disconnected — normal during test teardown
            }
        });
    }
}

async fn handle_backend_conn(
    stream: TcpStream,
    response: &[u8],
    running: &AtomicBool,
) -> std::io::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    while running.load(Ordering::Relaxed) {
        // Read request headers (until blank line)
        loop {
            line.clear();
            let n = reader.read_line(&mut line).await?;
            if n == 0 {
                return Ok(()); // client closed
            }
            if line == "\r\n" {
                break;
            }
        }
        writer.write_all(response).await?;
        writer.flush().await?;
    }
    Ok(())
}

// ── Load Generator ─────────────────────────────────────────────────

/// Result from a single load generator task.
struct TaskResult {
    requests: u64,
    errors: u64,
    latencies_us: Vec<u64>,
}

/// One keepalive connection sending requests in a tight loop.
async fn load_task(target: String, duration: Duration, start_signal: Arc<Barrier>) -> TaskResult {
    let mut result = TaskResult {
        requests: 0,
        errors: 0,
        latencies_us: Vec::with_capacity(10_000),
    };

    let request_bytes: &[u8] =
        b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n";

    // All tasks synchronize on the same start signal
    start_signal.wait().await;
    let deadline = Instant::now() + duration;

    // Per-operation timeout — prevents a slow/stuck proxy from hanging the test
    let io_timeout = Duration::from_secs(5);

    // Outer loop: reconnect on failure
    while Instant::now() < deadline {
        let connect = tokio::time::timeout(io_timeout, TcpStream::connect(&target)).await;
        let Ok(Ok(stream)) = connect else {
            result.errors += 1;
            tokio::time::sleep(Duration::from_millis(1)).await;
            continue;
        };
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut line = String::new();

        // Inner loop: send requests on this connection until deadline or error
        while Instant::now() < deadline {
            let start = Instant::now();

            // Send request (with timeout)
            let write_ok = tokio::time::timeout(io_timeout, writer.write_all(request_bytes)).await;
            if !matches!(write_ok, Ok(Ok(()))) {
                result.errors += 1;
                break;
            }

            // Read response headers (with timeout per line)
            let mut content_length: usize = 0;
            let mut header_error = false;
            loop {
                line.clear();
                let read = tokio::time::timeout(io_timeout, reader.read_line(&mut line)).await;
                let read_ok = matches!(read, Ok(Ok(n)) if n > 0);
                if !read_ok {
                    result.errors += 1;
                    header_error = true;
                    break;
                }
                if line == "\r\n" {
                    break;
                }
                // Parse Content-Length (case-insensitive — Pingora may normalize casing)
                let lower = line.to_ascii_lowercase();
                if let Some(cl) = lower.strip_prefix("content-length: ") {
                    content_length = cl.trim().parse().unwrap_or(0);
                }
            }
            if header_error {
                break;
            }

            // Read response body (with timeout)
            if content_length > 0 {
                let mut body_buf = vec![0u8; content_length];
                let read_body = tokio::time::timeout(
                    io_timeout,
                    tokio::io::AsyncReadExt::read_exact(&mut reader, &mut body_buf),
                )
                .await;
                if !matches!(read_body, Ok(Ok(_))) {
                    result.errors += 1;
                    break;
                }
            }

            let elapsed_us = start.elapsed().as_micros() as u64;
            result.latencies_us.push(elapsed_us);
            result.requests += 1;
        }
    }

    result
}

// ── Process Metrics ────────────────────────────────────────────────

/// Sample RSS (in KB) and CPU% of a process via `ps`.
fn sample_process_metrics(pid: u32) -> Option<(u64, f64)> {
    let output = Command::new("ps")
        .args(["-o", "rss=,pcpu=", "-p", &pid.to_string()])
        .output()
        .ok()?;

    let text = String::from_utf8_lossy(&output.stdout);
    let parts: Vec<&str> = text.split_whitespace().collect();
    if parts.len() >= 2 {
        let rss_kb = parts[0].parse().ok()?;
        let cpu_pct = parts[1].parse().ok()?;
        Some((rss_kb, cpu_pct))
    } else {
        None
    }
}

/// Collect process metrics in the background during a test phase.
fn spawn_metric_collector(
    pid: u32,
    running: Arc<AtomicBool>,
    peak_rss_kb: Arc<AtomicU64>,
    peak_cpu_pct: Arc<AtomicU64>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        while running.load(Ordering::Relaxed) {
            if let Some((rss_kb, cpu_pct)) = sample_process_metrics(pid) {
                peak_rss_kb.fetch_max(rss_kb, Ordering::Relaxed);
                // Store CPU% as integer hundredths (e.g., 12.5% → 1250)
                let cpu_hundredths = (cpu_pct * 100.0) as u64;
                peak_cpu_pct.fetch_max(cpu_hundredths, Ordering::Relaxed);
            }
            thread::sleep(METRIC_SAMPLE_INTERVAL);
        }
    })
}

// ── Percentile Calculation ─────────────────────────────────────────

/// All values in microseconds.
struct LatencyStats {
    p50: u64,
    p95: u64,
    p99: u64,
    max: u64,
}

fn compute_latency_stats(latencies: &mut [u64]) -> LatencyStats {
    latencies.sort_unstable();
    let n = latencies.len();

    if n == 0 {
        return LatencyStats {
            p50: 0,
            p95: 0,
            p99: 0,
            max: 0,
        };
    }

    LatencyStats {
        p50: latencies[n * 50 / 100],
        p95: latencies[n * 95 / 100],
        p99: latencies[n * 99 / 100],
        max: latencies[n - 1],
    }
}

// ── Proxy Lifecycle ────────────────────────────────────────────────

fn start_dwaar_with_config(config_path: &str) -> std::process::Child {
    // Prefer the release binary for meaningful perf numbers. The test binary
    // itself is debug, but we want to benchmark the proxy at full optimization.
    // Fall back to the test-profile binary if release isn't built.
    let workspace_root = format!("{}/../..", env!("CARGO_MANIFEST_DIR"));
    let release_bin = format!("{workspace_root}/target/release/dwaar");
    let bin = if std::path::Path::new(&release_bin).exists() {
        println!("Using release binary: {release_bin}");
        release_bin
    } else {
        let debug_bin = env!("CARGO_BIN_EXE_dwaar").to_string();
        println!("WARNING: release binary not found, using debug build (results will be slow)");
        println!("  Build release first: cargo build --release");
        debug_bin
    };

    let child = Command::new(bin)
        .args(["--config", config_path])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start dwaar");

    // Give the proxy time to bootstrap (Pingora runtime init)
    thread::sleep(Duration::from_secs(2));
    child
}

fn stop_dwaar(mut child: std::process::Child) {
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => {
                if start.elapsed() > Duration::from_secs(15) {
                    child.kill().ok();
                    return;
                }
                thread::sleep(Duration::from_millis(100));
            }
            Err(_) => {
                child.kill().ok();
                return;
            }
        }
    }
}

/// Wait for the proxy to accept connections.
fn wait_for_proxy(addr: &str) -> bool {
    for _ in 0..50 {
        if std::net::TcpStream::connect(addr).is_ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }
    false
}

// ── Reporting ──────────────────────────────────────────────────────

fn print_report_header() {
    println!();
    println!(
        "┌────────────┬──────────┬───────────┬───────────┬───────────┬───────────┬──────────┬──────────┬────────┐"
    );
    println!(
        "│ Concurrent │      RPS │   p50 lat │   p95 lat │   p99 lat │   max lat │ Peak RSS │ Peak CPU │ Errors │"
    );
    println!(
        "├────────────┼──────────┼───────────┼───────────┼───────────┼───────────┼──────────┼──────────┼────────┤"
    );
}

fn print_report_row(
    concurrency: usize,
    rps: u64,
    stats: &LatencyStats,
    peak_rss_kb: u64,
    peak_cpu_pct: f64,
    errors: u64,
) {
    println!(
        "│ {:>10} │ {:>8} │ {:>7}µs │ {:>7}µs │ {:>7}µs │ {:>7}µs │ {:>5} MB │ {:>6.1}% │ {:>6} │",
        concurrency,
        rps,
        stats.p50,
        stats.p95,
        stats.p99,
        stats.max,
        peak_rss_kb / 1024,
        peak_cpu_pct,
        errors,
    );
}

fn print_report_footer() {
    println!(
        "└────────────┴──────────┴───────────┴───────────┴───────────┴───────────┴──────────┴──────────┴────────┘"
    );
}

// ── Test ───────────────────────────────────────────────────────────

/// Run stress test at one concurrency level. Returns `(rps, stats, peak_rss_kb, peak_cpu, errors)`.
async fn run_concurrency_level(
    target: &str,
    concurrency: usize,
    proxy_pid: Option<u32>,
) -> (u64, LatencyStats, u64, f64, u64) {
    let barrier = Arc::new(Barrier::new(concurrency));
    let target_str = target.to_string();

    // Start metric collector if we have a PID
    let metric_running = Arc::new(AtomicBool::new(true));
    let peak_rss = Arc::new(AtomicU64::new(0));
    let peak_cpu = Arc::new(AtomicU64::new(0));

    let metric_handle = proxy_pid.map(|pid| {
        spawn_metric_collector(
            pid,
            metric_running.clone(),
            peak_rss.clone(),
            peak_cpu.clone(),
        )
    });

    // Spawn load tasks
    let mut handles = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let t = target_str.clone();
        let b = barrier.clone();
        handles.push(tokio::spawn(load_task(t, TEST_DURATION, b)));
    }

    // Collect results
    let start = Instant::now();
    let mut all_latencies = Vec::new();
    let mut total_requests = 0u64;
    let mut total_errors = 0u64;

    for handle in handles {
        match handle.await {
            Ok(result) => {
                total_requests += result.requests;
                total_errors += result.errors;
                all_latencies.extend_from_slice(&result.latencies_us);
            }
            Err(_) => {
                total_errors += 1;
            }
        }
    }
    let wall_time = start.elapsed();

    // Stop metric collector
    metric_running.store(false, Ordering::Relaxed);
    if let Some(h) = metric_handle {
        let _ = h.join();
    }

    let rps = if wall_time.as_secs() > 0 {
        total_requests / wall_time.as_secs()
    } else {
        total_requests
    };

    let stats = compute_latency_stats(&mut all_latencies);
    let peak_rss_val = peak_rss.load(Ordering::Relaxed);
    let peak_cpu_val = peak_cpu.load(Ordering::Relaxed) as f64 / 100.0;

    (rps, stats, peak_rss_val, peak_cpu_val, total_errors)
}

/// Check how many file descriptors are available.
/// Returns `u64::MAX` if unlimited, a parsed number otherwise, defaults to 256.
fn check_fd_limit() -> u64 {
    let output = Command::new("sh")
        .args(["-c", "ulimit -n"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());

    output.map_or(256, |s| {
        if s == "unlimited" {
            u64::MAX
        } else {
            s.parse().unwrap_or(256)
        }
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "long-running stress test — run with: cargo test --test stress -- --ignored --nocapture"]
async fn stress_test_concurrent_connections() {
    // ── Setup ──────────────────────────────────────────────────

    // Check if we should use an external proxy
    let external_target = std::env::var("STRESS_TARGET").ok();
    let external_backend = std::env::var("STRESS_BACKEND").ok();

    // Start mock backend on ephemeral port
    let backend_addr = external_backend.as_deref().unwrap_or("127.0.0.1:0");
    let backend_listener = TcpListener::bind(backend_addr)
        .await
        .expect("bind mock backend");
    let backend_port = backend_listener.local_addr().expect("local addr").port();
    println!("Mock backend listening on 127.0.0.1:{backend_port}");

    let backend_running = Arc::new(AtomicBool::new(true));
    let br = backend_running.clone();
    tokio::spawn(async move {
        mock_backend(backend_listener, br).await;
    });

    // Start Dwaar (unless using external proxy)
    let (target_addr, proxy_child) = if let Some(ref target) = external_target {
        println!("Using external proxy at {target}");
        (target.clone(), None)
    } else {
        // Write temp Dwaarfile
        let dwaarfile_content =
            format!("127.0.0.1 {{\n    reverse_proxy 127.0.0.1:{backend_port}\n}}\n");
        let config_path = "/tmp/dwaar-stress-test-config";
        std::fs::write(config_path, &dwaarfile_content).expect("write temp config");
        println!("Dwaarfile: {dwaarfile_content}");

        let child = start_dwaar_with_config(config_path);
        let pid = child.id();
        println!("Dwaar started (PID {pid})");

        assert!(
            wait_for_proxy("127.0.0.1:6188"),
            "proxy failed to start within 5 seconds"
        );
        println!("Proxy ready on 127.0.0.1:6188");

        ("127.0.0.1:6188".to_string(), Some(child))
    };

    let proxy_pid = proxy_child.as_ref().map(std::process::Child::id);

    // Check file descriptor limit for high concurrency
    let fd_limit = check_fd_limit();
    println!("File descriptor limit: {fd_limit}");

    // ── Run tests ──────────────────────────────────────────────

    println!("\nStress test: {TEST_DURATION:?} per level, target={target_addr}");
    print_report_header();

    let mut all_passed = true;

    for &concurrency in CONCURRENCY_LEVELS {
        // Skip high concurrency if FD limit is too low.
        // Each connection needs ~3 FDs (client socket + proxy→upstream + backend),
        // plus overhead for the runtime, logging, etc.
        let required_fds = (concurrency as u64) * 2 + 512;
        if required_fds > fd_limit {
            println!(
                "│ {:>10} │ SKIPPED — need ulimit -n {} (current: {}){}│",
                concurrency,
                required_fds,
                fd_limit,
                " ".repeat(37),
            );
            continue;
        }

        let (rps, stats, peak_rss_kb, peak_cpu, errors) =
            run_concurrency_level(&target_addr, concurrency, proxy_pid).await;

        print_report_row(concurrency, rps, &stats, peak_rss_kb, peak_cpu, errors);

        // Acceptance criteria from ISSUE-043
        if concurrency <= 1000 {
            // At ≤1K connections, P99 must be under 10ms
            if stats.p99 > 10_000 {
                eprintln!(
                    "FAIL: p99 latency {}µs exceeds 10ms at {} connections",
                    stats.p99, concurrency
                );
                all_passed = false;
            }
        }

        // Brief cooldown between levels
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    print_report_footer();

    // Check memory acceptance criteria if we have the PID
    if let Some(pid) = proxy_pid
        && let Some((final_rss_kb, _)) = sample_process_metrics(pid)
    {
        let rss_mb = final_rss_kb / 1024;
        println!("\nFinal proxy RSS: {rss_mb} MB");
        if rss_mb > 50 {
            eprintln!("FAIL: memory {rss_mb} MB exceeds 50 MB limit");
            all_passed = false;
        }
    }

    // ── Teardown ───────────────────────────────────────────────

    backend_running.store(false, Ordering::Relaxed);
    if let Some(child) = proxy_child {
        stop_dwaar(child);
        let _ = std::fs::remove_file("/tmp/dwaar-stress-test-config");
    }

    println!();
    if all_passed {
        println!("All acceptance criteria passed.");
    }
    assert!(all_passed, "one or more acceptance criteria failed");
}

/// Baseline benchmark: direct connection to mock backend (no proxy).
/// Establishes the floor — any overhead above this is proxy cost.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "long-running baseline test — run with: cargo test --test stress -- --ignored --nocapture"]
async fn stress_test_baseline_no_proxy() {
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock backend");
    let backend_port = backend_listener.local_addr().expect("local addr").port();

    let backend_running = Arc::new(AtomicBool::new(true));
    let br = backend_running.clone();
    tokio::spawn(async move {
        mock_backend(backend_listener, br).await;
    });

    // Brief pause for backend to be ready
    tokio::time::sleep(Duration::from_millis(100)).await;

    let target = format!("127.0.0.1:{backend_port}");
    println!("\nBaseline test (direct to backend): {TEST_DURATION:?}, target={target}");
    print_report_header();

    for &concurrency in &[100, 1_000] {
        let fd_limit = check_fd_limit();
        let required_fds = (concurrency as u64) * 2 + 512;
        if required_fds > fd_limit {
            continue;
        }

        let (rps, stats, _, _, errors) = run_concurrency_level(&target, concurrency, None).await;

        print_report_row(concurrency, rps, &stats, 0, 0.0, errors);
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    print_report_footer();
    backend_running.store(false, Ordering::Relaxed);
}
