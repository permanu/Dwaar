// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Standard Prometheus `process_*` metrics.
//!
//! Every Prometheus-instrumented service exposes these metrics. Without them,
//! operators can't monitor the proxy process itself (memory leaks, FD
//! exhaustion, CPU usage). Platform-specific implementations read from
//! `/proc/self` on Linux and fall back to `libc` / `sysctl` on macOS.

use std::fmt::Write;
#[cfg(target_os = "linux")]
use std::sync::Once;
use std::sync::OnceLock;
use std::time::SystemTime;

/// Logs a one-shot warning if a /proc read fails, then stays silent.
///
/// Used to surface "procfs unavailable" once per process so operators
/// know why metrics are zero, without flooding the log with every poll.
/// See issue #171.
#[cfg(target_os = "linux")]
fn warn_once_on_proc_failure(path: &str, err: &std::io::Error) {
    static WARNED: Once = Once::new();
    WARNED.call_once(|| {
        tracing::warn!(
            proc_path = %path,
            error = %err,
            "process metrics unavailable: /proc read failed (further failures will be silent)"
        );
    });
}

/// Synchronous /proc read used only at startup (process_start_time_secs init).
///
/// The async `read_proc` variant below must be used for all per-scrape reads.
/// Startup happens before the server accepts traffic, so a blocking read here
/// does not stall any runtime workers.
#[cfg(target_os = "linux")]
fn read_proc_sync(path: &str) -> Option<String> {
    match std::fs::read_to_string(path) {
        Ok(s) => Some(s),
        Err(e) => {
            warn_once_on_proc_failure(path, &e);
            None
        }
    }
}

/// Offloads a /proc file read onto a blocking thread via spawn_blocking.
///
/// Procfs reads are normally fast, but under disk pressure the kernel can
/// stall the page-fault path for tens to hundreds of milliseconds. Doing
/// this on a runtime worker thread blocks all tasks on that thread. Moving
/// the read onto a dedicated blocking thread keeps the async workers free.
/// See issue #156.
#[cfg(target_os = "linux")]
async fn read_proc(path: &'static str) -> Option<String> {
    tokio::task::spawn_blocking(move || match std::fs::read_to_string(path) {
        Ok(s) => Some(s),
        Err(e) => {
            warn_once_on_proc_failure(path, &e);
            None
        }
    })
    .await
    .ok()
    .flatten()
}

/// Offloads a /proc directory read onto a blocking thread via spawn_blocking.
///
/// Counting entries in /proc/self/fd requires a readdir syscall, which can
/// block under I/O pressure. We collect the count inside spawn_blocking to
/// avoid holding the async worker hostage.
/// See issue #156.
#[cfg(target_os = "linux")]
async fn read_proc_dir_count(path: &'static str) -> u64 {
    tokio::task::spawn_blocking(move || match std::fs::read_dir(path) {
        Ok(entries) => entries.count() as u64,
        Err(e) => {
            warn_once_on_proc_failure(path, &e);
            0
        }
    })
    .await
    .unwrap_or(0)
}

/// Cached process start time in Unix seconds.
///
/// Populated on first access via the platform-specific
/// [`process_start_time_secs`] implementation. The value never changes
/// after the process starts, so `OnceLock` is strictly a one-shot cache
/// with no contention and no reload cost. Using a static (rather than a
/// field on `ProcessMetrics`) means a late-initialized metrics registry
/// still reports the actual kernel-recorded process start time, not the
/// time at which `ProcessMetrics::new()` happened to run.
static PROCESS_START_TIME_SECS: OnceLock<f64> = OnceLock::new();

/// Collects standard Prometheus process metrics.
///
/// `start_time_seconds` is read from a platform-specific kernel source on
/// first access — not captured at construction — so a late-initialized
/// metrics registry still reports the true process start time instead of
/// the struct construction time. See [`process_start_time_secs`] for the
/// lookup order.
#[derive(Debug)]
pub struct ProcessMetrics {
    _priv: (),
}

impl Default for ProcessMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessMetrics {
    pub fn new() -> Self {
        // Eagerly populate the start-time cache so scrapers see a stable
        // value from the first render onward, but do NOT fall back to
        // `SystemTime::now()` inside `new()` — the platform lookup
        // determines the real value.
        let _ = *PROCESS_START_TIME_SECS.get_or_init(process_start_time_secs);
        Self { _priv: () }
    }

    pub fn cpu_seconds_total(&self) -> f64 {
        cpu_seconds_total_impl()
    }

    /// Async — offloads the /proc/self/status read onto a blocking thread.
    pub async fn resident_memory_bytes(&self) -> u64 {
        resident_memory_bytes_impl().await
    }

    /// Async — offloads the /proc/self/fd readdir onto a blocking thread.
    pub async fn open_fds(&self) -> u64 {
        open_fds_impl().await
    }

    pub fn start_time_seconds(&self) -> f64 {
        *PROCESS_START_TIME_SECS.get_or_init(process_start_time_secs)
    }

    pub fn max_fds(&self) -> u64 {
        max_fds_impl()
    }

    /// Async — offloads the /proc/self/status thread-count read onto a blocking thread.
    pub async fn threads(&self) -> u64 {
        threads_impl().await
    }

    /// Render all 6 `process_*` metrics in Prometheus text exposition format.
    ///
    /// Async because the per-scrape /proc reads are offloaded via
    /// `spawn_blocking` to avoid blocking the runtime worker on slow procfs
    /// I/O (issue #156).
    pub async fn render(&self, out: &mut String) {
        out.push_str(
            "# HELP process_cpu_seconds_total Total user and system CPU time spent in seconds.\n",
        );
        out.push_str("# TYPE process_cpu_seconds_total counter\n");
        let _ = writeln!(
            out,
            "process_cpu_seconds_total {:.6}",
            self.cpu_seconds_total()
        );

        out.push_str("# HELP process_resident_memory_bytes Resident memory size in bytes.\n");
        out.push_str("# TYPE process_resident_memory_bytes gauge\n");
        let _ = writeln!(
            out,
            "process_resident_memory_bytes {}",
            self.resident_memory_bytes().await
        );

        out.push_str("# HELP process_open_fds Number of open file descriptors.\n");
        out.push_str("# TYPE process_open_fds gauge\n");
        let _ = writeln!(out, "process_open_fds {}", self.open_fds().await);

        out.push_str("# HELP process_start_time_seconds Start time of the process since Unix epoch in seconds.\n");
        out.push_str("# TYPE process_start_time_seconds gauge\n");
        let _ = writeln!(
            out,
            "process_start_time_seconds {:.3}",
            self.start_time_seconds()
        );

        out.push_str("# HELP process_max_fds Maximum number of open file descriptors.\n");
        out.push_str("# TYPE process_max_fds gauge\n");
        let _ = writeln!(out, "process_max_fds {}", self.max_fds());

        out.push_str("# HELP process_threads Number of OS threads in the process.\n");
        out.push_str("# TYPE process_threads gauge\n");
        let _ = writeln!(out, "process_threads {}", self.threads().await);
    }
}

fn current_unix_secs() -> f64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Platform-specific lookup of the real process start time in Unix seconds.
///
/// * Linux: reads `/proc/self/stat` field 22 (`starttime`, in clock ticks
///   since boot) and combines it with `/proc/stat` `btime` (boot time in
///   Unix seconds) and `sysconf(_SC_CLK_TCK)`.
/// * macOS: calls `proc_pidinfo(PROC_PIDTBSDINFO)` on the current pid and
///   reads `pbi_start_tvsec` + `pbi_start_tvusec` from the returned
///   `proc_bsdinfo`.
/// * Other platforms (including Windows): falls back to `SystemTime::now()`.
///   This is the legacy behavior and is only "accurate" if the metrics
///   registry is constructed very early in `main()`.
///
/// Every path returns a finite non-negative `f64` — callers never have to
/// handle errors because the metric is a best-effort gauge.
///
/// Uses synchronous /proc reads deliberately: this runs exactly once at
/// startup (cached by `PROCESS_START_TIME_SECS`), before the server accepts
/// traffic, so blocking is acceptable here. Per-scrape reads use the async
/// helpers instead.
fn process_start_time_secs() -> f64 {
    #[cfg(target_os = "linux")]
    {
        if let Some(secs) = linux_process_start_time_secs_sync() {
            return secs;
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(secs) = macos_process_start_time_secs() {
            return secs;
        }
    }
    current_unix_secs()
}

/// Sync version of the Linux start-time lookup, used only at startup init.
#[cfg(target_os = "linux")]
fn linux_process_start_time_secs_sync() -> Option<f64> {
    // /proc/self/stat: split on the LAST `)` to avoid desync from a
    // `comm` field that contains spaces or parens.
    let stat = read_proc_sync("/proc/self/stat")?;
    let rparen = stat.rfind(')')?;
    let after = stat.get(rparen + 1..)?.trim_start();
    // `starttime` is original field 22 → index 22-3 = 19 in `after`.
    let starttime_ticks: u64 = after.split_ascii_whitespace().nth(19)?.parse().ok()?;

    // SAFETY: sysconf with a valid _SC_* constant has no preconditions.
    #[allow(unsafe_code)]
    let clk_tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if clk_tck <= 0 {
        return None;
    }
    #[allow(clippy::cast_precision_loss, clippy::cast_sign_loss)]
    let clk_tck = clk_tck as f64;
    #[allow(clippy::cast_precision_loss)]
    let seconds_since_boot = starttime_ticks as f64 / clk_tck;

    let stat2 = read_proc_sync("/proc/stat")?;
    let btime: u64 = stat2
        .lines()
        .find_map(|l| l.strip_prefix("btime "))?
        .trim()
        .parse()
        .ok()?;

    #[allow(clippy::cast_precision_loss)]
    let result = btime as f64 + seconds_since_boot;
    Some(result)
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn macos_process_start_time_secs() -> Option<f64> {
    // `proc_pidinfo(PROC_PIDTBSDINFO)` on the current pid returns a
    // `proc_bsdinfo` whose `pbi_start_tvsec`/`pbi_start_tvusec` give
    // the process start time in Unix seconds + microseconds. This is
    // the supported Darwin API for reading a process's start time
    // without touching the fragile `kinfo_proc` sysctl path.
    use std::mem;

    // SAFETY: `proc_bsdinfo` is a POD struct with no required invariants;
    // zeroed memory is a valid initial value that `proc_pidinfo` will
    // overwrite on success.
    let mut info: libc::proc_bsdinfo = unsafe { mem::zeroed() };
    // proc_bsdinfo is a small POD struct (~200 bytes); size fits in c_int
    // on every target Dwaar supports. `try_into` avoids the signed-cast lint.
    let size: libc::c_int = mem::size_of::<libc::proc_bsdinfo>()
        .try_into()
        .expect("proc_bsdinfo size fits in c_int");

    // SAFETY: `getpid()` is always safe. `proc_pidinfo` populates `info`
    // when the return value equals `size` — checked before reading.
    let pid = unsafe { libc::getpid() };
    let rc = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            std::ptr::from_mut::<libc::proc_bsdinfo>(&mut info).cast::<libc::c_void>(),
            size,
        )
    };
    if rc != size {
        return None;
    }

    #[allow(clippy::cast_precision_loss)]
    let sec = info.pbi_start_tvsec as f64;
    #[allow(clippy::cast_precision_loss)]
    let usec = info.pbi_start_tvusec as f64 / 1_000_000.0;
    let result = sec + usec;
    if result > 0.0 { Some(result) } else { None }
}

// libc FFI: getrusage has no safe Rust wrapper; zeroed struct + single call.
// tv_usec is i32 on macOS, i64 on Linux — `as f64` works on both without
// precision loss for microsecond values (max ~999999, well within f64 range).
#[allow(unsafe_code, clippy::cast_lossless, clippy::cast_precision_loss)]
fn cpu_seconds_total_impl() -> f64 {
    unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        if libc::getrusage(libc::RUSAGE_SELF, &raw mut usage) == 0 {
            let user = usage.ru_utime.tv_sec as f64 + usage.ru_utime.tv_usec as f64 / 1_000_000.0;
            let sys = usage.ru_stime.tv_sec as f64 + usage.ru_stime.tv_usec as f64 / 1_000_000.0;
            user + sys
        } else {
            0.0
        }
    }
}

#[cfg(target_os = "linux")]
async fn resident_memory_bytes_impl() -> u64 {
    // /proc/self/status VmRSS is in kB. The read is offloaded via spawn_blocking
    // because procfs can stall on disk pressure (issue #156).
    read_proc("/proc/self/status")
        .await
        .and_then(|s| {
            s.lines()
                .find(|line| line.starts_with("VmRSS:"))
                .and_then(|line| {
                    line.split_whitespace()
                        .nth(1)
                        .and_then(|v| v.parse::<u64>().ok())
                })
                .map(|kb| kb * 1024)
        })
        .unwrap_or(0)
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code, clippy::unused_async)]
// getrusage is a syscall with no blocking I/O, so spawn_blocking is not needed
// here. The async signature is kept so callers are uniform across platforms.
async fn resident_memory_bytes_impl() -> u64 {
    // ru_maxrss is in bytes on macOS (unlike Linux where it's KB).
    unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        if libc::getrusage(libc::RUSAGE_SELF, &raw mut usage) == 0 {
            usage.ru_maxrss as u64
        } else {
            0
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[allow(clippy::unused_async)]
// Stub for unsupported platforms; async signature kept for API uniformity.
async fn resident_memory_bytes_impl() -> u64 {
    0
}

#[cfg(target_os = "linux")]
async fn open_fds_impl() -> u64 {
    // Counting /proc/self/fd entries requires readdir, which can block under
    // I/O pressure. Offload to a blocking thread (issue #156).
    read_proc_dir_count("/proc/self/fd").await
}

#[cfg(target_os = "macos")]
async fn open_fds_impl() -> u64 {
    // /dev/fd is macOS's equivalent of /proc/self/fd. readdir can block
    // under I/O pressure; offload to a blocking thread (issue #156).
    tokio::task::spawn_blocking(|| {
        std::fs::read_dir("/dev/fd")
            .map(|entries| entries.count() as u64)
            .unwrap_or(0)
    })
    .await
    .unwrap_or(0)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[allow(clippy::unused_async)]
// Stub for unsupported platforms; async signature kept for API uniformity.
async fn open_fds_impl() -> u64 {
    0
}

// libc FFI: getrlimit has no safe Rust wrapper.
#[allow(unsafe_code)]
fn max_fds_impl() -> u64 {
    unsafe {
        let mut rlim: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut rlim) == 0 {
            rlim.rlim_cur
        } else {
            0
        }
    }
}

#[cfg(target_os = "linux")]
async fn threads_impl() -> u64 {
    // Threads: field in /proc/self/status. Offloaded via spawn_blocking
    // for the same reason as resident_memory_bytes_impl (issue #156).
    read_proc("/proc/self/status")
        .await
        .and_then(|s| {
            s.lines()
                .find(|line| line.starts_with("Threads:"))
                .and_then(|line| line.split_whitespace().nth(1))
                .and_then(|v| v.parse::<u64>().ok())
        })
        .unwrap_or(0)
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::unused_async)]
// Stub for non-Linux platforms; async signature kept for API uniformity.
async fn threads_impl() -> u64 {
    // No portable way without platform-specific APIs.
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_does_not_panic() {
        let _m = ProcessMetrics::new();
    }

    #[test]
    fn cpu_seconds_is_non_negative() {
        let m = ProcessMetrics::new();
        assert!(m.cpu_seconds_total() >= 0.0);
    }

    #[tokio::test]
    async fn resident_memory_is_positive() {
        let m = ProcessMetrics::new();
        assert!(
            m.resident_memory_bytes().await > 0,
            "process must use some memory"
        );
    }

    #[tokio::test]
    async fn open_fds_positive() {
        let m = ProcessMetrics::new();
        assert!(m.open_fds().await > 0, "stdin/stdout/stderr at minimum");
    }

    #[test]
    fn start_time_in_past() {
        let m = ProcessMetrics::new();
        let now = current_unix_secs();
        assert!(m.start_time_seconds() > 0.0);
        assert!(m.start_time_seconds() <= now);
    }

    #[test]
    fn max_fds_positive() {
        let m = ProcessMetrics::new();
        assert!(m.max_fds() > 0);
    }

    #[tokio::test]
    async fn render_contains_all_metrics() {
        let m = ProcessMetrics::new();
        let mut out = String::new();
        m.render(&mut out).await;

        assert!(out.contains("process_cpu_seconds_total"));
        assert!(out.contains("process_resident_memory_bytes"));
        assert!(out.contains("process_open_fds"));
        assert!(out.contains("process_start_time_seconds"));
        assert!(out.contains("process_max_fds"));
        assert!(out.contains("process_threads"));
    }

    #[tokio::test]
    async fn render_has_help_and_type_lines() {
        let m = ProcessMetrics::new();
        let mut out = String::new();
        m.render(&mut out).await;

        let help_count = out.matches("# HELP").count();
        let type_count = out.matches("# TYPE").count();
        assert_eq!(help_count, 6, "should have 6 HELP lines");
        assert_eq!(type_count, 6, "should have 6 TYPE lines");
    }

    #[test]
    fn is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ProcessMetrics>();
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn warn_once_helper_callable() {
        // Smoke test: the warn-once helper exists and runs without panicking
        // when invoked with a synthetic error. Behavior verification of the
        // Once gate is left to manual inspection (Once is process-global and
        // doesn't compose with parallel cargo-test execution). See issue #171.
        let err = std::io::Error::new(std::io::ErrorKind::NotFound, "synthetic");
        warn_once_on_proc_failure("/proc/self/synthetic", &err);
        warn_once_on_proc_failure("/proc/self/synthetic", &err);
        // Test passes if no panic.
    }

    /// Smoke test: the async read_proc helper returns Some for a real path.
    /// This is a regression guard — if spawn_blocking is broken or the path
    /// doesn't exist in the test environment, the scraper would silently
    /// report zeros.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn read_proc_returns_some_for_existing_file() {
        let r = read_proc("/proc/self/stat").await;
        assert!(r.is_some(), "expected Some(_) for /proc/self/stat");
    }

    /// Smoke test: a missing path returns None without panicking.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn read_proc_returns_none_for_missing_file() {
        let r = read_proc("/proc/self/this-file-does-not-exist").await;
        assert!(r.is_none());
    }
}
