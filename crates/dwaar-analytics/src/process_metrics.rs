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
use std::time::SystemTime;

/// Collects standard Prometheus process metrics.
///
/// `start_time` is captured once at construction — the process start time
/// doesn't change, so there's no reason to re-read it per scrape.
#[derive(Debug)]
pub struct ProcessMetrics {
    start_time_secs: f64,
}

impl Default for ProcessMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessMetrics {
    pub fn new() -> Self {
        Self {
            start_time_secs: current_unix_secs(),
        }
    }

    pub fn cpu_seconds_total(&self) -> f64 {
        cpu_seconds_total_impl()
    }

    pub fn resident_memory_bytes(&self) -> u64 {
        resident_memory_bytes_impl()
    }

    pub fn open_fds(&self) -> u64 {
        open_fds_impl()
    }

    pub fn start_time_seconds(&self) -> f64 {
        self.start_time_secs
    }

    pub fn max_fds(&self) -> u64 {
        max_fds_impl()
    }

    pub fn threads(&self) -> u64 {
        threads_impl()
    }

    /// Render all 6 `process_*` metrics in Prometheus text exposition format.
    pub fn render(&self, out: &mut String) {
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
            self.resident_memory_bytes()
        );

        out.push_str("# HELP process_open_fds Number of open file descriptors.\n");
        out.push_str("# TYPE process_open_fds gauge\n");
        let _ = writeln!(out, "process_open_fds {}", self.open_fds());

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
        let _ = writeln!(out, "process_threads {}", self.threads());
    }
}

fn current_unix_secs() -> f64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
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
fn resident_memory_bytes_impl() -> u64 {
    // /proc/self/status VmRSS is in kB.
    std::fs::read_to_string("/proc/self/status")
        .ok()
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
#[allow(unsafe_code)]
fn resident_memory_bytes_impl() -> u64 {
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
fn resident_memory_bytes_impl() -> u64 {
    0
}

#[cfg(target_os = "linux")]
fn open_fds_impl() -> u64 {
    std::fs::read_dir("/proc/self/fd")
        .map(|entries| entries.count() as u64)
        .unwrap_or(0)
}

#[cfg(target_os = "macos")]
fn open_fds_impl() -> u64 {
    // /dev/fd is macOS's equivalent of /proc/self/fd.
    std::fs::read_dir("/dev/fd")
        .map(|entries| entries.count() as u64)
        .unwrap_or(0)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn open_fds_impl() -> u64 {
    0
}

// libc FFI: getrlimit has no safe Rust wrapper.
#[allow(unsafe_code)]
fn max_fds_impl() -> u64 {
    unsafe {
        let mut rlim: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut rlim) == 0 {
            rlim.rlim_cur as u64
        } else {
            0
        }
    }
}

#[cfg(target_os = "linux")]
fn threads_impl() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|line| line.starts_with("Threads:"))
                .and_then(|line| line.split_whitespace().nth(1))
                .and_then(|v| v.parse::<u64>().ok())
        })
        .unwrap_or(0)
}

#[cfg(not(target_os = "linux"))]
fn threads_impl() -> u64 {
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

    #[test]
    fn resident_memory_is_positive() {
        let m = ProcessMetrics::new();
        assert!(
            m.resident_memory_bytes() > 0,
            "process must use some memory"
        );
    }

    #[test]
    fn open_fds_positive() {
        let m = ProcessMetrics::new();
        assert!(m.open_fds() > 0, "stdin/stdout/stderr at minimum");
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

    #[test]
    fn render_contains_all_metrics() {
        let m = ProcessMetrics::new();
        let mut out = String::new();
        m.render(&mut out);

        assert!(out.contains("process_cpu_seconds_total"));
        assert!(out.contains("process_resident_memory_bytes"));
        assert!(out.contains("process_open_fds"));
        assert!(out.contains("process_start_time_seconds"));
        assert!(out.contains("process_max_fds"));
        assert!(out.contains("process_threads"));
    }

    #[test]
    fn render_has_help_and_type_lines() {
        let m = ProcessMetrics::new();
        let mut out = String::new();
        m.render(&mut out);

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
}
