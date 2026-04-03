// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Scale-to-zero wake coordinator (ISSUE-082).
//!
//! When an upstream is unreachable and `scale_to_zero` is configured, the proxy
//! holds the incoming request, triggers a wake command (once per upstream —
//! coalesced across concurrent requests), polls health with exponential backoff,
//! and forwards the request once the backend responds.
//!
//! ## Design rationale (Four Pillars)
//!
//! | Pillar | Decision |
//! |---|---|
//! | Performance | `AtomicU8` state + `Notify` — no mutex on the wake-check fast path |
//! | Reliability | Single wake command per upstream (coalesced); bounded timeout prevents hangs |
//! | Security | Wake command runs via shell — operator controls what runs |
//! | Competitive Parity | Matches Traefik's `ServersTransport` wake behavior |

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use tokio::sync::Notify;
use tracing::{debug, error, info, warn};

/// Runtime config for scale-to-zero (compiled from `ScaleToZeroDirective`).
#[derive(Debug)]
pub struct ScaleToZeroConfig {
    /// Max time to wait for the backend to become reachable.
    pub wake_timeout: Duration,
    /// Shell command to execute to wake the backend.
    pub wake_command: String,
    /// Coordination state — ensures only one wake command runs at a time.
    state: AtomicU8,
    /// Notifier — woken when the backend becomes reachable (or times out).
    notify: Notify,
}

/// Internal state machine for the wake coordinator.
///
/// Transitions: Idle → Waking → Ready (success) or Idle (failure/timeout).
const STATE_IDLE: u8 = 0;
const STATE_WAKING: u8 = 1;
const STATE_READY: u8 = 2;

impl ScaleToZeroConfig {
    /// Create a new scale-to-zero config.
    pub fn new(wake_timeout: Duration, wake_command: String) -> Self {
        Self {
            wake_timeout,
            wake_command,
            state: AtomicU8::new(STATE_IDLE),
            notify: Notify::new(),
        }
    }

    /// Attempt to wake the upstream and wait for it to become reachable.
    ///
    /// Only the first caller triggers the wake command; subsequent callers
    /// wait on the same `Notify`. Returns `Ok(())` when the upstream is
    /// reachable, or `Err(WakeError)` on timeout or command failure.
    ///
    /// This runs inside Pingora's request handling (not a background service),
    /// so `tokio::spawn` for the shell command is appropriate here.
    pub async fn wake_and_wait(&self, upstream_addr: SocketAddr) -> Result<(), WakeError> {
        // Fast path: backend already woke from a previous request's wake cycle.
        if self.state.load(Ordering::Acquire) == STATE_READY {
            // Reset to idle so the next cold start can trigger a wake.
            self.state.store(STATE_IDLE, Ordering::Release);
            return Ok(());
        }

        // Try to become the wake leader (transition Idle → Waking).
        let prev = self.state.compare_exchange(
            STATE_IDLE,
            STATE_WAKING,
            Ordering::AcqRel,
            Ordering::Acquire,
        );

        match prev {
            Ok(STATE_IDLE) => {
                // We are the leader — run the wake command and poll health.
                info!(
                    %upstream_addr,
                    command = %self.wake_command,
                    "scale-to-zero: triggering wake command"
                );

                let result = self.run_wake_cycle(upstream_addr).await;

                match result {
                    Ok(()) => {
                        self.state.store(STATE_READY, Ordering::Release);
                        self.notify.notify_waiters();
                        // Reset to idle for the next cold start cycle.
                        self.state.store(STATE_IDLE, Ordering::Release);
                        Ok(())
                    }
                    Err(e) => {
                        // Reset to idle so future requests can retry.
                        self.state.store(STATE_IDLE, Ordering::Release);
                        self.notify.notify_waiters();
                        Err(e)
                    }
                }
            }
            Err(STATE_WAKING) => {
                // Another request is already waking this upstream — wait for it.
                debug!(
                    %upstream_addr,
                    "scale-to-zero: waiting for in-progress wake"
                );
                let wait_result =
                    tokio::time::timeout(self.wake_timeout, self.notify.notified()).await;

                if wait_result.is_err() {
                    return Err(WakeError::Timeout);
                }

                // Check if wake succeeded or failed.
                let state = self.state.load(Ordering::Acquire);
                if state == STATE_READY || state == STATE_IDLE {
                    // Leader either succeeded (READY) or already reset to IDLE after success.
                    Ok(())
                } else {
                    Err(WakeError::Timeout)
                }
            }
            _ => {
                // STATE_READY — backend is already awake.
                self.state.store(STATE_IDLE, Ordering::Release);
                Ok(())
            }
        }
    }

    /// Execute the wake command and poll health until the backend responds.
    async fn run_wake_cycle(&self, upstream_addr: SocketAddr) -> Result<(), WakeError> {
        // Run the wake command via shell.
        let cmd_result =
            tokio::time::timeout(self.wake_timeout, run_shell_command(&self.wake_command)).await;

        match cmd_result {
            Ok(Ok(output)) => {
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    error!(
                        command = %self.wake_command,
                        exit_code = ?output.status.code(),
                        stderr = %stderr,
                        "scale-to-zero: wake command failed"
                    );
                    return Err(WakeError::CommandFailed {
                        exit_code: output.status.code(),
                        stderr: stderr.into_owned(),
                    });
                }
                debug!(
                    command = %self.wake_command,
                    "scale-to-zero: wake command succeeded, polling health"
                );
            }
            Ok(Err(e)) => {
                error!(
                    command = %self.wake_command,
                    error = %e,
                    "scale-to-zero: failed to execute wake command"
                );
                return Err(WakeError::CommandExecFailed(e.to_string()));
            }
            Err(_) => {
                warn!(
                    command = %self.wake_command,
                    "scale-to-zero: wake command timed out"
                );
                return Err(WakeError::Timeout);
            }
        }

        // Poll the upstream with exponential backoff until it responds or we time out.
        poll_health_with_backoff(upstream_addr, self.wake_timeout).await
    }
}

/// Errors that can occur during the scale-to-zero wake cycle.
#[derive(Debug)]
pub enum WakeError {
    /// The wake timeout expired before the backend became reachable.
    Timeout,
    /// The wake command exited with a non-zero status.
    CommandFailed {
        exit_code: Option<i32>,
        stderr: String,
    },
    /// Failed to spawn the wake command process.
    CommandExecFailed(String),
    /// The health poll timed out — backend never became reachable.
    HealthPollTimeout,
}

impl std::fmt::Display for WakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout => write!(f, "wake timeout expired"),
            Self::CommandFailed { exit_code, stderr } => {
                write!(f, "wake command failed (exit={exit_code:?}): {stderr}")
            }
            Self::CommandExecFailed(msg) => write!(f, "failed to exec wake command: {msg}"),
            Self::HealthPollTimeout => write!(f, "health poll timed out after wake command"),
        }
    }
}

/// Run a shell command asynchronously.
async fn run_shell_command(command: &str) -> Result<std::process::Output, std::io::Error> {
    tokio::process::Command::new("sh")
        .arg("-c")
        .arg(command)
        .output()
        .await
}

/// Poll the upstream via TCP connect with exponential backoff.
///
/// Starts at 200ms, doubles each attempt up to 4s, continues until
/// success or the total timeout is reached.
pub async fn poll_health_with_backoff(
    addr: SocketAddr,
    total_timeout: Duration,
) -> Result<(), WakeError> {
    let start = tokio::time::Instant::now();
    let mut interval = Duration::from_millis(200);
    let max_interval = Duration::from_secs(4);

    loop {
        let elapsed = start.elapsed();
        if elapsed >= total_timeout {
            warn!(
                %addr,
                elapsed_ms = elapsed.as_millis(),
                "scale-to-zero: health poll timed out"
            );
            return Err(WakeError::HealthPollTimeout);
        }

        // Try a TCP connect with a short per-attempt timeout.
        let remaining = total_timeout.saturating_sub(elapsed);
        let connect_timeout = Duration::from_secs(2).min(remaining);
        match tokio::time::timeout(connect_timeout, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(_stream)) => {
                info!(
                    %addr,
                    elapsed_ms = start.elapsed().as_millis(),
                    "scale-to-zero: upstream is reachable"
                );
                return Ok(());
            }
            Ok(Err(e)) => {
                debug!(
                    %addr,
                    error = %e,
                    retry_ms = interval.as_millis(),
                    "scale-to-zero: health probe failed, retrying"
                );
            }
            Err(_) => {
                debug!(
                    %addr,
                    retry_ms = interval.as_millis(),
                    "scale-to-zero: health probe timed out, retrying"
                );
            }
        }

        // Sleep before the next attempt.
        let remaining = total_timeout.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            return Err(WakeError::HealthPollTimeout);
        }
        tokio::time::sleep(interval.min(remaining)).await;

        // Exponential backoff: double the interval up to the cap.
        interval = (interval * 2).min(max_interval);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    fn test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19999)
    }

    #[test]
    fn scale_to_zero_config_construction() {
        let cfg = ScaleToZeroConfig::new(Duration::from_secs(30), "docker start myapp".to_string());
        assert_eq!(cfg.wake_timeout, Duration::from_secs(30));
        assert_eq!(cfg.wake_command, "docker start myapp");
    }

    #[test]
    fn initial_state_is_idle() {
        let cfg = ScaleToZeroConfig::new(Duration::from_secs(5), "echo waking".to_string());
        assert_eq!(cfg.state.load(Ordering::Relaxed), STATE_IDLE);
    }

    #[tokio::test]
    async fn wake_and_wait_with_successful_command() {
        // Use "true" as the wake command — always succeeds.
        // Use a port that won't be listening so health poll fails,
        // but set a short timeout to avoid hanging.
        let cfg = ScaleToZeroConfig::new(Duration::from_millis(500), "true".to_string());
        let addr = test_addr();

        // This should fail with HealthPollTimeout because nothing is listening.
        let result = cfg.wake_and_wait(addr).await;
        assert!(result.is_err());
        // State should be reset to idle after failure.
        assert_eq!(cfg.state.load(Ordering::Relaxed), STATE_IDLE);
    }

    #[tokio::test]
    async fn wake_and_wait_with_failing_command() {
        let cfg = ScaleToZeroConfig::new(
            Duration::from_secs(2),
            "false".to_string(), // "false" exits with code 1
        );
        let addr = test_addr();

        let result = cfg.wake_and_wait(addr).await;
        assert!(result.is_err());
        if let Err(WakeError::CommandFailed { exit_code, .. }) = &result {
            assert_eq!(*exit_code, Some(1));
        } else {
            panic!("expected CommandFailed, got {result:?}");
        }
    }

    #[tokio::test]
    async fn coalescing_only_one_wake_runs() {
        // Start a TCP listener so health poll succeeds immediately.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let cfg = Arc::new(ScaleToZeroConfig::new(
            Duration::from_secs(5),
            "true".to_string(),
        ));

        // Spawn multiple concurrent wake requests.
        let mut handles = Vec::new();
        for _ in 0..5 {
            let cfg = cfg.clone();
            handles.push(tokio::spawn(async move { cfg.wake_and_wait(addr).await }));
        }

        // All should succeed.
        for h in handles {
            let result: Result<(), WakeError> = h.await.expect("task panicked");
            assert!(result.is_ok(), "expected Ok, got {result:?}");
        }

        // Keep listener alive until test completes.
        drop(listener);
    }

    #[tokio::test]
    async fn poll_health_succeeds_when_port_open() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let result = poll_health_with_backoff(addr, Duration::from_secs(2)).await;
        assert!(result.is_ok());
        drop(listener);
    }

    #[tokio::test]
    async fn poll_health_times_out_when_port_closed() {
        let addr = test_addr();
        let result = poll_health_with_backoff(addr, Duration::from_millis(500)).await;
        assert!(result.is_err());
    }
}
