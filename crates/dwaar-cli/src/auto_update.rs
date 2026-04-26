// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Background auto-update service.
//!
//! When `auto_update {}` is present in the Dwaarfile, this service runs
//! as a Pingora [`BackgroundService`] alongside the proxy. It periodically
//! checks GitHub Releases for a newer version, downloads and
//! verifies the binary, and either triggers a zero-downtime reload or
//! just replaces the binary on disk (depending on `on_new_version`).

use std::process::Command;
use std::time::Duration;

use async_trait::async_trait;
use dwaar_config::model::{AutoUpdateAction, AutoUpdateConfig};
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use tracing::{debug, error, info, warn};

/// Background service that periodically checks for and applies updates.
#[derive(Debug)]
pub(crate) struct AutoUpdateService {
    config: AutoUpdateConfig,
}

impl AutoUpdateService {
    pub(crate) fn new(config: AutoUpdateConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl BackgroundService for AutoUpdateService {
    async fn start(&self, shutdown: ShutdownWatch) {
        let base_interval = Duration::from_secs(self.config.check_interval_secs);

        // Initial delay: jitter up to 10% of the check interval to prevent
        // thundering herd when many instances start at the same time
        // (e.g. Kubernetes rolling restart).
        let jitter_secs = (fastrand::u64(0..=self.config.check_interval_secs / 10)).max(30);
        info!(
            check_interval = ?base_interval,
            initial_delay_secs = jitter_secs,
            channel = %self.config.channel,
            "auto-update service started"
        );

        tokio::time::sleep(Duration::from_secs(jitter_secs)).await;

        loop {
            if *shutdown.borrow() {
                debug!("auto-update shutting down");
                return;
            }

            self.check_and_apply().await;

            // Sleep until next check, interruptible by shutdown.
            let mut watch = shutdown.clone();
            tokio::select! {
                () = tokio::time::sleep(base_interval) => {}
                _ = watch.changed() => {
                    debug!("auto-update shutting down during sleep");
                    return;
                }
            }
        }
    }
}

impl AutoUpdateService {
    async fn check_and_apply(&self) {
        // Fetch latest version — runs the shared blocking client so we don't
        // stall the tokio executor. Delegates to version_check (#176).
        let latest =
            match tokio::task::spawn_blocking(crate::version_check::fetch_latest_version).await {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => {
                    warn!(error = %e, "auto-update: failed to check latest version");
                    return;
                }
                Err(e) => {
                    warn!(error = %e, "auto-update: spawn_blocking panicked");
                    return;
                }
            };

        let latest_version = latest.strip_prefix('v').unwrap_or(&latest);
        let current = env!("CARGO_PKG_VERSION");

        if latest_version == current {
            debug!(version = current, "auto-update: already on latest");
            return;
        }

        info!(
            current = current,
            latest = latest_version,
            "auto-update: new version available"
        );

        // Check maintenance window
        if let Some((start, end)) = self.config.window
            && !in_maintenance_window(start, end)
        {
            let (sh, sm) = (start / 60, start % 60);
            let (eh, em) = (end / 60, end % 60);
            info!(
                window = format_args!("{sh:02}:{sm:02}-{eh:02}:{em:02} UTC"),
                "auto-update: deferring until maintenance window"
            );
            return;
        }

        // Apply the update
        info!(
            target_version = latest_version,
            "auto-update: applying update"
        );
        match tokio::task::spawn_blocking(|| crate::self_update::run(true)).await {
            Ok(Ok(())) => {
                info!(
                    version = latest_version,
                    "auto-update: binary replaced successfully"
                );
            }
            Ok(Err(e)) => {
                error!(error = %e, "auto-update: failed to apply update");
                return;
            }
            Err(e) => {
                error!(error = %e, "auto-update: spawn_blocking panicked during update");
                return;
            }
        }

        // Post-update action
        match self.config.on_new_version {
            AutoUpdateAction::Reload => {
                info!("auto-update: triggering zero-downtime reload");
                if let Err(e) = trigger_reload() {
                    error!(error = %e, "auto-update: reload trigger failed — binary updated but server not restarted");
                }
            }
            AutoUpdateAction::Notify => {
                info!(
                    "auto-update: binary updated to {latest_version}. \
                     Restart the server to use the new version."
                );
            }
        }
    }
}

/// Check if current UTC time is within the maintenance window.
///
/// `start` and `end` are minutes from midnight UTC.
/// Handles windows that span midnight (e.g. 23:00-05:00).
fn in_maintenance_window(start: u16, end: u16) -> bool {
    let now = chrono::Utc::now();
    let now_minutes = (now.format("%H").to_string().parse::<u16>().unwrap_or(0)) * 60
        + now.format("%M").to_string().parse::<u16>().unwrap_or(0);

    if start <= end {
        // Normal window: e.g. 03:00-05:00
        now_minutes >= start && now_minutes < end
    } else {
        // Overnight window: e.g. 23:00-05:00
        now_minutes >= start || now_minutes < end
    }
}

/// Trigger a zero-downtime upgrade by execing `dwaar upgrade`.
fn trigger_reload() -> anyhow::Result<()> {
    let current_exe = std::env::current_exe()?;
    let status = Command::new(&current_exe).args(["upgrade"]).status()?;

    if !status.success() {
        anyhow::bail!("dwaar upgrade exited with status {status}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_day_window_always_matches() {
        // 00:00-24:00 — always in window regardless of current time
        assert!(in_maintenance_window(0, 1440));
    }

    #[test]
    fn zero_width_window_never_matches() {
        // start == end with normal range means no time is inside the window
        // (now_minutes >= 720 && now_minutes < 720) is always false
        assert!(!in_maintenance_window(720, 720));
    }

    #[test]
    fn overnight_window_compiles() {
        // 23:00-01:00 — just verify the logic handles the branches
        let _ = in_maintenance_window(1380, 60);
    }
}
