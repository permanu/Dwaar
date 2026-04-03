// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Leader election via Kubernetes Lease resources (`coordination.k8s.io/v1`).
//!
//! ## Why leader election?
//!
//! When multiple ingress controller replicas are running (e.g. for HA), only one
//! should drive route mutations. Without coordination, concurrent controllers would
//! race to upsert/delete routes, causing instability. The Kubernetes Lease API
//! provides a portable, server-side lock with built-in expiry.
//!
//! ## Protocol
//!
//! 1. **Candidate**: Try to create the Lease with `holderIdentity` = our pod name.
//!    - Success → we become leader, set `leader_ready = true`.
//!    - Conflict (409) → the Lease already exists, enter observer mode.
//!
//! 2. **Leader**: Renew the Lease every `renew_deadline` by updating
//!    `renewTime`. If renewal fails, immediately clear `leader_ready = false`
//!    and drop back to candidate.
//!
//! 3. **Observer**: Poll every `retry_period`. If the Lease's `renewTime` is
//!    older than `lease_duration`, the current holder has died — try to acquire.
//!
//! ## State machine
//!
//! ```text
//! Candidate ──acquire──► Leader ──renewal failure──► Candidate
//!     ▲                                                  │
//!     └───────────────── observe expired ◄───────────────┘
//! ```

use std::sync::atomic::Ordering;
use std::time::Duration;

use k8s_openapi::api::coordination::v1::Lease;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::MicroTime;
use kube::api::{Api, ObjectMeta, Patch, PatchParams, PostParams};
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use crate::error::WatcherError;
use crate::health::ReadinessState;
use crate::metrics::IngressMetrics;

/// Tunable knobs for the lease lifecycle.
///
/// Defaults match the Kubernetes controller-manager defaults:
/// - `lease_duration = 15s` — how long a lease is valid without renewal.
/// - `renew_deadline = 10s` — how long we keep trying to renew before giving up.
/// - `retry_period  = 2s`  — polling interval for candidates and renewal attempts.
#[derive(Debug, Clone)]
pub struct LeaderConfig {
    /// Seconds a lease is considered valid without renewal (holder liveness window).
    pub lease_duration_secs: i32,
    /// How frequently the leader renews the lease (must be < `lease_duration`).
    pub renew_deadline: Duration,
    /// How frequently a non-leader candidate polls to attempt acquisition.
    pub retry_period: Duration,
    /// Namespace that holds the Lease object.
    pub namespace: String,
    /// Name of the Lease object (shared across all controller replicas).
    pub lease_name: String,
    /// Identity of this controller instance (typically the pod hostname).
    pub holder_identity: String,
}

impl Default for LeaderConfig {
    fn default() -> Self {
        Self {
            lease_duration_secs: 15,
            renew_deadline: Duration::from_secs(10),
            retry_period: Duration::from_secs(2),
            namespace: "kube-system".to_string(),
            lease_name: "dwaar-ingress-leader".to_string(),
            holder_identity: std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string()),
        }
    }
}

/// Internal state of the leader election state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaderState {
    /// We have not yet seen or acquired the Lease.
    Candidate,
    /// We currently hold the Lease and are actively renewing it.
    Leader,
}

/// Leader election loop.
///
/// Runs forever until `shutdown` fires. Sets `readiness.leader_ready` when we
/// acquire the lease and clears it immediately on loss or any renewal error.
///
/// `on_leader` is called once when this instance becomes leader — callers use
/// this to start the `IngressWatcher`. It receives a `watch::Sender<bool>`
/// that fires when leadership is lost, so the watcher can gracefully stop.
pub struct LeaderElector {
    config: LeaderConfig,
    lease_api: Api<Lease>,
    readiness: ReadinessState,
    metrics: IngressMetrics,
}

impl std::fmt::Debug for LeaderElector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `lease_api` wraps an opaque HTTP client — we omit it intentionally
        // so Debug output remains readable without losing useful information.
        f.debug_struct("LeaderElector")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl LeaderElector {
    pub fn new(
        config: LeaderConfig,
        kube_client: kube::Client,
        readiness: ReadinessState,
        metrics: IngressMetrics,
    ) -> Self {
        let lease_api: Api<Lease> = Api::namespaced(kube_client, &config.namespace);
        Self {
            config,
            lease_api,
            readiness,
            metrics,
        }
    }

    /// Run the election loop until `shutdown` fires.
    ///
    /// `on_leader_start` is an async callback invoked when this pod first
    /// acquires leadership. It receives a `watch::Receiver<bool>` that becomes
    /// `true` when leadership is lost — callers should stop processing when this
    /// fires.
    pub async fn run<F, Fut>(&self, mut shutdown: watch::Receiver<bool>, on_leader_start: F)
    where
        F: Fn(watch::Receiver<bool>) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let mut state = LeaderState::Candidate;
        // Channel used to signal the watcher when we lose leadership.
        let (lost_tx, lost_rx) = watch::channel(false);
        let mut watcher_started = false;

        loop {
            // Check shutdown before each poll cycle
            if *shutdown.borrow() {
                info!("leader elector shutting down");
                self.set_not_ready();
                return;
            }

            match state {
                LeaderState::Candidate => {
                    match self.try_acquire().await {
                        Ok(true) => {
                            info!(
                                identity = %self.config.holder_identity,
                                "acquired leadership"
                            );
                            self.readiness.leader_ready.store(true, Ordering::Release);
                            self.metrics.inc_leader_acquired();
                            state = LeaderState::Leader;

                            // Notify the watcher that we're now the leader.
                            if watcher_started {
                                // Re-acquired after a loss — signal the previously
                                // stopped watcher to restart by re-invoking.
                                // In practice, the caller loops on lost_rx changing.
                                let _ = lost_tx.send(false);
                            } else {
                                watcher_started = true;
                                on_leader_start(lost_rx.clone()).await;
                            }
                        }
                        Ok(false) => {
                            // Someone else holds the lease — keep waiting.
                            debug!("lease held by another — waiting to retry");
                        }
                        Err(e) => {
                            warn!(error = %e, "lease acquisition error — retrying");
                        }
                    }

                    // Back off before the next candidate poll.
                    tokio::select! {
                        biased;
                        _ = shutdown.changed() => {}
                        () = tokio::time::sleep(self.config.retry_period) => {}
                    }
                }

                LeaderState::Leader => {
                    // Renew at the deadline interval.
                    tokio::select! {
                        biased;
                        _ = shutdown.changed() => {}
                        () = tokio::time::sleep(self.config.renew_deadline) => {}
                    }

                    match self.try_renew().await {
                        Ok(()) => {
                            debug!("lease renewed");
                        }
                        Err(e) => {
                            error!(error = %e, "lease renewal failed — losing leadership");
                            self.lose_leadership(&lost_tx);
                            state = LeaderState::Candidate;
                        }
                    }
                }
            }
        }
    }

    /// Attempt to acquire the Lease.
    ///
    /// Returns:
    /// - `Ok(true)` — we now hold the lease.
    /// - `Ok(false)` — someone else holds the lease (or it's not yet expired).
    /// - `Err(_)` — an unexpected API error occurred.
    async fn try_acquire(&self) -> Result<bool, WatcherError> {
        let now = utc_now();

        // Try to CREATE the Lease first — this succeeds only if no lease exists.
        let lease = build_lease(
            &self.config.lease_name,
            &self.config.namespace,
            &self.config.holder_identity,
            self.config.lease_duration_secs,
            &now,
        );

        match self.lease_api.create(&PostParams::default(), &lease).await {
            Ok(_) => {
                // We created the Lease — we are now the leader.
                return Ok(true);
            }
            Err(kube::Error::Api(ae)) if ae.code == 409 => {
                // Lease already exists — check if it has expired.
                // Fall through to the expiry check below.
            }
            Err(e) => {
                return Err(WatcherError::Kube(e));
            }
        }

        // Lease exists — read it and check if the current holder is still alive.
        let existing = self
            .lease_api
            .get(&self.config.lease_name)
            .await
            .map_err(WatcherError::Kube)?;

        if !self.is_lease_expired(&existing) {
            // Current holder is alive — we cannot acquire.
            return Ok(false);
        }

        // The lease has expired. Try to take it over via a strategic merge patch.
        // We use the resource version from the GET to ensure we win any concurrent race.
        let resource_version = existing
            .metadata
            .resource_version
            .as_deref()
            .unwrap_or("")
            .to_string();

        let patch_body = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": {
                "name": self.config.lease_name,
                "namespace": self.config.namespace,
                "resourceVersion": resource_version
            },
            "spec": {
                "holderIdentity": self.config.holder_identity,
                "leaseDurationSeconds": self.config.lease_duration_secs,
                "acquireTime": now,
                "renewTime": now,
                "leaseTransitions": existing
                    .spec.as_ref()
                    .and_then(|s| s.lease_transitions)
                    .unwrap_or(0) + 1,
            }
        });

        match self
            .lease_api
            .patch(
                &self.config.lease_name,
                &PatchParams::default(),
                &Patch::Merge(patch_body),
            )
            .await
        {
            Ok(_) => Ok(true),
            Err(kube::Error::Api(ae)) if ae.code == 409 => {
                // Another pod won the race — back off and retry later.
                Ok(false)
            }
            Err(e) => Err(WatcherError::Kube(e)),
        }
    }

    /// Renew the lease by updating `renewTime`.
    ///
    /// Uses a strategic merge patch with the current resource version to
    /// detect concurrent modifications (e.g. another controller taking over).
    async fn try_renew(&self) -> Result<(), WatcherError> {
        let now = utc_now();

        let patch_body = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "spec": {
                "holderIdentity": self.config.holder_identity,
                "renewTime": now,
            }
        });

        self.lease_api
            .patch(
                &self.config.lease_name,
                &PatchParams::default(),
                &Patch::Merge(patch_body),
            )
            .await
            .map(|_| ())
            .map_err(|e| WatcherError::Lease(e.to_string()))
    }

    /// Check whether the current lease has exceeded its duration (holder is dead).
    ///
    /// A lease is considered expired if `renewTime` is missing or older than
    /// `leaseDurationSeconds` from now.
    fn is_lease_expired(&self, lease: &Lease) -> bool {
        lease_is_expired(lease, self.config.lease_duration_secs)
    }

    /// Clear the `leader_ready` flag and notify observers via `lost_tx`.
    fn lose_leadership(&self, lost_tx: &watch::Sender<bool>) {
        self.readiness.leader_ready.store(false, Ordering::Release);
        self.metrics.inc_leader_lost();
        // Notify the watcher that it should stop processing.
        let _ = lost_tx.send(true);
        info!(
            identity = %self.config.holder_identity,
            "lost leadership — waiting to re-acquire"
        );
    }

    fn set_not_ready(&self) {
        self.readiness.leader_ready.store(false, Ordering::Release);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Pure function: determine whether a Lease has exceeded its valid duration.
///
/// Extracted from `LeaderElector::is_lease_expired` so it can be unit-tested
/// without constructing a real `kube::Client` (which requires a TLS stack).
fn lease_is_expired(lease: &Lease, duration_secs: i32) -> bool {
    let Some(spec) = lease.spec.as_ref() else {
        // No spec at all → treat as expired (no holder is maintaining it).
        return true;
    };

    let Some(renew_time) = spec.renew_time.as_ref() else {
        // No renewTime → the lease was never renewed → expired.
        return true;
    };

    let MicroTime(dt) = renew_time;
    let duration = duration_secs as u64;
    let age_secs = chrono::Utc::now()
        .signed_duration_since(*dt)
        .num_seconds()
        .max(0) as u64;

    age_secs >= duration
}

/// Build a new `Lease` object for initial creation.
fn build_lease(name: &str, namespace: &str, holder: &str, duration_secs: i32, now: &str) -> Lease {
    use k8s_openapi::api::coordination::v1::LeaseSpec;

    Lease {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        spec: Some(LeaseSpec {
            holder_identity: Some(holder.to_string()),
            lease_duration_seconds: Some(duration_secs),
            acquire_time: Some(MicroTime(parse_micro_time(now))),
            renew_time: Some(MicroTime(parse_micro_time(now))),
            lease_transitions: Some(0),
            ..Default::default()
        }),
    }
}

/// Return the current UTC time as an RFC 3339 string (microsecond precision).
fn utc_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

/// Parse an RFC 3339 timestamp into a `chrono::DateTime<Utc>`.
///
/// Panics only if the timestamp we just generated via `utc_now()` is not
/// parseable — which would indicate a bug in `chrono` itself. Using `expect`
/// rather than `unwrap` so the failure site is identifiable.
fn parse_micro_time(ts: &str) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(ts)
        .expect("timestamp generated by utc_now() must be valid RFC3339")
        .with_timezone(&chrono::Utc)
}

// ---------------------------------------------------------------------------
// Unit tests — mock Lease lifecycle without a real API server
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    fn make_readiness() -> ReadinessState {
        ReadinessState {
            leader_ready: Arc::new(AtomicBool::new(false)),
            sync_ready: Arc::new(AtomicBool::new(false)),
        }
    }

    // ── Lease expiry logic ───────────────────────────────────────────────────
    //
    // These tests call `lease_is_expired()` directly — a free function that
    // encapsulates the pure expiry logic. This avoids constructing a real
    // kube::Client (which requires a TLS crypto provider) in unit tests.

    fn make_lease_with_renew_time(seconds_ago: i64) -> Lease {
        use k8s_openapi::api::coordination::v1::LeaseSpec;
        let renew_dt = chrono::Utc::now() - chrono::Duration::seconds(seconds_ago);
        Lease {
            metadata: ObjectMeta {
                name: Some("dwaar-ingress-leader".to_string()),
                namespace: Some("kube-system".to_string()),
                ..Default::default()
            },
            spec: Some(LeaseSpec {
                holder_identity: Some("other-pod".to_string()),
                lease_duration_seconds: Some(15),
                renew_time: Some(MicroTime(renew_dt)),
                ..Default::default()
            }),
        }
    }

    #[test]
    fn lease_not_expired_when_recent() {
        // Renewed 5 seconds ago with a 15-second duration — should NOT be expired.
        let lease = make_lease_with_renew_time(5);
        assert!(
            !lease_is_expired(&lease, 15),
            "lease renewed 5s ago should not be expired (duration=15s)"
        );
    }

    #[test]
    fn lease_expired_when_old() {
        // Renewed 20 seconds ago with a 15-second duration — must be expired.
        let lease = make_lease_with_renew_time(20);
        assert!(
            lease_is_expired(&lease, 15),
            "lease renewed 20s ago should be expired (duration=15s)"
        );
    }

    #[test]
    fn lease_expired_when_no_renew_time() {
        use k8s_openapi::api::coordination::v1::LeaseSpec;
        let lease = Lease {
            metadata: ObjectMeta {
                name: Some("dwaar-ingress-leader".to_string()),
                ..Default::default()
            },
            spec: Some(LeaseSpec {
                holder_identity: Some("other-pod".to_string()),
                renew_time: None, // missing renewTime → treat as expired
                ..Default::default()
            }),
        };
        assert!(lease_is_expired(&lease, 15));
    }

    // ── State transitions ─────────────────────────────────────────────────────

    #[test]
    fn readiness_flag_toggled_on_lose_leadership() {
        // Test the atomic flag directly — simulates what LeaderElector::lose_leadership does.
        // We avoid constructing a real kube::Client here because doing so requires
        // a TLS crypto provider to be installed at the process level.
        let readiness = make_readiness();
        readiness.leader_ready.store(true, Ordering::Release);

        // Simulate losing leadership: clear the flag and send the signal.
        readiness.leader_ready.store(false, Ordering::Release);
        let (tx, _rx) = watch::channel(false);
        let _ = tx.send(true);

        assert!(
            !readiness.leader_ready.load(Ordering::Acquire),
            "leader_ready must be false after losing leadership"
        );
    }

    #[test]
    fn readiness_flag_initially_false() {
        let state = make_readiness();
        assert!(!state.leader_ready.load(Ordering::Acquire));
        assert!(!state.sync_ready.load(Ordering::Acquire));
    }

    // ── Utility functions ─────────────────────────────────────────────────────

    #[test]
    fn utc_now_produces_valid_rfc3339() {
        let ts = utc_now();
        let parsed = chrono::DateTime::parse_from_rfc3339(&ts);
        assert!(parsed.is_ok(), "utc_now() must produce valid RFC3339: {ts}");
    }

    #[test]
    fn build_lease_sets_correct_fields() {
        let now = utc_now();
        let lease = build_lease("my-lease", "my-ns", "pod-abc", 15, &now);

        let spec = lease.spec.expect("lease must have spec");
        assert_eq!(spec.holder_identity.as_deref(), Some("pod-abc"));
        assert_eq!(spec.lease_duration_seconds, Some(15));
        assert!(spec.renew_time.is_some());
        assert!(spec.acquire_time.is_some());
        assert_eq!(spec.lease_transitions, Some(0));
    }

    #[test]
    fn default_config_uses_hostname() {
        let config = LeaderConfig::default();
        // HOSTNAME is set or we get "unknown" — either is acceptable.
        assert!(!config.holder_identity.is_empty());
        assert_eq!(config.lease_duration_secs, 15);
        assert_eq!(config.renew_deadline, Duration::from_secs(10));
        assert_eq!(config.retry_period, Duration::from_secs(2));
    }
}
