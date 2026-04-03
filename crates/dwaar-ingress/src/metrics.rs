// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Prometheus metrics registry for the ingress controller.
//!
//! All metrics are registered once at startup and shared via `Arc<IngressMetrics>`.
//! We use `prometheus-client` (the official Prometheus Rust client) rather than
//! the older `prometheus` crate because it is async-safe and avoids global state.

use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{Histogram, exponential_buckets};
use prometheus_client::registry::Registry;
use std::sync::Arc;
use std::sync::atomic::AtomicI64;

/// Label set for `dwaar_ingress_sync_total`.
#[derive(Clone, Debug, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
pub struct SyncResultLabel {
    /// "ok" or "error"
    pub result: String,
}

/// Label set for `dwaar_ingress_sync_errors_total`.
#[derive(Clone, Debug, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
pub struct SyncErrorLabel {
    /// Short reason string (e.g. "transport", "status", "deserialize")
    pub reason: String,
}

/// All Prometheus metrics for the ingress controller.
///
/// Intentionally kept flat — no sub-registries — to keep encoding fast.
#[allow(missing_debug_implementations)]
pub struct IngressMetrics {
    registry: Registry,

    /// Total sync attempts, partitioned by result ("ok" / "error").
    pub sync_total: Family<SyncResultLabel, Counter>,

    /// Total sync errors, partitioned by failure reason.
    pub sync_errors_total: Family<SyncErrorLabel, Counter>,

    /// Reconcile duration in seconds (histogram with exponential buckets).
    pub reconcile_duration_seconds: Histogram,

    /// 1 when this instance holds the leader lease, 0 otherwise.
    pub leader_is_leader: Gauge<i64, AtomicI64>,

    /// Number of Ingress objects currently in the reflected store.
    pub watched_ingresses: Gauge<i64, AtomicI64>,
}

impl IngressMetrics {
    /// Build and register all metrics. Returns the instance wrapped in `Arc`
    /// so it can be shared between the watcher task and the health server.
    pub fn new() -> Arc<Self> {
        let mut registry = Registry::default();

        let sync_total = Family::<SyncResultLabel, Counter>::default();
        registry.register(
            "dwaar_ingress_sync",
            "Total route sync attempts partitioned by result",
            sync_total.clone(),
        );

        let sync_errors_total = Family::<SyncErrorLabel, Counter>::default();
        registry.register(
            "dwaar_ingress_sync_errors",
            "Total sync errors partitioned by failure reason",
            sync_errors_total.clone(),
        );

        // Buckets cover the expected range: 1 ms → ~1 min (exponential, factor 2)
        let reconcile_duration_seconds = Histogram::new(exponential_buckets(0.001, 2.0, 16));
        registry.register(
            "dwaar_ingress_reconcile_duration_seconds",
            "Time spent reconciling a single Ingress resource",
            reconcile_duration_seconds.clone(),
        );

        let leader_is_leader = Gauge::<i64, AtomicI64>::default();
        registry.register(
            "dwaar_ingress_leader_is_leader",
            "1 when this pod holds the leader election lease, 0 otherwise",
            leader_is_leader.clone(),
        );

        let watched_ingresses = Gauge::<i64, AtomicI64>::default();
        registry.register(
            "dwaar_ingress_watched_ingresses",
            "Number of Ingress objects currently reflected in memory",
            watched_ingresses.clone(),
        );

        Arc::new(Self {
            registry,
            sync_total,
            sync_errors_total,
            reconcile_duration_seconds,
            leader_is_leader,
            watched_ingresses,
        })
    }

    /// Render the full registry in the Prometheus text exposition format.
    pub fn render(&self) -> String {
        let mut buf = String::new();
        encode(&mut buf, &self.registry).expect("prometheus encoding is infallible");
        buf
    }

    /// Record a successful sync.
    pub fn record_sync_ok(&self) {
        self.sync_total
            .get_or_create(&SyncResultLabel {
                result: "ok".to_string(),
            })
            .inc();
    }

    /// Record a failed sync with the given short reason string.
    pub fn record_sync_error(&self, reason: &str) {
        self.sync_total
            .get_or_create(&SyncResultLabel {
                result: "error".to_string(),
            })
            .inc();
        self.sync_errors_total
            .get_or_create(&SyncErrorLabel {
                reason: reason.to_string(),
            })
            .inc();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_render_contains_expected_names() {
        let m = IngressMetrics::new();
        // Add samples so every metric appears in the output. Gauges and
        // histograms render even without samples; counter Families only
        // appear when at least one label-set has been touched.
        m.record_sync_ok();
        m.record_sync_error("transport");
        m.reconcile_duration_seconds.observe(0.001);

        let output = m.render();

        // Counters: prometheus-client appends _total in the exposition format
        assert!(
            output.contains("dwaar_ingress_sync"),
            "expected dwaar_ingress_sync in: {output}"
        );
        assert!(
            output.contains("dwaar_ingress_sync_errors"),
            "expected dwaar_ingress_sync_errors in: {output}"
        );
        assert!(
            output.contains("dwaar_ingress_reconcile_duration_seconds"),
            "expected dwaar_ingress_reconcile_duration_seconds in: {output}"
        );
        assert!(
            output.contains("dwaar_ingress_leader_is_leader"),
            "expected dwaar_ingress_leader_is_leader in: {output}"
        );
        assert!(
            output.contains("dwaar_ingress_watched_ingresses"),
            "expected dwaar_ingress_watched_ingresses in: {output}"
        );
    }

    #[test]
    fn sync_ok_increments_counter() {
        let m = IngressMetrics::new();
        m.record_sync_ok();
        m.record_sync_ok();
        let output = m.render();
        // Counter value appears in the output
        assert!(output.contains("result=\"ok\""));
    }

    #[test]
    fn sync_error_increments_both_counters() {
        let m = IngressMetrics::new();
        m.record_sync_error("transport");
        let output = m.render();
        assert!(output.contains("result=\"error\""));
        assert!(output.contains("reason=\"transport\""));
    }
}
