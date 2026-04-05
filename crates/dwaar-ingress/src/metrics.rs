// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Prometheus metrics for the ingress controller.
//!
//! Deliberately minimal — tracks the counters that matter for SLO alerting
//! without pulling in a heavy metrics framework. Exposed on `/metrics` by
//! the health server (future extension point).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Counters accumulated by the reconciliation loop.
#[derive(Debug, Default, Clone)]
pub struct IngressMetrics {
    inner: Arc<Counters>,
}

#[derive(Debug, Default)]
struct Counters {
    /// Number of times `upsert_route` succeeded.
    pub routes_upserted: AtomicU64,
    /// Number of times `delete_route` succeeded.
    pub routes_deleted: AtomicU64,
    /// Number of times a reconcile event was skipped due to a missing Service.
    pub service_lookup_misses: AtomicU64,
    /// Number of times the leader lease was acquired.
    pub leader_acquired: AtomicU64,
    /// Number of times the leader lease was lost or failed to renew.
    pub leader_lost: AtomicU64,
}

impl IngressMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inc_routes_upserted(&self) {
        self.inner.routes_upserted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_routes_deleted(&self) {
        self.inner.routes_deleted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_service_lookup_misses(&self) {
        self.inner
            .service_lookup_misses
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_leader_acquired(&self) {
        self.inner.leader_acquired.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_leader_lost(&self) {
        self.inner.leader_lost.fetch_add(1, Ordering::Relaxed);
    }

    /// Render the counters in Prometheus text exposition format.
    pub fn render(&self) -> String {
        let c = &self.inner;
        format!(
            "# HELP dwaar_ingress_routes_upserted_total Routes added or updated\n\
             # TYPE dwaar_ingress_routes_upserted_total counter\n\
             dwaar_ingress_routes_upserted_total {}\n\
             # HELP dwaar_ingress_routes_deleted_total Routes deleted\n\
             # TYPE dwaar_ingress_routes_deleted_total counter\n\
             dwaar_ingress_routes_deleted_total {}\n\
             # HELP dwaar_ingress_service_lookup_misses_total Service not found in cache\n\
             # TYPE dwaar_ingress_service_lookup_misses_total counter\n\
             dwaar_ingress_service_lookup_misses_total {}\n\
             # HELP dwaar_ingress_leader_acquired_total Leader lease acquisitions\n\
             # TYPE dwaar_ingress_leader_acquired_total counter\n\
             dwaar_ingress_leader_acquired_total {}\n\
             # HELP dwaar_ingress_leader_lost_total Leader lease losses\n\
             # TYPE dwaar_ingress_leader_lost_total counter\n\
             dwaar_ingress_leader_lost_total {}\n",
            c.routes_upserted.load(Ordering::Relaxed),
            c.routes_deleted.load(Ordering::Relaxed),
            c.service_lookup_misses.load(Ordering::Relaxed),
            c.leader_acquired.load(Ordering::Relaxed),
            c.leader_lost.load(Ordering::Relaxed),
        )
    }
}
