// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Kubernetes informer loop for `Ingress`, `Service`, `Secret` and `IngressClass` resources.
//!
//! Uses `kube::runtime::reflector` to maintain warm in-memory caches of each
//! resource type and `kube::runtime::watcher` to stream change events. All
//! reflector stores are read-only from the reconciliation perspective; mutations
//! to the Dwaar route table happen only through the admin API client.
//!
//! ## kube 0.98 event model
//!
//! The watcher emits four event variants:
//! - `Init`       — start of a list/resync cycle (buffer start)
//! - `InitApply`  — one object from the initial list pass
//! - `InitDone`   — end of the initial list pass; objects not seen are gone
//! - `Apply`      — an object was added or modified
//! - `Delete`     — an object was deleted
//!
//! We treat `InitApply` the same as `Apply` (upsert semantics) and use `InitDone`
//! to mark the initial sync complete and flip the readiness flag.
//!
//! ## Concurrency model
//!
//! All resource type streams are combined with `tokio::select!`. The event loop is
//! single-threaded — reconciliation tasks are dispatched sequentially to avoid
//! conflicting upserts.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use futures::StreamExt;
use k8s_openapi::api::core::v1::{Secret, Service};
use k8s_openapi::api::networking::v1::{Ingress, IngressClass};
use kube::Client;
use kube::runtime::reflector::{self, Store, store};
use kube::runtime::watcher::{self, Event};
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use crate::client::AdminApiClient;
use crate::health::ReadinessState;
use crate::metrics::IngressMetrics;
use crate::translator;

/// Watches Kubernetes Ingress/Service/Secret/IngressClass resources and
/// reconciles changes into the Dwaar route table.
pub struct IngressWatcher {
    client: Client,
    namespace: Option<String>,
    ingress_class: Option<String>,
    api_client: AdminApiClient,
    readiness: ReadinessState,
    metrics: IngressMetrics,
}

impl std::fmt::Debug for IngressWatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `client`, `api_client`, `readiness`, and `metrics` don't expose useful
        // Debug information — omit them to keep the output readable.
        f.debug_struct("IngressWatcher")
            .field("namespace", &self.namespace)
            .field("ingress_class", &self.ingress_class)
            .finish_non_exhaustive()
    }
}

impl IngressWatcher {
    pub fn new(
        client: Client,
        namespace: Option<String>,
        ingress_class: Option<String>,
        api_client: AdminApiClient,
        readiness: ReadinessState,
        metrics: IngressMetrics,
    ) -> Self {
        Self {
            client,
            namespace,
            ingress_class,
            api_client,
            readiness,
            metrics,
        }
    }

    /// Run the informer loop until `shutdown` fires.
    ///
    /// Builds reflector stores for each resource type, then enters the main
    /// event dispatch loop. Returns when shutdown is signalled or an
    /// unrecoverable stream error occurs.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) -> Result<(), kube::Error> {
        let watcher_config = watcher::Config::default();

        // ── Reflector stores (warm in-memory caches) ──────────────────────────
        let (_ingress_store, ingress_writer): (Store<Ingress>, store::Writer<Ingress>) =
            reflector::store();
        let (service_store, service_writer): (Store<Service>, store::Writer<Service>) =
            reflector::store();
        let (_secret_store, secret_writer): (Store<Secret>, store::Writer<Secret>) =
            reflector::store();
        let (_ingressclass_store, ingressclass_writer): (
            Store<IngressClass>,
            store::Writer<IngressClass>,
        ) = reflector::store();

        // We keep service_store in an Arc so it can be shared into reconcile calls.
        let service_store = Arc::new(service_store);

        // Tracks which domains each Ingress (by `namespace/name`) currently owns.
        // This lets us clean up the correct routes on a Deleted event without
        // needing to re-parse the object that just disappeared.
        let mut ingress_domains: HashMap<String, Vec<String>> = HashMap::new();

        // ── Watcher streams ───────────────────────────────────────────────────
        let api_ingress: kube::Api<Ingress> = match &self.namespace {
            Some(ns) => kube::Api::namespaced(self.client.clone(), ns),
            None => kube::Api::all(self.client.clone()),
        };
        let api_service: kube::Api<Service> = match &self.namespace {
            Some(ns) => kube::Api::namespaced(self.client.clone(), ns),
            None => kube::Api::all(self.client.clone()),
        };
        let api_secret: kube::Api<Secret> = match &self.namespace {
            Some(ns) => kube::Api::namespaced(self.client.clone(), ns),
            None => kube::Api::all(self.client.clone()),
        };
        let api_ingressclass: kube::Api<IngressClass> = kube::Api::all(self.client.clone());

        // Reflector wraps the watcher stream and keeps the Store warm.
        let ingress_stream = reflector::reflector(
            ingress_writer,
            watcher::watcher(api_ingress, watcher_config.clone()),
        )
        .boxed();

        let service_stream = reflector::reflector(
            service_writer,
            watcher::watcher(api_service, watcher_config.clone()),
        )
        .boxed();

        let secret_stream = reflector::reflector(
            secret_writer,
            watcher::watcher(api_secret, watcher_config.clone()),
        )
        .boxed();

        let _ingressclass_stream = reflector::reflector(
            ingressclass_writer,
            watcher::watcher(api_ingressclass, watcher_config),
        );

        tokio::pin!(ingress_stream);
        tokio::pin!(service_stream);
        tokio::pin!(secret_stream);

        info!("IngressWatcher started");

        loop {
            tokio::select! {
                biased;

                // Shutdown takes highest priority
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("IngressWatcher shutting down");
                        return Ok(());
                    }
                }

                // Ingress events drive route reconciliation
                Some(ingress_event) = ingress_stream.next() => {
                    match ingress_event {
                        Ok(event) => {
                            self.handle_ingress_event(
                                event,
                                &service_store,
                                &mut ingress_domains,
                            ).await;
                        }
                        Err(e) => {
                            warn!(error = %e, "Ingress watcher stream error — continuing");
                        }
                    }
                }

                // Service events refresh the store (no explicit action needed —
                // the reflector keeps the Store warm automatically).
                Some(svc_event) = service_stream.next() => {
                    match svc_event {
                        Ok(_) => {
                            debug!("Service store updated");
                        }
                        Err(e) => {
                            warn!(error = %e, "Service watcher stream error — continuing");
                        }
                    }
                }

                // Secret events are tracked for future TLS cert management.
                Some(secret_event) = secret_stream.next() => {
                    match secret_event {
                        Ok(_) => {
                            debug!("Secret store updated");
                        }
                        Err(e) => {
                            warn!(error = %e, "Secret watcher stream error — continuing");
                        }
                    }
                }
            }
        }
    }

    /// Dispatch an `Event<Ingress>` to the appropriate handler.
    ///
    /// kube 0.98 event variants:
    /// - `Apply`     → object added or modified (steady state)
    /// - `Delete`    → object removed
    /// - `InitApply` → object seen during initial list/resync pass (treat as Apply)
    /// - `Init`      → initial list pass beginning (no action needed)
    /// - `InitDone`  → initial list pass complete; set readiness flag
    async fn handle_ingress_event(
        &self,
        event: Event<Ingress>,
        service_store: &Store<Service>,
        ingress_domains: &mut HashMap<String, Vec<String>>,
    ) {
        match event {
            Event::Apply(ingress) | Event::InitApply(ingress) => {
                self.handle_applied(&ingress, service_store, ingress_domains)
                    .await;
            }
            Event::Delete(ingress) => {
                self.handle_deleted(&ingress, service_store, ingress_domains)
                    .await;
            }
            Event::InitDone => {
                // The reflector has finished its initial list pass — all known
                // objects have been processed. It is now safe to mark sync complete.
                self.readiness.sync_ready.store(true, Ordering::Release);
                info!("Initial sync complete — readiness flag set");
            }
            Event::Init => {
                // A new list/resync cycle is starting. Clear tracked state so
                // that domains not seen in the resync are cleaned up.
                debug!("Ingress store resync starting — clearing tracked state");
                ingress_domains.clear();
            }
        }
    }

    /// Handle an `Apply` or `InitApply` Ingress event.
    async fn handle_applied(
        &self,
        ingress: &Ingress,
        service_store: &Store<Service>,
        ingress_domains: &mut HashMap<String, Vec<String>>,
    ) {
        // Skip Ingresses targeting a different IngressClass.
        if !self.ingress_class_matches(ingress) {
            return;
        }

        let key = translator::ingress_key(ingress);
        let synced = translator::reconcile_applied(ingress, service_store, &self.api_client).await;

        for _ in &synced {
            self.metrics.inc_routes_upserted();
        }

        if synced.is_empty() {
            warn!(ingress = %key, "no routes resolved for Ingress — may have missing Services");
            self.metrics.inc_service_lookup_misses();
        } else {
            debug!(ingress = %key, domains = ?synced, "Ingress routes upserted");
        }

        ingress_domains.insert(key, synced);
    }

    /// Handle a `Delete` Ingress event.
    async fn handle_deleted(
        &self,
        ingress: &Ingress,
        service_store: &Store<Service>,
        ingress_domains: &mut HashMap<String, Vec<String>>,
    ) {
        if !self.ingress_class_matches(ingress) {
            return;
        }

        let key = translator::ingress_key(ingress);

        // Prefer tracked domains (fast path) over re-parsing the object.
        let domains = ingress_domains.remove(&key).unwrap_or_else(|| {
            warn!(
                ingress = %key,
                "Ingress deleted but no tracked domains found — falling back to spec parse"
            );
            translator::domains_from_ingress(ingress, service_store)
        });

        if domains.is_empty() {
            debug!(ingress = %key, "deleted Ingress owned no routes");
            return;
        }

        let errors = translator::reconcile_deleted(&domains, &self.api_client).await;
        let deleted = domains.len() - errors.len();
        for _ in 0..deleted {
            self.metrics.inc_routes_deleted();
        }
        for e in &errors {
            error!(ingress = %key, error = %e, "failed to delete route");
        }
    }

    /// Return `true` if this Ingress should be processed by this controller.
    ///
    /// When `ingress_class` is `None`, we process all Ingresses (useful in
    /// single-controller setups). When set, we match against the
    /// `kubernetes.io/ingress.class` annotation or `spec.ingressClassName`.
    fn ingress_class_matches(&self, ingress: &Ingress) -> bool {
        let Some(ref class_name) = self.ingress_class else {
            return true; // no filter configured — process everything
        };

        // Check annotation first (older convention)
        let annotation = ingress
            .metadata
            .annotations
            .as_ref()
            .and_then(|a| a.get("kubernetes.io/ingress.class"))
            .map(String::as_str);

        if let Some(ann) = annotation {
            return ann == class_name;
        }

        // Fall back to spec.ingressClassName (newer convention, v1.18+)
        let spec_class = ingress
            .spec
            .as_ref()
            .and_then(|s| s.ingress_class_name.as_deref());

        spec_class == Some(class_name.as_str())
    }
}
