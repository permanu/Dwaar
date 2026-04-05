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
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use futures::StreamExt;
use k8s_openapi::api::core::v1::{Secret, Service};
use k8s_openapi::api::networking::v1::{Ingress, IngressClass};
use kube::Client;
use kube::runtime::reflector::{self, Store};
use kube::runtime::watcher::{self, Event};
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use crate::reconciler::{ReconcilerConfig, run_reconciler, DesiredRoute};

use crate::client::AdminApiClient;
use crate::health::ReadinessState;
use crate::metrics::IngressMetrics;
use crate::tls;
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
    /// Directory where TLS PEM files are written.
    cert_dir: PathBuf,
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
        cert_dir: PathBuf,
    ) -> Self {
        Self {
            client,
            namespace,
            ingress_class,
            api_client,
            readiness,
            metrics,
            cert_dir,
        }
    }

}

/// Mutable tracking state passed to `handle_ingress_event` to avoid
/// a long parameter list (clippy: `too_many_arguments`).
struct ReconcileState {
    ingress_domains: HashMap<String, Vec<String>>,
    ingress_tls_bases: HashMap<String, Vec<String>>,
    ingress_specs: HashMap<String, Ingress>,
    prev_ingress_domains: Option<HashMap<String, Vec<String>>>,
    prev_ingress_tls_bases: Option<HashMap<String, Vec<String>>>,
    /// Reverse index: `"namespace/service_name" → [ingress_key]`.
    /// Narrows Service-change re-reconciliation to affected Ingresses only,
    /// avoiding O(events × ingresses) churn in large clusters.
    service_to_ingresses: HashMap<String, Vec<String>>,
    /// Reverse index: `"namespace/secret_name" → [ingress_key]`.
    secret_to_ingresses: HashMap<String, Vec<String>>,
}

impl IngressWatcher {
    /// Run the informer loop until `shutdown` fires.
    ///
    /// Builds reflector stores for each resource type, then enters the main
    /// event dispatch loop. Returns when shutdown is signalled or an
    /// unrecoverable stream error occurs.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) -> Result<(), kube::Error> {
        let (service_store, secret_store, mut ingress_stream, mut service_stream,
             mut secret_stream, mut ingressclass_stream) = self.build_streams();

        let mut rs = ReconcileState {
            ingress_domains: HashMap::new(),
            ingress_tls_bases: HashMap::new(),
            ingress_specs: HashMap::new(),
            prev_ingress_domains: None,
            prev_ingress_tls_bases: None,
            service_to_ingresses: HashMap::new(),
            secret_to_ingresses: HashMap::new(),
        };

        // The periodic reconciler needs a snapshot of desired routes on each
        // tick. We share a channel so the watcher loop can push a fresh snapshot
        // whenever state changes without coupling the reconciler into this loop.
        let (desired_tx, desired_rx) =
            tokio::sync::watch::channel::<Vec<DesiredRoute>>(Vec::new());

        // The reconciler must stop when this method returns — whether from an
        // explicit shutdown signal or from being dropped on lease loss. We create
        // a dedicated channel whose sender lives in `run()` scope; when the
        // sender is dropped the reconciler sees a closed channel and exits.
        let (_reconciler_stop_tx, reconciler_stop_rx) = watch::channel(false);

        let reconciler_client = self.api_client.clone();
        tokio::spawn(async move {
            run_reconciler(
                reconciler_client,
                ReconcilerConfig::default(),
                reconciler_stop_rx,
                move || desired_rx.borrow().clone(),
            )
            .await;
        });

        // `reconciler_stop_tx` stays alive in this scope. When `run()` returns
        // (shutdown or lease loss), it drops and the reconciler exits.

        info!("IngressWatcher started");

        loop {
            tokio::select! {
                biased;

                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("IngressWatcher shutting down");
                        return Ok(());
                    }
                }

                Some(ingress_event) = ingress_stream.next() => {
                    match ingress_event {
                        Ok(event) => {
                            self.handle_ingress_event(
                                event,
                                &service_store,
                                &secret_store,
                                &mut rs,
                            ).await;
                            push_desired_snapshot(&rs.ingress_domains, &rs.ingress_specs, &service_store, &desired_tx);
                        }
                        Err(e) => {
                            warn!(error = %e, "Ingress watcher stream error — continuing");
                        }
                    }
                }

                // Service and Secret reflector stores are kept warm automatically.
                // When a Service changes we re-reconcile every Ingress that may
                // reference it so stale ClusterIPs don't linger in the route table.
                Some(svc_event) = service_stream.next() => {
                    match svc_event {
                        Err(e) => {
                            warn!(error = %e, "Service watcher stream error — continuing");
                        }
                        Ok(event) => {
                            let svc_name = service_name_from_event(&event);
                            let svc_key = service_key_from_event(&event);
                            let affected = rs.service_to_ingresses
                                .get(&svc_key)
                                .cloned()
                                .unwrap_or_default();
                            if affected.is_empty() {
                                debug!(service = %svc_name, "Service store updated — no Ingresses reference it");
                            } else {
                                debug!(service = %svc_name, count = affected.len(), "Service store updated — re-evaluating affected Ingresses");
                                self.rereconcile_ingresses(
                                    &affected,
                                    &service_store,
                                    &secret_store,
                                    &mut rs.ingress_domains,
                                    &mut rs.ingress_tls_bases,
                                    &rs.ingress_specs,
                                ).await;
                                push_desired_snapshot(&rs.ingress_domains, &rs.ingress_specs, &service_store, &desired_tx);
                            }
                        }
                    }
                }

                Some(secret_event) = secret_stream.next() => {
                    match secret_event {
                        Err(e) => {
                            warn!(error = %e, "Secret watcher stream error — continuing");
                        }
                        Ok(event) => {
                            let secret_name = secret_name_from_event(&event);
                            let secret_key = secret_key_from_event(&event);
                            let affected = rs.secret_to_ingresses
                                .get(&secret_key)
                                .cloned()
                                .unwrap_or_default();
                            if affected.is_empty() {
                                debug!(secret = %secret_name, "Secret store updated — no Ingresses reference it");
                            } else {
                                debug!(secret = %secret_name, count = affected.len(), "Secret store updated — re-evaluating affected Ingresses");
                                self.rereconcile_ingresses(
                                    &affected,
                                    &service_store,
                                    &secret_store,
                                    &mut rs.ingress_domains,
                                    &mut rs.ingress_tls_bases,
                                    &rs.ingress_specs,
                                ).await;
                                push_desired_snapshot(&rs.ingress_domains, &rs.ingress_specs, &service_store, &desired_tx);
                            }
                        }
                    }
                }

                Some(ic_event) = ingressclass_stream.next() => {
                    if let Err(e) = ic_event {
                        warn!(error = %e, "IngressClass watcher stream error — continuing");
                    } else {
                        debug!("IngressClass store updated");
                    }
                }
            }
        }
    }

    /// Build the four reflector stores and their corresponding watcher streams.
    ///
    /// Extracted from `run()` to keep it under the line-count limit while
    /// preserving readability. Returns the Arc-wrapped read stores and four
    /// pinned `BoxStream`s ready for the `select!` loop.
    #[allow(clippy::type_complexity)]
    fn build_streams(
        &self,
    ) -> (
        Arc<Store<Service>>,
        Arc<Store<Secret>>,
        std::pin::Pin<Box<dyn futures::Stream<Item = Result<Event<Ingress>, watcher::Error>> + Send>>,
        std::pin::Pin<Box<dyn futures::Stream<Item = Result<Event<Service>, watcher::Error>> + Send>>,
        std::pin::Pin<Box<dyn futures::Stream<Item = Result<Event<Secret>, watcher::Error>> + Send>>,
        std::pin::Pin<Box<dyn futures::Stream<Item = Result<Event<IngressClass>, watcher::Error>> + Send>>,
    ) {
        let cfg = watcher::Config::default();

        let (_ingress_store, ingress_writer) = reflector::store::<Ingress>();
        let (service_store, service_writer) = reflector::store::<Service>();
        let (secret_store, secret_writer) = reflector::store::<Secret>();
        let (_ic_store, ic_writer) = reflector::store::<IngressClass>();

        let service_store = Arc::new(service_store);
        let secret_store = Arc::new(secret_store);

        // Build a namespace-scoped or cluster-wide API for each resource type.
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

        let ingress_stream = reflector::reflector(
            ingress_writer,
            watcher::watcher(api_ingress, cfg.clone()),
        )
        .boxed();

        let service_stream = reflector::reflector(
            service_writer,
            watcher::watcher(api_service, cfg.clone()),
        )
        .boxed();

        let secret_stream = reflector::reflector(
            secret_writer,
            watcher::watcher(api_secret, cfg.clone()),
        )
        .boxed();

        let ic_stream = reflector::reflector(
            ic_writer,
            watcher::watcher(kube::Api::all(self.client.clone()), cfg),
        )
        .boxed();

        (service_store, secret_store, ingress_stream, service_stream, secret_stream, ic_stream)
    }

    /// Dispatch an `Event<Ingress>` to the appropriate handler.
    ///
    /// kube 0.98 event variants:
    /// - `Apply`     → object added or modified (steady state)
    /// - `Delete`    → object removed
    /// - `InitApply` → object seen during initial list/resync pass (treat as Apply)
    /// - `Init`      → initial list pass beginning; clean up previous state first
    /// - `InitDone`  → initial list pass complete; set readiness flag
    async fn handle_ingress_event(
        &self,
        event: Event<Ingress>,
        service_store: &Store<Service>,
        secret_store: &Store<Secret>,
        state: &mut ReconcileState,
    ) {
        match event {
            Event::Apply(ingress) | Event::InitApply(ingress) => {
                let key = translator::ingress_key(&ingress);
                if self.ingress_class_matches(&ingress) {
                    self.handle_applied(
                        &ingress, service_store, secret_store,
                        &mut state.ingress_domains, &mut state.ingress_tls_bases,
                    ).await;
                    // Update reverse indexes for targeted re-reconciliation.
                    update_reverse_indexes(&ingress, &key, &mut state.service_to_ingresses, &mut state.secret_to_ingresses);
                    state.ingress_specs.insert(key, ingress);
                } else if state.ingress_specs.remove(&key).is_some() {
                    remove_from_reverse_indexes(&key, &mut state.service_to_ingresses, &mut state.secret_to_ingresses);
                    self.handle_deleted(
                        &ingress, service_store,
                        &mut state.ingress_domains, &mut state.ingress_tls_bases,
                    ).await;
                }
            }
            Event::Delete(ingress) => {
                let key = translator::ingress_key(&ingress);
                state.ingress_specs.remove(&key);
                remove_from_reverse_indexes(&key, &mut state.service_to_ingresses, &mut state.secret_to_ingresses);
                self.handle_deleted(
                    &ingress, service_store,
                    &mut state.ingress_domains, &mut state.ingress_tls_bases,
                ).await;
            }
            Event::InitDone => {
                if let Some(old_domains) = state.prev_ingress_domains.take() {
                    let gone_routes: Vec<String> = old_domains
                        .iter()
                        .flat_map(|(key, domains)| {
                            let current = state.ingress_domains.get(key);
                            domains.iter().filter(move |d| {
                                !current.is_some_and(|nd| nd.contains(d))
                            })
                        })
                        .cloned()
                        .collect();
                    if !gone_routes.is_empty() {
                        debug!(count = gone_routes.len(), "resync: deleting stale routes");
                        let _ = translator::reconcile_deleted(&gone_routes, &self.api_client).await;
                    }
                }
                if let Some(old_tls) = state.prev_ingress_tls_bases.take() {
                    let gone_pems: Vec<String> = old_tls
                        .iter()
                        .flat_map(|(key, bases)| {
                            let current = state.ingress_tls_bases.get(key);
                            bases.iter().filter(move |b| {
                                !current.is_some_and(|nb| nb.contains(b))
                            })
                        })
                        .cloned()
                        .collect();
                    if !gone_pems.is_empty() {
                        debug!(count = gone_pems.len(), "resync: removing stale TLS PEMs");
                        tls::remove_tls_pem_files(&gone_pems, &self.cert_dir);
                    }
                }
                self.readiness.sync_ready.store(true, Ordering::Release);
                info!("Initial sync complete — readiness flag set");
            }
            Event::Init => {
                state.prev_ingress_domains = Some(std::mem::take(&mut state.ingress_domains));
                state.prev_ingress_tls_bases = Some(std::mem::take(&mut state.ingress_tls_bases));
                state.ingress_specs.clear();
                // Reverse indexes are rebuilt from InitApply events during the resync.
                state.service_to_ingresses.clear();
                state.secret_to_ingresses.clear();
            }
        }
    }

    /// Handle an `Apply` or `InitApply` Ingress event.
    async fn handle_applied(
        &self,
        ingress: &Ingress,
        service_store: &Store<Service>,
        secret_store: &Store<Secret>,
        ingress_domains: &mut HashMap<String, Vec<String>>,
        ingress_tls_bases: &mut HashMap<String, Vec<String>>,
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

        // Clean up routes for hosts that were removed from this Ingress spec
        // since the last Apply. Without this, a deleted rule persists in the
        // route table until the next full resync.
        if let Some(old_domains) = ingress_domains.get(&key) {
            let removed: Vec<String> = old_domains
                .iter()
                .filter(|d| !synced.contains(d))
                .cloned()
                .collect();
            if !removed.is_empty() {
                debug!(ingress = %key, removed = ?removed, "cleaning up removed hosts");
                let _ = translator::reconcile_deleted(&removed, &self.api_client).await;
            }
        }

        ingress_domains.insert(key.clone(), synced);

        // Materialise TLS PEM files for every secret referenced by this Ingress.
        let tls_blocks = tls_blocks_from_ingress(ingress);
        if !tls_blocks.is_empty() {
            let bases = tls::sync_tls_secrets(&tls_blocks, secret_store, &self.cert_dir);
            debug!(ingress = %key, count = bases.len(), "TLS PEM files written");
            ingress_tls_bases.insert(key, bases);
        }
    }

    /// Handle a `Delete` Ingress event.
    async fn handle_deleted(
        &self,
        ingress: &Ingress,
        service_store: &Store<Service>,
        ingress_domains: &mut HashMap<String, Vec<String>>,
        ingress_tls_bases: &mut HashMap<String, Vec<String>>,
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
        } else {
            let errors = translator::reconcile_deleted(&domains, &self.api_client).await;
            let deleted = domains.len() - errors.len();
            for _ in 0..deleted {
                self.metrics.inc_routes_deleted();
            }
            for e in &errors {
                error!(ingress = %key, error = %e, "failed to delete route");
            }
        }

        // Clean up any TLS PEM files this Ingress wrote.
        if let Some(bases) = ingress_tls_bases.remove(&key)
            && !bases.is_empty()
        {
            debug!(ingress = %key, count = bases.len(), "removing TLS PEM files");
            tls::remove_tls_pem_files(&bases, &self.cert_dir);
        }
    }

    /// Re-run `handle_applied` for the specified Ingress keys only.
    ///
    /// Called when a Service or Secret changes — only the Ingresses that
    /// reference the changed resource are re-evaluated, not the entire set.
    /// This reduces admin API churn from O(events × ingresses) to
    /// O(events × affected_ingresses).
    async fn rereconcile_ingresses(
        &self,
        ingress_keys: &[String],
        service_store: &Store<Service>,
        secret_store: &Store<Secret>,
        ingress_domains: &mut HashMap<String, Vec<String>>,
        ingress_tls_bases: &mut HashMap<String, Vec<String>>,
        ingress_specs: &HashMap<String, Ingress>,
    ) {
        for key in ingress_keys {
            if let Some(ingress) = ingress_specs.get(key) {
                self.handle_applied(ingress, service_store, secret_store, ingress_domains, ingress_tls_bases)
                    .await;
            }
        }
    }

    /// Return `true` if this Ingress should be processed by this controller.
    ///
    /// When `ingress_class` is `None`, we process all Ingresses (useful in
    /// single-controller setups). When set, we match against
    /// `spec.ingressClassName` (preferred, v1.18+) and fall back to the
    /// `kubernetes.io/ingress.class` annotation (legacy). This matches the
    /// priority order used in `annotations::is_owned_by_dwaar`.
    fn ingress_class_matches(&self, ingress: &Ingress) -> bool {
        let Some(ref class_name) = self.ingress_class else {
            return true; // no filter configured — process everything
        };

        // Check spec.ingressClassName first (newer convention, v1.18+)
        let spec_class = ingress
            .spec
            .as_ref()
            .and_then(|s| s.ingress_class_name.as_deref());

        if let Some(sc) = spec_class {
            return sc == class_name;
        }

        // Fall back to the legacy annotation.
        ingress
            .metadata
            .annotations
            .as_ref()
            .and_then(|a| a.get("kubernetes.io/ingress.class"))
            .is_some_and(|v| v == class_name)
    }
}

/// Build a `Vec<DesiredRoute>` from the current watcher state and push it to
/// the reconciler's watch channel.
///
/// The reconciler only needs domain + upstream + tls. We re-derive the upstream
/// from the live service store so the snapshot reflects the current `ClusterIP`.
fn push_desired_snapshot(
    ingress_domains: &HashMap<String, Vec<String>>,
    ingress_specs: &HashMap<String, Ingress>,
    service_store: &Store<Service>,
    tx: &tokio::sync::watch::Sender<Vec<DesiredRoute>>,
) {
    let mut desired: Vec<DesiredRoute> = Vec::new();
    for ingress in ingress_specs.values() {
        let routes = translator::translate_ingress(ingress, service_store);
        for r in routes {
            desired.push(DesiredRoute {
                domain: r.domain,
                upstream: r.upstream,
                tls: r.tls,
            });
        }
    }
    // Also include any domains tracked but whose Ingress spec isn't in ingress_specs
    // yet (edge case during init). Use ingress_domains as the authority for what's
    // actually been applied so the reconciler doesn't delete routes mid-resync.
    let _ = ingress_domains; // already covered by ingress_specs iteration above
    let _ = tx.send(desired);
}

/// Extract a display name from a Service watcher event for logging.
fn service_name_from_event(event: &Event<Service>) -> String {
    let svc = match event {
        Event::Apply(s) | Event::InitApply(s) | Event::Delete(s) => s,
        Event::Init | Event::InitDone => return "<resync>".to_string(),
    };
    svc.metadata
        .name
        .as_deref()
        .unwrap_or("<unknown>")
        .to_string()
}

/// Extract a display name from a Secret watcher event for logging.
fn secret_name_from_event(event: &Event<Secret>) -> String {
    let secret = match event {
        Event::Apply(s) | Event::InitApply(s) | Event::Delete(s) => s,
        Event::Init | Event::InitDone => return "<resync>".to_string(),
    };
    secret
        .metadata
        .name
        .as_deref()
        .unwrap_or("<unknown>")
        .to_string()
}

/// Extract `(namespace, secret_name)` pairs from an Ingress's TLS blocks.
///
/// Each `spec.tls[].secretName` entry names a Secret that holds the cert/key
/// material. We pair it with the Ingress namespace so that `sync_tls_secrets`
/// can look it up in the Secret store.
/// Update the reverse indexes for an Ingress that was just applied.
///
/// Removes old entries for this Ingress key, then adds fresh ones derived
/// from the current spec. This handles both initial inserts and updates
/// (where the Ingress may now reference different services/secrets).
fn update_reverse_indexes(
    ingress: &Ingress,
    ingress_key: &str,
    service_to_ingresses: &mut HashMap<String, Vec<String>>,
    secret_to_ingresses: &mut HashMap<String, Vec<String>>,
) {
    // Remove stale entries first (handles spec changes).
    remove_from_reverse_indexes(ingress_key, service_to_ingresses, secret_to_ingresses);

    // Add fresh entries.
    for svc_key in services_from_ingress(ingress) {
        service_to_ingresses
            .entry(svc_key)
            .or_default()
            .push(ingress_key.to_owned());
    }
    for secret_key in secrets_from_ingress(ingress) {
        secret_to_ingresses
            .entry(secret_key)
            .or_default()
            .push(ingress_key.to_owned());
    }
}

/// Remove an Ingress key from all reverse index entries.
fn remove_from_reverse_indexes(
    ingress_key: &str,
    service_to_ingresses: &mut HashMap<String, Vec<String>>,
    secret_to_ingresses: &mut HashMap<String, Vec<String>>,
) {
    for values in service_to_ingresses.values_mut() {
        values.retain(|k| k != ingress_key);
    }
    // Clean up empty entries to prevent unbounded map growth.
    service_to_ingresses.retain(|_, v| !v.is_empty());

    for values in secret_to_ingresses.values_mut() {
        values.retain(|k| k != ingress_key);
    }
    secret_to_ingresses.retain(|_, v| !v.is_empty());
}

/// Build a `"namespace/name"` key from a Service watcher event.
fn service_key_from_event(event: &Event<Service>) -> String {
    let svc = match event {
        Event::Apply(s) | Event::InitApply(s) | Event::Delete(s) => s,
        Event::Init | Event::InitDone => return String::new(),
    };
    let ns = svc.metadata.namespace.as_deref().unwrap_or("default");
    let name = svc.metadata.name.as_deref().unwrap_or("<unknown>");
    format!("{ns}/{name}")
}

/// Build a `"namespace/name"` key from a Secret watcher event.
fn secret_key_from_event(event: &Event<Secret>) -> String {
    let secret = match event {
        Event::Apply(s) | Event::InitApply(s) | Event::Delete(s) => s,
        Event::Init | Event::InitDone => return String::new(),
    };
    let ns = secret.metadata.namespace.as_deref().unwrap_or("default");
    let name = secret.metadata.name.as_deref().unwrap_or("<unknown>");
    format!("{ns}/{name}")
}

/// Extract `"namespace/service_name"` keys referenced by this Ingress's backends.
///
/// Used to build the reverse index for targeted Service-change re-reconciliation.
fn services_from_ingress(ingress: &Ingress) -> Vec<String> {
    let namespace = ingress
        .metadata
        .namespace
        .as_deref()
        .unwrap_or("default");

    let mut services = Vec::new();

    if let Some(spec) = ingress.spec.as_ref() {
        // Default backend
        if let Some(backend) = spec.default_backend.as_ref() {
            if let Some(svc) = backend.service.as_ref() {
                services.push(format!("{namespace}/{}", svc.name));
            }
        }
        // Per-rule backends
        for rule in spec.rules.iter().flatten() {
            if let Some(http) = rule.http.as_ref() {
                for path in &http.paths {
                    if let Some(svc) = path.backend.service.as_ref() {
                        services.push(format!("{namespace}/{}", svc.name));
                    }
                }
            }
        }
    }

    services.sort();
    services.dedup();
    services
}

/// Extract `"namespace/secret_name"` keys referenced by this Ingress's TLS blocks.
///
/// Used to build the reverse index for targeted Secret-change re-reconciliation.
fn secrets_from_ingress(ingress: &Ingress) -> Vec<String> {
    let namespace = ingress
        .metadata
        .namespace
        .as_deref()
        .unwrap_or("default");

    ingress
        .spec
        .iter()
        .flat_map(|s| s.tls.iter().flatten())
        .filter_map(|t| t.secret_name.as_ref())
        .map(|name| format!("{namespace}/{name}"))
        .collect()
}

fn tls_blocks_from_ingress(ingress: &Ingress) -> Vec<(String, String)> {
    let namespace = ingress
        .metadata
        .namespace
        .as_deref()
        .unwrap_or("default")
        .to_string();

    ingress
        .spec
        .iter()
        .flat_map(|s| s.tls.iter().flatten())
        .filter_map(|t| t.secret_name.as_ref())
        .map(|secret_name| (namespace.clone(), secret_name.clone()))
        .collect()
}
