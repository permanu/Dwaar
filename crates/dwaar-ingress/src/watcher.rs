// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Kubernetes resource watchers for the ingress controller.
//!
//! Watches four resource types that together describe an Ingress route:
//! - `Ingress`      — the route spec (host → service mapping)
//! - `Service`      — needed to resolve `ClusterIP` / port
//! - `Secret`       — TLS certificates referenced by Ingress TLS blocks
//! - `IngressClass` — governs which Ingress objects we own
//!
//! Each resource type is backed by a `kube_runtime::reflector::Store` so
//! the rest of the controller can query current state without hitting the
//! API server.  The Ingress watcher also drives reconciliation: every
//! `Apply(Ingress)` event triggers an upsert to the Dwaar admin API,
//! and every `Delete(Ingress)` triggers a deletion.
//!
//! Reconnection / backoff is handled by `kube_runtime::watcher`'s built-in
//! `default_backoff()` — exponential 1 s → 30 s — so we never need to
//! write our own retry loop for the watch stream.
//!
//! Graceful shutdown is signalled by the `shutdown_rx` channel: when it
//! fires (SIGTERM / SIGINT from `main.rs`) the select! in `run()` exits.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use futures::{StreamExt, TryStreamExt};
use k8s_openapi::api::core::v1::{Secret, Service};
use k8s_openapi::api::networking::v1::{Ingress, IngressClass};
use kube::api::ResourceExt;
use kube::runtime::WatchStreamExt;
use kube::runtime::reflector::{self, Store};
use kube::runtime::watcher as kube_watcher;
use kube::{Api, Client};
use tokio::sync::watch;
use tracing::{debug, error, info, instrument, warn};

use crate::client::AdminApiClient;
use crate::health::ReadinessState;
use crate::metrics::IngressMetrics;

/// The ingress-class annotation key.
/// Ingress objects that do not carry a matching class name are ignored.
const INGRESS_CLASS_ANNOTATION: &str = "kubernetes.io/ingress.class";

/// Reflected state for all four resource types.
///
/// Each `Store<T>` is a cheap `Arc`-backed reader; cloning it is free.
/// `Store<T>` does not implement `Debug` so we skip deriving it.
#[allow(missing_debug_implementations)]
#[derive(Clone)]
pub struct WatcherStores {
    pub ingresses: Store<Ingress>,
    pub services: Store<Service>,
    pub secrets: Store<Secret>,
    pub ingress_classes: Store<IngressClass>,
}

/// Configuration for the watcher task.
#[derive(Debug, Clone)]
pub struct WatcherConfig {
    /// If `Some`, restrict watches to this namespace. If `None`, watch all namespaces.
    pub namespace: Option<String>,
    /// Only reconcile Ingress objects whose `ingressClassName` (or annotation)
    /// matches this value.
    pub ingress_class: Option<String>,
}

/// Main watcher that owns the four reflectors and drives reconciliation.
///
/// Call [`IngressWatcher::run`] as a long-lived tokio task.  It never
/// returns unless the shutdown channel fires.
#[allow(missing_debug_implementations)]
pub struct IngressWatcher {
    client: Client,
    admin: AdminApiClient,
    config: WatcherConfig,
    readiness: ReadinessState,
    metrics: Arc<IngressMetrics>,
}

impl IngressWatcher {
    pub fn new(
        client: Client,
        admin: AdminApiClient,
        config: WatcherConfig,
        readiness: ReadinessState,
        metrics: Arc<IngressMetrics>,
    ) -> Self {
        Self {
            client,
            admin,
            config,
            readiness,
            metrics,
        }
    }

    /// Build a namespaced or cluster-wide `Api<T>` depending on config.
    fn api<T>(&self) -> Api<T>
    where
        T: kube::Resource<Scope = k8s_openapi::NamespaceResourceScope>,
        T: Clone + std::fmt::Debug + serde::de::DeserializeOwned + Send + Sync + 'static,
        T::DynamicType: Default,
    {
        match &self.config.namespace {
            Some(ns) => Api::namespaced(self.client.clone(), ns),
            None => Api::all(self.client.clone()),
        }
    }

    /// Build a cluster-scoped `Api<T>`.
    fn cluster_api<T>(&self) -> Api<T>
    where
        T: kube::Resource<Scope = k8s_openapi::ClusterResourceScope>,
        T: Clone + std::fmt::Debug + serde::de::DeserializeOwned + Send + Sync + 'static,
        T::DynamicType: Default,
    {
        Api::all(self.client.clone())
    }

    /// Run all four watch streams concurrently until shutdown is signalled.
    ///
    /// Returns the `WatcherStores` so callers can inspect reflected state.
    pub async fn run(self: Arc<Self>, mut shutdown_rx: watch::Receiver<bool>) -> WatcherStores {
        // Set up the four reflector store pairs.
        let (ingress_reader, ingress_writer) = reflector::store();
        let (service_reader, service_writer) = reflector::store();
        let (secret_reader, secret_writer) = reflector::store();
        let (class_reader, class_writer) = reflector::store();

        let stores = WatcherStores {
            ingresses: ingress_reader,
            services: service_reader,
            secrets: secret_reader,
            ingress_classes: class_reader,
        };

        // --- Ingress watcher + reconciler ---
        // We keep the raw event stream (not `.applied_objects()`) so we can
        // detect both Apply and Delete events for reconciliation.
        let ingress_api: Api<Ingress> = self.api();
        let ingress_watcher = kube_watcher::watcher(ingress_api, kube_watcher::Config::default())
            .default_backoff()
            .reflect(ingress_writer);

        // --- Service watcher (reflected, no reconcile action) ---
        // `.applied_objects()` converts `TryStream<Item=Event<T>>` to `Stream<Item=T>`,
        // so we use `.for_each()` (not `try_for_each()`) to drain it.
        let service_api: Api<Service> = self.api();
        let service_watcher = kube_watcher::watcher(service_api, kube_watcher::Config::default())
            .default_backoff()
            .reflect(service_writer)
            .applied_objects();

        // --- Secret watcher (reflected, no reconcile action) ---
        let secret_api: Api<Secret> = self.api();
        let secret_watcher = kube_watcher::watcher(secret_api, kube_watcher::Config::default())
            .default_backoff()
            .reflect(secret_writer)
            .applied_objects();

        // --- IngressClass watcher (cluster-scoped, reflected only) ---
        let class_api: Api<IngressClass> = self.cluster_api();
        let class_watcher = kube_watcher::watcher(class_api, kube_watcher::Config::default())
            .default_backoff()
            .reflect(class_writer)
            .applied_objects();

        // Spawn secondary watchers as background tasks. They run for the
        // lifetime of the process and populate the reflector stores without
        // requiring explicit event dispatch.
        tokio::spawn(async move {
            service_watcher.for_each(|_svc| async {}).await;
            error!("Service watcher terminated unexpectedly");
        });

        tokio::spawn(async move {
            secret_watcher.for_each(|_secret| async {}).await;
            error!("Secret watcher terminated unexpectedly");
        });

        tokio::spawn(async move {
            class_watcher.for_each(|_class| async {}).await;
            error!("IngressClass watcher terminated unexpectedly");
        });

        // Pin the Ingress stream; it remains a TryStream so we use try_next().
        let mut ingress_stream = std::pin::pin!(ingress_watcher);

        loop {
            tokio::select! {
                biased;

                // Shutdown signal takes highest priority
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("IngressWatcher shutting down");
                        return stores;
                    }
                }

                event = ingress_stream.try_next() => {
                    match event {
                        Ok(Some(ev)) => {
                            self.handle_ingress_event(ev).await;
                        }
                        Ok(None) => {
                            // `default_backoff()` normally reconnects internally,
                            // so stream exhaustion should not happen in practice.
                            warn!("Ingress watch stream ended unexpectedly");
                            self.readiness.watcher_ready.store(false, Ordering::Release);
                        }
                        Err(e) => {
                            error!(error = %e, "Ingress watch stream error");
                            self.readiness.watcher_ready.store(false, Ordering::Release);
                        }
                    }
                }
            }
        }
    }

    /// Dispatch a raw watcher event to the appropriate reconcile action.
    async fn handle_ingress_event(&self, event: kube_watcher::Event<Ingress>) {
        match event {
            kube_watcher::Event::Apply(ingress) => {
                self.readiness.watcher_ready.store(true, Ordering::Release);
                self.metrics
                    .watched_ingresses
                    .set(self.metrics.watched_ingresses.get() + 1);

                if self.should_reconcile(&ingress) {
                    self.reconcile_upsert(&ingress).await;
                }
            }
            kube_watcher::Event::Delete(ingress) => {
                self.metrics
                    .watched_ingresses
                    .set((self.metrics.watched_ingresses.get() - 1).max(0));

                if self.should_reconcile(&ingress) {
                    self.reconcile_delete(&ingress).await;
                }
            }
            // Init / InitApply / InitDone are emitted during the initial list
            // phase. We treat InitApply items the same as Apply to bootstrap
            // the admin API with existing state on startup.
            kube_watcher::Event::Init => {
                debug!("Ingress watcher initialising (list phase)");
            }
            kube_watcher::Event::InitApply(ingress) => {
                if self.should_reconcile(&ingress) {
                    self.reconcile_upsert(&ingress).await;
                }
            }
            kube_watcher::Event::InitDone => {
                info!("Ingress watcher init complete — watch stream active");
                self.readiness.watcher_ready.store(true, Ordering::Release);
            }
        }
    }

    /// Returns `true` when the Ingress object belongs to our ingress class.
    ///
    /// If `--ingress-class` was not set, we handle everything.
    /// Otherwise we check both the `ingressClassName` field and the legacy
    /// `kubernetes.io/ingress.class` annotation.
    fn should_reconcile(&self, ingress: &Ingress) -> bool {
        let Some(ref expected_class) = self.config.ingress_class else {
            return true;
        };

        // Check spec.ingressClassName (preferred since Kubernetes 1.18)
        if let Some(spec) = &ingress.spec
            && let Some(class_name) = &spec.ingress_class_name
        {
            return class_name == expected_class;
        }

        // Fall back to the legacy annotation
        ingress.annotations().get(INGRESS_CLASS_ANNOTATION) == Some(expected_class)
    }

    /// Upsert all routes defined by a single Ingress object.
    ///
    /// An Ingress may define multiple rules (hostnames), each mapping to a
    /// backend service. We derive the upstream from the first path's backend.
    #[instrument(skip(self), fields(name = ingress.name_any(), namespace = ingress.namespace().unwrap_or_default()))]
    async fn reconcile_upsert(&self, ingress: &Ingress) {
        let start = Instant::now();
        let Some(spec) = &ingress.spec else {
            debug!("Ingress has no spec — skipping");
            return;
        };

        let rules = match &spec.rules {
            Some(r) if !r.is_empty() => r,
            _ => {
                debug!("Ingress has no rules — skipping");
                return;
            }
        };

        // TLS is enabled for this Ingress if any TLS block is present
        let has_tls = spec.tls.as_ref().is_some_and(|t| !t.is_empty());

        for rule in rules {
            let Some(host) = &rule.host else {
                debug!("Ingress rule has no host — skipping");
                continue;
            };

            // Derive upstream from the first path backend of this rule
            let Some(upstream) = derive_upstream(rule) else {
                warn!(host, "Cannot derive upstream from Ingress rule — skipping");
                continue;
            };

            info!(host, upstream, tls = has_tls, "upserting route");

            match self.admin.upsert_route(host, &upstream, has_tls).await {
                Ok(()) => {
                    self.metrics.record_sync_ok();
                    debug!(host, "route upserted");
                }
                Err(e) => {
                    let reason = error_reason(&e);
                    self.metrics.record_sync_error(reason);
                    error!(host, error = %e, "failed to upsert route");
                }
            }
        }

        self.metrics
            .reconcile_duration_seconds
            .observe(start.elapsed().as_secs_f64());
    }

    /// Delete all routes for the hosts defined by a deleted Ingress.
    #[instrument(skip(self), fields(name = ingress.name_any(), namespace = ingress.namespace().unwrap_or_default()))]
    async fn reconcile_delete(&self, ingress: &Ingress) {
        let start = Instant::now();
        let Some(spec) = &ingress.spec else {
            return;
        };

        let rules = match &spec.rules {
            Some(r) if !r.is_empty() => r,
            _ => return,
        };

        for rule in rules {
            let Some(host) = &rule.host else {
                continue;
            };

            info!(host, "deleting route");

            match self.admin.delete_route(host).await {
                Ok(()) => {
                    self.metrics.record_sync_ok();
                    debug!(host, "route deleted");
                }
                Err(e) => {
                    let reason = error_reason(&e);
                    self.metrics.record_sync_error(reason);
                    error!(host, error = %e, "failed to delete route");
                }
            }
        }

        self.metrics
            .reconcile_duration_seconds
            .observe(start.elapsed().as_secs_f64());
    }
}

/// Extract a `host:port` upstream string from the first backend in an Ingress rule.
///
/// The service name is used as the hostname so the proxy can resolve it via
/// cluster DNS (e.g. `my-svc:8080`). An operator can override with an
/// `ExternalName` service if a raw IP is required.
fn derive_upstream(rule: &k8s_openapi::api::networking::v1::IngressRule) -> Option<String> {
    let http = rule.http.as_ref()?;
    let path = http.paths.first()?;
    let backend = path.backend.service.as_ref()?;
    let port = backend.port.as_ref()?;

    let port_num = port.number?;
    Some(format!("{}:{}", backend.name, port_num))
}

/// Map an `AdminApiError` to a short reason string for the metrics label.
fn error_reason(e: &crate::error::AdminApiError) -> &'static str {
    use crate::error::AdminApiError;
    match e {
        AdminApiError::Transport(_) => "transport",
        AdminApiError::Status { .. } => "status",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::networking::v1::{
        HTTPIngressPath, HTTPIngressRuleValue, IngressBackend, IngressRule, IngressServiceBackend,
        IngressSpec, ServiceBackendPort,
    };

    fn make_ingress(host: &str, service: &str, port: i32, tls: bool) -> Ingress {
        let tls_block = if tls {
            Some(vec![k8s_openapi::api::networking::v1::IngressTLS {
                hosts: Some(vec![host.to_string()]),
                secret_name: Some("my-tls-secret".to_string()),
            }])
        } else {
            None
        };

        Ingress {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some("test-ingress".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: Some(IngressSpec {
                rules: Some(vec![IngressRule {
                    host: Some(host.to_string()),
                    http: Some(HTTPIngressRuleValue {
                        paths: vec![HTTPIngressPath {
                            backend: IngressBackend {
                                service: Some(IngressServiceBackend {
                                    name: service.to_string(),
                                    port: Some(ServiceBackendPort {
                                        number: Some(port),
                                        name: None,
                                    }),
                                }),
                                resource: None,
                            },
                            path: Some("/".to_string()),
                            path_type: "Prefix".to_string(),
                        }],
                    }),
                }]),
                tls: tls_block,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn make_ingress_with_class(class_name: &str) -> Ingress {
        let mut ingress = make_ingress("example.com", "my-svc", 80, false);
        if let Some(spec) = ingress.spec.as_mut() {
            spec.ingress_class_name = Some(class_name.to_string());
        }
        ingress
    }

    fn make_ingress_with_annotation(class_name: &str) -> Ingress {
        let mut ingress = make_ingress("example.com", "my-svc", 80, false);
        ingress.metadata.annotations =
            Some([(INGRESS_CLASS_ANNOTATION.to_string(), class_name.to_string())].into());
        ingress
    }

    fn make_watcher_config(class: Option<&str>, ns: Option<&str>) -> WatcherConfig {
        WatcherConfig {
            namespace: ns.map(ToString::to_string),
            ingress_class: class.map(ToString::to_string),
        }
    }

    // Thin struct to test the pure logic of should_reconcile without
    // needing a live kube client.
    struct PureWatcher {
        config: WatcherConfig,
    }

    impl PureWatcher {
        fn should_reconcile(&self, ingress: &Ingress) -> bool {
            let Some(ref expected_class) = self.config.ingress_class else {
                return true;
            };
            if let Some(spec) = &ingress.spec
                && let Some(class_name) = &spec.ingress_class_name
            {
                return class_name == expected_class;
            }
            ingress.annotations().get(INGRESS_CLASS_ANNOTATION) == Some(expected_class)
        }
    }

    #[test]
    fn derive_upstream_extracts_service_and_port() {
        let ingress = make_ingress("example.com", "my-backend", 8080, false);
        let spec = ingress.spec.expect("test ingress has spec");
        let rule = &spec.rules.expect("test ingress has rules")[0];
        let upstream = derive_upstream(rule).expect("should derive upstream");
        assert_eq!(upstream, "my-backend:8080");
    }

    #[test]
    fn derive_upstream_no_paths_returns_none() {
        let rule = IngressRule {
            host: Some("example.com".to_string()),
            http: Some(HTTPIngressRuleValue { paths: vec![] }),
        };
        assert!(derive_upstream(&rule).is_none());
    }

    #[test]
    fn derive_upstream_no_http_returns_none() {
        let rule = IngressRule {
            host: Some("example.com".to_string()),
            http: None,
        };
        assert!(derive_upstream(&rule).is_none());
    }

    #[test]
    fn no_class_filter_reconciles_all() {
        let w = PureWatcher {
            config: make_watcher_config(None, None),
        };
        let ingress = make_ingress("example.com", "svc", 80, false);
        assert!(w.should_reconcile(&ingress));
    }

    #[test]
    fn class_filter_matches_spec_field() {
        let w = PureWatcher {
            config: make_watcher_config(Some("dwaar"), None),
        };
        let ingress = make_ingress_with_class("dwaar");
        assert!(w.should_reconcile(&ingress));
    }

    #[test]
    fn class_filter_rejects_wrong_class() {
        let w = PureWatcher {
            config: make_watcher_config(Some("dwaar"), None),
        };
        let ingress = make_ingress_with_class("nginx");
        assert!(!w.should_reconcile(&ingress));
    }

    #[test]
    fn class_filter_matches_annotation_fallback() {
        let w = PureWatcher {
            config: make_watcher_config(Some("dwaar"), None),
        };
        let ingress = make_ingress_with_annotation("dwaar");
        assert!(w.should_reconcile(&ingress));
    }

    #[test]
    fn class_filter_rejects_wrong_annotation() {
        let w = PureWatcher {
            config: make_watcher_config(Some("dwaar"), None),
        };
        let ingress = make_ingress_with_annotation("traefik");
        assert!(!w.should_reconcile(&ingress));
    }

    #[test]
    fn ingress_with_tls_block_has_tls_true() {
        let ingress = make_ingress("secure.example.com", "svc", 443, true);
        let spec = ingress.spec.expect("test ingress has spec");
        let has_tls = spec.tls.as_ref().is_some_and(|t| !t.is_empty());
        assert!(has_tls);
    }

    #[test]
    fn ingress_without_tls_block_has_tls_false() {
        let ingress = make_ingress("plain.example.com", "svc", 80, false);
        let spec = ingress.spec.expect("test ingress has spec");
        let has_tls = spec.tls.as_ref().is_some_and(|t| !t.is_empty());
        assert!(!has_tls);
    }
}
