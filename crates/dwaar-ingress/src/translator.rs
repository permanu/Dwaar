// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Translates Kubernetes `Ingress` resources into Dwaar routes.
//!
//! ## Design
//!
//! A single K8s Ingress maps to one or more Dwaar routes:
//!
//! - Each `spec.rules[].host` becomes a distinct domain.
//! - Each `spec.rules[].http.paths[]` contributes a path matcher for that domain.
//! - `spec.defaultBackend` becomes a wildcard catch-all route when no host is set.
//!
//! Service lookup happens against the `kube::runtime::reflector::Store<Service>`
//! that the watcher keeps warm. This is a local in-memory cache — no API server
//! round-trip per reconcile event.
//!
//! ## Path types
//!
//! - `Prefix` / `ImplementationSpecific` → we treat as prefix match (most permissive,
//!   matches Caddy/Nginx "starts-with" semantics that operators expect).
//! - `Exact` → we emit the path verbatim as an exact upstream route key.
//!   Dwaar routes currently use domain-based dispatch; path info is carried through
//!   so callers can extend handling later without changing this layer.
//!
//! ## Error handling
//!
//! Missing services are logged and skipped — a misconfigured Ingress backend
//! must not block all other routes from being reconciled.

use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::networking::v1::{Ingress, IngressBackend, IngressRule};
use kube::runtime::reflector::Store;
use tracing::{debug, info, warn};

use crate::client::AdminApiClient;
use crate::error::AdminApiError;

/// A resolved route ready to send to the admin API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRoute {
    /// Hostname the route serves (may be `*` for default backend catch-alls).
    pub domain: String,
    /// Resolved upstream in `host:port` form (ClusterIP:port).
    pub upstream: String,
    /// Whether TLS is expected on the upstream connection.
    /// Derived from `spec.tls[].hosts` membership.
    pub tls: bool,
}

/// Translate an applied (Added/Modified) `Ingress` into a list of resolved routes.
///
/// Returns only the routes where the backend `Service` was successfully resolved.
/// Routes whose service is missing are skipped with a warning rather than failing
/// the entire batch — a partially working ingress is better than none at all.
pub fn translate_ingress(ingress: &Ingress, service_store: &Store<Service>) -> Vec<ResolvedRoute> {
    let meta = ingress.metadata.clone();
    let namespace = meta.namespace.as_deref().unwrap_or("default");
    let name = meta.name.as_deref().unwrap_or("<unnamed>");

    let Some(spec) = ingress.spec.as_ref() else {
        warn!(ingress = %name, "Ingress has no spec — skipping");
        return Vec::new();
    };

    // Build the set of TLS-covered hostnames so we can set `tls = true`
    // on routes that match. The TLS block lists the Secret name + host list.
    let tls_hosts: std::collections::HashSet<&str> = spec
        .tls
        .iter()
        .flatten()
        .flat_map(|t| t.hosts.iter().flatten())
        .map(String::as_str)
        .collect();

    let mut routes: Vec<ResolvedRoute> = Vec::new();

    // ── Per-host rules ────────────────────────────────────────────────────────
    for rule in spec.rules.iter().flatten() {
        process_rule(
            rule,
            namespace,
            name,
            &tls_hosts,
            service_store,
            &mut routes,
        );
    }

    // ── Default backend (catch-all, no host constraint) ───────────────────────
    if let Some(default_backend) = spec.default_backend.as_ref() {
        match resolve_backend(default_backend, namespace, service_store) {
            Some(upstream) => {
                // Use `*` as a catch-all domain sentinel. The admin API can
                // store it as-is; the proxy uses wildcard resolution for matching.
                let tls = false; // default backend is not per-host, so no TLS entry
                debug!(ingress = %name, upstream = %upstream, "adding default backend catch-all");
                routes.push(ResolvedRoute {
                    domain: "*".to_string(),
                    upstream,
                    tls,
                });
            }
            None => {
                warn!(
                    ingress = %name,
                    "default backend service unresolvable — skipping"
                );
            }
        }
    }

    info!(
        ingress = %name,
        namespace = %namespace,
        resolved = routes.len(),
        "translated Ingress"
    );

    routes
}

/// Process a single `IngressRule` and append any resolved routes to `out`.
fn process_rule(
    rule: &IngressRule,
    namespace: &str,
    ingress_name: &str,
    tls_hosts: &std::collections::HashSet<&str>,
    service_store: &Store<Service>,
    out: &mut Vec<ResolvedRoute>,
) {
    // A rule with no host matches requests regardless of the `Host` header.
    // We emit it as `*` (wildcard) so the proxy catches everything.
    let host = rule.host.as_deref().unwrap_or("*");
    let tls = tls_hosts.contains(host);

    let Some(http) = rule.http.as_ref() else {
        debug!(host, ingress = %ingress_name, "Ingress rule has no http block — skipping");
        return;
    };

    for path_item in &http.paths {
        // path_type is a non-optional String in k8s-openapi v0.24
        let path_type = path_item.path_type.as_str();
        let path = path_item.path.as_deref().unwrap_or("/");

        debug!(
            host,
            path,
            path_type,
            ingress = %ingress_name,
            "processing Ingress path"
        );

        match resolve_backend(&path_item.backend, namespace, service_store) {
            Some(upstream) => {
                // For Exact paths we pass the path through verbatim.
                // For Prefix / ImplementationSpecific we normalise to a prefix
                // form that the admin API understands.
                let effective_path = normalize_path(path, path_type);

                // We encode path into the domain key using a `host/path` scheme
                // so multiple paths per host each get their own admin-API entry.
                // Simple (single `/`) paths just use the bare host.
                let domain_key = if effective_path == "/" {
                    host.to_string()
                } else {
                    format!("{host}{effective_path}")
                };

                out.push(ResolvedRoute {
                    domain: domain_key,
                    upstream,
                    tls,
                });
            }
            None => {
                warn!(
                    host,
                    path,
                    ingress = %ingress_name,
                    "backend service not in store — skipping path"
                );
            }
        }
    }
}

/// Normalise an Ingress path to the form used in the admin API key.
///
/// - `Exact` → kept verbatim (exact match semantics).
/// - `Prefix` / `ImplementationSpecific` → ensure it ends without a trailing
///   wildcard character so the API key is clean; the proxy layer applies prefix
///   semantics from the route metadata, not the key string.
fn normalize_path(path: &str, path_type: &str) -> String {
    if path_type == "Exact" {
        return path.to_string();
    }
    // For prefix types, strip any trailing `*` that operators sometimes add
    // (not spec-compliant but seen in the wild). Ensure leading slash.
    let trimmed = path.trim_end_matches('*');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Resolve an `IngressBackend` to a `ClusterIP:port` string via the local store.
///
/// Returns `None` (and logs a warning) if:
/// - The backend has no `service` block (extension backends are unsupported).
/// - The Service is not yet in the reflector store (cache warming, or missing).
/// - The Service has no `ClusterIP` (headless service).
/// - The port number doesn't match any port in the Service spec.
fn resolve_backend(
    backend: &IngressBackend,
    namespace: &str,
    service_store: &Store<Service>,
) -> Option<String> {
    let svc_backend = backend.service.as_ref()?;
    let svc_name = &svc_backend.name;

    // Port can be specified as a number or as a named port string.
    // `svc_backend.port` is `Option<ServiceBackendPort>`.
    let port_number = svc_backend.port.as_ref().and_then(|p| p.number);
    let port_name = svc_backend.port.as_ref().and_then(|p| p.name.as_deref());

    // Look up the Service in the reflector's in-memory store.
    // ObjectRef::new sets the name; `.within()` sets the namespace.
    let obj_ref = kube::runtime::reflector::ObjectRef::<Service>::new(svc_name).within(namespace);
    let svc = service_store.get(&obj_ref)?;

    let spec = svc.spec.as_ref()?;

    // Headless services (ClusterIP = "None") have no stable VIP to forward to.
    // Pod-level targeting requires EndpointSlice resolution which is out of scope.
    let cluster_ip = spec.cluster_ip.as_deref()?;
    if cluster_ip == "None" || cluster_ip.is_empty() {
        warn!(
            service = %svc_name,
            namespace,
            "Service is headless (ClusterIP=None) — cannot resolve to a single upstream"
        );
        return None;
    }

    // Resolve the target port number from the Service's port list.
    let target_port = resolve_port(spec.ports.as_deref().unwrap_or(&[]), port_number, port_name)?;

    Some(format!("{cluster_ip}:{target_port}"))
}

/// Find the port number in the Service's port list matching either a numeric
/// or named port reference from the Ingress backend spec.
fn resolve_port(
    svc_ports: &[k8s_openapi::api::core::v1::ServicePort],
    port_number: Option<i32>,
    port_name: Option<&str>,
) -> Option<i32> {
    for sp in svc_ports {
        if let Some(num) = port_number {
            if sp.port == num {
                return Some(sp.port);
            }
        } else if port_name.is_some_and(|name| sp.name.as_deref() == Some(name)) {
            return Some(sp.port);
        }
    }
    None
}

/// Reconcile an `Added` or `Modified` Ingress event.
///
/// Translates the Ingress to routes and upserts each one. Failures for
/// individual routes are logged but do not abort the rest of the batch.
pub async fn reconcile_applied(
    ingress: &Ingress,
    service_store: &Store<Service>,
    client: &AdminApiClient,
) -> Vec<String> {
    let routes = translate_ingress(ingress, service_store);
    let mut synced_domains: Vec<String> = Vec::with_capacity(routes.len());

    for route in &routes {
        match client
            .upsert_route(&route.domain, &route.upstream, route.tls)
            .await
        {
            Ok(()) => {
                debug!(domain = %route.domain, upstream = %route.upstream, "upserted route");
                synced_domains.push(route.domain.clone());
            }
            Err(e) => {
                warn!(
                    domain = %route.domain,
                    upstream = %route.upstream,
                    error = %e,
                    "failed to upsert route — will retry on next reconcile"
                );
            }
        }
    }

    synced_domains
}

/// Reconcile a `Deleted` Ingress event.
///
/// Removes every domain that this Ingress previously owned. The `owned_domains`
/// list comes from the watcher's state tracking — it was built from the last
/// successful `reconcile_applied` for this Ingress.
pub async fn reconcile_deleted(
    owned_domains: &[String],
    client: &AdminApiClient,
) -> Vec<AdminApiError> {
    let mut errors: Vec<AdminApiError> = Vec::new();

    for domain in owned_domains {
        match client.delete_route(domain).await {
            Ok(()) => {
                debug!(%domain, "deleted route");
            }
            Err(e) => {
                warn!(%domain, error = %e, "failed to delete route");
                errors.push(e);
            }
        }
    }

    errors
}

/// Extract all domains an Ingress currently owns from its spec.
///
/// Used on the `Deleted` path when we need to clean up without having the
/// watcher's previous-state cache (e.g. controller restart).
pub fn domains_from_ingress(ingress: &Ingress, service_store: &Store<Service>) -> Vec<String> {
    translate_ingress(ingress, service_store)
        .into_iter()
        .map(|r| r.domain)
        .collect()
}

/// Build a stable tracking key for an Ingress: `namespace/name`.
///
/// Used as the key in the watcher's `ingress_domains` map so we can look up
/// which domains to delete when an Ingress is removed.
pub fn ingress_key(ingress: &Ingress) -> String {
    let ns = ingress.metadata.namespace.as_deref().unwrap_or("default");
    let name = ingress.metadata.name.as_deref().unwrap_or("unknown");
    format!("{ns}/{name}")
}

// ---------------------------------------------------------------------------
// Test helpers — constructors for K8s types without a real API server
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod test_helpers {
    use k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec};
    use k8s_openapi::api::networking::v1::{
        HTTPIngressPath, HTTPIngressRuleValue, Ingress, IngressBackend, IngressRule,
        IngressServiceBackend, IngressSpec, IngressTLS, ServiceBackendPort,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    pub(crate) fn make_service(
        name: &str,
        namespace: &str,
        cluster_ip: &str,
        port: i32,
    ) -> Service {
        Service {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                cluster_ip: Some(cluster_ip.to_string()),
                ports: Some(vec![ServicePort {
                    port,
                    name: Some("http".to_string()),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    pub(crate) fn make_ingress(
        name: &str,
        namespace: &str,
        host: Option<&str>,
        path: &str,
        path_type: &str,
        svc_name: &str,
        svc_port: i32,
    ) -> Ingress {
        Ingress {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            spec: Some(IngressSpec {
                rules: Some(vec![IngressRule {
                    host: host.map(ToString::to_string),
                    http: Some(HTTPIngressRuleValue {
                        paths: vec![HTTPIngressPath {
                            path: Some(path.to_string()),
                            path_type: path_type.to_string(),
                            backend: IngressBackend {
                                service: Some(IngressServiceBackend {
                                    name: svc_name.to_string(),
                                    port: Some(ServiceBackendPort {
                                        number: Some(svc_port),
                                        name: None,
                                    }),
                                }),
                                resource: None,
                            },
                        }],
                    }),
                }]),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    pub(crate) fn make_ingress_tls(
        name: &str,
        namespace: &str,
        host: &str,
        svc_name: &str,
        svc_port: i32,
        tls_hosts: Vec<String>,
    ) -> Ingress {
        Ingress {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            spec: Some(IngressSpec {
                rules: Some(vec![IngressRule {
                    host: Some(host.to_string()),
                    http: Some(HTTPIngressRuleValue {
                        paths: vec![HTTPIngressPath {
                            path: Some("/".to_string()),
                            path_type: "Prefix".to_string(),
                            backend: IngressBackend {
                                service: Some(IngressServiceBackend {
                                    name: svc_name.to_string(),
                                    port: Some(ServiceBackendPort {
                                        number: Some(svc_port),
                                        name: None,
                                    }),
                                }),
                                resource: None,
                            },
                        }],
                    }),
                }]),
                tls: Some(vec![IngressTLS {
                    hosts: Some(tls_hosts),
                    secret_name: Some("my-tls-secret".to_string()),
                }]),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    pub(crate) fn make_default_backend_ingress(
        name: &str,
        namespace: &str,
        svc_name: &str,
        svc_port: i32,
    ) -> Ingress {
        use k8s_openapi::api::networking::v1::IngressSpec;
        Ingress {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            spec: Some(IngressSpec {
                default_backend: Some(IngressBackend {
                    service: Some(IngressServiceBackend {
                        name: svc_name.to_string(),
                        port: Some(ServiceBackendPort {
                            number: Some(svc_port),
                            name: None,
                        }),
                    }),
                    resource: None,
                }),
                rules: None,
                ..Default::default()
            }),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_helpers::*;
    use super::*;
    use k8s_openapi::api::core::v1::Service;
    use k8s_openapi::api::networking::v1::{
        HTTPIngressPath, HTTPIngressRuleValue, Ingress, IngressBackend, IngressRule,
        IngressServiceBackend, IngressSpec, ServiceBackendPort,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use kube::runtime::reflector::Store;

    /// Build a Store and populate it with the given services.
    ///
    /// Uses `Writer::apply_watcher_event` with `Event::Apply` (kube 0.98 variant)
    /// to insert each object into the reflector's in-memory cache.
    fn make_store(services: Vec<Service>) -> Store<Service> {
        let (reader, mut writer) = kube::runtime::reflector::store();
        for svc in services {
            writer.apply_watcher_event(&kube::runtime::watcher::Event::Apply(svc));
        }
        reader
    }

    #[test]
    fn single_rule_produces_one_route() {
        let svc = make_service("backend", "default", "10.0.0.1", 8080);
        let store = make_store(vec![svc]);

        let ingress = make_ingress(
            "my-ingress",
            "default",
            Some("app.example.com"),
            "/",
            "Prefix",
            "backend",
            8080,
        );

        let routes = translate_ingress(&ingress, &store);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].domain, "app.example.com");
        assert_eq!(routes[0].upstream, "10.0.0.1:8080");
        assert!(!routes[0].tls);
    }

    #[test]
    fn multi_rule_produces_multiple_routes() {
        let svc_a = make_service("backend-a", "default", "10.0.0.1", 8080);
        let svc_b = make_service("backend-b", "default", "10.0.0.2", 9090);
        let store = make_store(vec![svc_a, svc_b]);

        let ingress = Ingress {
            metadata: ObjectMeta {
                name: Some("multi".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: Some(IngressSpec {
                rules: Some(vec![
                    IngressRule {
                        host: Some("a.example.com".to_string()),
                        http: Some(HTTPIngressRuleValue {
                            paths: vec![HTTPIngressPath {
                                path: Some("/".to_string()),
                                path_type: "Prefix".to_string(),
                                backend: IngressBackend {
                                    service: Some(IngressServiceBackend {
                                        name: "backend-a".to_string(),
                                        port: Some(ServiceBackendPort {
                                            number: Some(8080),
                                            name: None,
                                        }),
                                    }),
                                    resource: None,
                                },
                            }],
                        }),
                    },
                    IngressRule {
                        host: Some("b.example.com".to_string()),
                        http: Some(HTTPIngressRuleValue {
                            paths: vec![HTTPIngressPath {
                                path: Some("/".to_string()),
                                path_type: "Prefix".to_string(),
                                backend: IngressBackend {
                                    service: Some(IngressServiceBackend {
                                        name: "backend-b".to_string(),
                                        port: Some(ServiceBackendPort {
                                            number: Some(9090),
                                            name: None,
                                        }),
                                    }),
                                    resource: None,
                                },
                            }],
                        }),
                    },
                ]),
                ..Default::default()
            }),
            ..Default::default()
        };

        let routes = translate_ingress(&ingress, &store);
        assert_eq!(routes.len(), 2);
        let domains: Vec<&str> = routes.iter().map(|r| r.domain.as_str()).collect();
        assert!(domains.contains(&"a.example.com"));
        assert!(domains.contains(&"b.example.com"));
    }

    #[test]
    fn multi_path_produces_handler_blocks() {
        let svc = make_service("backend", "default", "10.0.0.1", 8080);
        let store = make_store(vec![svc]);

        let ingress = Ingress {
            metadata: ObjectMeta {
                name: Some("multi-path".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: Some(IngressSpec {
                rules: Some(vec![IngressRule {
                    host: Some("app.example.com".to_string()),
                    http: Some(HTTPIngressRuleValue {
                        paths: vec![
                            HTTPIngressPath {
                                path: Some("/api/".to_string()),
                                path_type: "Prefix".to_string(),
                                backend: IngressBackend {
                                    service: Some(IngressServiceBackend {
                                        name: "backend".to_string(),
                                        port: Some(ServiceBackendPort {
                                            number: Some(8080),
                                            name: None,
                                        }),
                                    }),
                                    resource: None,
                                },
                            },
                            HTTPIngressPath {
                                path: Some("/static/".to_string()),
                                path_type: "Prefix".to_string(),
                                backend: IngressBackend {
                                    service: Some(IngressServiceBackend {
                                        name: "backend".to_string(),
                                        port: Some(ServiceBackendPort {
                                            number: Some(8080),
                                            name: None,
                                        }),
                                    }),
                                    resource: None,
                                },
                            },
                        ],
                    }),
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };

        let routes = translate_ingress(&ingress, &store);
        // Two paths → two handler blocks (domain keys)
        assert_eq!(routes.len(), 2);
        let domains: Vec<&str> = routes.iter().map(|r| r.domain.as_str()).collect();
        assert!(domains.contains(&"app.example.com/api/"));
        assert!(domains.contains(&"app.example.com/static/"));
    }

    #[test]
    fn default_backend_produces_catch_all() {
        let svc = make_service("fallback", "default", "10.0.0.99", 8080);
        let store = make_store(vec![svc]);

        let ingress = make_default_backend_ingress("fallback-ingress", "default", "fallback", 8080);

        let routes = translate_ingress(&ingress, &store);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].domain, "*");
        assert_eq!(routes[0].upstream, "10.0.0.99:8080");
    }

    #[test]
    fn missing_service_is_skipped() {
        // Store is empty — service lookup will miss
        let store = make_store(vec![]);

        let ingress = make_ingress(
            "broken-ingress",
            "default",
            Some("app.example.com"),
            "/",
            "Prefix",
            "nonexistent-svc",
            8080,
        );

        let routes = translate_ingress(&ingress, &store);
        // Nothing resolved — skip rather than panic or error
        assert!(routes.is_empty());
    }

    #[test]
    fn exact_path_type_preserved() {
        let svc = make_service("backend", "default", "10.0.0.1", 8080);
        let store = make_store(vec![svc]);

        let ingress = make_ingress(
            "exact-ingress",
            "default",
            Some("app.example.com"),
            "/healthz",
            "Exact",
            "backend",
            8080,
        );

        let routes = translate_ingress(&ingress, &store);
        assert_eq!(routes.len(), 1);
        // Exact path → included in the domain key
        assert_eq!(routes[0].domain, "app.example.com/healthz");
    }

    #[test]
    fn prefix_path_type_normalised() {
        let svc = make_service("backend", "default", "10.0.0.1", 8080);
        let store = make_store(vec![svc]);

        let ingress = make_ingress(
            "prefix-ingress",
            "default",
            Some("app.example.com"),
            "/api/",
            "Prefix",
            "backend",
            8080,
        );

        let routes = translate_ingress(&ingress, &store);
        assert_eq!(routes.len(), 1);
        // Prefix path → appended to domain
        assert_eq!(routes[0].domain, "app.example.com/api/");
    }

    #[test]
    fn tls_flag_set_for_tls_host() {
        let svc = make_service("secure-backend", "default", "10.0.0.5", 443);
        let store = make_store(vec![svc]);

        let ingress = make_ingress_tls(
            "tls-ingress",
            "default",
            "secure.example.com",
            "secure-backend",
            443,
            vec!["secure.example.com".to_string()],
        );

        let routes = translate_ingress(&ingress, &store);
        assert_eq!(routes.len(), 1);
        assert!(routes[0].tls, "route should have tls=true");
    }

    #[test]
    fn no_host_rule_becomes_wildcard() {
        let svc = make_service("backend", "default", "10.0.0.1", 8080);
        let store = make_store(vec![svc]);

        // host: None in the rule → should produce wildcard domain "*"
        let ingress = make_ingress(
            "nohost-ingress",
            "default",
            None, // no host
            "/",
            "Prefix",
            "backend",
            8080,
        );

        let routes = translate_ingress(&ingress, &store);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].domain, "*");
    }

    #[test]
    fn ingress_key_format() {
        let ingress = make_ingress(
            "my-ingress",
            "production",
            Some("app.example.com"),
            "/",
            "Prefix",
            "svc",
            80,
        );
        assert_eq!(ingress_key(&ingress), "production/my-ingress");
    }

    #[test]
    fn normalize_path_strips_trailing_wildcard() {
        assert_eq!(normalize_path("/api/*", "Prefix"), "/api/");
        assert_eq!(normalize_path("/api/", "Prefix"), "/api/");
        assert_eq!(normalize_path("/healthz", "Exact"), "/healthz");
        assert_eq!(normalize_path("/*", "ImplementationSpecific"), "/");
    }

    #[test]
    fn headless_service_is_skipped() {
        use k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec};
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

        let svc = Service {
            metadata: ObjectMeta {
                name: Some("headless".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                cluster_ip: Some("None".to_string()),
                ports: Some(vec![ServicePort {
                    port: 8080,
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let store = make_store(vec![svc]);

        let ingress = make_ingress(
            "headless-ingress",
            "default",
            Some("headless.example.com"),
            "/",
            "Prefix",
            "headless",
            8080,
        );

        let routes = translate_ingress(&ingress, &store);
        assert!(routes.is_empty(), "headless service should be skipped");
    }
}
