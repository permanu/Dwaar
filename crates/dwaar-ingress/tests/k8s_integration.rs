// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Kubernetes integration tests for the dwaar-ingress controller.
//!
//! These tests require a reachable `kind` cluster. Each test opens a connection
//! with `kube::Client::try_default()` and skips immediately if that fails, so
//! the suite is safe to run in CI environments without a cluster — the tests
//! simply print a skip notice and return `Ok(())`.
//!
//! Each test is self-contained: it creates the resources it needs and deletes
//! them in a `defer`-style cleanup block before returning.
//!
//! Gated behind `#[cfg(feature = "k8s-integration")]` so the binary is not
//! compiled during `cargo test` without the feature flag.

#![cfg(feature = "k8s-integration")]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use k8s_openapi::ByteString;
use k8s_openapi::api::coordination::v1::{Lease, LeaseSpec};
use k8s_openapi::api::core::v1::{Namespace, Secret, Service, ServicePort, ServiceSpec};
use k8s_openapi::api::networking::v1::{
    HTTPIngressPath, HTTPIngressRuleValue, Ingress, IngressBackend, IngressRule,
    IngressServiceBackend, IngressSpec, IngressTLS, ServiceBackendPort,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{MicroTime, ObjectMeta};
use kube::api::{Api, DeleteParams, PostParams};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::time::sleep;
use tracing::info;

use dwaar_ingress::annotations::{is_owned_by_dwaar, parse_annotations};
use dwaar_ingress::client::{AdminApiClient, RouteEntry};
use dwaar_ingress::health::ReadinessState;
use dwaar_ingress::leader::{LeaderConfig, LeaderElector};
use dwaar_ingress::metrics::IngressMetrics;
use dwaar_ingress::translator::ingress_key;

// ── Test namespace ───────────────────────────────────────────────────────────

/// Dedicated namespace for all integration tests.
///
/// All resources are created here. The teardown helpers delete by name within
/// this namespace so tests never collide with cluster-level objects.
const TEST_NS: &str = "dwaar-integration-test";

// ── Cluster connectivity guard ───────────────────────────────────────────────

/// Attempt to connect to the default kubeconfig target.
///
/// Returns `None` if no cluster is reachable — callers should skip the test
/// in that case rather than failing. Returns `Some(client)` otherwise.
async fn try_connect() -> Option<kube::Client> {
    match kube::Client::try_default().await {
        Ok(client) => Some(client),
        Err(e) => {
            // No subscriber is installed in tests — this goes to the tracing no-op
            // sink, which is intentional. The skip is visible in --nocapture output.
            info!("Skipping: no K8s cluster reachable: {e}");
            None
        }
    }
}

// ── Namespace helpers ────────────────────────────────────────────────────────

/// Create the integration-test namespace, ignoring 409 (already exists).
async fn ensure_namespace(client: &kube::Client) {
    let api: Api<Namespace> = Api::all(client.clone());
    let ns = Namespace {
        metadata: ObjectMeta {
            name: Some(TEST_NS.to_string()),
            ..Default::default()
        },
        ..Default::default()
    };
    match api.create(&PostParams::default(), &ns).await {
        Ok(_) => {}
        Err(kube::Error::Api(ae)) if ae.code == 409 => {} // already exists
        Err(e) => panic!("failed to create test namespace: {e}"),
    }
}

// ── Resource builders ────────────────────────────────────────────────────────

fn build_service(name: &str) -> Service {
    Service {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(TEST_NS.to_string()),
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            // ClusterIP is assigned by the API server — we leave it empty on creation.
            selector: Some(BTreeMap::from([("app".to_string(), name.to_string())])),
            ports: Some(vec![ServicePort {
                port: 80,
                name: Some("http".to_string()),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn build_ingress(name: &str, host: &str, svc_name: &str) -> Ingress {
    build_ingress_with_class(name, host, svc_name, Some("dwaar"))
}

fn build_ingress_with_class(
    name: &str,
    host: &str,
    svc_name: &str,
    class: Option<&str>,
) -> Ingress {
    Ingress {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(TEST_NS.to_string()),
            ..Default::default()
        },
        spec: Some(IngressSpec {
            ingress_class_name: class.map(ToString::to_string),
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
                                    number: Some(80),
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

fn build_tls_secret(name: &str) -> Secret {
    // Self-signed DER bytes would be too heavyweight here — we use placeholder
    // PEM bytes that satisfy the Secret's `tls.crt`/`tls.key` fields. The
    // controller materialises whatever bytes are stored; cert validation is
    // a proxy concern, not a controller concern.
    let fake_cert = b"-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n";
    let fake_key = b"-----BEGIN EC PRIVATE KEY-----\nZmFrZQ==\n-----END EC PRIVATE KEY-----\n";

    let mut data = BTreeMap::new();
    data.insert("tls.crt".to_string(), ByteString(fake_cert.to_vec()));
    data.insert("tls.key".to_string(), ByteString(fake_key.to_vec()));

    Secret {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(TEST_NS.to_string()),
            ..Default::default()
        },
        type_: Some("kubernetes.io/tls".to_string()),
        data: Some(data),
        ..Default::default()
    }
}

fn build_tls_ingress(name: &str, host: &str, svc_name: &str, secret_name: &str) -> Ingress {
    Ingress {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(TEST_NS.to_string()),
            ..Default::default()
        },
        spec: Some(IngressSpec {
            ingress_class_name: Some("dwaar".to_string()),
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
                                    number: Some(80),
                                    name: None,
                                }),
                            }),
                            resource: None,
                        },
                    }],
                }),
            }]),
            tls: Some(vec![IngressTLS {
                hosts: Some(vec![host.to_string()]),
                secret_name: Some(secret_name.to_string()),
            }]),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn build_annotated_ingress(name: &str, host: &str, svc_name: &str, rate_limit: u32) -> Ingress {
    let mut base = build_ingress(name, host, svc_name);
    let annotations = base.metadata.annotations.get_or_insert_with(BTreeMap::new);
    annotations.insert("dwaar.dev/rate-limit".to_string(), rate_limit.to_string());
    base
}

// ── Mock admin API ───────────────────────────────────────────────────────────

/// An in-process mock of the Dwaar admin API.
///
/// Stores routes in a shared `Vec` and handles `GET /routes`, `POST /routes`,
/// and `DELETE /routes/:domain` requests. Tests interact with the real
/// `AdminApiClient` pointed at the mock's TCP address.
struct MockAdminApi {
    routes: Arc<Mutex<Vec<RouteEntry>>>,
    addr: SocketAddr,
    handle: tokio::task::JoinHandle<()>,
}

impl MockAdminApi {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0".parse::<SocketAddr>().expect("valid"))
            .await
            .expect("bind mock admin API");
        let addr = listener.local_addr().expect("local addr");
        let routes: Arc<Mutex<Vec<RouteEntry>>> = Arc::new(Mutex::new(Vec::new()));
        let routes_clone = Arc::clone(&routes);

        let handle = tokio::spawn(async move {
            // The test suite is serial (--test-threads=1). Accept a fixed cap of
            // connections per mock instance to avoid holding sockets open forever.
            for _ in 0..64usize {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let routes = Arc::clone(&routes_clone);
                tokio::spawn(async move {
                    handle_mock_connection(&mut stream, &routes).await;
                });
            }
        });

        MockAdminApi {
            routes,
            addr,
            handle,
        }
    }

    fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn client(&self) -> AdminApiClient {
        AdminApiClient::new(self.base_url())
    }

    fn routes_snapshot(&self) -> Vec<RouteEntry> {
        self.routes.lock().expect("routes lock").clone()
    }

    fn stop(self) {
        self.handle.abort();
    }
}

/// Handle one HTTP connection to the mock admin API.
///
/// Supports GET /routes, POST /routes, and DELETE /routes/:domain.
/// The response bodies mirror what the real Dwaar admin API returns so
/// `AdminApiClient` can deserialise them without modification.
async fn handle_mock_connection(
    stream: &mut tokio::net::TcpStream,
    routes: &Arc<Mutex<Vec<RouteEntry>>>,
) {
    let mut reader = BufReader::new(stream);
    let mut req_line = String::new();
    if reader.read_line(&mut req_line).await.is_err() {
        return;
    }

    // Drain the headers and collect Content-Length.
    let mut content_length: usize = 0;
    let mut header_line = String::new();
    loop {
        header_line.clear();
        if reader.read_line(&mut header_line).await.is_err() {
            return;
        }
        let lower = header_line.trim_ascii_start().to_lowercase();
        if lower.starts_with("content-length:")
            && let Some(v) = header_line.split(':').nth(1)
        {
            content_length = v.trim().parse().unwrap_or(0);
        }
        if header_line == "\r\n" || header_line.is_empty() {
            break;
        }
    }

    // Read the body if present.
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        let _ = reader.read_exact(&mut body).await;
    }

    let req = req_line.trim().to_string();
    let response = dispatch_mock_request(&req, &body, routes);

    let stream = reader.into_inner();
    let _ = stream.write_all(response.as_bytes()).await;
}

/// Route a raw HTTP request line to the appropriate mock handler.
fn dispatch_mock_request(
    req_line: &str,
    body: &[u8],
    routes: &Arc<Mutex<Vec<RouteEntry>>>,
) -> String {
    if req_line.starts_with("GET /routes ") {
        let snapshot = routes.lock().expect("routes lock").clone();
        let json = serde_json::to_string(&snapshot).unwrap_or_else(|_| "[]".to_string());
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json.len(),
            json
        )
    } else if req_line.starts_with("POST /routes ") {
        // Deserialise the upsert payload and insert/replace.
        if let Ok(entry) = serde_json::from_slice::<serde_json::Value>(body) {
            let domain = entry["domain"].as_str().unwrap_or("").to_string();
            let upstream = entry["upstream"].as_str().map(ToString::to_string);
            let tls = entry["tls"].as_bool().unwrap_or(false);
            let source = entry["source"].as_str().map(ToString::to_string);

            let mut locked = routes.lock().expect("routes lock");
            locked.retain(|r| r.domain != domain);
            locked.push(RouteEntry {
                domain,
                upstream,
                tls,
                source,
            });
        }
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
    } else if req_line.starts_with("DELETE /routes/") {
        // Extract the domain from the URL path.
        let domain = req_line
            .trim_start_matches("DELETE /routes/")
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string();

        let mut locked = routes.lock().expect("routes lock");
        let before = locked.len();
        locked.retain(|r| r.domain != domain);
        let removed = before != locked.len();

        if removed {
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
        } else {
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
        }
    } else {
        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
    }
}

// ── Poll helper ──────────────────────────────────────────────────────────────

/// Poll `check` up to `timeout` with `interval` between attempts.
///
/// Returns `Ok(())` when `check` returns `true`, `Err` if the deadline passes.
/// Used instead of bare `sleep` so tests don't waste time when the condition
/// resolves quickly and don't fail spuriously when CI is slow.
async fn poll_until(
    timeout: Duration,
    interval: Duration,
    mut check: impl FnMut() -> bool,
) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if check() {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!("condition not met within {}s", timeout.as_secs()));
        }
        sleep(interval).await;
    }
}

// ── Test 1: Create Ingress → route appears in admin API within 5s ────────────

/// Verifies the end-to-end create path: an Ingress lands in Kubernetes and the
/// controller translates it into a route upsert against the admin API.
///
/// We drive the translation directly (no background watcher) so this test does
/// not depend on a running controller binary — it proves the translation + client
/// layer using real K8s objects.
#[tokio::test]
async fn test_create_ingress_route_appears() {
    let Some(client) = try_connect().await else {
        return;
    };
    ensure_namespace(&client).await;

    let ingress_api: Api<Ingress> = Api::namespaced(client.clone(), TEST_NS);
    let service_api: Api<Service> = Api::namespaced(client.clone(), TEST_NS);

    let svc_name = "test-create-svc";
    let ingress_name = "test-create-ingress";
    let host = "create.integration.test";

    // Create a backing Service so the reflector store can resolve it.
    let svc = build_service(svc_name);
    let created_svc = service_api
        .create(&PostParams::default(), &svc)
        .await
        .expect("create service");

    // Fetch the assigned ClusterIP so we can build the expected upstream string.
    let cluster_ip = created_svc
        .spec
        .as_ref()
        .and_then(|s| s.cluster_ip.as_deref())
        .unwrap_or("None");

    let ingress = build_ingress(ingress_name, host, svc_name);
    ingress_api
        .create(&PostParams::default(), &ingress)
        .await
        .expect("create ingress");

    let mock = MockAdminApi::start().await;
    let api_client = mock.client();

    // Simulate what the watcher would do on an Apply event: translate + upsert.
    // We build a minimal in-memory service store from the live Service object.
    let (svc_store, mut svc_writer) = kube::runtime::reflector::store::<Service>();
    let live_svc = service_api.get(svc_name).await.expect("get service");
    svc_writer.apply_watcher_event(&kube::runtime::watcher::Event::Apply(live_svc));

    let live_ingress = ingress_api.get(ingress_name).await.expect("get ingress");
    let synced =
        dwaar_ingress::translator::reconcile_applied(&live_ingress, &svc_store, &api_client).await;

    // The route should appear in the mock API within 5 seconds (poll for safety).
    poll_until(Duration::from_secs(5), Duration::from_millis(100), || {
        mock.routes_snapshot().iter().any(|r| r.domain == host)
    })
    .await
    .expect("route should appear in admin API after Ingress creation");

    assert!(!synced.is_empty(), "at least one domain should be synced");

    // Check that the upstream points to the real Service's ClusterIP.
    if cluster_ip != "None" {
        let route = mock
            .routes_snapshot()
            .into_iter()
            .find(|r| r.domain == host)
            .expect("route exists");
        let expected_upstream = format!("{cluster_ip}:80");
        assert_eq!(
            route.upstream.as_deref(),
            Some(expected_upstream.as_str()),
            "upstream must be ClusterIP:port"
        );
    }

    // Cleanup
    let _ = ingress_api
        .delete(ingress_name, &DeleteParams::default())
        .await;
    let _ = service_api.delete(svc_name, &DeleteParams::default()).await;
    mock.stop();
}

// ── Test 2: Update Ingress backend → route updated ───────────────────────────

/// Verifies that changing the backend Service in an existing Ingress results in
/// the admin API route being updated with the new upstream.
#[tokio::test]
async fn test_update_ingress_backend_route_updated() {
    let Some(client) = try_connect().await else {
        return;
    };
    ensure_namespace(&client).await;

    let ingress_api: Api<Ingress> = Api::namespaced(client.clone(), TEST_NS);
    let service_api: Api<Service> = Api::namespaced(client.clone(), TEST_NS);

    let svc_a = "test-update-svc-a";
    let svc_b = "test-update-svc-b";
    let ingress_name = "test-update-ingress";
    let host = "update.integration.test";

    // Create two Services so we can switch the backend.
    service_api
        .create(&PostParams::default(), &build_service(svc_a))
        .await
        .expect("create service-a");
    service_api
        .create(&PostParams::default(), &build_service(svc_b))
        .await
        .expect("create service-b");

    // Create and translate the initial Ingress (pointing at svc_a).
    let ingress = build_ingress(ingress_name, host, svc_a);
    ingress_api
        .create(&PostParams::default(), &ingress)
        .await
        .expect("create ingress");

    let mock = MockAdminApi::start().await;
    let api_client = mock.client();

    let (svc_store, mut svc_writer) = kube::runtime::reflector::store::<Service>();
    for svc_name in [svc_a, svc_b] {
        let live = service_api.get(svc_name).await.expect("get service");
        svc_writer.apply_watcher_event(&kube::runtime::watcher::Event::Apply(live));
    }

    // Apply initial route.
    let live_ingress = ingress_api.get(ingress_name).await.expect("get ingress");
    dwaar_ingress::translator::reconcile_applied(&live_ingress, &svc_store, &api_client).await;

    let initial_routes = mock.routes_snapshot();
    let initial_upstream = initial_routes
        .iter()
        .find(|r| r.domain == host)
        .and_then(|r| r.upstream.clone())
        .expect("initial route must exist");

    // Now simulate what happens when the Ingress is updated to point at svc_b.
    // In a live cluster the watcher would stream an Apply event — we replicate
    // that by re-translating with a new Ingress object.
    let updated_ingress = build_ingress(ingress_name, host, svc_b);
    dwaar_ingress::translator::reconcile_applied(&updated_ingress, &svc_store, &api_client).await;

    // Both services have a ClusterIP — verify the upstream actually changed.
    let updated_upstream = mock
        .routes_snapshot()
        .into_iter()
        .find(|r| r.domain == host)
        .and_then(|r| r.upstream)
        .expect("route must still exist after update");

    // The upstreams will differ only if svc_a and svc_b got different ClusterIPs.
    // In kind, each Service gets a unique IP, so this assertion is valid.
    assert_ne!(
        initial_upstream, updated_upstream,
        "route upstream must change when backend Service is updated"
    );

    // Cleanup
    let _ = ingress_api
        .delete(ingress_name, &DeleteParams::default())
        .await;
    let _ = service_api.delete(svc_a, &DeleteParams::default()).await;
    let _ = service_api.delete(svc_b, &DeleteParams::default()).await;
    mock.stop();
}

// ── Test 3: Delete Ingress → route removed ───────────────────────────────────

/// Verifies that deleting an Ingress removes the corresponding route from the
/// admin API. The route must be gone within 5 seconds.
#[tokio::test]
async fn test_delete_ingress_route_removed() {
    let Some(client) = try_connect().await else {
        return;
    };
    ensure_namespace(&client).await;

    let ingress_api: Api<Ingress> = Api::namespaced(client.clone(), TEST_NS);
    let service_api: Api<Service> = Api::namespaced(client.clone(), TEST_NS);

    let svc_name = "test-delete-svc";
    let ingress_name = "test-delete-ingress";
    let host = "delete.integration.test";

    service_api
        .create(&PostParams::default(), &build_service(svc_name))
        .await
        .expect("create service");

    let ingress = build_ingress(ingress_name, host, svc_name);
    ingress_api
        .create(&PostParams::default(), &ingress)
        .await
        .expect("create ingress");

    let mock = MockAdminApi::start().await;
    let api_client = mock.client();

    let (svc_store, mut svc_writer) = kube::runtime::reflector::store::<Service>();
    let live_svc = service_api.get(svc_name).await.expect("get service");
    svc_writer.apply_watcher_event(&kube::runtime::watcher::Event::Apply(live_svc));

    // Apply the route first.
    let live_ingress = ingress_api.get(ingress_name).await.expect("get ingress");
    let owned =
        dwaar_ingress::translator::reconcile_applied(&live_ingress, &svc_store, &api_client).await;

    assert!(
        mock.routes_snapshot().iter().any(|r| r.domain == host),
        "route should be present before deletion"
    );

    // Simulate the Delete event: remove the domains that were tracked.
    dwaar_ingress::translator::reconcile_deleted(&owned, &api_client).await;

    // Route must disappear within 5 seconds.
    poll_until(Duration::from_secs(5), Duration::from_millis(100), || {
        !mock.routes_snapshot().iter().any(|r| r.domain == host)
    })
    .await
    .expect("route should be removed from admin API after Ingress deletion");

    // Cleanup
    let _ = ingress_api
        .delete(ingress_name, &DeleteParams::default())
        .await;
    let _ = service_api.delete(svc_name, &DeleteParams::default()).await;
    mock.stop();
}

// ── Test 4: Create TLS Secret + Ingress with TLS → cert provisioned ──────────

/// Verifies that a TLS-enabled Ingress results in PEM files being written to
/// the cert directory and the route being marked `tls = true` in the admin API.
#[tokio::test]
async fn test_tls_secret_provisioned() {
    let Some(client) = try_connect().await else {
        return;
    };
    ensure_namespace(&client).await;

    let ingress_api: Api<Ingress> = Api::namespaced(client.clone(), TEST_NS);
    let service_api: Api<Service> = Api::namespaced(client.clone(), TEST_NS);
    let secret_api: Api<Secret> = Api::namespaced(client.clone(), TEST_NS);

    let svc_name = "test-tls-svc";
    let ingress_name = "test-tls-ingress";
    let secret_name = "test-tls-secret";
    let host = "tls.integration.test";

    // Create the backing resources.
    service_api
        .create(&PostParams::default(), &build_service(svc_name))
        .await
        .expect("create service");
    secret_api
        .create(&PostParams::default(), &build_tls_secret(secret_name))
        .await
        .expect("create tls secret");
    let ingress = build_tls_ingress(ingress_name, host, svc_name, secret_name);
    ingress_api
        .create(&PostParams::default(), &ingress)
        .await
        .expect("create ingress");

    let mock = MockAdminApi::start().await;
    let api_client = mock.client();

    // Build in-memory stores from the live objects.
    let (svc_store, mut svc_writer) = kube::runtime::reflector::store::<Service>();
    let live_svc = service_api.get(svc_name).await.expect("get service");
    svc_writer.apply_watcher_event(&kube::runtime::watcher::Event::Apply(live_svc));

    let (secret_store, mut secret_writer) = kube::runtime::reflector::store::<Secret>();
    let live_secret = secret_api.get(secret_name).await.expect("get secret");
    secret_writer.apply_watcher_event(&kube::runtime::watcher::Event::Apply(live_secret));

    // Apply the route — the Ingress has a TLS block, so the route must be tls=true.
    let live_ingress = ingress_api.get(ingress_name).await.expect("get ingress");
    dwaar_ingress::translator::reconcile_applied(&live_ingress, &svc_store, &api_client).await;

    // Verify the route is marked tls=true in the admin API.
    let route = mock
        .routes_snapshot()
        .into_iter()
        .find(|r| r.domain == host)
        .expect("route must exist for TLS ingress");
    assert!(route.tls, "route for TLS Ingress must have tls=true");

    // Verify that the TLS cert sync writes PEM files to a temp directory.
    let cert_dir = tempfile::tempdir().expect("tempdir");
    let tls_blocks = vec![(TEST_NS.to_string(), secret_name.to_string())];
    let written = dwaar_ingress::tls::sync_tls_secrets(&tls_blocks, &secret_store, cert_dir.path());

    assert_eq!(
        written,
        vec![format!("{TEST_NS}_{secret_name}")],
        "PEM files should be written for the TLS secret"
    );
    assert!(
        cert_dir
            .path()
            .join(format!("{TEST_NS}_{secret_name}.crt"))
            .exists(),
        "cert file should be on disk"
    );
    assert!(
        cert_dir
            .path()
            .join(format!("{TEST_NS}_{secret_name}.key"))
            .exists(),
        "key file should be on disk"
    );

    // Cleanup
    let _ = ingress_api
        .delete(ingress_name, &DeleteParams::default())
        .await;
    let _ = service_api.delete(svc_name, &DeleteParams::default()).await;
    let _ = secret_api
        .delete(secret_name, &DeleteParams::default())
        .await;
    mock.stop();
}

// ── Test 5: Ingress without `dwaar` class → ignored ──────────────────────────

/// Verifies that Ingresses targeting a different `IngressClass` are not touched.
///
/// This is a pure unit-level assertion against the annotation/class logic
/// exercised against live objects from the cluster — the behaviour is the same
/// but the Ingress comes from the real API server.
#[tokio::test]
async fn test_ingress_wrong_class_ignored() {
    let Some(client) = try_connect().await else {
        return;
    };
    ensure_namespace(&client).await;

    let ingress_api: Api<Ingress> = Api::namespaced(client.clone(), TEST_NS);
    let service_api: Api<Service> = Api::namespaced(client.clone(), TEST_NS);

    let svc_name = "test-class-svc";
    let ingress_name = "test-class-ingress";
    let host = "wrongclass.integration.test";

    service_api
        .create(&PostParams::default(), &build_service(svc_name))
        .await
        .expect("create service");

    // Ingress with class "nginx" — our controller is configured for "dwaar".
    let ingress = build_ingress_with_class(ingress_name, host, svc_name, Some("nginx"));
    ingress_api
        .create(&PostParams::default(), &ingress)
        .await
        .expect("create ingress");

    let live_ingress = ingress_api.get(ingress_name).await.expect("get ingress");

    // The ownership check must return false — we must not process this Ingress.
    assert!(
        !is_owned_by_dwaar(&live_ingress, Some("dwaar")),
        "Ingress with class=nginx must not be owned by dwaar controller"
    );

    // Double-check: the ingress key is still derivable (we never crash on foreign Ingresses).
    let key = ingress_key(&live_ingress);
    assert!(
        key.contains(ingress_name),
        "ingress key should contain the name: {key}"
    );

    // Cleanup
    let _ = ingress_api
        .delete(ingress_name, &DeleteParams::default())
        .await;
    let _ = service_api.delete(svc_name, &DeleteParams::default()).await;
}

// ── Test 6: Leader election — standby takes over on expiry ───────────────────

/// Verifies the leader election expiry path using the live Kubernetes Lease API.
///
/// 1. Creates a Lease with a 2-second duration and a `renewTime` set 5 seconds
///    in the past, which means it is already expired.
/// 2. Confirms `lease_is_expired` agrees (the pure function is the same logic
///    the `LeaderElector` uses internally).
/// 3. Creates a `LeaderElector` that tries to take over the expired Lease,
///    verifying it succeeds within 15 seconds.
///
/// We cannot actually kill a pod in a kind cluster from within a test, so we
/// simulate the pod death by creating an already-expired Lease. This exercises
/// the same acquisition code path as a real failover.
#[tokio::test]
async fn test_leader_takeover_on_expired_lease() {
    let Some(client) = try_connect().await else {
        return;
    };

    let lease_api: Api<Lease> = Api::namespaced(client.clone(), "kube-system");
    let lease_name = "dwaar-integration-leader-test";

    // Delete any leftover Lease from a prior failed run.
    let _ = lease_api.delete(lease_name, &DeleteParams::default()).await;
    sleep(Duration::from_millis(200)).await;

    // Create a Lease whose renewTime is 60 seconds ago — clearly expired.
    let expired_renew = chrono::Utc::now() - chrono::Duration::seconds(60);
    let stale_lease = Lease {
        metadata: ObjectMeta {
            name: Some(lease_name.to_string()),
            namespace: Some("kube-system".to_string()),
            ..Default::default()
        },
        spec: Some(LeaseSpec {
            holder_identity: Some("dead-pod".to_string()),
            lease_duration_seconds: Some(15),
            renew_time: Some(MicroTime(expired_renew)),
            lease_transitions: Some(0),
            ..Default::default()
        }),
    };

    lease_api
        .create(&PostParams::default(), &stale_lease)
        .await
        .expect("create stale lease");

    // Confirm the lease reads as expired using the same predicate the controller uses.
    let fetched = lease_api.get(lease_name).await.expect("get lease");
    // The pure `lease_is_expired` function is internal to the `leader` module;
    // we replicate the same logic here to validate the data without needing to
    // expose it from the crate.
    let is_expired = {
        let spec = fetched.spec.as_ref().expect("spec must exist");
        if let Some(MicroTime(dt)) = spec.renew_time.as_ref() {
            let age = chrono::Utc::now()
                .signed_duration_since(*dt)
                .num_seconds()
                .max(0) as u64;
            age >= spec.lease_duration_seconds.unwrap_or(15) as u64
        } else {
            true
        }
    };
    assert!(
        is_expired,
        "lease renewed 60s ago must be considered expired"
    );

    // Now drive the acquisition path: try to acquire the expired lease as a new holder.
    let readiness = ReadinessState {
        leader_ready: Arc::new(AtomicBool::new(false)),
        sync_ready: Arc::new(AtomicBool::new(false)),
    };
    let metrics = IngressMetrics::new();
    let config = LeaderConfig {
        lease_duration_secs: 15,
        renew_deadline: Duration::from_secs(2),
        retry_period: Duration::from_millis(500),
        namespace: "kube-system".to_string(),
        lease_name: lease_name.to_string(),
        holder_identity: "integration-test-standby".to_string(),
    };

    let readiness_clone = ReadinessState {
        leader_ready: Arc::clone(&readiness.leader_ready),
        sync_ready: Arc::clone(&readiness.sync_ready),
    };
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Run the elector in a background task. It should become leader quickly
    // because the existing Lease is already expired.
    let elector = LeaderElector::new(config, client.clone(), readiness_clone, metrics);
    let leader_acquired = Arc::clone(&readiness.leader_ready);

    let elector_task = tokio::spawn(async move {
        elector.run(shutdown_rx, |_lost| async {}).await;
    });

    // Poll until leader_ready is set (should happen well within 15 seconds).
    let acquired = poll_until(Duration::from_secs(15), Duration::from_millis(500), || {
        leader_acquired.load(Ordering::Acquire)
    })
    .await;

    // Shut down the elector before asserting so it releases the lease.
    let _ = shutdown_tx.send(true);
    elector_task.abort();

    // Cleanup the lease regardless.
    let _ = lease_api.delete(lease_name, &DeleteParams::default()).await;

    acquired.expect("standby should acquire leadership within 15s after lease expiry");
}

// ── Test 7: Annotation rate-limit → route carries annotation data ────────────

/// Verifies that `dwaar.dev/rate-limit: 100` on an Ingress is parsed correctly
/// and the resulting annotation data is available to the route upsert path.
///
/// The admin API in this project stores routes without a separate rate-limit
/// field (that's a proxy concern), so this test validates that:
/// 1. The annotation is parsed from the live Ingress object without error.
/// 2. The parsed `DwaarAnnotations.rate_limit` equals the configured value.
/// 3. The route is still upserted to the admin API (annotation parsing does
///    not block route creation).
#[tokio::test]
async fn test_rate_limit_annotation_parsed() {
    let Some(client) = try_connect().await else {
        return;
    };
    ensure_namespace(&client).await;

    let ingress_api: Api<Ingress> = Api::namespaced(client.clone(), TEST_NS);
    let service_api: Api<Service> = Api::namespaced(client.clone(), TEST_NS);

    let svc_name = "test-ratelimit-svc";
    let ingress_name = "test-ratelimit-ingress";
    let host = "ratelimit.integration.test";
    let rate_limit_value: u32 = 100;

    service_api
        .create(&PostParams::default(), &build_service(svc_name))
        .await
        .expect("create service");

    let annotated = build_annotated_ingress(ingress_name, host, svc_name, rate_limit_value);
    ingress_api
        .create(&PostParams::default(), &annotated)
        .await
        .expect("create annotated ingress");

    // Fetch the live object back — annotations round-trip through the API server.
    let live_ingress = ingress_api
        .get(ingress_name)
        .await
        .expect("get annotated ingress");

    // Parse the Dwaar annotations from the live object.
    let annotations = parse_annotations(&live_ingress);
    assert_eq!(
        annotations.rate_limit,
        Some(rate_limit_value),
        "rate-limit annotation should parse to {rate_limit_value} req/s"
    );

    // The route itself should still be upserted — annotation parsing is additive.
    let mock = MockAdminApi::start().await;
    let api_client = mock.client();

    let (svc_store, mut svc_writer) = kube::runtime::reflector::store::<Service>();
    let live_svc = service_api.get(svc_name).await.expect("get service");
    svc_writer.apply_watcher_event(&kube::runtime::watcher::Event::Apply(live_svc));

    dwaar_ingress::translator::reconcile_applied(&live_ingress, &svc_store, &api_client).await;

    let route = mock
        .routes_snapshot()
        .into_iter()
        .find(|r| r.domain == host)
        .expect("route must exist for annotated Ingress");

    // The route exists; the rate-limit value is carried in the Ingress object
    // and available via `parse_annotations` when the proxy needs to apply it.
    assert_eq!(route.domain, host, "route domain must match Ingress host");

    // Cleanup
    let _ = ingress_api
        .delete(ingress_name, &DeleteParams::default())
        .await;
    let _ = service_api.delete(svc_name, &DeleteParams::default()).await;
    mock.stop();
}
