// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! `DwaarControl` service implementation.
//!
//! This module wires a tonic service that accepts the bidirectional
//! `Channel` RPC and dispatches each inbound `ClientMessage` to a
//! dedicated handler. `Hello` and `Heartbeat` are stateless; the stateful
//! command variants (`AddRoute`, `RemoveRoute`, `SplitTraffic`,
//! `MirrorRequest`) mutate the shared [`RouteTable`] or the split /
//! mirror registries that live in [`crate::routing`].
//!
//! Each mutation produces two outbound messages:
//!
//! 1. A [`pb::CommandAck`] correlated to the original `ack_id` with
//!    `status: "applied"` or `status: "rejected"`.
//! 2. For route-modifying commands, a follow-up [`pb::RouteEvent`] so
//!    Permanu can reconcile its mirror of Dwaar state without polling.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use arc_swap::ArcSwap;
use dwaar_core::route::{self, Route, RouteTable};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_stream::Stream;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Server;
use tonic::{Request, Response, Status, Streaming};
use tracing::{debug, info, warn};

use crate::pb;
use crate::pb::dwaar_control_server::{DwaarControl, DwaarControlServer};
use crate::routing::{MirrorConfig, MirrorRegistry, RouteRegistry, SplitConfig};
use crate::tls::{TlsConfig, TlsError};

/// Channel depth for the per-stream outbound queue. Small on purpose:
/// backpressure is preferable to unbounded memory if Permanu stalls.
const OUTBOUND_CHANNEL_DEPTH: usize = 64;

/// Dwaar version string surfaced in [`pb::HelloAck`].
const DWAAR_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Status strings surfaced in `CommandAck.status`. Mirrored in the
/// substrate contract — do not change casing without coordinating.
pub const STATUS_APPLIED: &str = "applied";
pub const STATUS_REJECTED: &str = "rejected";

/// Errors surfaced by the gRPC server.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to bind gRPC listener on {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: tonic::transport::Error,
    },
    #[error("gRPC server terminated: {0}")]
    Serve(#[from] tonic::transport::Error),
    #[error("TLS configuration error: {0}")]
    Tls(#[from] TlsError),
}

/// Shared server state injected into every channel.
///
/// Cloning is cheap — all fields are `Arc`. Each channel receives its own
/// clone so it can stream outbound messages independently.
#[derive(Clone)]
pub struct DwaarControlService {
    dwaar_instance_id: String,
    route_table: Arc<ArcSwap<RouteTable>>,
    splits: Arc<RouteRegistry>,
    mirrors: Arc<MirrorRegistry>,
}

impl std::fmt::Debug for DwaarControlService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DwaarControlService")
            .field("dwaar_instance_id", &self.dwaar_instance_id)
            .field("routes", &self.route_table.load().len())
            .field("splits", &self.splits.len())
            .field("mirrors", &self.mirrors.len())
            .finish()
    }
}

impl DwaarControlService {
    /// Build a service sharing the main process's route table plus new
    /// split/mirror registries.
    pub fn new(
        dwaar_instance_id: impl Into<String>,
        route_table: Arc<ArcSwap<RouteTable>>,
    ) -> Self {
        Self {
            dwaar_instance_id: dwaar_instance_id.into(),
            route_table,
            splits: Arc::new(RouteRegistry::new()),
            mirrors: Arc::new(MirrorRegistry::new()),
        }
    }

    /// Expose the split registry so the proxy hot path (Week 4) can look
    /// up splits without going through the service.
    pub fn split_registry(&self) -> Arc<RouteRegistry> {
        Arc::clone(&self.splits)
    }

    /// Expose the mirror registry for symmetry with `split_registry`.
    pub fn mirror_registry(&self) -> Arc<MirrorRegistry> {
        Arc::clone(&self.mirrors)
    }

    /// Inject pre-built registries — useful for tests that need to seed
    /// state before the service starts serving.
    #[must_use]
    pub fn with_registries(
        mut self,
        splits: Arc<RouteRegistry>,
        mirrors: Arc<MirrorRegistry>,
    ) -> Self {
        self.splits = splits;
        self.mirrors = mirrors;
        self
    }
}

type ChannelStream = Pin<Box<dyn Stream<Item = Result<pb::ServerMessage, Status>> + Send>>;

#[tonic::async_trait]
impl DwaarControl for DwaarControlService {
    type ChannelStream = ChannelStream;

    async fn channel(
        &self,
        request: Request<Streaming<pb::ClientMessage>>,
    ) -> Result<Response<Self::ChannelStream>, Status> {
        let peer = request
            .remote_addr()
            .map_or_else(|| "unknown".to_string(), |a| a.to_string());
        info!(peer, "dwaar-grpc: control channel opened");

        let mut inbound = request.into_inner();
        let (tx, rx) = mpsc::channel::<Result<pb::ServerMessage, Status>>(OUTBOUND_CHANNEL_DEPTH);
        let svc = self.clone();

        tokio::spawn(async move {
            loop {
                match inbound.message().await {
                    Ok(Some(msg)) => {
                        let replies = svc.handle_client_message(msg);
                        for reply in replies {
                            if tx.send(Ok(reply)).await.is_err() {
                                debug!("dwaar-grpc: downstream dropped, terminating channel");
                                return;
                            }
                        }
                    }
                    Ok(None) => {
                        info!(peer, "dwaar-grpc: control channel closed by peer");
                        break;
                    }
                    Err(status) => {
                        warn!(peer, %status, "dwaar-grpc: control channel errored");
                        let _ = tx.send(Err(status)).await;
                        break;
                    }
                }
            }
        });

        let stream: ChannelStream = Box::pin(ReceiverStream::new(rx));
        Ok(Response::new(stream))
    }
}

impl DwaarControlService {
    /// Translate a single `ClientMessage` into zero-or-more `ServerMessage`s.
    ///
    /// Mutation commands (`AddRoute`, `RemoveRoute`, `SplitTraffic`) emit
    /// two messages on success: the `CommandAck` and a trailing
    /// `RouteEvent`. Validation failures emit only the `CommandAck` with
    /// `status: "rejected"`.
    pub(crate) fn handle_client_message(&self, msg: pb::ClientMessage) -> Vec<pb::ServerMessage> {
        use pb::client_message::Kind as In;
        use pb::server_message::Kind as Out;

        let Some(kind) = msg.kind else {
            return Vec::new();
        };

        let out_vec: Vec<Out> = match kind {
            In::Hello(h) => {
                info!(
                    permanu_instance_id = %h.permanu_instance_id,
                    permanu_version = %h.permanu_version,
                    "dwaar-grpc: hello received"
                );
                vec![Out::HelloAck(pb::HelloAck {
                    dwaar_instance_id: self.dwaar_instance_id.clone(),
                    dwaar_version: DWAAR_VERSION.to_string(),
                })]
            }
            In::Heartbeat(hb) => {
                debug!(sequence = hb.sequence, "dwaar-grpc: heartbeat received");
                vec![Out::HeartbeatAck(pb::HeartbeatAck {
                    sequence: hb.sequence,
                    received_at_unix_ms: now_unix_ms(),
                })]
            }
            In::AddRoute(cmd) => self.handle_add_route(cmd),
            In::RemoveRoute(cmd) => self.handle_remove_route(cmd),
            In::SplitTraffic(cmd) => self.handle_split_traffic(&cmd),
            In::MirrorRequest(cmd) => self.handle_mirror_request(&cmd),
            In::SetHeaderRule(cmd) => vec![not_implemented(cmd.ack_id, "set_header_rule")],
        };

        out_vec
            .into_iter()
            .map(|k| pb::ServerMessage { kind: Some(k) })
            .collect()
    }

    // ─── AddRoute ─────────────────────────────────────────────────────

    fn handle_add_route(&self, cmd: pb::AddRoute) -> Vec<pb::server_message::Kind> {
        let ack_id = cmd.ack_id.clone();
        let Some(route) = cmd.route else {
            return vec![rejected(ack_id, "route field is required")];
        };

        if route.domain.is_empty() {
            return vec![rejected(ack_id, "route.domain is empty")];
        }
        if !route::is_valid_route_key(&route.domain) {
            return vec![rejected(
                ack_id,
                format!("route.domain is invalid: {}", route.domain),
            )];
        }
        let upstream: SocketAddr = match route.upstream_addr.parse() {
            Ok(a) => a,
            Err(e) => {
                return vec![rejected(
                    ack_id,
                    format!("route.upstream_addr invalid: {e}"),
                )];
            }
        };

        let new_route = Route::with_source(
            &route.domain,
            upstream,
            route.tls,
            None,
            Some(format!("dwaar-grpc:{}", route.deploy_id)),
        );
        let domain = new_route.domain.clone();

        self.route_table.rcu(|current| {
            let mut routes = current.all_routes();
            routes.retain(|r| r.domain != domain);
            routes.push(new_route.clone());
            Arc::new(RouteTable::new(routes))
        });

        info!(
            target: "dwaar::grpc::audit",
            action = "route_add",
            principal = "grpc",
            resource = %domain,
            deploy_id = %route.deploy_id,
            "grpc route mutation"
        );

        vec![
            applied(ack_id),
            pb::server_message::Kind::RouteEvent(pb::RouteEvent {
                domain,
                deploy_id: route.deploy_id,
                event_type: "added".into(),
                observed_at_unix_ms: now_unix_ms(),
            }),
        ]
    }

    // ─── RemoveRoute ──────────────────────────────────────────────────

    fn handle_remove_route(&self, cmd: pb::RemoveRoute) -> Vec<pb::server_message::Kind> {
        let ack_id = cmd.ack_id.clone();
        if cmd.domain.is_empty() {
            return vec![rejected(ack_id, "domain is empty")];
        }

        let domain = cmd.domain.to_lowercase();
        let mut removed = false;
        self.route_table.rcu(|current| {
            let before = current.all_routes();
            let before_len = before.len();
            let filtered: Vec<Route> = before.into_iter().filter(|r| r.domain != domain).collect();
            removed = filtered.len() < before_len;
            Arc::new(RouteTable::new(filtered))
        });

        // Also drop any split / mirror state keyed on this domain — leaving
        // orphan split configs pointing at a removed route would be a silent
        // deploy-to-nowhere footgun.
        let split_removed = self.splits.remove_split(&domain);
        let mirror_removed = self.mirrors.remove(&domain);

        if !removed && !split_removed && !mirror_removed {
            return vec![rejected(
                ack_id,
                format!("no route, split, or mirror for domain: {domain}"),
            )];
        }

        info!(
            target: "dwaar::grpc::audit",
            action = "route_remove",
            principal = "grpc",
            resource = %domain,
            deploy_id = %cmd.deploy_id,
            "grpc route mutation"
        );

        vec![
            applied(ack_id),
            pb::server_message::Kind::RouteEvent(pb::RouteEvent {
                domain,
                deploy_id: cmd.deploy_id,
                event_type: "removed".into(),
                observed_at_unix_ms: now_unix_ms(),
            }),
        ]
    }

    // ─── SplitTraffic ─────────────────────────────────────────────────

    fn handle_split_traffic(&self, cmd: &pb::SplitTraffic) -> Vec<pb::server_message::Kind> {
        let ack_id = cmd.ack_id.clone();
        let cfg = match SplitConfig::from_pb(cmd) {
            Ok(c) => c,
            Err(reason) => return vec![rejected(ack_id, reason)],
        };

        let domain = cfg.domain.clone();
        let strategy = cfg.strategy.clone();
        self.splits.upsert_split(cfg);

        info!(
            target: "dwaar::grpc::audit",
            action = "split_traffic_upsert",
            principal = "grpc",
            resource = %domain,
            strategy = %strategy,
            "grpc route mutation"
        );

        vec![
            applied(ack_id),
            pb::server_message::Kind::RouteEvent(pb::RouteEvent {
                domain,
                deploy_id: String::new(),
                event_type: "updated".into(),
                observed_at_unix_ms: now_unix_ms(),
            }),
        ]
    }

    // ─── MirrorRequest ────────────────────────────────────────────────

    fn handle_mirror_request(&self, cmd: &pb::MirrorRequest) -> Vec<pb::server_message::Kind> {
        let ack_id = cmd.ack_id.clone();
        let cfg = match MirrorConfig::from_pb(cmd) {
            Ok(c) => c,
            Err(reason) => return vec![rejected(ack_id, reason)],
        };

        let source_domain = cfg.source_domain.clone();
        let rate = cfg.sample_rate_bps;
        self.mirrors.upsert(cfg);

        info!(
            target: "dwaar::grpc::audit",
            action = "mirror_upsert",
            principal = "grpc",
            resource = %source_domain,
            sample_rate_bps = rate,
            "grpc route mutation"
        );

        // Mirrors don't emit a RouteEvent — the main domain's route is unchanged.
        // Permanu tracks mirror installs via the CommandAck alone.
        vec![applied(ack_id)]
    }
}

fn applied(ack_id: String) -> pb::server_message::Kind {
    pb::server_message::Kind::CommandAck(pb::CommandAck {
        ack_id,
        status: STATUS_APPLIED.to_string(),
        error_message: String::new(),
    })
}

fn rejected(ack_id: String, reason: impl Into<String>) -> pb::server_message::Kind {
    let reason = reason.into();
    warn!(%ack_id, reason = %reason, "dwaar-grpc: command rejected");
    pb::server_message::Kind::CommandAck(pb::CommandAck {
        ack_id,
        status: STATUS_REJECTED.to_string(),
        error_message: reason,
    })
}

fn not_implemented(ack_id: String, op: &'static str) -> pb::server_message::Kind {
    warn!(op, %ack_id, "dwaar-grpc: command not implemented");
    pb::server_message::Kind::CommandAck(pb::CommandAck {
        ack_id,
        status: "not_implemented".to_string(),
        error_message: format!("{op} handler lands in a later wheel"),
    })
}

fn now_unix_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Start the `DwaarControl` gRPC server on `addr` with no shutdown signal.
///
/// Prefer [`start_grpc_server_with_shutdown`] in production — this variant
/// exists for tests and short-lived processes where an explicit shutdown
/// future is overkill.
pub fn start_grpc_server(
    addr: SocketAddr,
    service: DwaarControlService,
    tls: TlsConfig,
) -> JoinHandle<Result<(), Error>> {
    start_grpc_server_with_shutdown(addr, service, tls, std::future::pending::<()>())
}

/// Start the `DwaarControl` gRPC server on `addr`, terminating gracefully
/// when `shutdown` resolves. This is how `dwaar-cli` wires the server into
/// the Pingora server: the shutdown future is a `ShutdownWatch` that fires
/// on SIGTERM.
///
/// Logs a structured `addr / tls_enabled` startup line so operators can
/// confirm the listening configuration from the journal.
pub fn start_grpc_server_with_shutdown<F>(
    addr: SocketAddr,
    service: DwaarControlService,
    tls: TlsConfig,
    shutdown: F,
) -> JoinHandle<Result<(), Error>>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        let tls_enabled = tls.is_enabled();
        let mtls_enabled = tls.is_mutual();
        info!(
            %addr,
            tls_enabled = %tls_enabled,
            mtls_enabled = %mtls_enabled,
            "dwaar-grpc: listening"
        );

        let mut builder = Server::builder();
        if let Some(tls_cfg) = tls.to_tonic() {
            builder = builder.tls_config(tls_cfg).map_err(Error::Serve)?;
        }
        builder
            .add_service(DwaarControlServer::new(service))
            .serve_with_shutdown(addr, shutdown)
            .await
            .map_err(Error::from)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service() -> DwaarControlService {
        let table = Arc::new(ArcSwap::from_pointee(RouteTable::new(Vec::new())));
        DwaarControlService::new("dwaar-test", table)
    }

    fn route(domain: &str, addr: &str, deploy: &str) -> pb::Route {
        pb::Route {
            deploy_id: deploy.into(),
            release_name: String::new(),
            domain: domain.into(),
            upstream_addr: addr.into(),
            tls: false,
            header_match: std::collections::HashMap::new(),
        }
    }

    fn assert_ack(msg: &pb::ServerMessage, expected_ack: &str, expected_status: &str) {
        let Some(pb::server_message::Kind::CommandAck(ack)) = &msg.kind else {
            panic!("expected CommandAck, got {:?}", msg.kind);
        };
        assert_eq!(ack.ack_id, expected_ack, "ack_id must round-trip");
        assert_eq!(
            ack.status, expected_status,
            "status mismatch (error_message = {:?})",
            ack.error_message
        );
    }

    fn assert_route_event(msg: &pb::ServerMessage, domain: &str, event: &str) {
        let Some(pb::server_message::Kind::RouteEvent(ev)) = &msg.kind else {
            panic!("expected RouteEvent, got {:?}", msg.kind);
        };
        assert_eq!(ev.domain, domain);
        assert_eq!(ev.event_type, event);
    }

    #[test]
    fn hello_produces_hello_ack() {
        let svc = service();
        let replies = svc.handle_client_message(pb::ClientMessage {
            kind: Some(pb::client_message::Kind::Hello(pb::Hello {
                permanu_instance_id: "permanu-1".into(),
                permanu_version: "0.1.0".into(),
            })),
        });
        assert_eq!(replies.len(), 1);
        let Some(pb::server_message::Kind::HelloAck(ack)) = &replies[0].kind else {
            panic!("expected HelloAck");
        };
        assert_eq!(ack.dwaar_instance_id, "dwaar-test");
        assert_eq!(ack.dwaar_version, DWAAR_VERSION);
    }

    #[test]
    fn heartbeat_echoes_sequence() {
        let svc = service();
        let replies = svc.handle_client_message(pb::ClientMessage {
            kind: Some(pb::client_message::Kind::Heartbeat(pb::Heartbeat {
                sequence: 42,
                sent_at_unix_ms: 0,
            })),
        });
        let Some(pb::server_message::Kind::HeartbeatAck(ack)) = &replies[0].kind else {
            panic!("expected HeartbeatAck");
        };
        assert_eq!(ack.sequence, 42);
    }

    #[test]
    fn add_route_applies_and_emits_event() {
        let svc = service();
        let replies = svc.handle_client_message(pb::ClientMessage {
            kind: Some(pb::client_message::Kind::AddRoute(pb::AddRoute {
                ack_id: "cmd-1".into(),
                route: Some(route("api.example.com", "127.0.0.1:8080", "d-42")),
            })),
        });

        assert_eq!(replies.len(), 2);
        assert_ack(&replies[0], "cmd-1", STATUS_APPLIED);
        assert_route_event(&replies[1], "api.example.com", "added");

        // Side effect: route table updated.
        let table = svc.route_table.load();
        let r = table.resolve("api.example.com").expect("route installed");
        assert_eq!(r.upstream().expect("upstream").port(), 8080);
        assert_eq!(r.source(), Some("dwaar-grpc:d-42"));
    }

    #[test]
    fn add_route_rejects_missing_route_field() {
        let svc = service();
        let replies = svc.handle_client_message(pb::ClientMessage {
            kind: Some(pb::client_message::Kind::AddRoute(pb::AddRoute {
                ack_id: "cmd-2".into(),
                route: None,
            })),
        });
        assert_eq!(replies.len(), 1);
        assert_ack(&replies[0], "cmd-2", STATUS_REJECTED);
    }

    #[test]
    fn add_route_rejects_invalid_domain() {
        let svc = service();
        let replies = svc.handle_client_message(pb::ClientMessage {
            kind: Some(pb::client_message::Kind::AddRoute(pb::AddRoute {
                ack_id: "cmd-3".into(),
                route: Some(route("../evil", "127.0.0.1:8080", "d")),
            })),
        });
        assert_ack(&replies[0], "cmd-3", STATUS_REJECTED);
    }

    #[test]
    fn add_route_rejects_bad_upstream() {
        let svc = service();
        let replies = svc.handle_client_message(pb::ClientMessage {
            kind: Some(pb::client_message::Kind::AddRoute(pb::AddRoute {
                ack_id: "cmd-4".into(),
                route: Some(route("api.example.com", "bogus", "d")),
            })),
        });
        assert_ack(&replies[0], "cmd-4", STATUS_REJECTED);
    }

    #[test]
    fn remove_route_applies_and_emits_event() {
        let svc = service();
        svc.handle_client_message(pb::ClientMessage {
            kind: Some(pb::client_message::Kind::AddRoute(pb::AddRoute {
                ack_id: "add".into(),
                route: Some(route("api.example.com", "127.0.0.1:8080", "d")),
            })),
        });

        let replies = svc.handle_client_message(pb::ClientMessage {
            kind: Some(pb::client_message::Kind::RemoveRoute(pb::RemoveRoute {
                ack_id: "rm-1".into(),
                domain: "api.example.com".into(),
                deploy_id: "d".into(),
            })),
        });
        assert_eq!(replies.len(), 2);
        assert_ack(&replies[0], "rm-1", STATUS_APPLIED);
        assert_route_event(&replies[1], "api.example.com", "removed");
        assert!(svc.route_table.load().resolve("api.example.com").is_none());
    }

    #[test]
    fn remove_route_rejects_unknown_domain() {
        let svc = service();
        let replies = svc.handle_client_message(pb::ClientMessage {
            kind: Some(pb::client_message::Kind::RemoveRoute(pb::RemoveRoute {
                ack_id: "rm-x".into(),
                domain: "ghost.example.com".into(),
                deploy_id: String::new(),
            })),
        });
        assert_ack(&replies[0], "rm-x", STATUS_REJECTED);
    }

    #[test]
    fn split_traffic_applies_and_records() {
        let svc = service();
        let cmd = pb::SplitTraffic {
            ack_id: "split-1".into(),
            domain: "api.example.com".into(),
            upstreams: vec![
                pb::WeightedUpstream {
                    route: Some(route("api.example.com", "127.0.0.1:1001", "stable")),
                    weight: 90,
                },
                pb::WeightedUpstream {
                    route: Some(route("api.example.com", "127.0.0.1:1002", "canary")),
                    weight: 10,
                },
            ],
            strategy: "canary".into(),
        };
        let replies = svc.handle_client_message(pb::ClientMessage {
            kind: Some(pb::client_message::Kind::SplitTraffic(cmd)),
        });
        assert_eq!(replies.len(), 2);
        assert_ack(&replies[0], "split-1", STATUS_APPLIED);
        assert_route_event(&replies[1], "api.example.com", "updated");

        let snap = svc
            .splits
            .snapshot_for("api.example.com")
            .expect("split recorded");
        assert_eq!(snap.entries.len(), 2);
        assert_eq!(snap.strategy, "canary");

        // Round-robin determinism: roll 0 must land on the 90% bucket.
        assert_eq!(snap.choose_with_roll(0).expect("pick").deploy_id, "stable");
        // Roll at 90 crosses into the canary bucket.
        assert_eq!(snap.choose_with_roll(90).expect("pick").deploy_id, "canary");
    }

    #[test]
    fn split_traffic_rejects_bad_sum() {
        let svc = service();
        let replies = svc.handle_client_message(pb::ClientMessage {
            kind: Some(pb::client_message::Kind::SplitTraffic(pb::SplitTraffic {
                ack_id: "split-bad".into(),
                domain: "api.example.com".into(),
                upstreams: vec![pb::WeightedUpstream {
                    route: Some(route("api.example.com", "127.0.0.1:1001", "stable")),
                    weight: 55,
                }],
                strategy: String::new(),
            })),
        });
        assert_ack(&replies[0], "split-bad", STATUS_REJECTED);
        assert!(svc.splits.is_empty());
    }

    #[test]
    fn mirror_request_applies_and_records() {
        let svc = service();
        let replies = svc.handle_client_message(pb::ClientMessage {
            kind: Some(pb::client_message::Kind::MirrorRequest(pb::MirrorRequest {
                ack_id: "mir-1".into(),
                source_domain: "api.example.com".into(),
                mirror_to: "127.0.0.1:9099".into(),
                sample_rate_bps: 5_000, // 50%
            })),
        });
        // Mirror upserts emit only the CommandAck — no RouteEvent.
        assert_eq!(replies.len(), 1);
        assert_ack(&replies[0], "mir-1", STATUS_APPLIED);
        let m = svc
            .mirrors
            .snapshot_for("api.example.com")
            .expect("mirror recorded");
        assert_eq!(m.mirror_to, "127.0.0.1:9099");
        assert_eq!(m.sample_rate_bps, 5_000);
    }

    #[test]
    fn mirror_request_rejects_overrate() {
        let svc = service();
        let replies = svc.handle_client_message(pb::ClientMessage {
            kind: Some(pb::client_message::Kind::MirrorRequest(pb::MirrorRequest {
                ack_id: "mir-bad".into(),
                source_domain: "api.example.com".into(),
                mirror_to: "127.0.0.1:9099".into(),
                sample_rate_bps: 20_000, // > 10_000
            })),
        });
        assert_ack(&replies[0], "mir-bad", STATUS_REJECTED);
        assert!(svc.mirrors.is_empty());
    }

    #[test]
    fn set_header_rule_still_stubbed() {
        let svc = service();
        let replies = svc.handle_client_message(pb::ClientMessage {
            kind: Some(pb::client_message::Kind::SetHeaderRule(pb::SetHeaderRule {
                ack_id: "hdr".into(),
                domain: "api.example.com".into(),
                header_name: "X-Foo".into(),
                header_value: "bar".into(),
                action: "set".into(),
            })),
        });
        assert_eq!(replies.len(), 1);
        let Some(pb::server_message::Kind::CommandAck(ack)) = &replies[0].kind else {
            panic!("expected CommandAck");
        };
        assert_eq!(ack.ack_id, "hdr");
        assert_eq!(ack.status, "not_implemented");
    }

    #[tokio::test]
    async fn server_shuts_down_on_signal() {
        use std::time::Duration;
        let table = Arc::new(ArcSwap::from_pointee(RouteTable::new(Vec::new())));
        let svc = DwaarControlService::new("dwaar-shutdown", table);
        let addr: SocketAddr = "127.0.0.1:0".parse().expect("valid addr");
        // NB: :0 would yield an ephemeral port, but tonic's Server::serve
        // binds to what we pass — pick 0 and accept the OS-assigned port.
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let handle = start_grpc_server_with_shutdown(addr, svc, TlsConfig::Plaintext, async move {
            let _ = rx.await;
        });

        // Give the server a beat, then fire the shutdown.
        tokio::time::sleep(Duration::from_millis(20)).await;
        let _ = tx.send(());
        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("shutdown within 2s");
        // The join result is Ok, and the inner Result is fine — tonic may
        // return Ok or a benign transport error on a rapid shutdown depending
        // on whether bind succeeded first. Either way the future resolved.
        assert!(result.is_ok(), "task must complete cleanly on shutdown");
    }
}
