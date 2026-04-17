// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! `DwaarControl` service scaffold.
//!
//! This module wires a tonic service that accepts the bidirectional
//! `Channel` RPC and routes each inbound `ClientMessage` to a tiny
//! handler. Only `Hello` and `Heartbeat` are fully implemented; every
//! other variant is answered with a `CommandAck { status:
//! "not_implemented" }` so Permanu's side of the stream can be
//! exercised end-to-end before Week 3 lands the mutation handlers.

use std::net::SocketAddr;
use std::pin::Pin;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_stream::Stream;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Server;
use tonic::{Request, Response, Status, Streaming};
use tracing::{debug, info, warn};

use crate::pb;
use crate::pb::dwaar_control_server::{DwaarControl, DwaarControlServer};
use crate::tls::{TlsConfig, TlsError};

/// Channel depth for the per-stream outbound queue. Small on purpose:
/// backpressure is preferable to unbounded memory if Permanu stalls.
const OUTBOUND_CHANNEL_DEPTH: usize = 64;

/// Dwaar version string surfaced in [`pb::HelloAck`].
const DWAAR_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Errors surfaced by the gRPC scaffold.
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

/// Stubbed `DwaarControl` service. Holds the Dwaar instance identity
/// that is echoed back in [`pb::HelloAck`].
#[derive(Debug, Clone)]
pub struct DwaarControlService {
    dwaar_instance_id: String,
}

impl DwaarControlService {
    #[must_use]
    pub fn new(dwaar_instance_id: impl Into<String>) -> Self {
        Self {
            dwaar_instance_id: dwaar_instance_id.into(),
        }
    }
}

impl Default for DwaarControlService {
    fn default() -> Self {
        Self::new("dwaar-unidentified")
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
                        if let Some(reply) = svc.handle_client_message(msg)
                            && tx.send(Ok(reply)).await.is_err()
                        {
                            debug!("dwaar-grpc: downstream dropped, terminating channel");
                            break;
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
    /// Translate a single `ClientMessage` into an optional `ServerMessage`.
    /// Returns `None` when no reply is warranted (currently unreachable — every
    /// known variant produces a reply — but kept as a hook for Week 3 streaming
    /// responses).
    fn handle_client_message(&self, msg: pb::ClientMessage) -> Option<pb::ServerMessage> {
        use pb::client_message::Kind as In;
        use pb::server_message::Kind as Out;

        let kind = msg.kind?;
        let out = match kind {
            In::Hello(h) => {
                info!(
                    permanu_instance_id = %h.permanu_instance_id,
                    permanu_version = %h.permanu_version,
                    "dwaar-grpc: hello received"
                );
                Out::HelloAck(pb::HelloAck {
                    dwaar_instance_id: self.dwaar_instance_id.clone(),
                    dwaar_version: DWAAR_VERSION.to_string(),
                })
            }
            In::Heartbeat(hb) => {
                debug!(sequence = hb.sequence, "dwaar-grpc: heartbeat received");
                Out::HeartbeatAck(pb::HeartbeatAck {
                    sequence: hb.sequence,
                    received_at_unix_ms: now_unix_ms(),
                })
            }
            In::AddRoute(cmd) => not_implemented(cmd.ack_id, "add_route"),
            In::RemoveRoute(cmd) => not_implemented(cmd.ack_id, "remove_route"),
            In::SplitTraffic(cmd) => not_implemented(cmd.ack_id, "split_traffic"),
            In::MirrorRequest(cmd) => not_implemented(cmd.ack_id, "mirror_request"),
            In::SetHeaderRule(cmd) => not_implemented(cmd.ack_id, "set_header_rule"),
        };

        Some(pb::ServerMessage { kind: Some(out) })
    }
}

fn not_implemented(ack_id: String, op: &'static str) -> pb::server_message::Kind {
    warn!(op, %ack_id, "dwaar-grpc: command not implemented (Week 3)");
    pb::server_message::Kind::CommandAck(pb::CommandAck {
        ack_id,
        status: "not_implemented".to_string(),
        error_message: format!("{op} handler lands in Wheel #2 Week 3"),
    })
}

fn now_unix_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Start the `DwaarControl` gRPC server on `addr`, ignoring shutdown.
///
/// Prefer [`start_grpc_server_with_shutdown`] in production. This variant
/// is kept for tests and short-lived processes.
pub fn start_grpc_server(
    addr: SocketAddr,
    service: DwaarControlService,
    tls: TlsConfig,
) -> JoinHandle<Result<(), Error>> {
    start_grpc_server_with_shutdown(addr, service, tls, std::future::pending::<()>())
}

/// Start the `DwaarControl` gRPC server on `addr`, terminating gracefully
/// when `shutdown` resolves. Returns a `JoinHandle` that resolves once the
/// server exits. The caller owns lifecycle — `dwaar-cli` pipes Pingora's
/// `ShutdownWatch` through this so SIGTERM tears down the gRPC listener
/// alongside the HTTP admin server.
///
/// Logs a structured `addr / tls_enabled` startup line so operators can
/// confirm the listening configuration from the journal. When `tls` is
/// [`TlsConfig::Enabled`] the server terminates TLS; when the config also
/// carries a client CA, mutual TLS is enforced.
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

    #[test]
    fn not_implemented_reply_carries_ack_id() {
        let kind = not_implemented("abc-123".to_string(), "add_route");
        let pb::server_message::Kind::CommandAck(ack) = kind else {
            panic!("expected CommandAck");
        };
        assert_eq!(ack.ack_id, "abc-123");
        assert_eq!(ack.status, "not_implemented");
        assert!(ack.error_message.contains("add_route"));
    }

    #[test]
    fn hello_produces_hello_ack() {
        let svc = DwaarControlService::new("dwaar-test");
        let reply = svc
            .handle_client_message(pb::ClientMessage {
                kind: Some(pb::client_message::Kind::Hello(pb::Hello {
                    permanu_instance_id: "permanu-1".into(),
                    permanu_version: "0.1.0".into(),
                })),
            })
            .expect("hello must produce a reply");
        let Some(pb::server_message::Kind::HelloAck(ack)) = reply.kind else {
            panic!("expected HelloAck");
        };
        assert_eq!(ack.dwaar_instance_id, "dwaar-test");
        assert_eq!(ack.dwaar_version, DWAAR_VERSION);
    }

    #[test]
    fn heartbeat_echoes_sequence() {
        let svc = DwaarControlService::new("dwaar-test");
        let reply = svc
            .handle_client_message(pb::ClientMessage {
                kind: Some(pb::client_message::Kind::Heartbeat(pb::Heartbeat {
                    sequence: 42,
                    sent_at_unix_ms: 0,
                })),
            })
            .expect("heartbeat must produce a reply");
        let Some(pb::server_message::Kind::HeartbeatAck(ack)) = reply.kind else {
            panic!("expected HeartbeatAck");
        };
        assert_eq!(ack.sequence, 42);
    }

    #[test]
    fn add_route_returns_not_implemented() {
        let svc = DwaarControlService::new("dwaar-test");
        let reply = svc
            .handle_client_message(pb::ClientMessage {
                kind: Some(pb::client_message::Kind::AddRoute(pb::AddRoute {
                    ack_id: "cmd-1".into(),
                    route: Some(pb::Route {
                        deploy_id: "d1".into(),
                        release_name: "amber-otter-1".into(),
                        domain: "example.test".into(),
                        upstream_addr: "127.0.0.1:8080".into(),
                        tls: false,
                        header_match: std::collections::HashMap::new(),
                    }),
                })),
            })
            .expect("add_route must produce a reply");
        let Some(pb::server_message::Kind::CommandAck(ack)) = reply.kind else {
            panic!("expected CommandAck");
        };
        assert_eq!(ack.ack_id, "cmd-1");
        assert_eq!(ack.status, "not_implemented");
    }
}
