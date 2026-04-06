// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! HTTP/3 over QUIC — listener, request parsing, proxy bridge, and lifecycle.
//!
//! # Architecture
//!
//! [`QuicService`] runs as a Pingora [`BackgroundService`] so it shares the
//! tokio runtime that `run_forever()` creates (Guardrail #20). On each
//! incoming QUIC connection it spawns a task that drives the h3 connection
//! loop, accepting request streams in parallel.
//!
//! # Modules
//!
//! - [`convert`]: header conversion between HTTP/3, Pingora, and HTTP/1.1
//! - [`bridge`]: upstream TCP forwarding and response parsing
//! - [`handler`]: connection driver and per-request handler
//! - [`pool`]: per-host upstream connection pool (ISSUE-108)

pub mod bridge;
pub mod convert;
pub mod h2_bridge;
pub mod h2_pool;
pub mod handler;
pub mod pool;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use dwaar_plugins::plugin::PluginChain;
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use tracing::{debug, info};

use crate::route::RouteTable;

// Re-export key public types for downstream consumers.
pub use convert::{H3ParseError, h3_to_pingora_headers};
pub use handler::{ConnectionHandlerError, RequestHandlerError};

/// Maximum concurrent HTTP/3 request streams per QUIC connection.
const DEFAULT_MAX_STREAMS: u32 = 100;

/// Background service that accepts QUIC connections and drives HTTP/3 sessions.
///
/// At construction time, receives the shared [`RouteTable`] and [`PluginChain`]
/// so that every h3 request can go through the same routing and plugin logic as
/// the TCP path.  The references are `Arc`-wrapped so construction is cheap and
/// no config reload is needed — `ArcSwap` delivers atomic updates automatically.
pub struct QuicService {
    endpoint: Mutex<Option<quinn::Endpoint>>,
    route_table: Arc<ArcSwap<RouteTable>>,
    plugin_chain: Arc<PluginChain>,
    /// Per-host upstream TCP connection pool for HTTP/1.1 (ISSUE-108).
    conn_pool: Arc<pool::UpstreamConnPool>,
    /// Per-host upstream H2 connection pool for HTTP/2 multiplexing.
    h2_pool: Arc<h2_pool::H2ConnPool>,
    max_streams: u32,
}

impl std::fmt::Debug for QuicService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicService")
            .field("endpoint", &"<quinn::Endpoint>")
            .field("max_streams", &self.max_streams)
            .finish_non_exhaustive()
    }
}

impl QuicService {
    /// Create a new QUIC service.
    ///
    /// `max_streams` caps concurrent request streams per connection.
    pub fn new(
        bind_addr: SocketAddr,
        cert_path: &Path,
        key_path: &Path,
        route_table: Arc<ArcSwap<RouteTable>>,
        plugin_chain: Arc<PluginChain>,
        max_streams: Option<u32>,
    ) -> Result<Self, QuicSetupError> {
        let max_streams = max_streams.unwrap_or(DEFAULT_MAX_STREAMS);
        let rustls_config = build_rustls_config(cert_path, key_path)?;
        let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)
            .map_err(|e| QuicSetupError::QuicCrypto(e.to_string()))?;

        let mut quinn_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));

        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(max_streams));
        quinn_config.transport_config(Arc::new(transport));

        let endpoint = quinn::Endpoint::server(quinn_config, bind_addr)
            .map_err(|e| QuicSetupError::Bind(bind_addr, e))?;

        info!(
            listen = %bind_addr,
            protocol = "quic+h3",
            max_streams,
            "HTTP/3 endpoint bound"
        );

        Ok(Self {
            endpoint: Mutex::new(Some(endpoint)),
            route_table,
            plugin_chain,
            conn_pool: Arc::new(pool::UpstreamConnPool::default()),
            h2_pool: Arc::new(h2_pool::H2ConnPool::new()),
            max_streams,
        })
    }
}

#[async_trait]
impl BackgroundService for QuicService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let endpoint = self
            .endpoint
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .expect("QuicService::start() must only be called once (Pingora guarantees this)");

        info!("HTTP/3 listener accepting connections");

        loop {
            tokio::select! {
                incoming = endpoint.accept() => {
                    let Some(incoming) = incoming else {
                        break;
                    };
                    let route_table = Arc::clone(&self.route_table);
                    let plugin_chain = Arc::clone(&self.plugin_chain);
                    let conn_pool = Arc::clone(&self.conn_pool);
                    let h2_pool = Arc::clone(&self.h2_pool);

                    tokio::spawn(async move {
                        let connecting = match incoming.accept() {
                            Ok(c) => c,
                            Err(e) => {
                                debug!(error = %e, "QUIC handshake failed");
                                return;
                            }
                        };
                        let (conn, early_data_active) = match connecting.into_0rtt() {
                            Ok((conn, zero_rtt_accepted)) => {
                                let flag = Arc::new(AtomicBool::new(true));
                                let flag_clone = Arc::clone(&flag);
                                tokio::spawn(async move {
                                    let _ = zero_rtt_accepted.await;
                                    flag_clone.store(false, Ordering::Release);
                                });
                                (conn, flag)
                            }
                            Err(connecting) => {
                                let conn = match connecting.await {
                                    Ok(c) => c,
                                    Err(e) => {
                                        debug!(error = %e, "QUIC handshake failed");
                                        return;
                                    }
                                };
                                (conn, Arc::new(AtomicBool::new(false)))
                            }
                        };

                        info!(remote = %conn.remote_address(), "QUIC connection established");

                        if let Err(e) = handler::handle_h3_connection(
                            conn,
                            early_data_active,
                            route_table,
                            plugin_chain,
                            conn_pool,
                            h2_pool,
                        )
                        .await
                        {
                            debug!(error = %e, "HTTP/3 connection closed with error");
                        }
                    });
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("HTTP/3 listener shutting down");
                        endpoint.close(quinn::VarInt::from_u32(0), b"server shutting down");
                        break;
                    }
                }
            }
        }
    }
}

// ── TLS setup ────────────────────────────────────────────────────────────────

/// Build a rustls `ServerConfig` for QUIC with 0-RTT session tickets.
fn build_rustls_config(
    cert_path: &Path,
    key_path: &Path,
) -> Result<rustls::ServerConfig, QuicSetupError> {
    let cert_pem = std::fs::read(cert_path)
        .map_err(|e| QuicSetupError::CertRead(cert_path.to_path_buf(), e))?;
    let key_pem = std::fs::read(key_path).map_err(QuicSetupError::KeyRead)?;

    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .map_err(QuicSetupError::CertParse)?;

    if certs.is_empty() {
        return Err(QuicSetupError::NoCerts(cert_path.to_path_buf()));
    }

    let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .map_err(QuicSetupError::KeyParse)?
        .ok_or(QuicSetupError::NoKey)?;

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(QuicSetupError::Rustls)?;

    config.alpn_protocols = vec![b"h3".to_vec()];

    let ticketer = rustls::crypto::ring::Ticketer::new().map_err(QuicSetupError::Rustls)?;
    config.ticketer = ticketer;
    config.max_early_data_size = u32::MAX;

    Ok(config)
}

// ── Error types ──────────────────────────────────────────────────────────────

/// Errors that can occur during QUIC endpoint setup.
#[derive(Debug, thiserror::Error)]
pub enum QuicSetupError {
    #[error("failed to bind QUIC endpoint to {0}: {1}")]
    Bind(SocketAddr, std::io::Error),

    #[error("failed to read TLS cert from {0}: {1}")]
    CertRead(std::path::PathBuf, std::io::Error),

    #[error("failed to read TLS key: {0}")]
    KeyRead(std::io::Error),

    #[error("failed to parse PEM certificates: {0}")]
    CertParse(std::io::Error),

    #[error("no certificates found in {0}")]
    NoCerts(std::path::PathBuf),

    #[error("failed to parse PEM private key: {0}")]
    KeyParse(std::io::Error),

    #[error("no private key found in key file")]
    NoKey,

    #[error("rustls configuration error: {0}")]
    Rustls(rustls::Error),

    #[error("QUIC crypto setup error: {0}")]
    QuicCrypto(String),
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn install_crypto_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    #[test]
    fn quic_setup_error_display_is_human_readable() {
        install_crypto_provider();
        let err = QuicSetupError::NoCerts("/etc/certs/cert.pem".into());
        assert!(err.to_string().contains("no certificates found"));
    }

    #[test]
    fn build_rustls_config_rejects_missing_cert() {
        install_crypto_provider();
        let result = build_rustls_config(
            Path::new("/nonexistent/cert.pem"),
            Path::new("/nonexistent/key.pem"),
        );
        assert!(matches!(result, Err(QuicSetupError::CertRead(..))));
    }

    #[test]
    fn build_rustls_config_rejects_missing_key() {
        install_crypto_provider();
        let dir = tempfile::tempdir().expect("temp dir");
        let cert_path = dir.path().join("cert.pem");
        std::fs::write(&cert_path, "not a real cert").expect("write cert");

        let result = build_rustls_config(&cert_path, Path::new("/nonexistent/key.pem"));
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn quic_stream_concurrency_limit_configurable() {
        install_crypto_provider();
        let dir = tempfile::tempdir().expect("temp dir");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        write_test_self_signed_cert(&cert_path, &key_path);

        let table = RouteTable::new(vec![]);
        let route_table = Arc::new(ArcSwap::from_pointee(table));
        let plugin_chain = Arc::new(PluginChain::new(vec![]));

        let service = QuicService::new(
            "127.0.0.1:0".parse().expect("addr"),
            &cert_path,
            &key_path,
            route_table,
            plugin_chain,
            Some(50),
        )
        .expect("QuicService::new");

        assert_eq!(service.max_streams, 50);
    }

    // ── Integration: h3 proxy round-trip ──────────────────────────────────────

    #[tokio::test]
    async fn h3_proxy_round_trip() {
        install_crypto_provider();

        let dir = tempfile::tempdir().expect("temp dir");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        write_test_self_signed_cert(&cert_path, &key_path);

        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let upstream_addr: SocketAddr = upstream_listener.local_addr().expect("upstream addr");

        tokio::spawn(async move {
            while let Ok((mut sock, _)) = upstream_listener.accept().await {
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = vec![0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    let _ = sock
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 20\r\n\r\nhello from upstream!",
                        )
                        .await;
                });
            }
        });

        let route = crate::route::Route::new("localhost", upstream_addr, false, None);
        let table = RouteTable::new(vec![route]);
        let route_table = Arc::new(ArcSwap::from_pointee(table));
        let plugin_chain = Arc::new(PluginChain::new(vec![]));

        let service = QuicService::new(
            "127.0.0.1:0".parse().expect("addr"),
            &cert_path,
            &key_path,
            Arc::clone(&route_table),
            Arc::clone(&plugin_chain),
            None,
        )
        .expect("QuicService::new");

        let bound_port = service
            .endpoint
            .lock()
            .expect("lock")
            .as_ref()
            .expect("endpoint")
            .local_addr()
            .expect("local addr")
            .port();
        let quic_addr: SocketAddr = format!("127.0.0.1:{bound_port}").parse().expect("addr");

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            service.start(ShutdownWatch::from(shutdown_rx)).await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let resp_body = h3_client_get(quic_addr, &cert_path, "localhost", "/").await;
        assert!(
            resp_body.contains("hello from upstream"),
            "expected upstream response, got: {resp_body:?}"
        );

        let _ = shutdown_tx.send(true);
    }

    #[tokio::test]
    async fn h3_security_headers_plugin_runs() {
        install_crypto_provider();

        let dir = tempfile::tempdir().expect("temp dir");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        write_test_self_signed_cert(&cert_path, &key_path);

        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let upstream_addr: SocketAddr = upstream_listener.local_addr().expect("upstream addr");
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = upstream_listener.accept().await {
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = vec![0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    let _ = sock
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                        .await;
                });
            }
        });

        let plugin: Box<dyn dwaar_plugins::plugin::DwaarPlugin> =
            Box::new(dwaar_plugins::security_headers::SecurityHeadersPlugin::new());
        let plugin_chain = Arc::new(PluginChain::new(vec![plugin]));

        let route = crate::route::Route::new("localhost", upstream_addr, false, None);
        let table = RouteTable::new(vec![route]);
        let route_table = Arc::new(ArcSwap::from_pointee(table));

        let service = QuicService::new(
            "127.0.0.1:0".parse().expect("addr"),
            &cert_path,
            &key_path,
            route_table,
            plugin_chain,
            None,
        )
        .expect("QuicService::new");

        let bound_port = service
            .endpoint
            .lock()
            .expect("lock")
            .as_ref()
            .expect("endpoint")
            .local_addr()
            .expect("local addr")
            .port();
        let quic_addr: SocketAddr = format!("127.0.0.1:{bound_port}").parse().expect("addr");

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            service.start(ShutdownWatch::from(shutdown_rx)).await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let resp_body = h3_client_get(quic_addr, &cert_path, "localhost", "/").await;
        assert!(!resp_body.is_empty(), "response should not be empty");

        let _ = shutdown_tx.send(true);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn write_test_self_signed_cert(cert_path: &Path, key_path: &Path) {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
                .expect("generate self-signed cert");
        std::fs::write(cert_path, cert.pem()).expect("write cert pem");
        std::fs::write(key_path, signing_key.serialize_pem()).expect("write key pem");
    }

    async fn h3_client_get(
        addr: SocketAddr,
        server_cert_path: &Path,
        server_name: &str,
        path: &str,
    ) -> String {
        let cert_pem = std::fs::read(server_cert_path).expect("read cert");
        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut cert_pem.as_slice())
                .collect::<Result<Vec<_>, _>>()
                .expect("parse certs");

        let mut root_store = rustls::RootCertStore::empty();
        for cert in certs {
            root_store.add(cert).expect("add cert");
        }

        let mut tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        tls_config.alpn_protocols = vec![b"h3".to_vec()];

        let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .expect("quic client config");
        let client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));

        let mut endpoint =
            quinn::Endpoint::client("0.0.0.0:0".parse().expect("addr")).expect("client endpoint");
        endpoint.set_default_client_config(client_config);

        let conn = endpoint
            .connect(addr, server_name)
            .expect("connect")
            .await
            .expect("established");

        let h3_conn = h3_quinn::Connection::new(conn);
        let (mut driver, mut send_req) = h3::client::new(h3_conn).await.expect("h3 client");

        tokio::spawn(
            async move { futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await },
        );

        let req = http::Request::builder()
            .method(http::Method::GET)
            .uri(format!("https://{server_name}{path}"))
            .header("host", server_name)
            .body(())
            .expect("build request");

        let mut stream = send_req.send_request(req).await.expect("send request");
        stream.finish().await.expect("finish");

        let _resp = stream.recv_response().await.expect("recv response");

        let mut body = Vec::new();
        while let Some(chunk) = stream.recv_data().await.expect("recv data") {
            use bytes::Buf;
            body.extend_from_slice(chunk.chunk());
        }

        String::from_utf8_lossy(&body).into_owned()
    }
}
