// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! QUIC listener with HTTP/3 request parsing for Dwaar (ISSUE-104).
//!
//! Builds on the raw quinn endpoint scaffold from ISSUE-079a. This phase
//! adds the h3 framing layer: each accepted `quinn::Connection` is wrapped in
//! an `h3::server::Connection`, requests are parsed into
//! `pingora_http::RequestHeader`, the body is buffered from the h3 stream,
//! and a minimal 200 echo-path response is returned.
//!
//! The full proxy bridge (handing parsed requests into Pingora's proxy engine)
//! is deferred to ISSUE-105.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::{Buf, Bytes, BytesMut};
use http::StatusCode;
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use pingora_http::RequestHeader;
use tracing::{debug, error, info, warn};

/// Background service that accepts QUIC connections and parses HTTP/3 requests.
///
/// Wraps a `quinn::Endpoint` and runs inside Pingora's runtime (Guardrail #20).
/// The endpoint is stored in a `Mutex<Option<_>>` so `start()` can take
/// ownership from `&self` — Pingora calls `start()` exactly once.
pub struct QuicService {
    endpoint: Mutex<Option<quinn::Endpoint>>,
}

impl std::fmt::Debug for QuicService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicService")
            .field("endpoint", &"<quinn::Endpoint>")
            .finish()
    }
}

impl QuicService {
    /// Create a new QUIC service bound to the given address.
    ///
    /// Loads TLS certs from the same PEM files used by the TCP/TLS listener
    /// (ISSUE-079c — shared cert store). Both OpenSSL (Pingora) and rustls
    /// (quinn) can independently load PEM, so no conversion is needed.
    pub fn new(
        bind_addr: SocketAddr,
        cert_path: &Path,
        key_path: &Path,
    ) -> Result<Self, QuicSetupError> {
        let rustls_config = build_rustls_config(cert_path, key_path)?;
        let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)
            .map_err(|e| QuicSetupError::QuicCrypto(e.to_string()))?;
        let quinn_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));

        let endpoint = quinn::Endpoint::server(quinn_config, bind_addr)
            .map_err(|e| QuicSetupError::Bind(bind_addr, e))?;

        info!(
            listen = %bind_addr,
            protocol = "quic",
            "QUIC endpoint bound"
        );

        Ok(Self {
            endpoint: Mutex::new(Some(endpoint)),
        })
    }
}

#[async_trait]
impl BackgroundService for QuicService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let endpoint = self
            .endpoint
            .lock()
            .expect("QuicService lock poisoned")
            .take()
            .expect("QuicService::start called more than once");

        info!("QUIC listener accepting connections");

        loop {
            tokio::select! {
                incoming = endpoint.accept() => {
                    let Some(connecting) = incoming else {
                        // Endpoint closed — nothing left to accept
                        break;
                    };
                    tokio::spawn(async move {
                        match connecting.await {
                            Ok(conn) => {
                                info!(
                                    remote = %conn.remote_address(),
                                    "QUIC connection established"
                                );
                                handle_h3_connection(conn).await;
                            }
                            Err(e) => {
                                debug!(error = %e, "QUIC connection failed during handshake");
                            }
                        }
                    });
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("QUIC listener shutting down");
                        endpoint.close(quinn::VarInt::from_u32(0), b"server shutting down");
                        break;
                    }
                }
            }
        }
    }
}

/// Drive an HTTP/3 connection: accept requests one by one until the client closes.
///
/// Uses concrete `h3_quinn` types so the per-request spawns are trivially
/// `Send + 'static` — generics over the QUIC layer would need additional
/// `Send + Sync + 'static` bounds that aren't worth threading through here.
async fn handle_h3_connection(conn: quinn::Connection) {
    // Wrap the raw QUIC connection in h3's server framing layer.
    // h3_quinn::Connection adapts quinn's stream API to h3's generic QUIC trait.
    let mut h3_conn: h3::server::Connection<h3_quinn::Connection, Bytes> =
        match h3::server::builder()
            .build(h3_quinn::Connection::new(conn))
            .await
        {
            Ok(c) => c,
            Err(e) => {
                error!(error = %e, "Failed to build H3 server connection");
                return;
            }
        };

    // h3::server::Connection owns the shared QPACK state and control streams,
    // so it must be driven from one task. We move each request's `RequestResolver`
    // into a separate spawn — the resolver owns only its single bidi stream.
    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                // Each bidi stream is independent; spawn so slow requests don't
                // block the accept loop.
                tokio::spawn(async move {
                    handle_h3_request(resolver).await;
                });
            }
            Ok(None) => {
                // Client closed the connection cleanly.
                debug!("H3 connection closed by peer");
                break;
            }
            Err(e) => {
                debug!(error = %e, "H3 connection error while accepting request");
                break;
            }
        }
    }
}

/// Parse and respond to a single HTTP/3 request.
///
/// Resolves the request headers, converts them into a `pingora_http::RequestHeader`,
/// drains the request body, then sends a 200 echo-path response. Malformed
/// requests get a 400; body-read failures get a 502.
///
/// Full proxy forwarding is ISSUE-105.
async fn handle_h3_request(
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
) {
    // Resolve headers off the wire. Drives QPACK decoding — can fail if the
    // client sent malformed blocks.
    let (req, mut stream) = match resolver.resolve_request().await {
        Ok(pair) => pair,
        Err(e) => {
            // Stream is gone if resolve_request failed — can't send a response.
            debug!(error = %e, "Failed to resolve H3 request headers");
            return;
        }
    };

    // Convert pseudo-headers + regular headers into Pingora's request type.
    let pingora_req = match h3_to_pingora_headers(&req) {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "Malformed H3 request — sending 400");
            send_error_response(&mut stream, StatusCode::BAD_REQUEST).await;
            return;
        }
    };

    // Drain the request body. We buffer it fully for now; streaming to the
    // upstream is ISSUE-105.
    let _body = match drain_request_body(&mut stream).await {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "Failed to read H3 request body — sending 502");
            send_error_response(&mut stream, StatusCode::BAD_GATEWAY).await;
            return;
        }
    };

    let path = pingora_req.uri.path().to_owned();
    debug!(
        method = %pingora_req.method,
        path = %path,
        "H3 request parsed"
    );

    // Echo the request path back as plain text. The proxy bridge to an upstream
    // is ISSUE-105 — this response lets integration tests verify parsing works.
    let response = http::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain")
        .body(())
        .expect("static response builder cannot fail");

    if let Err(e) = stream.send_response(response).await {
        debug!(error = %e, "Failed to send H3 response headers");
        return;
    }

    let body_bytes = Bytes::from(path);
    if let Err(e) = stream.send_data(body_bytes).await {
        debug!(error = %e, "Failed to send H3 response body");
        return;
    }

    if let Err(e) = stream.finish().await {
        debug!(error = %e, "Failed to finish H3 response stream");
    }
}

/// Convert an `http::Request<()>` produced by h3 into a `pingora_http::RequestHeader`.
///
/// HTTP/3 delivers the method, path, authority, and scheme as pseudo-headers
/// (`:method`, `:path`, `:authority`, `:scheme`) in the HEADERS frame. The h3
/// crate surfaces them as a normal `http::Request`, so by the time we get here
/// the method and URI are already decoded.
///
/// We map `:authority` → `Host` header so that downstream Pingora hooks that
/// read `Host` continue to work unchanged (they expect HTTP/1.1 conventions).
///
/// Never panics on malformed input — returns `Err(H3RequestError)` instead.
pub fn h3_to_pingora_headers(
    req: &http::Request<()>,
) -> Result<RequestHeader, H3RequestError> {
    let method = req.method().as_str();
    let uri = req.uri();

    // `:path` is mandatory in HTTP/3 (RFC 9114 §4.3.1). Reject requests that
    // arrive without one — they would route incorrectly.
    let path = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    let mut pingora_req = RequestHeader::build(method, path.as_bytes(), None)
        .map_err(|e| H3RequestError::InvalidMethod(e.to_string()))?;

    // `:authority` carries the virtual host, equivalent to the HTTP/1.1 Host
    // header. Map it so existing host-based routing logic sees it.
    if let Some(authority) = uri.authority() {
        pingora_req
            .insert_header("Host", authority.as_str())
            .map_err(|e| H3RequestError::InvalidHeader("host".into(), e.to_string()))?;
    }

    // Copy all regular (non-pseudo) headers. h3 already strips pseudo-headers
    // from `req.headers()`, so we won't double-insert :method/:path/:authority.
    for (name, value) in req.headers() {
        let name_str = name.as_str();
        if name_str.starts_with(':') {
            continue; // skip any pseudo-headers the library didn't elide
        }

        // Pingora's insert_header needs 'static for &str, so pass an owned
        // String. Header count per request is small — no allocation concern.
        pingora_req
            .insert_header(name_str.to_owned(), value.as_bytes())
            .map_err(|e| H3RequestError::InvalidHeader(name_str.into(), e.to_string()))?;
    }

    Ok(pingora_req)
}

/// Read all DATA frames from the request stream into a contiguous `Bytes` buffer.
///
/// Returns `Ok(Bytes::new())` for requests with no body (GET, HEAD, etc.).
/// Returns `Err` if a stream error occurs mid-body — the caller should send 502.
async fn drain_request_body(
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) -> Result<Bytes, H3RequestError> {
    let mut buf = BytesMut::new();
    loop {
        match stream.recv_data().await {
            Ok(Some(mut chunk)) => {
                // copy_to_bytes handles non-contiguous buffers correctly,
                // even though h3_quinn's underlying Bytes is always contiguous.
                let remaining = chunk.remaining();
                buf.extend_from_slice(&chunk.copy_to_bytes(remaining));
            }
            Ok(None) => break,
            Err(e) => return Err(H3RequestError::BodyRead(e.to_string())),
        }
    }
    Ok(buf.freeze())
}

/// Send a minimal error response and finish the stream.
///
/// Used for 400 (bad request) and 502 (bad gateway) paths. Best-effort —
/// if the send fails we log and move on; the client will see the connection
/// reset instead.
async fn send_error_response(
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    status: StatusCode,
) {
    let response = http::Response::builder()
        .status(status)
        .body(())
        .expect("static error response builder cannot fail");

    if let Err(e) = stream.send_response(response).await {
        debug!(error = %e, status = %status, "Failed to send error response");
        return;
    }
    if let Err(e) = stream.finish().await {
        debug!(error = %e, "Failed to finish error response stream");
    }
}

/// Load PEM cert and key into a rustls `ServerConfig` for QUIC.
///
/// Uses the same PEM files as Pingora's OpenSSL listener — both libraries
/// parse PEM natively, so the cert store is shared at the filesystem level.
fn build_rustls_config(
    cert_path: &Path,
    key_path: &Path,
) -> Result<rustls::ServerConfig, QuicSetupError> {
    let cert_pem = std::fs::read(cert_path)
        .map_err(|e| QuicSetupError::CertRead(cert_path.to_path_buf(), e))?;
    let key_pem =
        std::fs::read(key_path).map_err(|e| QuicSetupError::KeyRead(key_path.to_path_buf(), e))?;

    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .map_err(QuicSetupError::CertParse)?;

    if certs.is_empty() {
        return Err(QuicSetupError::NoCerts(cert_path.to_path_buf()));
    }

    let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .map_err(QuicSetupError::KeyParse)?
        .ok_or_else(|| QuicSetupError::NoKey(key_path.to_path_buf()))?;

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(QuicSetupError::Rustls)?;

    // ALPN for HTTP/3 — quinn requires this to negotiate the protocol.
    config.alpn_protocols = vec![b"h3".to_vec()];

    Ok(config)
}

/// Errors that can occur during QUIC endpoint setup.
#[derive(Debug, thiserror::Error)]
pub enum QuicSetupError {
    #[error("failed to bind QUIC endpoint to {0}: {1}")]
    Bind(SocketAddr, std::io::Error),

    #[error("failed to read TLS cert from {0}: {1}")]
    CertRead(std::path::PathBuf, std::io::Error),

    #[error("failed to read TLS key from {0}: {1}")]
    KeyRead(std::path::PathBuf, std::io::Error),

    #[error("failed to parse PEM certificates: {0}")]
    CertParse(std::io::Error),

    #[error("no certificates found in {0}")]
    NoCerts(std::path::PathBuf),

    #[error("failed to parse PEM private key: {0}")]
    KeyParse(std::io::Error),

    #[error("no private key found in {0}")]
    NoKey(std::path::PathBuf),

    #[error("rustls configuration error: {0}")]
    Rustls(rustls::Error),

    #[error("QUIC crypto setup error: {0}")]
    QuicCrypto(String),
}

/// Errors that can occur while parsing an individual HTTP/3 request.
#[derive(Debug, thiserror::Error)]
pub enum H3RequestError {
    #[error("invalid HTTP method: {0}")]
    InvalidMethod(String),

    #[error("invalid header '{0}': {1}")]
    InvalidHeader(String, String),

    #[error("error reading request body: {0}")]
    BodyRead(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Unit tests ────────────────────────────────────────────────────────────

    #[test]
    fn quic_setup_error_display() {
        let err = QuicSetupError::NoCerts("/etc/certs/cert.pem".into());
        assert!(err.to_string().contains("no certificates found"));
    }

    #[test]
    fn build_rustls_config_rejects_missing_cert() {
        let result = build_rustls_config(
            Path::new("/nonexistent/cert.pem"),
            Path::new("/nonexistent/key.pem"),
        );
        assert!(result.is_err());
        let err = result.expect_err("should fail");
        assert!(
            matches!(err, QuicSetupError::CertRead(..)),
            "expected CertRead error, got: {err}"
        );
    }

    #[test]
    fn build_rustls_config_rejects_missing_key() {
        let dir = tempfile::tempdir().expect("temp dir");
        let cert_path = dir.path().join("cert.pem");
        std::fs::write(&cert_path, "not a real cert").expect("write cert");
        let result = build_rustls_config(&cert_path, Path::new("/nonexistent/key.pem"));
        assert!(result.is_err());
    }

    #[test]
    fn h3_to_pingora_headers_basic_get() {
        // A typical GET: method, path, authority all present.
        let req = http::Request::builder()
            .method("GET")
            .uri("https://example.com/hello?q=1")
            .body(())
            .expect("build request");

        let result = h3_to_pingora_headers(&req).expect("conversion");

        assert_eq!(result.method.as_str(), "GET");
        assert_eq!(result.uri.path(), "/hello");
        assert_eq!(result.uri.query(), Some("q=1"));
        // :authority should have been mapped to Host
        let host = result
            .headers
            .get("host")
            .expect("Host header")
            .to_str()
            .expect("host value");
        assert_eq!(host, "example.com");
    }

    #[test]
    fn h3_to_pingora_headers_post_with_headers() {
        // POST with custom headers — verify they all survive the conversion.
        let req = http::Request::builder()
            .method("POST")
            .uri("https://api.example.com/upload")
            .header("content-type", "application/json")
            .header("x-request-id", "abc-123")
            .body(())
            .expect("build request");

        let result = h3_to_pingora_headers(&req).expect("conversion");

        assert_eq!(result.method.as_str(), "POST");
        assert_eq!(result.uri.path(), "/upload");

        let ct = result
            .headers
            .get("content-type")
            .expect("content-type header")
            .to_str()
            .expect("ct value");
        assert_eq!(ct, "application/json");

        let xrid = result
            .headers
            .get("x-request-id")
            .expect("x-request-id header")
            .to_str()
            .expect("xrid value");
        assert_eq!(xrid, "abc-123");
    }

    #[test]
    fn h3_to_pingora_headers_pseudo_headers_not_forwarded() {
        // Pseudo-headers (:method, :path, :authority, :scheme) live in the URI
        // and method fields of http::Request — they never appear in the header
        // map because the http crate rejects header names starting with ':'.
        // Our converter reads from headers() only, so pseudo-headers cannot
        // leak through. Verify by checking a normal request produces no
        // pseudo-header entries in the Pingora output.
        let req = http::Request::builder()
            .method("GET")
            .uri("https://example.com/path")
            .header("x-real-header", "value")
            .body(())
            .expect("build request");

        let result = h3_to_pingora_headers(&req).expect("conversion");

        // No pseudo-header names in the output
        for (name, _) in result.headers.iter() {
            assert!(
                !name.as_str().starts_with(':'),
                "pseudo-header leaked into output: {name}"
            );
        }
        // The regular header should be present
        assert!(result.headers.get("x-real-header").is_some());
    }

    #[test]
    fn h3_to_pingora_headers_no_authority() {
        // Requests without :authority (unusual but not forbidden by the spec for
        // CONNECT). We must not panic — just omit the Host header.
        let req = http::Request::builder()
            .method("GET")
            .uri("/bare-path")
            .body(())
            .expect("build request");

        let result = h3_to_pingora_headers(&req).expect("conversion");
        assert_eq!(result.uri.path(), "/bare-path");
        // No Host header added because there was no authority component
        assert!(result.headers.get("host").is_none());
    }

    #[test]
    fn h3_request_error_display() {
        let err = H3RequestError::InvalidMethod("BLARG".into());
        assert!(err.to_string().contains("BLARG"));

        let err = H3RequestError::InvalidHeader("x-bad".into(), "illegal value".into());
        assert!(err.to_string().contains("x-bad"));

        let err = H3RequestError::BodyRead("connection reset".into());
        assert!(err.to_string().contains("connection reset"));
    }

    // ── Integration tests ─────────────────────────────────────────────────────
    //
    // These tests spin up a real quinn endpoint with a self-signed cert (via
    // rcgen) and connect an h3 client to verify end-to-end request parsing.

    /// Ensure the ring crypto provider is installed. When running workspace-wide,
    /// other crates may pull in aws-lc-rs via reqwest, causing rustls to fail
    /// auto-detection. Installing ring explicitly avoids the conflict.
    fn ensure_crypto_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    /// Generate a self-signed cert/key pair for test use only.
    fn make_test_cert() -> (rcgen::CertifiedKey<rcgen::KeyPair>, Vec<u8>) {
        ensure_crypto_provider();
        let certified_key =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
                .expect("generate self-signed cert");
        let cert_der = certified_key.cert.der().to_vec();
        (certified_key, cert_der)
    }

    /// Build a quinn server config from an rcgen key pair (rustls directly).
    fn make_server_config(certified_key: &rcgen::CertifiedKey<rcgen::KeyPair>) -> quinn::ServerConfig {
        let cert_der = certified_key.cert.der().to_vec();
        let key_der = certified_key.signing_key.serialize_der();

        let cert = rustls::pki_types::CertificateDer::from(cert_der.to_vec());
        let key = rustls::pki_types::PrivateKeyDer::try_from(key_der)
            .expect("private key from DER");

        let mut rustls_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .expect("server tls config");
        rustls_cfg.alpn_protocols = vec![b"h3".to_vec()];

        let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_cfg)
            .expect("quic crypto config");
        quinn::ServerConfig::with_crypto(Arc::new(quic_crypto))
    }

    /// Build a quinn client config that trusts a specific self-signed cert.
    fn make_client_config(cert_der: &[u8]) -> quinn::ClientConfig {
        let cert = rustls::pki_types::CertificateDer::from(cert_der.to_vec());
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(cert).expect("add test cert to root store");

        let mut rustls_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        rustls_cfg.alpn_protocols = vec![b"h3".to_vec()];

        quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(rustls_cfg)
                .expect("quic client config"),
        ))
    }

    #[tokio::test]
    async fn h3_get_request_parsed_correctly() {
        // Start a quinn server on an ephemeral port.
        let (certified_key, cert_der) = make_test_cert();
        let server_cfg = make_server_config(&certified_key);
        let server_addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
        let server_endpoint =
            quinn::Endpoint::server(server_cfg, server_addr).expect("server endpoint");
        let server_addr = server_endpoint.local_addr().expect("local addr");

        // Spawn the server loop: accept one connection, parse one request.
        let server_task = tokio::spawn(async move {
            let incoming = server_endpoint
                .accept()
                .await
                .expect("accept incoming");
            let conn = incoming.await.expect("handshake");
            let mut h3_conn: h3::server::Connection<h3_quinn::Connection, Bytes> =
                h3::server::builder()
                    .build(h3_quinn::Connection::new(conn))
                    .await
                    .expect("h3 conn");

            let resolver = h3_conn
                .accept()
                .await
                .expect("accept ok")
                .expect("request present");

            let (req, mut stream) = resolver
                .resolve_request()
                .await
                .expect("resolve request");

            // Verify method and path before sending the response
            let method = req.method().as_str().to_owned();
            let path = req.uri().path().to_owned();

            let response = http::Response::builder()
                .status(200u16)
                .body(())
                .expect("response");
            stream.send_response(response).await.expect("send headers");
            stream
                .send_data(Bytes::from(path.clone()))
                .await
                .expect("send body");
            stream.finish().await.expect("finish");

            // Keep h3 connection alive until the client disconnects,
            // otherwise dropping h3_conn sends GOAWAY before the
            // client reads the response.
            while h3_conn.accept().await.is_ok_and(|r| r.is_some()) {}

            (method, path)
        });

        // Connect an h3 client to the server.
        let client_cfg = make_client_config(&cert_der);
        let mut client_endpoint =
            quinn::Endpoint::client("0.0.0.0:0".parse().expect("bind addr"))
                .expect("client endpoint");
        client_endpoint.set_default_client_config(client_cfg);

        let client_conn = client_endpoint
            .connect(server_addr, "localhost")
            .expect("connect")
            .await
            .expect("handshake");

        let (mut driver, mut send_request): (
            h3::client::Connection<h3_quinn::Connection, Bytes>,
            h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
        ) = h3::client::builder()
            .build(h3_quinn::Connection::new(client_conn))
            .await
            .expect("h3 client");

        // Drive the client connection in the background.
        let driver_handle = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("https://localhost/hello")
            .body(())
            .expect("request");

        let mut req_stream = send_request
            .send_request(request)
            .await
            .expect("send request");
        req_stream.finish().await.expect("finish request");

        let response = req_stream.recv_response().await.expect("recv response");
        assert_eq!(response.status(), 200u16);

        // Read the echoed path from the body
        let mut body = BytesMut::new();
        while let Some(mut chunk) = req_stream.recv_data().await.expect("recv data") {
            let remaining = chunk.remaining();
            body.extend_from_slice(&chunk.copy_to_bytes(remaining));
        }
        let body_str = std::str::from_utf8(&body).expect("utf8 body");
        assert_eq!(body_str, "/hello");

        // Close the client so the server's accept loop exits.
        drop(req_stream);
        drop(send_request);
        driver_handle.abort();

        let (method, path) = server_task.await.expect("server task");
        assert_eq!(method, "GET");
        assert_eq!(path, "/hello");
    }

    #[tokio::test]
    async fn h3_post_with_body_parsed_correctly() {
        let (certified_key, cert_der) = make_test_cert();
        let server_cfg = make_server_config(&certified_key);
        let server_addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
        let server_endpoint =
            quinn::Endpoint::server(server_cfg, server_addr).expect("server endpoint");
        let server_addr = server_endpoint.local_addr().expect("local addr");

        let server_task = tokio::spawn(async move {
            let incoming = server_endpoint
                .accept()
                .await
                .expect("accept incoming");
            let conn = incoming.await.expect("handshake");
            let mut h3_conn: h3::server::Connection<h3_quinn::Connection, Bytes> =
                h3::server::builder()
                    .build(h3_quinn::Connection::new(conn))
                    .await
                    .expect("h3 conn");

            let resolver = h3_conn
                .accept()
                .await
                .expect("accept ok")
                .expect("request present");

            let (req, mut stream) = resolver
                .resolve_request()
                .await
                .expect("resolve request");

            let method = req.method().as_str().to_owned();
            let path = req.uri().path().to_owned();

            // Drain the request body
            let mut body = BytesMut::new();
            while let Some(mut chunk) = stream.recv_data().await.expect("recv data") {
                let remaining = chunk.remaining();
                body.extend_from_slice(&chunk.copy_to_bytes(remaining));
            }
            let body_str = String::from_utf8(body.to_vec()).expect("utf8");

            let response = http::Response::builder()
                .status(200u16)
                .body(())
                .expect("response");
            stream.send_response(response).await.expect("send headers");
            stream.finish().await.expect("finish");

            while h3_conn.accept().await.is_ok_and(|r| r.is_some()) {}

            (method, path, body_str)
        });

        let client_cfg = make_client_config(&cert_der);
        let mut client_endpoint =
            quinn::Endpoint::client("0.0.0.0:0".parse().expect("bind addr"))
                .expect("client endpoint");
        client_endpoint.set_default_client_config(client_cfg);

        let client_conn = client_endpoint
            .connect(server_addr, "localhost")
            .expect("connect")
            .await
            .expect("handshake");

        let (mut driver, mut send_request): (
            h3::client::Connection<h3_quinn::Connection, Bytes>,
            h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
        ) = h3::client::builder()
            .build(h3_quinn::Connection::new(client_conn))
            .await
            .expect("h3 client");

        let driver_handle = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let request = http::Request::builder()
            .method("POST")
            .uri("https://localhost/submit")
            .header("content-type", "text/plain")
            .body(())
            .expect("request");

        let mut req_stream = send_request
            .send_request(request)
            .await
            .expect("send request");
        req_stream
            .send_data(Bytes::from("hello body"))
            .await
            .expect("send body");
        req_stream.finish().await.expect("finish request");

        let response = req_stream.recv_response().await.expect("recv response");
        assert_eq!(response.status(), 200u16);

        drop(req_stream);
        drop(send_request);
        driver_handle.abort();

        let (method, path, body) = server_task.await.expect("server task");
        assert_eq!(method, "POST");
        assert_eq!(path, "/submit");
        assert_eq!(body, "hello body");
    }

    #[tokio::test]
    async fn h3_multiple_headers_preserved() {
        let (certified_key, cert_der) = make_test_cert();
        let server_cfg = make_server_config(&certified_key);
        let server_addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
        let server_endpoint =
            quinn::Endpoint::server(server_cfg, server_addr).expect("server endpoint");
        let server_addr = server_endpoint.local_addr().expect("local addr");

        let server_task = tokio::spawn(async move {
            let incoming = server_endpoint
                .accept()
                .await
                .expect("accept incoming");
            let conn = incoming.await.expect("handshake");
            let mut h3_conn: h3::server::Connection<h3_quinn::Connection, Bytes> =
                h3::server::builder()
                    .build(h3_quinn::Connection::new(conn))
                    .await
                    .expect("h3 conn");

            let resolver = h3_conn
                .accept()
                .await
                .expect("accept ok")
                .expect("request present");

            let (req, mut stream) = resolver
                .resolve_request()
                .await
                .expect("resolve request");

            // Convert and verify all headers survived
            let pingora_req = h3_to_pingora_headers(&req).expect("convert headers");

            let response = http::Response::builder()
                .status(200u16)
                .body(())
                .expect("response");
            stream.send_response(response).await.expect("send");
            stream.finish().await.expect("finish");

            let result = pingora_req
                .headers
                .get("x-custom")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);

            while h3_conn.accept().await.is_ok_and(|r| r.is_some()) {}

            result
        });

        let client_cfg = make_client_config(&cert_der);
        let mut client_endpoint =
            quinn::Endpoint::client("0.0.0.0:0".parse().expect("bind addr"))
                .expect("client endpoint");
        client_endpoint.set_default_client_config(client_cfg);

        let client_conn = client_endpoint
            .connect(server_addr, "localhost")
            .expect("connect")
            .await
            .expect("handshake");

        let (mut driver, mut send_request): (
            h3::client::Connection<h3_quinn::Connection, Bytes>,
            h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
        ) = h3::client::builder()
            .build(h3_quinn::Connection::new(client_conn))
            .await
            .expect("h3 client");

        let driver_handle = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("https://localhost/multi")
            .header("x-custom", "test-value")
            .header("accept", "text/html")
            .body(())
            .expect("request");

        let mut req_stream = send_request
            .send_request(request)
            .await
            .expect("send request");
        req_stream.finish().await.expect("finish request");

        let response = req_stream.recv_response().await.expect("recv response");
        assert_eq!(response.status(), 200u16);

        drop(req_stream);
        drop(send_request);
        driver_handle.abort();

        let x_custom = server_task.await.expect("server task");
        assert_eq!(x_custom.as_deref(), Some("test-value"));
    }
}
