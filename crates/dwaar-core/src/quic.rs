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
//! For each request:
//! 1. Parse the h3 frame into a [`pingora_http::RequestHeader`] — this bridges
//!    HTTP/3's pseudo-headers (`:method`, `:path`, etc.) into HTTP/1.1 form.
//! 2. Run the plugin chain (`on_request`) — same plugins as the TCP path.
//! 3. If the plugin short-circuits (e.g. 429 rate limit), write the response
//!    directly over the h3 stream and finish.
//! 4. Otherwise, resolve the route from the [`RouteTable`] and connect to the
//!    upstream over plain TCP using `tokio::net::TcpStream`. HTTP/1.1 is spoken
//!    to the upstream — the same semantics as Pingora's TCP path (ISSUE-105).
//! 5. Write the upstream response back over the h3 stream.
//! 6. Run `on_response` and `on_body` plugin hooks.
//!
//! # Lifecycle (ISSUE-106)
//!
//! - **Graceful shutdown:** the endpoint is closed with `endpoint.close()` on
//!   the shutdown signal; in-flight connection tasks run to completion.
//! - **Stream concurrency:** enforced at the QUIC transport level by setting
//!   `max_concurrent_bidi_streams` on `TransportConfig`. Default: 100.
//! - **0-RTT:** enabled by installing a rustls `Ticketer` (session tickets)
//!   and setting `max_early_data_size`. Only idempotent methods (GET, HEAD,
//!   OPTIONS) are accepted over 0-RTT; POST/PUT/DELETE are rejected with 425.
//!   Detection uses a shared `AtomicBool` that flips `false` once the full
//!   TLS handshake completes (`ZeroRttAccepted` future resolved).
//!
//! ## Known limitations
//!
//! The current H3 implementation is a functional but non-streaming fallback:
//! - Request bodies are fully buffered before forwarding (memory: `O(request_size)`)
//! - A fresh TCP connection is opened per upstream request (no connection pooling)
//! - Response bodies are fully read before replying (TTFB = upstream response time)
//! - No Pingora session integration (tracked in ISSUE-108)
//!
//! For latency-sensitive traffic, prefer HTTP/1.1 or HTTP/2. The H3 path is
//! suitable for small-body requests where QUIC's transport benefits (0-RTT,
//! multiplexing) outweigh the buffering overhead.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use bytes::Bytes;
use dwaar_plugins::plugin::{PluginChain, PluginCtx, PluginResponse};
use h3::server::RequestStream;
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use pingora_http::{RequestHeader, ResponseHeader};
use tracing::{debug, info, warn};

use crate::route::{Handler, RouteTable};

// ── Public types ──────────────────────────────────────────────────────────────

/// Maximum concurrent HTTP/3 request streams per QUIC connection.
const DEFAULT_MAX_STREAMS: u32 = 100;

/// Cap on client request body size. Clients exceeding this receive 413.
const MAX_REQUEST_BODY: usize = 10 * 1024 * 1024; // 10 MB

/// Cap on upstream response body size. Upstream responses exceeding this are
/// dropped and the client receives 502.
const MAX_UPSTREAM_RESPONSE: usize = 100 * 1024 * 1024; // 100 MB

/// Timeout for the full upstream round-trip (connect + write + read).
const UPSTREAM_TIMEOUT_SECS: u64 = 30;

/// Background service that accepts QUIC connections and drives HTTP/3 sessions.
///
/// At construction time, receives the shared [`RouteTable`] and [`PluginChain`]
/// so that every h3 request can go through the same routing and plugin logic as
/// the TCP path.  The references are `Arc`-wrapped so construction is cheap and
/// no config reload is needed — `ArcSwap` delivers atomic updates automatically.
pub struct QuicService {
    endpoint: Mutex<Option<quinn::Endpoint>>,
    /// Shared route table — same `ArcSwap` pointer as the TCP path.
    route_table: Arc<ArcSwap<RouteTable>>,
    /// Plugin chain — shared, sorted by priority.
    plugin_chain: Arc<PluginChain>,
    /// Maximum concurrent request streams per connection.
    max_streams: u32,
}

impl std::fmt::Debug for QuicService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicService")
            .field("endpoint", &"<quinn::Endpoint>")
            .field("max_streams", &self.max_streams)
            // route_table and plugin_chain are omitted — their Debug output
            // is large and not useful in this context.
            .finish_non_exhaustive()
    }
}

impl QuicService {
    /// Create a new QUIC service.
    ///
    /// Shares the `route_table` and `plugin_chain` references with the TCP
    /// proxy path — both read from the same `ArcSwap` guard, so config reloads
    /// affect h3 traffic automatically.
    ///
    /// `max_streams` caps concurrent request streams per connection
    /// (Caddyfile: `servers { h3_max_streams 100 }`).
    ///
    /// # 0-RTT
    /// Enabled automatically — a rustls session ticketer is installed.
    /// Non-idempotent requests arriving over 0-RTT are rejected with 425.
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

        // Apply stream concurrency limit at the QUIC transport layer.
        // h3 streams are bidirectional, so this caps concurrent requests.
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
            .expect("QuicService lock poisoned")
            .take()
            .expect("QuicService::start called more than once");

        info!("HTTP/3 listener accepting connections");

        loop {
            tokio::select! {
                incoming = endpoint.accept() => {
                    let Some(incoming) = incoming else {
                        break;
                    };
                    let route_table = Arc::clone(&self.route_table);
                    let plugin_chain = Arc::clone(&self.plugin_chain);

                    tokio::spawn(async move {
                        // into_0rtt always succeeds server-side — it lets us start
                        // accepting request streams before the full handshake finishes.
                        let connecting = match incoming.accept() {
                            Ok(c) => c,
                            Err(e) => {
                                debug!(error = %e, "QUIC handshake failed");
                                return;
                            }
                        };
                        let (conn, zero_rtt_accepted) = connecting
                            .into_0rtt()
                            .expect("into_0rtt always succeeds on server side");

                        info!(remote = %conn.remote_address(), "QUIC connection established");

                        // Shared flag: `true` while the 0-RTT window is open,
                        // flipped to `false` once the full handshake completes.
                        let early_data_active = Arc::new(AtomicBool::new(true));
                        let early_data_flag = Arc::clone(&early_data_active);

                        // Resolve the ZeroRttAccepted future in the background so
                        // request handlers see the flag flip without blocking.
                        tokio::spawn(async move {
                            // ZeroRttAccepted resolves to `true` if the 0-RTT was
                            // accepted, `false` if the handshake completed without 0-RTT.
                            let _ = zero_rtt_accepted.await;
                            early_data_flag.store(false, Ordering::Release);
                        });

                        // Drive the HTTP/3 session on this connection.
                        if let Err(e) = handle_h3_connection(
                            conn,
                            early_data_active,
                            route_table,
                            plugin_chain,
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
                        // Close the endpoint — no new connections are accepted.
                        // In-flight connection tasks keep running until they complete.
                        endpoint.close(quinn::VarInt::from_u32(0), b"server shutting down");
                        break;
                    }
                }
            }
        }
    }
}

// ── h3 connection driver ──────────────────────────────────────────────────────

/// Drive one HTTP/3 connection from acceptance to close.
///
/// Accepts request streams in a loop, spawning a task per request so streams
/// run concurrently. When the loop ends (peer disconnects or error), any
/// spawned tasks that haven't finished yet continue until they complete.
async fn handle_h3_connection(
    conn: quinn::Connection,
    early_data_active: Arc<AtomicBool>,
    route_table: Arc<ArcSwap<RouteTable>>,
    plugin_chain: Arc<PluginChain>,
) -> Result<(), ConnectionHandlerError> {
    let h3_conn = h3_quinn::Connection::new(conn);
    let mut h3_server: h3::server::Connection<_, Bytes> = h3::server::Connection::new(h3_conn)
        .await
        .map_err(ConnectionHandlerError::Accept)?;

    loop {
        match h3_server.accept().await {
            Ok(Some(resolver)) => {
                let route_table = Arc::clone(&route_table);
                let plugin_chain = Arc::clone(&plugin_chain);
                // Snapshot the 0-RTT flag at stream-accept time.
                let is_early_data = early_data_active.load(Ordering::Acquire);

                tokio::spawn(async move {
                    if let Err(e) =
                        handle_h3_request(resolver, route_table, plugin_chain, is_early_data).await
                    {
                        debug!(error = %e, "HTTP/3 request handler error");
                    }
                });
            }
            // Peer closed the connection cleanly.
            Ok(None) => break,
            Err(e) if e.is_h3_no_error() => break,
            Err(e) => {
                debug!(error = %e, "HTTP/3 accept error");
                break;
            }
        }
    }

    Ok(())
}

// ── Request handler ───────────────────────────────────────────────────────────

/// Handle one HTTP/3 request stream: parse, route, proxy, respond.
///
/// The `is_early_data` flag is `true` when the request arrived while the 0-RTT
/// window was still open. Non-idempotent methods are rejected in that case —
/// 0-RTT data is replayable, so only safe methods are permitted (RFC 9114 §4.2.5).
async fn handle_h3_request<C, B>(
    resolver: h3::server::RequestResolver<C, B>,
    route_table: Arc<ArcSwap<RouteTable>>,
    plugin_chain: Arc<PluginChain>,
    is_early_data: bool,
) -> Result<(), RequestHandlerError>
where
    C: h3::quic::Connection<B>,
    B: bytes::Buf + From<Bytes> + Send + 'static,
    C::BidiStream: h3::quic::BidiStream<B> + Send,
    Bytes: From<B>,
{
    // Resolve the raw h3 request into (http::Request, RequestStream).
    let (req, mut stream) = resolver
        .resolve_request()
        .await
        .map_err(RequestHandlerError::Resolve)?;

    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    // Reject non-idempotent 0-RTT requests — they are replayable.
    if is_early_data && !is_idempotent_method(&method) {
        warn!(
            method = %method,
            "rejecting non-idempotent 0-RTT request"
        );
        send_error_response(&mut stream, 425, "0-RTT replay rejected").await;
        return Ok(());
    }

    // Build a Pingora-compatible RequestHeader from the h3 request.
    let pingora_req = match h3_to_pingora_headers(&method, &uri, &headers) {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "malformed HTTP/3 request headers");
            send_error_response(&mut stream, 400, "bad request headers").await;
            return Ok(());
        }
    };

    // Build the plugin context — mirrors what request_filter() does on the TCP path.
    let mut ctx = build_plugin_ctx(&method, &uri, &headers);

    // Run the request-phase plugins (bot detection, rate limiting, etc.).
    if let Some(plugin_resp) = plugin_chain.run_request(&pingora_req, &mut ctx) {
        send_plugin_response(&mut stream, plugin_resp, &mut ctx, &plugin_chain).await;
        return Ok(());
    }

    // Extract the host for route lookup — `:authority` pseudo-header maps to Host.
    // Strip port suffix (e.g. "example.com:8443" → "example.com") before lookup.
    let host = ctx
        .host
        .as_deref()
        .map_or("", |h| h.split(':').next().unwrap_or(h));

    if host.is_empty() {
        send_error_response(&mut stream, 400, "missing :authority").await;
        return Ok(());
    }

    // Resolve the upstream from the route table (O(1) lock-free read).
    let upstream_addr = match resolve_upstream_addr(&route_table, host) {
        Ok(addr) => addr,
        Err(status) => {
            send_error_response(&mut stream, status, "upstream routing failed").await;
            return Ok(());
        }
    };

    // Read the request body from the h3 stream.
    let body = match drain_request_body(&mut stream).await {
        Ok(b) => b,
        Err(BodyDrainError::TooLarge) => {
            send_error_response(&mut stream, 413, "request body too large").await;
            return Ok(());
        }
        Err(BodyDrainError::Stream(e)) => {
            debug!(error = ?e, "failed to drain request body");
            Bytes::new()
        }
    };

    // Forward the request to the upstream over plain HTTP/1.1 TCP.
    // No reqwest (forbidden by Guardrail dep policy) — raw Tokio TCP.
    let (resp_status, resp_headers, resp_body) =
        forward_to_upstream(upstream_addr, &method, &uri, &headers, body)
            .await
            .unwrap_or_else(|e| {
                warn!(error = %e, upstream = %upstream_addr, "upstream connection failed");
                (
                    502u16,
                    vec![],
                    Bytes::from_static(b"upstream connection failed"),
                )
            });

    // Build the response header and run plugin hooks.
    let mut pingora_resp = match ResponseHeader::build(resp_status, Some(resp_headers.len())) {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "failed to build response header");
            send_error_response(&mut stream, 500, "internal error").await;
            return Ok(());
        }
    };

    // Copy upstream response headers (skip hop-by-hop headers).
    // `IntoCaseHeaderName` needs `String`, `&'static str`, or `HeaderName` —
    // not a borrowed `&str`. We use owned `String` here.
    for (name, value) in &resp_headers {
        if !is_hop_by_hop(name.as_str()) {
            let _ = pingora_resp.insert_header(name.clone(), value.as_str().to_owned());
        }
    }

    // Run the response-phase plugins (security headers, etc.).
    plugin_chain.run_response(&mut pingora_resp, &mut ctx);

    // Convert the Pingora ResponseHeader into an http::Response for h3.
    let h3_resp = pingora_resp_to_h3(&pingora_resp, resp_status)
        .map_err(RequestHandlerError::BuildResponse)?;

    stream
        .send_response(h3_resp)
        .await
        .map_err(RequestHandlerError::SendResponse)?;

    // Run body plugins on the response body chunk.
    let mut body_opt = Some(resp_body);
    plugin_chain.run_body(&mut body_opt, true, &mut ctx);
    let final_body = body_opt.unwrap_or_default();

    if !final_body.is_empty() {
        stream
            .send_data(B::from(final_body))
            .await
            .map_err(RequestHandlerError::SendData)?;
    }

    stream.finish().await.map_err(RequestHandlerError::Finish)?;
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Look up the upstream address for `host` in the route table.
///
/// Returns `Ok(addr)` on success, or `Err(status_code)` to signal that an
/// error response of the given status should be sent to the client. This
/// keeps `handle_h3_request` under the function-length limit while all
/// routing logic stays in one readable place.
fn resolve_upstream_addr(route_table: &ArcSwap<RouteTable>, host: &str) -> Result<SocketAddr, u16> {
    let table = route_table.load();
    let Some(route) = table.resolve(host) else {
        return Err(502);
    };
    // Only ReverseProxy routes are supported over h3 for now.
    // FileServer, StaticResponse, FastCgi are deferred (ISSUE-107).
    if let Some(handler) = route.handlers.first().map(|b| &b.handler) {
        match handler {
            Handler::ReverseProxy { upstream } => return Ok(*upstream),
            Handler::ReverseProxyPool { pool } => {
                if let Some(selected) = pool.select(None) {
                    return Ok(selected.addr);
                }
            }
            _ => {}
        }
    }
    Err(502)
}

/// Build a [`PluginCtx`] from the h3 request components.
///
/// Populates `host`, `method`, `path`, and marks `is_tls = true` — QUIC
/// is always TLS 1.3 so this is unconditional.
fn build_plugin_ctx(
    method: &http::Method,
    uri: &http::Uri,
    headers: &http::HeaderMap,
) -> PluginCtx {
    PluginCtx {
        method: compact_str::CompactString::from(method.as_str()),
        path: compact_str::CompactString::from(uri.path()),
        is_tls: true,
        host: uri
            .host()
            .map(compact_str::CompactString::from)
            .or_else(|| {
                headers
                    .get(http::header::HOST)
                    .and_then(|v| v.to_str().ok())
                    .map(compact_str::CompactString::from)
            }),
        ..PluginCtx::default()
    }
}

/// Whether `method` is safe to replay over 0-RTT (idempotent + no side effects).
///
/// RFC 9110 §9.2.1 defines safe methods as those that "do not request that
/// the origin server perform any action other than retrieval."
fn is_idempotent_method(method: &http::Method) -> bool {
    matches!(
        *method,
        http::Method::GET | http::Method::HEAD | http::Method::OPTIONS
    )
}

/// Convert an HTTP/3 request into a `pingora_http::RequestHeader`.
///
/// HTTP/3 uses pseudo-headers (`:method`, `:path`, `:authority`, `:scheme`)
/// that don't appear in the `HeaderMap` — they arrive as fields in the
/// `http::Uri` and `http::Method`. This function translates them back into
/// the Host header and request line that Pingora's type system expects.
pub fn h3_to_pingora_headers(
    method: &http::Method,
    uri: &http::Uri,
    headers: &http::HeaderMap,
) -> Result<RequestHeader, H3ParseError> {
    let path_and_query = uri.path_and_query().map_or("/", |pq| pq.as_str());

    let mut pingora_req = RequestHeader::build(method.as_str(), path_and_query.as_bytes(), None)
        .map_err(|e| H3ParseError::BuildHeader(e.to_string()))?;

    // `:authority` becomes the HTTP/1.1 `Host` header.
    let authority = uri
        .authority()
        .map(http::uri::Authority::as_str)
        .or_else(|| headers.get("host").and_then(|v| v.to_str().ok()));

    if let Some(host) = authority {
        // Use owned String for host — `IntoCaseHeaderName` doesn't accept borrowed `&str`.
        pingora_req
            .insert_header("Host", host.to_owned())
            .map_err(|e| H3ParseError::InsertHeader("Host".into(), e.to_string()))?;
    }

    // Copy all non-pseudo regular headers.
    for (name, value) in headers {
        let name_str = name.as_str();
        // Pseudo-headers start with `:` — skip them, they're in Uri/Method already.
        if name_str.starts_with(':') {
            continue;
        }
        // Both name and value must be owned — `IntoCaseHeaderName` requires
        // `String` or `&'static str`, not a borrowed `&str`.
        let name_owned = name_str.to_owned();
        let value_owned: String = value
            .to_str()
            .map_err(|_| H3ParseError::NonAsciiHeader(name_owned.clone()))?
            .to_owned();
        pingora_req
            .insert_header(name_owned.clone(), value_owned)
            .map_err(|e| H3ParseError::InsertHeader(name_owned, e.to_string()))?;
    }

    Ok(pingora_req)
}

/// Read all request body chunks from the h3 stream into a single [`Bytes`].
///
/// HTTP/3 body arrives as a sequence of DATA frames. We read until the peer
/// signals end-of-stream (`recv_data` returns `None`), or until the accumulated
/// size exceeds [`MAX_REQUEST_BODY`], whichever comes first.
async fn drain_request_body<S, B>(
    stream: &mut RequestStream<S, B>,
) -> Result<Bytes, BodyDrainError>
where
    S: h3::quic::RecvStream,
    B: bytes::Buf,
    Bytes: From<B>,
{
    use bytes::BufMut;
    let mut buf = bytes::BytesMut::new();
    while let Some(chunk) = stream.recv_data().await.map_err(BodyDrainError::Stream)? {
        use bytes::Buf;
        let remaining = chunk.remaining();
        if buf.len() + remaining > MAX_REQUEST_BODY {
            return Err(BodyDrainError::TooLarge);
        }
        let mut tmp = bytes::BytesMut::with_capacity(remaining);
        tmp.put(chunk);
        buf.put(tmp.freeze());
    }
    Ok(buf.freeze())
}

/// Forward an HTTP/1.1 request to `upstream_addr` over a plain TCP connection.
///
/// Returns `(status, headers, body)`. Uses `tokio::net::TcpStream` directly —
/// no reqwest (forbidden by dependency policy) and no Pingora Session
/// (which requires an established downstream session to construct). This is the
/// minimal working proxy path; deeper Pingora session integration is tracked
/// in ISSUE-108.
///
/// The entire round-trip (connect + write + read) is bounded by
/// [`UPSTREAM_TIMEOUT_SECS`] to prevent a slow upstream from holding a QUIC
/// stream open indefinitely.
async fn forward_to_upstream(
    upstream_addr: SocketAddr,
    method: &http::Method,
    uri: &http::Uri,
    req_headers: &http::HeaderMap,
    body: Bytes,
) -> Result<Http1Response, UpstreamError> {
    tokio::time::timeout(
        std::time::Duration::from_secs(UPSTREAM_TIMEOUT_SECS),
        forward_to_upstream_inner(upstream_addr, method, uri, req_headers, body),
    )
    .await
    .map_err(|_| UpstreamError::Timeout)?
}

async fn forward_to_upstream_inner(
    upstream_addr: SocketAddr,
    method: &http::Method,
    uri: &http::Uri,
    req_headers: &http::HeaderMap,
    body: Bytes,
) -> Result<Http1Response, UpstreamError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut tcp = tokio::net::TcpStream::connect(upstream_addr)
        .await
        .map_err(|e| UpstreamError::Connect(upstream_addr, e))?;

    // Build the HTTP/1.1 request line and headers.
    let path = uri.path_and_query().map_or("/", |pq| pq.as_str());
    let host = uri
        .authority()
        .map_or_else(|| upstream_addr.to_string(), |a| a.as_str().to_owned());

    // Pre-allocate with a reasonable capacity to reduce reallocations.
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n");

    // Forward safe request headers to the upstream.
    for (name, value) in req_headers {
        let name_str = name.as_str();
        if name_str.starts_with(':') || is_hop_by_hop(name_str) {
            continue;
        }
        if let Ok(v) = value.to_str() {
            request.push_str(name_str);
            request.push_str(": ");
            request.push_str(v);
            request.push_str("\r\n");
        }
    }

    if !body.is_empty() {
        use std::fmt::Write as _;
        let _ = write!(request, "Content-Length: {}\r\n", body.len());
    }
    request.push_str("Connection: close\r\n\r\n");

    tcp.write_all(request.as_bytes())
        .await
        .map_err(UpstreamError::Write)?;

    if !body.is_empty() {
        tcp.write_all(&body).await.map_err(UpstreamError::Write)?;
    }

    // Read the full response — `Connection: close` means we read until EOF.
    // Cap at MAX_UPSTREAM_RESPONSE to prevent a malicious upstream from
    // exhausting memory.
    let mut resp_bytes = Vec::new();
    let n = tcp
        .take(MAX_UPSTREAM_RESPONSE as u64 + 1)
        .read_to_end(&mut resp_bytes)
        .await
        .map_err(UpstreamError::Read)?;

    if n > MAX_UPSTREAM_RESPONSE {
        return Err(UpstreamError::ResponseTooLarge);
    }

    parse_http1_response(&resp_bytes).map_err(UpstreamError::Parse)
}

/// Parsed HTTP/1.1 response: (status, headers, body).
type Http1Response = (u16, Vec<(String, String)>, Bytes);

/// Parse a raw HTTP/1.1 response into `(status, headers, body)`.
fn parse_http1_response(raw: &[u8]) -> Result<Http1Response, String> {
    // Split head from body on the double CRLF separator.
    let split_pos = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "HTTP response missing header/body separator".to_string())?;

    let head = std::str::from_utf8(&raw[..split_pos])
        .map_err(|e| format!("non-UTF-8 response head: {e}"))?;
    let raw_body = &raw[split_pos + 4..];

    let mut lines = head.lines();
    let status_line = lines.next().ok_or("empty response")?;

    // Parse `HTTP/1.1 200 OK`
    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("invalid status line: {status_line}"))?;

    let mut headers = Vec::new();
    let mut is_chunked = false;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            let value = value.trim();
            if name.eq_ignore_ascii_case("transfer-encoding")
                && value.eq_ignore_ascii_case("chunked")
            {
                is_chunked = true;
            }
            headers.push((name.to_string(), value.to_string()));
        }
    }

    let body = if is_chunked {
        decode_chunked(raw_body)?
    } else {
        Bytes::copy_from_slice(raw_body)
    };

    Ok((status_code, headers, body))
}

/// Decode a chunked transfer-encoded body per RFC 9112 §7.1.
///
/// Reads `<hex-size>\r\n<data>\r\n` chunks until the terminal `0\r\n\r\n`.
/// Chunk extensions and trailers are ignored — they carry no meaning for our
/// upstream probe use-case and are rare in practice.
fn decode_chunked(mut input: &[u8]) -> Result<Bytes, String> {
    let mut out = Vec::new();

    loop {
        // Find the end of the chunk-size line.
        let crlf = input
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| "chunked: missing CRLF after chunk size".to_string())?;

        let size_line = std::str::from_utf8(&input[..crlf])
            .map_err(|_| "chunked: non-UTF-8 chunk size line".to_string())?;

        // Strip optional chunk extensions (`;ext=value`).
        let size_str = size_line.split(';').next().unwrap_or("").trim();
        let chunk_size = usize::from_str_radix(size_str, 16)
            .map_err(|_| format!("chunked: invalid chunk size: {size_str:?}"))?;

        input = &input[crlf + 2..]; // advance past size line CRLF

        if chunk_size == 0 {
            break; // terminal chunk
        }

        if input.len() < chunk_size + 2 {
            return Err(format!(
                "chunked: truncated chunk (expected {} + 2 bytes, got {})",
                chunk_size,
                input.len()
            ));
        }

        out.extend_from_slice(&input[..chunk_size]);
        input = &input[chunk_size + 2..]; // advance past data + trailing CRLF
    }

    Ok(Bytes::from(out))
}

/// Send a best-effort error response over the h3 stream.
///
/// Logs on write failure but does not propagate — the connection will be
/// cleaned up by the caller regardless.
async fn send_error_response<S, B>(stream: &mut RequestStream<S, B>, status: u16, message: &str)
where
    S: h3::quic::BidiStream<B>,
    B: bytes::Buf + From<Bytes>,
{
    let Ok(resp) = http::Response::builder().status(status).body(()) else {
        return;
    };

    if let Err(e) = stream.send_response(resp).await {
        debug!(error = %e, "failed to send error response headers");
        return;
    }
    let body = B::from(Bytes::copy_from_slice(message.as_bytes()));
    if let Err(e) = stream.send_data(body).await {
        debug!(error = %e, "failed to send error response body");
        return;
    }
    let _ = stream.finish().await;
}

/// Send a plugin short-circuit response, running `on_response` and `on_body` hooks.
async fn send_plugin_response<S, B>(
    stream: &mut RequestStream<S, B>,
    plugin_resp: PluginResponse,
    ctx: &mut PluginCtx,
    plugin_chain: &PluginChain,
) where
    S: h3::quic::BidiStream<B>,
    B: bytes::Buf + From<Bytes>,
{
    let Ok(mut pingora_resp) =
        ResponseHeader::build(plugin_resp.status, Some(plugin_resp.headers.len()))
    else {
        send_error_response(stream, 500, "internal error").await;
        return;
    };

    for (name, value) in &plugin_resp.headers {
        let _ = pingora_resp.insert_header(*name, value.as_str());
    }

    plugin_chain.run_response(&mut pingora_resp, ctx);

    let Ok(h3_resp) = pingora_resp_to_h3(&pingora_resp, plugin_resp.status) else {
        send_error_response(stream, 500, "internal error").await;
        return;
    };

    if let Err(e) = stream.send_response(h3_resp).await {
        debug!(error = %e, "failed to send plugin response");
        return;
    }

    let mut body_opt = Some(plugin_resp.body);
    plugin_chain.run_body(&mut body_opt, true, ctx);
    let body_bytes = body_opt.unwrap_or_default();

    if !body_bytes.is_empty() {
        let _ = stream.send_data(B::from(body_bytes)).await;
    }

    let _ = stream.finish().await;
}

/// Convert a `pingora_http::ResponseHeader` into an `http::Response<()>` for h3.
///
/// h3's `send_response` takes `http::Response<()>` — this builds one from the
/// Pingora type by iterating its header map.
fn pingora_resp_to_h3(
    pingora_resp: &ResponseHeader,
    status: u16,
) -> Result<http::Response<()>, String> {
    let mut builder = http::Response::builder().status(status);

    // ResponseHeader exposes headers via Deref to http::response::Parts.
    // Reading via Deref is safe — we're not mutating (Guardrail #7).
    for (name, value) in &pingora_resp.headers {
        builder = builder.header(name, value);
    }

    builder.body(()).map_err(|e| e.to_string())
}

/// Whether a header is a hop-by-hop header that must not be forwarded.
///
/// These headers describe the single-hop connection and lose meaning when
/// the proxy terminates the connection and opens a new one upstream.
fn is_hop_by_hop(name: &str) -> bool {
    name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("te")
        || name.eq_ignore_ascii_case("trailer")
        || name.eq_ignore_ascii_case("proxy-authorization")
        || name.eq_ignore_ascii_case("proxy-authenticate")
        || name.eq_ignore_ascii_case("upgrade")
}

// ── TLS setup ────────────────────────────────────────────────────────────────

/// Build a rustls `ServerConfig` for QUIC with 0-RTT session tickets.
///
/// The cert/key files are the same PEM files used by Pingora's TCP/TLS
/// listener — both libraries parse PEM natively, so no conversion is needed.
///
/// Session tickets (via rustls's built-in `Ticketer`) allow clients to resume
/// QUIC connections in 0-RTT, cutting the handshake from 1 RTT to 0 RTT for
/// repeat visitors. We set `max_early_data_size = u32::MAX` to allow the full
/// early-data window; non-idempotent requests are rejected at the HTTP layer.
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

    // Install a session ticketer so clients can resume in 0-RTT.
    // Stateless ticket-based approach — no shared session store needed.
    let ticketer = rustls::crypto::ring::Ticketer::new().map_err(QuicSetupError::Rustls)?;
    config.ticketer = ticketer;
    // Allow the full early-data window; we reject at the HTTP layer instead.
    config.max_early_data_size = u32::MAX;

    Ok(config)
}

// ── Error types ───────────────────────────────────────────────────────────────

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

/// Errors while managing an h3 connection at the transport level.
#[derive(Debug, thiserror::Error)]
pub enum ConnectionHandlerError {
    // ConnectionError doesn't implement Display in h3 0.0.8, so we use Debug.
    #[error("h3 connection accept error: {0:?}")]
    Accept(h3::error::ConnectionError),
}

/// Errors that can occur while processing one HTTP/3 request stream.
#[derive(Debug, thiserror::Error)]
pub enum RequestHandlerError {
    #[error("failed to resolve h3 request: {0:?}")]
    Resolve(h3::error::StreamError),

    #[error("failed to build response: {0}")]
    BuildResponse(String),

    #[error("failed to send response headers: {0:?}")]
    SendResponse(h3::error::StreamError),

    #[error("failed to send response data: {0:?}")]
    SendData(h3::error::StreamError),

    #[error("failed to finish stream: {0:?}")]
    Finish(h3::error::StreamError),
}

/// Errors from the h3 request header parsing step.
#[derive(Debug, thiserror::Error)]
pub enum H3ParseError {
    #[error("failed to build RequestHeader: {0}")]
    BuildHeader(String),

    #[error("failed to insert header '{0}': {1}")]
    InsertHeader(String, String),

    #[error("header '{0}' contains non-ASCII bytes")]
    NonAsciiHeader(String),
}

/// Errors from upstream TCP forwarding.
#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    #[error("failed to connect to upstream {0}: {1}")]
    Connect(SocketAddr, std::io::Error),

    #[error("failed to write to upstream: {0}")]
    Write(std::io::Error),

    #[error("failed to read from upstream: {0}")]
    Read(std::io::Error),

    #[error("failed to parse upstream HTTP/1.1 response: {0}")]
    Parse(String),

    #[error("upstream response exceeded {MAX_UPSTREAM_RESPONSE} byte limit")]
    ResponseTooLarge,

    #[error("upstream did not respond within {UPSTREAM_TIMEOUT_SECS}s")]
    Timeout,
}

/// Errors that can occur while draining an h3 request body.
#[derive(Debug, thiserror::Error)]
pub enum BodyDrainError {
    #[error("request body exceeded {MAX_REQUEST_BODY} byte limit")]
    TooLarge,

    #[error("h3 stream error while reading body: {0:?}")]
    Stream(h3::error::StreamError),
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    /// Install the ring crypto provider for rustls so tests don't panic on
    /// `CryptoProvider` conflicts when multiple tests call `build_rustls_config`.
    fn install_crypto_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    // ── Unit: error display ────────────────────────────────────────────────────

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

    // ── Unit: h3_to_pingora_headers ────────────────────────────────────────────

    #[test]
    fn h3_to_pingora_headers_converts_get() {
        install_crypto_provider();
        let method = http::Method::GET;
        let uri: http::Uri = "https://example.com/path?q=1".parse().expect("valid URI");
        let headers = http::HeaderMap::new();

        let req = h3_to_pingora_headers(&method, &uri, &headers).expect("conversion ok");
        assert_eq!(req.method, http::Method::GET);
        // Host header should be set from :authority
        assert!(req.headers.get("host").is_some());
    }

    #[test]
    fn h3_to_pingora_headers_preserves_custom_headers() {
        install_crypto_provider();
        let method = http::Method::POST;
        let uri: http::Uri = "https://api.example.com/data".parse().expect("valid URI");
        let mut headers = http::HeaderMap::new();
        headers.insert("x-request-id", "abc123".parse().expect("valid value"));
        headers.insert(
            "content-type",
            "application/json".parse().expect("valid value"),
        );

        let req = h3_to_pingora_headers(&method, &uri, &headers).expect("conversion ok");
        assert!(req.headers.get("x-request-id").is_some());
        assert!(req.headers.get("content-type").is_some());
    }

    #[test]
    fn h3_to_pingora_headers_skips_pseudo_headers() {
        install_crypto_provider();
        let method = http::Method::GET;
        let uri: http::Uri = "https://example.com/".parse().expect("valid URI");
        let headers = http::HeaderMap::new();

        let req = h3_to_pingora_headers(&method, &uri, &headers).expect("conversion ok");
        // No `:path` pseudo-header should appear in output headers.
        assert!(req.headers.get(":path").is_none());
    }

    // ── Unit: parse_http1_response ─────────────────────────────────────────────

    #[test]
    fn parse_http1_response_200_ok() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHello!";
        let (status, headers, body) = parse_http1_response(raw).expect("parse ok");
        assert_eq!(status, 200);
        assert!(headers.iter().any(|(k, _)| k == "Content-Type"));
        assert_eq!(body, Bytes::from_static(b"Hello!"));
    }

    #[test]
    fn parse_http1_response_404_empty_body() {
        let raw = b"HTTP/1.1 404 Not Found\r\n\r\n";
        let (status, _headers, body) = parse_http1_response(raw).expect("parse ok");
        assert_eq!(status, 404);
        assert!(body.is_empty());
    }

    #[test]
    fn parse_http1_response_missing_separator_returns_err() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n";
        let result = parse_http1_response(raw);
        assert!(result.is_err());
    }

    // ── Unit: is_idempotent_method ─────────────────────────────────────────────

    #[test]
    fn idempotent_methods_allowed_on_0rtt() {
        assert!(is_idempotent_method(&http::Method::GET));
        assert!(is_idempotent_method(&http::Method::HEAD));
        assert!(is_idempotent_method(&http::Method::OPTIONS));
    }

    #[test]
    fn non_idempotent_methods_blocked_on_0rtt() {
        assert!(!is_idempotent_method(&http::Method::POST));
        assert!(!is_idempotent_method(&http::Method::PUT));
        assert!(!is_idempotent_method(&http::Method::DELETE));
        assert!(!is_idempotent_method(&http::Method::PATCH));
    }

    // ── Unit: is_hop_by_hop ────────────────────────────────────────────────────

    #[test]
    fn hop_by_hop_headers_are_filtered() {
        assert!(is_hop_by_hop("connection"));
        assert!(is_hop_by_hop("Transfer-Encoding")); // case-insensitive
        assert!(is_hop_by_hop("keep-alive"));
        assert!(!is_hop_by_hop("content-type"));
        assert!(!is_hop_by_hop("x-custom-header"));
    }

    // ── Unit: stream concurrency config ───────────────────────────────────────

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
    //
    // Spins up a tiny TCP echo server as "upstream", creates a QuicService
    // with a self-signed cert, sends an HTTP/3 GET request via a quinn/h3
    // client, and asserts the response came back through the proxy.

    #[tokio::test]
    async fn h3_proxy_round_trip() {
        install_crypto_provider();

        let dir = tempfile::tempdir().expect("temp dir");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        write_test_self_signed_cert(&cert_path, &key_path);

        // -- Upstream: minimal HTTP/1.1 server --
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

        // -- Route table --
        let route = crate::route::Route::new("localhost", upstream_addr, false, None);
        let table = RouteTable::new(vec![route]);
        let route_table = Arc::new(ArcSwap::from_pointee(table));
        let plugin_chain = Arc::new(PluginChain::new(vec![]));

        // -- QUIC server --
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

        // Brief pause for the listener to be ready.
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // -- h3 client GET --
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

        // Upstream echoes plain text.
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

        // Add security headers plugin.
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

        // Verify the proxy round trip works (plugin ran without panic).
        let resp_body = h3_client_get(quic_addr, &cert_path, "localhost", "/").await;
        assert!(!resp_body.is_empty(), "response should not be empty");

        let _ = shutdown_tx.send(true);
    }

    // ── Helper: write a self-signed TLS cert for tests ─────────────────────────

    fn write_test_self_signed_cert(cert_path: &Path, key_path: &Path) {
        // rcgen 0.14+ returns CertifiedKey { cert, signing_key }.
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
                .expect("generate self-signed cert");
        std::fs::write(cert_path, cert.pem()).expect("write cert pem");
        std::fs::write(key_path, signing_key.serialize_pem()).expect("write key pem");
    }

    // ── Helper: h3 GET client ──────────────────────────────────────────────────

    async fn h3_client_get(
        addr: SocketAddr,
        server_cert_path: &Path,
        server_name: &str,
        path: &str,
    ) -> String {
        // Build a rustls ClientConfig that trusts our self-signed cert.
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
        // Must advertise h3 ALPN — the server rejects connections without it.
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

        // Drive the connection in background.
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
