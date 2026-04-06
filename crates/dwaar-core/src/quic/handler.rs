// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! HTTP/3 connection driver and per-request handler.
//!
//! `handle_h3_connection` accepts request streams in a loop, spawning a task
//! per request so streams run concurrently. `handle_h3_request` handles the
//! full request lifecycle: parse → route → plugin → streaming proxy → respond.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;
use bytes::Bytes;
use dwaar_plugins::plugin::{PluginChain, PluginResponse};
use h3::server::RequestStream;
use pingora_http::ResponseHeader;
use tracing::{debug, warn};

use crate::route::RouteTable;

use super::bridge::{
    self, BodyFraming, UpstreamError, MAX_REQUEST_BODY, UPSTREAM_TIMEOUT_SECS,
};
use super::pool::BufferedConn;
use super::convert::{
    build_plugin_ctx, h3_to_pingora_headers, is_hop_by_hop, is_idempotent_method,
    pingora_resp_to_h3, resolve_upstream_addr,
};
use super::pool::UpstreamConnPool;

/// Errors while managing an h3 connection at the transport level.
#[derive(Debug, thiserror::Error)]
pub enum ConnectionHandlerError {
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

/// Drive one HTTP/3 connection from acceptance to close.
pub async fn handle_h3_connection(
    conn: quinn::Connection,
    early_data_active: Arc<AtomicBool>,
    route_table: Arc<ArcSwap<RouteTable>>,
    plugin_chain: Arc<PluginChain>,
    conn_pool: Arc<UpstreamConnPool>,
    h2_pool: Arc<super::h2_pool::H2ConnPool>,
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
                let conn_pool = Arc::clone(&conn_pool);
                let h2_pool = Arc::clone(&h2_pool);
                let is_early_data = early_data_active.load(Ordering::Acquire);

                tokio::spawn(async move {
                    if let Err(e) = handle_h3_request(
                        resolver,
                        route_table,
                        plugin_chain,
                        conn_pool,
                        h2_pool,
                        is_early_data,
                    )
                    .await
                    {
                        debug!(error = %e, "HTTP/3 request handler error");
                    }
                });
            }
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

/// Handle one HTTP/3 request stream with streaming proxy.
///
/// Flow:
/// 1. Parse h3 pseudo-headers
/// 2. 0-RTT validation
/// 3. Plugin `run_request()`
/// 4. Resolve upstream from route table
/// 5. Acquire upstream TCP connection (pool or fresh)
/// 6. Stream request body: h3 `recv_data` → chunked encode → TCP
/// 7. Parse upstream response headers incrementally
/// 8. Plugin `run_response()` + send h3 response headers
/// 9. Stream response body: TCP read → plugin `run_body()` → h3 `send_data`
/// 10. Release connection to pool if reusable
async fn handle_h3_request<C, B>(
    resolver: h3::server::RequestResolver<C, B>,
    route_table: Arc<ArcSwap<RouteTable>>,
    plugin_chain: Arc<PluginChain>,
    conn_pool: Arc<UpstreamConnPool>,
    h2_pool: Arc<super::h2_pool::H2ConnPool>,
    is_early_data: bool,
) -> Result<(), RequestHandlerError>
where
    C: h3::quic::Connection<B>,
    B: bytes::Buf + From<Bytes> + Send + 'static,
    C::BidiStream: h3::quic::BidiStream<B> + Send,
    Bytes: From<B>,
{
    let (req, mut stream) = resolver
        .resolve_request()
        .await
        .map_err(RequestHandlerError::Resolve)?;

    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    if is_early_data && !is_idempotent_method(&method) {
        warn!(method = %method, "rejecting non-idempotent 0-RTT request");
        send_error_response(&mut stream, 425, "0-RTT replay rejected").await;
        return Ok(());
    }

    let pingora_req = match h3_to_pingora_headers(&method, &uri, &headers) {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "malformed HTTP/3 request headers");
            send_error_response(&mut stream, 400, "bad request headers").await;
            return Ok(());
        }
    };

    let mut ctx = build_plugin_ctx(&method, &uri, &headers);

    if let Some(plugin_resp) = plugin_chain.run_request(&pingora_req, &mut ctx) {
        send_plugin_response(&mut stream, plugin_resp, &mut ctx, &plugin_chain).await;
        return Ok(());
    }

    let host = ctx
        .host
        .as_deref()
        .map_or("", |h| h.split(':').next().unwrap_or(h));

    if host.is_empty() {
        send_error_response(&mut stream, 400, "missing :authority").await;
        return Ok(());
    }

    let request_path = uri.path();
    let (upstream_addr, upstream_h2) = match resolve_upstream_addr(&route_table, host, request_path) {
        Ok(resolved) => resolved,
        Err(status) => {
            send_error_response(&mut stream, status, "upstream routing failed").await;
            return Ok(());
        }
    };

    // Wrap the entire upstream exchange in a timeout.
    let result = if upstream_h2 {
        // HTTP/2 upstream — multiplex on shared H2 connections.
        tokio::time::timeout(
            std::time::Duration::from_secs(UPSTREAM_TIMEOUT_SECS),
            stream_proxy_h2(
                &mut stream,
                upstream_addr,
                &method,
                &uri,
                &headers,
                &plugin_chain,
                &mut ctx,
                &h2_pool,
            ),
        )
        .await
        .map(|r| r.map_err(|e| StreamProxyError::H2Bridge(e)))
    } else {
        // HTTP/1.1 upstream — one TCP connection per stream.
        tokio::time::timeout(
            std::time::Duration::from_secs(UPSTREAM_TIMEOUT_SECS),
            stream_proxy(
                &mut stream,
                upstream_addr,
                &method,
                &uri,
                &headers,
                &plugin_chain,
                &mut ctx,
                &conn_pool,
            ),
        )
        .await
    };

    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            warn!(error = %e, upstream = %upstream_addr, "streaming proxy error");
            Ok(())
        }
        Err(_timeout) => {
            warn!(upstream = %upstream_addr, "upstream timeout ({UPSTREAM_TIMEOUT_SECS}s)");
            Ok(())
        }
    }
}

/// The streaming proxy core — separated from the timeout wrapper for clarity.
///
/// Streams both request body (h3 → TCP) and response body (TCP → h3) without
/// buffering the full bodies in memory. Uses the connection pool for reuse.
#[allow(clippy::too_many_arguments)]
async fn stream_proxy<S, B>(
    h3_stream: &mut RequestStream<S, B>,
    upstream_addr: SocketAddr,
    method: &http::Method,
    uri: &http::Uri,
    headers: &http::HeaderMap,
    plugin_chain: &PluginChain,
    ctx: &mut dwaar_plugins::plugin::PluginCtx,
    conn_pool: &UpstreamConnPool,
) -> Result<(), StreamProxyError>
where
    S: h3::quic::SendStream<B> + h3::quic::RecvStream,
    B: bytes::Buf + From<Bytes> + Send + 'static,
{
    // Acquire upstream connection (pool or fresh). BufferedConn carries its
    // own read buffer — no per-request allocation needed for body streaming.
    let mut conn = if let Some(pooled) = conn_pool.take(upstream_addr) {
        debug!(upstream = %upstream_addr, "reusing pooled connection");
        pooled
    } else {
        BufferedConn::new(
            tokio::net::TcpStream::connect(upstream_addr)
                .await
                .map_err(|e| StreamProxyError::Upstream(UpstreamError::Connect(upstream_addr, e)))?,
        )
    };

    // Always use chunked encoding to the upstream. The h3 Content-Length
    // is between the h3 client and us — we can't trust it to match the
    // actual bytes delivered by recv_data(). Forwarding it as-is and then
    // writing raw bytes would corrupt the TCP stream if the counts diverge.
    // Chunked encoding is self-framing: each DATA frame becomes a chunk,
    // the terminal 0-chunk signals end-of-body, no byte count to enforce.
    let has_body = *method != http::Method::GET && *method != http::Method::HEAD;

    bridge::write_request_head(&mut conn.stream, method, uri, headers, None)
        .await
        .map_err(StreamProxyError::Upstream)?;

    let mut total_body = 0usize;

    while let Some(chunk) = h3_stream.recv_data().await.map_err(StreamProxyError::H3RecvData)? {
        use bytes::Buf;
        let remaining = chunk.remaining();
        total_body += remaining;
        if total_body > MAX_REQUEST_BODY {
            return Err(StreamProxyError::RequestTooLarge);
        }
        let mut data = bytes::BytesMut::with_capacity(remaining);
        bytes::BufMut::put(&mut data, chunk);
        let frozen = data.freeze();

        if has_body {
            bridge::write_chunked_data(&mut conn.stream, &frozen)
                .await
                .map_err(StreamProxyError::Upstream)?;
        }
    }

    if has_body {
        bridge::write_chunked_end(&mut conn.stream)
            .await
            .map_err(StreamProxyError::Upstream)?;
    }

    // Parse upstream response headers using the connection's own buffer.
    let resp_head = bridge::read_response_head(&mut conn)
        .await
        .map_err(StreamProxyError::Upstream)?;

    // Destructure — headers are consumed by Pingora, body fields kept for streaming.
    let bridge::UpstreamResponseHead {
        status,
        headers,
        body_framing,
        body_prefix,
    } = resp_head;

    // Build response headers, run plugins, send to h3 immediately (TTFB).
    let mut pingora_resp = ResponseHeader::build(status, Some(headers.len()))
        .map_err(|e| StreamProxyError::BuildResponse(e.to_string()))?;

    for (name, value) in headers {
        if !is_hop_by_hop(name.as_str()) {
            let _ = pingora_resp.insert_header(
                String::from(name.as_str()),
                String::from(value.as_str()),
            );
        }
    }

    plugin_chain.run_response(&mut pingora_resp, ctx);

    let h3_resp = pingora_resp_to_h3(&pingora_resp, status)
        .map_err(StreamProxyError::BuildResponse)?;

    h3_stream
        .send_response(h3_resp)
        .await
        .map_err(StreamProxyError::H3SendResponse)?;

    // Stream response body — reads from the connection's own buffer (zero alloc).
    let reusable = stream_response_body_inline(
        &mut conn,
        h3_stream,
        &body_framing,
        body_prefix,
        plugin_chain,
        ctx,
    )
    .await?;

    h3_stream
        .finish()
        .await
        .map_err(StreamProxyError::H3Finish)?;

    if reusable {
        conn_pool.put(upstream_addr, conn);
    }

    Ok(())
}

/// Stream the response body from TCP to h3, running plugin body hooks per chunk.
///
/// Uses the connection's own [`BytesMut`] read buffer — zero per-request
/// allocation. Reads via [`BufferedConn::read_into_buf`], yields chunks via
/// [`BufferedConn::take_bytes`] (zero-copy `split_to().freeze()`).
///
/// Returns whether the upstream connection is reusable.
#[allow(clippy::too_many_lines)]
async fn stream_response_body_inline<S, B>(
    conn: &mut BufferedConn,
    h3_stream: &mut RequestStream<S, B>,
    body_framing: &BodyFraming,
    body_prefix: Vec<u8>,
    plugin_chain: &PluginChain,
    ctx: &mut dwaar_plugins::plugin::PluginCtx,
) -> Result<bool, StreamProxyError>
where
    S: h3::quic::SendStream<B>,
    B: bytes::Buf + From<Bytes>,
{
    /// Send one chunk through plugins and h3.
    async fn send_chunk<S2, B2>(
        h3_stream: &mut RequestStream<S2, B2>,
        plugin_chain: &PluginChain,
        ctx: &mut dwaar_plugins::plugin::PluginCtx,
        chunk: Bytes,
        is_last: bool,
    ) -> Result<(), StreamProxyError>
    where
        S2: h3::quic::SendStream<B2>,
        B2: bytes::Buf + From<Bytes>,
    {
        let mut body_opt = if chunk.is_empty() { None } else { Some(chunk) };
        plugin_chain.run_body(&mut body_opt, is_last, ctx);
        let data = body_opt.unwrap_or_default();
        if !data.is_empty() {
            h3_stream
                .send_data(B2::from(data))
                .await
                .map_err(|e| StreamProxyError::BuildResponse(format!("h3 send: {e:?}")))?;
        }
        Ok(())
    }

    match *body_framing {
        BodyFraming::ContentLength(total) => {
            let mut sent = 0usize;

            // Yield any prefix bytes left over from header parsing.
            // Bytes::from(Vec<u8>) takes ownership — zero copy.
            if !body_prefix.is_empty() {
                let n = body_prefix.len().min(total);
                sent += n;
                let is_last = sent >= total;
                let prefix_bytes = if n == body_prefix.len() {
                    Bytes::from(body_prefix)
                } else {
                    Bytes::from(body_prefix[..n].to_vec())
                };
                send_chunk(h3_stream, plugin_chain, ctx, prefix_bytes, is_last).await?;
                if is_last {
                    return Ok(true);
                }
            }

            // Stream remaining body using the connection's own buffer.
            while sent < total {
                let n = conn.read_into_buf().await
                    .map_err(|e| StreamProxyError::Upstream(UpstreamError::Read(e)))?;
                if n == 0 {
                    return Err(StreamProxyError::Upstream(UpstreamError::Parse(
                        "upstream closed before content-length fulfilled".into(),
                    )));
                }
                // Don't read past the declared Content-Length.
                let usable = n.min(total - sent);
                sent += usable;
                let is_last = sent >= total;
                let chunk = conn.take_bytes(usable);
                send_chunk(h3_stream, plugin_chain, ctx, chunk, is_last).await?;
            }
            Ok(true)
        }
        BodyFraming::CloseDelimited => {
            if !body_prefix.is_empty() {
                send_chunk(
                    h3_stream, plugin_chain, ctx,
                    Bytes::from(body_prefix),
                    false,
                ).await?;
            }

            loop {
                let n = conn.read_into_buf().await
                    .map_err(|e| StreamProxyError::Upstream(UpstreamError::Read(e)))?;
                if n == 0 {
                    send_chunk(h3_stream, plugin_chain, ctx, Bytes::new(), true).await?;
                    break;
                }
                let chunk = conn.take_bytes(n);
                send_chunk(h3_stream, plugin_chain, ctx, chunk, false).await?;
            }
            Ok(false)
        }
        BodyFraming::Chunked => {
            // Inline chunked decoding — async closures can't borrow h3_stream,
            // so we decode inline rather than using stream_chunked_body.
            let mut raw = Vec::from(body_prefix);

            loop {
                // Drain all complete chunks from the buffer before hitting the network.
                if let Some((payload, consumed, is_terminal)) =
                    bridge::try_decode_one_chunk(&raw)
                        .map_err(StreamProxyError::Upstream)?
                {
                    raw.drain(..consumed);

                    if is_terminal {
                        send_chunk(h3_stream, plugin_chain, ctx, Bytes::new(), true).await?;
                        return Ok(true);
                    }

                    if !payload.is_empty() {
                        send_chunk(
                            h3_stream, plugin_chain, ctx,
                            Bytes::from(payload),
                            false,
                        ).await?;
                    }
                    continue;
                }

                // Need more data from upstream — read into connection's buffer,
                // then append to the chunked accumulator.
                let n = conn.read_into_buf().await
                    .map_err(|e| StreamProxyError::Upstream(UpstreamError::Read(e)))?;
                if n == 0 {
                    return Err(StreamProxyError::Upstream(UpstreamError::Parse(
                        "upstream closed mid-chunked-body".into(),
                    )));
                }
                if raw.len() + n > super::pool::MAX_CHUNKED_ACCUMULATOR {
                    return Err(StreamProxyError::Upstream(UpstreamError::ResponseTooLarge));
                }
                // Move from conn's BytesMut into the chunked accumulator.
                let fresh = conn.take_bytes(n);
                raw.extend_from_slice(&fresh);
            }
        }
    }
}

/// H2 upstream proxy — multiplexes on shared H2 connections.
///
/// Gets a `SendRequest` handle from the H2 pool (or establishes a new
/// connection), then delegates to [`h2_bridge::stream_via_h2`].
/// On connection-level errors, evicts the dead connection and retries
/// once for idempotent methods.
#[allow(clippy::too_many_arguments)]
async fn stream_proxy_h2<S, B>(
    h3_stream: &mut RequestStream<S, B>,
    upstream_addr: SocketAddr,
    method: &http::Method,
    uri: &http::Uri,
    headers: &http::HeaderMap,
    plugin_chain: &PluginChain,
    ctx: &mut dwaar_plugins::plugin::PluginCtx,
    h2_pool: &super::h2_pool::H2ConnPool,
) -> Result<(), super::h2_bridge::H2BridgeError>
where
    S: h3::quic::SendStream<B> + h3::quic::RecvStream,
    B: bytes::Buf + From<Bytes> + Send + 'static,
    Bytes: From<B>,
{
    let sender = h2_pool
        .get_or_connect(upstream_addr)
        .await
        .map_err(|e| super::h2_bridge::H2BridgeError::BuildResponse(e.to_string()))?;

    let result = super::h2_bridge::stream_via_h2(
        h3_stream, sender, method, uri, headers, plugin_chain, ctx,
    )
    .await;

    // On H2 connection-level error, evict the dead connection so the
    // next request gets a fresh one.
    if let Err(ref e) = result {
        if matches!(e,
            super::h2_bridge::H2BridgeError::SendRequest(_)
            | super::h2_bridge::H2BridgeError::RecvResponse(_))
        {
            h2_pool.evict(upstream_addr);
        }
    }

    result
}

/// Errors from the streaming proxy path.
#[derive(Debug, thiserror::Error)]
enum StreamProxyError {
    #[error("upstream: {0}")]
    Upstream(UpstreamError),

    #[error("h2 bridge: {0}")]
    H2Bridge(super::h2_bridge::H2BridgeError),

    #[error("h3 recv_data: {0:?}")]
    H3RecvData(h3::error::StreamError),

    #[error("request body exceeded limit")]
    RequestTooLarge,

    #[error("failed to build response: {0}")]
    BuildResponse(String),

    #[error("h3 send_response: {0:?}")]
    H3SendResponse(h3::error::StreamError),

    #[error("h3 finish: {0:?}")]
    H3Finish(h3::error::StreamError),
}

/// Send a best-effort error response over the h3 stream.
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
    ctx: &mut dwaar_plugins::plugin::PluginCtx,
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
