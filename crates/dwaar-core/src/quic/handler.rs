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
    self, BodyFraming, UpstreamError, BRIDGE_CHUNK_SIZE, MAX_REQUEST_BODY,
    UPSTREAM_TIMEOUT_SECS,
};
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
                let is_early_data = early_data_active.load(Ordering::Acquire);

                tokio::spawn(async move {
                    if let Err(e) = handle_h3_request(
                        resolver,
                        route_table,
                        plugin_chain,
                        conn_pool,
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
    let upstream_addr = match resolve_upstream_addr(&route_table, host, request_path) {
        Ok(addr) => addr,
        Err(status) => {
            send_error_response(&mut stream, status, "upstream routing failed").await;
            return Ok(());
        }
    };

    // Wrap the entire upstream exchange in a timeout.
    let result = tokio::time::timeout(
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
    .await;

    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            warn!(error = %e, upstream = %upstream_addr, "streaming proxy error");
            // If headers haven't been sent yet, we can send an error.
            // Otherwise the stream is already mid-flight and will be reset on drop.
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
    use tokio::io::AsyncWriteExt;

    // Acquire upstream connection (pool or fresh).
    let mut tcp = if let Some(pooled) = conn_pool.take(upstream_addr) {
        debug!(upstream = %upstream_addr, "reusing pooled connection");
        pooled
    } else {
        tokio::net::TcpStream::connect(upstream_addr)
            .await
            .map_err(|e| StreamProxyError::Upstream(UpstreamError::Connect(upstream_addr, e)))?
    };

    let content_length: Option<u64> = headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok());

    // Write request headers.
    bridge::write_request_head(&mut tcp, method, uri, headers, content_length)
        .await
        .map_err(StreamProxyError::Upstream)?;

    // Stream request body chunks from h3 to upstream.
    let uses_chunked = content_length.is_none()
        && *method != http::Method::GET
        && *method != http::Method::HEAD;
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

        if uses_chunked {
            bridge::write_chunked_data(&mut tcp, &frozen)
                .await
                .map_err(StreamProxyError::Upstream)?;
        } else {
            tcp.write_all(&frozen)
                .await
                .map_err(|e| StreamProxyError::Upstream(UpstreamError::Write(e)))?;
        }
    }

    if uses_chunked {
        bridge::write_chunked_end(&mut tcp)
            .await
            .map_err(StreamProxyError::Upstream)?;
    }

    // Parse upstream response headers incrementally.
    let resp_head = bridge::read_response_head(&mut tcp)
        .await
        .map_err(StreamProxyError::Upstream)?;

    // Build response headers, run plugins, send to h3 immediately (TTFB).
    let mut pingora_resp =
        ResponseHeader::build(resp_head.status, Some(resp_head.headers.len()))
            .map_err(|e| StreamProxyError::BuildResponse(e.to_string()))?;

    for (name, value) in &resp_head.headers {
        if !is_hop_by_hop(name.as_str()) {
            let _ = pingora_resp.insert_header(name.clone(), value.as_str().to_owned());
        }
    }

    plugin_chain.run_response(&mut pingora_resp, ctx);

    let h3_resp = pingora_resp_to_h3(&pingora_resp, resp_head.status)
        .map_err(StreamProxyError::BuildResponse)?;

    h3_stream
        .send_response(h3_resp)
        .await
        .map_err(StreamProxyError::H3SendResponse)?;

    // Stream response body inline — read from TCP, run plugins, send to h3.
    let reusable = stream_response_body_inline(
        &mut tcp,
        h3_stream,
        &resp_head,
        plugin_chain,
        ctx,
    )
    .await?;

    h3_stream
        .finish()
        .await
        .map_err(StreamProxyError::H3Finish)?;

    if reusable {
        conn_pool.put(upstream_addr, tcp);
    }

    Ok(())
}

/// Stream the response body from TCP to h3, running plugin body hooks per chunk.
///
/// Returns whether the upstream connection is reusable.
#[allow(clippy::too_many_lines)]
async fn stream_response_body_inline<S, B>(
    tcp: &mut tokio::net::TcpStream,
    h3_stream: &mut RequestStream<S, B>,
    resp_head: &bridge::UpstreamResponseHead,
    plugin_chain: &PluginChain,
    ctx: &mut dwaar_plugins::plugin::PluginCtx,
) -> Result<bool, StreamProxyError>
where
    S: h3::quic::SendStream<B>,
    B: bytes::Buf + From<Bytes>,
{
    use tokio::io::AsyncReadExt;

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

    match resp_head.body_framing {
        BodyFraming::ContentLength(total) => {
            let mut sent = 0usize;

            // Yield prefix bytes.
            if !resp_head.body_prefix.is_empty() {
                let n = resp_head.body_prefix.len().min(total);
                sent += n;
                let is_last = sent >= total;
                send_chunk(
                    h3_stream, plugin_chain, ctx,
                    Bytes::copy_from_slice(&resp_head.body_prefix[..n]),
                    is_last,
                ).await?;
                if is_last {
                    return Ok(true);
                }
            }

            let mut buf = vec![0u8; BRIDGE_CHUNK_SIZE];
            while sent < total {
                let to_read = (total - sent).min(BRIDGE_CHUNK_SIZE);
                let n = tcp.read(&mut buf[..to_read]).await
                    .map_err(|e| StreamProxyError::Upstream(UpstreamError::Read(e)))?;
                if n == 0 {
                    return Err(StreamProxyError::Upstream(UpstreamError::Parse(
                        "upstream closed before content-length fulfilled".into(),
                    )));
                }
                sent += n;
                let is_last = sent >= total;
                send_chunk(
                    h3_stream, plugin_chain, ctx,
                    Bytes::copy_from_slice(&buf[..n]),
                    is_last,
                ).await?;
            }
            Ok(true)
        }
        BodyFraming::CloseDelimited => {
            if !resp_head.body_prefix.is_empty() {
                send_chunk(
                    h3_stream, plugin_chain, ctx,
                    Bytes::copy_from_slice(&resp_head.body_prefix),
                    false,
                ).await?;
            }

            let mut buf = vec![0u8; BRIDGE_CHUNK_SIZE];
            loop {
                let n = tcp.read(&mut buf).await
                    .map_err(|e| StreamProxyError::Upstream(UpstreamError::Read(e)))?;
                if n == 0 {
                    send_chunk(h3_stream, plugin_chain, ctx, Bytes::new(), true).await?;
                    break;
                }
                send_chunk(
                    h3_stream, plugin_chain, ctx,
                    Bytes::copy_from_slice(&buf[..n]),
                    false,
                ).await?;
            }
            Ok(false)
        }
        BodyFraming::Chunked => {
            // Inline chunked decoding — we can't use the closure-based
            // stream_chunked_body because async closures can't borrow h3_stream.
            let mut raw = Vec::from(resp_head.body_prefix.as_slice());
            let mut buf = vec![0u8; BRIDGE_CHUNK_SIZE];

            loop {
                // Try to decode a chunk from accumulated raw data.
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

                // Need more data from upstream.
                let n = tcp.read(&mut buf).await
                    .map_err(|e| StreamProxyError::Upstream(UpstreamError::Read(e)))?;
                if n == 0 {
                    return Err(StreamProxyError::Upstream(UpstreamError::Parse(
                        "upstream closed mid-chunked-body".into(),
                    )));
                }
                if raw.len() + n > 10 * 1024 * 1024 {
                    return Err(StreamProxyError::Upstream(UpstreamError::ResponseTooLarge));
                }
                raw.extend_from_slice(&buf[..n]);
            }
        }
    }
}

/// Errors from the streaming proxy path.
#[derive(Debug, thiserror::Error)]
enum StreamProxyError {
    #[error("upstream: {0}")]
    Upstream(UpstreamError),

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
