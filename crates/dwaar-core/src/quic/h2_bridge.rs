// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! HTTP/2 upstream bridge for the HTTP/3 path.
//!
//! Streams request and response bodies between an H3 `RequestStream` and
//! an H2 `SendRequest`/`RecvStream`, running the plugin chain per chunk.
//! Unlike the HTTP/1.1 bridge, H2 handles framing and flow control
//! automatically — no manual chunked encoding or response parsing.

use super::convert::{is_hop_by_hop, pingora_resp_to_h3};
use super::stream_guard::{BodyDeadline, H2CapacityError, await_h2_capacity, with_chunk_deadline};
use bytes::{Buf, Bytes};
use dwaar_plugins::plugin::{PluginChain, PluginCtx};
use h3::server::RequestStream;
use pingora_http::ResponseHeader;

/// Errors from the H2 upstream bridge.
#[derive(Debug, thiserror::Error)]
pub enum H2BridgeError {
    #[error("H2 send_request failed: {0}")]
    SendRequest(h2::Error),

    #[error("H2 response error: {0}")]
    RecvResponse(h2::Error),

    #[error("H2 response body error: {0}")]
    RecvBody(h2::Error),

    #[error("H3 send_response error: {0:?}")]
    H3SendResponse(h3::error::StreamError),

    #[error("H3 send_data error: {0}")]
    H3SendData(String),

    #[error("H3 finish error: {0:?}")]
    H3Finish(h3::error::StreamError),

    #[error("H3 recv_data error: {0:?}")]
    H3RecvData(h3::error::StreamError),

    #[error("request body exceeded limit")]
    RequestTooLarge,

    #[error("failed to build response: {0}")]
    BuildResponse(String),

    #[error("H2 send body error: {0}")]
    SendBody(h2::Error),

    #[error("H2 flow control capacity error: {0}")]
    FlowControl(h2::Error),

    /// A single H3 `recv_data()` call didn't return within the per-chunk
    /// timeout window defined by [`super::stream_guard::CHUNK_READ_TIMEOUT`]
    /// or the remaining wall-clock from [`BodyDeadline`].
    #[error("H3 request body chunk read timed out")]
    RequestChunkTimeout,

    /// The H2 peer's flow-control window stayed closed past
    /// [`super::stream_guard::H2_CAPACITY_WAIT`] — the upstream is
    /// effectively stalled, not just slow.
    #[error("H2 upstream flow-control window did not open in time")]
    UpstreamCapacityTimeout,

    /// The cumulative wall-clock for one body transfer has been exceeded
    /// (see [`super::stream_guard::BODY_WALL_CLOCK`]). This catches
    /// slow-loris peers that trickle bytes below the per-chunk threshold.
    #[error("body transfer exceeded wall-clock budget")]
    BodyDeadlineExceeded,
}

/// Maximum request body size (same as H1 bridge, Guardrail #28).
const MAX_REQUEST_BODY: usize = 10 * 1024 * 1024; // 10 MB

/// Proxy a single H3 request via an H2 upstream connection.
///
/// 1. Convert H3 headers → H2 request
/// 2. Stream request body: H3 `recv_data` → H2 `send_data`
/// 3. Receive H2 response headers → run plugins → send H3 response
/// 4. Stream response body: H2 `recv_data` → plugins → H3 `send_data`
///
/// Flow control is handled by the `h2` crate. We call
/// `release_capacity()` after consuming each DATA frame to prevent
/// deadlock.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub async fn stream_via_h2<S, B>(
    h3_stream: &mut RequestStream<S, B>,
    mut sender: h2::client::SendRequest<Bytes>,
    method: &http::Method,
    uri: &http::Uri,
    headers: &http::HeaderMap,
    plugin_chain: &PluginChain,
    ctx: &mut PluginCtx,
) -> Result<(), H2BridgeError>
where
    S: h3::quic::SendStream<B> + h3::quic::RecvStream,
    B: bytes::Buf + From<Bytes> + Send + 'static,
    Bytes: From<B>,
{
    // Build the H2 request from H3 headers.
    let has_body = *method != http::Method::GET && *method != http::Method::HEAD;
    let end_of_stream = !has_body;

    let h2_request =
        build_h2_request(method, uri, headers).map_err(H2BridgeError::BuildResponse)?;

    // Send request headers. Returns (ResponseFuture, SendStream).
    let (response_future, mut send_stream) = sender
        .send_request(h2_request, end_of_stream)
        .map_err(H2BridgeError::SendRequest)?;

    // Stream request body from H3 to H2 (if present).
    //
    // Invariants enforced by this loop:
    //
    // * Per-chunk recv_data timeout — a stalled H3 client can't pin
    //   the stream forever (Guardrail #29).
    // * Wall-clock deadline across the whole body — slow-loris clients
    //   that trickle one byte at a time within the per-chunk window
    //   still hit a 5-minute ceiling (BodyDeadline).
    // * Reserve + await-capacity before every send_data — the h2
    //   crate explicitly documents that send_data without reserved
    //   capacity buffers unboundedly in memory. Awaiting poll_capacity
    //   propagates back-pressure up to the H3 client: if the upstream
    //   is slow, h3 recv_data() is not polled, and quinn's receive
    //   window drains, throttling the client transport-level rather
    //   than piling bytes onto our heap.
    // * Total body bytes bounded by MAX_REQUEST_BODY (Guardrail #28).
    if has_body {
        let deadline = BodyDeadline::new();
        let mut total_body = 0usize;

        loop {
            if deadline.is_exhausted() {
                return Err(H2BridgeError::BodyDeadlineExceeded);
            }

            let recv = with_chunk_deadline(deadline, h3_stream.recv_data())
                .await
                .map_err(|_elapsed| H2BridgeError::RequestChunkTimeout)?
                .map_err(H2BridgeError::H3RecvData)?;

            let Some(mut chunk) = recv else {
                break;
            };

            // Zero-copy conversion: `recv_data` returns `impl Buf`, which
            // h3-quinn monomorphises to `Bytes`. `Bytes` overrides
            // `Buf::copy_to_bytes` to be `split_to` — an O(1) ref-count
            // bump, no memcpy. Using the default trait path (BytesMut +
            // BufMut::put + freeze) would instead clone the bytes on
            // every chunk, defeating the streaming invariant.
            let len = chunk.remaining();
            let frozen: Bytes = chunk.copy_to_bytes(len);

            total_body = total_body
                .checked_add(len)
                .ok_or(H2BridgeError::RequestTooLarge)?;
            if total_body > MAX_REQUEST_BODY {
                return Err(H2BridgeError::RequestTooLarge);
            }

            if len > 0 {
                // Reserve the window slice for this chunk, then block until
                // the upstream actually grants it. If the upstream window
                // is closed and stays closed past H2_CAPACITY_WAIT, bail.
                send_stream.reserve_capacity(len);
                match await_h2_capacity(&mut send_stream, len).await {
                    Ok(()) => {}
                    Err(H2CapacityError::Timeout) => {
                        return Err(H2BridgeError::UpstreamCapacityTimeout);
                    }
                    Err(H2CapacityError::H2(e)) => {
                        return Err(H2BridgeError::FlowControl(e));
                    }
                }

                send_stream
                    .send_data(frozen, false)
                    .map_err(H2BridgeError::SendBody)?;
            }
        }

        // Signal end of request body. The zero-length final frame does
        // not need flow-control capacity.
        send_stream
            .send_data(Bytes::new(), true)
            .map_err(H2BridgeError::SendBody)?;
    }

    // Receive response headers from H2.
    let h2_response = response_future.await.map_err(H2BridgeError::RecvResponse)?;
    let (parts, mut recv_stream) = h2_response.into_parts();

    // Build Pingora response headers for plugin chain.
    let mut pingora_resp = ResponseHeader::build(parts.status.as_u16(), Some(parts.headers.len()))
        .map_err(|e| H2BridgeError::BuildResponse(e.to_string()))?;

    for (name, value) in &parts.headers {
        let name_str = name.as_str();
        if !is_hop_by_hop(name_str)
            && let Ok(v) = value.to_str()
        {
            let _ = pingora_resp.insert_header(name_str.to_owned(), v.to_owned());
        }
    }

    // Run response plugins.
    plugin_chain.run_response(&mut pingora_resp, ctx);

    // Send H3 response headers.
    let h3_resp = pingora_resp_to_h3(&pingora_resp, parts.status.as_u16())
        .map_err(H2BridgeError::BuildResponse)?;

    h3_stream
        .send_response(h3_resp)
        .await
        .map_err(H2BridgeError::H3SendResponse)?;

    // Stream response body: H2 → plugins → H3.
    //
    // The h2 crate yields Bytes directly (zero-copy from its internal
    // buffer). Each recv is bounded by a per-chunk timeout so a wedged
    // upstream can't keep the H3 stream open forever, and the whole
    // body transfer is bounded by a 5-minute wall-clock.
    let resp_deadline = BodyDeadline::new();
    loop {
        if resp_deadline.is_exhausted() {
            return Err(H2BridgeError::BodyDeadlineExceeded);
        }

        let next = with_chunk_deadline(resp_deadline, recv_stream.data())
            .await
            .map_err(|_elapsed| H2BridgeError::RequestChunkTimeout)?;

        let Some(chunk) = next else {
            break;
        };
        let chunk = chunk.map_err(H2BridgeError::RecvBody)?;
        let len = chunk.len();

        if len > 0 {
            // Release flow control capacity immediately after consuming the
            // DATA frame. This prevents deadlock where the sender is waiting
            // for window space and the receiver is waiting for data.
            let () = recv_stream
                .flow_control()
                .release_capacity(len)
                .map_err(H2BridgeError::FlowControl)?;

            // Run body plugins.
            let mut body_opt = Some(chunk);
            plugin_chain.run_body(&mut body_opt, false, ctx);
            let data = body_opt.unwrap_or_default();
            if !data.is_empty() {
                h3_stream
                    .send_data(B::from(data))
                    .await
                    .map_err(|e| H2BridgeError::H3SendData(format!("{e:?}")))?;
            }
        }
    }

    // Signal end of response body to plugins and H3.
    {
        let mut body_opt: Option<Bytes> = None;
        plugin_chain.run_body(&mut body_opt, true, ctx);
        if let Some(final_data) = body_opt
            && !final_data.is_empty()
        {
            h3_stream
                .send_data(B::from(final_data))
                .await
                .map_err(|e| H2BridgeError::H3SendData(format!("{e:?}")))?;
        }
    }

    h3_stream.finish().await.map_err(H2BridgeError::H3Finish)?;

    Ok(())
}

/// Build an `http::Request<()>` suitable for `h2::client::SendRequest`.
///
/// Copies non-pseudo, non-hop-by-hop headers from the H3 request.
/// Strips `content-length` and `transfer-encoding` (H2 uses DATA frame
/// boundaries for body framing).
fn build_h2_request(
    method: &http::Method,
    uri: &http::Uri,
    headers: &http::HeaderMap,
) -> Result<http::Request<()>, String> {
    let mut builder = http::Request::builder()
        .method(method.clone())
        .uri(uri.clone());

    for (name, value) in headers {
        let name_str = name.as_str();
        // Skip pseudo-headers (h2 sets these from the Request builder)
        if name_str.starts_with(':') {
            continue;
        }
        // Skip hop-by-hop headers (not valid in H2)
        if is_hop_by_hop(name_str) {
            continue;
        }
        // Skip framing headers (H2 handles these)
        if name_str.eq_ignore_ascii_case("content-length")
            || name_str.eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        builder = builder.header(name, value);
    }

    builder
        .body(())
        .map_err(|e| format!("build H2 request: {e}"))
}
