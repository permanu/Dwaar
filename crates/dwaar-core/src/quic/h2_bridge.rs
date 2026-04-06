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

use bytes::Bytes;
use dwaar_plugins::plugin::{PluginChain, PluginCtx};
use h3::server::RequestStream;
use pingora_http::ResponseHeader;
use super::convert::{is_hop_by_hop, pingora_resp_to_h3};

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
}

/// Maximum request body size (same as H1 bridge, Guardrail #28).
const MAX_REQUEST_BODY: usize = 10 * 1024 * 1024; // 10 MB

/// Proxy a single H3 request via an H2 upstream connection.
///
/// 1. Convert H3 headers → H2 request
/// 2. Stream request body: H3 recv_data → H2 send_data
/// 3. Receive H2 response headers → run plugins → send H3 response
/// 4. Stream response body: H2 recv_data → plugins → H3 send_data
///
/// Flow control is handled by the `h2` crate. We call
/// `release_capacity()` after consuming each DATA frame to prevent
/// deadlock.
#[allow(clippy::too_many_arguments)]
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

    let h2_request = build_h2_request(method, uri, headers)
        .map_err(|e| H2BridgeError::BuildResponse(e))?;

    // Send request headers. Returns (ResponseFuture, SendStream).
    let (response_future, mut send_stream) = sender
        .send_request(h2_request, end_of_stream)
        .map_err(H2BridgeError::SendRequest)?;

    // Stream request body from H3 to H2 (if present).
    if has_body {
        let mut total_body = 0usize;
        while let Some(chunk) = h3_stream.recv_data().await.map_err(H2BridgeError::H3RecvData)? {
            use bytes::Buf;
            let remaining = chunk.remaining();
            total_body += remaining;
            if total_body > MAX_REQUEST_BODY {
                return Err(H2BridgeError::RequestTooLarge);
            }
            let mut data = bytes::BytesMut::with_capacity(remaining);
            bytes::BufMut::put(&mut data, chunk);
            let frozen = data.freeze();

            // Reserve capacity before sending (H2 flow control).
            send_stream.reserve_capacity(frozen.len());
            send_stream
                .send_data(frozen, false)
                .map_err(H2BridgeError::SendBody)?;
        }
        // Signal end of request body.
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
        if !is_hop_by_hop(name_str) {
            if let Ok(v) = value.to_str() {
                let _ = pingora_resp.insert_header(
                    name_str.to_owned(),
                    v.to_owned(),
                );
            }
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
    // The h2 crate yields Bytes directly (zero-copy from its internal buffer).
    while let Some(chunk) = recv_stream.data().await {
        let chunk = chunk.map_err(H2BridgeError::RecvBody)?;
        let len = chunk.len();

        if len > 0 {
            // Release flow control capacity immediately after consuming the
            // DATA frame. This prevents deadlock where the sender is waiting
            // for window space and the receiver is waiting for data.
            let _ = recv_stream
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
        if let Some(final_data) = body_opt {
            if !final_data.is_empty() {
                h3_stream
                    .send_data(B::from(final_data))
                    .await
                    .map_err(|e| H2BridgeError::H3SendData(format!("{e:?}")))?;
            }
        }
    }

    h3_stream
        .finish()
        .await
        .map_err(H2BridgeError::H3Finish)?;

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

    builder.body(()).map_err(|e| format!("build H2 request: {e}"))
}
