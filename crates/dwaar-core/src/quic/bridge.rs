// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Upstream TCP bridge for the HTTP/3 path.
//!
//! Handles request body draining, HTTP/1.1 forwarding over TCP, response
//! parsing, and chunked transfer-encoding decoding. The streaming rewrite
//! (ISSUE-108) will replace the buffered `forward_to_upstream` path with
//! incremental header parsing and chunk-by-chunk body streaming.

use std::net::SocketAddr;

use bytes::Bytes;
use compact_str::CompactString;
use h3::server::RequestStream;

use super::convert::is_hop_by_hop;

/// Cap on client request body size. Clients exceeding this receive 413.
pub const MAX_REQUEST_BODY: usize = 10 * 1024 * 1024; // 10 MB

/// Cap on upstream response body size over the buffered path.
pub const MAX_UPSTREAM_RESPONSE: usize = 10 * 1024 * 1024; // 10 MB

/// Timeout for the full upstream round-trip (connect + write + read).
pub const UPSTREAM_TIMEOUT_SECS: u64 = 30;

/// Parsed HTTP/1.1 response: (status, headers, body).
pub type Http1Response = (u16, Vec<(String, String)>, Bytes);

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

/// Read all request body chunks from the h3 stream into a single [`Bytes`].
///
/// HTTP/3 body arrives as a sequence of DATA frames. We read until the peer
/// signals end-of-stream (`recv_data` returns `None`), or until the accumulated
/// size exceeds [`MAX_REQUEST_BODY`], whichever comes first.
pub async fn drain_request_body<S, B>(
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
/// Returns `(status, headers, body)`. The entire round-trip is bounded by
/// [`UPSTREAM_TIMEOUT_SECS`] to prevent a slow upstream from holding a QUIC
/// stream open indefinitely.
pub async fn forward_to_upstream(
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

    let path = uri.path_and_query().map_or("/", |pq| pq.as_str());
    let host = uri
        .authority()
        .map_or_else(|| upstream_addr.to_string(), |a| a.as_str().to_owned());

    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n");

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

/// Parse a raw HTTP/1.1 response into `(status, headers, body)`.
pub fn parse_http1_response(raw: &[u8]) -> Result<Http1Response, String> {
    let split_pos = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "HTTP response missing header/body separator".to_string())?;

    let head = std::str::from_utf8(&raw[..split_pos])
        .map_err(|e| format!("non-UTF-8 response head: {e}"))?;
    let raw_body = &raw[split_pos + 4..];

    let mut lines = head.lines();
    let status_line = lines.next().ok_or("empty response")?;

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
fn decode_chunked(mut input: &[u8]) -> Result<Bytes, String> {
    let mut out = Vec::new();

    loop {
        let crlf = input
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| "chunked: missing CRLF after chunk size".to_string())?;

        let size_line = std::str::from_utf8(&input[..crlf])
            .map_err(|_| "chunked: non-UTF-8 chunk size line".to_string())?;

        let size_str = size_line.split(';').next().unwrap_or("").trim();
        let chunk_size = usize::from_str_radix(size_str, 16)
            .map_err(|_| format!("chunked: invalid chunk size: {size_str:?}"))?;

        input = &input[crlf + 2..];

        if chunk_size == 0 {
            break;
        }

        if input.len() < chunk_size + 2 {
            return Err(format!(
                "chunked: truncated chunk (expected {} + 2 bytes, got {})",
                chunk_size,
                input.len()
            ));
        }

        out.extend_from_slice(&input[..chunk_size]);
        input = &input[chunk_size + 2..];
    }

    Ok(Bytes::from(out))
}

// ── Streaming bridge (ISSUE-108) ─────────────────────────────────────────────

/// Chunk size for reading upstream response body and forwarding to h3.
pub const BRIDGE_CHUNK_SIZE: usize = 64 * 1024; // 64 KB

/// Maximum HTTP/1.1 response header block size (Guardrail #28).
const MAX_HEADER_SIZE: usize = 8 * 1024; // 8 KB

/// Parsed response headers from the upstream.
///
/// Header names and values use [`CompactString`] — stores ≤24 bytes
/// inline without heap allocation. Most HTTP header names fit inline
/// (e.g. "content-type" = 12 bytes, "cache-control" = 13 bytes).
#[derive(Debug)]
pub struct UpstreamResponseHead {
    pub status: u16,
    pub headers: Vec<(CompactString, CompactString)>,
    /// How the body is framed — determines how we read it.
    pub body_framing: BodyFraming,
    /// Leftover bytes after the header block that belong to the body.
    pub body_prefix: Vec<u8>,
}

/// How an HTTP/1.1 response body is framed.
#[derive(Debug)]
pub enum BodyFraming {
    /// `Content-Length: N` — read exactly N bytes.
    ContentLength(usize),
    /// `Transfer-Encoding: chunked` — decode chunk framing.
    Chunked,
    /// No explicit framing — read until EOF. Connection is not reusable.
    CloseDelimited,
}

/// Write the HTTP/1.1 request line and headers to the upstream TCP stream.
///
/// If `content_length` is known (from the h3 request), uses `Content-Length`.
/// Otherwise uses `Transfer-Encoding: chunked` so body can be streamed
/// without knowing the total size upfront.
///
/// Uses `Connection: keep-alive` to enable connection pooling.
pub async fn write_request_head(
    tcp: &mut tokio::net::TcpStream,
    method: &http::Method,
    uri: &http::Uri,
    req_headers: &http::HeaderMap,
    content_length: Option<u64>,
) -> Result<(), UpstreamError> {
    use tokio::io::AsyncWriteExt;

    let path = uri.path_and_query().map_or("/", |pq| pq.as_str());
    let host = uri
        .authority()
        .map_or_else(|| "localhost".to_owned(), |a| a.as_str().to_owned());

    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n");

    for (name, value) in req_headers {
        let name_str = name.as_str();
        // Skip pseudo-headers, hop-by-hop, and Content-Length (we set our
        // own framing — forwarding the h3 client's Content-Length would
        // conflict with chunked encoding on the TCP side).
        if name_str.starts_with(':')
            || is_hop_by_hop(name_str)
            || name_str.eq_ignore_ascii_case("content-length")
        {
            continue;
        }
        if let Ok(v) = value.to_str() {
            head.push_str(name_str);
            head.push_str(": ");
            head.push_str(v);
            head.push_str("\r\n");
        }
    }

    if let Some(len) = content_length {
        use std::fmt::Write as _;
        let _ = write!(head, "Content-Length: {len}\r\n");
    } else if method != http::Method::GET && method != http::Method::HEAD {
        head.push_str("Transfer-Encoding: chunked\r\n");
    }

    head.push_str("Connection: keep-alive\r\n\r\n");

    tcp.write_all(head.as_bytes())
        .await
        .map_err(UpstreamError::Write)
}

/// Write a single chunk in HTTP/1.1 chunked encoding.
pub async fn write_chunked_data(
    tcp: &mut tokio::net::TcpStream,
    data: &[u8],
) -> Result<(), UpstreamError> {
    use tokio::io::AsyncWriteExt;

    let header = format!("{:x}\r\n", data.len());
    tcp.write_all(header.as_bytes())
        .await
        .map_err(UpstreamError::Write)?;
    tcp.write_all(data).await.map_err(UpstreamError::Write)?;
    tcp.write_all(b"\r\n").await.map_err(UpstreamError::Write)
}

/// Write the terminal chunk (`0\r\n\r\n`) to signal end of chunked body.
pub async fn write_chunked_end(tcp: &mut tokio::net::TcpStream) -> Result<(), UpstreamError> {
    use tokio::io::AsyncWriteExt;
    tcp.write_all(b"0\r\n\r\n")
        .await
        .map_err(UpstreamError::Write)
}

/// Parse response headers incrementally using the connection's own buffer.
///
/// Reads into [`BufferedConn::read_buf`] (bounded at 8 KB by the
/// `MAX_HEADER_SIZE` check) until the full header block arrives. Returns
/// the parsed headers plus any leftover body bytes that were read past
/// the header boundary.
pub async fn read_response_head(
    conn: &mut super::pool::BufferedConn,
) -> Result<UpstreamResponseHead, UpstreamError> {
    loop {
        if conn.buffered() >= MAX_HEADER_SIZE {
            return Err(UpstreamError::Parse(
                "response headers exceed 8 KB limit".into(),
            ));
        }

        // Try to parse what we have so far before reading more.
        {
            let mut headers_buf = [httparse::EMPTY_HEADER; 64];
            let mut resp = httparse::Response::new(&mut headers_buf);

            match resp.parse(&conn.read_buf) {
                Ok(httparse::Status::Complete(header_len)) => {
                    let status = resp.code.unwrap_or(502);

                    let mut headers = Vec::with_capacity(resp.headers.len());
                    let mut content_length: Option<usize> = None;
                    let mut is_chunked = false;

                    for h in resp.headers.iter() {
                        let name = CompactString::from(h.name);
                        let value = CompactString::from(String::from_utf8_lossy(h.value).as_ref());

                        if name.eq_ignore_ascii_case("content-length") {
                            content_length = value.trim().parse().ok();
                        }
                        if name.eq_ignore_ascii_case("transfer-encoding")
                            && value.eq_ignore_ascii_case("chunked")
                        {
                            is_chunked = true;
                        }
                        headers.push((name, value));
                    }

                    let body_framing = if is_chunked {
                        BodyFraming::Chunked
                    } else if let Some(len) = content_length {
                        BodyFraming::ContentLength(len)
                    } else {
                        BodyFraming::CloseDelimited
                    };

                    // Consume the header bytes, leave body prefix in the buffer.
                    let filled = conn.buffered();
                    let _ = conn.take_bytes(header_len);
                    let body_prefix = if filled > header_len {
                        conn.take_bytes(filled - header_len).to_vec()
                    } else {
                        Vec::new()
                    };

                    return Ok(UpstreamResponseHead {
                        status,
                        headers,
                        body_framing,
                        body_prefix,
                    });
                }
                Ok(httparse::Status::Partial) => {
                    // Need more data — fall through to read.
                }
                Err(e) => {
                    return Err(UpstreamError::Parse(format!("httparse error: {e}")));
                }
            }
        }

        // Read more data into the connection's buffer.
        let n = conn.read_into_buf().await.map_err(UpstreamError::Read)?;
        if n == 0 {
            return Err(UpstreamError::Parse(
                "upstream closed before sending complete headers".into(),
            ));
        }
    }
}

/// Read exactly `remaining` bytes from `tcp`, yielding chunks of up to
/// `BRIDGE_CHUNK_SIZE`. Calls `on_chunk` for each chunk with `(data, is_last)`.
pub async fn stream_content_length_body<F, Fut>(
    tcp: &mut tokio::net::TcpStream,
    prefix: &[u8],
    total: usize,
    mut on_chunk: F,
) -> Result<bool, UpstreamError>
where
    F: FnMut(Bytes, bool) -> Fut,
    Fut: std::future::Future<Output = Result<(), UpstreamError>>,
{
    use tokio::io::AsyncReadExt;

    let mut sent = 0usize;

    // First, yield whatever we already have from the header read.
    if !prefix.is_empty() {
        let n = prefix.len().min(total);
        sent += n;
        let is_last = sent >= total;
        on_chunk(Bytes::copy_from_slice(&prefix[..n]), is_last).await?;
        if is_last {
            return Ok(true); // reusable
        }
    }

    let mut buf = vec![0u8; BRIDGE_CHUNK_SIZE];
    while sent < total {
        let to_read = (total - sent).min(BRIDGE_CHUNK_SIZE);
        let n = tcp
            .read(&mut buf[..to_read])
            .await
            .map_err(UpstreamError::Read)?;
        if n == 0 {
            return Err(UpstreamError::Parse(
                "upstream closed before content-length fulfilled".into(),
            ));
        }
        sent += n;
        let is_last = sent >= total;
        on_chunk(Bytes::copy_from_slice(&buf[..n]), is_last).await?;
    }

    Ok(true) // connection is reusable
}

/// Read a close-delimited body (no Content-Length, no chunked). Reads until
/// EOF, yielding chunks. Connection is NOT reusable after this.
pub async fn stream_close_delimited_body<F, Fut>(
    tcp: &mut tokio::net::TcpStream,
    prefix: &[u8],
    mut on_chunk: F,
) -> Result<bool, UpstreamError>
where
    F: FnMut(Bytes, bool) -> Fut,
    Fut: std::future::Future<Output = Result<(), UpstreamError>>,
{
    use tokio::io::AsyncReadExt;

    if !prefix.is_empty() {
        on_chunk(Bytes::copy_from_slice(prefix), false).await?;
    }

    let mut buf = vec![0u8; BRIDGE_CHUNK_SIZE];
    loop {
        let n = tcp.read(&mut buf).await.map_err(UpstreamError::Read)?;
        if n == 0 {
            // EOF — send a final empty-ish signal if we sent data before.
            on_chunk(Bytes::new(), true).await?;
            break;
        }
        on_chunk(Bytes::copy_from_slice(&buf[..n]), false).await?;
    }

    Ok(false) // not reusable — we read until EOF
}

/// Read a chunked transfer-encoded body, decoding the framing and yielding
/// decoded data chunks. Returns whether the connection is reusable.
pub async fn stream_chunked_body<F, Fut>(
    tcp: &mut tokio::net::TcpStream,
    prefix: &[u8],
    mut on_chunk: F,
) -> Result<bool, UpstreamError>
where
    F: FnMut(Bytes, bool) -> Fut,
    Fut: std::future::Future<Output = Result<(), UpstreamError>>,
{
    use tokio::io::AsyncReadExt;

    // Accumulator for raw chunked data. We read into it and decode
    // chunk-by-chunk, yielding decoded payloads to on_chunk.
    let mut raw = Vec::from(prefix);
    let mut buf = vec![0u8; BRIDGE_CHUNK_SIZE];

    loop {
        // Drain all complete chunks from the buffer before hitting the network.
        // A single TCP read can carry multiple HTTP chunks — we must decode all
        // of them before blocking on the next read.
        #[allow(clippy::needless_continue)]
        if let Some((payload, consumed, is_terminal)) = try_decode_one_chunk(&raw)? {
            raw.drain(..consumed);

            if is_terminal {
                on_chunk(Bytes::new(), true).await?;
                return Ok(true); // reusable
            }

            if !payload.is_empty() {
                on_chunk(Bytes::from(payload), false).await?;
            }
            continue;
        }

        // Buffer exhausted — read more from the network.
        let n = tcp.read(&mut buf).await.map_err(UpstreamError::Read)?;
        if n == 0 {
            return Err(UpstreamError::Parse(
                "upstream closed mid-chunked-body".into(),
            ));
        }

        // Bound the accumulator (Guardrail #28).
        if raw.len() + n > 10 * 1024 * 1024 {
            return Err(UpstreamError::ResponseTooLarge);
        }
        raw.extend_from_slice(&buf[..n]);
    }
}

/// Try to decode one chunk from the front of `raw`.
///
/// Returns `Some((payload, bytes_consumed, is_terminal))` if a complete
/// chunk was found, `None` if more data is needed.
pub fn try_decode_one_chunk(raw: &[u8]) -> Result<Option<(Vec<u8>, usize, bool)>, UpstreamError> {
    // Find the chunk-size line ending.
    let Some(crlf) = raw.windows(2).position(|w| w == b"\r\n") else {
        return Ok(None); // need more data
    };

    let size_line = std::str::from_utf8(&raw[..crlf])
        .map_err(|_| UpstreamError::Parse("chunked: non-UTF-8 size line".into()))?;

    let size_str = size_line.split(';').next().unwrap_or("").trim();
    let chunk_size = usize::from_str_radix(size_str, 16)
        .map_err(|_| UpstreamError::Parse(format!("chunked: bad size: {size_str:?}")))?;

    if chunk_size == 0 {
        // Terminal chunk: `0\r\n\r\n`. We must consume the trailing CRLF
        // before declaring done — otherwise the 2 leftover bytes corrupt
        // the next request on a pooled keep-alive connection.
        let after_size = crlf + 2; // past `0\r\n`
        if raw.len() < after_size + 2 {
            return Ok(None); // trailing CRLF not yet received
        }
        return Ok(Some((vec![], after_size + 2, true)));
    }

    // Need chunk_size + 2 bytes (data + trailing CRLF) after the size line.
    let data_start = crlf + 2;
    let needed = data_start + chunk_size + 2;
    if raw.len() < needed {
        return Ok(None); // need more data
    }

    let payload = raw[data_start..data_start + chunk_size].to_vec();
    Ok(Some((payload, needed, false)))
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn try_decode_one_chunk_complete() {
        let raw = b"5\r\nhello\r\n0\r\n\r\n";
        let (payload, consumed, terminal) =
            try_decode_one_chunk(raw).expect("ok").expect("complete");
        assert_eq!(payload, b"hello");
        assert_eq!(consumed, 10); // "5\r\nhello\r\n"
        assert!(!terminal);

        // Decode terminal
        let rest = &raw[consumed..];
        let (payload2, _, terminal2) = try_decode_one_chunk(rest).expect("ok").expect("complete");
        assert!(payload2.is_empty());
        assert!(terminal2);
    }

    #[test]
    fn try_decode_one_chunk_partial() {
        let raw = b"5\r\nhel"; // incomplete
        assert!(try_decode_one_chunk(raw).expect("ok").is_none());
    }

    #[test]
    fn try_decode_terminal_chunk_needs_trailing_crlf() {
        // `0\r\n` without the trailing `\r\n` — must return None (need more
        // data), NOT terminal. Otherwise 2 bytes are left in the TCP stream
        // and the next request on a pooled connection sees `\r\nHTTP/1.1 ...`.
        let raw = b"0\r\n";
        assert!(
            try_decode_one_chunk(raw).expect("ok").is_none(),
            "terminal chunk without trailing CRLF should request more data"
        );
    }

    #[test]
    fn try_decode_terminal_chunk_complete() {
        let raw = b"0\r\n\r\n";
        let (payload, consumed, terminal) =
            try_decode_one_chunk(raw).expect("ok").expect("complete");
        assert!(payload.is_empty());
        assert!(terminal);
        assert_eq!(consumed, 5, "must consume the full 0\\r\\n\\r\\n sequence");
    }

    #[tokio::test]
    async fn stream_chunked_body_drains_all_chunks_from_single_read() {
        // Upstream sends multiple chunks + terminal in a single TCP write.
        // Without the `continue` after decoding, the decoder blocks on a
        // network read instead of draining the buffer — and hangs forever
        // on a keep-alive connection.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");

        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            use tokio::io::AsyncWriteExt;
            // All chunks in one write.
            sock.write_all(b"5\r\nhello\r\n3\r\nfoo\r\n0\r\n\r\n")
                .await
                .expect("write");
            // Keep connection open — don't drop or shutdown.
            // If the decoder wrongly does a network read after the first chunk,
            // it will hang here instead of completing.
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        });

        let mut tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");

        let mut chunks = Vec::new();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream_chunked_body(&mut tcp, &[], |chunk, is_last| {
                chunks.push((chunk.to_vec(), is_last));
                async { Ok(()) }
            }),
        )
        .await;

        let reusable = result
            .expect("should not timeout — all chunks were in the buffer")
            .expect("decode should succeed");

        assert!(reusable, "chunked body with terminal chunk is reusable");
        assert_eq!(chunks.len(), 3, "hello + foo + terminal");
        assert_eq!(chunks[0].0, b"hello");
        assert_eq!(chunks[1].0, b"foo");
        assert!(chunks[2].1, "last chunk should be final");
    }

    #[tokio::test]
    async fn read_response_head_parses_headers() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");

        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            use tokio::io::AsyncWriteExt;
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                .await
                .expect("write");
        });

        let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let mut conn = crate::quic::pool::BufferedConn::new(tcp);
        let head = read_response_head(&mut conn).await.expect("parse");

        assert_eq!(head.status, 200);
        assert!(head.headers.iter().any(|(k, _)| k == "Content-Length"));
        assert!(matches!(head.body_framing, BodyFraming::ContentLength(5)));
        assert_eq!(head.body_prefix, b"hello");
    }

    #[tokio::test]
    async fn stream_content_length_body_yields_chunks() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");

        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            use tokio::io::AsyncWriteExt;
            // Write a 10-byte body.
            sock.write_all(b"0123456789").await.expect("write");
        });

        let mut tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");

        let mut chunks = Vec::new();
        stream_content_length_body(&mut tcp, &[], 10, |chunk, is_last| {
            chunks.push((chunk, is_last));
            async { Ok(()) }
        })
        .await
        .expect("stream");

        let total: usize = chunks.iter().map(|(c, _)| c.len()).sum();
        assert_eq!(total, 10);
        assert!(
            chunks.last().expect("has chunks").1,
            "last chunk should be final"
        );
    }
}
