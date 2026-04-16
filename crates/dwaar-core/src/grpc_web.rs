// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! gRPC-Web ↔ gRPC protocol translation.
//!
//! Browsers cannot speak native gRPC (HTTP/2 with trailers), so gRPC-Web
//! clients send requests as `application/grpc-web` (binary) or
//! `application/grpc-web-text` (base64-encoded). This module translates
//! those into standard `application/grpc` for the upstream and reverses
//! the translation on the response path.
//!
//! The translation is transparent — no Dwaarfile directive needed. If a
//! request arrives with a gRPC-Web content type, Dwaar auto-translates.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use bytes::{BufMut, Bytes, BytesMut};

/// The 5-byte gRPC frame header: 1 flag byte + 4-byte big-endian length.
const GRPC_FRAME_HEADER_LEN: usize = 5;

/// Flag byte indicating a trailer frame (as opposed to 0x00 for data).
const TRAILER_FLAG: u8 = 0x80;

/// Which gRPC-Web encoding variant the client used. Stored in
/// [`RequestContext`] so the response path knows how to encode back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrpcWebMode {
    /// `application/grpc-web` — binary wire format, no base64.
    Binary,
    /// `application/grpc-web-text` — body is base64-encoded.
    Text,
}

/// Errors specific to gRPC-Web translation.
#[derive(Debug, thiserror::Error)]
pub enum GrpcWebError {
    #[error("invalid base64 in grpc-web-text body")]
    InvalidBase64(#[from] base64::DecodeError),
}

/// Check whether a `Content-Type` value indicates a gRPC-Web request.
///
/// Matches `application/grpc-web` and `application/grpc-web-text` (with
/// optional `+proto`/`+json` suffixes and `;charset=…` parameters) but
/// rejects plain `application/grpc` so existing transparent gRPC proxy
/// remains untouched.
pub fn is_grpc_web(content_type: &str) -> bool {
    let ct = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim();
    ct.eq_ignore_ascii_case("application/grpc-web")
        || ct.starts_with("application/grpc-web+")
        || ct.eq_ignore_ascii_case("application/grpc-web-text")
        || ct.starts_with("application/grpc-web-text+")
}

/// Check whether the content type is the base64 text variant.
pub fn is_grpc_web_text(content_type: &str) -> bool {
    let ct = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim();
    ct.eq_ignore_ascii_case("application/grpc-web-text")
        || ct.starts_with("application/grpc-web-text+")
}

/// Determine the [`GrpcWebMode`] from a content-type string.
///
/// Returns `None` if the content type is not gRPC-Web at all.
pub fn detect_mode(content_type: &str) -> Option<GrpcWebMode> {
    if !is_grpc_web(content_type) {
        return None;
    }
    if is_grpc_web_text(content_type) {
        Some(GrpcWebMode::Text)
    } else {
        Some(GrpcWebMode::Binary)
    }
}

/// Translate request headers from gRPC-Web to standard gRPC for the upstream.
///
/// - Rewrites `Content-Type` from `application/grpc-web*` to `application/grpc`
/// - Adds `TE: trailers` so the upstream knows we accept HTTP/2 trailers
///
/// Called in `upstream_request_filter()` after gRPC-Web mode is detected.
pub fn translate_request_headers(
    headers: &mut pingora_http::RequestHeader,
) -> pingora_core::Result<()> {
    headers.insert_header("content-type", "application/grpc")?;
    headers.insert_header("te", "trailers")?;
    Ok(())
}

/// Translate upstream gRPC response headers back to gRPC-Web for the client.
///
/// - Rewrites `Content-Type` to match the original gRPC-Web variant
/// - Adds CORS headers required by browser gRPC-Web clients
pub fn translate_response_headers(
    headers: &mut pingora_http::ResponseHeader,
    mode: GrpcWebMode,
) -> pingora_core::Result<()> {
    let ct = match mode {
        GrpcWebMode::Binary => "application/grpc-web",
        GrpcWebMode::Text => "application/grpc-web-text",
    };
    headers.insert_header("content-type", ct)?;

    // gRPC-Web browser clients need CORS to read grpc-status/grpc-message
    // from the response. Expose these so the client library can parse them.
    headers.insert_header("access-control-expose-headers", "grpc-status,grpc-message")?;

    Ok(())
}

/// Encode HTTP/2 trailers into a gRPC trailer frame.
///
/// The gRPC-Web spec encodes trailers as a gRPC frame with flag byte 0x80,
/// followed by the trailers serialized as HTTP/1.1-style `key: value\r\n`
/// pairs. This replaces the HTTP/2 HEADERS frame that browsers can't access.
///
/// ```text
/// +------+----------+---------------------------+
/// | 0x80 | 4-byte   | trailer1: val1\r\n        |
/// |      | length   | trailer2: val2\r\n        |
/// +------+----------+---------------------------+
/// ```
pub fn encode_trailers_frame(trailers: &[(String, String)]) -> Bytes {
    // Pre-calculate the payload size to avoid reallocations.
    let payload_len: usize = trailers
        .iter()
        .map(|(k, v)| k.len() + 2 + v.len() + 2) // "key: value\r\n"
        .sum();

    let mut buf = BytesMut::with_capacity(GRPC_FRAME_HEADER_LEN + payload_len);

    // Frame header: trailer flag + big-endian payload length
    buf.put_u8(TRAILER_FLAG);
    // Payload fits in u32 — gRPC messages are capped well below 4 GiB.
    #[allow(clippy::cast_possible_truncation)]
    let len = payload_len as u32;
    buf.put_u32(len);

    for (key, value) in trailers {
        buf.put_slice(key.as_bytes());
        buf.put_slice(b": ");
        buf.put_slice(value.as_bytes());
        buf.put_slice(b"\r\n");
    }

    buf.freeze()
}

/// Base64-decode a gRPC-Web-Text request body.
pub fn decode_text_body(body: &[u8]) -> Result<Bytes, GrpcWebError> {
    let decoded = BASE64.decode(body)?;
    Ok(Bytes::from(decoded))
}

/// Base64-encode a response body for gRPC-Web-Text.
pub fn encode_text_body(body: &[u8]) -> Bytes {
    Bytes::from(BASE64.encode(body))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Detection ---

    #[test]
    fn detects_grpc_web_binary() {
        assert!(is_grpc_web("application/grpc-web"));
        assert!(is_grpc_web("application/grpc-web+proto"));
        assert!(is_grpc_web("application/grpc-web+json"));
        assert!(is_grpc_web("application/grpc-web;charset=utf-8"));
    }

    #[test]
    fn detects_grpc_web_text() {
        assert!(is_grpc_web("application/grpc-web-text"));
        assert!(is_grpc_web("application/grpc-web-text+proto"));
        assert!(is_grpc_web_text("application/grpc-web-text"));
        assert!(is_grpc_web_text("application/grpc-web-text+proto"));
    }

    #[test]
    fn rejects_plain_grpc() {
        assert!(!is_grpc_web("application/grpc"));
        assert!(!is_grpc_web("application/grpc+proto"));
    }

    #[test]
    fn rejects_unrelated_types() {
        assert!(!is_grpc_web("text/html"));
        assert!(!is_grpc_web("application/json"));
        assert!(!is_grpc_web(""));
    }

    #[test]
    fn text_variant_not_detected_as_binary() {
        assert!(!is_grpc_web_text("application/grpc-web"));
        assert!(!is_grpc_web_text("application/grpc-web+proto"));
    }

    #[test]
    fn detect_mode_binary() {
        assert_eq!(
            detect_mode("application/grpc-web"),
            Some(GrpcWebMode::Binary)
        );
        assert_eq!(
            detect_mode("application/grpc-web+proto"),
            Some(GrpcWebMode::Binary)
        );
    }

    #[test]
    fn detect_mode_text() {
        assert_eq!(
            detect_mode("application/grpc-web-text"),
            Some(GrpcWebMode::Text)
        );
        assert_eq!(
            detect_mode("application/grpc-web-text+proto"),
            Some(GrpcWebMode::Text)
        );
    }

    #[test]
    fn detect_mode_none_for_non_grpc_web() {
        assert_eq!(detect_mode("application/grpc"), None);
        assert_eq!(detect_mode("text/plain"), None);
    }

    // --- Trailer encoding ---

    #[test]
    fn encode_trailers_frame_produces_valid_grpc_frame() {
        let trailers = vec![
            ("grpc-status".to_string(), "0".to_string()),
            ("grpc-message".to_string(), "OK".to_string()),
        ];
        let frame = encode_trailers_frame(&trailers);

        // Flag byte must be 0x80 (trailer)
        assert_eq!(frame[0], 0x80);

        // Length field (bytes 1..5) is big-endian u32
        let len = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]);
        let payload = &frame[GRPC_FRAME_HEADER_LEN..];
        assert_eq!(len as usize, payload.len());

        // Payload is key-value pairs separated by \r\n
        let text = std::str::from_utf8(payload).expect("valid UTF-8");
        assert!(text.contains("grpc-status: 0\r\n"));
        assert!(text.contains("grpc-message: OK\r\n"));
    }

    #[test]
    fn encode_trailers_frame_empty() {
        let frame = encode_trailers_frame(&[]);
        assert_eq!(frame.len(), GRPC_FRAME_HEADER_LEN);
        assert_eq!(frame[0], 0x80);
        assert_eq!(&frame[1..5], &[0, 0, 0, 0]);
    }

    // --- Base64 round-trip ---

    #[test]
    fn text_body_round_trip() {
        let original = b"\x00\x00\x00\x00\x05hello";
        let encoded = encode_text_body(original);
        let decoded = decode_text_body(&encoded).expect("valid base64");
        assert_eq!(&decoded[..], original);
    }

    #[test]
    fn decode_invalid_base64_returns_error() {
        assert!(decode_text_body(b"not!valid!base64!!!").is_err());
    }

    #[test]
    fn text_body_encodes_grpc_frame_correctly() {
        // A minimal gRPC data frame: flag=0, length=5, payload="hello"
        let grpc_frame = {
            let mut buf = BytesMut::with_capacity(10);
            buf.put_u8(0x00);
            buf.put_u32(5);
            buf.put_slice(b"hello");
            buf.freeze()
        };
        let encoded = encode_text_body(&grpc_frame);
        let decoded = decode_text_body(&encoded).expect("round-trip");
        assert_eq!(decoded, grpc_frame);
    }

    // --- Request header translation ---

    #[test]
    fn translate_request_headers_sets_grpc_content_type() {
        let mut header =
            RequestHeader::build("POST", b"/test.Service/Method", None).expect("valid header");
        header
            .insert_header("content-type", "application/grpc-web")
            .expect("insert");

        translate_request_headers(&mut header).expect("translate");

        let ct = header.headers.get("content-type").expect("content-type");
        assert_eq!(ct.to_str().expect("str"), "application/grpc");

        let te = header.headers.get("te").expect("te header");
        assert_eq!(te.to_str().expect("str"), "trailers");
    }

    // --- Response header translation ---

    #[test]
    fn translate_response_headers_binary_mode() {
        let mut header = ResponseHeader::build(200, Some(4)).expect("valid header");
        header
            .insert_header("content-type", "application/grpc")
            .expect("insert");

        translate_response_headers(&mut header, GrpcWebMode::Binary).expect("translate");

        let ct = header.headers.get("content-type").expect("content-type");
        assert_eq!(ct.to_str().expect("str"), "application/grpc-web");

        // CORS expose headers present
        let expose = header
            .headers
            .get("access-control-expose-headers")
            .expect("expose");
        assert!(expose.to_str().expect("str").contains("grpc-status"));
    }

    #[test]
    fn translate_response_headers_text_mode() {
        let mut header = ResponseHeader::build(200, Some(4)).expect("valid header");
        header
            .insert_header("content-type", "application/grpc")
            .expect("insert");

        translate_response_headers(&mut header, GrpcWebMode::Text).expect("translate");

        let ct = header.headers.get("content-type").expect("content-type");
        assert_eq!(ct.to_str().expect("str"), "application/grpc-web-text");
    }

    // --- Integration-style tests ---

    #[test]
    fn full_binary_flow_headers() {
        // Simulate: client sends grpc-web → translate to grpc → upstream responds → translate back
        let mut req_header = RequestHeader::build("POST", b"/pkg.Svc/Method", None).expect("valid");
        req_header
            .insert_header("content-type", "application/grpc-web")
            .expect("insert");

        // Detect mode
        let ct = req_header
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .expect("ct");
        let mode = detect_mode(ct).expect("grpc-web");
        assert_eq!(mode, GrpcWebMode::Binary);

        // Translate request
        translate_request_headers(&mut req_header).expect("translate req");
        assert_eq!(
            req_header
                .headers
                .get("content-type")
                .expect("content-type header must be present")
                .to_str()
                .expect("content-type must be valid UTF-8"),
            "application/grpc"
        );

        // Simulate upstream response
        let mut resp_header = ResponseHeader::build(200, Some(4)).expect("valid");
        resp_header
            .insert_header("content-type", "application/grpc")
            .expect("insert");

        // Translate response back
        translate_response_headers(&mut resp_header, mode).expect("translate resp");
        assert_eq!(
            resp_header
                .headers
                .get("content-type")
                .expect("content-type header must be present")
                .to_str()
                .expect("content-type must be valid UTF-8"),
            "application/grpc-web"
        );
    }

    #[test]
    fn full_text_flow_body() {
        // Simulate: client sends base64-encoded body → decode → process → re-encode
        let original_body = b"\x00\x00\x00\x00\x0bhello world";
        let client_body = encode_text_body(original_body);

        // Proxy decodes for upstream
        let decoded = decode_text_body(&client_body).expect("decode");
        assert_eq!(&decoded[..], original_body);

        // Upstream responds with binary gRPC, proxy re-encodes for client
        let upstream_body = b"\x00\x00\x00\x00\x02ok";
        let response_body = encode_text_body(upstream_body);
        let client_decoded = decode_text_body(&response_body).expect("round-trip");
        assert_eq!(&client_decoded[..], upstream_body);
    }

    use pingora_http::{RequestHeader, ResponseHeader};
}
