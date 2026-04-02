// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Streaming response body compression.
//!
//! Negotiates the best encoding from the client's `Accept-Encoding` header,
//! then compresses response body chunks as they flow through the proxy.
//!
//! ## Pipeline position
//!
//! In `response_body_filter()`, compression runs **after** analytics injection:
//!
//! ```text
//! upstream chunk → decompress → inject analytics → COMPRESS → client
//! ```
//!
//! This ensures the analytics script is injected into uncompressed HTML,
//! then the entire modified response is recompressed for the wire.

use std::io::Write;

use bytes::Bytes;
use pingora_http::ResponseHeader;
use tracing::debug;

use crate::plugin::{DwaarPlugin, PluginAction, PluginCtx};

/// Minimum response body size worth compressing. Below this threshold,
/// compression overhead (headers, framing) can actually increase size.
const MIN_COMPRESS_SIZE: u64 = 1024;

/// Compression encoding, ordered by preference: brotli > gzip > zstd.
/// Brotli achieves ~20% better compression than gzip at similar CPU.
/// Zstd is fast but has limited browser support (Chrome 123+).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressEncoding {
    Brotli,
    Gzip,
    Zstd,
}

impl CompressEncoding {
    /// The `Content-Encoding` header value for this encoding.
    pub fn header_value(self) -> &'static str {
        match self {
            Self::Brotli => "br",
            Self::Gzip => "gzip",
            Self::Zstd => "zstd",
        }
    }
}

/// Parse `Accept-Encoding` header and pick the best encoding we support.
///
/// Priority: brotli > gzip. Respects `q=0` (explicitly disabled).
/// Returns `None` if the client doesn't accept anything we support.
pub fn negotiate_encoding(accept_encoding: &str) -> Option<CompressEncoding> {
    let mut best: Option<(CompressEncoding, f32, u8)> = None;

    for part in accept_encoding.split(',') {
        let part = part.trim();
        let (name, quality) = parse_encoding_with_quality(part);

        if quality <= 0.0 {
            continue;
        }

        let (encoding, priority) = match name {
            "br" => (CompressEncoding::Brotli, 3),
            "gzip" | "x-gzip" => (CompressEncoding::Gzip, 2),
            "zstd" => (CompressEncoding::Zstd, 1),
            _ => continue,
        };

        // Client quality takes precedence. On equal quality, our priority
        // order wins (brotli=3 > gzip=2 > zstd=1).
        // Compare quality as fixed-point to avoid float comparison lint.
        // Multiply by 1000 and compare as integers (q values have at most 3 decimal places).
        #[allow(clippy::cast_possible_truncation)]
        let q_int = (quality * 1000.0) as i32;
        let dominated = best.as_ref().is_none_or(|(_, bq, bp)| {
            #[allow(clippy::cast_possible_truncation)]
            let bq_int = (*bq * 1000.0) as i32;
            q_int > bq_int || (q_int == bq_int && priority > *bp)
        });
        if dominated {
            best = Some((encoding, quality, priority));
        }
    }

    best.map(|(enc, _, _)| enc)
}

/// Parse "gzip;q=0.8" into ("gzip", 0.8). Missing q defaults to 1.0.
fn parse_encoding_with_quality(part: &str) -> (&str, f32) {
    if let Some((name, params)) = part.split_once(';') {
        let name = name.trim();
        let quality = params
            .split(';')
            .find_map(|p| {
                let p = p.trim();
                p.strip_prefix("q=")
                    .and_then(|q| q.trim().parse::<f32>().ok())
            })
            .unwrap_or(1.0);
        (name, quality)
    } else {
        (part.trim(), 1.0)
    }
}

/// Content types eligible for compression. Binary formats (images, video,
/// fonts) are already compressed and re-compressing wastes CPU.
/// `application/grpc` is intentionally absent — gRPC has its own compression
/// protocol (`grpc-encoding` header). Double-compressing breaks gRPC framing.
const COMPRESSIBLE_TYPES: &[&str] = &[
    "text/html",
    "text/css",
    "text/javascript",
    "text/plain",
    "text/xml",
    "application/javascript",
    "application/json",
    "application/xml",
    "application/xhtml+xml",
    "image/svg+xml",
    "application/wasm",
];

/// Check if a `Content-Type` header value is compressible.
pub fn is_compressible(content_type: &str) -> bool {
    // Strip charset/boundary params: "text/html; charset=utf-8" → "text/html"
    let mime = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim();
    COMPRESSIBLE_TYPES
        .iter()
        .any(|ct| mime.eq_ignore_ascii_case(ct))
}

/// Check if compression should be applied to this response.
pub fn should_compress(
    content_type: Option<&str>,
    content_encoding: Option<&str>,
    content_length: Option<u64>,
) -> bool {
    // Already compressed — don't double-compress
    if content_encoding.is_some_and(|ce| !ce.eq_ignore_ascii_case("identity")) {
        return false;
    }

    // Not a compressible content type
    let Some(ct) = content_type else {
        return false;
    };
    if !is_compressible(ct) {
        return false;
    }

    // Too small to benefit from compression
    if content_length.is_some_and(|len| len < MIN_COMPRESS_SIZE) {
        return false;
    }

    true
}

/// Streaming compressor for response body chunks.
///
/// Created in `response_filter()` after negotiating encoding. Each call
/// to `compress()` in `response_body_filter()` compresses a chunk and
/// replaces the body bytes in-place.
pub struct ResponseCompressor {
    encoding: CompressEncoding,
    gzip_encoder: Option<flate2::write::GzEncoder<Vec<u8>>>,
    brotli_encoder: Option<brotli::CompressorWriter<Vec<u8>>>,
    zstd_encoder: Option<zstd::stream::write::Encoder<'static, Vec<u8>>>,
}

impl std::fmt::Debug for ResponseCompressor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseCompressor")
            .field("encoding", &self.encoding)
            .field("gzip_encoder", &self.gzip_encoder.is_some())
            .field("brotli_encoder", &self.brotli_encoder.is_some())
            .field("zstd_encoder", &self.zstd_encoder.is_some())
            .finish()
    }
}

impl ResponseCompressor {
    /// Create a new compressor for the given encoding.
    pub fn new(encoding: CompressEncoding) -> Self {
        match encoding {
            CompressEncoding::Gzip => Self {
                encoding,
                gzip_encoder: Some(flate2::write::GzEncoder::new(
                    Vec::new(),
                    flate2::Compression::fast(),
                )),
                brotli_encoder: None,
                zstd_encoder: None,
            },
            CompressEncoding::Brotli => Self {
                encoding,
                gzip_encoder: None,
                // quality 4 = good balance of speed and ratio (default is 11, too slow for proxying)
                brotli_encoder: Some(brotli::CompressorWriter::new(Vec::new(), 4096, 4, 22)),
                zstd_encoder: None,
            },
            CompressEncoding::Zstd => Self {
                encoding,
                gzip_encoder: None,
                brotli_encoder: None,
                // level 3 = fast compression (default is 3, range 1-22)
                zstd_encoder: zstd::stream::write::Encoder::new(Vec::new(), 3).ok(),
            },
        }
    }

    /// The encoding this compressor uses (for setting `Content-Encoding`).
    pub fn encoding(&self) -> CompressEncoding {
        self.encoding
    }

    /// Compress a body chunk. Replaces `body` with compressed bytes.
    /// At end-of-stream, flushes the compressor to emit final bytes.
    pub fn compress(&mut self, body: &mut Option<Bytes>, end_of_stream: bool) {
        // Take data out of the option to avoid borrow conflicts
        let data = body.take().unwrap_or_default();

        if data.is_empty() && !end_of_stream {
            *body = Some(Bytes::new());
            return;
        }

        let compressed = self.compress_bytes(&data, end_of_stream);
        *body = Some(compressed);
    }

    fn compress_bytes(&mut self, data: &[u8], end_of_stream: bool) -> Bytes {
        // Feed data into encoder
        if !data.is_empty() {
            let write_result = match self.encoding {
                CompressEncoding::Gzip => self
                    .gzip_encoder
                    .as_mut()
                    .map_or(Ok(()), |e| e.write_all(data)),
                CompressEncoding::Brotli => self
                    .brotli_encoder
                    .as_mut()
                    .map_or(Ok(()), |e| e.write_all(data)),
                CompressEncoding::Zstd => self
                    .zstd_encoder
                    .as_mut()
                    .map_or(Ok(()), |e| e.write_all(data)),
            };
            if let Err(e) = write_result {
                debug!(error = %e, "compression write error");
                return Bytes::from(data.to_vec());
            }
        }

        if end_of_stream {
            return self.finish().unwrap_or_default();
        }

        // Flush to produce output for this chunk
        self.flush_encoder()
    }

    fn flush_encoder(&mut self) -> Bytes {
        match self.encoding {
            CompressEncoding::Gzip => {
                if let Some(ref mut encoder) = self.gzip_encoder {
                    let _ = encoder.flush();
                    let inner = encoder.get_mut();
                    if !inner.is_empty() {
                        return Bytes::from(std::mem::take(inner));
                    }
                }
                Bytes::new()
            }
            CompressEncoding::Brotli => {
                if let Some(ref mut encoder) = self.brotli_encoder {
                    let _ = encoder.flush();
                    let inner = encoder.get_mut();
                    if !inner.is_empty() {
                        return Bytes::from(std::mem::take(inner));
                    }
                }
                Bytes::new()
            }
            CompressEncoding::Zstd => {
                if let Some(ref mut encoder) = self.zstd_encoder {
                    let _ = encoder.flush();
                    let inner = encoder.get_mut();
                    if !inner.is_empty() {
                        return Bytes::from(std::mem::take(inner));
                    }
                }
                Bytes::new()
            }
        }
    }

    /// Finalize the compressor and return remaining bytes.
    fn finish(&mut self) -> Option<Bytes> {
        match self.encoding {
            CompressEncoding::Gzip => {
                if let Some(encoder) = self.gzip_encoder.take() {
                    match encoder.finish() {
                        Ok(buf) if !buf.is_empty() => Some(Bytes::from(buf)),
                        Ok(_) => Some(Bytes::new()),
                        Err(e) => {
                            debug!(error = %e, "gzip finalization error");
                            Some(Bytes::new())
                        }
                    }
                } else {
                    None
                }
            }
            CompressEncoding::Brotli => {
                if let Some(encoder) = self.brotli_encoder.take() {
                    // into_inner() flushes and finalizes
                    match encoder.into_inner() {
                        buf if !buf.is_empty() => Some(Bytes::from(buf)),
                        _ => Some(Bytes::new()),
                    }
                } else {
                    None
                }
            }
            CompressEncoding::Zstd => {
                if let Some(encoder) = self.zstd_encoder.take() {
                    match encoder.finish() {
                        Ok(buf) if !buf.is_empty() => Some(Bytes::from(buf)),
                        Ok(_) => Some(Bytes::new()),
                        Err(e) => {
                            debug!(error = %e, "zstd finalization error");
                            Some(Bytes::new())
                        }
                    }
                } else {
                    None
                }
            }
        }
    }
}

/// Plugin wrapper that negotiates and applies response compression.
///
/// Priority 90 — runs late in the response phase (after analytics injection
/// setup by the core proxy), and runs in body phase to compress chunks.
///
/// In `on_response`: checks Accept-Encoding (from `PluginCtx`), Content-Type,
/// Content-Encoding, Content-Length from the response, creates a compressor
/// if appropriate, and sets the Content-Encoding header.
///
/// In `on_body`: compresses each chunk using the compressor set in `on_response`.
#[derive(Debug)]
pub struct CompressionPlugin;

impl CompressionPlugin {
    pub fn new() -> Self {
        Self
    }
}

impl Default for CompressionPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl DwaarPlugin for CompressionPlugin {
    fn name(&self) -> &'static str {
        "compression"
    }

    fn priority(&self) -> u16 {
        90
    }

    fn on_response(&self, resp: &mut ResponseHeader, ctx: &mut PluginCtx) -> PluginAction {
        if ctx.accept_encoding.is_empty() {
            return PluginAction::Continue;
        }

        let content_type = resp
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok());

        let content_encoding = resp
            .headers
            .get(http::header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok());

        let content_length = resp
            .headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        if !should_compress(content_type, content_encoding, content_length) {
            return PluginAction::Continue;
        }

        let Some(enc) = negotiate_encoding(&ctx.accept_encoding) else {
            return PluginAction::Continue;
        };

        ctx.compressor = Some(ResponseCompressor::new(enc));
        resp.insert_header("Content-Encoding", enc.header_value())
            .expect("static header value");
        resp.remove_header("Content-Length");

        debug!(
            encoding = enc.header_value(),
            "compression plugin: encoding negotiated"
        );

        PluginAction::Continue
    }

    fn on_body(
        &self,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut PluginCtx,
    ) -> PluginAction {
        if let Some(ref mut compressor) = ctx.compressor {
            compressor.compress(body, end_of_stream);
        }
        PluginAction::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::GzDecoder;
    use std::io::Read;

    // ── Encoding negotiation ───────────────────────────────────────

    #[test]
    fn negotiate_prefers_brotli() {
        assert_eq!(
            negotiate_encoding("gzip, br"),
            Some(CompressEncoding::Brotli)
        );
    }

    #[test]
    fn negotiate_gzip_when_no_brotli() {
        assert_eq!(
            negotiate_encoding("gzip, deflate"),
            Some(CompressEncoding::Gzip)
        );
    }

    #[test]
    fn negotiate_respects_quality() {
        // Client explicitly prefers gzip over brotli
        assert_eq!(
            negotiate_encoding("br;q=0.5, gzip;q=1.0"),
            Some(CompressEncoding::Gzip)
        );
    }

    #[test]
    fn negotiate_q_zero_disables() {
        // Client disables gzip
        assert_eq!(
            negotiate_encoding("gzip;q=0, br"),
            Some(CompressEncoding::Brotli)
        );
    }

    #[test]
    fn negotiate_zstd() {
        assert_eq!(negotiate_encoding("zstd"), Some(CompressEncoding::Zstd));
    }

    #[test]
    fn negotiate_unsupported_returns_none() {
        assert_eq!(negotiate_encoding("compress, identity"), None);
    }

    #[test]
    fn negotiate_empty_returns_none() {
        assert_eq!(negotiate_encoding(""), None);
    }

    #[test]
    fn negotiate_x_gzip() {
        assert_eq!(negotiate_encoding("x-gzip"), Some(CompressEncoding::Gzip));
    }

    // ── Content type checks ────────────────────────────────────────

    #[test]
    fn html_is_compressible() {
        assert!(is_compressible("text/html"));
        assert!(is_compressible("text/html; charset=utf-8"));
    }

    #[test]
    fn json_is_compressible() {
        assert!(is_compressible("application/json"));
    }

    #[test]
    fn svg_is_compressible() {
        assert!(is_compressible("image/svg+xml"));
    }

    #[test]
    fn png_is_not_compressible() {
        assert!(!is_compressible("image/png"));
    }

    #[test]
    fn octet_stream_is_not_compressible() {
        assert!(!is_compressible("application/octet-stream"));
    }

    #[test]
    fn grpc_is_not_compressible() {
        assert!(!is_compressible("application/grpc"));
        assert!(!is_compressible("application/grpc+proto"));
        assert!(!is_compressible("application/grpc-web"));
    }

    // ── Should-compress logic ──────────────────────────────────────

    #[test]
    fn skip_already_compressed() {
        assert!(!should_compress(
            Some("text/html"),
            Some("gzip"),
            Some(5000)
        ));
    }

    #[test]
    fn skip_small_response() {
        assert!(!should_compress(Some("text/html"), None, Some(500)));
    }

    #[test]
    fn skip_binary_type() {
        assert!(!should_compress(Some("image/png"), None, Some(50000)));
    }

    #[test]
    fn compress_html_no_encoding() {
        assert!(should_compress(Some("text/html"), None, Some(5000)));
    }

    #[test]
    fn compress_when_content_length_unknown() {
        // Chunked transfer — no Content-Length
        assert!(should_compress(Some("text/html"), None, None));
    }

    #[test]
    fn identity_encoding_is_not_already_compressed() {
        assert!(should_compress(
            Some("text/html"),
            Some("identity"),
            Some(5000)
        ));
    }

    // ── Gzip compression ───────────────────────────────────────────

    #[test]
    fn gzip_single_chunk() {
        let mut compressor = ResponseCompressor::new(CompressEncoding::Gzip);
        let input = b"Hello, World! This is a test string that should be compressed by gzip.";
        let mut body = Some(Bytes::from(input.as_slice()));

        compressor.compress(&mut body, true);

        let compressed = body.expect("should have output");
        assert!(!compressed.is_empty());

        // Verify it decompresses correctly
        let mut decoder = GzDecoder::new(&compressed[..]);
        let mut decompressed = String::new();
        decoder
            .read_to_string(&mut decompressed)
            .expect("decompress");
        assert_eq!(decompressed.as_bytes(), input);
    }

    #[test]
    fn gzip_multi_chunk() {
        let mut compressor = ResponseCompressor::new(CompressEncoding::Gzip);
        let mut all_compressed = Vec::new();

        let chunk1 = b"First chunk of data. ";
        let mut body = Some(Bytes::from(chunk1.as_slice()));
        compressor.compress(&mut body, false);
        if let Some(ref b) = body {
            all_compressed.extend_from_slice(b);
        }

        let chunk2 = b"Second chunk of data.";
        body = Some(Bytes::from(chunk2.as_slice()));
        compressor.compress(&mut body, true);
        if let Some(ref b) = body {
            all_compressed.extend_from_slice(b);
        }

        let mut decoder = GzDecoder::new(&all_compressed[..]);
        let mut decompressed = String::new();
        decoder
            .read_to_string(&mut decompressed)
            .expect("decompress");
        assert_eq!(decompressed, "First chunk of data. Second chunk of data.");
    }

    // ── Brotli compression ─────────────────────────────────────────

    #[test]
    fn brotli_single_chunk() {
        let mut compressor = ResponseCompressor::new(CompressEncoding::Brotli);
        let input = b"Hello, World! This is a test string that should be compressed by brotli.";
        let mut body = Some(Bytes::from(input.as_slice()));

        compressor.compress(&mut body, true);

        let compressed = body.expect("should have output");
        assert!(!compressed.is_empty());

        // Verify it decompresses correctly
        let mut decompressed = Vec::new();
        brotli::BrotliDecompress(&mut &compressed[..], &mut decompressed).expect("decompress");
        assert_eq!(decompressed, input);
    }

    #[test]
    fn brotli_multi_chunk() {
        let mut compressor = ResponseCompressor::new(CompressEncoding::Brotli);
        let mut all_compressed = Vec::new();

        let chunk1 = b"First chunk of brotli data. ";
        let mut body = Some(Bytes::from(chunk1.as_slice()));
        compressor.compress(&mut body, false);
        if let Some(ref b) = body {
            all_compressed.extend_from_slice(b);
        }

        let chunk2 = b"Second chunk of brotli data.";
        body = Some(Bytes::from(chunk2.as_slice()));
        compressor.compress(&mut body, true);
        if let Some(ref b) = body {
            all_compressed.extend_from_slice(b);
        }

        let mut decompressed = Vec::new();
        brotli::BrotliDecompress(&mut &all_compressed[..], &mut decompressed).expect("decompress");
        assert_eq!(
            String::from_utf8(decompressed).expect("utf8"),
            "First chunk of brotli data. Second chunk of brotli data."
        );
    }

    // ── Zstd compression ────────────────────────────────────────────

    #[test]
    fn zstd_single_chunk() {
        let mut compressor = ResponseCompressor::new(CompressEncoding::Zstd);
        let input = b"Hello, World! This is a test string that should be compressed by zstd.";
        let mut body = Some(Bytes::from(input.as_slice()));

        compressor.compress(&mut body, true);

        let compressed = body.expect("should have output");
        assert!(!compressed.is_empty());

        let decompressed = zstd::stream::decode_all(&compressed[..]).expect("decompress");
        assert_eq!(decompressed, input);
    }

    #[test]
    fn zstd_multi_chunk() {
        let mut compressor = ResponseCompressor::new(CompressEncoding::Zstd);
        let mut all_compressed = Vec::new();

        let chunk1 = b"First chunk of zstd data. ";
        let mut body = Some(Bytes::from(chunk1.as_slice()));
        compressor.compress(&mut body, false);
        if let Some(ref b) = body {
            all_compressed.extend_from_slice(b);
        }

        let chunk2 = b"Second chunk of zstd data.";
        body = Some(Bytes::from(chunk2.as_slice()));
        compressor.compress(&mut body, true);
        if let Some(ref b) = body {
            all_compressed.extend_from_slice(b);
        }

        let decompressed = zstd::stream::decode_all(&all_compressed[..]).expect("decompress");
        assert_eq!(
            String::from_utf8(decompressed).expect("utf8"),
            "First chunk of zstd data. Second chunk of zstd data."
        );
    }

    // ── Edge cases ─────────────────────────────────────────────────

    #[test]
    fn empty_body_produces_valid_output() {
        let mut compressor = ResponseCompressor::new(CompressEncoding::Gzip);
        let mut body: Option<Bytes> = Some(Bytes::new());
        compressor.compress(&mut body, true);
        // Should produce valid (empty) gzip stream
        assert!(body.is_some());
    }
}
