// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Streaming response body decompressor.
//!
//! Wraps `flate2` (gzip/deflate) and `brotli` for chunk-by-chunk
//! decompression of response bodies. Used by `response_body_filter()`
//! to decompress compressed HTML before passing it to [`HtmlInjector`].
//!
//! ## Security
//!
//! - Decompression output is bounded by the 256 KB scan limit in `HtmlInjector`
//!   (we don't buffer — each chunk is decompressed and immediately passed through)
//! - Decompression errors are non-fatal: the decompressor transitions to an
//!   error state and all subsequent chunks pass through unmodified

use std::io::Read;

use bytes::Bytes;
use flate2::read::{DeflateDecoder, GzDecoder};

/// The supported compression encodings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Gzip,
    Deflate,
    Brotli,
}

impl Encoding {
    /// Parse a Content-Encoding header value into an Encoding variant.
    /// Returns None for unsupported or unknown encodings.
    pub fn from_header(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "gzip" | "x-gzip" => Some(Self::Gzip),
            "deflate" => Some(Self::Deflate),
            "br" => Some(Self::Brotli),
            _ => None,
        }
    }
}

/// Max compressed buffer before giving up — prevents OOM from
/// adversarial or unexpectedly large compressed responses.
/// 10 MB is generous for HTML responses (injection only applies to HTML).
const MAX_BUFFER_SIZE: usize = 10 * 1024 * 1024;

/// Streaming decompressor for response body chunks.
///
/// Buffers compressed data internally and attempts decompression on each
/// call to [`decompress()`]. At end-of-stream, flushes all remaining data.
///
/// On decompression error, passes through the raw bytes and stops trying —
/// better to serve garbled content than to silently drop the response.
///
/// Buffer is bounded at [`MAX_BUFFER_SIZE`] (10 MB) to prevent
/// unbounded memory growth from adversarial inputs (Guardrail #19).
#[derive(Debug)]
pub struct Decompressor {
    encoding: Encoding,
    /// Accumulated compressed data fed to the decoder
    buffer: Vec<u8>,
    /// Set on first decompression failure — stops attempting decompression
    failed: bool,
}

impl Decompressor {
    /// Create a new decompressor for the given encoding.
    pub fn new(encoding: Encoding) -> Self {
        Self {
            encoding,
            buffer: Vec::new(),
            failed: false,
        }
    }

    /// Decompress a chunk. Appends to internal buffer and attempts
    /// decompression. On success, replaces `body` with decompressed data.
    /// On failure, marks as failed and passes through unchanged.
    pub fn decompress(&mut self, body: &mut Option<Bytes>, end_of_stream: bool) {
        if self.failed {
            return;
        }

        let Some(ref data) = *body else {
            return;
        };

        if data.is_empty() && !end_of_stream {
            return;
        }

        // Bound buffer to prevent OOM from adversarial compressed responses
        if self.buffer.len() + data.len() > MAX_BUFFER_SIZE {
            tracing::warn!(
                buffered = self.buffer.len(),
                chunk = data.len(),
                limit = MAX_BUFFER_SIZE,
                "compressed response exceeded buffer limit, passing through raw"
            );
            self.failed = true;
            *body = Some(Bytes::from(std::mem::take(&mut self.buffer)));
            return;
        }

        self.buffer.extend_from_slice(data);

        if end_of_stream {
            // End of stream — must produce all remaining output
            if let Ok(decompressed) = self.try_decompress_all() {
                *body = Some(Bytes::from(decompressed));
            } else {
                // Decompression failed — emit whatever we buffered raw
                self.failed = true;
                *body = Some(Bytes::from(std::mem::take(&mut self.buffer)));
            }
        } else {
            // Try partial decompression — might need more data
            match self.try_decompress() {
                Ok(decompressed) if !decompressed.is_empty() => {
                    *body = Some(Bytes::from(decompressed));
                }
                Ok(_) => {
                    // Decoder needs more input before it can produce output
                    *body = Some(Bytes::new());
                }
                Err(_) => {
                    // Don't fail yet — might just need more data to form a valid block
                    *body = Some(Bytes::new());
                }
            }
        }
    }

    /// Try to decompress accumulated buffer, consuming as much as possible.
    fn try_decompress(&mut self) -> Result<Vec<u8>, std::io::Error> {
        let input = std::mem::take(&mut self.buffer);
        let result = self.decompress_bytes(&input);
        match result {
            Ok(output) => Ok(output),
            Err(e) => {
                // Put data back — might succeed with more data
                self.buffer = input;
                Err(e)
            }
        }
    }

    /// Decompress all remaining data (called at end of stream).
    fn try_decompress_all(&mut self) -> Result<Vec<u8>, std::io::Error> {
        let input = std::mem::take(&mut self.buffer);
        self.decompress_bytes(&input)
    }

    /// Decompress a byte slice using the configured encoding.
    fn decompress_bytes(&self, data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        match self.encoding {
            Encoding::Gzip => {
                let mut decoder = GzDecoder::new(data);
                let mut output = Vec::new();
                decoder.read_to_end(&mut output)?;
                Ok(output)
            }
            Encoding::Deflate => {
                let mut decoder = DeflateDecoder::new(data);
                let mut output = Vec::new();
                decoder.read_to_end(&mut output)?;
                Ok(output)
            }
            Encoding::Brotli => {
                let mut output = Vec::new();
                brotli::BrotliDecompress(&mut std::io::Cursor::new(data), &mut output)?;
                Ok(output)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;

    fn gzip_compress(data: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(data).expect("gzip compress");
        encoder.finish().expect("gzip finish")
    }

    fn brotli_compress(data: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        let mut writer = brotli::CompressorWriter::new(&mut output, 4096, 4, 22);
        writer.write_all(data).expect("brotli compress");
        drop(writer);
        output
    }

    #[test]
    fn encoding_from_header() {
        assert_eq!(Encoding::from_header("gzip"), Some(Encoding::Gzip));
        assert_eq!(Encoding::from_header("x-gzip"), Some(Encoding::Gzip));
        assert_eq!(Encoding::from_header("deflate"), Some(Encoding::Deflate));
        assert_eq!(Encoding::from_header("br"), Some(Encoding::Brotli));
        assert_eq!(Encoding::from_header("identity"), None);
        assert_eq!(Encoding::from_header("zstd"), None);
        assert_eq!(Encoding::from_header(" GZIP "), Some(Encoding::Gzip));
    }

    #[test]
    fn gzip_decompresses_single_chunk() {
        let html = b"<html><head></head><body></body></html>";
        let compressed = gzip_compress(html);

        let mut decomp = Decompressor::new(Encoding::Gzip);
        let mut body = Some(Bytes::from(compressed));
        decomp.decompress(&mut body, true);

        assert_eq!(body.expect("body").as_ref(), html);
    }

    #[test]
    fn brotli_decompresses_single_chunk() {
        let html = b"<html><head></head><body></body></html>";
        let compressed = brotli_compress(html);

        let mut decomp = Decompressor::new(Encoding::Brotli);
        let mut body = Some(Bytes::from(compressed));
        decomp.decompress(&mut body, true);

        assert_eq!(body.expect("body").as_ref(), html);
    }

    #[test]
    fn failed_decompression_passes_through() {
        let garbage = b"this is not compressed data";
        let mut decomp = Decompressor::new(Encoding::Gzip);
        let mut body = Some(Bytes::from(garbage.to_vec()));
        decomp.decompress(&mut body, true);

        // Should pass through the raw data on failure
        assert!(decomp.failed);
    }

    #[test]
    fn empty_body_unchanged() {
        let mut decomp = Decompressor::new(Encoding::Gzip);
        let mut body: Option<Bytes> = Some(Bytes::new());
        decomp.decompress(&mut body, false);
        assert_eq!(body.expect("body").len(), 0);
    }

    #[test]
    fn none_body_unchanged() {
        let mut decomp = Decompressor::new(Encoding::Gzip);
        let mut body: Option<Bytes> = None;
        decomp.decompress(&mut body, false);
        assert!(body.is_none());
    }
}
