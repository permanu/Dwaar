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
/// 256 KB matches `HtmlInjector::MAX_SCAN_BYTES` — the injector only
/// scans the first 256 KB of decompressed output, so buffering more
/// compressed data is wasted memory.
const MAX_BUFFER_SIZE: usize = 256 * 1024;

/// Max decompressed output size — prevents decompression bombs where a small
/// compressed payload expands to gigabytes. 100 MB matches Guardrail #28's
/// response body cap.
const MAX_DECOMPRESSED_SIZE: usize = 100 * 1024 * 1024;

/// Initial capacity for the `read_bounded` output buffer. 32 KiB covers
/// the lower end of typical decompressed HTML pages without re-growing,
/// while staying small enough not to over-commit memory for tiny
/// responses. See issue #155.
const READ_BOUNDED_INITIAL_CAPACITY: usize = 32 * 1024;

/// Read chunk size for `read_bounded`. 16 KiB matches typical decoder
/// output granularity and halves the syscall count vs the old 8 KiB
/// chunk size on large payloads. See issue #155.
const READ_BOUNDED_CHUNK_SIZE: usize = 16 * 1024;

/// Streaming decompressor for response body chunks.
///
/// Buffers compressed data internally and attempts decompression on each
/// call to [`decompress()`]. At end-of-stream, flushes all remaining data.
///
/// On decompression error, passes through the raw bytes and stops trying —
/// better to serve garbled content than to silently drop the response.
///
/// Buffer is bounded at [`MAX_BUFFER_SIZE`] (256 KB) to prevent
/// unbounded memory growth from adversarial inputs (Guardrail #19).
/// Matches `HtmlInjector::MAX_SCAN_BYTES` — injection only scans
/// the first 256 KB of decompressed output.
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
    ///
    /// Pre-allocates 8 KiB for the internal feed buffer so that typical
    /// small compressed HTML responses fit in the first chunk without
    /// triggering a realloc cascade. The compressed `<head>` of a typical
    /// HTML page lands in the 2–8 KiB range, so 8 KiB avoids a first-chunk
    /// realloc without over-committing memory for small responses. See issue #153.
    pub fn new(encoding: Encoding) -> Self {
        Self {
            encoding,
            buffer: Vec::with_capacity(8192),
            failed: false,
        }
    }

    /// Returns the current capacity of the internal compressed-data buffer.
    ///
    /// Exposed for testing the pre-allocation guarantee from issue #153.
    /// Production callers should not rely on this value.
    #[cfg(test)]
    pub(crate) fn buffer_capacity(&self) -> usize {
        self.buffer.capacity()
    }

    /// Decompress a chunk. Appends to internal buffer and attempts
    /// decompression. On success, replaces `body` with decompressed data.
    ///
    /// On failure (overflow or decoder error) the decompressor enters a
    /// terminal `failed` state. Per M-25 we never emit raw compressed
    /// bytes as HTML body — browsers can charset-guess binary into
    /// executable text. Instead, once failed, every subsequent chunk is
    /// replaced with an empty `Bytes::new()` so the client gets a safely
    /// truncated response instead of garbled binary. Injection is
    /// abandoned for this request (the outer layer stripped the
    /// `Content-Encoding` header so we cannot recover the compressed
    /// stream either way).
    pub fn decompress(&mut self, body: &mut Option<Bytes>, end_of_stream: bool) {
        if self.failed {
            // Drop every subsequent chunk so no binary bytes reach the
            // wire. The client sees a clean truncation.
            if body.is_some() {
                *body = Some(Bytes::new());
            }
            return;
        }

        let Some(ref data) = *body else {
            return;
        };

        if data.is_empty() && !end_of_stream {
            return;
        }

        // Bound buffer to prevent OOM from adversarial compressed responses.
        //
        // M-25: On overflow we MUST NOT emit the raw compressed bytes as a
        // body. Browsers that charset-guess can misinterpret binary content
        // as HTML and potentially render attacker-controlled sequences.
        // Instead, drop the accumulated buffer and emit an empty body. The
        // outer `HtmlInjector` then has nothing to scan → injection is
        // abandoned and subsequent chunks pass through untouched via the
        // `failed` flag below. The client still gets the upstream response
        // (Pingora continues streaming future chunks unmodified); we just
        // skip the analytics injection for this request.
        if self.buffer.len() + data.len() > MAX_BUFFER_SIZE {
            tracing::warn!(
                buffered = self.buffer.len(),
                chunk = data.len(),
                limit = MAX_BUFFER_SIZE,
                "compressed response exceeded buffer limit, skipping injection"
            );
            self.failed = true;
            // Zeroize the buffered compressed data — we never emit it.
            self.buffer.clear();
            self.buffer.shrink_to_fit();
            *body = Some(Bytes::new());
            return;
        }

        self.buffer.extend_from_slice(data);

        if end_of_stream {
            // End of stream — must produce all remaining output
            if let Ok(decompressed) = self.try_decompress_all() {
                *body = Some(Bytes::from(decompressed));
            } else {
                // Decompression failed — emit an empty body rather than
                // leaking raw compressed bytes as HTML (M-25). The
                // response is effectively truncated; better UX would
                // require the upstream layer to restore Content-Encoding,
                // which isn't currently possible from inside the
                // body filter.
                self.failed = true;
                self.buffer.clear();
                self.buffer.shrink_to_fit();
                *body = Some(Bytes::new());
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
    ///
    /// Output is capped at [`MAX_DECOMPRESSED_SIZE`] to prevent
    /// decompression bombs (small compressed input expanding to gigabytes).
    fn decompress_bytes(&self, data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        match self.encoding {
            Encoding::Gzip => {
                let decoder = GzDecoder::new(data);
                read_bounded(decoder)
            }
            Encoding::Deflate => {
                let decoder = DeflateDecoder::new(data);
                read_bounded(decoder)
            }
            Encoding::Brotli => {
                let cursor = std::io::Cursor::new(data);
                let decoder = brotli::Decompressor::new(cursor, 4096);
                read_bounded(decoder)
            }
        }
    }
}

/// Read from a decoder into a `Vec<u8>`, aborting if the output exceeds
/// [`MAX_DECOMPRESSED_SIZE`]. Prevents decompression bombs from consuming
/// unbounded memory.
///
/// Pre-allocates [`READ_BOUNDED_INITIAL_CAPACITY`] of output and reads in
/// [`READ_BOUNDED_CHUNK_SIZE`] chunks. Most HTML responses decompress to
/// 20–100 KiB, so this trims the typical realloc cascade from 6–7 grows
/// down to 1–2 (issue #155).
fn read_bounded<R: Read>(mut reader: R) -> Result<Vec<u8>, std::io::Error> {
    let mut output = Vec::with_capacity(READ_BOUNDED_INITIAL_CAPACITY);
    let mut buf = [0u8; READ_BOUNDED_CHUNK_SIZE];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if output.len() + n > MAX_DECOMPRESSED_SIZE {
            return Err(std::io::Error::other(
                "decompressed output exceeds MAX_DECOMPRESSED_SIZE",
            ));
        }
        output.extend_from_slice(&buf[..n]);
    }
    Ok(output)
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
    fn failed_decompression_emits_empty_body() {
        // M-25: on overflow/decoder error we must NEVER emit the
        // raw compressed bytes — they could be charset-guessed as HTML
        // and interpreted as attacker-controlled markup.
        let garbage = b"this is not compressed data";
        let mut decomp = Decompressor::new(Encoding::Gzip);
        let mut body = Some(Bytes::from(garbage.to_vec()));
        decomp.decompress(&mut body, true);

        assert!(decomp.failed);
        let out = body.expect("body");
        assert!(
            out.is_empty(),
            "failed decompressor must emit empty body, got {} bytes",
            out.len()
        );
    }

    #[test]
    fn overflow_does_not_leak_compressed_bytes() {
        // Feed more than MAX_BUFFER_SIZE of "compressed" data. The body
        // must become empty — we never want the raw buffer on the wire.
        let mut decomp = Decompressor::new(Encoding::Gzip);
        let huge = vec![0xffu8; MAX_BUFFER_SIZE + 1];
        let mut body = Some(Bytes::from(huge));
        decomp.decompress(&mut body, false);
        assert!(decomp.failed);
        assert_eq!(body.expect("body").len(), 0);
    }

    #[test]
    fn failed_decompressor_drops_subsequent_chunks() {
        let mut decomp = Decompressor::new(Encoding::Gzip);
        // First chunk triggers overflow.
        let huge = vec![0u8; MAX_BUFFER_SIZE + 1];
        let mut body1 = Some(Bytes::from(huge));
        decomp.decompress(&mut body1, false);
        assert!(decomp.failed);

        // Every subsequent chunk must be replaced with empty so no
        // binary bytes reach the client.
        let mut body2 = Some(Bytes::from_static(b"follow-up chunk"));
        decomp.decompress(&mut body2, false);
        assert_eq!(body2.expect("body").len(), 0);

        let mut body3 = Some(Bytes::from_static(b"another"));
        decomp.decompress(&mut body3, true);
        assert_eq!(body3.expect("body").len(), 0);
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

    #[test]
    fn decompressor_buffer_preallocated() {
        let d = Decompressor::new(Encoding::Gzip);
        // Pre-allocation: a fresh decompressor should hold at least 8 KiB
        // of capacity so the first compressed chunk does not trigger a
        // re-alloc cascade. See issue #153.
        assert!(
            d.buffer_capacity() >= 8192,
            "expected >=8192 capacity, got {}",
            d.buffer_capacity()
        );
    }

    #[test]
    fn decompress_50k_roundtrip() {
        // Correctness regression guard for the read_bounded change in
        // issue #155. Verifies the round-trip still produces byte-exact
        // output at a typical HTML-page size; the pre-alloc invariant
        // itself (READ_BOUNDED_INITIAL_CAPACITY output, READ_BOUNDED_CHUNK_SIZE
        // read buffer) is enforced structurally by the constants defined above
        // and exercised perf-wise by the decompress_50k_gzip_one_shot
        // criterion bench.
        let html = vec![b'a'; 50_000];
        let compressed = gzip_compress(&html);
        let mut dec = Decompressor::new(Encoding::Gzip);
        let mut body = Some(Bytes::from(compressed));
        dec.decompress(&mut body, true);
        let out = body.expect("body decompressed");
        assert_eq!(out.len(), 50_000);
        assert!(out.iter().all(|b| *b == b'a'));
    }
}
