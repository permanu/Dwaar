// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! W3C Trace Context header parsing, validation, and generation.
//!
//! Implements the subset of the [W3C Trace Context] spec needed for header
//! propagation: parse an incoming `traceparent`, validate it, or generate a
//! fresh one when absent or invalid.
//!
//! [W3C Trace Context]: https://www.w3.org/TR/trace-context/

/// Parsed W3C trace context for a single request.
///
/// All fields are fixed-size byte arrays (no heap allocation). Convert to
/// `&str` via the accessor methods only when injecting into headers or logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceContext {
    /// 16-byte trace ID as 32 lowercase hex chars.
    trace_id: [u8; 32],
    /// 8-byte span/parent ID as 16 lowercase hex chars.
    span_id: [u8; 16],
    /// Full `traceparent` header value: `00-{trace_id}-{span_id}-{flags}` (55 chars).
    traceparent: [u8; 55],
}

impl TraceContext {
    /// 32-char lowercase hex trace ID as `&str`.
    pub fn trace_id(&self) -> &str {
        std::str::from_utf8(&self.trace_id).expect("trace_id is valid ASCII hex")
    }

    /// 16-char lowercase hex span ID as `&str`.
    pub fn span_id(&self) -> &str {
        std::str::from_utf8(&self.span_id).expect("span_id is valid ASCII hex")
    }

    /// Full 55-char `traceparent` header value as `&str`.
    pub fn traceparent(&self) -> &str {
        std::str::from_utf8(&self.traceparent).expect("traceparent is valid ASCII")
    }
}

/// Validate that `s` is exactly `len` hex characters.
fn is_valid_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Parse a `traceparent` header value per the W3C spec.
///
/// Returns `None` if the value is malformed, uses a non-`00` version byte,
/// or contains all-zero trace/span IDs (invalid per spec).
///
/// Uses `splitn` instead of `split().collect::<Vec>()` to avoid heap allocation.
pub fn parse_traceparent(value: &str) -> Option<TraceContext> {
    let mut parts = value.splitn(4, '-');

    let version = parts.next()?;
    let trace_id = parts.next()?;
    let span_id = parts.next()?;
    let flags = parts.next()?;

    // splitn(4) always returns at least 1 element; the rest may be empty.
    // We need exactly 4 non-empty parts.
    if version.is_empty() || trace_id.is_empty() || span_id.is_empty() || flags.is_empty() {
        return None;
    }
    // Ensure there was no 5th part (splitn may leave remainder in last element).
    if flags.contains('-') {
        return None;
    }

    // Only version "00" is supported; future versions need explicit opt-in.
    if version != "00" {
        return None;
    }

    if !is_valid_hex(trace_id, 32) || !is_valid_hex(span_id, 16) || !is_valid_hex(flags, 2) {
        return None;
    }

    // All-zero IDs are explicitly invalid per the spec.
    if trace_id == "00000000000000000000000000000000" || span_id == "0000000000000000" {
        return None;
    }

    let mut ctx = TraceContext {
        trace_id: [0u8; 32],
        span_id: [0u8; 16],
        traceparent: [0u8; 55],
    };

    // Copy validated ASCII bytes into fixed arrays.
    ctx.trace_id.copy_from_slice(trace_id.as_bytes());
    ctx.span_id.copy_from_slice(span_id.as_bytes());
    ctx.traceparent.copy_from_slice(value.as_bytes());

    Some(ctx)
}

/// Generate a fresh `TraceContext` with random trace and span IDs.
///
/// Uses `fastrand` (thread-local, no syscall) for speed — this runs on
/// every request without an existing traceparent.
pub fn generate_traceparent() -> TraceContext {
    let mut trace_bytes = [0u8; 16];
    let mut span_bytes = [0u8; 8];

    // fastrand::fill is fast (~3ns) and sufficient for trace IDs, which
    // need uniqueness, not cryptographic strength.
    fastrand::fill(&mut trace_bytes);
    fastrand::fill(&mut span_bytes);

    let mut ctx = TraceContext {
        trace_id: [0u8; 32],
        span_id: [0u8; 16],
        traceparent: *b"00-00000000000000000000000000000000-0000000000000000-01",
    };

    hex_encode_lower_into(&trace_bytes, &mut ctx.trace_id);
    hex_encode_lower_into(&span_bytes, &mut ctx.span_id);

    // Embed trace_id and span_id into the traceparent array.
    // Layout: "00-" (3) + trace_id (32) + "-" (1) + span_id (16) + "-01" (3) = 55
    ctx.traceparent[3..35].copy_from_slice(&ctx.trace_id);
    ctx.traceparent[36..52].copy_from_slice(&ctx.span_id);

    ctx
}

/// Build a completed OTLP span from a finished request. Called at the end
/// of the request lifecycle when both timing and status are known.
///
/// Returns a `dwaar_analytics::otel::Span` ready for `OtlpExporter::record()`.
/// The trace/span IDs come from the propagated or generated `TraceContext`;
/// everything else is request metadata captured during proxying.
pub fn create_request_span(
    trace_ctx: &TraceContext,
    method: &str,
    path: &str,
    status: u16,
    upstream: &str,
    start_ns: u64,
    end_ns: u64,
) -> dwaar_analytics::otel::Span {
    use compact_str::CompactString;
    use dwaar_analytics::otel::{SpanAttribute, SpanKind, SpanValue};

    let name = CompactString::from(format!("HTTP {method} {path}"));

    let attributes = vec![
        SpanAttribute {
            key: CompactString::from("http.method"),
            value: SpanValue::String(CompactString::from(method)),
        },
        SpanAttribute {
            key: CompactString::from("http.url"),
            value: SpanValue::String(CompactString::from(path)),
        },
        SpanAttribute {
            key: CompactString::from("http.status_code"),
            value: SpanValue::Int(i64::from(status)),
        },
        SpanAttribute {
            key: CompactString::from("net.peer.name"),
            value: SpanValue::String(CompactString::from(upstream)),
        },
    ];

    dwaar_analytics::otel::Span {
        trace_id: trace_ctx.trace_id,
        span_id: trace_ctx.span_id,
        parent_span_id: None,
        name,
        kind: SpanKind::Server,
        start_ns,
        end_ns,
        status_code: status,
        attributes,
    }
}

/// Encode bytes as lowercase hex directly into a fixed buffer.
fn hex_encode_lower_into(src: &[u8], dst: &mut [u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, &b) in src.iter().enumerate() {
        dst[i * 2] = HEX[(b >> 4) as usize];
        dst[i * 2 + 1] = HEX[(b & 0x0f) as usize];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_traceparent_parsed() {
        let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let ctx = parse_traceparent(tp).expect("should parse valid traceparent");
        assert_eq!(ctx.trace_id(), "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(ctx.span_id(), "00f067aa0ba902b7");
        assert_eq!(ctx.traceparent(), tp);
    }

    #[test]
    fn valid_traceparent_with_unsampled_flag() {
        let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00";
        let ctx = parse_traceparent(tp).expect("should parse with flag 00");
        assert_eq!(ctx.trace_id(), "4bf92f3577b34da6a3ce929d0e0e4736");
    }

    #[test]
    fn missing_traceparent_generates_valid() {
        let ctx = generate_traceparent();
        assert_eq!(ctx.trace_id().len(), 32);
        assert_eq!(ctx.span_id().len(), 16);
        assert!(ctx.traceparent().starts_with("00-"));
        assert!(ctx.traceparent().ends_with("-01"));
        assert_eq!(ctx.traceparent().len(), 55);

        // Verify the generated traceparent round-trips through the parser.
        let reparsed = parse_traceparent(ctx.traceparent()).expect("generated should be parseable");
        assert_eq!(reparsed.trace_id(), ctx.trace_id());
        assert_eq!(reparsed.span_id(), ctx.span_id());
    }

    #[test]
    fn invalid_hex_in_trace_id_returns_none() {
        let tp = "00-ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ-00f067aa0ba902b7-01";
        assert!(parse_traceparent(tp).is_none());
    }

    #[test]
    fn wrong_number_of_dashes_returns_none() {
        assert!(parse_traceparent("00-abc-01").is_none());
        assert!(parse_traceparent("00-abc-def-ghi-01-extra").is_none());
    }

    #[test]
    fn wrong_version_returns_none() {
        let tp = "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        assert!(parse_traceparent(tp).is_none());
    }

    #[test]
    fn all_zero_trace_id_returns_none() {
        let tp = "00-00000000000000000000000000000000-00f067aa0ba902b7-01";
        assert!(parse_traceparent(tp).is_none());
    }

    #[test]
    fn all_zero_span_id_returns_none() {
        let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01";
        assert!(parse_traceparent(tp).is_none());
    }

    #[test]
    fn generated_traceparent_format() {
        for _ in 0..100 {
            let ctx = generate_traceparent();
            let parts: Vec<&str> = ctx.traceparent().split('-').collect();
            assert_eq!(parts.len(), 4);
            assert_eq!(parts[0], "00");
            assert_eq!(parts[1].len(), 32);
            assert_eq!(parts[2].len(), 16);
            assert_eq!(parts[3], "01");
            assert!(is_valid_hex(parts[1], 32));
            assert!(is_valid_hex(parts[2], 16));
        }
    }

    #[test]
    fn generated_ids_are_unique() {
        let a = generate_traceparent();
        let b = generate_traceparent();
        assert_ne!(a.trace_id(), b.trace_id());
    }

    #[test]
    fn short_trace_id_returns_none() {
        let tp = "00-4bf92f3577b34da6a3ce929d0e0e47-00f067aa0ba902b7-01";
        assert!(parse_traceparent(tp).is_none());
    }

    #[test]
    fn short_span_id_returns_none() {
        let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902-01";
        assert!(parse_traceparent(tp).is_none());
    }

    #[test]
    fn uppercase_hex_is_accepted() {
        // W3C spec says implementations SHOULD accept mixed case.
        let tp = "00-4BF92F3577B34DA6A3CE929D0E0E4736-00F067AA0BA902B7-01";
        let ctx = parse_traceparent(tp).expect("should accept uppercase hex");
        assert_eq!(ctx.trace_id(), "4BF92F3577B34DA6A3CE929D0E0E4736");
    }

    #[test]
    fn create_request_span_populates_fields() {
        let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let ctx = parse_traceparent(tp).expect("valid");
        let span = create_request_span(&ctx, "GET", "/api/users", 200, "backend:8080", 1000, 2000);

        assert_eq!(
            std::str::from_utf8(&span.trace_id).expect("ascii"),
            "4bf92f3577b34da6a3ce929d0e0e4736"
        );
        assert_eq!(
            std::str::from_utf8(&span.span_id).expect("ascii"),
            "00f067aa0ba902b7"
        );
        assert_eq!(span.name.as_str(), "HTTP GET /api/users");
        assert_eq!(span.kind, dwaar_analytics::otel::SpanKind::Server);
        assert_eq!(span.start_ns, 1000);
        assert_eq!(span.end_ns, 2000);
        assert_eq!(span.status_code, 200);
        assert_eq!(span.attributes.len(), 4);
    }

    #[test]
    fn create_request_span_from_generated_context() {
        let ctx = generate_traceparent();
        let span = create_request_span(&ctx, "POST", "/upload", 201, "store:9090", 5000, 6000);
        assert_eq!(span.status_code, 201);
        assert_eq!(span.name.as_str(), "HTTP POST /upload");
    }
}
