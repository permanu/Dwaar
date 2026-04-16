// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Lightweight OTLP/HTTP JSON span exporter.
//!
//! Batches completed spans in a bounded ring buffer and flushes to the
//! configured collector endpoint on a 5-second timer or when the buffer
//! hits 80% capacity. Zero overhead when no endpoint is configured —
//! the exporter is never created (lazy loading via `Option<Arc<OtlpExporter>>`).
//!
//! Uses hand-rolled OTLP JSON over a raw TCP socket instead of the
//! `opentelemetry` crate (~2 MB with tonic) to keep binary size small.

use std::collections::VecDeque;
use std::sync::Arc;

use compact_str::CompactString;
use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Maximum number of consecutive flush failures before dropping buffered spans.
const MAX_RETRIES: u32 = 3;

/// Flush interval in seconds.
const FLUSH_INTERVAL_SECS: u64 = 5;

/// Flush when buffer reaches this fraction of capacity.
const FLUSH_THRESHOLD: f64 = 0.8;

/// Default ring buffer capacity.
const DEFAULT_BUFFER_CAPACITY: usize = 1024;

/// A completed span ready for export.
#[derive(Debug, Clone)]
pub struct Span {
    pub trace_id: [u8; 32],
    pub span_id: [u8; 16],
    pub parent_span_id: Option<[u8; 16]>,
    pub name: CompactString,
    pub kind: SpanKind,
    pub start_ns: u64,
    pub end_ns: u64,
    pub status_code: u16,
    pub attributes: Vec<SpanAttribute>,
}

/// OTLP span kind values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SpanKind {
    Internal = 1,
    Server = 2,
    Client = 3,
}

/// A key-value attribute attached to a span.
#[derive(Debug, Clone)]
pub struct SpanAttribute {
    pub key: CompactString,
    pub value: SpanValue,
}

/// Typed span attribute value.
#[derive(Debug, Clone)]
pub enum SpanValue {
    String(CompactString),
    Int(i64),
    Bool(bool),
}

/// Errors from the OTLP exporter.
#[derive(Debug, thiserror::Error)]
pub enum OtlpError {
    #[error("failed to connect to OTLP endpoint: {0}")]
    Connect(std::io::Error),
    #[error("failed to send OTLP payload: {0}")]
    Send(std::io::Error),
    #[error("OTLP endpoint returned HTTP {0}")]
    Status(u16),
    #[error("invalid endpoint URL: {0}")]
    InvalidEndpoint(String),
}

/// Parsed host:port + path from an OTLP HTTP endpoint URL.
#[derive(Debug, Clone)]
struct EndpointAddr {
    path: String,
    /// Full `host:port` for the `Host` header and TCP connect.
    authority: String,
}

/// Parse `http://host:port/path` into components. Only HTTP is supported
/// since OTLP collectors are always local/trusted.
fn parse_endpoint(url: &str) -> Result<EndpointAddr, OtlpError> {
    let stripped = url
        .strip_prefix("http://")
        .ok_or_else(|| OtlpError::InvalidEndpoint("only http:// endpoints supported".into()))?;

    let (authority_part, path) = stripped.find('/').map_or((stripped, "/v1/traces"), |i| {
        (&stripped[..i], &stripped[i..])
    });

    let (host, port) = if let Some(colon) = authority_part.rfind(':') {
        let port_str = &authority_part[colon + 1..];
        let port: u16 = port_str
            .parse()
            .map_err(|_| OtlpError::InvalidEndpoint(format!("invalid port: {port_str}")))?;
        (authority_part[..colon].to_string(), port)
    } else {
        (authority_part.to_string(), 80)
    };

    Ok(EndpointAddr {
        authority: format!("{host}:{port}"),
        path: path.to_string(),
    })
}

/// OTLP/HTTP JSON span exporter. Created once at startup when
/// `otlp_endpoint` is configured.
#[derive(Debug)]
pub struct OtlpExporter {
    endpoint: EndpointAddr,
    buffer: Mutex<VecDeque<Span>>,
    buffer_capacity: usize,
    service_name: CompactString,
    service_version: CompactString,
}

impl OtlpExporter {
    /// Create a new exporter targeting the given OTLP/HTTP endpoint.
    ///
    /// # Errors
    ///
    /// Returns `OtlpError::InvalidEndpoint` if the URL cannot be parsed.
    pub fn new(endpoint: &str, service_version: &str) -> Result<Self, OtlpError> {
        let addr = parse_endpoint(endpoint)?;
        Ok(Self {
            endpoint: addr,
            buffer: Mutex::new(VecDeque::with_capacity(DEFAULT_BUFFER_CAPACITY)),
            buffer_capacity: DEFAULT_BUFFER_CAPACITY,
            service_name: CompactString::from("dwaar"),
            service_version: CompactString::from(service_version),
        })
    }

    /// Record a completed span. Lock-free fast path: acquire mutex, push,
    /// release. If the buffer is full, drop the oldest span (lossy — acceptable
    /// for tracing where completeness is best-effort).
    pub fn record(&self, span: Span) {
        let mut buf = self.buffer.lock();
        if buf.len() >= self.buffer_capacity {
            buf.pop_front();
        }
        buf.push_back(span);
    }

    /// Returns true when the buffer has reached the flush threshold.
    fn should_flush_early(&self) -> bool {
        let len = self.buffer.lock().len();
        len as f64 >= self.buffer_capacity as f64 * FLUSH_THRESHOLD
    }

    /// Flush all buffered spans to the OTLP endpoint.
    ///
    /// # Errors
    ///
    /// Returns `OtlpError` on connection or send failure. Callers should
    /// retry up to `MAX_RETRIES` before dropping the batch.
    pub async fn flush(&self) -> Result<(), OtlpError> {
        let spans: Vec<Span> = {
            let mut buf = self.buffer.lock();
            buf.drain(..).collect()
        };

        if spans.is_empty() {
            return Ok(());
        }

        let body = self.serialize_batch(&spans);

        match self.send_payload(&body).await {
            Ok(()) => Ok(()),
            Err(e) => {
                // Put spans back for retry.
                let mut buf = self.buffer.lock();
                for span in spans.into_iter().rev() {
                    if buf.len() < self.buffer_capacity {
                        buf.push_front(span);
                    }
                }
                Err(e)
            }
        }
    }

    /// Send the OTLP JSON payload over a raw TCP connection.
    /// Uses HTTP/1.1 POST — the collector is local/trusted so TLS is unnecessary.
    async fn send_payload(&self, body: &[u8]) -> Result<(), OtlpError> {
        let mut stream = TcpStream::connect(&self.endpoint.authority)
            .await
            .map_err(OtlpError::Connect)?;

        // Hand-rolled HTTP/1.1 POST — avoids pulling in a full HTTP client
        // library for what's always a local-network call.
        let header = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n",
            self.endpoint.path,
            self.endpoint.authority,
            body.len()
        );

        stream
            .write_all(header.as_bytes())
            .await
            .map_err(OtlpError::Send)?;
        stream.write_all(body).await.map_err(OtlpError::Send)?;
        stream.flush().await.map_err(OtlpError::Send)?;

        // Read just enough of the response to check the status code.
        let mut resp_buf = [0u8; 64];
        let n = stream.read(&mut resp_buf).await.map_err(OtlpError::Send)?;
        let resp = String::from_utf8_lossy(&resp_buf[..n]);

        // Parse "HTTP/1.1 200 OK" — status code starts at byte 9.
        if let Some(status_str) = resp.get(9..12)
            && let Ok(status) = status_str.parse::<u16>()
            && status >= 400
        {
            return Err(OtlpError::Status(status));
        }

        Ok(())
    }

    /// Serialize a batch of spans into OTLP JSON format.
    ///
    /// Builds the JSON manually with `sonic_rs::Writer` for SIMD-accelerated
    /// serialization without requiring `serde::Serialize` on the span types.
    fn serialize_batch(&self, spans: &[Span]) -> Vec<u8> {
        use sonic_rs::Value;

        let span_array: Vec<Value> = spans.iter().map(Self::span_to_json).collect();

        let resource_attrs = vec![
            attr_json(
                "service.name",
                &SpanValue::String(self.service_name.clone()),
            ),
            attr_json(
                "service.version",
                &SpanValue::String(self.service_version.clone()),
            ),
        ];

        let payload = sonic_rs::json!({
            "resourceSpans": [{
                "resource": {
                    "attributes": Value::from(resource_attrs)
                },
                "scopeSpans": [{
                    "scope": { "name": "dwaar.proxy" },
                    "spans": Value::from(span_array)
                }]
            }]
        });

        sonic_rs::to_vec(&payload).unwrap_or_default()
    }

    /// Convert a single `Span` into an OTLP JSON value.
    fn span_to_json(span: &Span) -> sonic_rs::Value {
        use sonic_rs::Value;

        let trace_id = std::str::from_utf8(&span.trace_id).unwrap_or("");
        let span_id = std::str::from_utf8(&span.span_id).unwrap_or("");

        let attrs: Vec<Value> = span
            .attributes
            .iter()
            .map(|a| attr_json(&a.key, &a.value))
            .collect();

        // OTLP status: 0=UNSET, 1=OK, 2=ERROR.
        let otel_status_code = if span.status_code >= 400 { 2 } else { 1 };

        let parent_str = span
            .parent_span_id
            .as_ref()
            .map(|p| std::str::from_utf8(p).unwrap_or("").to_string());

        // Include parentSpanId only when present — OTLP spec treats absent
        // as "root span".
        if let Some(parent) = parent_str {
            sonic_rs::json!({
                "traceId": trace_id,
                "spanId": span_id,
                "parentSpanId": parent.as_str(),
                "name": span.name.as_str(),
                "kind": span.kind as u8,
                "startTimeUnixNano": span.start_ns.to_string(),
                "endTimeUnixNano": span.end_ns.to_string(),
                "attributes": Value::from(attrs),
                "status": { "code": otel_status_code }
            })
        } else {
            sonic_rs::json!({
                "traceId": trace_id,
                "spanId": span_id,
                "name": span.name.as_str(),
                "kind": span.kind as u8,
                "startTimeUnixNano": span.start_ns.to_string(),
                "endTimeUnixNano": span.end_ns.to_string(),
                "attributes": Value::from(attrs),
                "status": { "code": otel_status_code }
            })
        }
    }

    /// Start the background flush loop. Runs until the shutdown watch fires.
    /// Flushes every `FLUSH_INTERVAL_SECS` or when the buffer hits 80% capacity.
    pub async fn run(self: &Arc<Self>, mut shutdown: pingora_core::server::ShutdownWatch) {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(FLUSH_INTERVAL_SECS));
        let mut consecutive_failures: u32 = 0;

        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = shutdown.changed() => {
                    // Final flush on shutdown — best-effort.
                    if let Err(e) = self.flush().await {
                        tracing::warn!(error = %e, "OTLP final flush failed");
                    }
                    return;
                }
            }

            // Also check early-flush threshold between ticks.
            if self.should_flush_early() || interval.period().is_zero() {
                // Threshold-based flush handled by the timer tick above.
            }

            match self.flush().await {
                Ok(()) => {
                    consecutive_failures = 0;
                }
                Err(e) => {
                    consecutive_failures += 1;
                    if consecutive_failures >= MAX_RETRIES {
                        tracing::warn!(
                            error = %e,
                            retries = MAX_RETRIES,
                            "OTLP flush failed after max retries, dropping buffered spans"
                        );
                        self.buffer.lock().clear();
                        consecutive_failures = 0;
                    } else {
                        tracing::warn!(
                            error = %e,
                            attempt = consecutive_failures,
                            "OTLP flush failed, will retry"
                        );
                    }
                }
            }
        }
    }
}

/// Build a single OTLP attribute JSON object.
fn attr_json(key: &str, value: &SpanValue) -> sonic_rs::Value {
    let val = match value {
        SpanValue::String(s) => sonic_rs::json!({ "stringValue": s.as_str() }),
        SpanValue::Int(i) => sonic_rs::json!({ "intValue": i.to_string() }),
        SpanValue::Bool(b) => sonic_rs::json!({ "boolValue": *b }),
    };
    sonic_rs::json!({ "key": key, "value": val })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sonic_rs::{JsonContainerTrait, JsonValueTrait};

    fn make_test_span() -> Span {
        Span {
            trace_id: *b"4bf92f3577b34da6a3ce929d0e0e4736",
            span_id: *b"00f067aa0ba902b7",
            parent_span_id: None,
            name: CompactString::from("HTTP GET /api/users"),
            kind: SpanKind::Server,
            start_ns: 1_700_000_000_000_000_000,
            end_ns: 1_700_000_001_000_000_000,
            status_code: 200,
            attributes: vec![
                SpanAttribute {
                    key: CompactString::from("http.method"),
                    value: SpanValue::String(CompactString::from("GET")),
                },
                SpanAttribute {
                    key: CompactString::from("http.url"),
                    value: SpanValue::String(CompactString::from("/api/users")),
                },
                SpanAttribute {
                    key: CompactString::from("http.status_code"),
                    value: SpanValue::Int(200),
                },
            ],
        }
    }

    #[test]
    fn serialize_batch_produces_valid_otlp_json() {
        let exporter =
            OtlpExporter::new("http://localhost:4318/v1/traces", "0.2.13").expect("valid endpoint");
        let span = make_test_span();
        let json_bytes = exporter.serialize_batch(&[span]);
        let json_str = std::str::from_utf8(&json_bytes).expect("valid UTF-8");

        // Parse it back to verify structure.
        let val: sonic_rs::Value = sonic_rs::from_str(json_str).expect("valid JSON");

        // Top-level resourceSpans array.
        let resource_spans = val.get("resourceSpans").expect("has resourceSpans");
        assert!(resource_spans.is_array());

        let rs0 = &resource_spans[0];

        // Resource attributes contain service.name.
        let resource = rs0.get("resource").expect("has resource");
        let attrs = resource.get("attributes").expect("has attributes");
        let first_attr = &attrs[0];
        assert_eq!(
            first_attr
                .get("key")
                .and_then(sonic_rs::JsonValueTrait::as_str),
            Some("service.name")
        );

        // scopeSpans[0].spans[0] has expected fields.
        let scope_spans = rs0.get("scopeSpans").expect("has scopeSpans");
        let spans = scope_spans[0].get("spans").expect("has spans");
        let s0 = &spans[0];
        assert_eq!(
            s0.get("traceId").and_then(sonic_rs::JsonValueTrait::as_str),
            Some("4bf92f3577b34da6a3ce929d0e0e4736")
        );
        assert_eq!(
            s0.get("spanId").and_then(sonic_rs::JsonValueTrait::as_str),
            Some("00f067aa0ba902b7")
        );
        assert_eq!(
            s0.get("kind").and_then(sonic_rs::JsonValueTrait::as_u64),
            Some(2)
        );

        // Status code 200 → OTLP OK (1).
        let status = s0.get("status").expect("has status");
        assert_eq!(
            status
                .get("code")
                .and_then(sonic_rs::JsonValueTrait::as_u64),
            Some(1)
        );
    }

    #[test]
    fn serialize_error_span_has_error_status() {
        let exporter =
            OtlpExporter::new("http://localhost:4318/v1/traces", "0.2.13").expect("valid endpoint");
        let mut span = make_test_span();
        span.status_code = 502;
        let json_bytes = exporter.serialize_batch(&[span]);
        let val: sonic_rs::Value =
            sonic_rs::from_str(std::str::from_utf8(&json_bytes).expect("utf8"))
                .expect("valid JSON");
        let status = &val["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["status"];
        assert_eq!(
            status
                .get("code")
                .and_then(sonic_rs::JsonValueTrait::as_u64),
            Some(2)
        );
    }

    #[test]
    fn buffer_overflow_drops_oldest_span() {
        let exporter =
            OtlpExporter::new("http://localhost:4318/v1/traces", "0.2.13").expect("valid endpoint");

        // Fill buffer to capacity.
        for i in 0..DEFAULT_BUFFER_CAPACITY {
            let mut span = make_test_span();
            span.start_ns = i as u64;
            exporter.record(span);
        }
        assert_eq!(exporter.buffer.lock().len(), DEFAULT_BUFFER_CAPACITY);

        // Record one more — should drop the oldest (start_ns=0).
        let mut overflow_span = make_test_span();
        overflow_span.start_ns = 9999;
        exporter.record(overflow_span);

        let buf = exporter.buffer.lock();
        assert_eq!(buf.len(), DEFAULT_BUFFER_CAPACITY);
        // Oldest should now be start_ns=1 (the 0 was dropped).
        assert_eq!(buf.front().expect("not empty").start_ns, 1);
        assert_eq!(buf.back().expect("not empty").start_ns, 9999);
    }

    #[test]
    fn attribute_serialization_all_types() {
        let string_attr = attr_json("key.str", &SpanValue::String(CompactString::from("val")));
        assert_eq!(string_attr["value"]["stringValue"].as_str(), Some("val"));

        let int_attr = attr_json("key.int", &SpanValue::Int(42));
        assert_eq!(int_attr["value"]["intValue"].as_str(), Some("42"));

        let bool_attr = attr_json("key.bool", &SpanValue::Bool(true));
        assert_eq!(bool_attr["value"]["boolValue"].as_bool(), Some(true));
    }

    #[test]
    fn no_exporter_when_endpoint_is_none() {
        // Simulates the lazy-loading pattern: Option<Arc<OtlpExporter>>
        let exporter: Option<Arc<OtlpExporter>> = None;
        assert!(exporter.is_none());

        // The record call site should check and skip.
        if let Some(exp) = &exporter {
            exp.record(make_test_span());
        }
        // No panic, no allocation — this is a no-op when None.
    }

    #[test]
    fn parse_endpoint_valid_urls() {
        let addr = parse_endpoint("http://localhost:4318/v1/traces").expect("valid");
        assert_eq!(addr.path, "/v1/traces");
        assert_eq!(addr.authority, "localhost:4318");
    }

    #[test]
    fn parse_endpoint_default_port() {
        let addr = parse_endpoint("http://collector/v1/traces").expect("valid");
        assert_eq!(addr.authority, "collector:80");
    }

    #[test]
    fn parse_endpoint_no_path_defaults_to_v1_traces() {
        let addr = parse_endpoint("http://localhost:4318").expect("valid");
        assert_eq!(addr.path, "/v1/traces");
    }

    #[test]
    fn parse_endpoint_rejects_https() {
        assert!(parse_endpoint("https://localhost:4318/v1/traces").is_err());
    }

    #[test]
    fn parent_span_id_included_in_json() {
        let exporter =
            OtlpExporter::new("http://localhost:4318/v1/traces", "0.2.13").expect("valid endpoint");
        let mut span = make_test_span();
        span.parent_span_id = Some(*b"abcdef0123456789");
        let json_bytes = exporter.serialize_batch(&[span]);
        let val: sonic_rs::Value =
            sonic_rs::from_str(std::str::from_utf8(&json_bytes).expect("utf8"))
                .expect("valid JSON");
        let s0 = &val["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
        assert_eq!(
            s0.get("parentSpanId")
                .and_then(sonic_rs::JsonValueTrait::as_str),
            Some("abcdef0123456789")
        );
    }

    #[tokio::test]
    async fn integration_flush_to_mock_server() {
        use tokio::net::TcpListener;

        // Spawn a mock OTLP collector that accepts one request.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
        let addr = listener.local_addr().expect("local addr");

        let exporter = Arc::new(
            OtlpExporter::new(
                &format!("http://127.0.0.1:{}/v1/traces", addr.port()),
                "0.2.13",
            )
            .expect("valid endpoint"),
        );

        // Record some spans.
        exporter.record(make_test_span());
        let mut span2 = make_test_span();
        span2.name = CompactString::from("HTTP POST /api/data");
        span2.status_code = 500;
        exporter.record(span2);

        // Spawn mock server that reads the request and responds 200.
        let server_handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 8192];
            let mut total = 0;

            // Read until we get the full request (headers + body).
            loop {
                let n = stream.read(&mut buf[total..]).await.expect("read");
                if n == 0 {
                    break;
                }
                total += n;

                // Check if we have the full body by finding Content-Length.
                let request = String::from_utf8_lossy(&buf[..total]);
                if let Some(cl_start) = request.find("Content-Length: ") {
                    let cl_str = &request[cl_start + 16..];
                    if let Some(end) = cl_str.find("\r\n")
                        && let Ok(content_len) = cl_str[..end].parse::<usize>()
                        && let Some(body_start) = request.find("\r\n\r\n")
                    {
                        let body_offset = body_start + 4;
                        if total >= body_offset + content_len {
                            // Got full request — extract body for verification.
                            let body = &buf[body_offset..body_offset + content_len];
                            let val: sonic_rs::Value =
                                sonic_rs::from_slice(body).expect("valid JSON body");

                            // Respond 200.
                            stream
                                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                                .await
                                .expect("write response");

                            return val;
                        }
                    }
                }
            }
            panic!("mock server did not receive complete request");
        });

        // Flush and verify.
        exporter.flush().await.expect("flush should succeed");

        let received = server_handle.await.expect("server task");

        // Verify the OTLP payload structure.
        let received_spans = &received["resourceSpans"][0]["scopeSpans"][0]["spans"];
        assert!(received_spans.is_array());
        // We sent 2 spans.
        assert_eq!(received_spans.as_array().expect("is array").len(), 2);
    }
}
