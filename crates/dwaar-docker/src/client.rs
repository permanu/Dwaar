// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Raw HTTP/1.1 client for the Docker Engine API over a Unix socket.
//!
//! No `hyper`, no `reqwest`, no `bollard` — just `tokio::net::UnixStream`
//! with manual HTTP/1.1 framing. Keeps the dependency tree minimal and
//! avoids pulling in a full HTTP stack for three simple API calls.

use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tracing::trace;

/// Max size for any single line or chunk body (64 KB).
const MAX_LINE_BYTES: usize = 64 * 1024;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Docker Engine API version we target.
const API_VERSION: &str = "/v1.43";

#[derive(Debug, thiserror::Error)]
pub enum DockerError {
    #[error("failed to connect to Docker socket at {path}: {source}")]
    Connect { path: String, source: std::io::Error },
    #[error("Docker API error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Docker API returned HTTP {status}")]
    HttpError { status: u16 },
    #[error("Docker API response parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Docker API request timed out after {0:?}")]
    Timeout(Duration),
    #[error("response line too long ({len} bytes, max {max})")]
    LineTooLong { len: usize, max: usize },
}

/// Minimal HTTP/1.1 client that talks to the Docker Engine API over a Unix socket.
#[derive(Debug)]
pub struct DockerClient {
    socket_path: PathBuf,
}

/// A long-lived chunked event stream from `GET /events`.
///
/// Docker sends `Transfer-Encoding: chunked` for the events endpoint.
/// Each chunk is a single JSON object representing a container lifecycle event.
#[derive(Debug)]
pub struct EventStream {
    reader: BufReader<UnixStream>,
    line_buf: String,
}

impl DockerClient {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: path.into(),
        }
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Open a connection to the Docker daemon socket.
    async fn connect(&self) -> Result<BufReader<UnixStream>, DockerError> {
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, UnixStream::connect(&self.socket_path))
            .await
            .map_err(|_| DockerError::Timeout(CONNECT_TIMEOUT))?
            .map_err(|source| DockerError::Connect {
                path: self.socket_path.display().to_string(),
                source,
            })?;
        Ok(BufReader::new(stream))
    }

    /// Send a GET request and return the parsed JSON body.
    ///
    /// Uses `Connection: close` so the server signals EOF after the response,
    /// which lets us simply read until EOF for the body.
    pub async fn request(&self, path: &str) -> Result<serde_json::Value, DockerError> {
        tokio::time::timeout(REQUEST_TIMEOUT, self.do_request(path))
            .await
            .map_err(|_| DockerError::Timeout(REQUEST_TIMEOUT))?
    }

    async fn do_request(&self, path: &str) -> Result<serde_json::Value, DockerError> {
        let mut reader = self.connect().await?;
        let request = format_request(path, "close");
        trace!(path, "sending Docker API request");

        reader.get_mut().write_all(request.as_bytes()).await?;

        // Read and validate the status line
        let status_line = read_bounded_line(&mut reader).await?;
        let status = parse_status_code(&status_line)?;
        if status >= 400 {
            return Err(DockerError::HttpError { status });
        }

        // Consume headers until the blank line
        loop {
            let header_line = read_bounded_line(&mut reader).await?;
            if header_line.is_empty() {
                break;
            }
        }

        // Read body until EOF (Connection: close guarantees this works)
        let mut body = Vec::new();
        reader.read_to_end(&mut body).await?;

        let value = serde_json::from_slice(&body)?;
        Ok(value)
    }

    /// List running containers that have the given label.
    pub async fn list_containers(
        &self,
        label: &str,
    ) -> Result<Vec<serde_json::Value>, DockerError> {
        let filters = encode_filters(&[("label", label), ("status", "running")]);
        let path = format!("{API_VERSION}/containers/json?filters={filters}");
        let value = self.request(&path).await?;

        // The Docker API returns a JSON array for this endpoint
        match value {
            serde_json::Value::Array(arr) => Ok(arr),
            other => Ok(vec![other]),
        }
    }

    /// Get full details for a single container.
    pub async fn inspect_container(
        &self,
        id: &str,
    ) -> Result<serde_json::Value, DockerError> {
        self.request(&format!("{API_VERSION}/containers/{id}/json"))
            .await
    }

    /// Open a long-lived chunked stream of container lifecycle events.
    ///
    /// Only subscribes to `start` and `die` events on containers, which is
    /// all we need for route discovery/removal.
    pub async fn stream_events(&self) -> Result<EventStream, DockerError> {
        let mut reader = self.connect().await?;

        let filters = encode_filters(&[("type", "container"), ("event", "start"), ("event", "die")]);
        let path = format!("{API_VERSION}/events?filters={filters}");
        let request = format_request(&path, "keep-alive");

        reader.get_mut().write_all(request.as_bytes()).await?;

        let status_line = read_bounded_line(&mut reader).await?;
        let status = parse_status_code(&status_line)?;
        if status >= 400 {
            return Err(DockerError::HttpError { status });
        }

        // Consume response headers
        loop {
            let header_line = read_bounded_line(&mut reader).await?;
            if header_line.is_empty() {
                break;
            }
        }

        Ok(EventStream {
            reader,
            line_buf: String::with_capacity(1024),
        })
    }
}

impl EventStream {
    /// Read the next JSON event from the chunked stream.
    ///
    /// Returns `None` on EOF or connection close. Docker's event stream
    /// uses chunked transfer encoding: each chunk is a hex size line,
    /// followed by that many bytes of JSON, followed by `\r\n`.
    pub async fn next_event(&mut self) -> Option<Result<serde_json::Value, DockerError>> {
        // Read the chunk size line (hex-encoded length)
        self.line_buf.clear();
        match self.reader.read_line(&mut self.line_buf).await {
            Ok(0) => return None, // EOF
            Ok(n) if n > MAX_LINE_BYTES => {
                return Some(Err(DockerError::LineTooLong {
                    len: n,
                    max: MAX_LINE_BYTES,
                }));
            }
            Err(e) => return Some(Err(DockerError::Io(e))),
            Ok(_) => {}
        }

        let size_str = self.line_buf.trim();
        if size_str.is_empty() {
            return None;
        }

        let chunk_size = match usize::from_str_radix(size_str, 16) {
            Ok(0) => return None, // terminal chunk
            Ok(n) if n > MAX_LINE_BYTES => {
                return Some(Err(DockerError::LineTooLong {
                    len: n,
                    max: MAX_LINE_BYTES,
                }));
            }
            Ok(n) => n,
            Err(_) => {
                // Not a valid hex chunk size — might be raw JSON line (some Docker
                // versions skip chunked encoding). Try parsing the line itself.
                return match serde_json::from_str(self.line_buf.trim()) {
                    Ok(v) => Some(Ok(v)),
                    Err(e) => Some(Err(DockerError::Json(e))),
                };
            }
        };

        // Read exactly chunk_size bytes
        let mut chunk_buf = vec![0u8; chunk_size];
        if let Err(e) = self.reader.read_exact(&mut chunk_buf).await {
            return Some(Err(DockerError::Io(e)));
        }

        // Consume the trailing \r\n after the chunk data
        let mut trailer = [0u8; 2];
        if let Err(e) = self.reader.read_exact(&mut trailer).await {
            return Some(Err(DockerError::Io(e)));
        }

        match serde_json::from_slice(&chunk_buf) {
            Ok(v) => Some(Ok(v)),
            Err(e) => Some(Err(DockerError::Json(e))),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers — extracted as free functions so they're unit-testable without a
// real Docker socket.
// ---------------------------------------------------------------------------

/// Build an HTTP/1.1 GET request string.
fn format_request(path: &str, connection: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: {connection}\r\n\r\n")
}

/// Parse the HTTP status code out of a status line like `HTTP/1.1 200 OK`.
fn parse_status_code(line: &str) -> Result<u16, DockerError> {
    // Status line format: HTTP/1.x <status> <reason>
    let status_str = line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed status line"))?;

    status_str
        .parse::<u16>()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "non-numeric status code").into())
}

/// URL-encode a set of Docker API filter parameters.
///
/// Docker expects `filters={"key":["val1","val2"],...}` as a URL query param.
/// Multiple pairs with the same key get merged into the same array.
fn encode_filters(pairs: &[(&str, &str)]) -> String {
    // Build the JSON object, merging duplicate keys into arrays
    let mut map: std::collections::BTreeMap<&str, Vec<&str>> = std::collections::BTreeMap::new();
    for &(key, val) in pairs {
        map.entry(key).or_default().push(val);
    }

    // Serialize manually to avoid pulling in another dep for URL encoding.
    // The JSON is simple enough: {"key":["val",...], ...}
    let mut json = String::from('{');
    for (i, (key, vals)) in map.iter().enumerate() {
        if i > 0 {
            json.push(',');
        }
        json.push('"');
        json.push_str(key);
        json.push_str("\":[");
        for (j, val) in vals.iter().enumerate() {
            if j > 0 {
                json.push(',');
            }
            json.push('"');
            json.push_str(val);
            json.push('"');
        }
        json.push(']');
    }
    json.push('}');

    // Percent-encode the JSON for use in a URL query string
    url_encode(&json)
}

/// Minimal percent-encoding for Docker filter JSON.
///
/// Only encodes the characters that actually appear in our filter values
/// and would break a URL query string. We don't need a full RFC 3986
/// encoder here — the input is machine-generated JSON with known characters.
fn url_encode(s: &str) -> String {
    let mut encoded = String::with_capacity(s.len() * 2);
    for b in s.bytes() {
        match b {
            b'{' => encoded.push_str("%7B"),
            b'}' => encoded.push_str("%7D"),
            b'"' => encoded.push_str("%22"),
            b'[' => encoded.push_str("%5B"),
            b']' => encoded.push_str("%5D"),
            b':' => encoded.push_str("%3A"),
            b',' => encoded.push_str("%2C"),
            b' ' => encoded.push_str("%20"),
            _ => encoded.push(b as char),
        }
    }
    encoded
}

/// Read a line from the buffered reader, enforcing the max line length.
/// Strips the trailing `\r\n` or `\n`.
async fn read_bounded_line(reader: &mut BufReader<UnixStream>) -> Result<String, DockerError> {
    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n > MAX_LINE_BYTES {
        return Err(DockerError::LineTooLong {
            len: n,
            max: MAX_LINE_BYTES,
        });
    }
    // Strip trailing CRLF/LF
    if line.ends_with('\n') {
        line.pop();
    }
    if line.ends_with('\r') {
        line.pop();
    }
    Ok(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_request() {
        let req = format_request("/v1.43/containers/json", "close");
        assert_eq!(
            req,
            "GET /v1.43/containers/json HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn test_format_request_keepalive() {
        let req = format_request("/v1.43/events", "keep-alive");
        assert!(req.contains("Connection: keep-alive"));
        assert!(req.starts_with("GET /v1.43/events HTTP/1.1\r\n"));
        assert!(req.ends_with("\r\n\r\n"));
    }

    #[test]
    fn test_parse_status_line_200() {
        let status = parse_status_code("HTTP/1.1 200 OK").expect("should parse");
        assert_eq!(status, 200);
    }

    #[test]
    fn test_parse_status_line_404() {
        let status = parse_status_code("HTTP/1.1 404 Not Found").expect("should parse");
        assert_eq!(status, 404);
    }

    #[test]
    fn test_parse_status_line_500() {
        let status = parse_status_code("HTTP/1.1 500 Internal Server Error").expect("should parse");
        assert_eq!(status, 500);
    }

    #[test]
    fn test_parse_status_line_malformed() {
        assert!(parse_status_code("garbage").is_err());
        assert!(parse_status_code("HTTP/1.1").is_err());
        assert!(parse_status_code("HTTP/1.1 abc OK").is_err());
    }

    #[test]
    fn test_encode_filters_single_label() {
        let encoded = encode_filters(&[("label", "dwaar.domain"), ("status", "running")]);
        // Should produce percent-encoded JSON: {"label":["dwaar.domain"],"status":["running"]}
        assert!(encoded.contains("label"));
        assert!(encoded.contains("dwaar.domain"));
        assert!(encoded.contains("status"));
        assert!(encoded.contains("running"));
        // Should not contain raw special chars
        assert!(!encoded.contains('{'));
        assert!(!encoded.contains('}'));
        assert!(!encoded.contains('"'));
        assert!(!encoded.contains('['));
        assert!(!encoded.contains(']'));
    }

    #[test]
    fn test_encode_filters_merges_duplicate_keys() {
        let encoded = encode_filters(&[("event", "start"), ("event", "die"), ("type", "container")]);
        // Decode for verification
        let decoded = encoded
            .replace("%7B", "{")
            .replace("%7D", "}")
            .replace("%22", "\"")
            .replace("%5B", "[")
            .replace("%5D", "]")
            .replace("%3A", ":")
            .replace("%2C", ",");

        let parsed: serde_json::Value = serde_json::from_str(&decoded).expect("should be valid JSON");
        let events = parsed["event"].as_array().expect("event should be array");
        assert_eq!(events.len(), 2);
        assert!(events.contains(&serde_json::Value::String("start".into())));
        assert!(events.contains(&serde_json::Value::String("die".into())));

        let types = parsed["type"].as_array().expect("type should be array");
        assert_eq!(types.len(), 1);
        assert_eq!(types[0], "container");
    }

    #[test]
    fn test_encode_filters_roundtrips_through_json() {
        let encoded = encode_filters(&[("label", "dwaar.domain")]);
        let decoded = encoded
            .replace("%7B", "{")
            .replace("%7D", "}")
            .replace("%22", "\"")
            .replace("%5B", "[")
            .replace("%5D", "]")
            .replace("%3A", ":")
            .replace("%2C", ",");

        let parsed: serde_json::Value = serde_json::from_str(&decoded).expect("valid JSON");
        assert_eq!(parsed, serde_json::json!({"label": ["dwaar.domain"]}));
    }

    #[test]
    fn test_url_encode_special_chars() {
        let encoded = url_encode(r#"{"key":["val"]}"#);
        assert_eq!(
            encoded,
            "%7B%22key%22%3A%5B%22val%22%5D%7D"
        );
    }
}
