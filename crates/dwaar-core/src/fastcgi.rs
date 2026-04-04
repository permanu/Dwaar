// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Minimal `FastCGI` client for the `php_fastcgi` directive.
//!
//! Implements just enough of the `FastCGI` protocol to communicate with `php-fpm`:
//! `BEGIN_REQUEST` → `PARAMS` → `STDIN` → read `STDOUT` → `END_REQUEST`.
//!
//! The protocol is simple binary framing (9-page spec). No external crate needed.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// FastCGI record types
const FCGI_BEGIN_REQUEST: u8 = 1;
const FCGI_END_REQUEST: u8 = 3;
const FCGI_PARAMS: u8 = 4;
const FCGI_STDIN: u8 = 5;
const FCGI_STDOUT: u8 = 6;
const FCGI_STDERR: u8 = 7;

// FastCGI roles
const FCGI_RESPONDER: u16 = 1;

const FCGI_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESPONSE_SIZE: usize = 10 * 1024 * 1024; // 10 MB

/// Result of a `FastCGI` request.
#[derive(Debug)]
pub struct FastCgiResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

/// Parameters for a `FastCGI` request.
#[derive(Debug)]
pub struct FastCgiRequest<'a> {
    pub upstream: SocketAddr,
    pub root: &'a Path,
    pub request_path: &'a str,
    pub query_string: &'a str,
    pub method: &'a str,
    pub request_body: &'a [u8],
    pub server_name: &'a str,
    pub remote_addr: &'a str,
}

/// Execute a `FastCGI` request to `php-fpm` and return the parsed HTTP response.
pub async fn execute(req: &FastCgiRequest<'_>) -> Result<FastCgiResponse, String> {
    // Resolve script path with try_files logic:
    // {path} → {path}/index.php → /index.php
    let script_filename = resolve_script(req.root, req.request_path);
    let document_root = req.root.to_string_lossy();

    // Build FastCGI params
    let mut params = HashMap::new();
    params.insert("SCRIPT_FILENAME", script_filename.clone());
    params.insert("DOCUMENT_ROOT", document_root.to_string());
    params.insert("QUERY_STRING", req.query_string.to_string());
    params.insert("REQUEST_METHOD", req.method.to_string());
    params.insert(
        "REQUEST_URI",
        format!("{}?{}", req.request_path, req.query_string),
    );
    params.insert("SERVER_NAME", req.server_name.to_string());
    params.insert("SERVER_PORT", "80".to_string());
    params.insert("REMOTE_ADDR", req.remote_addr.to_string());
    params.insert("CONTENT_LENGTH", req.request_body.len().to_string());
    params.insert(
        "CONTENT_TYPE",
        "application/x-www-form-urlencoded".to_string(),
    );
    params.insert("SERVER_PROTOCOL", "HTTP/1.1".to_string());
    params.insert("GATEWAY_INTERFACE", "CGI/1.1".to_string());

    // PATH_INFO splitting on .php — require a boundary after the extension
    // to avoid matching .phpx, .phpinfo, etc.
    let php_split = req.request_path.find(".php").and_then(|pos| {
        let split = pos + 4;
        let is_boundary = split >= req.request_path.len()
            || matches!(req.request_path.as_bytes().get(split), Some(b'/' | b'?'));
        is_boundary.then_some(split)
    });
    if let Some(split) = php_split {
        let script = &req.request_path[..split];
        let path_info = &req.request_path[split..];
        params.insert("SCRIPT_NAME", script.to_string());
        if !path_info.is_empty() {
            params.insert("PATH_INFO", path_info.to_string());
        }
    } else {
        params.insert("SCRIPT_NAME", req.request_path.to_string());
    }

    // Connect
    let mut stream = tokio::time::timeout(FCGI_TIMEOUT, TcpStream::connect(req.upstream))
        .await
        .map_err(|_| "FastCGI connect timed out".to_string())?
        .map_err(|e| format!("FastCGI connect failed: {e}"))?;

    let request_id: u16 = 1;

    // Send BEGIN_REQUEST
    let begin_body = [
        (FCGI_RESPONDER >> 8) as u8,
        (FCGI_RESPONDER & 0xFF) as u8,
        0, // flags (no keep-alive)
        0,
        0,
        0,
        0,
        0, // reserved
    ];
    write_record(&mut stream, FCGI_BEGIN_REQUEST, request_id, &begin_body).await?;

    // Send PARAMS
    let encoded_params = encode_params(&params);
    write_record(&mut stream, FCGI_PARAMS, request_id, &encoded_params).await?;
    write_record(&mut stream, FCGI_PARAMS, request_id, &[]).await?; // empty params = end

    // Send STDIN (request body)
    if !req.request_body.is_empty() {
        write_record(&mut stream, FCGI_STDIN, request_id, req.request_body).await?;
    }
    write_record(&mut stream, FCGI_STDIN, request_id, &[]).await?; // empty stdin = end

    stream
        .flush()
        .await
        .map_err(|e| format!("FastCGI flush: {e}"))?;

    // Read response records
    let mut stdout_buf = Vec::new();
    loop {
        let record = read_record(&mut stream).await?;
        match record.record_type {
            FCGI_STDOUT => {
                stdout_buf.extend_from_slice(&record.content);
                if stdout_buf.len() > MAX_RESPONSE_SIZE {
                    return Err("FastCGI response too large".to_string());
                }
            }
            FCGI_STDERR => {
                // Log stderr but don't fail
                if let Ok(msg) = std::str::from_utf8(&record.content) {
                    tracing::warn!(stderr = %msg, "FastCGI stderr");
                }
            }
            FCGI_END_REQUEST => break,
            _ => {} // ignore unknown record types
        }
    }

    // Parse the CGI-style response (headers + body separated by \r\n\r\n)
    parse_cgi_response(&stdout_buf)
}

/// Caddy's `try_files` logic: `{path}` → `{path}/index.php` → `/index.php`
fn resolve_script(root: &Path, request_path: &str) -> String {
    let clean = request_path.trim_start_matches('/');

    // Direct .php file
    if Path::new(request_path)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("php"))
    {
        let candidate = root.join(clean);
        if candidate.exists() {
            return candidate.to_string_lossy().to_string();
        }
    }

    // {path}/index.php
    let with_index = root.join(clean).join("index.php");
    if with_index.exists() {
        return with_index.to_string_lossy().to_string();
    }

    // Fallback: root index.php (for router-based PHP apps like Laravel/WordPress)
    let root_index = root.join("index.php");
    root_index.to_string_lossy().to_string()
}

#[derive(Debug)]
struct FcgiRecord {
    record_type: u8,
    content: Vec<u8>,
}

async fn write_record(
    stream: &mut TcpStream,
    record_type: u8,
    request_id: u16,
    content: &[u8],
) -> Result<(), String> {
    let content_len = content.len();
    let padding_len = (8 - (content_len % 8)) % 8;

    // 8-byte header
    let header = [
        1, // version
        record_type,
        (request_id >> 8) as u8,
        (request_id & 0xFF) as u8,
        (content_len >> 8) as u8,
        (content_len & 0xFF) as u8,
        padding_len as u8,
        0, // reserved
    ];

    tokio::time::timeout(FCGI_TIMEOUT, async {
        stream.write_all(&header).await?;
        if !content.is_empty() {
            stream.write_all(content).await?;
        }
        if padding_len > 0 {
            stream.write_all(&vec![0u8; padding_len]).await?;
        }
        Ok::<_, std::io::Error>(())
    })
    .await
    .map_err(|_| "FastCGI write timed out".to_string())?
    .map_err(|e| format!("FastCGI write: {e}"))
}

async fn read_record(stream: &mut TcpStream) -> Result<FcgiRecord, String> {
    let mut header = [0u8; 8];
    tokio::time::timeout(FCGI_TIMEOUT, stream.read_exact(&mut header))
        .await
        .map_err(|_| "FastCGI read timed out".to_string())?
        .map_err(|e| format!("FastCGI read header: {e}"))?;

    let record_type = header[1];
    let content_len = ((header[4] as usize) << 8) | (header[5] as usize);
    let padding_len = header[6] as usize;

    let mut content = vec![0u8; content_len];
    if content_len > 0 {
        tokio::time::timeout(FCGI_TIMEOUT, stream.read_exact(&mut content))
            .await
            .map_err(|_| "FastCGI read content timed out".to_string())?
            .map_err(|e| format!("FastCGI read content: {e}"))?;
    }

    if padding_len > 0 {
        let mut padding = vec![0u8; padding_len];
        tokio::time::timeout(FCGI_TIMEOUT, stream.read_exact(&mut padding))
            .await
            .map_err(|_| "FastCGI read padding timed out".to_string())?
            .map_err(|e| format!("FastCGI read padding: {e}"))?;
    }

    Ok(FcgiRecord {
        record_type,
        content,
    })
}

/// Encode `FastCGI` name-value pairs.
fn encode_params(params: &HashMap<&str, String>) -> Vec<u8> {
    let mut buf = Vec::new();
    for (name, value) in params {
        encode_length(&mut buf, name.len());
        encode_length(&mut buf, value.len());
        buf.extend_from_slice(name.as_bytes());
        buf.extend_from_slice(value.as_bytes());
    }
    buf
}

/// Encode a length as 1 byte (< 128) or 4 bytes (>= 128).
fn encode_length(buf: &mut Vec<u8>, len: usize) {
    if len < 128 {
        buf.push(len as u8);
    } else {
        buf.push(((len >> 24) as u8) | 0x80);
        buf.push((len >> 16) as u8);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
}

/// Parse CGI-style response: headers separated from body by \r\n\r\n.
/// The Status header determines the HTTP status code.
fn parse_cgi_response(raw: &[u8]) -> Result<FastCgiResponse, String> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "malformed FastCGI response: no header terminator".to_string())?;

    let header_str = std::str::from_utf8(&raw[..header_end])
        .map_err(|_| "invalid UTF-8 in FastCGI response headers".to_string())?;

    let body = Bytes::copy_from_slice(&raw[header_end + 4..]);

    let mut status = 200u16;
    let mut headers = Vec::new();

    for line in header_str.lines() {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            let value = value.trim();
            if name.eq_ignore_ascii_case("Status") {
                // "Status: 404 Not Found" → 404
                status = value
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(200);
            } else {
                headers.push((name.to_string(), value.to_string()));
            }
        }
    }

    Ok(FastCgiResponse {
        status,
        headers,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_short_length() {
        let mut buf = Vec::new();
        encode_length(&mut buf, 5);
        assert_eq!(buf, vec![5]);
    }

    #[test]
    fn encode_long_length() {
        let mut buf = Vec::new();
        encode_length(&mut buf, 300);
        assert_eq!(buf.len(), 4);
        assert!(buf[0] & 0x80 != 0);
    }

    #[test]
    fn encode_params_roundtrip() {
        let mut params = HashMap::new();
        params.insert("KEY", "value".to_string());
        let encoded = encode_params(&params);
        // 1 byte name len + 1 byte value len + 3 bytes name + 5 bytes value = 10
        assert_eq!(encoded.len(), 10);
    }

    #[test]
    fn parse_cgi_response_basic() {
        let raw = b"Status: 200 OK\r\nContent-Type: text/html\r\n\r\n<html>hello</html>";
        let resp = parse_cgi_response(raw).expect("parse");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.headers.len(), 1);
        assert_eq!(resp.headers[0].0, "Content-Type");
        assert_eq!(resp.body.as_ref(), b"<html>hello</html>");
    }

    #[test]
    fn parse_cgi_response_404() {
        let raw = b"Status: 404 Not Found\r\nContent-Type: text/plain\r\n\r\nNot Found";
        let resp = parse_cgi_response(raw).expect("parse");
        assert_eq!(resp.status, 404);
    }

    #[test]
    fn parse_cgi_response_no_status_defaults_200() {
        let raw = b"Content-Type: text/html\r\n\r\nbody";
        let resp = parse_cgi_response(raw).expect("parse");
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn resolve_script_direct_php() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("test.php"), "<?php").expect("write");
        let script = resolve_script(dir.path(), "/test.php");
        assert!(script.ends_with("test.php"));
    }

    #[test]
    fn resolve_script_fallback_to_index() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("index.php"), "<?php").expect("write");
        let script = resolve_script(dir.path(), "/some/path");
        assert!(script.ends_with("index.php"));
    }
}
