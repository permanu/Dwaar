// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Minimal HTTP/1.1 client for querying the Dwaar Admin API.
//!
//! Uses raw `TcpStream` or `UnixStream` — no external HTTP library needed.
//! Only supports simple GET/POST to localhost, which is all CLI
//! commands need for talking to the co-located admin API.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Response from the admin API.
pub(crate) struct AdminResponse {
    pub status: u16,
    pub body: String,
}

/// Returns `true` if `addr` looks like a Unix socket path rather than a TCP
/// `host:port`. We accept both bare paths (`/var/run/dwaar-admin.sock`) and
/// the explicit `unix://` scheme.
fn is_unix_addr(addr: &str) -> bool {
    addr.starts_with('/') || addr.starts_with("unix://")
}

/// Strip the `unix://` prefix if present, returning the bare filesystem path.
fn unix_path(addr: &str) -> &str {
    addr.strip_prefix("unix://").unwrap_or(addr)
}

/// Build an actionable error message for a failed connect to the admin API.
///
/// `ConnectionRefused` and `NotFound` both mean "nobody is listening on this
/// address" — the daemon is almost certainly not running. Surface a hint
/// that tells the user exactly how to start it, instead of the bare OS
/// error that clap/anyhow would otherwise print.
///
/// All other errors (timeouts, permission, routing) get the raw message so
/// the user can diagnose the environment problem.
fn friendly_connect_error(addr: &str, err: &std::io::Error) -> anyhow::Error {
    let is_not_listening = matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
    );

    // Prefer the explicit DWAAR_CONFIG if the user set one, otherwise fall
    // back to the conventional Dwaarfile name. We intentionally do not try
    // to canonicalize here — we want the suggestion to match what the user
    // will type, not a filesystem-resolved absolute path.
    let config_hint = std::env::var("DWAAR_CONFIG").unwrap_or_else(|_| "./Dwaarfile".to_string());

    if is_not_listening {
        anyhow::anyhow!(
            "dwaar admin socket at {addr} is not accepting connections.\n\
             Is dwaar running? Start it with:\n  \
               dwaar --config {config_hint}"
        )
    } else {
        anyhow::anyhow!("cannot connect to admin API at {addr}: {err}")
    }
}

/// Send a GET request to the admin API and return the response.
pub(crate) fn get(addr: &str, path: &str) -> anyhow::Result<AdminResponse> {
    request(addr, "GET", path, None)
}

/// Send a POST request to the admin API with a JSON body.
pub(crate) fn post(addr: &str, path: &str, body: &str) -> anyhow::Result<AdminResponse> {
    request(addr, "POST", path, Some(body))
}

fn request(
    addr: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> anyhow::Result<AdminResponse> {
    if is_unix_addr(addr) {
        request_unix(addr, method, path, body)
    } else {
        request_tcp(addr, method, path, body)
    }
}

fn request_tcp(
    addr: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> anyhow::Result<AdminResponse> {
    let mut stream = TcpStream::connect(addr).map_err(|e| friendly_connect_error(addr, &e))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    send_and_parse(&mut stream, method, path, body)
}

#[cfg(unix)]
fn request_unix(
    addr: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> anyhow::Result<AdminResponse> {
    use std::os::unix::net::UnixStream;

    let socket_path = unix_path(addr);
    let mut stream =
        UnixStream::connect(socket_path).map_err(|e| friendly_connect_error(addr, &e))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    send_and_parse(&mut stream, method, path, body)
}

#[cfg(not(unix))]
fn request_unix(
    addr: &str,
    _method: &str,
    _path: &str,
    _body: Option<&str>,
) -> anyhow::Result<AdminResponse> {
    anyhow::bail!("Unix socket admin connections are not supported on this platform: {addr}")
}

fn send_and_parse(
    stream: &mut (impl Read + Write),
    method: &str,
    path: &str,
    body: Option<&str>,
) -> anyhow::Result<AdminResponse> {
    // Add auth token if set
    let auth_header = std::env::var("DWAAR_ADMIN_TOKEN")
        .ok()
        .map_or_else(String::new, |t| {
            let sanitized: String = t.chars().filter(|c| *c != '\r' && *c != '\n').collect();
            format!("Authorization: Bearer {sanitized}\r\n")
        });

    let content_length = body.map_or(0, str::len);
    let req = format!(
        "{method} {path} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\
         {auth_header}\
         Content-Length: {content_length}\r\n\
         \r\n"
    );

    stream.write_all(req.as_bytes())?;
    if let Some(body) = body {
        stream.write_all(body.as_bytes())?;
    }
    stream.flush()?;

    parse_response(stream)
}

fn parse_response(stream: &mut impl Read) -> anyhow::Result<AdminResponse> {
    let mut reader = BufReader::new(stream);

    // Parse status line
    let mut status_line = String::new();
    reader.read_line(&mut status_line)?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    // Parse headers to find Content-Length and Transfer-Encoding
    let mut content_length: Option<usize> = None;
    let mut is_chunked = false;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        let lower = trimmed.to_ascii_lowercase();
        if let Some(val) = lower.strip_prefix("content-length:") {
            content_length = val.trim().parse().ok();
        } else if lower.contains("transfer-encoding") && lower.contains("chunked") {
            is_chunked = true;
        }
    }

    // Read body. Admin API only sends small JSON responses, so this simple
    // chunked decoder is sufficient. Format: hex-size\r\n, data, \r\n;
    // a zero-size chunk signals end-of-body.
    let body = if is_chunked {
        let mut decoded = String::new();
        loop {
            let mut size_line = String::new();
            reader.read_line(&mut size_line)?;
            let chunk_size = usize::from_str_radix(size_line.trim(), 16).unwrap_or(0);
            if chunk_size == 0 {
                break;
            }
            let mut chunk = vec![0u8; chunk_size];
            reader.read_exact(&mut chunk)?;
            decoded.push_str(&String::from_utf8_lossy(&chunk));
            // Consume trailing \r\n after chunk data
            let mut crlf = [0u8; 2];
            let _ = reader.read_exact(&mut crlf);
        }
        decoded
    } else if let Some(len) = content_length {
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf)?;
        String::from_utf8_lossy(&buf).to_string()
    } else {
        let mut buf = String::new();
        let _ = reader.read_to_string(&mut buf);
        buf
    };

    Ok(AdminResponse { status, body })
}
