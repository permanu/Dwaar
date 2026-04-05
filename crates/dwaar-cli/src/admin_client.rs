// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Minimal HTTP/1.1 client for querying the Dwaar Admin API.
//!
//! Uses raw `TcpStream` — no external HTTP library needed.
//! Only supports simple GET/POST to localhost, which is all CLI
//! commands need for talking to the co-located admin API.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Default admin API address.
pub(crate) const DEFAULT_ADMIN_ADDR: &str = "127.0.0.1:6190";

/// Response from the admin API.
pub(crate) struct AdminResponse {
    pub status: u16,
    pub body: String,
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
    let mut stream = TcpStream::connect(addr).map_err(|e| {
        anyhow::anyhow!(
            "cannot connect to admin API at {addr}: {e}\n\
             Is Dwaar running? The admin API listens on {DEFAULT_ADMIN_ADDR} by default."
        )
    })?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

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

    parse_response(&mut stream)
}

fn parse_response(stream: &mut TcpStream) -> anyhow::Result<AdminResponse> {
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
