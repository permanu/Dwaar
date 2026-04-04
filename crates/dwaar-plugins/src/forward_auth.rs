// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Forward auth middleware — subrequest to external auth service.
//!
//! Sends a GET request to an auth endpoint (Authelia, Authentik, etc.) with
//! the original request's `X-Forwarded-Method` and `X-Forwarded-Uri` headers.
//! On 2xx → allow (copy selected headers to upstream). On 4xx → block.
//!
//! ## Security (CVE-2026-30851 mitigation)
//!
//! Client-supplied values for `copy_headers` fields are **always stripped**
//! from the upstream request before copying the auth service's values. This
//! prevents a client from injecting headers like `Remote-User` to impersonate
//! authenticated users when the auth service doesn't return them.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use compact_str::CompactString;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// Pre-compiled forward auth configuration.
#[derive(Debug, Clone)]
pub struct ForwardAuthConfig {
    /// Resolved address of the auth service.
    pub upstream: SocketAddr,
    /// URI path sent to the auth service (e.g., `/api/authz/forward-auth`).
    pub auth_uri: CompactString,
    /// Headers to copy from auth response → upstream request.
    pub copy_headers: Vec<CompactString>,
    /// Whether the subrequest to the auth service uses TLS.
    ///
    /// When `false`, responses travel in plaintext — an on-path attacker can
    /// forge a 2xx and inject `copy_headers` values (e.g. `Remote-User`).
    /// Set to `true` and configure a TLS-capable backend to close this gap.
    pub tls: bool,
}

/// Result of an auth subrequest.
#[derive(Debug)]
pub enum AuthResult {
    /// Auth succeeded (2xx). Contains headers to copy to upstream.
    Allowed(HashMap<CompactString, CompactString>),
    /// Auth denied (4xx). Contains status code and response body for the client.
    Denied { status: u16, body: Vec<u8> },
    /// Auth service unreachable or errored.
    Error(String),
}

const AUTH_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_AUTH_RESPONSE: u64 = 65_536;

/// Strip CR/LF from a value before it enters a raw HTTP request header.
/// Prevents CRLF injection when interpolating client-supplied strings.
fn sanitize_header_value(s: &str) -> String {
    s.chars().filter(|c| *c != '\r' && *c != '\n').collect()
}

impl ForwardAuthConfig {
    /// Make the auth subrequest. Returns whether to allow or deny.
    pub async fn check(
        &self,
        method: &str,
        original_uri: &str,
        client_ip: Option<&str>,
    ) -> AuthResult {
        match self.do_request(method, original_uri, client_ip).await {
            Ok(result) => result,
            Err(e) => AuthResult::Error(e),
        }
    }

    async fn do_request(
        &self,
        method: &str,
        original_uri: &str,
        client_ip: Option<&str>,
    ) -> Result<AuthResult, String> {
        if !self.tls {
            tracing::warn!(
                upstream = %self.upstream,
                "forward_auth uses plaintext TCP — auth responses are not integrity-protected; \
                 set tls: true and point to a TLS-capable endpoint to fix this"
            );
        }

        // Connect TCP with timeout
        let tcp_stream = tokio::time::timeout(AUTH_TIMEOUT, TcpStream::connect(self.upstream))
            .await
            .map_err(|_| "auth service connection timed out".to_string())?
            .map_err(|e| format!("auth service connect failed: {e}"))?;

        // Upgrade to TLS if configured, otherwise use plaintext.
        // Boxing avoids a monomorphization explosion on a non-hot path (one
        // subrequest per client request at most) — negligible vs. handshake cost.
        let (mut reader, mut writer): (
            Box<dyn AsyncRead + Unpin + Send>,
            Box<dyn AsyncWrite + Unpin + Send>,
        ) = if self.tls {
            let tls_stream = tls_connect(tcp_stream, self.upstream).await?;
            let (r, w) = tokio::io::split(tls_stream);
            (Box::new(r), Box::new(w))
        } else {
            let (r, w) = tokio::io::split(tcp_stream);
            (Box::new(r), Box::new(w))
        };

        // Build GET request with forwarded metadata.
        // Sanitize all client-supplied values to prevent CRLF header injection.
        let safe_method = sanitize_header_value(method);
        let safe_uri = sanitize_header_value(original_uri);
        let ip_header = client_ip.map_or_else(String::new, |ip| {
            format!("X-Forwarded-For: {}\r\n", sanitize_header_value(ip))
        });
        let request = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             X-Forwarded-Method: {safe_method}\r\n\
             X-Forwarded-Uri: {safe_uri}\r\n\
             {ip_header}\
             Connection: close\r\n\
             \r\n",
            self.auth_uri, self.upstream
        );

        // Write with timeout
        tokio::time::timeout(AUTH_TIMEOUT, async {
            writer.write_all(request.as_bytes()).await?;
            writer.flush().await?;
            Ok::<_, std::io::Error>(())
        })
        .await
        .map_err(|_| "auth service write timed out".to_string())?
        .map_err(|e| format!("auth service write failed: {e}"))?;

        // Read response with size limit
        let mut buf = Vec::with_capacity(4096);
        tokio::time::timeout(
            AUTH_TIMEOUT,
            (&mut reader).take(MAX_AUTH_RESPONSE).read_to_end(&mut buf),
        )
        .await
        .map_err(|_| "auth service read timed out".to_string())?
        .map_err(|e| format!("auth service read failed: {e}"))?;

        // Parse status line
        let header_end = buf
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| "malformed auth response".to_string())?;

        let header_bytes = &buf[..header_end];
        let header_str = std::str::from_utf8(header_bytes)
            .map_err(|_| "invalid UTF-8 in auth response headers".to_string())?;

        let status = header_str
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|s| s.parse::<u16>().ok())
            .ok_or_else(|| "cannot parse auth response status".to_string())?;

        let body = buf[header_end + 4..].to_vec();

        if (200..300).contains(&status) {
            // Parse response headers we need to copy
            let mut copied = HashMap::new();
            for line in header_str.lines().skip(1) {
                if let Some((name, value)) = line.split_once(':') {
                    let name_trimmed = name.trim();
                    let value_trimmed = value.trim();
                    // Only copy headers that are in the copy_headers list
                    for wanted in &self.copy_headers {
                        if name_trimmed.eq_ignore_ascii_case(wanted) {
                            copied.insert(wanted.clone(), CompactString::from(value_trimmed));
                        }
                    }
                }
            }
            Ok(AuthResult::Allowed(copied))
        } else {
            Ok(AuthResult::Denied { status, body })
        }
    }
}

/// Perform a TLS handshake over an established TCP connection.
///
/// Uses `webpki-roots` for certificate verification so we don't depend on
/// the host OS trust store. SNI is derived from the socket address IP —
/// the auth service certificate must cover that IP (common for internal
/// services) or a hostname-based approach should be used instead.
async fn tls_connect(
    tcp: TcpStream,
    addr: SocketAddr,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

    // Use IP-based SNI — rustls 0.23 supports `ServerName::from(IpAddr)`.
    let server_name = rustls::pki_types::ServerName::from(addr.ip());

    tokio::time::timeout(AUTH_TIMEOUT, connector.connect(server_name.to_owned(), tcp))
        .await
        .map_err(|_| "auth service TLS handshake timed out".to_string())?
        .map_err(|e| format!("auth service TLS handshake failed: {e}"))
}
