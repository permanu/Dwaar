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
    /// Original hostname from the config (e.g., `authelia` from `authelia:9091`).
    /// Used as TLS SNI when present, so certs issued to the hostname verify
    /// correctly even though we connect to the resolved IP address.
    /// `None` when the upstream was a literal IP address.
    pub sni_hostname: Option<CompactString>,
    /// Explicit opt-in to plaintext (non-TLS) subrequests to non-loopback
    /// auth services. Defaults to `false`; must be set to `true` to bypass
    /// the runtime enforcement that errors on plaintext non-loopback targets.
    /// A warning is still logged on first use even when opted in.
    pub allow_plaintext: bool,
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

    // do_request is a flat request pipeline: socket connect → write request →
    // read status → parse — splitting it fragments the error-handling flow.
    #[allow(clippy::too_many_lines)]
    async fn do_request(
        &self,
        method: &str,
        original_uri: &str,
        client_ip: Option<&str>,
    ) -> Result<AuthResult, String> {
        // Belt-and-braces runtime guard in case a ForwardAuthConfig is
        // constructed programmatically bypassing the parse-time check in
        // dwaar-config. The parser rejects this at config load time.
        if !self.tls && !self.upstream.ip().is_loopback() && !self.allow_plaintext {
            return Err(format!(
                "forward_auth target '{}' is plaintext and non-loopback; \
                 set tls: true or insecure_plaintext: true",
                if let Some(host) = self.sni_hostname.as_deref() {
                    format!("{host}:{}", self.upstream.port())
                } else {
                    self.upstream.to_string()
                }
            ));
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
            let tls_stream =
                tls_connect(tcp_stream, self.upstream, self.sni_hostname.as_deref()).await?;
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
            // Parse response headers we need to copy. The helper handles RFC 7230
            // §3.2.4 obs-fold (continuation lines starting with SP/HTAB).
            let mut copied = HashMap::new();
            for (name, value) in parse_response_headers(header_str) {
                for wanted in &self.copy_headers {
                    if name.eq_ignore_ascii_case(wanted.as_str()) {
                        copied.insert(wanted.clone(), CompactString::from(value.as_str()));
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
/// Uses `webpki-roots` for certificate verification. When `sni_hostname` is
/// provided (upstream was configured as a DNS name like `authelia:9091`), it's
/// used as the SNI server name so that hostname-based certificates verify
/// correctly. Falls back to IP-based SNI for literal IP upstreams.
async fn tls_connect(
    tcp: TcpStream,
    addr: SocketAddr,
    sni_hostname: Option<&str>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

    // Prefer the original hostname for SNI so certs issued to DNS names
    // verify correctly. Fall back to IP when the upstream was a literal addr.
    let server_name = match sni_hostname {
        Some(hostname) => rustls::pki_types::ServerName::try_from(hostname.to_owned())
            .map_err(|e| format!("invalid SNI hostname '{hostname}': {e}"))?,
        None => rustls::pki_types::ServerName::from(addr.ip()),
    };

    tokio::time::timeout(AUTH_TIMEOUT, connector.connect(server_name.to_owned(), tcp))
        .await
        .map_err(|_| "auth service TLS handshake timed out".to_string())?
        .map_err(|e| format!("auth service TLS handshake failed: {e}"))
}

/// Parse HTTP response header lines (everything after the status line) into
/// `(name, value)` pairs, handling RFC 7230 §3.2.4 obs-fold continuations.
///
/// A continuation line starts with SP (0x20) or HTAB (0x09). Per the RFC the
/// recipient must either reject the message or replace each fold with one or
/// more SP octets — we replace with a single SP. Orphan continuations (a fold
/// before any header has been seen) are silently discarded as malformed.
fn parse_response_headers(header_str: &str) -> Vec<(String, String)> {
    let mut headers: Vec<(String, String)> = Vec::new();
    // Track the in-progress header so obs-fold lines can append to its value.
    let mut last_header: Option<(String, String)> = None;

    for line in header_str.lines().skip(1) {
        if line.is_empty() {
            continue;
        }

        // Continuation line — leading SP or HTAB signals obs-fold.
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some((_, value)) = last_header.as_mut() {
                value.push(' ');
                value.push_str(line.trim());
            }
            // No previous header yet — malformed, skip silently.
            continue;
        }

        // Flush the completed previous header before starting a new one.
        if let Some(prev) = last_header.take() {
            headers.push(prev);
        }

        if let Some((name, value)) = line.split_once(':') {
            last_header = Some((name.trim().to_string(), value.trim().to_string()));
        }
    }

    // Flush the final header.
    if let Some(prev) = last_header {
        headers.push(prev);
    }

    headers
}

#[cfg(test)]
mod tests {
    use super::parse_response_headers;

    #[test]
    fn obs_fold_concatenates_continuation_lines() {
        // RFC 7230 §3.2.4: a header line starting with SP or HTAB is a
        // continuation of the previous header's value. We replace the fold with
        // a single SP. Issue #169.
        let raw = "HTTP/1.1 200 OK\r\nX-Long: first part\r\n  second part\r\n\tthird part\r\nOther: foo\r\n\r\n";
        let parsed = parse_response_headers(raw);
        let x_long = parsed
            .iter()
            .find(|(n, _)| n == "X-Long")
            .map(|(_, v)| v.as_str());
        assert_eq!(x_long, Some("first part second part third part"));
        let other = parsed
            .iter()
            .find(|(n, _)| n == "Other")
            .map(|(_, v)| v.as_str());
        assert_eq!(other, Some("foo"));
    }

    #[test]
    fn obs_fold_orphan_continuation_is_ignored() {
        // Continuation before any header — malformed, skip silently.
        let raw = "HTTP/1.1 200 OK\r\n  orphan\r\nReal: yes\r\n\r\n";
        let parsed = parse_response_headers(raw);
        assert_eq!(
            parsed
                .iter()
                .find(|(n, _)| n == "Real")
                .map(|(_, v)| v.as_str()),
            Some("yes")
        );
    }

    #[test]
    fn no_obs_fold_unchanged_behavior() {
        // Smoke: regular headers without folds parse identically to before.
        let raw = "HTTP/1.1 200 OK\r\nA: 1\r\nB: 2\r\n\r\n";
        let parsed = parse_response_headers(raw);
        assert_eq!(
            parsed
                .iter()
                .find(|(n, _)| n == "A")
                .map(|(_, v)| v.as_str()),
            Some("1")
        );
        assert_eq!(
            parsed
                .iter()
                .find(|(n, _)| n == "B")
                .map(|(_, v)| v.as_str()),
            Some("2")
        );
    }
}
