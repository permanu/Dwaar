// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! OCSP response fetching and validation.
//!
//! Builds OCSP requests using OpenSSL, transports them via raw HTTP/1.1,
//! and validates the response signature and cert status.

use std::time::Duration;

use openssl::hash::MessageDigest;
use openssl::ocsp::{OcspCertStatus, OcspFlag, OcspRequest, OcspResponse, OcspResponseStatus};
use openssl::x509::X509;
use openssl::x509::store::X509StoreBuilder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};

/// Timeout for HTTP requests to OCSP responders.
const OCSP_HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// Max response size from an OCSP responder (64 KB — real responses are 1-4 KB).
const MAX_OCSP_RESPONSE_SIZE: u64 = 65_536;

/// Errors from OCSP fetching and validation.
#[derive(Debug, thiserror::Error)]
pub enum OcspError {
    #[error("cert has no OCSP responder URL")]
    NoResponder,

    #[error("failed to build OCSP request: {0}")]
    RequestBuild(String),

    #[error("HTTP fetch failed: {0}")]
    HttpFetch(String),

    #[error("invalid OCSP response: {0}")]
    InvalidResponse(String),

    #[error("certificate revoked per OCSP responder for {domain} (serial: {serial})")]
    CertRevoked { domain: String, serial: String },
}

/// Fetch and validate an OCSP response for a certificate.
///
/// Returns the raw DER-encoded OCSP response bytes on success.
/// These bytes can be stapled directly into TLS handshakes.
pub async fn fetch_ocsp_response(
    domain: &str,
    cert: &X509,
    issuer: &X509,
) -> Result<Vec<u8>, OcspError> {
    let responder_url = extract_ocsp_url(cert)?;
    debug!(domain, url = %responder_url, "OCSP responder URL found");

    let ocsp_request_der = build_ocsp_request(cert, issuer)?;

    let response_der = http_post_ocsp(&responder_url, &ocsp_request_der).await?;

    validate_ocsp_response(domain, &response_der, cert, issuer)?;

    Ok(response_der)
}

/// Extract the first OCSP responder URL from the cert's AIA extension.
fn extract_ocsp_url(cert: &X509) -> Result<String, OcspError> {
    // `ocsp_responders()` returns Err when the AIA extension is absent
    let Ok(responders) = cert.ocsp_responders() else {
        return Err(OcspError::NoResponder);
    };

    responders
        .into_iter()
        .next()
        .map(|s| s.to_string())
        .ok_or(OcspError::NoResponder)
}

/// Build a DER-encoded OCSP request for the given cert.
fn build_ocsp_request(cert: &X509, issuer: &X509) -> Result<Vec<u8>, OcspError> {
    let cert_id = openssl::ocsp::OcspCertId::from_cert(MessageDigest::sha1(), cert, issuer)
        .map_err(|e| OcspError::RequestBuild(format!("failed to create cert ID: {e}")))?;

    let mut request = OcspRequest::new()
        .map_err(|e| OcspError::RequestBuild(format!("failed to create request: {e}")))?;

    request
        .add_id(cert_id)
        .map_err(|e| OcspError::RequestBuild(format!("failed to add cert ID: {e}")))?;

    request
        .to_der()
        .map_err(|e| OcspError::RequestBuild(format!("failed to serialize: {e}")))
}

/// Send an OCSP request via raw HTTP/1.1 POST.
///
/// OCSP responders typically serve plain HTTP — the response is
/// cryptographically signed, so transport security is unnecessary.
async fn http_post_ocsp(url: &str, body: &[u8]) -> Result<Vec<u8>, OcspError> {
    // OCSP URLs are always simple http://host[:port]/path
    let stripped = url
        .strip_prefix("http://")
        .ok_or_else(|| OcspError::HttpFetch(format!("non-HTTP OCSP URL: {url}")))?;

    let (host_port, path) = stripped
        .find('/')
        .map_or((stripped, "/"), |i| (&stripped[..i], &stripped[i..]));

    let (host, port) = if let Some(colon) = host_port.rfind(':') {
        let port_str = &host_port[colon + 1..];
        let port: u16 = port_str
            .parse()
            .map_err(|_| OcspError::HttpFetch(format!("invalid port: {port_str}")))?;
        (&host_port[..colon], port)
    } else {
        (host_port, 80)
    };

    let addr = format!("{host}:{port}");

    let mut stream = tokio::time::timeout(OCSP_HTTP_TIMEOUT, TcpStream::connect(&addr))
        .await
        .map_err(|_| OcspError::HttpFetch("connection timed out".to_string()))?
        .map_err(|e| OcspError::HttpFetch(format!("connect failed: {e}")))?;

    let request = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Type: application/ocsp-request\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );

    tokio::time::timeout(OCSP_HTTP_TIMEOUT, async {
        stream.write_all(request.as_bytes()).await?;
        stream.write_all(body).await?;
        stream.flush().await?;
        Ok::<_, std::io::Error>(())
    })
    .await
    .map_err(|_| OcspError::HttpFetch("write timed out".to_string()))?
    .map_err(|e| OcspError::HttpFetch(format!("write failed: {e}")))?;

    // Read response with bounded size
    let mut response_buf = Vec::with_capacity(8192);
    tokio::time::timeout(
        OCSP_HTTP_TIMEOUT,
        stream
            .take(MAX_OCSP_RESPONSE_SIZE)
            .read_to_end(&mut response_buf),
    )
    .await
    .map_err(|_| OcspError::HttpFetch("read timed out".to_string()))?
    .map_err(|e| OcspError::HttpFetch(format!("read failed: {e}")))?;

    // Find the body after the \r\n\r\n header terminator
    let header_end = response_buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| OcspError::HttpFetch("malformed HTTP response".to_string()))?;

    let status_line_end = response_buf.iter().position(|&b| b == b'\r').unwrap_or(0);
    let status_line = std::str::from_utf8(&response_buf[..status_line_end]).unwrap_or("");
    if !status_line.contains("200") {
        return Err(OcspError::HttpFetch(format!(
            "OCSP responder returned: {status_line}"
        )));
    }

    Ok(response_buf[header_end + 4..].to_vec())
}

/// Validate an OCSP response: check status, verify signature, check cert status.
fn validate_ocsp_response(
    domain: &str,
    response_der: &[u8],
    cert: &X509,
    issuer: &X509,
) -> Result<(), OcspError> {
    let response = OcspResponse::from_der(response_der)
        .map_err(|e| OcspError::InvalidResponse(format!("failed to parse DER: {e}")))?;

    let status = response.status();
    if status != OcspResponseStatus::SUCCESSFUL {
        return Err(OcspError::InvalidResponse(format!(
            "OCSP response status: {status:?}"
        )));
    }

    let basic = response
        .basic()
        .map_err(|e| OcspError::InvalidResponse(format!("failed to get basic response: {e}")))?;

    // Build an X509Store with the issuer for signature verification
    let mut store_builder = X509StoreBuilder::new()
        .map_err(|e| OcspError::InvalidResponse(format!("X509Store build failed: {e}")))?;
    store_builder
        .add_cert(issuer.clone())
        .map_err(|e| OcspError::InvalidResponse(format!("add issuer to store failed: {e}")))?;
    let store = store_builder.build();

    let certs = openssl::stack::Stack::new()
        .map_err(|e| OcspError::InvalidResponse(format!("stack creation failed: {e}")))?;

    basic
        .verify(&certs, &store, OcspFlag::empty())
        .map_err(|e| OcspError::InvalidResponse(format!("signature verification failed: {e}")))?;

    let cert_id = openssl::ocsp::OcspCertId::from_cert(MessageDigest::sha1(), cert, issuer)
        .map_err(|e| OcspError::InvalidResponse(format!("cert ID creation failed: {e}")))?;

    let cert_status = basic
        .find_status(&cert_id)
        .ok_or_else(|| OcspError::InvalidResponse("cert not found in OCSP response".to_string()))?;

    // Check response freshness (thisUpdate/nextUpdate timestamps)
    if let Err(e) = cert_status.check_validity(300, None) {
        return Err(OcspError::InvalidResponse(format!(
            "OCSP response timestamps invalid: {e}"
        )));
    }

    match cert_status.status {
        OcspCertStatus::GOOD => {
            debug!(domain, "OCSP cert status: GOOD");
            Ok(())
        }
        OcspCertStatus::REVOKED => {
            let serial = cert
                .serial_number()
                .to_bn()
                .map(|bn| bn.to_hex_str().map(|s| s.to_string()).unwrap_or_default())
                .unwrap_or_default();
            Err(OcspError::CertRevoked {
                domain: domain.to_string(),
                serial,
            })
        }
        _ => {
            warn!(domain, "OCSP cert status: UNKNOWN");
            Err(OcspError::InvalidResponse(
                "OCSP cert status is UNKNOWN".to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_ocsp_request_produces_valid_der() {
        let (leaf_pem, _key_pem, ca_pem) =
            crate::test_util::generate_ca_signed("ocsp-test.example.com");

        let leaf = X509::from_pem(&leaf_pem).expect("parse leaf");
        let ca = X509::from_pem(&ca_pem).expect("parse CA");

        let der = build_ocsp_request(&leaf, &ca).expect("build request");
        assert!(!der.is_empty(), "OCSP request DER should not be empty");
        assert_eq!(der[0], 0x30, "should start with SEQUENCE tag");
    }

    #[test]
    fn extract_ocsp_url_returns_none_for_self_signed() {
        let (cert_pem, _key_pem) = crate::test_util::generate_self_signed("no-aia.example.com");
        let cert = X509::from_pem(&cert_pem).expect("parse");
        let result = extract_ocsp_url(&cert);
        assert!(
            matches!(result, Err(OcspError::NoResponder)),
            "self-signed cert has no OCSP responder"
        );
    }
}
