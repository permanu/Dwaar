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

    #[test]
    fn extract_ocsp_url_finds_aia_responder() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);

        let (cert_pem, _key_pem, _ca_pem, _ca_key_pem) =
            crate::test_util::generate_ca_signed_with_ocsp(
                "aia-test.example.com",
                &format!("http://127.0.0.1:{port}"),
            );
        let cert = X509::from_pem(&cert_pem).expect("parse");
        let url = extract_ocsp_url(&cert).expect("should find OCSP URL");
        assert_eq!(url, format!("http://127.0.0.1:{port}"));
    }

    /// Mock OCSP infrastructure for integration testing.
    ///
    /// Uses `openssl-sys` FFI to build signed OCSP responses because the
    /// high-level `openssl` crate only exposes parsing/validation, not creation.
    mod mock_ocsp {
        #![allow(unsafe_code)]

        use foreign_types_shared::ForeignType;
        use openssl::pkey::{PKey, Private};
        use openssl::x509::X509;
        use std::io::{Read, Write};
        use std::ptr;

        // Functions not exposed by the openssl-sys crate (it only binds a subset
        // of OpenSSL's OCSP API). Declared here for test use only.
        unsafe extern "C" {
            fn OCSP_basic_add1_status(
                rsp: *mut openssl_sys::OCSP_BASICRESP,
                cid: *mut openssl_sys::OCSP_CERTID,
                status: std::ffi::c_int,
                reason: std::ffi::c_int,
                revtime: *mut openssl_sys::ASN1_TIME,
                thisupd: *mut openssl_sys::ASN1_TIME,
                nextupd: *mut openssl_sys::ASN1_TIME,
            ) -> *mut std::ffi::c_void; // actually OCSP_SINGLERESP, not in bindings

            fn OCSP_basic_sign(
                brsp: *mut openssl_sys::OCSP_BASICRESP,
                signer: *mut openssl_sys::X509,
                key: *mut openssl_sys::EVP_PKEY,
                dgst: *const openssl_sys::EVP_MD,
                certs: *mut openssl_sys::stack_st_X509,
                flags: std::ffi::c_ulong,
            ) -> std::ffi::c_int;

            fn OCSP_response_create(
                status: std::ffi::c_int,
                bs: *mut openssl_sys::OCSP_BASICRESP,
            ) -> *mut openssl_sys::OCSP_RESPONSE;
        }

        // OpenSSL constants defined as C macros — not in openssl-sys
        const V_OCSP_CERTSTATUS_GOOD: std::ffi::c_int = 0;
        const V_OCSP_CERTSTATUS_REVOKED: std::ffi::c_int = 1;
        const OCSP_RESPONSE_STATUS_SUCCESSFUL: std::ffi::c_int = 0;
        const OCSP_NOFLAGS: std::ffi::c_ulong = 0;

        /// Build a DER-encoded, CA-signed OCSP response.
        ///
        /// Produces a response that passes our production `validate_ocsp_response()`
        /// checks: signed by the issuer cert, valid timestamps, correct cert status.
        pub(super) fn build_signed_response(
            cert: &X509,
            issuer: &X509,
            ca_key: &PKey<Private>,
            good: bool,
        ) -> Vec<u8> {
            unsafe {
                let cert_id = openssl_sys::OCSP_cert_to_id(
                    openssl_sys::EVP_sha1(),
                    cert.as_ptr(),
                    issuer.as_ptr(),
                );
                assert!(!cert_id.is_null(), "OCSP_cert_to_id failed");

                let basic = openssl_sys::OCSP_BASICRESP_new();
                assert!(!basic.is_null(), "OCSP_BASICRESP_new failed");

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("system time")
                    .as_secs();

                let this_update = openssl_sys::ASN1_TIME_set(ptr::null_mut(), now.cast_signed());
                let next_update =
                    openssl_sys::ASN1_TIME_set(ptr::null_mut(), (now + 86_400).cast_signed());

                let status = if good {
                    V_OCSP_CERTSTATUS_GOOD
                } else {
                    V_OCSP_CERTSTATUS_REVOKED
                };

                let revtime = if good { ptr::null_mut() } else { this_update };

                let single = OCSP_basic_add1_status(
                    basic,
                    cert_id,
                    status,
                    0, // reason (unspecified)
                    revtime,
                    this_update,
                    next_update,
                );
                assert!(!single.is_null(), "OCSP_basic_add1_status failed");

                let ret = OCSP_basic_sign(
                    basic,
                    issuer.as_ptr(),
                    ca_key.as_ptr(),
                    openssl_sys::EVP_sha256(),
                    ptr::null_mut(),
                    OCSP_NOFLAGS,
                );
                assert!(ret > 0, "OCSP_basic_sign failed: {ret}");

                let response = OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, basic);
                assert!(!response.is_null(), "OCSP_response_create failed");

                let mut der_ptr: *mut u8 = ptr::null_mut();
                let len = openssl_sys::i2d_OCSP_RESPONSE(response, &raw mut der_ptr);
                assert!(len > 0, "i2d_OCSP_RESPONSE failed");

                let der = std::slice::from_raw_parts(der_ptr, len as usize).to_vec();

                openssl_sys::OPENSSL_free(der_ptr.cast());
                openssl_sys::OCSP_RESPONSE_free(response);
                openssl_sys::OCSP_BASICRESP_free(basic);
                openssl_sys::ASN1_TIME_free(this_update);
                openssl_sys::ASN1_TIME_free(next_update);
                openssl_sys::OCSP_CERTID_free(cert_id);

                der
            }
        }

        /// Bind a mock OCSP responder to an ephemeral port, returning the
        /// listener so the caller can embed the port in a cert's AIA URL
        /// before the server starts accepting.
        pub(super) fn bind_responder() -> std::net::TcpListener {
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind mock OCSP")
        }

        /// Start serving OCSP responses on an already-bound listener.
        ///
        /// Accepts exactly `request_count` connections, serving the same
        /// DER response each time, then shuts down.
        pub(super) fn serve(
            listener: std::net::TcpListener,
            response_der: Vec<u8>,
            request_count: usize,
        ) -> std::thread::JoinHandle<()> {
            std::thread::spawn(move || {
                for _ in 0..request_count {
                    let (mut stream, _) = listener.accept().expect("accept");

                    // Drain the full request so no unread data remains in the
                    // receive buffer (leftover data → TCP RST on close).
                    stream
                        .set_read_timeout(Some(std::time::Duration::from_millis(100)))
                        .ok();
                    let mut buf = [0u8; 4096];
                    loop {
                        match stream.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {}
                        }
                    }

                    let http_response = format!(
                        "HTTP/1.1 200 OK\r\n\
                         Content-Type: application/ocsp-response\r\n\
                         Content-Length: {}\r\n\
                         Connection: close\r\n\
                         \r\n",
                        response_der.len()
                    );
                    let _ = stream.write_all(http_response.as_bytes());
                    let _ = stream.write_all(&response_der);
                    let _ = stream.flush();

                    // Half-close the write side so the client sees a clean
                    // EOF instead of a TCP RST when we drop the socket.
                    let _ = stream.shutdown(std::net::Shutdown::Write);
                }
            })
        }
    }

    // ── Integration tests ──────────────────────────────────────────────

    #[tokio::test]
    async fn fetch_ocsp_from_mock_responder() {
        // Bind first to grab a port, then generate the cert with that port in AIA
        let listener = mock_ocsp::bind_responder();
        let port = listener.local_addr().expect("addr").port();

        let (cert_pem, _key_pem, ca_pem, ca_key_pem) =
            crate::test_util::generate_ca_signed_with_ocsp(
                "ocsp-fetch.example.com",
                &format!("http://127.0.0.1:{port}"),
            );

        let cert = X509::from_pem(&cert_pem).expect("parse cert");
        let ca = X509::from_pem(&ca_pem).expect("parse CA");
        let ca_key = openssl::pkey::PKey::private_key_from_pem(&ca_key_pem).expect("parse CA key");

        let ocsp_der = mock_ocsp::build_signed_response(&cert, &ca, &ca_key, true);

        // Start serving on the already-bound listener
        let server_handle = mock_ocsp::serve(listener, ocsp_der.clone(), 1);

        // Fetch and validate through our production code
        let result = fetch_ocsp_response("ocsp-fetch.example.com", &cert, &ca).await;
        let response_der = result.expect("fetch_ocsp_response should succeed");

        assert_eq!(response_der, ocsp_der);

        server_handle.join().expect("mock server thread");
    }

    #[tokio::test]
    async fn revoked_cert_rejected_by_ocsp() {
        let listener = mock_ocsp::bind_responder();
        let port = listener.local_addr().expect("addr").port();

        let (cert_pem, _key_pem, ca_pem, ca_key_pem) =
            crate::test_util::generate_ca_signed_with_ocsp(
                "revoked.example.com",
                &format!("http://127.0.0.1:{port}"),
            );

        let cert = X509::from_pem(&cert_pem).expect("parse cert");
        let ca = X509::from_pem(&ca_pem).expect("parse CA");
        let ca_key = openssl::pkey::PKey::private_key_from_pem(&ca_key_pem).expect("parse CA key");

        let ocsp_der = mock_ocsp::build_signed_response(&cert, &ca, &ca_key, false);
        let server_handle = mock_ocsp::serve(listener, ocsp_der, 1);

        let result = fetch_ocsp_response("revoked.example.com", &cert, &ca).await;

        assert!(
            matches!(result, Err(OcspError::CertRevoked { .. })),
            "revoked cert should be rejected, got: {result:?}"
        );

        server_handle.join().expect("mock server thread");
    }

    /// Proves the full stapling path: OCSP response bytes set by the server's
    /// status callback are received by the client during TLS handshake.
    /// This is what `sni.rs` does via `ssl.set_ocsp_status()`.
    #[test]
    fn ocsp_stapled_in_tls_handshake() {
        #![allow(unsafe_code)]

        use openssl::pkey::PKey;
        use openssl::ssl::{Ssl, SslAcceptor, SslContext, SslMethod, SslVerifyMode};
        use openssl::x509::X509;

        let (cert_pem, key_pem, ca_pem, ca_key_pem) =
            crate::test_util::generate_ca_signed_with_ocsp(
                "staple-test.example.com",
                "http://127.0.0.1:1", // placeholder — not contacted in this test
            );

        let cert = X509::from_pem(&cert_pem).expect("parse cert");
        let key = PKey::private_key_from_pem(&key_pem).expect("parse key");
        let ca = X509::from_pem(&ca_pem).expect("parse CA");
        let ca_key = PKey::private_key_from_pem(&ca_key_pem).expect("parse CA key");

        let ocsp_der = mock_ocsp::build_signed_response(&cert, &ca, &ca_key, true);
        let expected_ocsp = ocsp_der.clone();

        // Server: accepts one TLS connection, staples the OCSP response
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let tls_port = listener.local_addr().expect("addr").port();

        let server_handle = std::thread::spawn(move || {
            let mut acceptor =
                SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).expect("acceptor");
            acceptor.set_certificate(&cert).expect("set cert");
            acceptor.set_private_key(&key).expect("set key");

            // This mirrors what sni.rs does in certificate_callback
            acceptor
                .set_status_callback(move |ssl| {
                    ssl.set_ocsp_status(&ocsp_der).expect("set OCSP status");
                    Ok(true)
                })
                .expect("set status callback");

            let acceptor = acceptor.build();
            let (stream, _) = listener.accept().expect("accept");
            let _tls = acceptor.accept(stream).expect("TLS accept");
        });

        // Client: connects with OCSP status request enabled
        let tcp = std::net::TcpStream::connect(format!("127.0.0.1:{tls_port}"))
            .expect("connect to TLS server");

        let mut ctx_builder = SslContext::builder(SslMethod::tls_client()).expect("ctx");
        ctx_builder.set_verify(SslVerifyMode::NONE);

        // Enable OCSP stapling request (SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE = 65)
        unsafe {
            openssl_sys::SSL_CTX_ctrl(
                ctx_builder.as_ptr(),
                65, // SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE
                1,  // TLSEXT_STATUSTYPE_ocsp
                std::ptr::null_mut(),
            );
        }

        let ctx = ctx_builder.build();
        let ssl = Ssl::new(&ctx).expect("SSL object");

        let tls_stream = ssl.connect(tcp).expect("TLS handshake");

        let received_ocsp = tls_stream
            .ssl()
            .ocsp_status()
            .expect("client must receive a stapled OCSP response");
        assert!(
            !received_ocsp.is_empty(),
            "stapled OCSP response must not be empty"
        );
        assert_eq!(
            received_ocsp,
            expected_ocsp.as_slice(),
            "stapled OCSP response must match what the server set"
        );

        server_handle.join().expect("TLS server thread");
    }
}
