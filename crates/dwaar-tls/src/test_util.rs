// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Shared test utilities for dwaar-tls.

use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::extension::SubjectAlternativeName;
use openssl::x509::{X509, X509Name};

/// Generate a CA cert, then a leaf cert signed by that CA.
/// Returns `(leaf_cert_pem, leaf_key_pem, ca_cert_pem)`.
pub(crate) fn generate_ca_signed(domain: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    use openssl::x509::extension::BasicConstraints;

    // Generate CA
    let ca_rsa = Rsa::generate(2048).expect("generate CA RSA");
    let ca_key = PKey::from_rsa(ca_rsa).expect("CA pkey");

    let mut ca_name = X509Name::builder().expect("CA name builder");
    ca_name
        .append_entry_by_nid(Nid::COMMONNAME, "Test CA")
        .expect("set CA CN");
    let ca_name = ca_name.build();

    let mut ca_builder = X509::builder().expect("CA x509 builder");
    ca_builder.set_version(2).expect("set version");
    let serial = BigNum::from_u32(1).expect("bn");
    let serial = serial.to_asn1_integer().expect("asn1");
    ca_builder.set_serial_number(&serial).expect("set serial");
    ca_builder.set_subject_name(&ca_name).expect("set subject");
    ca_builder.set_issuer_name(&ca_name).expect("set issuer");
    ca_builder.set_pubkey(&ca_key).expect("set pubkey");
    let not_before = Asn1Time::days_from_now(0).expect("not_before");
    let not_after = Asn1Time::days_from_now(365).expect("not_after");
    ca_builder.set_not_before(&not_before).expect("set nb");
    ca_builder.set_not_after(&not_after).expect("set na");
    let bc = BasicConstraints::new().critical().ca().build().expect("bc");
    ca_builder.append_extension(bc).expect("append bc");
    ca_builder
        .sign(&ca_key, MessageDigest::sha256())
        .expect("sign CA");
    let ca_cert = ca_builder.build();

    // Generate leaf cert signed by CA
    let leaf_rsa = Rsa::generate(2048).expect("generate leaf RSA");
    let leaf_key = PKey::from_rsa(leaf_rsa).expect("leaf pkey");

    let mut leaf_name = X509Name::builder().expect("leaf name builder");
    leaf_name
        .append_entry_by_nid(Nid::COMMONNAME, domain)
        .expect("set leaf CN");
    let leaf_name = leaf_name.build();

    let mut leaf_builder = X509::builder().expect("leaf x509 builder");
    leaf_builder.set_version(2).expect("set version");
    let serial2 = BigNum::from_u32(2).expect("bn");
    let serial2 = serial2.to_asn1_integer().expect("asn1");
    leaf_builder
        .set_serial_number(&serial2)
        .expect("set serial");
    leaf_builder
        .set_subject_name(&leaf_name)
        .expect("set subject");
    leaf_builder
        .set_issuer_name(ca_cert.subject_name())
        .expect("set issuer");
    leaf_builder.set_pubkey(&leaf_key).expect("set pubkey");
    leaf_builder.set_not_before(&not_before).expect("set nb");
    leaf_builder.set_not_after(&not_after).expect("set na");

    let mut san = SubjectAlternativeName::new();
    san.dns(domain);
    let san_ext = san
        .build(&leaf_builder.x509v3_context(Some(&ca_cert), None))
        .expect("build SAN");
    leaf_builder.append_extension(san_ext).expect("append SAN");

    leaf_builder
        .sign(&ca_key, MessageDigest::sha256())
        .expect("sign leaf");
    let leaf_cert = leaf_builder.build();

    (
        leaf_cert.to_pem().expect("leaf cert pem"),
        leaf_key.private_key_to_pem_pkcs8().expect("leaf key pem"),
        ca_cert.to_pem().expect("ca cert pem"),
    )
}

/// Generate a CA cert + leaf cert with an OCSP responder URL in the AIA extension.
///
/// Returns `(leaf_cert_pem, leaf_key_pem, ca_cert_pem, ca_key_pem)`.
/// The CA key is needed to sign mock OCSP responses in tests.
pub(crate) fn generate_ca_signed_with_ocsp(
    domain: &str,
    ocsp_url: &str,
) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    use openssl::x509::X509Extension;
    use openssl::x509::extension::BasicConstraints;

    // Generate CA (same as generate_ca_signed)
    let ca_rsa = Rsa::generate(2048).expect("generate CA RSA");
    let ca_key = PKey::from_rsa(ca_rsa).expect("CA pkey");

    let mut ca_name = X509Name::builder().expect("CA name builder");
    ca_name
        .append_entry_by_nid(Nid::COMMONNAME, "Test CA")
        .expect("set CA CN");
    let ca_name = ca_name.build();

    let mut ca_builder = X509::builder().expect("CA x509 builder");
    ca_builder.set_version(2).expect("set version");
    let serial = BigNum::from_u32(1).expect("bn");
    let serial = serial.to_asn1_integer().expect("asn1");
    ca_builder.set_serial_number(&serial).expect("set serial");
    ca_builder.set_subject_name(&ca_name).expect("set subject");
    ca_builder.set_issuer_name(&ca_name).expect("set issuer");
    ca_builder.set_pubkey(&ca_key).expect("set pubkey");
    let not_before = Asn1Time::days_from_now(0).expect("not_before");
    let not_after = Asn1Time::days_from_now(365).expect("not_after");
    ca_builder.set_not_before(&not_before).expect("set nb");
    ca_builder.set_not_after(&not_after).expect("set na");
    let bc = BasicConstraints::new().critical().ca().build().expect("bc");
    ca_builder.append_extension(bc).expect("append bc");
    ca_builder
        .sign(&ca_key, MessageDigest::sha256())
        .expect("sign CA");
    let ca_cert = ca_builder.build();

    // Generate leaf cert signed by CA, with AIA extension for OCSP
    let leaf_rsa = Rsa::generate(2048).expect("generate leaf RSA");
    let leaf_key = PKey::from_rsa(leaf_rsa).expect("leaf pkey");

    let mut leaf_name = X509Name::builder().expect("leaf name builder");
    leaf_name
        .append_entry_by_nid(Nid::COMMONNAME, domain)
        .expect("set leaf CN");
    let leaf_name = leaf_name.build();

    let mut leaf_builder = X509::builder().expect("leaf x509 builder");
    leaf_builder.set_version(2).expect("set version");
    let serial2 = BigNum::from_u32(2).expect("bn");
    let serial2 = serial2.to_asn1_integer().expect("asn1");
    leaf_builder
        .set_serial_number(&serial2)
        .expect("set serial");
    leaf_builder
        .set_subject_name(&leaf_name)
        .expect("set subject");
    leaf_builder
        .set_issuer_name(ca_cert.subject_name())
        .expect("set issuer");
    leaf_builder.set_pubkey(&leaf_key).expect("set pubkey");
    leaf_builder.set_not_before(&not_before).expect("set nb");
    leaf_builder.set_not_after(&not_after).expect("set na");

    let mut san = SubjectAlternativeName::new();
    san.dns(domain);
    let san_ext = san
        .build(&leaf_builder.x509v3_context(Some(&ca_cert), None))
        .expect("build SAN");
    leaf_builder.append_extension(san_ext).expect("append SAN");

    // Authority Information Access — tells clients where the OCSP responder lives.
    // No high-level builder exists for AIA in the openssl crate; the deprecated
    // X509Extension::new is the only way to create arbitrary extension types.
    #[allow(deprecated)]
    let aia = X509Extension::new(
        None,
        Some(&leaf_builder.x509v3_context(Some(&ca_cert), None)),
        "authorityInfoAccess",
        &format!("OCSP;URI:{ocsp_url}"),
    )
    .expect("build AIA extension");
    leaf_builder.append_extension(aia).expect("append AIA");

    leaf_builder
        .sign(&ca_key, MessageDigest::sha256())
        .expect("sign leaf");
    let leaf_cert = leaf_builder.build();

    (
        leaf_cert.to_pem().expect("leaf cert pem"),
        leaf_key.private_key_to_pem_pkcs8().expect("leaf key pem"),
        ca_cert.to_pem().expect("ca cert pem"),
        ca_key.private_key_to_pem_pkcs8().expect("ca key pem"),
    )
}

/// Generate a self-signed cert+key PEM pair for testing.
pub(crate) fn generate_self_signed(domain: &str) -> (Vec<u8>, Vec<u8>) {
    let rsa = Rsa::generate(2048).expect("generate RSA");
    let key = PKey::from_rsa(rsa).expect("pkey from rsa");

    let mut name = X509Name::builder().expect("x509 name builder");
    name.append_entry_by_nid(Nid::COMMONNAME, domain)
        .expect("set CN");
    let name = name.build();

    let mut builder = X509::builder().expect("x509 builder");
    builder.set_version(2).expect("set version");

    let serial = BigNum::from_u32(1).expect("bn");
    let serial = serial.to_asn1_integer().expect("asn1");
    builder.set_serial_number(&serial).expect("set serial");

    builder.set_subject_name(&name).expect("set subject");
    builder.set_issuer_name(&name).expect("set issuer");
    builder.set_pubkey(&key).expect("set pubkey");

    let not_before = Asn1Time::days_from_now(0).expect("not_before");
    let not_after = Asn1Time::days_from_now(365).expect("not_after");
    builder.set_not_before(&not_before).expect("set not_before");
    builder.set_not_after(&not_after).expect("set not_after");

    let mut san = SubjectAlternativeName::new();
    san.dns(domain);
    let san_ext = san
        .build(&builder.x509v3_context(None, None))
        .expect("build SAN");
    builder.append_extension(san_ext).expect("append SAN");

    builder.sign(&key, MessageDigest::sha256()).expect("sign");

    let cert = builder.build();
    (
        cert.to_pem().expect("cert pem"),
        key.private_key_to_pem_pkcs8().expect("key pem"),
    )
}
