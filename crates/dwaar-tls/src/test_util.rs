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
