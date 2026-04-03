// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! dwaar-tls — TLS termination with SNI-based cert selection.
//!
//! Provides a [`CertStore`](cert_store::CertStore) for loading and caching
//! certificates, and an [`SniResolver`](sni::SniResolver) that implements
//! Pingora's `TlsAccept` trait for dynamic cert selection during handshake.

pub mod acme;
pub mod cert_store;
pub mod dns;
pub mod dns_cloudflare;
pub mod mtls;
pub mod ocsp;
pub mod sni;

#[cfg(test)]
pub(crate) mod test_util;
