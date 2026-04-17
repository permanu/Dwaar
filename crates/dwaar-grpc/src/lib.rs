// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! dwaar-grpc — bidirectional control fabric between Permanu and Dwaar.
//!
//! Wheel #2 of the substrate contract (see
//! `permanu/docs/substrate-contract.md`).
//!
//! Week 1 shipped the tonic scaffold with `Hello` / `Heartbeat` handlers
//! and `not_implemented` stubs. Week 2 wires the server into admin startup
//! with optional mTLS ([`tls`]). Week 3 implements the real route-mutation
//! handlers.
//!
//! ## mTLS environment variables
//!
//! The server supports optional mutual TLS, configured via environment:
//!
//! - `DWAAR_GRPC_CERT_FILE` — path to server certificate PEM (with chain)
//! - `DWAAR_GRPC_KEY_FILE`  — path to server private key PEM
//! - `DWAAR_GRPC_CA_FILE`   — path to CA bundle for client verification
//!
//! If `CERT_FILE` and `KEY_FILE` are both set, the server terminates TLS.
//! If `CA_FILE` is additionally set, the server enforces mutual TLS — every
//! client must present a certificate signed by that CA. With no cert/key
//! configured the server runs plaintext — the expected default for local
//! development.

pub mod pb {
    //! Protobuf types generated from `proto/dwaar.proto`.
    #![allow(clippy::all, clippy::pedantic, missing_debug_implementations)]
    tonic::include_proto!("permanu.dwaar.v1");
}

pub mod service;
pub mod tls;

pub use service::{DwaarControlService, Error, start_grpc_server, start_grpc_server_with_shutdown};
pub use tls::{TlsConfig, TlsError};
