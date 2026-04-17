// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! dwaar-grpc — bidirectional control fabric between Permanu and Dwaar.
//!
//! Wheel #2 of the substrate contract (see
//! `permanu/docs/substrate-contract.md`). Week 1 ships the scaffold only:
//! a tonic-generated `DwaarControl` service that acknowledges `Hello` and
//! `Heartbeat` envelopes, and stubs every stateful command with a
//! `CommandAck { status: "not_implemented" }`.
//!
//! Route / `SplitTraffic` / `MirrorRequest` handlers land in Week 3.

pub mod pb {
    //! Protobuf types generated from `proto/dwaar.proto`.
    #![allow(clippy::all, clippy::pedantic, missing_debug_implementations)]
    tonic::include_proto!("permanu.dwaar.v1");
}

pub mod service;

pub use service::{DwaarControlService, Error, start_grpc_server};
