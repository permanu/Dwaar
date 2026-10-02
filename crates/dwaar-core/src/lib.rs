// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! dwaar-core — the proxy engine.
//!
//! This crate contains the `ProxyHttp` implementation that powers Dwaar.
//! It is the heart of the system: every HTTP request flows through
//! [`proxy::DwaarProxy`], with per-request state tracked in
//! [`context::RequestContext`].
//!
//! The [`route`] module provides the domain→upstream mapping that
//! `upstream_peer()` consults on every request.

pub mod admin_routes;
pub mod cache;
pub mod context;
mod fake_issuer;
pub mod fastcgi;
pub mod file_server;
pub mod grpc_web;
pub mod l4;
pub mod l4_udp;
pub mod permanu_challenge;
pub mod proxy;
pub mod quic;
pub mod registries;
pub mod route;
pub mod template;
pub mod trace;
pub mod upstream;
pub mod wake;

/// Startup failure state used by the private upgrade readiness coordinator.
pub mod readiness;
