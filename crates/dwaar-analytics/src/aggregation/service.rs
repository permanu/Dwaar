// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Background service that consumes beacon and request-log channels,
//! updating per-domain `DomainMetrics` in a shared `DashMap`.
//!
//! Implemented in ISSUE-028 Task 7.
