// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! dwaar-log — structured request logging with batch writing.
//!
//! Provides [`RequestLog`] for capturing per-request metrics and
//! a batch writer pipeline for efficient I/O.

pub mod request_log;
pub mod writer;

pub use request_log::RequestLog;
pub use writer::{LogOutput, LogReceiver, LogSender, StdoutWriter, channel, run_writer, spawn_writer};
