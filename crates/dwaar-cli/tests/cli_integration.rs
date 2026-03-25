// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Integration tests for Dwaar CLI and server bootstrap.
//!
//! These tests run the actual `dwaar` binary as a subprocess
//! and verify its behavior from the outside.

// Test-only: we need unsafe for libc::kill, thread::sleep for waiting, and u32→i32 cast for PID
#![allow(unsafe_code, clippy::cast_possible_wrap)]

use assert_cmd::Command;
use predicates::prelude::*;
use std::time::Duration;

/// Helper to get a Command for the dwaar binary.
fn dwaar() -> Command {
    Command::cargo_bin("dwaar").expect("dwaar binary should exist")
}

#[test]
fn version_subcommand_prints_version() {
    dwaar()
        .arg("version")
        .assert()
        .success()
        .stderr(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn help_flag_shows_usage() {
    dwaar()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "The gateway for your applications",
        ));
}

#[test]
fn test_flag_exits_successfully() {
    dwaar().arg("--test").assert().success();
}

#[test]
fn custom_config_path_accepted() {
    // --test with custom config should still exit cleanly
    // (config validation not yet implemented, just verifies flag is accepted)
    dwaar()
        .args(["--config", "/tmp/nonexistent.conf", "--test"])
        .assert()
        .success();
}

#[test]
fn unknown_flag_fails() {
    dwaar().arg("--nonexistent-flag").assert().failure();
}

#[test]
fn server_shuts_down_on_sigterm() {
    use std::process::Command as StdCommand;

    // Start dwaar as a subprocess (it will block in run_forever)
    let mut child = StdCommand::new(env!("CARGO_BIN_EXE_dwaar"))
        .spawn()
        .expect("failed to start dwaar");

    // Give the server time to bootstrap
    std::thread::sleep(Duration::from_secs(2));

    // Send SIGTERM
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }

    // Wait for exit with timeout
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => {
                // Process exited — success
                return;
            }
            Ok(None) => {
                if start.elapsed() > Duration::from_secs(5) {
                    child.kill().ok();
                    panic!("dwaar did not shut down within 5 seconds of SIGTERM");
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                panic!("error waiting for dwaar process: {e}");
            }
        }
    }
}
