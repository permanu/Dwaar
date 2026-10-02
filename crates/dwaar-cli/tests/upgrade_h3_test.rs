// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1

//! HTTP/3 upgrade rejection must happen before listener transfer or worker fork.
use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn configured_h3_rejects_direct_upgrade_before_bootstrap() {
    check_rejection(false);
}

#[test]
fn configured_h3_rejects_environment_upgrade_before_bootstrap() {
    check_rejection(true);
}

fn check_rejection(environment_upgrade: bool) {
    let dir = tempfile::tempdir().expect("private configuration");
    let config = dir.path().join("Dwaarfile");
    std::fs::write(
        &config,
        "{\n servers {\n h3 on\n }\n}\nlocalhost {\n tls off\n reverse_proxy 127.0.0.1:1\n}\n",
    )
    .expect("write configuration");
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("dwaar"));
    command.arg("--config").arg(config).arg("--test");
    command.env_remove("DWAAR_UPGRADE_FROM");
    if environment_upgrade {
        command.env("DWAAR_UPGRADE_FROM", "1");
    } else {
        command.arg("--upgrade");
    }
    command.assert().failure().stderr(predicate::str::contains(
        "HTTP/3 graceful upgrade is unsupported",
    ));
}

#[test]
fn http_only_upgrade_validation_remains_supported() {
    let dir = tempfile::tempdir().expect("private configuration");
    let config = dir.path().join("Dwaarfile");
    std::fs::write(
        &config,
        "localhost {\n tls off\n reverse_proxy 127.0.0.1:1\n}\n",
    )
    .expect("write configuration");
    Command::new(assert_cmd::cargo::cargo_bin!("dwaar"))
        .arg("--config")
        .arg(config)
        .arg("--test")
        .arg("--upgrade")
        .env_remove("DWAAR_UPGRADE_FROM")
        .assert()
        .success();
}
