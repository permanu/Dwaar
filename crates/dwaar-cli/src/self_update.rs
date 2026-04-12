// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Self-update: check releases.dwaar.dev, download, verify, replace.
//!
//! Uses the system `curl` to avoid pulling in an HTTP+TLS stack just
//! for this subcommand. The installer already depends on curl, so every
//! machine that installed Dwaar already has it.

use std::fmt::Write as FmtWrite;
use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, bail};

const BASE_URL: &str = "https://releases.dwaar.dev";
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Run the self-update flow. Returns a human-readable status message.
// Self-update is an interactive CLI subcommand; println! is correct here.
#[allow(clippy::disallowed_macros, clippy::print_stdout)]
pub(crate) fn run(force: bool) -> anyhow::Result<()> {
    let latest_tag = fetch_latest_version()?;
    let latest_version = latest_tag.strip_prefix('v').unwrap_or(&latest_tag);

    println!("Current version: {CURRENT_VERSION}");
    println!("Latest version:  {latest_version}");

    if latest_version == CURRENT_VERSION && !force {
        println!("\nAlready up to date.");
        return Ok(());
    }

    if latest_version == CURRENT_VERSION && force {
        println!("\nAlready up to date, but --force was specified. Re-downloading.");
    }

    let artifact = artifact_name();
    let download_url = format!("{BASE_URL}/{latest_tag}/{artifact}");
    let checksum_url = format!("{download_url}.sha256");

    println!("\nDownloading {artifact} {latest_tag}...");

    let tmp_dir = tempfile::tempdir().context("failed to create temp directory")?;
    let bin_path = tmp_dir.path().join(&artifact);
    let sha_path = tmp_dir.path().join(format!("{artifact}.sha256"));

    // Download binary + checksum
    curl_download(&download_url, &bin_path)?;
    curl_download(&checksum_url, &sha_path)?;

    // Verify checksum
    println!("Verifying SHA-256 checksum...");
    verify_sha256(&bin_path, &sha_path)?;
    println!("Checksum OK.");

    // Find current binary path
    let current_exe =
        std::env::current_exe().context("cannot determine current executable path")?;
    let install_path = fs::canonicalize(&current_exe).unwrap_or(current_exe);

    // Atomic replace: write to .new, rename over old
    let new_path = install_path.with_extension("new");
    fs::copy(&bin_path, &new_path)
        .with_context(|| format!("failed to copy new binary to {}", new_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&new_path, fs::Permissions::from_mode(0o755))
            .context("failed to set permissions on new binary")?;
    }

    fs::rename(&new_path, &install_path).with_context(|| {
        format!(
            "failed to replace {} — do you need sudo?",
            install_path.display()
        )
    })?;

    println!(
        "\ndwaar updated to {latest_version} at {}\nRestart the server to use the new version:\n  dwaar upgrade  (zero-downtime)\n  systemctl restart dwaar  (systemd)",
        install_path.display()
    );

    Ok(())
}

/// Fetch the latest version tag from releases.dwaar.dev/latest.
fn fetch_latest_version() -> anyhow::Result<String> {
    let output = Command::new("curl")
        .args(["-fsSL", &format!("{BASE_URL}/latest")])
        .output()
        .context("failed to run curl — is it installed?")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("failed to fetch latest version: {stderr}");
    }

    let version = String::from_utf8(output.stdout)
        .context("latest version response is not UTF-8")?
        .trim()
        .to_string();

    if version.is_empty() {
        bail!("releases.dwaar.dev/latest returned empty response");
    }

    Ok(version)
}

/// Download a URL to a local file via curl.
fn curl_download(url: &str, dest: &Path) -> anyhow::Result<()> {
    let output = Command::new("curl")
        .args(["-fSL", "--progress-bar", "-o"])
        .arg(dest)
        .arg(url)
        .status()
        .context("failed to run curl")?;

    if !output.success() {
        bail!("download failed: {url}");
    }
    Ok(())
}

/// Verify the SHA-256 checksum of `binary` against the content of `checksum_file`.
///
/// The checksum file is expected to be in the format produced by `sha256sum`:
/// `<hex>  <filename>\n`
fn verify_sha256(binary: &Path, checksum_file: &Path) -> anyhow::Result<()> {
    let expected_line =
        fs::read_to_string(checksum_file).context("failed to read checksum file")?;
    let expected_hash = expected_line
        .split_whitespace()
        .next()
        .context("checksum file is empty")?
        .to_lowercase();

    let binary_bytes = fs::read(binary).context("failed to read downloaded binary")?;

    let digest = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), &binary_bytes)
        .context("SHA-256 hash failed")?;
    let actual_hash = hex_encode(&digest);

    if actual_hash != expected_hash {
        bail!(
            "checksum mismatch!\n  expected: {expected_hash}\n  actual:   {actual_hash}\n\nThe download may be corrupted or tampered with."
        );
    }

    Ok(())
}

/// Hex-encode a byte slice (lowercase).
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{b:02x}").expect("fmt::Write to String is infallible");
    }
    s
}

/// Construct the artifact name for this platform (matches release workflow).
///
/// # Supported targets
///
/// | Artifact | Target | Notes |
/// |---|---|---|
/// | `dwaar-linux-amd64` | `x86_64-unknown-linux-gnu` | Primary production target |
/// | `dwaar-linux-arm64` | `aarch64-unknown-linux-gnu` | ARM servers (AWS Graviton, etc.) |
/// | `dwaar-darwin-arm64` | `aarch64-apple-darwin` | Apple Silicon Macs (M1+) |
///
/// # Unsupported targets
///
/// **`x86_64-apple-darwin` is not supported.** Apple has ended support for
/// Intel-based Macs (last model shipped 2020, macOS support dropped in macOS
/// 15). GitHub Actions' `macos-latest` runners are ARM-only since macOS 14,
/// making CI cross-compilation impractical. Users on Intel Macs should build
/// from source (`cargo build --release`) or run via Docker/Rosetta 2.
fn artifact_name() -> String {
    let os = if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "unknown"
    };

    let arch = if cfg!(target_arch = "x86_64") {
        if cfg!(target_os = "macos") {
            // Intel Macs are not a supported release target. If someone
            // compiles from source on an Intel Mac and runs self-update,
            // we'll look for dwaar-darwin-amd64 — which won't exist on
            // releases.dwaar.dev. self_update will exit cleanly with a
            // "download failed" message pointing them to build from source.
            "amd64"
        } else {
            "amd64"
        }
    } else if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "unknown"
    };

    format!("dwaar-{os}-{arch}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_name_is_valid() {
        let name = artifact_name();
        assert!(name.starts_with("dwaar-"), "unexpected: {name}");
        // Should be one of the 4 release targets
        let valid = [
            "dwaar-linux-amd64",
            "dwaar-linux-arm64",
            "dwaar-darwin-amd64",
            "dwaar-darwin-arm64",
        ];
        assert!(
            valid.contains(&name.as_str()),
            "artifact name '{name}' not in release matrix"
        );
    }

    #[test]
    fn hex_encode_works() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(hex_encode(&[0x00, 0xff]), "00ff");
    }

    #[test]
    fn current_version_is_set() {
        assert!(!CURRENT_VERSION.is_empty());
        // Should be semver-ish
        assert!(
            CURRENT_VERSION.contains('.'),
            "version should contain dots: {CURRENT_VERSION}"
        );
    }

    #[test]
    fn verify_sha256_valid() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let bin_path = dir.path().join("test-binary");
        let sha_path = dir.path().join("test-binary.sha256");

        let content = b"hello world";
        std::fs::write(&bin_path, content).expect("write bin");

        let digest =
            openssl::hash::hash(openssl::hash::MessageDigest::sha256(), content).expect("hash");
        let hex = hex_encode(&digest);
        std::fs::write(&sha_path, format!("{hex}  test-binary\n")).expect("write sha");

        verify_sha256(&bin_path, &sha_path).expect("should pass");
    }

    #[test]
    fn verify_sha256_mismatch() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let bin_path = dir.path().join("test-binary");
        let sha_path = dir.path().join("test-binary.sha256");

        std::fs::write(&bin_path, b"hello world").expect("write bin");
        std::fs::write(
            &sha_path,
            "0000000000000000000000000000000000000000000000000000000000000000  test-binary\n",
        )
        .expect("write sha");

        let result = verify_sha256(&bin_path, &sha_path);
        assert!(result.is_err(), "should fail on mismatch");
        let err = result
            .expect_err("verify_sha256 should fail on mismatch")
            .to_string();
        assert!(err.contains("checksum mismatch"), "error: {err}");
    }
}
