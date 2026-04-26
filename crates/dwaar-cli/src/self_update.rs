// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Self-update: check GitHub Releases, download, verify, replace.
//!
//! All HTTP is done in-process via `reqwest` with `rustls` — curl is no
//! longer in the trust path, so a compromised `curl` binary cannot intercept
//! the download or inject a malicious binary. Closes issue #147.

use std::fmt::Write as FmtWrite;
use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, bail};
use subtle::ConstantTimeEq;

/// GitHub Releases base URL for download assets. The URL format for a
/// specific asset is: `{BASE_URL}/v{version}/{artifact}`.
///
/// Previously pointed to `releases.dwaar.dev` (Cloudflare R2). Migrated
/// to GitHub Releases so the project has a single authoritative asset host
/// and the R2 bucket can be decommissioned.
const BASE_URL: &str = "https://github.com/permanu/Dwaar/releases/download";

/// GitHub API endpoint to resolve the latest release tag.
const LATEST_API: &str = "https://api.github.com/repos/permanu/Dwaar/releases/latest";

const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Minimal GitHub Release object for deserialization.
///
/// The GitHub API returns many fields; we only care about `tag_name`.
/// `serde_json` ignores extra fields by default, so this struct remains
/// robust to API changes.
#[derive(serde::Deserialize)]
struct GhRelease {
    tag_name: String,
}

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

/// Build the shared HTTP client used by self-update operations.
///
/// Reusing a single client across calls is idiomatic reqwest and avoids
/// redundant TLS handshakes. The 30-second timeout guards against hung
/// connections during background provisioning (Guardrail #29).
fn build_client() -> anyhow::Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .user_agent(concat!("dwaar-self-update/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(30))
        .build()
        .context("failed to build HTTP client")
}

/// Fetch the latest release tag from the GitHub API.
///
/// Primary path: calls the GitHub Releases JSON API and parses `tag_name`.
/// Fallback: follows the `/releases/latest` redirect and extracts the tag from
/// the final URL — this mirrors what curl's `%{url_effective}` trick did, but
/// entirely in-process via reqwest so curl is not in the trust path (#147).
fn fetch_latest_version() -> anyhow::Result<String> {
    let client = build_client()?;

    // Primary: GitHub REST API returns JSON with `tag_name`.
    let resp = client
        .get(LATEST_API)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .context("GitHub API request failed")?;

    if resp.status().is_success() {
        let body = resp.text().context("GitHub API response is not UTF-8")?;
        if let Ok(release) = serde_json::from_str::<GhRelease>(&body)
            && !release.tag_name.is_empty()
        {
            return Ok(release.tag_name);
        }
    }

    // Fallback: follow the /releases/latest redirect; reqwest follows redirects
    // by default and exposes the final URL via `response.url()`.
    // GitHub redirects /releases/latest → /releases/tag/vX.Y.Z.
    let resp = client
        .get("https://github.com/permanu/Dwaar/releases/latest")
        .send()
        .context("failed to resolve latest release via redirect")?;

    let tag = resp
        .url()
        .path_segments()
        .and_then(|mut segs| segs.next_back())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .context("could not extract tag from GitHub redirect URL")?;

    Ok(tag)
}

/// Download a URL to a local file in-process via reqwest.
///
/// Replaces the previous `curl -fSL -o <dest> <url>` shell-out (#147).
/// reqwest follows redirects by default (matching curl's `-L`). Writing
/// directly to the destination file avoids buffering the entire binary in
/// memory, which matters for large release artifacts.
fn curl_download(url: &str, dest: &Path) -> anyhow::Result<()> {
    let client = build_client()?;
    let mut resp = client
        .get(url)
        .send()
        .with_context(|| format!("HTTP GET failed: {url}"))?;

    if !resp.status().is_success() {
        bail!("download failed ({}): {url}", resp.status());
    }

    let mut file =
        fs::File::create(dest).with_context(|| format!("failed to create {}", dest.display()))?;

    resp.copy_to(&mut file)
        .with_context(|| format!("failed to write download to {}", dest.display()))?;

    Ok(())
}

/// Constant-time hex string comparison.
///
/// Per Guardrail #30 and issue #149, compare hex hashes using constant-time
/// comparison to mitigate timing side-channels on the expected hash. While
/// this is a download integrity check (not a secret), constant-time comparison
/// is consistent with the rest of the codebase and defends against weak local
/// attackers who might measure timing on the comparison loop.
fn constant_time_eq_hex(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
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

    if !constant_time_eq_hex(&actual_hash, &expected_hash) {
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

    #[test]
    fn sha256_compare_rejects_mismatch() {
        // Constant-time compare must still reject as not-equal when
        // hashes differ — issue #149 guard against the migration breaking
        // the actual mismatch path.
        let a = "abc123";
        let b = "abc124";
        assert!(!constant_time_eq_hex(a, b));
    }

    #[test]
    fn sha256_compare_accepts_match() {
        let a = "deadbeef";
        assert!(constant_time_eq_hex(a, a));
    }

    #[test]
    fn parse_release_tag_from_json() {
        let json = r#"{"tag_name":"v0.3.10","name":"v0.3.10","draft":false}"#;
        let parsed: GhRelease = serde_json::from_str(json).expect("valid JSON");
        assert_eq!(parsed.tag_name, "v0.3.10");
    }

    #[test]
    fn parse_release_tag_ignores_extra_fields() {
        let json = r#"{"tag_name":"v1.2.3","html_url":"https://...","assets":[]}"#;
        let parsed: GhRelease = serde_json::from_str(json).expect("valid JSON");
        assert_eq!(parsed.tag_name, "v1.2.3");
    }

    #[test]
    fn http_client_builds() {
        // Smoke: the migrated reqwest client builder constructs without
        // panicking. No network calls are made here — integration tests
        // cover wire-level behavior. Issue #147: curl shell-out replaced.
        let client = reqwest::blocking::Client::builder()
            .user_agent(concat!("dwaar-self-update/", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(30))
            .build();
        assert!(client.is_ok(), "blocking HTTP client failed to build");
    }
}
