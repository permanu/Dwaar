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
//!
//! Version resolution is delegated to `version_check::fetch_latest_version`
//! (issue #176) so that `auto_update` uses the same JSON-then-redirect logic.

use std::fmt::Write as FmtWrite;
use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, bail};
use subtle::ConstantTimeEq;

/// GitHub Releases base URL for download assets. The URL format for a
/// specific asset is: `{BASE_URL}/v{version}/{artifact}`.
///
/// Previously pointed to `releases.dwaar.dev` (Cloudflare R2). Migrated
/// to GitHub Releases so the project has a single authoritative asset host
/// and the R2 bucket can be decommissioned.
const BASE_URL: &str = "https://github.com/permanu/Dwaar/releases/download";

const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const KEYLESS_CERTIFICATE_IDENTITY_REGEXP: &str =
    "^https://github\\.com/permanu/Dwaar/\\.github/workflows/release\\.yml@.*";
const KEYLESS_CERTIFICATE_OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// Run the self-update flow. Returns a human-readable status message.
// Self-update is an interactive CLI subcommand; println! is correct here.
#[allow(clippy::disallowed_macros, clippy::print_stdout)]
pub(crate) fn run(force: bool) -> anyhow::Result<()> {
    let latest_tag = crate::version_check::fetch_latest_version()?;
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
    let bundle_url = format!("{download_url}.bundle");
    let sig_url = format!("{download_url}.sig");
    let cert_url = format!("{download_url}.cert");

    println!("\nDownloading {artifact} {latest_tag}...");

    let tmp_dir = tempfile::tempdir().context("failed to create temp directory")?;
    let bin_path = tmp_dir.path().join(&artifact);
    let sha_path = tmp_dir.path().join(format!("{artifact}.sha256"));
    let bundle_path = tmp_dir.path().join(format!("{artifact}.bundle"));
    let sig_path = tmp_dir.path().join(format!("{artifact}.sig"));
    let cert_path = tmp_dir.path().join(format!("{artifact}.cert"));
    let pubkey_path = tmp_dir.path().join("dwaar-release-authority.pub");

    // Download binary + checksum
    curl_download(&download_url, &bin_path)?;
    curl_download(&checksum_url, &sha_path)?;

    // Verify checksum
    println!("Verifying SHA-256 checksum...");
    verify_sha256(&bin_path, &sha_path)?;
    println!("Checksum OK.");

    let release_key = configured_cosign_public_key()?;
    let signature_policy = select_signature_policy(
        http_exists(&bundle_url)?,
        http_exists(&sig_url)?,
        http_exists(&cert_url)?,
        release_key,
    )?;

    match &signature_policy {
        SignaturePolicy::ReleaseKey { key } => {
            curl_download(&bundle_url, &bundle_path)?;
            if let CosignPublicKey::Url(url) = key {
                curl_download(url, &pubkey_path)?;
            }
        }
        SignaturePolicy::KeylessBundle => {
            curl_download(&bundle_url, &bundle_path)?;
        }
        SignaturePolicy::KeylessCertificate => {
            curl_download(&sig_url, &sig_path)?;
            curl_download(&cert_url, &cert_path)?;
        }
    }

    println!("Verifying cosign signature...");
    verify_cosign_signature(
        &bin_path,
        &signature_policy,
        &bundle_path,
        &sig_path,
        &cert_path,
        &pubkey_path,
    )?;
    println!(
        "Cosign signature OK ({}).",
        signature_policy.trust_description()
    );

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

/// Download a URL to a local file in-process via reqwest.
///
/// Replaces the previous `curl -fSL -o <dest> <url>` shell-out (#147).
/// reqwest follows redirects by default (matching curl's `-L`). Writing
/// directly to the destination file avoids buffering the entire binary in
/// memory, which matters for large release artifacts.
fn curl_download(url: &str, dest: &Path) -> anyhow::Result<()> {
    let client = crate::version_check::build_http_client()?;
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

fn http_exists(url: &str) -> anyhow::Result<bool> {
    let client = crate::version_check::build_http_client()?;
    let resp = client
        .head(url)
        .send()
        .with_context(|| format!("HTTP HEAD failed: {url}"))?;

    Ok(resp.status().is_success())
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CosignPublicKey {
    Path(String),
    Url(String),
}

impl CosignPublicKey {
    fn materialized_path<'a>(&'a self, downloaded_path: &'a Path) -> &'a Path {
        match self {
            Self::Path(path) => Path::new(path),
            Self::Url(_) => downloaded_path,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SignaturePolicy {
    /// Enterprise / BYOS: verify the bundle against an explicitly configured
    /// public key (DWAAR_COSIGN_PUBKEY[_URL]).
    ReleaseKey { key: CosignPublicKey },
    /// Default public path: self-contained keyless cosign bundle signed by the
    /// release.yml GitHub Actions workflow via Fulcio OIDC. No key needed.
    KeylessBundle,
    /// Older releases that published split `.sig` + `.cert` instead of a bundle.
    KeylessCertificate,
}

impl SignaturePolicy {
    fn trust_description(&self) -> &'static str {
        match self {
            Self::ReleaseKey { .. } => "Permanu/Dwaar release-authority key",
            Self::KeylessBundle => "GitHub Actions keyless OIDC",
            Self::KeylessCertificate => "GitHub Actions keyless OIDC (split cert)",
        }
    }
}

fn configured_cosign_public_key() -> anyhow::Result<Option<CosignPublicKey>> {
    let path = non_empty_env("DWAAR_COSIGN_PUBKEY");
    let url = non_empty_env("DWAAR_COSIGN_PUBKEY_URL");

    match (path, url) {
        (Some(_), Some(_)) => {
            bail!("set only one of DWAAR_COSIGN_PUBKEY or DWAAR_COSIGN_PUBKEY_URL")
        }
        (Some(path), None) => Ok(Some(CosignPublicKey::Path(path))),
        (None, Some(url)) => {
            if !url.starts_with("https://") {
                bail!("DWAAR_COSIGN_PUBKEY_URL must be an https:// URL");
            }
            Ok(Some(CosignPublicKey::Url(url)))
        }
        (None, None) => Ok(None),
    }
}

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn select_signature_policy(
    has_bundle: bool,
    has_sig: bool,
    has_cert: bool,
    release_key: Option<CosignPublicKey>,
) -> anyhow::Result<SignaturePolicy> {
    if let Some(key) = release_key {
        if !has_bundle {
            bail!(
                "configured release key requires a cosign bundle; refusing keyless fallback for key-based verification"
            );
        }
        return Ok(SignaturePolicy::ReleaseKey { key });
    }

    // A `.bundle` alone is the normal keyless case: the Sigstore bundle is
    // self-contained (it embeds the Fulcio certificate and transparency-log
    // proof), so it verifies against the workflow identity with no public key.
    // The `.sig`/`.cert` siblings are redundant and no longer required.
    if has_bundle {
        return Ok(SignaturePolicy::KeylessBundle);
    }

    if has_sig && has_cert {
        return Ok(SignaturePolicy::KeylessCertificate);
    }

    bail!("no signature artefacts found; refusing to self-update an unverifiable Dwaar binary");
}

fn verify_cosign_signature(
    binary: &Path,
    policy: &SignaturePolicy,
    bundle: &Path,
    signature: &Path,
    certificate: &Path,
    downloaded_pubkey: &Path,
) -> anyhow::Result<()> {
    let mut cmd = Command::new("cosign");
    cmd.arg("verify-blob").arg(binary);

    match policy {
        SignaturePolicy::ReleaseKey { key } => {
            cmd.arg("--bundle")
                .arg(bundle)
                .arg("--key")
                .arg(key.materialized_path(downloaded_pubkey));
        }
        SignaturePolicy::KeylessBundle => {
            cmd.arg("--bundle")
                .arg(bundle)
                .arg("--certificate-identity-regexp")
                .arg(KEYLESS_CERTIFICATE_IDENTITY_REGEXP)
                .arg("--certificate-oidc-issuer")
                .arg(KEYLESS_CERTIFICATE_OIDC_ISSUER);
        }
        SignaturePolicy::KeylessCertificate => {
            cmd.arg("--certificate")
                .arg(certificate)
                .arg("--signature")
                .arg(signature)
                .arg("--certificate-identity-regexp")
                .arg(KEYLESS_CERTIFICATE_IDENTITY_REGEXP)
                .arg("--certificate-oidc-issuer")
                .arg(KEYLESS_CERTIFICATE_OIDC_ISSUER);
        }
    }

    let output = cmd.output().context(
        "cosign is required for self-update verification; install cosign or use install.sh with manual verification",
    )?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!(
            "cosign verification failed for {}.\nstdout:\n{}\nstderr:\n{}",
            policy.trust_description(),
            stdout.trim(),
            stderr.trim()
        );
    }

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
    fn http_client_builds() {
        // Smoke: delegates to the shared client builder in version_check.
        // No network calls are made here — integration tests cover
        // wire-level behaviour. Issue #147: curl shell-out replaced.
        // Issue #176: builder is now shared across self_update and auto_update.
        crate::version_check::build_http_client().expect("blocking HTTP client should build");
    }

    #[test]
    fn signature_policy_prefers_configured_release_key_bundle_over_legacy() {
        let key = CosignPublicKey::Path("release.pub".into());

        let policy = select_signature_policy(true, true, true, Some(key))
            .expect("configured public key with bundle should select key verification");

        assert_eq!(
            policy,
            SignaturePolicy::ReleaseKey {
                key: CosignPublicKey::Path("release.pub".into())
            }
        );
    }

    #[test]
    fn signature_policy_uses_keyless_bundle_without_release_key() {
        let policy = select_signature_policy(true, true, true, None)
            .expect("keyless bundle should be accepted without a configured key");

        assert_eq!(policy, SignaturePolicy::KeylessBundle);
    }

    #[test]
    fn signature_policy_accepts_bundle_only_release_keylessly() {
        // Regression: v0.3.23 shipped a `.bundle` with no `.sig`/`.cert` and no
        // configured key. That is the normal keyless case and must verify
        // keylessly, NOT demand a (nonexistent) pinned public key.
        let policy = select_signature_policy(true, false, false, None)
            .expect("bundle-only release must verify keylessly");

        assert_eq!(policy, SignaturePolicy::KeylessBundle);
    }

    #[test]
    fn signature_policy_requires_signature_for_release_key() {
        let key = CosignPublicKey::Url("https://keys.example.invalid/dwaar.pub".to_string());

        let err = select_signature_policy(false, true, true, Some(key))
            .expect_err("configured release key must not fall back without a bundle");

        assert!(
            err.to_string().contains("configured release key"),
            "error: {err}"
        );
    }

    #[test]
    fn signature_policy_uses_split_certificate_when_bundle_missing() {
        let policy = select_signature_policy(false, true, true, None)
            .expect("split .sig/.cert should remain supported");

        assert_eq!(policy, SignaturePolicy::KeylessCertificate);
    }
}
