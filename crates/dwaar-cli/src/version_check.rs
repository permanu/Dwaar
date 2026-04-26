// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Shared GitHub Releases version check helper.
//!
//! Both `self_update` and `auto_update` need to resolve the latest release tag.
//! Rather than maintaining two separate implementations that can drift apart
//! (as happened before issue #176), this module provides the single canonical
//! function that both callers delegate to.
//!
//! The implementation prefers the GitHub REST API (JSON response with a
//! `tag_name` field) over the older redirect trick. The redirect fallback is
//! retained so that a transient API outage does not block updates entirely.

use std::time::Duration;

use anyhow::Context;

/// GitHub REST API endpoint for the latest release.
const LATEST_API: &str = "https://api.github.com/repos/permanu/Dwaar/releases/latest";

/// GitHub HTML releases page — following the redirect reveals the tag in the URL.
const LATEST_HTML: &str = "https://github.com/permanu/Dwaar/releases/latest";

/// Minimal GitHub Release object for deserialization.
///
/// The GitHub API returns many fields; we only care about `tag_name`.
/// `serde_json` ignores extra fields by default, so this struct stays robust
/// to API changes without any maintenance burden.
#[derive(serde::Deserialize)]
pub(crate) struct GhRelease {
    pub(crate) tag_name: String,
}

/// Build a reusable blocking HTTP client for GitHub requests.
///
/// Centralised here so both the version check and the download path share the
/// same TLS and timeout configuration. The 30-second timeout guards against
/// hung connections during background provisioning (Guardrail #29).
pub(crate) fn build_http_client() -> anyhow::Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .user_agent(concat!("dwaar/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(30))
        .build()
        .context("failed to build HTTP client")
}

/// Fetch the latest release tag from GitHub.
///
/// Primary path: calls the GitHub Releases JSON API and parses `tag_name`.
/// Fallback: follows the `/releases/latest` redirect and extracts the tag from
/// the final URL — equivalent to curl's `%{url_effective}` trick, but entirely
/// in-process via reqwest so curl is not in the trust path (issue #147).
///
/// Returns the raw tag string (e.g. `"v0.3.7"`). Callers that want a semver
/// without the leading `v` should strip it themselves.
pub(crate) fn fetch_latest_version() -> anyhow::Result<String> {
    let client = build_http_client()?;

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
        .get(LATEST_HTML)
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn http_client_builds_in_canonical_helper() {
        // Smoke test: the canonical client builder constructs without panicking.
        // No network calls — integration tests cover wire-level behaviour.
        build_http_client().expect("HTTP client should build");
    }

    /// Live network test — skipped by default; run with
    /// `cargo test -p dwaar-cli -- --ignored fetch_latest_version_network`.
    #[test]
    #[ignore = "requires live network; run with --ignored"]
    fn fetch_latest_version_network() {
        let tag = fetch_latest_version().expect("should return a version tag");
        assert!(tag.starts_with('v'), "tag should start with 'v': {tag}");
    }
}
