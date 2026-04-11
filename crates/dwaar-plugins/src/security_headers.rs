// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Security headers plugin — baseline defense against common web attacks.
//!
//! Adds HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy,
//! and a generic Server banner to every response. HSTS is only applied on
//! TLS connections to avoid locking out intentionally HTTP-only routes.
//!
//! ## Info-leak header stripping (M-20)
//!
//! Upstream applications routinely emit framework/version banners such as
//! `X-Powered-By: PHP/7.4` or `X-AspNet-Version: 4.0.30319`. Those make
//! version fingerprinting trivial for an attacker, so by default this plugin
//! strips a small curated list of known leaky headers before installing its
//! own banner. The list is conservative and only matches headers that serve
//! no user-facing purpose. Set `strip_leaky_headers = false` to disable.
//!
//! ## CSP default policy (M-20)
//!
//! When `content_security_policy` is `None` we do NOT inject a default CSP.
//! The v0.2.1 changelog promised CSP would remain opt-in for backwards
//! compatibility — shipping a default now would break existing deployments
//! that rely on inline scripts, third-party assets, or eval()-based clients.
//! Operators who want CSP enable it explicitly via the `csp` directive.

use pingora_http::ResponseHeader;

use crate::plugin::{DwaarPlugin, PluginAction, PluginCtx};

/// Upstream headers that leak implementation details (framework, runtime,
/// server version) and serve no legitimate browser purpose. Removing them
/// is cheap and denies attackers a fingerprinting channel.
///
/// `Server` is in this list too: we install our own `Server: Dwaar` banner
/// immediately after stripping, so the upstream value is always replaced.
const LEAKY_HEADERS: &[&str] = &[
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Runtime",
    "X-Generator",
    "Server",
];

/// Default security headers applied to every proxied response.
///
/// Priority 100 — runs after feature plugins (bot, rate limit) but the
/// exact ordering doesn't matter since it only modifies response headers.
#[derive(Debug)]
pub struct SecurityHeadersPlugin {
    pub content_security_policy: Option<String>,
    pub content_security_policy_report_only: Option<String>,
    /// When `true` (default), the plugin removes known info-leak headers
    /// (see [`LEAKY_HEADERS`]) from the upstream response before installing
    /// its own banner. Disable only if you have a specific reason to keep
    /// framework/version headers on the wire.
    pub strip_leaky_headers: bool,
}

impl Default for SecurityHeadersPlugin {
    fn default() -> Self {
        Self {
            content_security_policy: None,
            content_security_policy_report_only: None,
            strip_leaky_headers: true,
        }
    }
}

impl SecurityHeadersPlugin {
    pub fn new() -> Self {
        Self::default()
    }
}

impl DwaarPlugin for SecurityHeadersPlugin {
    fn name(&self) -> &'static str {
        "security-headers"
    }

    fn priority(&self) -> u16 {
        100
    }

    fn on_response(&self, resp: &mut ResponseHeader, ctx: &mut PluginCtx) -> PluginAction {
        // Strip upstream info-leak headers first (M-20). Must happen before
        // any insert_header() call that intends to replace them — otherwise
        // upstream banners like X-Powered-By would ride through untouched.
        // Uses Pingora's wrapper API per Guardrail §7.
        if self.strip_leaky_headers {
            for name in LEAKY_HEADERS {
                resp.remove_header(*name);
            }
        }

        // HSTS only on TLS — emitting on plaintext could lock browsers out
        // of intentionally HTTP-only routes if the response gets cached.
        if ctx.is_tls {
            resp.insert_header(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            )
            .expect("static header value");
        }

        // Prevent MIME-sniffing (uploaded .txt executed as JS)
        resp.insert_header("X-Content-Type-Options", "nosniff")
            .expect("static header value");

        // Block clickjacking via iframe embedding
        resp.insert_header("X-Frame-Options", "SAMEORIGIN")
            .expect("static header value");

        // Limit referer leakage to third parties
        resp.insert_header("Referrer-Policy", "strict-origin-when-cross-origin")
            .expect("static header value");

        // Replace upstream server banner to avoid fingerprinting
        resp.insert_header("Server", "Dwaar")
            .expect("static header value");

        if let Some(ref csp) = self.content_security_policy {
            let _ = resp.insert_header("Content-Security-Policy", csp.as_str());
        }
        if let Some(ref csp_ro) = self.content_security_policy_report_only {
            let _ = resp.insert_header("Content-Security-Policy-Report-Only", csp_ro.as_str());
        }

        PluginAction::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::PluginCtx;

    fn make_ctx(is_tls: bool) -> PluginCtx {
        PluginCtx {
            is_tls,
            ..PluginCtx::default()
        }
    }

    #[test]
    fn adds_security_headers_on_tls() {
        let plugin = SecurityHeadersPlugin::new();
        let mut resp = ResponseHeader::build(200, Some(5)).expect("valid");
        let mut ctx = make_ctx(true);

        plugin.on_response(&mut resp, &mut ctx);

        assert!(resp.headers.get("Strict-Transport-Security").is_some());
        assert_eq!(
            resp.headers
                .get("X-Content-Type-Options")
                .expect("X-Content-Type-Options header"),
            "nosniff"
        );
        assert_eq!(
            resp.headers
                .get("X-Frame-Options")
                .expect("X-Frame-Options header"),
            "SAMEORIGIN"
        );
        assert_eq!(resp.headers.get("Server").expect("Server header"), "Dwaar");
    }

    #[test]
    fn skips_hsts_on_plaintext() {
        let plugin = SecurityHeadersPlugin::new();
        let mut resp = ResponseHeader::build(200, Some(5)).expect("valid");
        let mut ctx = make_ctx(false);

        plugin.on_response(&mut resp, &mut ctx);

        assert!(resp.headers.get("Strict-Transport-Security").is_none());
        // Other headers still present
        assert_eq!(
            resp.headers
                .get("X-Content-Type-Options")
                .expect("X-Content-Type-Options header"),
            "nosniff"
        );
    }

    #[test]
    fn priority_is_100() {
        assert_eq!(SecurityHeadersPlugin::new().priority(), 100);
    }

    #[test]
    fn strips_x_powered_by_and_other_info_leak_headers() {
        // M-20: upstream banners must not ride through to the client.
        let plugin = SecurityHeadersPlugin::new();
        let mut resp = ResponseHeader::build(200, Some(8)).expect("valid");
        // Simulate upstream leaking framework/version info.
        resp.insert_header("X-Powered-By", "PHP/7.4")
            .expect("valid");
        resp.insert_header("X-AspNet-Version", "4.0.30319")
            .expect("valid");
        resp.insert_header("X-AspNetMvc-Version", "5.2")
            .expect("valid");
        resp.insert_header("X-Runtime", "0.012345").expect("valid");
        resp.insert_header("X-Generator", "Drupal 7 (https://www.drupal.org)")
            .expect("valid");
        // A legitimate app header that must NOT be stripped.
        resp.insert_header("X-Custom-Header", "keep-me")
            .expect("valid");

        let mut ctx = make_ctx(false);
        plugin.on_response(&mut resp, &mut ctx);

        assert!(resp.headers.get("X-Powered-By").is_none());
        assert!(resp.headers.get("X-AspNet-Version").is_none());
        assert!(resp.headers.get("X-AspNetMvc-Version").is_none());
        assert!(resp.headers.get("X-Runtime").is_none());
        assert!(resp.headers.get("X-Generator").is_none());
        // Server is stripped but then re-set to our own banner.
        assert_eq!(resp.headers.get("Server").expect("server header"), "Dwaar");
        // Non-leaky custom headers survive.
        assert_eq!(
            resp.headers.get("X-Custom-Header").expect("custom"),
            "keep-me"
        );
    }

    #[test]
    fn leaky_header_stripping_can_be_disabled() {
        let mut plugin = SecurityHeadersPlugin::new();
        plugin.strip_leaky_headers = false;
        let mut resp = ResponseHeader::build(200, Some(0)).expect("valid");
        resp.insert_header("X-Powered-By", "Express")
            .expect("valid");

        let mut ctx = make_ctx(false);
        plugin.on_response(&mut resp, &mut ctx);

        // With stripping off the upstream banner rides through untouched.
        assert_eq!(
            resp.headers.get("X-Powered-By").expect("x-powered-by"),
            "Express"
        );
    }

    #[test]
    fn csp_is_opt_in_no_default_injected() {
        // M-20 design note: CSP remains opt-in for backwards compatibility.
        // Verify that the default plugin does not inject any CSP header.
        let plugin = SecurityHeadersPlugin::new();
        let mut resp = ResponseHeader::build(200, Some(0)).expect("valid");
        let mut ctx = make_ctx(true);
        plugin.on_response(&mut resp, &mut ctx);
        assert!(resp.headers.get("Content-Security-Policy").is_none());
        assert!(
            resp.headers
                .get("Content-Security-Policy-Report-Only")
                .is_none()
        );
    }
}
