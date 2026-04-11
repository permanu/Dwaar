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

use pingora_http::ResponseHeader;

use crate::plugin::{DwaarPlugin, PluginAction, PluginCtx};

/// Default security headers applied to every proxied response.
///
/// Priority 100 — runs after feature plugins (bot, rate limit) but the
/// exact ordering doesn't matter since it only modifies response headers.
#[derive(Debug, Default)]
pub struct SecurityHeadersPlugin {
    pub content_security_policy: Option<String>,
    pub content_security_policy_report_only: Option<String>,
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
}
