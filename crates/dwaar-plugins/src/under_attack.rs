// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Under Attack Mode plugin — JS proof-of-work challenge for L7 `DDoS` mitigation.
//!
//! When enabled for a route, unverified clients receive an interstitial HTML page
//! containing a JavaScript proof-of-work challenge. Browsers solve the challenge
//! (SHA-256 hash with leading zeros), submit the solution, and receive a signed
//! HMAC-SHA256 clearance cookie (`_dwaar_clearance`). Subsequent requests with
//! a valid cookie pass through to the upstream.
//!
//! Non-JS clients (curl, bots, scrapers) can never solve the challenge and never
//! reach the upstream — they're permanently stuck on the challenge page.
//!
//! ## Cookie format
//!
//! `{timestamp_hex}.{hmac_hex}`
//!
//! Where HMAC = HMAC-SHA256(timestamp_bytes || `client_ip_bytes`, `secret_key`).
//!
//! ## Challenge flow
//!
//! 1. GET without valid cookie → 200 + challenge HTML (JS computes `PoW`)
//! 2. GET with `_dwaar_solved=1` query param + valid `PoW` → 302 + Set-Cookie
//! 3. GET with valid `_dwaar_clearance` cookie → Continue (pass to upstream)

use std::fmt;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use hmac::{Hmac, Mac};
use pingora_http::RequestHeader;
use sha2::Sha256;

use crate::plugin::{DwaarPlugin, PluginAction, PluginCtx, PluginResponse};

type HmacSha256 = Hmac<Sha256>;

/// How many leading zero bits the `PoW` hash must have.
/// 20 bits ≈ 1M iterations ≈ 200ms on a modern browser.
const POW_DIFFICULTY: u32 = 20;

/// Default cookie TTL: 1 hour.
const DEFAULT_TTL_SECS: u64 = 3600;

/// Cookie name for the clearance token.
const CLEARANCE_COOKIE: &str = "_dwaar_clearance";

/// Query parameter indicating the browser solved the challenge.
const SOLVED_PARAM: &str = "_dwaar_solved";

/// Query parameter carrying the nonce solution.
const NONCE_PARAM: &str = "_dwaar_nonce";

/// Query parameter carrying the challenge string.
const CHALLENGE_PARAM: &str = "_dwaar_challenge";

/// Under Attack Mode plugin.
///
/// Priority 15 — runs after bot detection (10) but before rate limiting (20).
/// This ordering means detected bots get flagged before the challenge check,
/// and rate limiting still applies to challenge page requests.
pub struct UnderAttackPlugin {
    secret: Vec<u8>,
    ttl_secs: u64,
}

impl UnderAttackPlugin {
    /// Create with a secret key for HMAC signing.
    pub fn new(secret: Vec<u8>) -> Self {
        Self {
            secret,
            ttl_secs: DEFAULT_TTL_SECS,
        }
    }

    /// Create with a custom TTL for clearance cookies.
    pub fn with_ttl(secret: Vec<u8>, ttl_secs: u64) -> Self {
        Self { secret, ttl_secs }
    }

    /// Generate a deterministic challenge from the client's IP and a time window.
    /// The time window rounds to 5-minute buckets so the challenge stays valid
    /// for a reasonable period without server-side state.
    fn generate_challenge(&self, ip: IpAddr) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_secs();
        // 5-minute window
        let window = now / 300;

        let mut mac =
            HmacSha256::new_from_slice(&self.secret).expect("HMAC accepts any key length");
        mac.update(&window.to_be_bytes());
        mac.update(ip_bytes(ip).as_slice());
        hex::encode(mac.finalize().into_bytes())
    }

    /// Verify a challenge + nonce pair: the SHA-256 hash of challenge||nonce
    /// must have `POW_DIFFICULTY` leading zero bits.
    fn verify_pow(challenge: &str, nonce: &str) -> bool {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(challenge.as_bytes());
        hasher.update(nonce.as_bytes());
        let hash = hasher.finalize();
        leading_zero_bits(&hash) >= POW_DIFFICULTY
    }

    /// Sign a clearance cookie for this IP at the current time.
    fn sign_cookie(&self, ip: IpAddr) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_secs();
        let timestamp_hex = format!("{now:x}");

        let mut mac =
            HmacSha256::new_from_slice(&self.secret).expect("HMAC accepts any key length");
        mac.update(&now.to_be_bytes());
        mac.update(ip_bytes(ip).as_slice());
        let hmac_hex = hex::encode(mac.finalize().into_bytes());

        format!("{timestamp_hex}.{hmac_hex}")
    }

    /// Verify a clearance cookie: check HMAC and expiry.
    fn verify_cookie(&self, cookie_value: &str, ip: IpAddr) -> bool {
        let Some((timestamp_hex, hmac_hex)) = cookie_value.split_once('.') else {
            return false;
        };

        let Ok(timestamp) = u64::from_str_radix(timestamp_hex, 16) else {
            return false;
        };

        // Check expiry
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_secs();
        if now > timestamp + self.ttl_secs {
            return false;
        }

        // Recompute HMAC and compare
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).expect("HMAC accepts any key length");
        mac.update(&timestamp.to_be_bytes());
        mac.update(ip_bytes(ip).as_slice());
        let expected = hex::encode(mac.finalize().into_bytes());

        // Constant-time comparison to prevent timing attacks
        constant_time_eq(hmac_hex, &expected)
    }

    /// Build the challenge HTML page with embedded JS proof-of-work.
    fn challenge_page(challenge: &str, original_path: &str) -> String {
        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Checking your browser — Dwaar</title>
<style>
body {{ font-family: -apple-system, sans-serif; display: flex;
  justify-content: center; align-items: center; min-height: 100vh;
  margin: 0; background: #f5f5f5; color: #333; }}
.box {{ text-align: center; padding: 2rem; }}
.spinner {{ width: 40px; height: 40px; margin: 1rem auto;
  border: 4px solid #ddd; border-top-color: #333;
  border-radius: 50%; animation: spin 0.8s linear infinite; }}
@keyframes spin {{ to {{ transform: rotate(360deg); }} }}
#status {{ margin-top: 1rem; font-size: 0.9rem; color: #666; }}
</style>
</head>
<body>
<div class="box">
<h2>Verifying you are human</h2>
<div class="spinner"></div>
<p id="status">This takes a moment…</p>
</div>
<script>
(function() {{
  var challenge = "{challenge}";
  var difficulty = {difficulty};
  var path = "{path}";
  var nonce = 0;
  function check() {{
    var end = nonce + 50000;
    while (nonce < end) {{
      var data = challenge + nonce.toString();
      // Use SubtleCrypto for SHA-256
      crypto.subtle.digest("SHA-256", new TextEncoder().encode(data)).then(function(buf) {{
        var arr = new Uint8Array(buf);
        var zeros = 0;
        for (var i = 0; i < arr.length; i++) {{
          if (arr[i] === 0) {{ zeros += 8; }}
          else {{ for (var b = 7; b >= 0; b--) {{ if ((arr[i] & (1 << b)) === 0) zeros++; else break; }} break; }}
        }}
        if (zeros >= difficulty) {{
          document.getElementById("status").textContent = "Verified! Redirecting…";
          var sep = path.indexOf("?") >= 0 ? "&" : "?";
          window.location = path + sep + "{solved_param}=1&{challenge_param}=" +
            encodeURIComponent(challenge) + "&{nonce_param}=" + nonce;
        }}
      }});
      nonce++;
    }}
    document.getElementById("status").textContent = "Working… (" + nonce + " attempts)";
    setTimeout(check, 10);
  }}
  check();
}})();
</script>
</body>
</html>"#,
            challenge = challenge,
            difficulty = POW_DIFFICULTY,
            path = html_escape(original_path),
            solved_param = SOLVED_PARAM,
            challenge_param = CHALLENGE_PARAM,
            nonce_param = NONCE_PARAM,
        )
    }
}

impl fmt::Debug for UnderAttackPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnderAttackPlugin")
            .field("ttl_secs", &self.ttl_secs)
            .finish_non_exhaustive()
    }
}

impl DwaarPlugin for UnderAttackPlugin {
    fn name(&self) -> &'static str {
        "under-attack"
    }

    fn priority(&self) -> u16 {
        15
    }

    fn on_request(&self, req: &RequestHeader, ctx: &mut PluginCtx) -> PluginAction {
        if !ctx.under_attack {
            return PluginAction::Continue;
        }

        let Some(ip) = ctx.client_ip else { return PluginAction::Continue };

        // Check for existing valid clearance cookie
        if let Some(cookie_header) = req.headers.get(http::header::COOKIE)
            && let Ok(cookies) = cookie_header.to_str()
            && let Some(value) = extract_cookie(cookies, CLEARANCE_COOKIE)
            && self.verify_cookie(value, ip) {
            return PluginAction::Continue;
        }

        // Check for challenge solution in query params
        let query = req.uri.query().unwrap_or("");

        if has_param(query, SOLVED_PARAM)
            && let (Some(challenge), Some(nonce)) = (
                get_param(query, CHALLENGE_PARAM),
                get_param(query, NONCE_PARAM),
            )
        {
            // Verify the challenge matches what we'd generate for this IP
            let expected_challenge = self.generate_challenge(ip);
            if constant_time_eq(&challenge, &expected_challenge)
                && Self::verify_pow(&challenge, &nonce)
            {
                // Sign and set clearance cookie, redirect to clean URL
                let cookie_value = self.sign_cookie(ip);
                let clean_path = strip_dwaar_params(&ctx.path);
                let cookie_header = format!(
                    "{CLEARANCE_COOKIE}={cookie_value}; Path=/; Max-Age={ttl}; HttpOnly; SameSite=Lax{secure}",
                    ttl = self.ttl_secs,
                    secure = if ctx.is_tls { "; Secure" } else { "" },
                );

                return PluginAction::Respond(PluginResponse {
                    status: 302,
                    headers: vec![
                        ("Set-Cookie", cookie_header),
                        ("Location", clean_path),
                        ("Content-Length", "0".to_string()),
                        ("Cache-Control", "no-store".to_string()),
                    ],
                    body: Bytes::new(),
                });
            }
        }

        // No valid cookie or solution — serve the challenge page
        let challenge = self.generate_challenge(ip);
        let html = Self::challenge_page(&challenge, &ctx.path);
        let body = Bytes::from(html);
        PluginAction::Respond(PluginResponse {
            status: 200,
            headers: vec![
                ("Content-Type", "text/html; charset=utf-8".to_string()),
                ("Content-Length", body.len().to_string()),
                ("Cache-Control", "no-store".to_string()),
            ],
            body,
        })
    }
}

// -- Helper functions --

/// Convert an IP address to bytes for HMAC input.
fn ip_bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

/// Count leading zero bits in a byte slice.
fn leading_zero_bits(data: &[u8]) -> u32 {
    let mut zeros = 0u32;
    for &byte in data {
        if byte == 0 {
            zeros += 8;
        } else {
            zeros += byte.leading_zeros();
            break;
        }
    }
    zeros
}

/// Constant-time string comparison to prevent timing side-channels.
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Extract a named cookie value from a Cookie header string.
fn extract_cookie<'a>(cookies: &'a str, name: &str) -> Option<&'a str> {
    for pair in cookies.split(';') {
        let pair = pair.trim();
        if let Some(value) = pair.strip_prefix(name)
            && let Some(value) = value.strip_prefix('=') {
            return Some(value);
        }
    }
    None
}

/// Check if a query string contains a parameter.
fn has_param(query: &str, name: &str) -> bool {
    query
        .split('&')
        .any(|p| p.split('=').next().is_some_and(|n| n == name))
}

/// Get a parameter value from a query string.
fn get_param(query: &str, name: &str) -> Option<String> {
    for pair in query.split('&') {
        if let Some((key, value)) = pair.split_once('=')
            && key == name {
            // Basic URL-decode (percent-encoded)
            return Some(url_decode(value));
        }
    }
    None
}

/// Minimal URL decode for the query parameter values we generate ourselves.
fn url_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let hi = chars.next().and_then(hex_digit);
            let lo = chars.next().and_then(hex_digit);
            if let (Some(h), Some(l)) = (hi, lo) {
                result.push(char::from(h << 4 | l));
            }
        } else if b == b'+' {
            result.push(' ');
        } else {
            result.push(char::from(b));
        }
    }
    result
}

fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Strip _dwaar_* query parameters from a path, returning a clean URL.
fn strip_dwaar_params(path: &str) -> String {
    let Some((base, query)) = path.split_once('?') else {
        return path.to_string();
    };

    let clean_params: Vec<&str> = query
        .split('&')
        .filter(|p| {
            let key = p.split('=').next().unwrap_or("");
            !key.starts_with("_dwaar_")
        })
        .collect();

    if clean_params.is_empty() {
        base.to_string()
    } else {
        format!("{base}?{}", clean_params.join("&"))
    }
}

/// Minimal HTML escaping for user-supplied path in the challenge page.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &[u8] = b"test-secret-key-for-dwaar-under-attack";

    fn make_plugin() -> UnderAttackPlugin {
        UnderAttackPlugin::new(TEST_SECRET.to_vec())
    }

    fn make_ctx(ip: IpAddr, under_attack: bool) -> PluginCtx {
        let mut ctx = PluginCtx::new("test-req".to_string());
        ctx.client_ip = Some(ip);
        ctx.under_attack = under_attack;
        ctx.path = "/test".to_string();
        ctx
    }

    fn test_ip() -> IpAddr {
        "192.168.1.100".parse().expect("valid IP")
    }

    // -- Cookie signing and verification --

    #[test]
    fn sign_and_verify_cookie() {
        let plugin = make_plugin();
        let ip = test_ip();
        let cookie = plugin.sign_cookie(ip);
        assert!(plugin.verify_cookie(&cookie, ip));
    }

    #[test]
    fn cookie_rejected_for_different_ip() {
        let plugin = make_plugin();
        let ip1: IpAddr = "10.0.0.1".parse().expect("valid");
        let ip2: IpAddr = "10.0.0.2".parse().expect("valid");
        let cookie = plugin.sign_cookie(ip1);
        assert!(!plugin.verify_cookie(&cookie, ip2));
    }

    #[test]
    fn expired_cookie_rejected() {
        let plugin = UnderAttackPlugin::with_ttl(TEST_SECRET.to_vec(), 0);
        let ip = test_ip();
        let cookie = plugin.sign_cookie(ip);
        // TTL is 0, so the cookie is immediately expired
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(!plugin.verify_cookie(&cookie, ip));
    }

    #[test]
    fn tampered_cookie_rejected() {
        let plugin = make_plugin();
        let ip = test_ip();
        let cookie = plugin.sign_cookie(ip);
        // Flip a character in the HMAC portion
        let tampered = format!("{}x", &cookie[..cookie.len() - 1]);
        assert!(!plugin.verify_cookie(&tampered, ip));
    }

    #[test]
    fn malformed_cookie_rejected() {
        let plugin = make_plugin();
        let ip = test_ip();
        assert!(!plugin.verify_cookie("not-a-cookie", ip));
        assert!(!plugin.verify_cookie("", ip));
        assert!(!plugin.verify_cookie("abc.", ip));
        assert!(!plugin.verify_cookie(".abc", ip));
    }

    // -- Proof of work --

    #[test]
    fn valid_pow_accepted() {
        // Brute-force a valid nonce for a known challenge
        let challenge = "test-challenge-value";
        let mut nonce = 0u64;
        loop {
            if UnderAttackPlugin::verify_pow(challenge, &nonce.to_string()) {
                break;
            }
            nonce += 1;
            // Safety valve — if we can't find one in 10M tries, something is wrong
            assert!(nonce < 10_000_000, "couldn't find valid PoW nonce");
        }
        // Re-verify
        assert!(UnderAttackPlugin::verify_pow(challenge, &nonce.to_string()));
    }

    #[test]
    fn invalid_pow_rejected() {
        assert!(!UnderAttackPlugin::verify_pow("challenge", "0"));
        assert!(!UnderAttackPlugin::verify_pow("challenge", "1"));
    }

    // -- Challenge generation --

    #[test]
    fn challenge_is_deterministic_within_window() {
        let plugin = make_plugin();
        let ip = test_ip();
        let c1 = plugin.generate_challenge(ip);
        let c2 = plugin.generate_challenge(ip);
        assert_eq!(c1, c2);
    }

    #[test]
    fn challenge_differs_by_ip() {
        let plugin = make_plugin();
        let ip1: IpAddr = "10.0.0.1".parse().expect("valid");
        let ip2: IpAddr = "10.0.0.2".parse().expect("valid");
        assert_ne!(
            plugin.generate_challenge(ip1),
            plugin.generate_challenge(ip2)
        );
    }

    // -- Plugin behavior --

    #[test]
    fn disabled_route_passes_through() {
        let plugin = make_plugin();
        let req = RequestHeader::build("GET", b"/", None).expect("valid");
        let mut ctx = make_ctx(test_ip(), false);

        match plugin.on_request(&req, &mut ctx) {
            PluginAction::Continue => {}
            other => panic!("expected Continue, got {other:?}"),
        }
    }

    #[test]
    fn no_cookie_serves_challenge_page() {
        let plugin = make_plugin();
        let req = RequestHeader::build("GET", b"/page", None).expect("valid");
        let mut ctx = make_ctx(test_ip(), true);

        match plugin.on_request(&req, &mut ctx) {
            PluginAction::Respond(resp) => {
                assert_eq!(resp.status, 200);
                let body = String::from_utf8_lossy(&resp.body);
                assert!(body.contains("Checking your browser"));
                assert!(body.contains("crypto.subtle.digest"));
            }
            other => panic!("expected Respond, got {other:?}"),
        }
    }

    #[test]
    fn valid_cookie_passes_through() {
        let plugin = make_plugin();
        let ip = test_ip();
        let cookie = plugin.sign_cookie(ip);

        let mut req = RequestHeader::build("GET", b"/page", None).expect("valid");
        req.insert_header("Cookie", format!("{CLEARANCE_COOKIE}={cookie}"))
            .expect("valid header");

        let mut ctx = make_ctx(ip, true);
        match plugin.on_request(&req, &mut ctx) {
            PluginAction::Continue => {}
            other => panic!("expected Continue, got {other:?}"),
        }
    }

    // -- Helper function tests --

    #[test]
    fn leading_zero_bits_counts_correctly() {
        assert_eq!(leading_zero_bits(&[0x00, 0x00, 0xFF]), 16);
        assert_eq!(leading_zero_bits(&[0x00, 0x80, 0xFF]), 8);
        assert_eq!(leading_zero_bits(&[0x0F, 0xFF, 0xFF]), 4);
        assert_eq!(leading_zero_bits(&[0xFF]), 0);
        assert_eq!(leading_zero_bits(&[0x01]), 7);
        assert_eq!(leading_zero_bits(&[]), 0);
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "ab"));
        assert!(!constant_time_eq("", "a"));
    }

    #[test]
    fn extract_cookie_parses() {
        assert_eq!(extract_cookie("foo=bar; baz=qux", "foo"), Some("bar"));
        assert_eq!(extract_cookie("foo=bar; baz=qux", "baz"), Some("qux"));
        assert_eq!(extract_cookie("foo=bar; baz=qux", "missing"), None);
    }

    #[test]
    fn strip_dwaar_params_cleans_url() {
        assert_eq!(
            strip_dwaar_params("/page?_dwaar_solved=1&_dwaar_nonce=123&keep=yes"),
            "/page?keep=yes"
        );
        assert_eq!(strip_dwaar_params("/page?_dwaar_solved=1"), "/page");
        assert_eq!(strip_dwaar_params("/page"), "/page");
    }

    #[test]
    fn html_escape_sanitizes() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("a&b"), "a&amp;b");
    }

    #[test]
    fn url_decode_handles_percent() {
        assert_eq!(url_decode("hello%20world"), "hello world");
        assert_eq!(url_decode("a%2Fb"), "a/b");
        assert_eq!(url_decode("plain"), "plain");
    }
}
