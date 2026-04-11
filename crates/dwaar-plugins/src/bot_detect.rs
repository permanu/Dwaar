// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Bot detection via User-Agent classification.
//!
//! Uses `daachorse::DoubleArrayAhoCorasick` for multi-pattern substring matching
//! in a single O(n) pass over the input. All patterns are pre-lowercased and the
//! input UA is lowercased once before matching, replacing the old `(?i)` regex
//! approach with zero backtracking risk.

use daachorse::DoubleArrayAhoCorasick;
use pingora_http::RequestHeader;

use crate::plugin::{DwaarPlugin, PluginAction, PluginCtx};

/// Stack buffer size for in-place User-Agent lowercasing (M-17). Covers the
/// overwhelming majority of real-world UA strings (RFC 9110 suggests ≤ 256);
/// longer UAs fall back to a heap `Vec`.
const STACK_BUF: usize = 512;

/// Broad category of the detected bot. Kept coarse intentionally — callers
/// decide what to do (block, rate-limit, tag, log) based on category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BotCategory {
    SearchEngine,
    SocialCrawler,
    Monitoring,
    Malicious,
    Generic,
}

impl BotCategory {
    /// Stable string representation used in log fields and analytics tags.
    /// These strings are part of the public API — do not rename them.
    pub fn as_str(self) -> &'static str {
        match self {
            BotCategory::SearchEngine => "search_engine",
            BotCategory::SocialCrawler => "social_crawler",
            BotCategory::Monitoring => "monitoring",
            BotCategory::Malicious => "malicious",
            BotCategory::Generic => "generic",
        }
    }
}

// Patterns are ordered by priority: malicious tools first so a UA that
// matches both "sqlmap" and (hypothetically) a search engine string gets
// classified as Malicious. We take the lowest index, which corresponds
// to the highest-priority pattern.
//
// Within each category order doesn't matter — we just need any match.
//
// The boolean flag indicates whether the pattern must appear at position 0
// (i.e., the original regex used a `^` anchor). This prevents false positives
// like "obscurlity" matching the "curl/" pattern.
const PATTERNS: &[(&str, BotCategory, bool)] = &[
    // --- Malicious ---
    // Security scanners and exploit tools; block or heavily rate-limit these.
    ("sqlmap", BotCategory::Malicious, false),
    ("nikto", BotCategory::Malicious, false),
    ("masscan", BotCategory::Malicious, false),
    ("zgrab", BotCategory::Malicious, false),
    ("nuclei", BotCategory::Malicious, false),
    ("nmap", BotCategory::Malicious, false),
    ("dirbuster", BotCategory::Malicious, false),
    ("gobuster", BotCategory::Malicious, false),
    ("wpscan", BotCategory::Malicious, false),
    // --- SearchEngine ---
    // Legitimate crawlers worth allowing; may still want to rate-limit.
    ("googlebot", BotCategory::SearchEngine, false),
    ("bingbot", BotCategory::SearchEngine, false),
    ("yandexbot", BotCategory::SearchEngine, false),
    ("baiduspider", BotCategory::SearchEngine, false),
    ("duckduckbot", BotCategory::SearchEngine, false),
    ("slurp", BotCategory::SearchEngine, false),
    ("applebot", BotCategory::SearchEngine, false),
    ("ahrefsbot", BotCategory::SearchEngine, false),
    ("semrushbot", BotCategory::SearchEngine, false),
    ("mj12bot", BotCategory::SearchEngine, false),
    // --- SocialCrawler ---
    // Link-preview fetchers from social platforms.
    ("twitterbot", BotCategory::SocialCrawler, false),
    ("facebookexternalhit", BotCategory::SocialCrawler, false),
    ("linkedinbot", BotCategory::SocialCrawler, false),
    ("slackbot", BotCategory::SocialCrawler, false),
    ("discordbot", BotCategory::SocialCrawler, false),
    ("whatsapp", BotCategory::SocialCrawler, false),
    ("telegrambot", BotCategory::SocialCrawler, false),
    // --- Monitoring ---
    // Uptime checkers; typically benign but worth tagging separately.
    ("uptimerobot", BotCategory::Monitoring, false),
    ("pingdom", BotCategory::Monitoring, false),
    ("site24x7", BotCategory::Monitoring, false),
    ("statuscake", BotCategory::Monitoring, false),
    ("betteruptime", BotCategory::Monitoring, false),
    // --- Generic ---
    // Scripted HTTP clients. Anchored to start-of-string to avoid false
    // positives — e.g. "curl/" won't match "obscurlity" or "procurement".
    ("curl/", BotCategory::Generic, true),
    ("wget/", BotCategory::Generic, true),
    ("python-requests", BotCategory::Generic, false),
    ("go-http-client", BotCategory::Generic, false),
    ("libwww", BotCategory::Generic, true),
    ("java/", BotCategory::Generic, false),
    ("scrapy", BotCategory::Generic, false),
    ("php/", BotCategory::Generic, true),
];

/// Classifies User-Agent strings using Aho-Corasick multi-pattern matching.
///
/// Construct once at startup and reuse — construction is the expensive part.
pub struct BotDetector {
    automaton: DoubleArrayAhoCorasick<usize>,
    /// Parallel to the pattern list: index i gives the category for pattern i.
    categories: Vec<BotCategory>,
    /// Parallel flag: true if pattern i must match at position 0 (start-anchored).
    anchored: Vec<bool>,
}

impl BotDetector {
    /// Builds the Aho-Corasick automaton from all bot patterns.
    ///
    /// Panics if construction fails — these are static strings so a failure
    /// means a programmer error, not bad input.
    pub fn new() -> Self {
        let patterns: Vec<&str> = PATTERNS.iter().map(|(p, _, _)| *p).collect();
        let categories: Vec<BotCategory> = PATTERNS.iter().map(|(_, c, _)| *c).collect();
        let anchored: Vec<bool> = PATTERNS.iter().map(|(_, _, a)| *a).collect();

        // Build with pattern indices as values so we can map matches back
        // to their category. Patterns are already lowercase.
        let automaton = DoubleArrayAhoCorasick::with_values(patterns.iter().zip(0usize..))
            .expect("hardcoded bot detection patterns must build");

        Self {
            automaton,
            categories,
            anchored,
        }
    }

    /// Returns `None` for human traffic, or the first (highest-priority)
    /// matching `BotCategory` for known bots.
    ///
    /// Empty UA is treated as human — no UA is not the same as a bot UA.
    /// Callers that want to treat missing UA as suspicious should check for
    /// emptiness themselves and apply their own policy.
    pub fn classify(&self, user_agent: &str) -> Option<BotCategory> {
        if user_agent.is_empty() {
            return None;
        }

        // Real-world User-Agent strings almost always fit in a few hundred
        // bytes (the RFC 9110 recommendation is ≤ 256). Lowercase into a fixed
        // stack buffer to avoid a per-request heap allocation, and only fall
        // back to a Vec for the rare oversize UA. All stored patterns are
        // already lowercase, so case-folding the input is sufficient.
        let bytes = user_agent.as_bytes();
        if bytes.len() <= STACK_BUF {
            let mut stack = [0u8; STACK_BUF];
            let slice = &mut stack[..bytes.len()];
            slice.copy_from_slice(bytes);
            slice.make_ascii_lowercase();
            self.find_match(slice)
        } else {
            // Oversize path — rare enough that the fallback alloc is fine.
            let mut heap = bytes.to_vec();
            heap.make_ascii_lowercase();
            self.find_match(&heap)
        }
    }

    /// Run the automaton and resolve the highest-priority match. Split out so
    /// both the stack and heap paths share a single scanning implementation.
    fn find_match(&self, lowered: &[u8]) -> Option<BotCategory> {
        self.automaton
            .find_overlapping_iter(lowered)
            .filter(|m| {
                let idx = m.value();
                !self.anchored[idx] || m.start() == 0
            })
            .map(|m| m.value())
            .min()
            .map(|idx| self.categories[idx])
    }
}

impl Default for BotDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for BotDetector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BotDetector")
            .field("pattern_count", &self.categories.len())
            .finish_non_exhaustive()
    }
}

/// Plugin wrapper that runs bot detection on every request.
///
/// Priority 10 — runs first so other plugins (rate limiter) can use
/// the `is_bot` flag for differentiated behavior.
#[derive(Debug)]
pub struct BotDetectPlugin {
    detector: BotDetector,
}

impl BotDetectPlugin {
    pub fn new() -> Self {
        Self {
            detector: BotDetector::new(),
        }
    }
}

impl Default for BotDetectPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl DwaarPlugin for BotDetectPlugin {
    fn name(&self) -> &'static str {
        "bot-detect"
    }

    fn priority(&self) -> u16 {
        10
    }

    fn on_request(&self, req: &RequestHeader, ctx: &mut PluginCtx) -> PluginAction {
        if let Some(ua) = req.headers.get(http::header::USER_AGENT)
            && let Ok(ua_str) = ua.to_str()
            && let Some(category) = self.detector.classify(ua_str)
        {
            ctx.is_bot = true;
            ctx.bot_category = Some(category);
        }
        PluginAction::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn googlebot_detected_as_search_engine() {
        let detector = BotDetector::new();
        let result = detector
            .classify("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)");
        assert_eq!(result, Some(BotCategory::SearchEngine));
    }

    #[test]
    fn curl_detected_as_generic() {
        let detector = BotDetector::new();
        assert_eq!(detector.classify("curl/7.88.1"), Some(BotCategory::Generic));
    }

    #[test]
    fn empty_ua_is_human() {
        let detector = BotDetector::new();
        assert_eq!(detector.classify(""), None);
    }

    #[test]
    fn normal_browser_is_human() {
        let detector = BotDetector::new();
        let chrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        assert_eq!(detector.classify(chrome), None);
        let firefox = "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0";
        assert_eq!(detector.classify(firefox), None);
    }

    #[test]
    fn case_insensitive_matching() {
        let detector = BotDetector::new();
        assert_eq!(
            detector.classify("GOOGLEBOT/2.1"),
            Some(BotCategory::SearchEngine)
        );
        assert_eq!(detector.classify("Curl/7.0"), Some(BotCategory::Generic));
    }

    #[test]
    fn malicious_tool_detected() {
        let detector = BotDetector::new();
        assert_eq!(
            detector.classify("sqlmap/1.0-dev"),
            Some(BotCategory::Malicious)
        );
        assert_eq!(
            detector.classify("Nikto/2.1.6"),
            Some(BotCategory::Malicious)
        );
        assert_eq!(
            detector.classify("nuclei v2.9.0"),
            Some(BotCategory::Malicious)
        );
    }

    #[test]
    fn social_crawler_detected() {
        let detector = BotDetector::new();
        assert_eq!(
            detector.classify("Twitterbot/1.0"),
            Some(BotCategory::SocialCrawler)
        );
        assert_eq!(
            detector.classify("facebookexternalhit/1.1"),
            Some(BotCategory::SocialCrawler)
        );
    }

    #[test]
    fn monitoring_bot_detected() {
        let detector = BotDetector::new();
        assert_eq!(
            detector.classify("UptimeRobot/2.0"),
            Some(BotCategory::Monitoring)
        );
    }

    #[test]
    fn bot_category_as_str() {
        assert_eq!(BotCategory::SearchEngine.as_str(), "search_engine");
        assert_eq!(BotCategory::SocialCrawler.as_str(), "social_crawler");
        assert_eq!(BotCategory::Monitoring.as_str(), "monitoring");
        assert_eq!(BotCategory::Malicious.as_str(), "malicious");
        assert_eq!(BotCategory::Generic.as_str(), "generic");
    }

    #[test]
    fn anchored_pattern_rejects_mid_string_match() {
        let detector = BotDetector::new();
        assert_eq!(detector.classify("something curl/7.0"), None);
        assert_eq!(detector.classify("obscurlity"), None);
    }

    #[test]
    fn oversize_ua_still_classified_correctly() {
        // UA longer than the 512-byte stack buffer must hit the heap path and
        // still produce the same classification as the short-path counterpart.
        let detector = BotDetector::new();
        let padding = "x".repeat(1024);
        let ua = format!("Mozilla/5.0 Googlebot/2.1 {padding}");
        assert!(ua.len() > 512);
        assert_eq!(detector.classify(&ua), Some(BotCategory::SearchEngine));
    }

    #[test]
    fn anchored_pattern_accepts_start_of_string() {
        let detector = BotDetector::new();
        assert_eq!(detector.classify("wget/1.21"), Some(BotCategory::Generic));
        assert_eq!(
            detector.classify("libwww-perl/6.72"),
            Some(BotCategory::Generic)
        );
        assert_eq!(detector.classify("PHP/8.2.0"), Some(BotCategory::Generic));
    }
}
