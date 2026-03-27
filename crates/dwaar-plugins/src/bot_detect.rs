// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Bot detection via User-Agent classification.
//!
//! Uses a compiled `RegexSet` (Aho-Corasick internally) so all patterns are
//! tested in a single pass — O(n) in input length regardless of pattern count.
//! This matters because `classify()` runs on every proxied request.

use regex::RegexSet;

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
// classified as Malicious. RegexSet returns all matching indices; we take
// the lowest index, which corresponds to the highest-priority pattern.
//
// Within each category order doesn't matter — we just need any match.
const PATTERNS: &[(&str, BotCategory)] = &[
    // --- Malicious ---
    // Security scanners and exploit tools; block or heavily rate-limit these.
    (r"(?i)sqlmap", BotCategory::Malicious),
    (r"(?i)nikto", BotCategory::Malicious),
    (r"(?i)masscan", BotCategory::Malicious),
    (r"(?i)zgrab", BotCategory::Malicious),
    (r"(?i)nuclei", BotCategory::Malicious),
    (r"(?i)nmap", BotCategory::Malicious),
    (r"(?i)dirbuster", BotCategory::Malicious),
    (r"(?i)gobuster", BotCategory::Malicious),
    (r"(?i)wpscan", BotCategory::Malicious),
    // --- SearchEngine ---
    // Legitimate crawlers worth allowing; may still want to rate-limit.
    (r"(?i)googlebot", BotCategory::SearchEngine),
    (r"(?i)bingbot", BotCategory::SearchEngine),
    (r"(?i)yandexbot", BotCategory::SearchEngine),
    (r"(?i)baiduspider", BotCategory::SearchEngine),
    (r"(?i)duckduckbot", BotCategory::SearchEngine),
    (r"(?i)slurp", BotCategory::SearchEngine),
    (r"(?i)applebot", BotCategory::SearchEngine),
    (r"(?i)ahrefsbot", BotCategory::SearchEngine),
    (r"(?i)semrushbot", BotCategory::SearchEngine),
    (r"(?i)mj12bot", BotCategory::SearchEngine),
    // --- SocialCrawler ---
    // Link-preview fetchers from social platforms.
    (r"(?i)twitterbot", BotCategory::SocialCrawler),
    (r"(?i)facebookexternalhit", BotCategory::SocialCrawler),
    (r"(?i)linkedinbot", BotCategory::SocialCrawler),
    (r"(?i)slackbot", BotCategory::SocialCrawler),
    (r"(?i)discordbot", BotCategory::SocialCrawler),
    (r"(?i)whatsapp", BotCategory::SocialCrawler),
    (r"(?i)telegrambot", BotCategory::SocialCrawler),
    // --- Monitoring ---
    // Uptime checkers; typically benign but worth tagging separately.
    (r"(?i)uptimerobot", BotCategory::Monitoring),
    (r"(?i)pingdom", BotCategory::Monitoring),
    (r"(?i)site24x7", BotCategory::Monitoring),
    (r"(?i)statuscake", BotCategory::Monitoring),
    (r"(?i)betteruptime", BotCategory::Monitoring),
    // --- Generic ---
    // Scripted HTTP clients. Anchored with `^` to avoid false positives —
    // e.g. `^curl/` won't match "obscurlity" or "procurement".
    (r"(?i)^curl/", BotCategory::Generic),
    (r"(?i)^wget/", BotCategory::Generic),
    (r"(?i)python-requests", BotCategory::Generic),
    (r"(?i)go-http-client", BotCategory::Generic),
    (r"(?i)^libwww", BotCategory::Generic),
    (r"(?i)java/", BotCategory::Generic),
    (r"(?i)scrapy", BotCategory::Generic),
    (r"(?i)^php/", BotCategory::Generic),
];

/// Classifies User-Agent strings using a single compiled `RegexSet`.
///
/// Construct once at startup and reuse — compilation is the expensive part.
pub struct BotDetector {
    patterns: RegexSet,
    /// Parallel to the pattern list: index i gives the category for pattern i.
    categories: Vec<BotCategory>,
}

impl BotDetector {
    /// Compiles all bot patterns into a single `RegexSet`.
    ///
    /// Panics if any hardcoded pattern fails to compile — these are static
    /// strings so a compile failure means a programmer error, not bad input.
    pub fn new() -> Self {
        let (raw_patterns, categories): (Vec<&str>, Vec<BotCategory>) =
            PATTERNS.iter().map(|(p, c)| (*p, *c)).unzip();

        let patterns =
            RegexSet::new(&raw_patterns).expect("hardcoded bot detection patterns must compile");

        Self {
            patterns,
            categories,
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

        // `matches()` returns all matching pattern indices. We take the
        // minimum because PATTERNS is ordered highest-priority-first, so the
        // lowest index wins when multiple patterns fire.
        self.patterns
            .matches(user_agent)
            .into_iter()
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
        // `patterns` (RegexSet) is intentionally excluded — its Debug output is
        // verbose compiled automaton internals, not useful to callers.
        f.debug_struct("BotDetector")
            .field("pattern_count", &self.categories.len())
            .finish_non_exhaustive()
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
}
