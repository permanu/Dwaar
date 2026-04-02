// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! IP allowlist/blocklist plugin using a binary CIDR trie (ISSUE-071).
//!
//! The trie provides O(prefix-length) lookups regardless of rule count.
//! IPv4 addresses are stored as IPv4-mapped IPv6 (`::ffff:x.x.x.x`) so
//! a single trie handles both address families.

use std::net::IpAddr;

use bytes::Bytes;

use crate::plugin::{DwaarPlugin, PluginAction, PluginCtx, PluginResponse};

// ── CIDR Trie ────────────────────────────────────────────────────────

/// What to do when a CIDR rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpAction {
    Allow,
    Deny,
}

/// Default policy when no CIDR rule matches the client IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultPolicy {
    /// Blocklist mode: allow unless explicitly denied.
    Allow,
    /// Allowlist mode: deny unless explicitly allowed.
    Deny,
}

/// Arena-allocated binary trie node. Index 0 is the root.
/// Each node has optional left (bit=0) and right (bit=1) children,
/// plus an optional action if this node marks the end of a CIDR prefix.
#[derive(Debug, Clone)]
struct TrieNode {
    children: [Option<u32>; 2],
    action: Option<IpAction>,
}

impl TrieNode {
    fn new() -> Self {
        Self {
            children: [None, None],
            action: None,
        }
    }
}

/// Binary CIDR trie with longest-prefix-match semantics.
///
/// Stores all rules in a flat `Vec<TrieNode>` (arena allocation) for
/// cache locality. Lookups walk at most 128 levels (IPv6 bit length).
#[derive(Debug, Clone)]
pub struct CidrTrie {
    nodes: Vec<TrieNode>,
}

impl CidrTrie {
    pub fn new() -> Self {
        Self {
            nodes: vec![TrieNode::new()], // root at index 0
        }
    }

    /// Insert a CIDR rule. IPv4 addresses are mapped to IPv4-mapped IPv6.
    pub fn insert(&mut self, addr: IpAddr, prefix_len: u8, action: IpAction) {
        let bits = ip_to_bits(addr);
        let mut node_idx = 0;

        for i in 0..prefix_len as usize {
            let bit = ((bits[i / 8] >> (7 - (i % 8))) & 1) as usize;
            if self.nodes[node_idx].children[bit].is_none() {
                let new_idx = self.nodes.len() as u32;
                self.nodes.push(TrieNode::new());
                self.nodes[node_idx].children[bit] = Some(new_idx);
            }
            node_idx = self.nodes[node_idx].children[bit].expect("just inserted") as usize;
        }
        self.nodes[node_idx].action = Some(action);
    }

    /// Longest-prefix-match lookup. Returns the action of the most specific
    /// matching CIDR rule, or `None` if no rule matches.
    pub fn lookup(&self, addr: IpAddr) -> Option<IpAction> {
        let bits = ip_to_bits(addr);
        let mut node_idx: usize = 0;
        let mut last_action = self.nodes[0].action;

        for i in 0..128 {
            let bit = ((bits[i / 8] >> (7 - (i % 8))) & 1) as usize;
            match self.nodes[node_idx].children[bit] {
                Some(child) => {
                    node_idx = child as usize;
                    if let Some(action) = self.nodes[node_idx].action {
                        last_action = Some(action);
                    }
                }
                None => break,
            }
        }
        last_action
    }

    /// Number of nodes in the trie (for diagnostics).
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

impl Default for CidrTrie {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert any IP address to a 128-bit (16-byte) representation.
/// IPv4 maps to `::ffff:x.x.x.x` so both families share one trie.
fn ip_to_bits(addr: IpAddr) -> [u8; 16] {
    match addr {
        IpAddr::V6(v6) => v6.octets(),
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
    }
}

/// Parse a CIDR string like `10.0.0.0/8` or `2001:db8::/32`.
/// Returns (address, `prefix_length`). Handles bare IPs as /32 or /128.
pub fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    if let Some((addr_str, len_str)) = s.split_once('/') {
        let addr: IpAddr = addr_str.parse().ok()?;
        let prefix_len: u8 = len_str.parse().ok()?;
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max {
            return None;
        }
        // Adjust IPv4 prefix length to IPv6 space (add 96 for the ::ffff: prefix)
        let effective_len = match addr {
            IpAddr::V4(_) => prefix_len + 96,
            IpAddr::V6(_) => prefix_len,
        };
        Some((addr, effective_len))
    } else {
        // Bare IP — treat as host route
        let addr: IpAddr = s.parse().ok()?;
        Some((addr, 128))
    }
}

// ── Compiled IP Filter Config ────────────────────────────────────────

/// Compiled IP filter configuration. Built once at config load, shared
/// across requests via `Arc`. Contains the CIDR trie and default policy.
#[derive(Debug, Clone)]
pub struct IpFilterConfig {
    pub trie: CidrTrie,
    pub default_policy: DefaultPolicy,
}

impl IpFilterConfig {
    /// Check whether a client IP should be allowed.
    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        match self.trie.lookup(ip) {
            Some(IpAction::Allow) => true,
            Some(IpAction::Deny) => false,
            None => matches!(self.default_policy, DefaultPolicy::Allow),
        }
    }
}

// ── Plugin ───────────────────────────────────────────────────────────

/// IP allowlist/blocklist plugin. Reads per-route `IpFilterConfig` from
/// `PluginCtx`, checks client IP against the CIDR trie, returns 403 on deny.
#[derive(Debug)]
pub struct IpFilterPlugin;

impl IpFilterPlugin {
    pub fn new() -> Self {
        Self
    }
}

impl Default for IpFilterPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl DwaarPlugin for IpFilterPlugin {
    fn name(&self) -> &'static str {
        "ip-filter"
    }

    fn priority(&self) -> u16 {
        // Run early — block denied IPs before bot detection or rate limiting.
        // After under_attack (5) but before bot_detect (10).
        8
    }

    fn on_request(&self, _req: &pingora_http::RequestHeader, ctx: &mut PluginCtx) -> PluginAction {
        let Some(ref filter) = ctx.ip_filter else {
            return PluginAction::Continue;
        };
        let Some(ip) = ctx.client_ip else {
            return PluginAction::Continue;
        };

        if filter.is_allowed(ip) {
            PluginAction::Continue
        } else {
            PluginAction::Respond(PluginResponse {
                status: 403,
                headers: vec![("Content-Length", "0".to_string())],
                body: Bytes::new(),
            })
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn ipv4_exact_match() {
        let mut trie = CidrTrie::new();
        let (addr, len) = parse_cidr("192.168.1.1").unwrap();
        trie.insert(addr, len, IpAction::Deny);

        assert_eq!(
            trie.lookup(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            Some(IpAction::Deny)
        );
        assert_eq!(trie.lookup(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))), None);
    }

    #[test]
    fn ipv4_subnet_match() {
        let mut trie = CidrTrie::new();
        let (addr, len) = parse_cidr("10.0.0.0/8").unwrap();
        trie.insert(addr, len, IpAction::Allow);

        assert_eq!(
            trie.lookup(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))),
            Some(IpAction::Allow)
        );
        assert_eq!(
            trie.lookup(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255))),
            Some(IpAction::Allow)
        );
        assert_eq!(trie.lookup(IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1))), None);
    }

    #[test]
    fn ipv4_catch_all() {
        let mut trie = CidrTrie::new();
        let (addr, len) = parse_cidr("0.0.0.0/0").unwrap();
        trie.insert(addr, len, IpAction::Deny);

        assert_eq!(
            trie.lookup(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
            Some(IpAction::Deny)
        );
        assert_eq!(
            trie.lookup(IpAddr::V4(Ipv4Addr::BROADCAST)),
            Some(IpAction::Deny)
        );
    }

    #[test]
    fn ipv4_longest_prefix_wins() {
        let mut trie = CidrTrie::new();
        let (addr, len) = parse_cidr("10.0.0.0/8").unwrap();
        trie.insert(addr, len, IpAction::Allow);
        let (addr, len) = parse_cidr("10.0.1.0/24").unwrap();
        trie.insert(addr, len, IpAction::Deny);

        // 10.0.1.50 matches both /8 (allow) and /24 (deny) — longest wins
        assert_eq!(
            trie.lookup(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 50))),
            Some(IpAction::Deny)
        );
        // 10.0.2.1 matches only /8 (allow)
        assert_eq!(
            trie.lookup(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1))),
            Some(IpAction::Allow)
        );
    }

    #[test]
    fn ipv6_subnet_match() {
        let mut trie = CidrTrie::new();
        let (addr, len) = parse_cidr("2001:db8::/32").unwrap();
        trie.insert(addr, len, IpAction::Allow);

        let test_ip: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(trie.lookup(test_ip), Some(IpAction::Allow));

        let other_ip: IpAddr = "2001:db9::1".parse().unwrap();
        assert_eq!(trie.lookup(other_ip), None);
    }

    #[test]
    fn ipv6_exact_match() {
        let mut trie = CidrTrie::new();
        let (addr, len) = parse_cidr("::1").unwrap();
        trie.insert(addr, len, IpAction::Deny);

        let loopback: IpAddr = "::1".parse().unwrap();
        assert_eq!(trie.lookup(loopback), Some(IpAction::Deny));

        let other: IpAddr = "::2".parse().unwrap();
        assert_eq!(trie.lookup(other), None);
    }

    #[test]
    fn parse_cidr_valid() {
        assert!(parse_cidr("10.0.0.0/8").is_some());
        assert!(parse_cidr("192.168.1.0/24").is_some());
        assert!(parse_cidr("0.0.0.0/0").is_some());
        assert!(parse_cidr("255.255.255.255/32").is_some());
        assert!(parse_cidr("2001:db8::/32").is_some());
        assert!(parse_cidr("::1").is_some());
        assert!(parse_cidr("127.0.0.1").is_some());
    }

    #[test]
    fn parse_cidr_invalid() {
        assert!(parse_cidr("not-an-ip").is_none());
        assert!(parse_cidr("10.0.0.0/33").is_none());
        assert!(parse_cidr("10.0.0.0/-1").is_none());
        assert!(parse_cidr("").is_none());
    }

    #[test]
    fn ip_filter_config_default_allow() {
        let config = IpFilterConfig {
            trie: CidrTrie::new(),
            default_policy: DefaultPolicy::Allow,
        };
        assert!(config.is_allowed(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
    }

    #[test]
    fn ip_filter_config_default_deny() {
        let config = IpFilterConfig {
            trie: CidrTrie::new(),
            default_policy: DefaultPolicy::Deny,
        };
        assert!(!config.is_allowed(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
    }

    #[test]
    fn ip_filter_config_deny_overrides_default_allow() {
        let mut trie = CidrTrie::new();
        let (addr, len) = parse_cidr("203.0.113.0/24").unwrap();
        trie.insert(addr, len, IpAction::Deny);

        let config = IpFilterConfig {
            trie,
            default_policy: DefaultPolicy::Allow,
        };

        // Denied subnet → blocked
        assert!(!config.is_allowed(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50))));
        // Everything else → allowed
        assert!(config.is_allowed(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn ip_filter_config_allow_overrides_default_deny() {
        let mut trie = CidrTrie::new();
        let (addr, len) = parse_cidr("10.0.0.0/8").unwrap();
        trie.insert(addr, len, IpAction::Allow);

        let config = IpFilterConfig {
            trie,
            default_policy: DefaultPolicy::Deny,
        };

        // Allowed subnet → passes
        assert!(config.is_allowed(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        // Everything else → denied
        assert!(!config.is_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn mixed_ipv4_ipv6_rules() {
        let mut trie = CidrTrie::new();
        let (addr, len) = parse_cidr("10.0.0.0/8").unwrap();
        trie.insert(addr, len, IpAction::Allow);
        let (addr, len) = parse_cidr("2001:db8::/32").unwrap();
        trie.insert(addr, len, IpAction::Deny);

        assert_eq!(
            trie.lookup(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            Some(IpAction::Allow)
        );
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(trie.lookup(v6), Some(IpAction::Deny));
    }
}
