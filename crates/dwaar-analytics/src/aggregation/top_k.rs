// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Bounded top-K frequency tracker.
//!
//! Maintains the K items with the highest counts using a `HashMap` for
//! O(1) lookups and evicting the minimum-count entry when capacity
//! is exceeded.

use std::collections::HashMap;

/// Tracks the K most frequently seen items.
///
/// Uses a `HashMap` for O(1) count lookups. When the map exceeds K
/// entries, the entry with the smallest count is evicted.
#[derive(Debug)]
pub struct TopK<T: std::hash::Hash + Eq + Clone + Ord> {
    counts: HashMap<T, u64>,
    capacity: usize,
}

impl<T: std::hash::Hash + Eq + Clone + Ord> TopK<T> {
    pub fn new(capacity: usize) -> Self {
        Self {
            counts: HashMap::with_capacity(capacity),
            capacity,
        }
    }

    /// Record one occurrence of `item`.
    ///
    /// If the item is already tracked, its count is incremented. If
    /// it's new and the map is at capacity, the minimum-count entry
    /// is evicted first to make room — this prevents the new item
    /// from immediately evicting itself.
    pub fn insert(&mut self, item: T) {
        if self.counts.contains_key(&item) {
            *self.counts.get_mut(&item).expect("just checked") += 1;
            return;
        }

        // New item — make room if needed
        if self.counts.len() >= self.capacity {
            self.evict_min();
        }
        self.counts.insert(item, 1);
    }

    /// Return all tracked items sorted by count (descending).
    pub fn top(&self) -> Vec<(T, u64)> {
        let mut entries: Vec<_> = self.counts.iter().map(|(k, &v)| (k.clone(), v)).collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        entries
    }

    pub fn len(&self) -> usize {
        self.counts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }

    fn evict_min(&mut self) {
        if let Some((min_key, _)) = self
            .counts
            .iter()
            .min_by_key(|&(_, &count)| count)
            .map(|(k, &v)| (k.clone(), v))
        {
            self.counts.remove(&min_key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_retrieve() {
        let mut tk = TopK::new(3);
        tk.insert("/home".to_string());
        tk.insert("/home".to_string());
        tk.insert("/about".to_string());
        let top = tk.top();
        assert_eq!(top[0], ("/home".to_string(), 2));
        assert_eq!(top[1], ("/about".to_string(), 1));
    }

    #[test]
    fn respects_capacity() {
        let mut tk = TopK::new(2);
        tk.insert("a".to_string());
        tk.insert("a".to_string());
        tk.insert("b".to_string());
        tk.insert("b".to_string());
        assert_eq!(tk.len(), 2);
        tk.insert("c".to_string());
        assert!(tk.len() <= 2);
    }

    #[test]
    fn high_frequency_item_displaces_low() {
        let mut tk = TopK::new(2);
        tk.insert("a".to_string());
        tk.insert("b".to_string());
        for _ in 0..5 {
            tk.insert("c".to_string());
        }
        let top = tk.top();
        assert!(top.iter().any(|(k, _)| k == "c"));
        assert_eq!(top.iter().find(|(k, _)| k == "c").expect("c should be present").1, 5);
    }

    #[test]
    fn top_returns_sorted_descending() {
        let mut tk = TopK::new(10);
        for _ in 0..5 { tk.insert("x".to_string()); }
        for _ in 0..3 { tk.insert("y".to_string()); }
        for _ in 0..8 { tk.insert("z".to_string()); }
        let top = tk.top();
        assert_eq!(top[0].0, "z");
        assert_eq!(top[1].0, "x");
        assert_eq!(top[2].0, "y");
    }

    #[test]
    fn many_items_top_100() {
        let mut tk = TopK::new(100);
        // Insert 500 unique items, each with a distinct frequency.
        // Items are inserted in random-ish order (low, then high) to
        // exercise the eviction path realistically.
        for i in 0..500u64 {
            let key = format!("page_{i}");
            let freq = i + 1; // page_0=1, page_499=500
            for _ in 0..freq {
                tk.insert(key.clone());
            }
        }
        let top = tk.top();
        assert_eq!(top.len(), 100);
        // Highest-frequency item should be on top
        assert_eq!(top[0].0, "page_499");
        assert_eq!(top[0].1, 500);
        // 100th item should be page_400 (count=401)
        assert_eq!(top[99].0, "page_400");
        assert_eq!(top[99].1, 401);
    }
}
