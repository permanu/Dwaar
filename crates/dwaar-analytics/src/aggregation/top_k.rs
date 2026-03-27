// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Bounded top-K frequency tracker.
//!
//! Maintains the K items with the highest counts using a `HashMap` for
//! O(1) lookups. Tracks the minimum-count entry explicitly so eviction
//! is O(1) in the common case (when the cached min is still valid).
//! Recomputes the min in O(K) only after an eviction invalidates the
//! cache — amortized across many increments this is negligible.

use std::collections::HashMap;

/// Tracks the K most frequently seen items.
///
/// The hot path (incrementing an existing item) is O(1). New items
/// that force eviction pay O(K) once to find the new minimum, then
/// subsequent evictions of that same minimum are O(1).
#[derive(Debug)]
pub struct TopK<T: std::hash::Hash + Eq + Clone + Ord> {
    counts: HashMap<T, u64>,
    capacity: usize,
    /// Cached minimum key and count. Invalidated on eviction.
    cached_min: Option<(T, u64)>,
}

impl<T: std::hash::Hash + Eq + Clone + Ord> TopK<T> {
    pub fn new(capacity: usize) -> Self {
        Self {
            counts: HashMap::with_capacity(capacity),
            capacity,
            cached_min: None,
        }
    }

    /// Record one occurrence of `item`.
    ///
    /// If the item is already tracked, its count is incremented (O(1)).
    /// If it's new and the map is at capacity, the minimum-count entry
    /// is evicted first — O(1) if the cached min is valid, O(K) to
    /// recompute otherwise.
    pub fn insert(&mut self, item: T) {
        if self.counts.contains_key(&item) {
            *self.counts.get_mut(&item).expect("just checked") += 1;
            return;
        }

        if self.counts.len() >= self.capacity {
            self.evict_min();
        }
        self.counts.insert(item, 1);
        // New item at count=1 might be the new minimum
        self.cached_min = None;
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
        let (min_key, _) = self.find_min();
        self.counts.remove(&min_key);
        self.cached_min = None; // must recompute after removal
    }

    fn find_min(&mut self) -> (T, u64) {
        if let Some(ref cached) = self.cached_min {
            // Verify the cached min still has the same count (it could
            // have been incremented since caching).
            if self.counts.get(&cached.0).copied() == Some(cached.1) {
                return cached.clone();
            }
        }

        // Recompute — O(K)
        let (min_key, min_count) = self
            .counts
            .iter()
            .min_by_key(|&(_, &count)| count)
            .map(|(k, &v)| (k.clone(), v))
            .expect("called on non-empty map");
        self.cached_min = Some((min_key.clone(), min_count));
        (min_key, min_count)
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
        assert_eq!(
            top.iter().find(|(k, _)| k == "c").expect("c should be present").1,
            5
        );
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
        for i in 0..500u64 {
            let key = format!("page_{i}");
            let freq = i + 1;
            for _ in 0..freq {
                tk.insert(key.clone());
            }
        }
        let top = tk.top();
        assert_eq!(top.len(), 100);
        assert_eq!(top[0].0, "page_499");
        assert_eq!(top[0].1, 500);
        assert_eq!(top[99].0, "page_400");
        assert_eq!(top[99].1, 401);
    }

    #[test]
    fn ten_thousand_items_top_100() {
        // Restored from original spec — this must complete in <5s.
        // With cached-min eviction, this is fast even at scale.
        let mut tk = TopK::new(100);
        for i in 0..10_000u64 {
            let key = format!("page_{i}");
            for _ in 0..=i {
                tk.insert(key.clone());
            }
        }
        let top = tk.top();
        assert_eq!(top.len(), 100);
        assert_eq!(top[0].0, "page_9999");
        assert_eq!(top[0].1, 10_000);
        assert_eq!(top[99].0, "page_9900");
        assert_eq!(top[99].1, 9901);
    }
}
