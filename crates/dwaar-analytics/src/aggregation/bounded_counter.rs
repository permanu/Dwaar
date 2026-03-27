// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Bounded frequency counter using the Space-Saving algorithm.
//!
//! Tracks the N most frequent items. When capacity is reached, a new
//! item evicts the minimum-count entry and inherits its count + 1.
//! Uses a cached minimum for O(1) amortized eviction.

use std::collections::HashMap;

/// Space-Saving bounded frequency counter.
///
/// When at capacity, new items evict the minimum-count entry and start
/// with count = `evicted_min + 1`. The minimum is cached for O(1)
/// eviction in the common case; recomputed in O(N) only when the
/// cache is invalidated.
#[derive(Debug)]
pub struct BoundedCounter<T: std::hash::Hash + Eq + Clone + Ord> {
    counts: HashMap<T, u64>,
    capacity: usize,
    cached_min: Option<(T, u64)>,
}

impl<T: std::hash::Hash + Eq + Clone + Ord> BoundedCounter<T> {
    pub fn new(capacity: usize) -> Self {
        Self {
            counts: HashMap::with_capacity(capacity),
            capacity,
            cached_min: None,
        }
    }

    /// Record one occurrence of `item`.
    pub fn insert(&mut self, item: T) {
        if self.counts.contains_key(&item) {
            *self.counts.get_mut(&item).expect("just checked") += 1;
            // Increment may have changed what the true min is
            self.cached_min = None;
            return;
        }

        if self.counts.len() >= self.capacity {
            let evicted_min = self.evict_min();
            self.counts.insert(item, evicted_min + 1);
        } else {
            self.counts.insert(item, 1);
        }
        self.cached_min = None;
    }

    pub fn get(&self, item: &str) -> Option<u64>
    where
        T: std::borrow::Borrow<str>,
    {
        self.counts.get(item).copied()
    }

    /// All items sorted by count descending.
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

    /// Remove the entry with the smallest count and return that count.
    fn evict_min(&mut self) -> u64 {
        let (min_key, min_count) = self.find_min();
        self.counts.remove(&min_key);
        self.cached_min = None;
        min_count
    }

    fn find_min(&mut self) -> (T, u64) {
        let valid = self.cached_min.as_ref().is_some_and(|(key, count)| {
            self.counts.get(key).copied() == Some(*count)
        });
        if valid {
            return self.cached_min.clone().expect("just checked");
        }

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
    fn basic_counting() {
        let mut bc = BoundedCounter::new(10);
        bc.insert("a".to_string());
        bc.insert("a".to_string());
        bc.insert("b".to_string());
        assert_eq!(bc.get("a"), Some(2));
        assert_eq!(bc.get("b"), Some(1));
        assert_eq!(bc.get("c"), None);
    }

    #[test]
    fn never_exceeds_capacity() {
        let mut bc = BoundedCounter::new(3);
        for i in 0..1000 {
            bc.insert(format!("item_{i}"));
        }
        assert!(bc.len() <= 3);
    }

    #[test]
    fn new_item_inherits_evicted_count_plus_one() {
        let mut bc = BoundedCounter::new(2);
        for _ in 0..5 { bc.insert("a".to_string()); }
        for _ in 0..3 { bc.insert("b".to_string()); }
        assert_eq!(bc.len(), 2);
        bc.insert("c".to_string());
        assert_eq!(bc.len(), 2);
        assert_eq!(bc.get("c"), Some(4));
        assert_eq!(bc.get("b"), None);
        assert_eq!(bc.get("a"), Some(5));
    }

    #[test]
    fn existing_item_increments_normally() {
        let mut bc = BoundedCounter::new(2);
        bc.insert("a".to_string());
        bc.insert("b".to_string());
        bc.insert("a".to_string());
        assert_eq!(bc.get("a"), Some(2));
        assert_eq!(bc.len(), 2);
    }

    #[test]
    fn top_returns_sorted() {
        let mut bc = BoundedCounter::new(10);
        for _ in 0..5 { bc.insert("x".to_string()); }
        for _ in 0..2 { bc.insert("y".to_string()); }
        for _ in 0..8 { bc.insert("z".to_string()); }
        let top = bc.top();
        assert_eq!(top[0], ("z".to_string(), 8));
        assert_eq!(top[1], ("x".to_string(), 5));
        assert_eq!(top[2], ("y".to_string(), 2));
    }

    #[test]
    fn high_churn_at_capacity() {
        // Verifies the cached-min optimization handles rapid evictions
        let mut bc = BoundedCounter::new(50);
        for i in 0..10_000u64 {
            bc.insert(format!("ref_{i}"));
        }
        assert!(bc.len() <= 50);
    }
}
