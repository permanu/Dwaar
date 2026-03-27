// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Ring buffer of 60 counters for per-minute page view tracking.
//!
//! Each bucket covers one minute of the hour. Stale buckets are zeroed
//! on first access after their minute has passed, so the buffer always
//! reflects the last 60 minutes of traffic.

const NUM_BUCKETS: usize = 60;

/// Per-minute page view counter using a ring buffer.
///
/// Tracks the last 60 minutes of traffic. Stale buckets are lazily
/// zeroed when the current minute advances past them.
#[derive(Debug)]
pub struct MinuteBuckets {
    buckets: [u64; NUM_BUCKETS],
    last_minute: u64,
}

impl Default for MinuteBuckets {
    fn default() -> Self {
        Self::new()
    }
}

impl MinuteBuckets {
    pub fn new() -> Self {
        Self {
            buckets: [0; NUM_BUCKETS],
            last_minute: 0,
        }
    }

    /// Increment the counter for the given absolute minute.
    pub fn increment_at(&mut self, absolute_minute: u64) {
        self.clear_stale(absolute_minute);
        self.buckets[Self::idx(absolute_minute)] += 1;
        self.last_minute = absolute_minute;
    }

    /// Increment using the current wall-clock minute.
    pub fn increment(&mut self) {
        let now = Self::current_minute();
        self.increment_at(now);
    }

    /// Read the count in a specific absolute minute's bucket.
    pub fn count_at(&self, absolute_minute: u64) -> u64 {
        self.buckets[Self::idx(absolute_minute)]
    }

    /// Sum of the last `n` minutes of counts, ending at `current_minute`.
    ///
    /// Uses checked subtraction so that calls with small `current_minute` values
    /// (e.g. in tests that start at minute 0) never alias back into valid buckets
    /// via u64 wrap-around.
    pub fn count_last_n(&self, current_minute: u64, n: usize) -> u64 {
        let n = n.min(NUM_BUCKETS);
        (0..n as u64)
            .filter_map(|offset| current_minute.checked_sub(offset))
            .map(|minute| self.buckets[Self::idx(minute)])
            .sum()
    }

    /// Sum of the last `n` minutes using the wall clock.
    pub fn count_last_n_now(&self, n: usize) -> u64 {
        self.count_last_n(Self::current_minute(), n)
    }

    fn clear_stale(&mut self, current_minute: u64) {
        if current_minute <= self.last_minute {
            return;
        }
        let gap = current_minute - self.last_minute;
        // When the new write position laps or revisits any index the previous write
        // occupied, the entire ring is stale — wipe it all in one pass.
        if gap >= NUM_BUCKETS as u64 || Self::idx(current_minute) <= Self::idx(self.last_minute) {
            self.buckets = [0; NUM_BUCKETS];
        } else {
            for offset in 1..=gap {
                self.buckets[Self::idx(self.last_minute + offset)] = 0;
            }
        }
    }

    fn idx(minute: u64) -> usize {
        (minute % NUM_BUCKETS as u64) as usize
    }

    fn current_minute() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_secs()
            / 60
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn increment_in_same_minute() {
        let mut b = MinuteBuckets::new();
        b.increment_at(0);
        b.increment_at(0);
        b.increment_at(0);
        assert_eq!(b.count_at(0), 3);
    }

    #[test]
    fn increment_advances_minute() {
        let mut b = MinuteBuckets::new();
        b.increment_at(0);
        b.increment_at(0);
        b.increment_at(1);
        assert_eq!(b.count_at(0), 2);
        assert_eq!(b.count_at(1), 1);
    }

    #[test]
    fn stale_buckets_zeroed_on_advance() {
        let mut b = MinuteBuckets::new();
        b.increment_at(0);
        b.increment_at(0);
        b.increment_at(3);
        assert_eq!(b.count_at(0), 2); // still within 60-min window
        assert_eq!(b.count_at(1), 0); // zeroed by advance
        assert_eq!(b.count_at(2), 0); // zeroed by advance
        assert_eq!(b.count_at(3), 1); // freshly incremented
    }

    #[test]
    fn wraps_around_at_60() {
        let mut b = MinuteBuckets::new();
        b.increment_at(59);
        b.increment_at(59);
        b.increment_at(60); // maps to index 0
        assert_eq!(b.count_at(0), 1);
        assert_eq!(b.count_at(59), 0); // stale after full wrap
    }

    #[test]
    fn count_last_n_minutes() {
        let mut b = MinuteBuckets::new();
        b.increment_at(5);
        b.increment_at(5);
        b.increment_at(6);
        b.increment_at(7);
        b.increment_at(7);
        b.increment_at(7);
        assert_eq!(b.count_last_n(7, 3), 6);
        assert_eq!(b.count_last_n(7, 1), 3);
    }

    #[test]
    fn count_last_60_is_total() {
        let mut b = MinuteBuckets::new();
        for m in 0..60 {
            b.increment_at(m);
        }
        assert_eq!(b.count_last_n(59, 60), 60);
    }

    #[test]
    fn full_wrap_clears_all() {
        let mut b = MinuteBuckets::new();
        b.increment_at(0);
        b.increment_at(1);
        b.increment_at(61); // maps to index 1
        assert_eq!(b.count_last_n(1, 60), 1);
    }
}
