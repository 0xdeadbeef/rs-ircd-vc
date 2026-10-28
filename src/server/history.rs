//! Bounded in-memory channel history for `draft/chathistory`.
//!
//! A message store is a storage problem before it is a protocol problem, so
//! this is deliberately small: a fixed-capacity ring per channel, no
//! persistence, no cross-server replication, and a hard ceiling on what a query
//! can return. A daemon that restarts has no history, which is the honest
//! behaviour for a server that does not own durable storage.
//!
//! The store is keyed by the folded channel name, so a query is one hash lookup
//! plus a scan over at most `capacity` entries.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};

use dashmap::DashMap;

/// One stored channel message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    /// When the message was sent (Unix seconds).
    pub at: u64,
    /// Sender mask, `nick!user@host`.
    pub prefix: String,
    /// Message body.
    pub text: String,
}

/// Which slice of the ring a query asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryRange {
    /// The most recent entries, newest last.
    Latest,
    /// Entries strictly older than the instant.
    Before(u64),
    /// Entries strictly newer than the instant.
    After(u64),
    /// Entries on both sides of the instant.
    Around(u64),
    /// Entries strictly between two instants.
    Between(u64, u64),
}

/// Per-channel bounded history.
#[derive(Debug)]
pub struct HistoryStore {
    channels: DashMap<String, VecDeque<HistoryEntry>>,
    capacity: AtomicUsize,
}

impl HistoryStore {
    /// Create a store holding at most `capacity` entries per channel.
    ///
    /// A capacity of zero disables storage entirely: `remember` returns before
    /// taking any lock.
    pub fn new(capacity: usize) -> Self {
        Self {
            channels: DashMap::new(),
            capacity: AtomicUsize::new(capacity),
        }
    }

    /// Current capacity, used by the configuration reload path.
    pub fn capacity(&self) -> usize {
        self.capacity.load(Ordering::Relaxed)
    }

    /// Change the capacity, trimming every channel that exceeds it.
    ///
    /// Set to zero, this also drops the stored rings rather than leaving them
    /// unreachable but allocated.
    pub fn set_capacity(&self, capacity: usize) {
        self.capacity.store(capacity, Ordering::Relaxed);
        if capacity == 0 {
            self.channels.clear();
            return;
        }
        for mut entry in self.channels.iter_mut() {
            while entry.value().len() > capacity {
                entry.value_mut().pop_front();
            }
        }
    }

    /// Append one message, dropping the oldest when the ring is full.
    pub fn remember(&self, channel: &str, entry: HistoryEntry) {
        let capacity = self.capacity.load(Ordering::Relaxed);
        if capacity == 0 {
            return;
        }
        let mut ring = self
            .channels
            .entry(channel.to_owned())
            .or_insert_with(|| VecDeque::with_capacity(capacity.min(64)));
        ring.push_back(entry);
        while ring.len() > capacity {
            ring.pop_front();
        }
    }

    /// Drop a channel's ring, e.g. when the channel becomes empty.
    pub fn forget(&self, channel: &str) {
        self.channels.remove(channel);
    }

    /// Number of channels with stored history.
    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }

    /// Select at most `limit` entries matching `range`, oldest first.
    ///
    /// `limit` is clamped by the caller; this method never allocates more than
    /// it was asked for and never exposes more than the ring holds.
    pub fn query(&self, channel: &str, range: HistoryRange, limit: usize) -> Vec<HistoryEntry> {
        if limit == 0 {
            return Vec::new();
        }
        let Some(ring) = self.channels.get(channel) else {
            return Vec::new();
        };
        let entries: Vec<&HistoryEntry> = match range {
            HistoryRange::Latest => ring
                .iter()
                .rev()
                .take(limit)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect(),
            HistoryRange::Before(at) => ring
                .iter()
                .rev()
                .filter(|entry| entry.at < at)
                .take(limit)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect(),
            HistoryRange::After(at) => ring
                .iter()
                .filter(|entry| entry.at > at)
                .take(limit)
                .collect(),
            HistoryRange::Between(start, end) => ring
                .iter()
                .filter(|entry| entry.at > start && entry.at < end)
                .take(limit)
                .collect(),
            HistoryRange::Around(at) => {
                let half = limit.div_ceil(2);
                let before: Vec<&HistoryEntry> = ring
                    .iter()
                    .rev()
                    .filter(|entry| entry.at <= at)
                    .take(half)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect();
                let after: Vec<&HistoryEntry> = ring
                    .iter()
                    .filter(|entry| entry.at > at)
                    .take(limit.saturating_sub(before.len()))
                    .collect();
                before.into_iter().chain(after).collect()
            }
        };
        entries.into_iter().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(at: u64, text: &str) -> HistoryEntry {
        HistoryEntry {
            at,
            prefix: "alice!a@host".to_owned(),
            text: text.to_owned(),
        }
    }

    fn filled(capacity: usize) -> HistoryStore {
        let store = HistoryStore::new(capacity);
        for at in 1..=10 {
            store.remember("#room", entry(at, &format!("line {at}")));
        }
        store
    }

    fn texts(entries: Vec<HistoryEntry>) -> Vec<String> {
        entries.into_iter().map(|entry| entry.text).collect()
    }

    #[test]
    fn ring_drops_the_oldest_entries() {
        let store = filled(4);
        assert_eq!(
            texts(store.query("#room", HistoryRange::Latest, 10)),
            ["line 7", "line 8", "line 9", "line 10"]
        );
    }

    #[test]
    fn latest_respects_its_limit() {
        let store = filled(10);
        assert_eq!(
            texts(store.query("#room", HistoryRange::Latest, 2)),
            ["line 9", "line 10"]
        );
        assert!(store.query("#room", HistoryRange::Latest, 0).is_empty());
    }

    #[test]
    fn before_and_after_are_exclusive() {
        let store = filled(10);
        assert_eq!(
            texts(store.query("#room", HistoryRange::Before(4), 2)),
            ["line 2", "line 3"]
        );
        assert_eq!(
            texts(store.query("#room", HistoryRange::After(8), 5)),
            ["line 9", "line 10"]
        );
        assert!(store.query("#room", HistoryRange::After(10), 5).is_empty());
    }

    #[test]
    fn between_uses_strict_bounds() {
        let store = filled(10);
        assert_eq!(
            texts(store.query("#room", HistoryRange::Between(3, 6), 10)),
            ["line 4", "line 5"]
        );
    }

    #[test]
    fn around_splits_the_window() {
        let store = filled(10);
        assert_eq!(
            texts(store.query("#room", HistoryRange::Around(5), 4)),
            ["line 4", "line 5", "line 6", "line 7"]
        );
    }

    #[test]
    fn zero_capacity_stores_nothing_and_trimming_forgets_old() {
        let empty = HistoryStore::new(0);
        empty.remember("#room", entry(1, "one"));
        assert!(empty.query("#room", HistoryRange::Latest, 10).is_empty());
        assert_eq!(empty.channel_count(), 0);

        let store = filled(10);
        store.set_capacity(2);
        assert_eq!(
            texts(store.query("#room", HistoryRange::Latest, 10)),
            ["line 9", "line 10"]
        );
        store.set_capacity(0);
        assert_eq!(store.channel_count(), 0);
    }

    #[test]
    fn unknown_channel_is_empty() {
        let store = filled(4);
        assert!(store.query("#other", HistoryRange::Latest, 10).is_empty());
        store.forget("#room");
        assert!(store.query("#room", HistoryRange::Latest, 10).is_empty());
    }
}
