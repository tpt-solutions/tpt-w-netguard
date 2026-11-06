// SPDX-License-Identifier: MIT OR Apache-2.0
//! Cache of reverse-DNS names for remote addresses, shown next to connections.
//!
//! The cache only decides *what* needs a lookup and *how long* an answer lives. The network
//! work (done through the encrypted DNS resolver) happens in the app shell, so this module
//! stays pure and testable.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

/// How long a found name is kept before it is looked up again.
pub const NAME_TTL_MS: u64 = 60 * 60 * 1000;
/// How long "no name" (no PTR record, or a failed lookup) is kept. Shorter, so that transient
/// failures recover without waiting an hour.
pub const NEGATIVE_TTL_MS: u64 = 10 * 60 * 1000;

#[derive(Debug, Clone)]
struct Entry {
    name: Option<String>,
    at_ms: u64,
}

impl Entry {
    fn ttl_ms(&self) -> u64 {
        if self.name.is_some() {
            NAME_TTL_MS
        } else {
            NEGATIVE_TTL_MS
        }
    }
}

#[derive(Debug, Default)]
pub struct NameCache {
    entries: HashMap<IpAddr, Entry>,
    /// Addresses queued for a lookup that has not finished yet.
    in_flight: HashSet<IpAddr>,
}

impl NameCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// The last known name for `ip`, even if it is due for refresh. `None` when unknown or when
    /// the last lookup found nothing.
    pub fn name(&self, ip: IpAddr) -> Option<&str> {
        self.entries.get(&ip).and_then(|e| e.name.as_deref())
    }

    /// Whether `ip` should be queued now: it has no fresh answer and no lookup is pending.
    pub fn needs_lookup(&self, ip: IpAddr, now_ms: u64) -> bool {
        if self.in_flight.contains(&ip) {
            return false;
        }
        match self.entries.get(&ip) {
            None => true,
            Some(entry) => now_ms.saturating_sub(entry.at_ms) >= entry.ttl_ms(),
        }
    }

    /// Marks `ip` as queued. Returns `false` if it already was, so callers never queue twice.
    pub fn mark_queued(&mut self, ip: IpAddr) -> bool {
        self.in_flight.insert(ip)
    }

    /// Undoes `mark_queued` when the work could not be handed to a worker.
    pub fn cancel(&mut self, ip: IpAddr) {
        self.in_flight.remove(&ip);
    }

    /// Records the outcome of a lookup. `None` means no name was found or the lookup failed.
    pub fn complete(&mut self, ip: IpAddr, name: Option<String>, now_ms: u64) {
        self.in_flight.remove(&ip);
        self.entries.insert(
            ip,
            Entry {
                name,
                at_ms: now_ms,
            },
        );
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([203, 0, 113, last])
    }

    #[test]
    fn unknown_addresses_need_a_lookup_once() {
        let mut cache = NameCache::new();
        assert!(cache.needs_lookup(ip(1), 0));
        assert!(cache.mark_queued(ip(1)));
        assert!(
            !cache.needs_lookup(ip(1), 0),
            "pending lookups are not queued again"
        );
        assert!(!cache.mark_queued(ip(1)));
    }

    #[test]
    fn found_names_are_served_until_they_expire() {
        let mut cache = NameCache::new();
        cache.mark_queued(ip(1));
        cache.complete(ip(1), Some("example.net".into()), 1_000);
        assert_eq!(cache.name(ip(1)), Some("example.net"));
        assert!(!cache.needs_lookup(ip(1), 1_000 + NAME_TTL_MS - 1));
        assert!(cache.needs_lookup(ip(1), 1_000 + NAME_TTL_MS));
        // The stale name is still shown while the refresh runs.
        assert_eq!(cache.name(ip(1)), Some("example.net"));
    }

    #[test]
    fn negative_answers_expire_sooner() {
        let mut cache = NameCache::new();
        cache.complete(ip(2), None, 0);
        assert_eq!(cache.name(ip(2)), None);
        assert!(!cache.needs_lookup(ip(2), NEGATIVE_TTL_MS - 1));
        assert!(cache.needs_lookup(ip(2), NEGATIVE_TTL_MS));
    }

    #[test]
    fn a_cancelled_queue_entry_can_be_queued_again() {
        let mut cache = NameCache::new();
        assert!(cache.mark_queued(ip(3)));
        cache.cancel(ip(3));
        assert!(cache.needs_lookup(ip(3), 0));
        assert!(cache.mark_queued(ip(3)));
    }

    #[test]
    fn completing_a_lookup_clears_its_pending_mark() {
        let mut cache = NameCache::new();
        cache.mark_queued(ip(4));
        cache.complete(ip(4), None, 5);
        assert_eq!(cache.len(), 1);
        assert!(!cache.is_empty());
        assert!(cache.needs_lookup(ip(4), 5 + NEGATIVE_TTL_MS));
    }
}
