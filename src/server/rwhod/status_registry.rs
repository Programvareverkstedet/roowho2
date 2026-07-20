use std::collections::{BTreeSet, HashMap};

use chrono::{DateTime, Utc};

use crate::proto::WhodStatusUpdate;

/// A bounded collection of rwhod status updates, keyed by hostname.
///
/// This exists to put a hard cap on memory usage regardless of how many
/// distinct hostnames a (potentially malicious) sender on the LAN tries to
/// report. When the registry is at capacity and an update for a
/// previously-unseen hostname comes in, the entry with the oldest
/// `recvtime` is evicted to make room for it. Hosts that keep broadcasting
/// periodically naturally stay "recent" and are never evicted by this.
#[derive(Debug)]
pub struct RwhodStatusRegistry {
    max_entries: usize,
    by_hostname: HashMap<String, WhodStatusUpdate>,
    by_recvtime: BTreeSet<(DateTime<Utc>, String)>,
}

impl RwhodStatusRegistry {
    pub fn new(max_entries: usize) -> Self {
        Self {
            max_entries,
            by_hostname: HashMap::new(),
            by_recvtime: BTreeSet::new(),
        }
    }

    /// Insert or refresh a status update, keyed by its hostname.
    ///
    /// If the registry is at capacity and `status_update` is for a
    /// previously-unseen hostname, the entry with the oldest `recvtime`
    /// will be evicted to make room for it.
    pub fn upsert(&mut self, status_update: WhodStatusUpdate) {
        let Some(recvtime) = status_update.recvtime else {
            tracing::warn!(
                "Refusing to store whod status update from '{}' with no recvtime set",
                status_update.hostname
            );
            return;
        };

        if self.max_entries == 0 {
            tracing::warn!(
                "rwhod status registry capacity is 0; dropping update from '{}'",
                status_update.hostname
            );
            return;
        }

        let is_known_hostname =
            if let Some(previous) = self.by_hostname.get(&status_update.hostname) {
                if let Some(previous_recvtime) = previous.recvtime {
                    self.by_recvtime
                        .remove(&(previous_recvtime, status_update.hostname.clone()));
                }
                true
            } else {
                false
            };

        if !is_known_hostname
            && self.by_hostname.len() >= self.max_entries
            && let Some((stale_recvtime, stale_hostname)) = self.by_recvtime.pop_first()
        {
            tracing::warn!(
                "rwhod status registry at capacity ({} entries); evicting stalest entry '{}' (last seen {}) to make room for '{}'",
                self.max_entries,
                stale_hostname,
                stale_recvtime,
                status_update.hostname
            );
            self.by_hostname.remove(&stale_hostname);
        }

        self.by_recvtime
            .insert((recvtime, status_update.hostname.clone()));
        self.by_hostname
            .insert(status_update.hostname.clone(), status_update);
    }

    pub fn len(&self) -> usize {
        self.by_hostname.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_hostname.is_empty()
    }

    pub fn values(&self) -> impl Iterator<Item = &WhodStatusUpdate> {
        self.by_hostname.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status_update_at(hostname: &str, recvtime_secs: i64) -> WhodStatusUpdate {
        let now = DateTime::from_timestamp(recvtime_secs, 0).unwrap();
        WhodStatusUpdate::new(now, Some(now), hostname.to_string(), (0, 0, 0), now, vec![])
    }

    #[test]
    fn test_upsert_evicts_stalest_entry_when_at_capacity() {
        let mut registry = RwhodStatusRegistry::new(2);

        registry.upsert(status_update_at("a", 1));
        registry.upsert(status_update_at("b", 2));
        assert_eq!(registry.len(), 2);

        registry.upsert(status_update_at("c", 3));

        assert_eq!(registry.len(), 2);
        let hostnames: std::collections::HashSet<_> =
            registry.values().map(|u| u.hostname.as_str()).collect();
        assert_eq!(hostnames, std::collections::HashSet::from(["b", "c"]));
    }

    #[test]
    fn test_upsert_refresh_does_not_evict_itself() {
        let mut registry = RwhodStatusRegistry::new(2);

        registry.upsert(status_update_at("a", 1));
        registry.upsert(status_update_at("a", 2));

        assert_eq!(registry.len(), 1);
        assert_eq!(
            registry.values().next().unwrap().recvtime,
            Some(DateTime::from_timestamp(2, 0).unwrap())
        );
    }

    #[test]
    fn test_upsert_with_zero_capacity_drops_everything() {
        let mut registry = RwhodStatusRegistry::new(0);

        registry.upsert(status_update_at("a", 1));

        assert!(registry.is_empty());
    }

    #[test]
    fn test_refreshing_a_hostname_does_not_count_against_capacity() {
        let mut registry = RwhodStatusRegistry::new(3);

        registry.upsert(status_update_at("a", 1));
        registry.upsert(status_update_at("a", 2));
        registry.upsert(status_update_at("a", 3));

        assert_eq!(registry.len(), 1);
    }
}
