//! Short-lived memory of container names Docker does not know about.
//!
//! An execution for a runtime that is neither in the registry nor mid-create
//! ends with an adoption attempt, and that attempt costs one `inspect` against
//! the Docker daemon. A bot sweeping unknown IDs therefore turns into one
//! daemon call per request. Remembering the miss for a couple of seconds cuts
//! that to one call per name per TTL, which is short enough that a container
//! that genuinely appears is still adopted almost immediately.

use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Point at which a sweep of expired entries is worthwhile. A scan against
/// random IDs would otherwise grow the map without bound.
const PRUNE_THRESHOLD: usize = 1024;

/// Records, per container name, when adoption last found nothing.
#[derive(Clone)]
pub struct AdoptionNegativeCache {
    entries: Arc<DashMap<String, Instant>>,
    ttl: Duration,
}

impl AdoptionNegativeCache {
    /// Create a cache whose entries expire after `ttl`.
    ///
    /// A zero `ttl` disables the cache: every lookup goes to Docker.
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: Arc::new(DashMap::new()),
            ttl,
        }
    }

    /// Whether adoption for `name` recently came back empty.
    pub fn is_absent(&self, name: &str) -> bool {
        if self.ttl.is_zero() {
            return false;
        }

        let fresh = self
            .entries
            .get(name)
            .map(|recorded| recorded.elapsed() < self.ttl);

        match fresh {
            Some(true) => true,
            Some(false) => {
                self.entries.remove(name);
                false
            }
            None => false,
        }
    }

    /// Record that Docker has no container under `name`.
    pub fn record_absent(&self, name: &str) {
        if self.ttl.is_zero() {
            return;
        }

        if self.entries.len() >= PRUNE_THRESHOLD {
            self.prune();
        }

        self.entries.insert(name.to_string(), Instant::now());
    }

    /// Drop any record for `name`, so the next request goes to Docker.
    pub fn forget(&self, name: &str) {
        if self.ttl.is_zero() {
            return;
        }

        self.entries.remove(name);
    }

    /// Number of names currently remembered. Test and diagnostics only.
    #[allow(dead_code)]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    fn prune(&self) {
        let ttl = self.ttl;
        self.entries.retain(|_, recorded| recorded.elapsed() < ttl);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_recorded_miss_is_remembered() {
        let cache = AdoptionNegativeCache::new(Duration::from_secs(2));
        assert!(!cache.is_absent("exc1-fn-1"));

        cache.record_absent("exc1-fn-1");
        assert!(cache.is_absent("exc1-fn-1"));
        assert!(!cache.is_absent("exc1-fn-2"));
    }

    #[test]
    fn a_miss_is_forgotten_once_the_ttl_has_passed() {
        let cache = AdoptionNegativeCache::new(Duration::from_millis(1));
        cache.record_absent("exc1-fn-1");
        std::thread::sleep(Duration::from_millis(5));

        assert!(!cache.is_absent("exc1-fn-1"));
        assert_eq!(
            cache.entry_count(),
            0,
            "an expired entry is dropped when read"
        );
    }

    #[test]
    fn adopting_a_runtime_clears_its_record() {
        let cache = AdoptionNegativeCache::new(Duration::from_secs(60));
        cache.record_absent("exc1-fn-1");
        cache.forget("exc1-fn-1");

        assert!(!cache.is_absent("exc1-fn-1"));
    }

    #[test]
    fn a_zero_ttl_disables_the_cache() {
        let cache = AdoptionNegativeCache::new(Duration::ZERO);
        cache.record_absent("exc1-fn-1");

        assert!(!cache.is_absent("exc1-fn-1"));
        assert_eq!(cache.entry_count(), 0);
    }

    #[test]
    fn a_scan_over_random_names_does_not_grow_without_bound() {
        let cache = AdoptionNegativeCache::new(Duration::from_millis(1));
        for index in 0..PRUNE_THRESHOLD {
            cache.record_absent(&format!("exc1-scan-{index}"));
        }
        std::thread::sleep(Duration::from_millis(5));

        cache.record_absent("exc1-scan-last");
        assert_eq!(cache.entry_count(), 1);
    }
}
