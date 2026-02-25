//! Keep-alive ID registry for protecting runtimes from cleanup
//!
//! A runtime with a keep_alive_id is protected from cleanup as long as it
//! "owns" that ID. Ownership is transferred when a new runtime starts with
//! the same keep_alive_id.

use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, OwnedMutexGuard};

/// Registry tracking which runtime owns each keep-alive ID
#[derive(Debug, Clone)]
pub struct KeepAliveRegistry {
    /// Maps keep_alive_id -> runtime_name (the owner)
    owners: Arc<DashMap<String, String>>,
    /// Monotonic generation counter per keep-alive ID.
    generations: Arc<DashMap<String, u64>>,
    /// Per keep-alive ID lock to serialize ownership transfer/replacement.
    locks: Arc<DashMap<String, Arc<Mutex<()>>>>,
}

impl KeepAliveRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            owners: Arc::new(DashMap::new()),
            generations: Arc::new(DashMap::new()),
            locks: Arc::new(DashMap::new()),
        }
    }

    /// Register a runtime as the owner of a keep-alive ID.
    /// Returns the previous owner's runtime name if there was one.
    pub fn register(&self, keep_alive_id: &str, runtime_name: &str) -> Option<String> {
        self.register_with_generation(keep_alive_id, runtime_name).0
    }

    /// Register ownership and return `(previous_owner, new_generation)`.
    pub fn register_with_generation(
        &self,
        keep_alive_id: &str,
        runtime_name: &str,
    ) -> (Option<String>, u64) {
        let generation = if let Some(mut entry) = self.generations.get_mut(keep_alive_id) {
            *entry = entry.saturating_add(1);
            *entry
        } else {
            self.generations.insert(keep_alive_id.to_string(), 1);
            1
        };

        let previous_owner = self
            .owners
            .insert(keep_alive_id.to_string(), runtime_name.to_string());

        (previous_owner, generation)
    }

    /// Restore ownership without incrementing generation (used by adoption/reconciliation).
    pub fn restore_owner(&self, keep_alive_id: &str, runtime_name: &str) -> Option<String> {
        self.owners
            .insert(keep_alive_id.to_string(), runtime_name.to_string())
    }

    /// Track an externally-observed generation (for adoption/reconciliation).
    pub fn observe_generation(&self, keep_alive_id: &str, observed_generation: u64) {
        if observed_generation == 0 {
            return;
        }

        if let Some(mut entry) = self.generations.get_mut(keep_alive_id) {
            if observed_generation > *entry {
                *entry = observed_generation;
            }
        } else {
            self.generations
                .insert(keep_alive_id.to_string(), observed_generation);
        }
    }

    /// Return the current generation for a keep-alive ID.
    #[allow(dead_code)]
    pub fn current_generation(&self, keep_alive_id: &str) -> Option<u64> {
        self.generations.get(keep_alive_id).map(|g| *g.value())
    }

    /// Acquire a per keep-alive ID lock for serialized replacement flow.
    pub async fn lock(&self, keep_alive_id: &str) -> OwnedMutexGuard<()> {
        let lock = self
            .locks
            .entry(keep_alive_id.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        lock.lock_owned().await
    }

    /// Unregister a runtime's ownership (call when runtime is removed).
    /// Only removes if this runtime is still the owner.
    pub fn unregister(&self, keep_alive_id: &str, runtime_name: &str) {
        let removed = self
            .owners
            .remove_if(keep_alive_id, |_, owner| owner == runtime_name)
            .is_some();

        if removed && !self.owners.contains_key(keep_alive_id) {
            self.generations.remove(keep_alive_id);
            self.locks.remove(keep_alive_id);
        }
    }

    /// Check if a runtime owns its keep-alive ID
    pub fn is_owner(&self, keep_alive_id: &str, runtime_name: &str) -> bool {
        self.owners
            .get(keep_alive_id)
            .map(|owner| owner.value() == runtime_name)
            .unwrap_or(false)
    }

    /// Get the owner runtime name for a keep-alive ID
    #[allow(dead_code)]
    pub fn get_owner(&self, keep_alive_id: &str) -> Option<String> {
        self.owners.get(keep_alive_id).map(|r| r.value().clone())
    }

    /// Get all registered keep-alive IDs and their owners
    pub fn get_all_owners(&self) -> Vec<(String, String)> {
        self.owners
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }
}

impl Default for KeepAliveRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_new_owner() {
        let registry = KeepAliveRegistry::new();

        // First registration returns None (no previous owner)
        let prev = registry.register("my-service", "runtime-a");
        assert!(prev.is_none());

        assert!(registry.is_owner("my-service", "runtime-a"));
        assert!(!registry.is_owner("my-service", "runtime-b"));
    }

    #[test]
    fn test_register_transfers_ownership() {
        let registry = KeepAliveRegistry::new();

        registry.register("my-service", "runtime-a");
        assert!(registry.is_owner("my-service", "runtime-a"));

        // New runtime takes over ownership
        let prev = registry.register("my-service", "runtime-b");
        assert_eq!(prev, Some("runtime-a".to_string()));

        // Old runtime no longer owner
        assert!(!registry.is_owner("my-service", "runtime-a"));
        assert!(registry.is_owner("my-service", "runtime-b"));
    }

    #[test]
    fn test_unregister_only_if_owner() {
        let registry = KeepAliveRegistry::new();

        registry.register("my-service", "runtime-a");

        // Try to unregister with wrong runtime name - should not remove
        registry.unregister("my-service", "runtime-b");
        assert!(registry.is_owner("my-service", "runtime-a"));

        // Unregister with correct runtime name
        registry.unregister("my-service", "runtime-a");
        assert!(!registry.is_owner("my-service", "runtime-a"));
    }

    #[test]
    fn test_get_owner() {
        let registry = KeepAliveRegistry::new();

        assert!(registry.get_owner("my-service").is_none());

        registry.register("my-service", "runtime-a");
        assert_eq!(
            registry.get_owner("my-service"),
            Some("runtime-a".to_string())
        );
    }

    #[test]
    fn test_multiple_keep_alive_ids() {
        let registry = KeepAliveRegistry::new();

        registry.register("service-a", "runtime-1");
        registry.register("service-b", "runtime-2");

        assert!(registry.is_owner("service-a", "runtime-1"));
        assert!(registry.is_owner("service-b", "runtime-2"));
        assert!(!registry.is_owner("service-a", "runtime-2"));
        assert!(!registry.is_owner("service-b", "runtime-1"));
    }

    #[test]
    fn test_register_with_generation_monotonic() {
        let registry = KeepAliveRegistry::new();

        let (prev_1, gen_1) = registry.register_with_generation("svc", "runtime-a");
        let (prev_2, gen_2) = registry.register_with_generation("svc", "runtime-b");

        assert!(prev_1.is_none());
        assert_eq!(prev_2, Some("runtime-a".to_string()));
        assert_eq!(gen_1, 1);
        assert_eq!(gen_2, 2);
        assert_eq!(registry.current_generation("svc"), Some(2));
    }

    #[test]
    fn test_observe_generation_advances_counter() {
        let registry = KeepAliveRegistry::new();

        registry.observe_generation("svc", 12);
        let (_, generation) = registry.register_with_generation("svc", "runtime-a");

        assert_eq!(generation, 13);
    }
}
