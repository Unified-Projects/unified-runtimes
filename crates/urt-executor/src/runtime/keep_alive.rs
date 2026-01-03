//! Keep-alive ID registry for protecting runtimes from cleanup
//!
//! A runtime with a keep_alive_id is protected from cleanup as long as it
//! "owns" that ID. Ownership is transferred when a new runtime starts with
//! the same keep_alive_id.

use dashmap::DashMap;
use std::sync::Arc;

/// Registry tracking which runtime owns each keep-alive ID
#[derive(Debug, Clone)]
pub struct KeepAliveRegistry {
    /// Maps keep_alive_id -> runtime_name (the owner)
    owners: Arc<DashMap<String, String>>,
}

impl KeepAliveRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            owners: Arc::new(DashMap::new()),
        }
    }

    /// Register a runtime as the owner of a keep-alive ID.
    /// Returns the previous owner's runtime name if there was one.
    pub fn register(&self, keep_alive_id: &str, runtime_name: &str) -> Option<String> {
        self.owners
            .insert(keep_alive_id.to_string(), runtime_name.to_string())
    }

    /// Unregister a runtime's ownership (call when runtime is removed).
    /// Only removes if this runtime is still the owner.
    pub fn unregister(&self, keep_alive_id: &str, runtime_name: &str) {
        self.owners
            .remove_if(keep_alive_id, |_, owner| owner == runtime_name);
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
}
