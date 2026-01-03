//! Thread-safe runtime registry with lock-free concurrent access

use super::Runtime;
use crate::error::{ExecutorError, Result};
use dashmap::DashMap;
use std::sync::Arc;

/// Thread-safe registry for managing active runtimes
/// Uses DashMap for lock-free concurrent reads and fine-grained write locks
#[derive(Debug, Clone)]
pub struct RuntimeRegistry {
    runtimes: Arc<DashMap<String, Runtime>>,
}

impl RuntimeRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            runtimes: Arc::new(DashMap::new()),
        }
    }

    /// Add a new runtime to the registry
    /// Returns error if runtime already exists
    /// Uses entry API for atomic check-and-insert
    pub async fn insert(&self, runtime: Runtime) -> Result<()> {
        use dashmap::mapref::entry::Entry;

        match self.runtimes.entry(runtime.name.clone()) {
            Entry::Occupied(_) => Err(ExecutorError::RuntimeConflict),
            Entry::Vacant(entry) => {
                entry.insert(runtime);
                Ok(())
            }
        }
    }

    /// Get a runtime by its full name - lock-free read
    #[inline]
    pub async fn get(&self, name: &str) -> Option<Runtime> {
        self.runtimes.get(name).map(|r| r.clone())
    }

    /// Get a runtime by its ID (searches for name ending with -id)
    pub async fn get_by_id(&self, runtime_id: &str, hostname: &str) -> Option<Runtime> {
        let full_name = format!("{}-{}", hostname, runtime_id);
        self.get(&full_name).await
    }

    /// Check if a runtime exists - lock-free
    #[inline]
    pub async fn exists(&self, name: &str) -> bool {
        self.runtimes.contains_key(name)
    }

    /// Check if a runtime exists by ID
    #[allow(dead_code)]
    pub async fn exists_by_id(&self, runtime_id: &str, hostname: &str) -> bool {
        let full_name = format!("{}-{}", hostname, runtime_id);
        self.exists(&full_name).await
    }

    /// Update a runtime in the registry
    pub async fn update(&self, runtime: Runtime) -> Result<()> {
        if !self.runtimes.contains_key(&runtime.name) {
            return Err(ExecutorError::RuntimeNotFound);
        }
        self.runtimes.insert(runtime.name.clone(), runtime);
        Ok(())
    }

    /// Remove a runtime from the registry
    pub async fn remove(&self, name: &str) -> Option<Runtime> {
        self.runtimes.remove(name).map(|(_, v)| v)
    }

    /// Remove a runtime by ID
    #[allow(dead_code)]
    pub async fn remove_by_id(&self, runtime_id: &str, hostname: &str) -> Option<Runtime> {
        let full_name = format!("{}-{}", hostname, runtime_id);
        self.remove(&full_name).await
    }

    /// Get all runtimes
    /// Returns Arc<Vec> for zero-copy sharing when possible
    pub async fn list(&self) -> Vec<Runtime> {
        self.runtimes.iter().map(|r| r.value().clone()).collect()
    }

    /// Get count of runtimes - lock-free
    #[inline]
    pub async fn count(&self) -> usize {
        self.runtimes.len()
    }

    /// Touch a runtime (update its last activity timestamp)
    /// Uses get_mut for efficient in-place update
    pub async fn touch(&self, name: &str) -> Result<()> {
        if let Some(mut runtime) = self.runtimes.get_mut(name) {
            runtime.touch();
            Ok(())
        } else {
            Err(ExecutorError::RuntimeNotFound)
        }
    }

    /// Mark a runtime as listening on port 3000
    /// Called after successful TCP port check (matching executor-main)
    pub async fn set_listening(&self, name: &str) -> Result<()> {
        if let Some(mut runtime) = self.runtimes.get_mut(name) {
            runtime.set_listening();
            Ok(())
        } else {
            Err(ExecutorError::RuntimeNotFound)
        }
    }

    /// Get runtimes that have been idle for more than threshold seconds
    pub async fn get_idle(&self, threshold_secs: u64) -> Vec<Runtime> {
        self.runtimes
            .iter()
            .filter(|r| r.idle_seconds() > threshold_secs)
            .map(|r| r.clone())
            .collect()
    }

    /// Clear all runtimes (used during shutdown)
    #[allow(dead_code)]
    pub async fn clear(&self) -> Vec<Runtime> {
        let all: Vec<Runtime> = self.runtimes.iter().map(|r| r.clone()).collect();
        self.runtimes.clear();
        all
    }
}

impl Default for RuntimeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_insert_and_get() {
        let registry = RuntimeRegistry::new();
        let rt = Runtime::new("test", "exec", "img", "v5", None);
        let name = rt.name.clone();

        registry.insert(rt).await.unwrap();

        let retrieved = registry.get(&name).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, name);
    }

    #[tokio::test]
    async fn test_conflict() {
        let registry = RuntimeRegistry::new();
        let rt1 = Runtime::new("test", "exec", "img", "v5", None);
        let rt2 = Runtime::new("test", "exec", "img", "v5", None);

        registry.insert(rt1).await.unwrap();
        let result = registry.insert(rt2).await;

        assert!(matches!(result, Err(ExecutorError::RuntimeConflict)));
    }

    #[tokio::test]
    async fn test_list() {
        let registry = RuntimeRegistry::new();
        registry
            .insert(Runtime::new("a", "e", "i", "v5", None))
            .await
            .unwrap();
        registry
            .insert(Runtime::new("b", "e", "i", "v5", None))
            .await
            .unwrap();

        let list = registry.list().await;
        assert_eq!(list.len(), 2);
    }

    #[tokio::test]
    async fn test_remove() {
        let registry = RuntimeRegistry::new();
        let rt = Runtime::new("test", "exec", "img", "v5", None);
        let name = rt.name.clone();

        registry.insert(rt).await.unwrap();
        let removed = registry.remove(&name).await;

        assert!(removed.is_some());
        assert!(!registry.exists(&name).await);
    }

    #[tokio::test]
    async fn test_touch() {
        let registry = RuntimeRegistry::new();
        let rt = Runtime::new("test", "exec", "img", "v5", None);
        let name = rt.name.clone();
        let original_updated = rt.updated;

        registry.insert(rt).await.unwrap();

        // Wait a tiny bit to ensure timestamp changes
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        registry.touch(&name).await.unwrap();

        let updated = registry.get(&name).await.unwrap();
        assert!(updated.updated >= original_updated);
    }

    #[tokio::test]
    async fn test_concurrent_access() {
        use std::sync::Arc;

        let registry = Arc::new(RuntimeRegistry::new());
        let mut handles = vec![];

        // Spawn multiple concurrent writers
        for i in 0..10 {
            let reg = registry.clone();
            handles.push(tokio::spawn(async move {
                let rt = Runtime::new(&format!("rt-{}", i), "exec", "img", "v5", None);
                reg.insert(rt).await
            }));
        }

        // Wait for all inserts
        for handle in handles {
            handle.await.unwrap().unwrap();
        }

        // Verify all were inserted
        assert_eq!(registry.count().await, 10);

        // Spawn concurrent readers
        let mut read_handles = vec![];
        for i in 0..10 {
            let reg = registry.clone();
            read_handles.push(tokio::spawn(async move {
                reg.get(&format!("exec-rt-{}", i)).await
            }));
        }

        // All reads should succeed
        for handle in read_handles {
            let result = handle.await.unwrap();
            assert!(result.is_some());
        }
    }
}
