//! Thread-safe runtime registry with lock-free concurrent access

use super::Runtime;
use crate::error::{ExecutorError, Result};
use dashmap::DashMap;
use std::sync::Arc;

/// Record an observed container status on a registry entry.
///
/// A pending entry belongs to the create that inserted it: the container exists
/// long before the build behind it is finished, so adopting its status here
/// would advertise a runtime that is still extracting code or running a build
/// command. Only the create publishes its own entry.
///
/// `failed` is the executor's verdict on a runtime that never listened, not a
/// container state. Docker still reports that container as running, so applying
/// the observation would resurrect the entry before the watchdog reaps it.
///
/// Returns whether the status was applied.
fn apply_observed_status(runtime: &mut Runtime, observed_status: String) -> bool {
    if runtime.is_pending() || runtime.is_failed() {
        return false;
    }

    runtime.status = observed_status;
    true
}

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
    #[allow(dead_code)]
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

    /// Touch a runtime only when its activity timestamp is stale enough.
    pub async fn touch_if_stale(&self, name: &str, min_interval_secs: f64) -> Result<bool> {
        if let Some(mut runtime) = self.runtimes.get_mut(name) {
            Ok(runtime.touch_if_stale(min_interval_secs))
        } else {
            Err(ExecutorError::RuntimeNotFound)
        }
    }

    /// Mark a runtime as listening on port 3000, which is also what sets
    /// `initialised`. Called after a successful TCP port check.
    pub async fn set_listening(&self, name: &str) -> Result<()> {
        if let Some(mut runtime) = self.runtimes.get_mut(name) {
            runtime.set_listening();
            Ok(())
        } else {
            Err(ExecutorError::RuntimeNotFound)
        }
    }

    /// Record that a runtime started but never listened within its startup
    /// window. The entry keeps its place in the registry with a `failed` status
    /// so `GET /v1/runtimes` shows the verdict; the listening watchdog removes it
    /// on its next cycle. Returns the runtime as it now stands.
    ///
    /// A runtime that is already listening is left alone, which closes the race
    /// against a probe that succeeded while the sweep was deciding.
    pub async fn mark_failed(&self, name: &str) -> Result<Runtime> {
        match self.runtimes.get_mut(name) {
            Some(mut runtime) => {
                if !runtime.is_listening() {
                    runtime.mark_failed();
                }
                Ok(runtime.clone())
            }
            None => Err(ExecutorError::RuntimeNotFound),
        }
    }

    /// Sync container status from Docker
    /// Updates the runtime status based on current Docker container state
    /// Returns the updated runtime if found, None otherwise
    pub async fn sync_status(
        &self,
        name: &str,
        docker: &crate::docker::DockerManager,
    ) -> Option<Runtime> {
        if !self.runtimes.contains_key(name) {
            return None;
        }

        // Clone the current entry so we do not hold a DashMap shard lock across
        // the async Docker inspect call (H2).
        let _exists = self.runtimes.contains_key(name);

        match docker.inspect_container(name).await {
            Ok(info) => {
                // Re-acquire write access only for the mutation; the async work is done.
                if let Some(mut runtime) = self.runtimes.get_mut(name) {
                    apply_observed_status(&mut runtime, info.state);
                    return Some(runtime.clone());
                }
                None
            }
            Err(ExecutorError::RuntimeNotFound) => {
                // Read current state without holding across an await.
                let is_pending = self
                    .runtimes
                    .get(name)
                    .map(|r| r.is_pending())
                    .unwrap_or(false);
                if is_pending {
                    return self.runtimes.get(name).map(|r| r.clone());
                }
                // Container was removed outside the registry — atomically remove the
                // stale metadata entry only when it is not pending.  remove_if closes
                // the TOCTOU window that existed with the previous drop+re-check+remove
                // sequence.
                self.runtimes.remove_if(name, |_, r| !r.is_pending());
                None
            }
            Err(_) => self.runtimes.get(name).map(|r| r.clone()),
        }
    }

    /// Get runtimes that have been idle for longer than they tolerate.
    ///
    /// Each runtime is measured against its own `inactiveThreshold`;
    /// `default_threshold` applies to entries that carry no value of their own.
    pub async fn get_idle(&self, default_threshold: u64) -> Vec<Runtime> {
        self.runtimes
            .iter()
            .filter(|r| r.idle_seconds() > r.effective_inactive_threshold(default_threshold))
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
    async fn test_touch_if_stale_skips_frequent_updates() {
        let registry = RuntimeRegistry::new();
        let rt = Runtime::new("test", "exec", "img", "v5", None);
        let name = rt.name.clone();
        let original_updated = rt.updated;

        registry.insert(rt).await.unwrap();

        let touched = registry.touch_if_stale(&name, 60.0).await.unwrap();
        assert!(!touched);

        let updated = registry.get(&name).await.unwrap();
        assert_eq!(updated.updated, original_updated);
    }

    #[test]
    fn test_observed_status_leaves_a_pending_entry_alone() {
        let mut runtime = Runtime::new("test", "exec", "img", "v5", None);

        let applied = apply_observed_status(&mut runtime, "running".to_string());

        assert!(!applied, "a pending entry must not take a container status");
        assert!(runtime.is_pending());
        assert_eq!(runtime.status, "pending");
        assert!(!runtime.is_running());
    }

    #[test]
    fn test_observed_status_updates_a_published_entry() {
        let mut runtime = Runtime::new("test", "exec", "img", "v5", None);
        runtime.mark_running("running");

        let applied = apply_observed_status(&mut runtime, "exited".to_string());

        assert!(applied);
        assert_eq!(runtime.status, "exited");
        assert!(!runtime.is_running());
    }

    #[tokio::test]
    async fn test_mark_failed_sets_the_status_and_clears_initialised() {
        let registry = RuntimeRegistry::new();
        let mut rt = Runtime::new("test", "exec", "img", "v5", None);
        rt.mark_running("running");
        let name = rt.name.clone();
        registry.insert(rt).await.unwrap();

        let failed = registry.mark_failed(&name).await.unwrap();
        assert!(failed.is_failed());
        assert_eq!(failed.initialised, 0);

        // Still listed, so operators can see the verdict before it is reaped.
        assert_eq!(registry.list().await.len(), 1);
    }

    #[tokio::test]
    async fn test_mark_failed_does_not_condemn_a_runtime_that_started_listening() {
        let registry = RuntimeRegistry::new();
        let mut rt = Runtime::new("test", "exec", "img", "v5", None);
        rt.mark_running("running");
        let name = rt.name.clone();
        registry.insert(rt).await.unwrap();
        registry.set_listening(&name).await.unwrap();

        let runtime = registry.mark_failed(&name).await.unwrap();
        assert!(!runtime.is_failed());
        assert_eq!(runtime.initialised, 1);
    }

    #[tokio::test]
    async fn test_get_idle_uses_the_per_runtime_threshold() {
        let registry = RuntimeRegistry::new();

        let mut patient = Runtime::new("patient", "exec", "img", "v5", None);
        patient.mark_running("running");
        patient.inactive_threshold = 3_600;
        patient.updated -= 120.0;
        let patient_name = patient.name.clone();

        let mut impatient = Runtime::new("impatient", "exec", "img", "v5", None);
        impatient.mark_running("running");
        impatient.inactive_threshold = 5;
        impatient.updated -= 120.0;
        let impatient_name = impatient.name.clone();

        registry.insert(patient).await.unwrap();
        registry.insert(impatient).await.unwrap();

        let idle = registry.get_idle(60).await;
        let idle_names: Vec<&str> = idle.iter().map(|r| r.name.as_str()).collect();

        assert_eq!(idle_names, vec![impatient_name.as_str()]);
        assert!(!idle_names.contains(&patient_name.as_str()));
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
