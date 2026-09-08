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

    /// Record that the container behind `name` has stopped: status, exit code
    /// and the listening flag are updated so the next execution probes again.
    ///
    /// Returns the updated entry and whether it was `running` beforehand, so a
    /// death observed twice (events task and execution path) is counted once.
    pub async fn mark_dead(
        &self,
        name: &str,
        status: &str,
        exit_code: Option<i64>,
    ) -> Option<(Runtime, bool)> {
        self.runtimes.get_mut(name).map(|mut runtime| {
            let was_running = runtime.is_running();
            runtime.mark_dead(status, exit_code);
            (runtime.clone(), was_running)
        })
    }

    /// Overwrite the status of `name` without touching anything else.
    pub async fn set_status(&self, name: &str, status: &str) -> Option<Runtime> {
        self.runtimes.get_mut(name).map(|mut runtime| {
            runtime.status = status.to_string();
            runtime.clone()
        })
    }

    /// Put `name` into quarantine until the given Unix timestamp.
    pub async fn mark_quarantined(
        &self,
        name: &str,
        until: f64,
        exit_code: Option<i64>,
    ) -> Option<Runtime> {
        self.runtimes.get_mut(name).map(|mut runtime| {
            runtime.mark_quarantined(until, exit_code);
            runtime.clone()
        })
    }

    /// Remove the entry for `name` only while it is quarantined.
    pub async fn remove_if_quarantined(&self, name: &str) -> Option<Runtime> {
        self.runtimes
            .remove_if(name, |_, runtime| runtime.is_quarantined())
            .map(|(_, runtime)| runtime)
    }

    /// Apply a fresh Docker inspect result to the entry for `name`.
    ///
    /// A container that is not running loses its listening flag, and a rising
    /// restart count is carried over so callers can tell that Docker restarted
    /// it since the last sync. Returns the updated entry.
    pub fn apply_container_state(
        &self,
        name: &str,
        info: &crate::docker::container::ContainerInfo,
    ) -> Option<Runtime> {
        self.runtimes.get_mut(name).map(|mut runtime| {
            if runtime.is_quarantined() {
                return runtime.clone();
            }
            runtime.status = info.state.clone();
            runtime.restart_count = info.restart_count;
            if !info.state.eq_ignore_ascii_case("running") {
                runtime.listening = 0;
                if info.exit_code.is_some() {
                    runtime.last_exit_code = info.exit_code;
                }
            }
            runtime.clone()
        })
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

        // The Docker inspect runs without any DashMap shard lock held; write
        // access is re-acquired only for the mutation afterwards.
        match docker.inspect_container(name).await {
            Ok(info) => self.apply_container_state(name, &info),
            Err(ExecutorError::RuntimeNotFound) => {
                // Pending entries belong to a create that is still running and
                // quarantined entries are kept as a visible record until the
                // quarantine expires; neither is dropped because the container
                // is absent.
                let keep = self
                    .runtimes
                    .get(name)
                    .map(|r| r.is_pending() || r.is_quarantined())
                    .unwrap_or(false);
                if keep {
                    return self.runtimes.get(name).map(|r| r.clone());
                }
                // Container was removed outside the registry: drop the stale
                // metadata entry atomically so a concurrent state change cannot
                // slip between the check and the removal.
                self.runtimes
                    .remove_if(name, |_, r| !r.is_pending() && !r.is_quarantined());
                None
            }
            Err(_) => self.runtimes.get(name).map(|r| r.clone()),
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

    #[tokio::test]
    async fn test_mark_dead_and_apply_container_state() {
        use crate::docker::container::ContainerInfo;
        use std::collections::HashMap;

        let registry = RuntimeRegistry::new();
        let mut rt = Runtime::new("test", "exec", "img", "v5", None);
        rt.mark_running("running");
        rt.set_listening();
        let name = rt.name.clone();
        registry.insert(rt).await.unwrap();

        let (dead, was_running) = registry
            .mark_dead(&name, "exited", Some(134))
            .await
            .unwrap();
        assert!(was_running);
        assert_eq!(dead.status, "exited");
        assert!(!dead.is_listening());
        assert_eq!(dead.last_exit_code, Some(134));

        // A second observer of the same death sees no transition.
        let (_, was_running) = registry
            .mark_dead(&name, "exited", Some(134))
            .await
            .unwrap();
        assert!(!was_running);

        let info = ContainerInfo {
            id: "id".to_string(),
            name: name.clone(),
            image: "img".to_string(),
            state: "running".to_string(),
            status: "running".to_string(),
            created: 1,
            labels: HashMap::new(),
            env: HashMap::new(),
            hostname: String::new(),
            exit_code: Some(0),
            oom_killed: false,
            restart_policy: "on-failure".to_string(),
            restart_max_retries: 3,
            restart_count: 2,
        };
        let synced = registry.apply_container_state(&name, &info).unwrap();
        assert_eq!(synced.status, "running");
        assert_eq!(synced.restart_count, 2);
        // A restarted container is not assumed to be listening again.
        assert!(!synced.is_listening());
        assert_eq!(synced.last_exit_code, Some(134));
    }

    #[tokio::test]
    async fn test_quarantined_entries_survive_state_sync_and_removal_guard() {
        let registry = RuntimeRegistry::new();
        let rt = Runtime::new("test", "exec", "img", "v5", None);
        let name = rt.name.clone();
        registry.insert(rt).await.unwrap();

        let quarantined = registry
            .mark_quarantined(&name, 1_800_000_000.0, Some(137))
            .await
            .unwrap();
        assert!(quarantined.is_quarantined());

        assert!(registry.remove_if_quarantined("exec-other").await.is_none());
        let removed = registry.remove_if_quarantined(&name).await.unwrap();
        assert_eq!(removed.last_exit_code, Some(137));
        assert!(!registry.exists(&name).await);
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
