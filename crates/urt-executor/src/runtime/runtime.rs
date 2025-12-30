//! Runtime struct representing a container instance

use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Runtime state representing a containerized function instance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Runtime {
    /// Runtime version (v2 or v5)
    pub version: String,
    /// Creation timestamp (Unix seconds)
    pub created: f64,
    /// Last activity timestamp (Unix seconds)
    pub updated: f64,
    /// Container name: {hostname}-{runtimeId}
    pub name: String,
    /// Internal hostname (32-char hex)
    pub hostname: String,
    /// Container status: "pending" or Docker status string
    pub status: String,
    /// Secret key for internal auth (32-char hex)
    pub key: String,
    /// Number of active listeners
    pub listening: u8,
    /// Docker image name
    pub image: String,
    /// Initialization counter
    pub initialised: u8,
}

impl Runtime {
    /// Create a new runtime in pending state
    pub fn new(runtime_id: &str, executor_hostname: &str, image: &str, version: &str) -> Self {
        let now = Self::unix_timestamp();

        // Generate random 16-byte secrets encoded as hex
        let mut key_bytes = [0u8; 16];
        let mut hostname_bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut key_bytes);
        rand::rng().fill_bytes(&mut hostname_bytes);

        Self {
            version: version.to_string(),
            created: now,
            updated: now,
            name: format!("{}-{}", executor_hostname, runtime_id),
            hostname: hex::encode(hostname_bytes),
            status: "pending".to_string(),
            key: hex::encode(key_bytes),
            listening: 0,
            image: image.to_string(),
            initialised: 0,
        }
    }

    /// Mark runtime as running with the container status
    pub fn mark_running(&mut self, status: &str) {
        self.status = status.to_string();
        self.initialised = 1;
        self.touch();
    }

    /// Update the last activity timestamp
    pub fn touch(&mut self) {
        self.updated = Self::unix_timestamp();
    }

    /// Check if the runtime is pending
    pub fn is_pending(&self) -> bool {
        self.status == "pending"
    }

    /// Check if the runtime is running
    /// Docker inspect returns status like "running", "exited", "created", etc.
    pub fn is_running(&self) -> bool {
        !self.is_pending() && self.status.to_lowercase() == "running"
    }

    /// Get the runtime ID from the full name
    #[allow(dead_code)]
    pub fn runtime_id(&self) -> &str {
        self.name.split('-').next_back().unwrap_or(&self.name)
    }

    /// Get seconds since last activity
    pub fn idle_seconds(&self) -> u64 {
        let now = Self::unix_timestamp();
        (now - self.updated).max(0.0) as u64
    }

    fn unix_timestamp() -> f64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_runtime() {
        let rt = Runtime::new("test-123", "executor", "node-18", "v5");

        assert_eq!(rt.name, "executor-test-123");
        assert_eq!(rt.version, "v5");
        assert_eq!(rt.image, "node-18");
        assert!(rt.is_pending());
        assert!(!rt.is_running());
        assert_eq!(rt.key.len(), 32); // 16 bytes = 32 hex chars
        assert_eq!(rt.hostname.len(), 32);
    }

    #[test]
    fn test_mark_running() {
        let mut rt = Runtime::new("test", "exec", "img", "v5");
        // Docker inspect returns "running" as the status
        rt.mark_running("running");

        assert!(!rt.is_pending());
        assert!(rt.is_running());
        assert_eq!(rt.initialised, 1);
    }

    #[test]
    fn test_runtime_id() {
        let rt = Runtime::new("my-func-123", "executor", "img", "v5");
        assert_eq!(rt.runtime_id(), "123");
    }
}
