//! Runtime struct representing a container instance

use crate::error::{ExecutorError, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::rngs::OsRng;
use rand::TryRngCore;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Runtime state representing a containerized function instance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Runtime {
    /// Canonical runtime identifier from the API request
    #[serde(default)]
    pub runtime_id: String,
    /// Executor hostname that owns this runtime
    #[serde(default)]
    pub executor_hostname: String,
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
    /// Optional keep-alive ID for cleanup protection.
    /// When set, this runtime is protected from cleanup as long as it
    /// owns this ID (i.e., is the newest runtime with this ID).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keep_alive_id: Option<String>,
    /// Precomputed Authorization header for runtime requests.
    #[serde(skip)]
    pub authorization_header: String,
    /// Unix timestamp at which a crash-loop quarantine lifts, when quarantined.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quarantined_until: Option<f64>,
    /// Exit code from the most recent container death observed for this runtime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_exit_code: Option<i64>,
    /// Number of restarts Docker has performed for the container, as last synced.
    #[serde(default)]
    pub restart_count: i64,
}

/// Registry status used while a runtime is quarantined after a crash loop.
pub const STATUS_QUARANTINED: &str = "quarantined";

impl Runtime {
    /// Create a new runtime in pending state
    pub fn new(
        runtime_id: &str,
        executor_hostname: &str,
        image: &str,
        version: &str,
        keep_alive_id: Option<String>,
    ) -> Self {
        let now = Self::unix_timestamp();

        // Generate random 16-byte secrets encoded as hex
        let mut key_bytes = [0u8; 16];
        let mut hostname_bytes = [0u8; 16];
        let mut rng = OsRng;
        rng.try_fill_bytes(&mut key_bytes)
            .expect("failed to read OS randomness for runtime key");
        rng.try_fill_bytes(&mut hostname_bytes)
            .expect("failed to read OS randomness for runtime hostname");

        let mut runtime = Self {
            runtime_id: runtime_id.to_string(),
            executor_hostname: executor_hostname.to_string(),
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
            keep_alive_id,
            authorization_header: String::new(),
            quarantined_until: None,
            last_exit_code: None,
            restart_count: 0,
        };
        runtime.refresh_cached_auth();
        runtime
    }

    /// Record that the container behind this runtime has stopped.
    ///
    /// The port probe runs again before the next execution, so a container that
    /// Docker restarts is re-checked rather than assumed to be listening.
    pub fn mark_dead(&mut self, status: &str, exit_code: Option<i64>) {
        self.status = status.to_string();
        self.listening = 0;
        if exit_code.is_some() {
            self.last_exit_code = exit_code;
        }
    }

    /// Put the runtime into quarantine until `until` (Unix seconds).
    pub fn mark_quarantined(&mut self, until: f64, exit_code: Option<i64>) {
        self.status = STATUS_QUARANTINED.to_string();
        self.listening = 0;
        self.quarantined_until = Some(until);
        if exit_code.is_some() {
            self.last_exit_code = exit_code;
        }
    }

    /// Whether the runtime is currently held in crash-loop quarantine.
    pub fn is_quarantined(&self) -> bool {
        self.status == STATUS_QUARANTINED
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

    /// Update the last activity timestamp only when the previous value is stale enough.
    /// This avoids a write lock on every hot-path execution while preserving second-level
    /// liveness semantics for cleanup and keep-alive decisions.
    pub fn touch_if_stale(&mut self, min_interval_secs: f64) -> bool {
        let now = Self::unix_timestamp();
        if now - self.updated >= min_interval_secs {
            self.updated = now;
            true
        } else {
            false
        }
    }

    /// Check if the runtime is pending
    pub fn is_pending(&self) -> bool {
        self.status == "pending"
    }

    /// Check if the runtime is running
    /// Docker inspect returns status like "running", "exited", "created", etc.
    pub fn is_running(&self) -> bool {
        !self.is_pending() && self.status.eq_ignore_ascii_case("running")
    }

    /// Get the runtime ID from the full name
    #[allow(dead_code)]
    pub fn runtime_id(&self) -> &str {
        &self.runtime_id
    }

    /// Get seconds since the entry was created
    pub fn age_seconds(&self) -> u64 {
        let now = Self::unix_timestamp();
        (now - self.created).max(0.0) as u64
    }

    /// Get seconds since last activity
    pub fn idle_seconds(&self) -> u64 {
        let now = Self::unix_timestamp();
        (now - self.updated).max(0.0) as u64
    }

    /// Check if the runtime is listening on port 3000
    pub fn is_listening(&self) -> bool {
        self.listening > 0
    }

    /// Mark the runtime as listening on port 3000
    pub fn set_listening(&mut self) {
        self.listening = 1;
        // A runtime that answered on its port is running, whatever the last
        // synced Docker state said (a restart leaves "restarting" behind).
        if !self.is_pending() && !self.is_quarantined() {
            self.status = "running".to_string();
        }
        self.touch();
    }

    pub fn refresh_cached_auth(&mut self) {
        let auth = format!("opr:{}", self.key);
        let auth_encoded = BASE64.encode(auth.as_bytes());
        self.authorization_header = format!("Basic {}", auth_encoded);
    }

    pub fn authorization_header(&self) -> &str {
        &self.authorization_header
    }

    fn unix_timestamp() -> f64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64()
    }
}

pub async fn wait_for_runtime_port(hostname: &str, port: u16, timeout: Duration) -> Result<()> {
    let addr = format!("{}:{}", hostname, port);
    let start = Instant::now();
    let mut retry_delay = Duration::from_millis(50);
    let max_retry_delay = Duration::from_millis(500);

    while start.elapsed() < timeout {
        match tokio::time::timeout(
            Duration::from_secs(1),
            tokio::net::TcpStream::connect(&addr),
        )
        .await
        {
            Ok(Ok(_)) => return Ok(()),
            _ => {
                tokio::time::sleep(retry_delay).await;
                retry_delay = (retry_delay * 2).min(max_retry_delay);
            }
        }
    }

    Err(ExecutorError::RuntimeTimeout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_runtime() {
        let rt = Runtime::new("test-123", "executor", "node-18", "v5", None);

        assert_eq!(rt.name, "executor-test-123");
        assert_eq!(rt.version, "v5");
        assert_eq!(rt.image, "node-18");
        assert!(rt.is_pending());
        assert!(!rt.is_running());
        assert_eq!(rt.key.len(), 32); // 16 bytes = 32 hex chars
        assert_eq!(rt.hostname.len(), 32);
        assert!(rt.keep_alive_id.is_none());
    }

    #[test]
    fn test_new_runtime_with_keep_alive() {
        let rt = Runtime::new(
            "test-123",
            "executor",
            "node-18",
            "v5",
            Some("my-service".to_string()),
        );

        assert_eq!(rt.name, "executor-test-123");
        assert_eq!(rt.keep_alive_id, Some("my-service".to_string()));
    }

    #[test]
    fn test_mark_running() {
        let mut rt = Runtime::new("test", "exec", "img", "v5", None);
        // Docker inspect returns "running" as the status
        rt.mark_running("running");

        assert!(!rt.is_pending());
        assert!(rt.is_running());
        assert_eq!(rt.initialised, 1);
    }

    #[test]
    fn test_runtime_id() {
        let rt = Runtime::new("my-func-123", "executor", "img", "v5", None);
        assert_eq!(rt.runtime_id(), "my-func-123");
    }

    #[test]
    fn test_mark_dead_clears_listening_and_keeps_exit_code() {
        let mut rt = Runtime::new("test", "exec", "img", "v5", None);
        rt.mark_running("running");
        rt.set_listening();

        rt.mark_dead("exited", Some(134));

        assert!(!rt.is_running());
        assert!(!rt.is_listening());
        assert_eq!(rt.last_exit_code, Some(134));

        // A death without a known exit code keeps the last one seen.
        rt.mark_dead("exited", None);
        assert_eq!(rt.last_exit_code, Some(134));
    }

    #[test]
    fn test_quarantine_status_round_trips_through_json() {
        let mut rt = Runtime::new("test", "exec", "img", "v5", None);
        rt.mark_quarantined(1_800_000_000.0, Some(137));
        assert!(rt.is_quarantined());
        assert!(!rt.is_running());
        assert!(!rt.is_pending());

        let json = serde_json::to_value(&rt).unwrap();
        assert_eq!(json["status"], "quarantined");
        assert_eq!(json["quarantined_until"].as_f64(), Some(1_800_000_000.0));
        assert_eq!(json["last_exit_code"], 137);

        let plain = Runtime::new("plain", "exec", "img", "v5", None);
        let json = serde_json::to_value(&plain).unwrap();
        assert!(json.get("quarantined_until").is_none());
        assert!(json.get("last_exit_code").is_none());
    }
}
