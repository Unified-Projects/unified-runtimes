//! Runtime struct representing a container instance

use crate::error::{ExecutorError, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::rngs::OsRng;
use rand::TryRngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Lifecycle state of a registry entry, tracked separately from the Docker
/// status string so an observation of the container can never publish an entry
/// that its create still owns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RuntimeState {
    /// A create inserted the entry and is still building it. Only that create
    /// publishes it, by calling [`Runtime::mark_running`].
    Pending,
    /// The entry is published: its status reflects the container.
    #[default]
    Published,
}

/// Port every managed runtime is expected to serve on.
pub const RUNTIME_PORT: u16 = 3000;

/// Status of a runtime the executor has given up on: the container is up but it
/// never started listening inside its startup window. Docker never reports this
/// state itself, so it cannot be confused with a container state.
pub const STATUS_FAILED: &str = "failed";

/// Seconds a runtime may be running without listening on its port before it is
/// marked failed. Default for `URT_STARTUP_TIMEOUT_SECS` and for the per-runtime
/// `startupTimeout` request field.
pub const DEFAULT_STARTUP_TIMEOUT_SECS: u64 = 60;

/// Seconds a runtime may sit idle before maintenance reclaims it. Default for
/// `URT_INACTIVE_THRESHOLD` and for the per-runtime `inactiveThreshold` field.
pub const DEFAULT_INACTIVE_THRESHOLD_SECS: u64 = 60;

/// The lifecycle knobs a caller may set per runtime, resolved against the
/// executor-wide defaults at creation time and carried on the runtime itself so
/// every consumer reads one value rather than re-deriving it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeLifecycle {
    /// Seconds the runtime has to start listening before it is marked failed.
    pub startup_timeout: u64,
    /// Seconds of inactivity before idle cleanup may reclaim the runtime.
    pub inactive_threshold: u64,
    /// Cap on executions in flight against this runtime. `None` is unlimited.
    pub max_concurrency: Option<usize>,
}

impl Default for RuntimeLifecycle {
    fn default() -> Self {
        Self {
            startup_timeout: DEFAULT_STARTUP_TIMEOUT_SECS,
            inactive_threshold: DEFAULT_INACTIVE_THRESHOLD_SECS,
            max_concurrency: None,
        }
    }
}

/// Container label carrying the startup window.
pub const LABEL_STARTUP_TIMEOUT: &str = "urt.startup_timeout";
/// Container label carrying the idle threshold.
pub const LABEL_INACTIVE_THRESHOLD: &str = "urt.inactive_threshold";
/// Container label carrying the in-flight execution cap, where `0` is unlimited.
pub const LABEL_MAX_CONCURRENCY: &str = "urt.max_concurrency";

impl RuntimeLifecycle {
    /// The knobs as container labels, so a runtime adopted after an executor
    /// restart keeps the values its creator asked for rather than silently
    /// reverting to the executor defaults.
    pub fn to_labels(self) -> HashMap<String, String> {
        HashMap::from([
            (
                LABEL_STARTUP_TIMEOUT.to_string(),
                self.startup_timeout.to_string(),
            ),
            (
                LABEL_INACTIVE_THRESHOLD.to_string(),
                self.inactive_threshold.to_string(),
            ),
            (
                LABEL_MAX_CONCURRENCY.to_string(),
                self.max_concurrency.unwrap_or(0).to_string(),
            ),
        ])
    }

    /// Read the knobs back off a container's labels, falling back to `defaults`
    /// for anything missing or unparseable (a container created before these
    /// labels existed, or one labelled by hand).
    pub fn from_labels(labels: &HashMap<String, String>, defaults: Self) -> Self {
        let parsed = |key: &str| -> Option<u64> { labels.get(key)?.trim().parse::<u64>().ok() };

        Self {
            startup_timeout: parsed(LABEL_STARTUP_TIMEOUT)
                .filter(|value| *value > 0)
                .unwrap_or(defaults.startup_timeout),
            inactive_threshold: parsed(LABEL_INACTIVE_THRESHOLD)
                .unwrap_or(defaults.inactive_threshold),
            max_concurrency: match parsed(LABEL_MAX_CONCURRENCY) {
                // The label is always written, with 0 standing for unlimited, so
                // a present-and-zero value is a deliberate "no cap".
                Some(0) => None,
                Some(limit) => Some(limit as usize),
                None => defaults.max_concurrency,
            },
        }
    }
}

fn default_startup_timeout() -> u64 {
    DEFAULT_STARTUP_TIMEOUT_SECS
}

fn default_inactive_threshold() -> u64 {
    DEFAULT_INACTIVE_THRESHOLD_SECS
}

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
    /// 32-char hex identity reported on the runtime object. The container's own
    /// hostname is left to Docker; adoption fills this in from the container.
    pub hostname: String,
    /// Container status: "pending" or Docker status string
    pub status: String,
    /// Lifecycle state of this entry. Process-local: it is not part of the wire
    /// contract, and an entry rebuilt from JSON describes a runtime this process
    /// is not building, so it deserialises as published.
    #[serde(skip)]
    pub state: RuntimeState,
    /// Secret key for internal auth (32-char hex)
    pub key: String,
    /// Number of active listeners
    pub listening: u8,
    /// Docker image name
    pub image: String,
    /// Set to 1 once the runtime has been observed listening on its port, and
    /// never before: a runtime that reports `initialised: 1, listening: 0` was
    /// what hid two production outages.
    pub initialised: u8,
    /// Seconds this runtime has to start listening before it is marked failed.
    #[serde(default = "default_startup_timeout")]
    pub startup_timeout: u64,
    /// Seconds of inactivity before idle cleanup may reclaim this runtime.
    #[serde(default = "default_inactive_threshold")]
    pub inactive_threshold: u64,
    /// Cap on executions in flight against this runtime; `null` is unlimited.
    #[serde(default)]
    pub max_concurrency: Option<usize>,
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
            state: RuntimeState::Pending,
            key: hex::encode(key_bytes),
            listening: 0,
            image: image.to_string(),
            initialised: 0,
            startup_timeout: DEFAULT_STARTUP_TIMEOUT_SECS,
            inactive_threshold: DEFAULT_INACTIVE_THRESHOLD_SECS,
            max_concurrency: None,
            keep_alive_id,
            authorization_header: String::new(),
            quarantined_until: None,
            last_exit_code: None,
            restart_count: 0,
        };
        runtime.refresh_cached_auth();
        runtime
    }

    /// Publish the entry with a container status, leaving pending state behind.
    pub fn publish_status(&mut self, status: &str) {
        self.status = status.to_string();
        self.state = RuntimeState::Published;
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
    ///
    /// The verdict is terminal for the entry, so it publishes as well: nothing
    /// is still building behind a runtime the executor has given up restarting,
    /// and a caller reading the entry has to see the quarantine rather than a
    /// pending build.
    pub fn mark_quarantined(&mut self, until: f64, exit_code: Option<i64>) {
        self.publish_status(STATUS_QUARANTINED);
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

    /// Apply the resolved lifecycle knobs to this runtime.
    pub fn with_lifecycle(mut self, lifecycle: RuntimeLifecycle) -> Self {
        self.apply_lifecycle(lifecycle);
        self
    }

    /// Apply the resolved lifecycle knobs in place.
    pub fn apply_lifecycle(&mut self, lifecycle: RuntimeLifecycle) {
        self.startup_timeout = lifecycle.startup_timeout.max(1);
        self.inactive_threshold = lifecycle.inactive_threshold;
        self.max_concurrency = lifecycle.max_concurrency.filter(|limit| *limit > 0);
    }

    /// The lifecycle knobs currently in force for this runtime.
    pub fn lifecycle(&self) -> RuntimeLifecycle {
        RuntimeLifecycle {
            startup_timeout: self.startup_timeout,
            inactive_threshold: self.inactive_threshold,
            max_concurrency: self.max_concurrency,
        }
    }

    /// Mark runtime as running with the container status.
    ///
    /// Deliberately leaves `initialised` alone: a container that is up has not
    /// yet proved it can serve, and only `set_listening` makes that claim.
    pub fn mark_running(&mut self, status: &str) {
        self.publish_status(status);
        self.touch();
    }

    /// Give up on a runtime that started but never listened. The entry stays in
    /// the registry so `GET /v1/runtimes` shows the verdict until the watchdog
    /// reaps it on its next cycle.
    pub fn mark_failed(&mut self) {
        self.status = STATUS_FAILED.to_string();
        self.initialised = 0;
    }

    /// Whether the executor has given up on this runtime.
    pub fn is_failed(&self) -> bool {
        self.status.eq_ignore_ascii_case(STATUS_FAILED)
    }

    /// Seconds of inactivity this runtime tolerates, falling back to the
    /// executor-wide default for entries that carry no value of their own.
    pub fn effective_inactive_threshold(&self, default_threshold: u64) -> u64 {
        if self.inactive_threshold > 0 {
            self.inactive_threshold
        } else {
            default_threshold
        }
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
        self.state == RuntimeState::Pending
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

    /// Record that the runtime has been observed listening on port 3000.
    ///
    /// This is the only transition that sets `initialised`. A runtime that
    /// answered on its port is running whatever the last synced state said, so
    /// this also clears a failed verdict for one that came up late and the
    /// `restarting` a Docker restart leaves behind. A pending entry keeps its
    /// state for its create to publish, and a quarantine is only lifted when it
    /// expires.
    pub fn set_listening(&mut self) {
        self.listening = 1;
        self.initialised = 1;
        if !self.is_pending() && !self.is_quarantined() {
            self.status = "running".to_string();
        }
        self.touch();
    }

    /// Whether the runtime is up but has not listened within its startup window.
    pub fn missed_startup_window(&self) -> bool {
        self.is_running() && !self.is_listening() && self.age_seconds() >= self.startup_timeout
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

/// Single-shot check that something is accepting connections on the runtime's
/// port. Unlike `wait_for_runtime_port` this never retries, so a caller
/// sweeping many runtimes spends at most `timeout` on each.
pub async fn is_runtime_listening(name: &str, timeout: Duration) -> bool {
    let addr = format!("{}:{}", name, RUNTIME_PORT);

    matches!(
        tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await,
        Ok(Ok(_))
    )
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
    fn test_mark_running_does_not_claim_initialised() {
        let mut rt = Runtime::new("test", "exec", "img", "v5", None);
        // Docker inspect returns "running" as the status
        rt.mark_running("running");

        assert!(!rt.is_pending());
        assert!(rt.is_running());
        assert_eq!(rt.initialised, 0);
        assert_eq!(rt.listening, 0);
    }

    #[test]
    fn test_set_listening_is_what_initialises_a_runtime() {
        let mut rt = Runtime::new("test", "exec", "img", "v5", None);
        rt.mark_running("running");
        rt.set_listening();

        assert_eq!(rt.listening, 1);
        assert_eq!(rt.initialised, 1);
        assert!(rt.is_listening());
    }

    #[test]
    fn test_mark_failed_clears_initialised_and_is_visible_as_status() {
        let mut rt = Runtime::new("test", "exec", "img", "v5", None);
        rt.mark_running("running");
        rt.set_listening();
        rt.mark_failed();

        assert!(rt.is_failed());
        assert_eq!(rt.status, "failed");
        assert_eq!(rt.initialised, 0);
        assert!(!rt.is_running());
        assert!(!rt.is_pending());
    }

    #[test]
    fn test_late_listener_clears_the_failed_verdict() {
        let mut rt = Runtime::new("test", "exec", "img", "v5", None);
        rt.mark_running("running");
        rt.mark_failed();
        rt.set_listening();

        assert!(!rt.is_failed());
        assert!(rt.is_running());
        assert_eq!(rt.initialised, 1);
    }

    #[test]
    fn test_missed_startup_window_only_after_the_window() {
        let mut rt = Runtime::new("test", "exec", "img", "v5", None);
        rt.apply_lifecycle(RuntimeLifecycle {
            startup_timeout: 30,
            ..RuntimeLifecycle::default()
        });
        rt.mark_running("running");

        assert!(!rt.missed_startup_window());

        rt.created -= 31.0;
        assert!(rt.missed_startup_window());

        rt.set_listening();
        assert!(!rt.missed_startup_window());
    }

    #[test]
    fn test_pending_runtime_never_misses_the_startup_window() {
        let mut rt = Runtime::new("test", "exec", "img", "v5", None);
        rt.created -= 3_600.0;

        assert!(rt.is_pending());
        assert!(!rt.missed_startup_window());
    }

    #[test]
    fn test_lifecycle_round_trips_and_normalises() {
        let rt = Runtime::new("test", "exec", "img", "v5", None).with_lifecycle(RuntimeLifecycle {
            startup_timeout: 0,
            inactive_threshold: 900,
            max_concurrency: Some(0),
        });

        // A zero startup timeout would condemn every runtime immediately, and a
        // zero concurrency cap would reject every execution.
        assert_eq!(rt.startup_timeout, 1);
        assert_eq!(rt.inactive_threshold, 900);
        assert_eq!(rt.max_concurrency, None);
        assert_eq!(rt.lifecycle().inactive_threshold, 900);
    }

    #[test]
    fn test_effective_inactive_threshold_falls_back_to_default() {
        let mut rt = Runtime::new("test", "exec", "img", "v5", None);
        assert_eq!(rt.effective_inactive_threshold(120), 60);

        rt.inactive_threshold = 0;
        assert_eq!(rt.effective_inactive_threshold(120), 120);

        rt.inactive_threshold = 5;
        assert_eq!(rt.effective_inactive_threshold(120), 5);
    }

    #[test]
    fn test_runtime_deserialises_without_lifecycle_fields() {
        let json = r#"{
            "runtime_id": "fn-1",
            "executor_hostname": "exec",
            "version": "v5",
            "created": 1.0,
            "updated": 1.0,
            "name": "exec-fn-1",
            "hostname": "abc",
            "status": "running",
            "key": "k",
            "listening": 0,
            "image": "img",
            "initialised": 0
        }"#;

        let rt: Runtime = serde_json::from_str(json).unwrap();
        assert_eq!(rt.startup_timeout, DEFAULT_STARTUP_TIMEOUT_SECS);
        assert_eq!(rt.inactive_threshold, DEFAULT_INACTIVE_THRESHOLD_SECS);
        assert_eq!(rt.max_concurrency, None);
    }

    #[test]
    fn test_pending_is_a_state_not_a_status_string() {
        let mut rt = Runtime::new("test", "exec", "img", "v5", None);
        assert!(rt.is_pending());

        // A container that reports "pending" as its status is still a published
        // entry: only the create that inserted the entry can clear pending.
        rt.publish_status("pending");
        assert!(!rt.is_pending());
        assert_eq!(rt.status, "pending");
    }

    #[test]
    fn test_status_string_alone_does_not_make_an_entry_pending() {
        let mut rt = Runtime::new("test", "exec", "img", "v5", None);
        rt.mark_running("running");
        rt.status = "pending".to_string();

        assert!(!rt.is_pending());
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
