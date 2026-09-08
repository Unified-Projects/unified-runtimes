//! Runtime CRUD endpoints

use super::executions::VariablesInput;
use super::logs::{parse_build_logs, LogEntry};
use super::AppState;
use crate::docker::container::ContainerConfig;
use crate::error::{ExecutorError, Result};
use crate::platform;
use crate::resilience::{is_transient_error, retry_with_backoff};
use crate::runtime::create_tracker::spawn_or_join;
use crate::runtime::readiness::ReadinessGuard;
use crate::runtime::{wait_for_runtime_port, KeepAliveRegistry, Runtime};
use crate::storage;
use crate::tasks;
use crate::telemetry::{metrics, LatencyKind, OperationTimer};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Request body for creating a runtime
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRuntimeRequest {
    pub runtime_id: String,
    pub image: String,
    #[serde(default)]
    pub entrypoint: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub destination: String,
    #[serde(default)]
    pub output_directory: String,
    #[serde(default)]
    pub variables: VariablesInput,
    #[serde(default)]
    pub runtime_entrypoint: String,
    #[serde(default)]
    pub command: String,
    #[serde(default = "default_timeout")]
    pub timeout: u32,
    #[serde(default)]
    pub remove: bool,
    #[serde(default = "default_cpus")]
    pub cpus: f64,
    #[serde(default = "default_memory")]
    pub memory: u64,
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default = "default_restart_policy")]
    pub restart_policy: String,
    /// Docker CMD to run in the container (e.g., ["node", "/usr/local/server/src/server.js"])
    #[serde(default)]
    pub docker_cmd: Vec<String>,
    /// Optional keep-alive ID for cleanup protection.
    /// When set, this runtime is protected from cleanup until a newer
    /// runtime starts with the same keep_alive_id.
    /// Fallback: reads URT_KEEP_ALIVE from container's env if not provided.
    #[serde(default)]
    pub keep_alive_id: Option<String>,
}

pub fn default_timeout() -> u32 {
    600
}
/// Default CPU allocation - matches executor-main.
pub fn default_cpus() -> f64 {
    1.0
}
/// Default memory allocation in MB - matches executor-main.
pub fn default_memory() -> u64 {
    512
}
pub fn default_version() -> String {
    "v5".to_string()
}
const DEFAULT_RESTART_POLICY: &str = "no";
pub fn default_restart_policy() -> String {
    DEFAULT_RESTART_POLICY.to_string()
}

fn is_legacy_v2(version: &str) -> bool {
    version.trim().eq_ignore_ascii_case("v2")
}

fn uses_modern_runtime_layout(version: &str) -> bool {
    !is_legacy_v2(version)
}

/// Mount name the source archive is stored under inside the runtime's `/tmp` mount.
///
/// Mirrors executor-main 0.29: a source with a known archive extension keeps that
/// extension so the runtime's lifecycle helper can pick the right decompressor,
/// and anything else falls back to the gzipped-tar default.
fn source_mount_file_name(source: &str) -> &'static str {
    let lowered = source.to_ascii_lowercase();
    if lowered.ends_with(".tar.gz") {
        "code.tar.gz"
    } else if lowered.ends_with(".tgz") {
        "code.tgz"
    } else if lowered.ends_with(".tar") {
        "code.tar"
    } else if lowered.ends_with(".sqfs") {
        "code.sqfs"
    } else if lowered.ends_with(".gz") {
        "code.gz"
    } else {
        "code.tar.gz"
    }
}

/// Absolute path the source archive is visible at from inside the container.
fn source_code_path(source: &str) -> String {
    format!("/tmp/{}", source_mount_file_name(source))
}

/// Docker seeds this variable with the container identity. Server scripts that
/// treat it as a bind address (Next.js standalone `server.js` reads
/// `process.env.HOSTNAME || '0.0.0.0'`) then bind to a single per-container
/// address, which the executor cannot reach from the runtimes network.
pub(crate) const RUNTIME_BIND_HOSTNAME_VAR: &str = "HOSTNAME";

/// Wildcard bind address, so a runtime answers on every network it is attached to.
pub(crate) const DEFAULT_RUNTIME_BIND_HOSTNAME: &str = "0.0.0.0";

struct RuntimeEnvVars<'a> {
    version: &'a str,
    entrypoint: &'a str,
    executor_hostname: &'a str,
    cpus: f64,
    memory: u64,
    output_directory: &'a str,
    source: &'a str,
}

fn apply_runtime_env_vars(
    env: &mut std::collections::HashMap<String, String>,
    runtime: &Runtime,
    config: RuntimeEnvVars<'_>,
) {
    if is_legacy_v2(config.version) {
        env.insert("INTERNAL_RUNTIME_KEY".to_string(), runtime.key.clone());
        env.insert(
            "INTERNAL_RUNTIME_ENTRYPOINT".to_string(),
            config.entrypoint.to_string(),
        );
        env.insert(
            "INTERNAL_EXECUTOR_HOSTNAME".to_string(),
            config.executor_hostname.to_string(),
        );
        // Mirror the historical typo used by executor-main for older images.
        env.insert(
            "INERNAL_EXECUTOR_HOSTNAME".to_string(),
            config.executor_hostname.to_string(),
        );
        return;
    }

    env.insert("OPEN_RUNTIMES_SECRET".to_string(), runtime.key.clone());
    env.insert(
        "OPEN_RUNTIMES_ENTRYPOINT".to_string(),
        config.entrypoint.to_string(),
    );
    env.insert(
        "OPEN_RUNTIMES_HOSTNAME".to_string(),
        config.executor_hostname.to_string(),
    );
    env.insert("OPEN_RUNTIMES_CPUS".to_string(), config.cpus.to_string());
    env.insert(
        "OPEN_RUNTIMES_MEMORY".to_string(),
        config.memory.to_string(),
    );

    if !config.output_directory.is_empty() {
        env.insert(
            "OPEN_RUNTIMES_OUTPUT_DIRECTORY".to_string(),
            config.output_directory.to_string(),
        );
    }

    // Runtime images from September 2026 onwards read OPEN_RUNTIMES_CODE_PATH to locate
    // the code archive; without it the lifecycle helper only searches /mnt/code and serve
    // mode fails with "Code archive not found". A caller-supplied value always wins.
    if !config.source.is_empty() {
        env.entry("OPEN_RUNTIMES_CODE_PATH".to_string())
            .or_insert_with(|| source_code_path(config.source));
    }

    apply_default_bind_hostname(env);
}

/// Seed the wildcard bind address unless the caller supplied a non-blank value
/// of its own, which stays the escape hatch for a runtime that needs something
/// else. A runtime that wants its container identity can read `/etc/hostname`,
/// which this does not touch.
fn apply_default_bind_hostname(env: &mut std::collections::HashMap<String, String>) {
    let caller_supplied = env
        .get(RUNTIME_BIND_HOSTNAME_VAR)
        .is_some_and(|value| !value.trim().is_empty());

    if !caller_supplied {
        env.insert(
            RUNTIME_BIND_HOSTNAME_VAR.to_string(),
            DEFAULT_RUNTIME_BIND_HOSTNAME.to_string(),
        );
    }
}

/// Roll back keep-alive ownership if runtime creation fails after ownership transfer.
struct KeepAliveRegistrationGuard {
    registry: KeepAliveRegistry,
    keep_alive_id: Option<String>,
    runtime_name: String,
    previous_owner: Option<String>,
    committed: bool,
}

impl KeepAliveRegistrationGuard {
    fn new(
        registry: KeepAliveRegistry,
        keep_alive_id: Option<String>,
        runtime_name: String,
    ) -> Self {
        Self {
            registry,
            keep_alive_id,
            runtime_name,
            previous_owner: None,
            committed: false,
        }
    }

    fn set_previous_owner(&mut self, previous_owner: Option<String>) {
        self.previous_owner = previous_owner;
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for KeepAliveRegistrationGuard {
    fn drop(&mut self) {
        if self.committed {
            return;
        }

        let Some(keep_alive_id) = self.keep_alive_id.as_ref() else {
            return;
        };

        self.registry.unregister(keep_alive_id, &self.runtime_name);
        if let Some(previous_owner) = self.previous_owner.as_ref() {
            self.registry.register(keep_alive_id, previous_owner);
        }
    }
}

/// Validate runtime ID format
/// Only allows alphanumeric characters, dashes, and underscores
fn validate_runtime_id(id: &str) -> Result<()> {
    if id.is_empty() {
        return Err(ExecutorError::BadRequest(
            "Runtime ID cannot be empty".to_string(),
        ));
    }

    if id.len() > 64 {
        return Err(ExecutorError::BadRequest(
            "Runtime ID too long (max 64 chars)".to_string(),
        ));
    }

    // Only allow alphanumeric, dash, underscore
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ExecutorError::BadRequest(
            "Runtime ID must contain only alphanumeric characters, dashes, or underscores"
                .to_string(),
        ));
    }

    // Prevent path traversal attempts
    if id.contains("..") || id.starts_with('/') || id.starts_with('\\') {
        return Err(ExecutorError::BadRequest(
            "Runtime ID contains invalid path characters".to_string(),
        ));
    }

    // Prevent shell metacharacter injection
    if id.contains(';')
        || id.contains('&')
        || id.contains('|')
        || id.contains('$')
        || id.contains('`')
    {
        return Err(ExecutorError::BadRequest(
            "Runtime ID contains invalid characters".to_string(),
        ));
    }

    Ok(())
}

/// Sanitize tar extraction commands to prevent permission and ownership restoration failures on
/// Docker-mounted volumes where the container user lacks the necessary privileges.
///
/// Injects `--no-same-permissions -o` immediately after `tar` for any invocation that includes
/// the extract flag (`x`) without the create flag (`c`). These flags are supported by both GNU
/// tar and BusyBox tar; GNU-only flags such as `--no-acls` and `--no-xattrs` break BusyBox-based
/// runtime images.
/// Idempotent: no-op if the flags are already present. Does not touch create commands or
/// non-tar commands.
fn sanitize_tar_flags(cmd: &str) -> String {
    // Idempotent guard: if the flags are already in the command, return unchanged.
    if cmd.contains("--no-same-permissions") || cmd.contains("tar -o ") || cmd.contains(" tar -o ")
    {
        return cmd.to_string();
    }

    // Find the `tar ` invocation.
    let tar_pos = match cmd.find("tar ") {
        Some(pos) => pos,
        None => return cmd.to_string(),
    };

    // Inspect the first argument token after `tar `.
    let after_tar = &cmd[tar_pos + 4..];
    let first_arg = after_tar.split_whitespace().next().unwrap_or("");

    // Only handle short-flag style (e.g. -zxf, -xzf, -xf).
    // Must contain 'x' (extract) and must NOT contain 'c' (create).
    let is_extract = first_arg.starts_with('-')
        && !first_arg.starts_with("--")
        && first_arg.contains('x')
        && !first_arg.contains('c');

    if !is_extract {
        return cmd.to_string();
    }

    // Inject flags immediately after "tar ".
    let inject_pos = tar_pos + 4;
    format!(
        "{}--no-same-permissions -o {}",
        &cmd[..inject_pos],
        &cmd[inject_pos..]
    )
}

/// Validate Docker image name format
fn validate_image_name(image: &str) -> Result<()> {
    if image.is_empty() {
        return Err(ExecutorError::BadRequest(
            "Image name cannot be empty".to_string(),
        ));
    }

    if image.len() > 256 {
        return Err(ExecutorError::BadRequest(
            "Image name too long (max 256 chars)".to_string(),
        ));
    }

    // Docker image names: [registry/][namespace/]name[:tag][@digest]
    // Valid characters: a-z, A-Z (for registry), 0-9, -, _, ., /, :, @
    let valid_chars =
        |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | ':' | '@');

    if !image.chars().all(valid_chars) {
        return Err(ExecutorError::BadRequest(
            "Image name contains invalid characters".to_string(),
        ));
    }

    // Prevent command injection via image name
    if image.contains("$(")
        || image.contains('`')
        || image.contains(';')
        || image.contains("&&")
        || image.contains("||")
        || image.contains('\n')
    {
        return Err(ExecutorError::BadRequest(
            "Image name contains shell metacharacters".to_string(),
        ));
    }

    // Prevent path traversal
    if image.contains("..") {
        return Err(ExecutorError::BadRequest(
            "Image name contains path traversal sequence".to_string(),
        ));
    }

    Ok(())
}

fn is_live_container_state(state: &str, status: &str) -> bool {
    let normalized_state = state.trim().to_ascii_lowercase();
    if !normalized_state.is_empty() {
        return matches!(
            normalized_state.as_str(),
            "running" | "created" | "restarting" | "paused"
        );
    }

    let normalized_status = status.trim().to_ascii_lowercase();
    normalized_status == "running"
        || normalized_status == "up"
        || normalized_status.starts_with("up ")
}

/// Tear down everything a failed build owns: the container if one reached
/// Docker, the working directory, the readiness notifier and the pending
/// registry entry.
///
/// Consuming the `ReadinessGuard` makes it impossible for a failure path to
/// forget it: waiters are always woken before the registry entry disappears, so
/// they see the absence and return a deterministic 404.
async fn abandon_pending_create(
    state: &AppState,
    full_name: &str,
    tmp_folder: &std::path::Path,
    readiness_guard: ReadinessGuard,
    remove_container: bool,
) {
    if remove_container {
        state.docker.remove_container(full_name, true).await.ok();
    }
    tokio::fs::remove_dir_all(tmp_folder).await.ok();
    drop(readiness_guard);
    state.registry.remove(full_name).await;
}

async fn cleanup_runtime_artifacts(state: &AppState, full_name: &str) {
    state.readiness_notify_and_remove(full_name);
    state.registry.remove(full_name).await;
    let tmp_folder = platform::temp_dir().join(full_name);
    tokio::fs::remove_dir_all(&tmp_folder).await.ok();
}

/// Settle an existing entry for this runtime ID before a build starts.
///
/// The caller must hold the create slot for `full_name`, which is what makes it
/// safe to treat a pending entry as an orphan rather than a live build.
async fn reconcile_existing_runtime_id(
    state: &AppState,
    runtime_id: &str,
    full_name: &str,
) -> Result<()> {
    if let Some(runtime) = state.registry.sync_status(full_name, &state.docker).await {
        if runtime.is_pending() {
            // The caller holds the create slot for this name, so no build is
            // running behind this entry: it was left by a create that ended
            // without cleaning up. Reclaim it rather than refusing every retry
            // until maintenance reaps it.
            warn!(
                "Reclaiming orphaned pending entry for runtime {} ({}s old, no create in flight)",
                runtime_id,
                runtime.age_seconds()
            );
            let _ = state.docker.remove_container(full_name, true).await;
            cleanup_runtime_artifacts(state, full_name).await;
        } else if is_live_container_state(&runtime.status, &runtime.status) {
            info!(
                "Runtime {} already exists with live status {}",
                runtime_id, runtime.status
            );
            return Err(ExecutorError::RuntimeConflict);
        } else {
            warn!(
                "Cleaning up stale registry entry for runtime {} with status {}",
                runtime_id, runtime.status
            );
            let _ = state.docker.remove_container(full_name, true).await;
            cleanup_runtime_artifacts(state, full_name).await;
        }
    } else if state.registry.exists(full_name).await {
        return Err(ExecutorError::RuntimeConflict);
    }

    match state.docker.inspect_container(full_name).await {
        Ok(container) => {
            if tasks::adopt_container_by_name(
                &state.docker,
                &state.registry,
                &state.keep_alive_registry,
                &state.config.hostname,
                full_name,
            )
            .await
            {
                info!(
                    "Runtime {} already exists as managed container {}",
                    runtime_id, full_name
                );
                return Err(ExecutorError::RuntimeConflict);
            }

            if is_live_container_state(&container.state, &container.status) {
                warn!(
                    "Refusing to recreate runtime {} because live container {} already exists",
                    runtime_id, full_name
                );
                return Err(ExecutorError::RuntimeConflict);
            }

            warn!(
                "Removing stale container {} before recreating runtime {}",
                full_name, runtime_id
            );
            state.docker.remove_container(full_name, true).await?;
            cleanup_runtime_artifacts(state, full_name).await;
        }
        Err(ExecutorError::RuntimeNotFound) => {}
        Err(error) => return Err(error),
    }

    Ok(())
}

/// Response for creating a runtime
/// Field names must match executor-main exactly for Appwrite compatibility
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRuntimeResponse {
    pub output: Vec<LogEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(rename = "startTime")]
    pub start_time: f64,
    pub duration: f64,
}

// LogEntry is imported from super::logs

/// Map a failed source fetch onto the error returned to the caller.
///
/// A fault that is worth another attempt, such as a 5xx from object storage,
/// answers 500 so the caller retries; a source that is genuinely unusable
/// answers 400.
fn source_download_error(source: &str, error: ExecutorError) -> ExecutorError {
    let message = format!("Failed to copy source code from '{}': {}", source, error);
    if is_transient_error(&error) {
        ExecutorError::Storage(message)
    } else {
        ExecutorError::RuntimeFailed(message)
    }
}

/// Everything a build needs once the request has been validated.
///
/// Collected into one owned value so the build can be handed to a detached task
/// without borrowing anything from the HTTP handler.
struct RuntimeBuild {
    state: AppState,
    req: CreateRuntimeRequest,
    resolved_image: String,
    full_name: String,
    start_time: std::time::Instant,
    start_timestamp: f64,
    /// Held for the life of the build, so the create concurrency limit bounds
    /// builds actually running rather than clients still connected.
    create_permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

/// POST /v1/runtimes - Create a new runtime
/// Note: Accepts JSON regardless of Content-Type header for backwards compatibility
pub async fn create_runtime(
    State(state): State<AppState>,
    body: String,
) -> Result<(StatusCode, Json<CreateRuntimeResponse>)> {
    let mut operation_timer = OperationTimer::new(LatencyKind::RuntimeCreate);
    let start_time = std::time::Instant::now();
    let start_timestamp = chrono::Utc::now().timestamp_millis() as f64 / 1000.0;

    let queue_wait_started = std::time::Instant::now();
    let runtime_create_permit = match &state.runtime_create_limiter {
        Some(limiter) => {
            let queue_wait_timeout =
                Duration::from_millis(state.config.runtime_create_queue_wait_ms);
            match tokio::time::timeout(queue_wait_timeout, limiter.clone().acquire_owned()).await {
                Ok(Ok(permit)) => {
                    metrics().observe_runtime_create_queue_wait(queue_wait_started.elapsed());
                    Some(permit)
                }
                Ok(Err(_)) => return Err(ExecutorError::Unknown),
                Err(_) => {
                    metrics().observe_runtime_create_queue_wait(queue_wait_timeout);
                    metrics().inc_error_class("create_runtime", "overload");
                    operation_timer.mark_overload();
                    return Err(ExecutorError::RuntimeOverloaded);
                }
            }
        }
        None => None,
    };

    // Parse JSON body manually for backwards compatibility (no Content-Type requirement)
    let req: CreateRuntimeRequest = serde_json::from_str(&body)
        .map_err(|e| ExecutorError::BadRequest(format!("Invalid JSON: {}", e)))?;
    let resolved_image = state.config.resolve_runtime_image(
        &req.image,
        &req.entrypoint,
        &req.runtime_entrypoint,
        &req.command,
    );

    if resolved_image != req.image {
        info!(
            runtime_id = %req.runtime_id,
            requested_image = %req.image,
            resolved_image = %resolved_image,
            "Resolved runtime image"
        );
    }

    info!(
        runtime_id = %req.runtime_id,
        image = %resolved_image,
        version = %req.version,
        "Creating runtime"
    );

    // Validate runtime ID and image name
    validate_runtime_id(&req.runtime_id)?;
    validate_image_name(&resolved_image)?;

    // Check if image is allowed
    if !state.config.is_runtime_allowed(&resolved_image) {
        return Err(ExecutorError::BadRequest(format!(
            "Image {} is not in allowed runtimes list",
            resolved_image
        )));
    }

    let full_name = format!("{}-{}", state.config.hostname, req.runtime_id);

    // The build runs on a detached task from here on. A client that hangs up
    // mid-download no longer cancels it, so the pending registry entry this
    // create is about to insert is always resolved by the work behind it, and a
    // create that arrives while the build is running joins it instead of being
    // refused by the existing-runtime guard.
    let build = run_create(RuntimeBuild {
        state: state.clone(),
        req,
        resolved_image,
        full_name: full_name.clone(),
        start_time,
        start_timestamp,
        create_permit: runtime_create_permit,
    });

    let response = spawn_or_join(&state.create_tracker, &full_name, build).await?;

    operation_timer.mark_success();

    Ok((StatusCode::CREATED, Json(response)))
}

/// Build a runtime: reconcile any existing entry, register it as pending,
/// download the source, create and start the container, then publish it as
/// running.
///
/// Runs to completion regardless of what the requesting client does. Every exit
/// after the pending entry is inserted either promotes that entry out of pending
/// or tears it down along with the container and working directory it owns.
async fn run_create(build: RuntimeBuild) -> Result<CreateRuntimeResponse> {
    let RuntimeBuild {
        state,
        req,
        resolved_image,
        full_name,
        start_time,
        start_timestamp,
        create_permit: _create_permit,
    } = build;

    if state.registry.exists(&full_name).await {
        reconcile_existing_runtime_id(&state, &req.runtime_id, &full_name).await?;
    }

    // Apply minimum resource overrides
    let (cpus, memory) = state.config.apply_min_resources(req.cpus, req.memory);
    info!(
        "Resource allocation: requested={} CPUs / {} MB, applied={} CPUs / {} MB",
        req.cpus, req.memory, cpus, memory
    );

    // Determine keep_alive_id: prefer request field, fallback to URT_KEEP_ALIVE env var
    let keep_alive_id = req.keep_alive_id.clone().or_else(|| {
        req.variables
            .to_map()
            .get("URT_KEEP_ALIVE")
            .cloned()
            .filter(|s| !s.is_empty())
    });
    let _keep_alive_lock = match keep_alive_id.as_ref() {
        Some(ka_id) => Some(state.keep_alive_registry.lock(ka_id).await),
        None => None,
    };

    // Create runtime entry
    let runtime = Runtime::new(
        &req.runtime_id,
        &state.config.hostname,
        &resolved_image,
        &req.version,
        keep_alive_id.clone(),
    );

    // Register as pending. The 409 from a concurrent create_runtime surfaces here
    // before any notifier or Docker resource is allocated (M8).
    state.registry.insert(runtime.clone()).await?;
    // Insert readiness notifier AFTER successful registry insertion so that the
    // 409 path never creates a dangling notifier entry.
    // Wrap in a ReadinessGuard so any error path between here and the explicit
    // success-path notify automatically fires notify_waiters() and removes the
    // entry, preventing the DashMap leak (Fix D).
    state.readiness_notifier(&full_name);
    let mut readiness_guard =
        ReadinessGuard::new(full_name.clone(), std::sync::Arc::clone(&state.readiness));

    // Register keep-alive ownership (if applicable)
    // This also revokes protection from any previous owner with the same ID
    let mut keep_alive_guard = KeepAliveRegistrationGuard::new(
        state.keep_alive_registry.clone(),
        keep_alive_id.clone(),
        runtime.name.clone(),
    );
    let mut previous_keep_alive_owner: Option<String> = None;
    let mut keep_alive_generation: Option<u64> = None;
    if let Some(ref ka_id) = keep_alive_id {
        let (previous_owner, generation) = state
            .keep_alive_registry
            .register_with_generation(ka_id, &runtime.name);
        previous_keep_alive_owner = previous_owner;
        keep_alive_generation = Some(generation);
        keep_alive_guard.set_previous_owner(previous_keep_alive_owner.clone());
        if let Some(prev) = &previous_keep_alive_owner {
            metrics().inc_keep_alive_transfer();
            info!(
                "Keep-alive ID '{}' transferred from {} to {}",
                ka_id, prev, runtime.name
            );
        } else {
            info!("Keep-alive ID '{}' registered for {}", ka_id, runtime.name);
        }
    }

    // Build environment variables (convert any JSON values to strings)
    let mut env = req.variables.to_map();
    let build_compression_none = env
        .get("OPEN_RUNTIMES_BUILD_COMPRESSION")
        .map(|v| v.eq_ignore_ascii_case("none"))
        .unwrap_or(false);

    apply_runtime_env_vars(
        &mut env,
        &runtime,
        RuntimeEnvVars {
            version: &req.version,
            entrypoint: &req.entrypoint,
            executor_hostname: &state.config.hostname,
            cpus,
            memory,
            output_directory: &req.output_directory,
            source: &req.source,
        },
    );

    // Always set CI=true
    env.insert("CI".to_string(), "true".to_string());

    // Build container config
    let mut container = ContainerConfig::new(&full_name, &resolved_image)
        .with_hostname(&runtime.hostname)
        .with_cpus(cpus)
        .with_memory_mb(memory)
        .with_envs(env)
        .with_restart_policy(&req.restart_policy)
        .with_label("urt.managed", "true")
        .with_label("urt.executor_hostname", &state.config.hostname)
        .with_label("urt.runtime_id", &req.runtime_id)
        .with_label("urt.version", &req.version);

    if let Some(ref ka_id) = keep_alive_id {
        container = container.with_label("urt.keep_alive_id", ka_id);
        if let Some(generation) = keep_alive_generation {
            container = container.with_label("urt.keep_alive_generation", &generation.to_string());
        }
    }

    // Attach to one configured network at create time, then connect to the rest
    // after start so runtimes are reachable everywhere the executor is attached.
    let primary_network = state.config.random_network().map(str::to_string);
    if let Some(network) = primary_network.as_deref() {
        container = container.with_network(network);
    }

    // Volume mounts - exactly matches Docker.php lines 471-479
    let code_mount_path = if is_legacy_v2(&req.version) {
        "/usr/code"
    } else {
        "/mnt/code"
    };

    // Canonicalize tmp_base first (L1) so all derived paths are consistent and
    // the cleanup target matches what was created.
    let tmp_base_raw = platform::temp_dir();
    let canonical_tmp_base = match tokio::fs::canonicalize(&tmp_base_raw).await {
        Ok(base) => base,
        Err(e) => {
            error!("Failed to canonicalize temp base path: {}", e);
            abandon_pending_create(&state, &full_name, &tmp_base_raw, readiness_guard, false).await;
            return Err(ExecutorError::RuntimeFailed(format!(
                "Failed to canonicalize temp base path: {}",
                e
            )));
        }
    };
    let tmp_folder = canonical_tmp_base.join(&full_name);

    // Verify containment to prevent path-traversal via crafted runtime IDs.
    if !tmp_folder.starts_with(&canonical_tmp_base) {
        drop(readiness_guard);
        state.registry.remove(&full_name).await;
        return Err(ExecutorError::BadRequest(
            "Invalid runtime id leads to unsafe path".to_string(),
        ));
    }

    // Create mount directories (Docker.php line 448) — derived from canonical base.
    let src_dir: PathBuf = tmp_folder.join("src");
    let builds_dir: PathBuf = tmp_folder.join("builds");
    if let Err(e) = tokio::fs::create_dir_all(&src_dir).await {
        error!(
            "Failed to create src directory {}: {}",
            src_dir.display(),
            e
        );
        abandon_pending_create(&state, &full_name, &tmp_folder, readiness_guard, false).await;
        return Err(ExecutorError::RuntimeFailed(format!(
            "Failed to create source directory: {}",
            e
        )));
    }
    // Set directory permissions to 0777 to allow tar extraction with preserved permissions
    if let Err(e) = platform::set_permissions_open(&src_dir).await {
        error!(
            "Failed to set src directory permissions {}: {}",
            src_dir.display(),
            e
        );
        abandon_pending_create(&state, &full_name, &tmp_folder, readiness_guard, false).await;
        return Err(ExecutorError::RuntimeFailed(format!(
            "Failed to set source directory permissions: {}",
            e
        )));
    }
    if let Err(e) = tokio::fs::create_dir_all(&builds_dir).await {
        error!(
            "Failed to create builds directory {}: {}",
            builds_dir.display(),
            e
        );
        abandon_pending_create(&state, &full_name, &tmp_folder, readiness_guard, false).await;
        return Err(ExecutorError::RuntimeFailed(format!(
            "Failed to create builds directory: {}",
            e
        )));
    }
    // Set directory permissions to 0777 to allow tar extraction with preserved permissions
    if let Err(e) = platform::set_permissions_open(&builds_dir).await {
        error!("Failed to set builds directory permissions: {}", e);
        abandon_pending_create(&state, &full_name, &tmp_folder, readiness_guard, false).await;
        return Err(ExecutorError::RuntimeFailed(format!(
            "Failed to set builds directory permissions: {}",
            e
        )));
    }

    // Copy source file from storage to local tmp (Docker.php lines 439-443)
    // This is required because Docker can only mount local paths
    if !req.source.is_empty() {
        // Same derivation the OPEN_RUNTIMES_CODE_PATH env var uses, so the mounted
        // file name and the path handed to the runtime cannot drift.
        let local_source = src_dir.join(source_mount_file_name(&req.source));

        info!(
            "Downloading source {} to {}",
            req.source,
            local_source.display()
        );
        match storage::download_verified_archive(
            state.storage.as_ref(),
            &req.source,
            &local_source,
            state.config.retry_attempts,
            state.config.retry_delay_ms,
        )
        .await
        {
            Ok(size) => info!("Source downloaded successfully: {} bytes", size),
            Err(e) => {
                error!("Failed to download source {}: {}", req.source, e);
                // Leave nothing behind: the pending entry, the readiness notifier,
                // the create-tracker slot and the tmp folder all go, so the next
                // request for this deployment starts a fresh create rather than
                // adopting a runtime built from a body that is not an archive.
                abandon_pending_create(&state, &full_name, &tmp_folder, readiness_guard, false)
                    .await;
                return Err(source_download_error(&req.source, e));
            }
        }

        // Fix permissions on all input source files before handing off to the runtime container.
        // This prevents tar from trying to chown/chmod on a Docker-mounted volume (exit code 2).
        if let Err(e) = platform::set_permissions_recursive(&src_dir).await {
            warn!("Failed to normalize src directory permissions: {}", e);
            // Non-fatal: log and continue
        }
    }

    // Add standard mounts (Docker.php lines 471-474)
    let src_dir_str = src_dir.display().to_string();
    let builds_dir_str = builds_dir.display().to_string();
    container = container
        .with_mount(&src_dir_str, "/tmp", false)
        .with_mount(&builds_dir_str, code_mount_path, false);

    // Add v5-specific mounts (Docker.php lines 476-479)
    if uses_modern_runtime_layout(&req.version) {
        let logs_dir = tmp_folder.join("logs");
        let logging_dir = tmp_folder.join("logging");
        tokio::fs::create_dir_all(&logs_dir).await.ok();
        tokio::fs::create_dir_all(&logging_dir).await.ok();
        let logs_dir_str = logs_dir.display().to_string();
        let logging_dir_str = logging_dir.display().to_string();
        container = container
            .with_mount(&logs_dir_str, "/mnt/logs", false)
            .with_mount(&logging_dir_str, "/tmp/logging", false);
    }

    // Container command logic - exactly matches Docker.php lines 456-464
    let cmd = if !req.docker_cmd.is_empty() {
        // Explicit docker_cmd overrides everything
        req.docker_cmd.clone()
    } else if !req.runtime_entrypoint.is_empty() {
        // runtimeEntrypoint provided - run it via bash (Docker.php line 463)
        vec![
            "bash".to_string(),
            "-c".to_string(),
            req.runtime_entrypoint.clone(),
        ]
    } else if is_legacy_v2(&req.version) && req.command.is_empty() {
        // v2 with no command - no keep-alive needed (Docker.php lines 457-458)
        vec![]
    } else {
        // Default: keep container alive with tail (Docker.php line 460)
        vec![
            "tail".to_string(),
            "-f".to_string(),
            "/dev/null".to_string(),
        ]
    };

    if !cmd.is_empty() {
        container = container.with_cmd(cmd);
    }

    // Create and start container
    let mut output_logs = Vec::new();
    let docker = state.docker.clone();

    match retry_with_backoff(
        "runtime_create_container",
        state.config.retry_attempts,
        state.config.retry_delay_ms,
        |_| {
            let container_cfg = container.clone();
            let docker = docker.clone();
            async move { docker.create_container(container_cfg).await }
        },
    )
    .await
    {
        Ok(container_id) => {
            output_logs.push(LogEntry {
                timestamp: chrono::Utc::now().to_rfc3339(),
                content: format!("Container created: {}", container_id),
            });
        }
        Err(e) => {
            error!("Failed to create container: {}", e);
            abandon_pending_create(&state, &full_name, &tmp_folder, readiness_guard, true).await;
            return Err(ExecutorError::RuntimeFailed(format!(
                "Failed to create container: {}",
                e
            )));
        }
    }

    if state.config.networks.len() > 1 {
        state.docker.connect_container_to_networks(&full_name).await;
    }

    // Wait for container to reach running state, with exponential backoff.
    // Start fast (50ms) to detect quick-starting containers, then progressively back off.
    let startup_timeout = Duration::from_secs(30);
    let deadline = tokio::time::Instant::now() + startup_timeout;
    let mut poll_delay = Duration::from_millis(50);
    let max_poll_delay = Duration::from_secs(1);
    let mut last_status = String::from("unknown");
    let mut running = false;

    loop {
        if tokio::time::Instant::now() >= deadline {
            break;
        }

        match state.docker.inspect_container(&full_name).await {
            Ok(info) => {
                let status = info.state.to_lowercase();
                last_status = info.state.clone();

                if status == "running" {
                    running = true;
                    break;
                }

                if matches!(status.as_str(), "exited" | "dead" | "removing" | "failed") {
                    // Terminal failure states — no point retrying.
                    error!("Container reached terminal state: {}", info.state);
                    abandon_pending_create(&state, &full_name, &tmp_folder, readiness_guard, true)
                        .await;
                    return Err(ExecutorError::RuntimeFailed(format!(
                        "Container exited with status: {}",
                        info.state
                    )));
                }

                // "created", "restarting", "paused", etc: keep waiting with backoff.
            }
            Err(e) => {
                // Transient inspect error: continue to next retry
                debug!("Failed to inspect container {}: {}", full_name, e);
            }
        }

        tokio::time::sleep(poll_delay).await;
        poll_delay = (poll_delay * 2).min(max_poll_delay);
    }

    if !running {
        // Final timeout handling - one last inspect for the freshest status.
        let last_status = state
            .docker
            .inspect_container(&full_name)
            .await
            .map(|i| i.state)
            .unwrap_or(last_status);

        error!("Container startup timed out, last status: {}", last_status);
        abandon_pending_create(&state, &full_name, &tmp_folder, readiness_guard, true).await;
        return Err(ExecutorError::RuntimeFailed(format!(
            "Container startup timed out (last status: {})",
            last_status
        )));
    }

    // Note: runtime_entrypoint is now the container CMD (Docker.php line 463)
    // It runs as the main container process, not via exec

    // Execute additional command if provided (Docker.php lines 505-545)
    // v5 uses script command for log capture, v2 uses simple shell
    if !req.command.is_empty() {
        info!("Executing build command: {}", req.command);

        // Normalize tar extraction flags to prevent permission errors on Docker volumes.
        let sanitized_command = sanitize_tar_flags(&req.command);

        let wrapped_command = if is_legacy_v2(&req.version) {
            // v2: simple shell with log capture
            format!(
                "touch /var/tmp/logs.txt && ({}) >> /var/tmp/logs.txt 2>&1 && cat /var/tmp/logs.txt",
                sanitized_command
            )
        } else {
            // v5: use script for proper TTY logging
            format!(
                "mkdir -p /tmp/logging && touch /tmp/logging/timings.txt && touch /tmp/logging/logs.txt && script --log-out /tmp/logging/logs.txt --flush --log-timing /tmp/logging/timings.txt --return --quiet --command \"{}\"",
                sanitized_command.replace('"', "\\\"")
            )
        };

        // Execute using the appropriate shell for the version
        // v2 uses sh, v5 uses bash (matches executor-main Docker.php lines 507-517)
        let exec_result = if is_legacy_v2(&req.version) {
            state
                .docker
                .exec_shell(&full_name, &wrapped_command, req.timeout as u64)
                .await
        } else {
            state
                .docker
                .exec_bash(&full_name, &wrapped_command, req.timeout as u64)
                .await
        };

        match exec_result {
            Ok(result) => {
                // For v5, parse logs with timing info (matches executor-main Logs::get())
                if uses_modern_runtime_layout(&req.version) {
                    let logging_dir = tmp_folder.join("logging");
                    let logging_dir_str = logging_dir.display().to_string();
                    let parsed_logs = parse_build_logs(&logging_dir_str).await;
                    output_logs.extend(parsed_logs);
                } else if !result.stdout.is_empty() {
                    // v2: use stdout directly
                    output_logs.push(LogEntry {
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        content: result.stdout,
                    });
                }

                if result.exit_code != 0 {
                    error!(
                        "Build command failed with code {}: {}",
                        result.exit_code, result.stderr
                    );
                    // On failure, cleanup and return error
                    abandon_pending_create(&state, &full_name, &tmp_folder, readiness_guard, true)
                        .await;

                    let error_msg = if output_logs.is_empty() {
                        result.stderr.clone()
                    } else {
                        output_logs
                            .iter()
                            .map(|l| l.content.clone())
                            .collect::<Vec<_>>()
                            .join("\n")
                    };
                    return Err(ExecutorError::RuntimeFailed(error_msg));
                }
            }
            Err(e) => {
                error!("Failed to execute build command: {}", e);
                abandon_pending_create(&state, &full_name, &tmp_folder, readiness_guard, true)
                    .await;
                return Err(ExecutorError::RuntimeFailed(format!(
                    "Failed to execute command: {}",
                    e
                )));
            }
        }
    }

    // Handle destination - copy build artifact to storage (Docker.php lines 550-567)
    let mut result_path: Option<String> = None;
    let mut result_size: Option<u64> = None;

    if !req.destination.is_empty() {
        // Determine build file path (matches executor-main OPEN_RUNTIMES_BUILD_COMPRESSION)
        let build_file = if build_compression_none {
            "code.tar"
        } else {
            "code.tar.gz"
        };
        let local_build = builds_dir.join(build_file);
        let local_build_str = local_build.display().to_string();

        // Check if build artifact exists
        if tokio::fs::metadata(&local_build).await.is_ok() {
            // Get file size
            if let Ok(metadata) = tokio::fs::metadata(&local_build).await {
                result_size = Some(metadata.len());
            }

            // Generate unique destination path
            let unique_id = uuid::Uuid::new_v4().to_string();
            let dest_path = if build_file.ends_with(".tar") {
                format!(
                    "{}/{}.tar",
                    req.destination.trim_end_matches('/'),
                    unique_id
                )
            } else {
                format!(
                    "{}/{}.tar.gz",
                    req.destination.trim_end_matches('/'),
                    unique_id
                )
            };

            // Upload to storage
            info!("Uploading build artifact to {}", dest_path);
            if let Err(e) = retry_with_backoff(
                "runtime_artifact_upload",
                state.config.retry_attempts,
                state.config.retry_delay_ms,
                |_| async { state.storage.upload(&local_build_str, &dest_path).await },
            )
            .await
            {
                error!("Failed to upload build artifact: {}", e);
                // Continue anyway, just won't have the path
            } else {
                result_path = Some(dest_path);
            }
        } else {
            error!("Build artifact not found at {}", local_build.display());
        }
    }

    // Container cleanup if remove flag is set (Docker.php lines 640-652)
    if req.remove {
        // Allow time to read logs
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        // Remove container
        state.docker.remove_container(&full_name, true).await.ok();

        // Delete local tmp folder
        tokio::fs::remove_dir_all(&tmp_folder).await.ok();

        // Disarm the guard then manually notify so we control ordering:
        // notify_waiters fires here, then the registry entry is removed.
        readiness_guard.disarm();
        state.readiness_notify_and_remove(&full_name);
        // Remove from registry
        state.registry.remove(&full_name).await;

        info!("Cleaned up runtime {} after build", req.runtime_id);
    } else {
        let mut updated_runtime = runtime.clone();
        if state.config.eager_runtime_readiness {
            let port_timeout_secs = u64::from(req.timeout.clamp(1, 30));
            if let Err(error) =
                wait_for_runtime_port(&full_name, 3000, Duration::from_secs(port_timeout_secs))
                    .await
            {
                error!(
                    "Runtime {} failed port readiness: {}",
                    req.runtime_id, error
                );
                abandon_pending_create(&state, &full_name, &tmp_folder, readiness_guard, true)
                    .await;
                return Err(ExecutorError::RuntimeFailed(
                    "Runtime port readiness check timed out".to_string(),
                ));
            }
            updated_runtime.set_listening();
        }
        updated_runtime.mark_running("running");
        if let Err(e) = state.registry.update(updated_runtime).await {
            // Entry was concurrently removed (e.g. a racing DELETE). Wake any
            // parked waiters first so they re-check and return a deterministic
            // 404 rather than waiting to deadline, then tear down the orphaned
            // container and working directory before propagating the error.
            readiness_guard.disarm();
            state.readiness_notify_and_remove(&full_name);
            state.docker.remove_container(&full_name, true).await.ok();
            tokio::fs::remove_dir_all(&tmp_folder).await.ok();
            return Err(e);
        }
        // Disarm the guard and then explicitly notify AFTER registry.update so
        // that woken waiters find a non-pending entry.
        readiness_guard.disarm();
        state.readiness_notify_and_remove(&full_name);
    }

    // If a keep-alive ID was transferred, clean up the previous owner now that
    // this runtime is successfully running (avoid removing the new runtime).
    if !req.remove {
        if let (Some(prev), Some(ka_id)) = (previous_keep_alive_owner, keep_alive_id.as_ref()) {
            if prev != runtime.name {
                cleanup_previous_keep_alive_runtime(&state, &prev, ka_id, keep_alive_generation)
                    .await;
            }
        }

        keep_alive_guard.commit();
    }

    let duration = start_time.elapsed().as_secs_f64();

    info!("Runtime {} created in {:.2}s", req.runtime_id, duration);

    Ok(CreateRuntimeResponse {
        output: output_logs,
        path: result_path,
        size: result_size,
        start_time: start_timestamp,
        duration,
    })
}

/// GET /v1/runtimes - List all runtimes
pub async fn list_runtimes(State(state): State<AppState>) -> Result<Json<Vec<Runtime>>> {
    let runtimes = state.registry.list().await;
    Ok(Json(runtimes))
}

/// GET /v1/runtimes/:runtime_id - Get a single runtime
pub async fn get_runtime(
    State(state): State<AppState>,
    Path(runtime_id): Path<String>,
) -> Result<Json<Runtime>> {
    let full_name = format!("{}-{}", state.config.hostname, runtime_id);

    // Sync status from Docker once, then fall back to registry lookup (M3).
    let synced = state.registry.sync_status(&full_name, &state.docker).await;
    let runtime = if let Some(rt) = synced {
        rt
    } else if let Some(rt) = state.registry.get(&full_name).await {
        rt
    } else {
        let _ = tasks::adopt_container_by_name(
            &state.docker,
            &state.registry,
            &state.keep_alive_registry,
            &state.config.hostname,
            &full_name,
        )
        .await;

        {
            let after_adopt_synced = state.registry.sync_status(&full_name, &state.docker).await;
            if let Some(rt) = after_adopt_synced {
                rt
            } else if let Some(rt) = state.registry.get(&full_name).await {
                rt
            } else {
                return Err(ExecutorError::RuntimeNotFound);
            }
        }
    };

    Ok(Json(runtime))
}

/// DELETE /v1/runtimes/:runtime_id - Delete a runtime (idempotent, best-effort cleanup)
/// DELETE /v1/runtimes/:runtime_id - Delete a runtime (label-based, no name guessing)
pub async fn delete_runtime(
    State(state): State<AppState>,
    Path(runtime_id): Path<String>,
) -> Result<StatusCode> {
    // Validate runtime_id from URL path parameter
    validate_runtime_id(&runtime_id)?;

    let full_name = format!("{}-{}", state.config.hostname, runtime_id);

    info!("Deleting runtime: {}", full_name);

    // Get runtime info before deletion to check keep_alive_id
    let runtime_info = state.registry.get(&full_name).await;
    let _keep_alive_lock = match runtime_info
        .as_ref()
        .and_then(|runtime| runtime.keep_alive_id.as_ref())
    {
        Some(ka_id) => Some(state.keep_alive_registry.lock(ka_id).await),
        None => None,
    };

    // DO NOT GUESS THE NAME — ASK DOCKER
    let label = format!("urt.runtime_id={}", runtime_id);

    if let Ok(containers) = state.docker.list_containers(Some(&label)).await {
        for container in containers {
            // Uses your existing remove_container implementation
            let _ = state.docker.remove_container(&container.name, true).await;
        }
    }

    // Remove runtime-owned tmp directory
    let tmp_base = platform::temp_dir();
    let tmp_folder = tmp_base.join(&full_name);
    tokio::fs::remove_dir_all(&tmp_folder).await.ok();

    // Unregister keep-alive ownership if this runtime had one
    if let Some(runtime) = runtime_info {
        if let Some(ref ka_id) = runtime.keep_alive_id {
            state.keep_alive_registry.unregister(ka_id, &full_name);
            info!(
                "Keep-alive ID '{}' unregistered for deleted runtime {}",
                ka_id, full_name
            );
        }
    }

    // Registry is metadata only; remove last (idempotent)
    state.readiness_notify_and_remove(&full_name);
    state.registry.remove(&full_name).await;

    info!("Delete runtime finished: {}", full_name);

    Ok(StatusCode::OK)
}

async fn cleanup_previous_keep_alive_runtime(
    state: &AppState,
    previous_owner: &str,
    keep_alive_id: &str,
    replacement_generation: Option<u64>,
) {
    info!(
        "Cleaning up previous keep-alive runtime {} for keep-alive ID '{}'",
        previous_owner, keep_alive_id
    );

    let runtime_info = state.registry.get(previous_owner).await;
    if state
        .keep_alive_registry
        .is_owner(keep_alive_id, previous_owner)
    {
        metrics().inc_keep_alive_cleanup("skipped_owner_guard");
        debug!(
            "Skipping keep-alive cleanup for {} on '{}' because it is still the owner",
            previous_owner, keep_alive_id
        );
        return;
    }

    if let Some(expected_generation) = replacement_generation {
        if let Ok(container_info) = state.docker.inspect_container(previous_owner).await {
            let label_keep_alive_id = container_info
                .labels
                .get("urt.keep_alive_id")
                .map(String::as_str)
                .unwrap_or_default();
            if label_keep_alive_id != keep_alive_id {
                metrics().inc_keep_alive_cleanup("skipped_id_mismatch");
                debug!(
                    "Skipping keep-alive cleanup for {} due keep-alive label mismatch (expected '{}', got '{}')",
                    previous_owner, keep_alive_id, label_keep_alive_id
                );
                return;
            }

            let label_generation = container_info
                .labels
                .get("urt.keep_alive_generation")
                .and_then(|value| value.parse::<u64>().ok());
            if label_generation == Some(expected_generation) {
                metrics().inc_keep_alive_cleanup("skipped_generation_guard");
                debug!(
                    "Skipping keep-alive cleanup for {} due generation guard (generation={})",
                    previous_owner, expected_generation
                );
                return;
            }
        }
    }

    if let Err(e) = state.docker.stop_container(previous_owner, 10).await {
        metrics().inc_keep_alive_cleanup("stop_error");
        debug!(
            "Previous keep-alive container {} stop returned non-fatal error: {}",
            previous_owner, e
        );
    }

    match state.docker.remove_container(previous_owner, true).await {
        Ok(_) => {
            metrics().inc_keep_alive_cleanup("removed");
        }
        Err(ExecutorError::RuntimeNotFound) => {
            metrics().inc_keep_alive_cleanup("missing");
        }
        Err(e) => {
            metrics().inc_keep_alive_cleanup("remove_error");
            warn!(
                "Failed to remove previous keep-alive container {}: {}",
                previous_owner, e
            );
        }
    }

    let tmp_folder = platform::temp_dir().join(previous_owner);
    tokio::fs::remove_dir_all(&tmp_folder).await.ok();

    if let Some(runtime) = runtime_info {
        if let Some(ref ka_id) = runtime.keep_alive_id {
            state.keep_alive_registry.unregister(ka_id, previous_owner);
        }
    }

    state.registry.remove(previous_owner).await;
}

#[cfg(test)]
mod tests {
    use super::{
        apply_runtime_env_vars, is_legacy_v2, is_live_container_state, sanitize_tar_flags,
        source_mount_file_name, uses_modern_runtime_layout, KeepAliveRegistrationGuard,
        RuntimeEnvVars, DEFAULT_RUNTIME_BIND_HOSTNAME, RUNTIME_BIND_HOSTNAME_VAR,
    };
    use crate::runtime::{KeepAliveRegistry, Runtime};
    use std::collections::HashMap;

    #[test]
    fn test_sanitize_tar_flags_injects_portable_flags() {
        let cmd = "tar -zxf /tmp/code.tar.gz -C /mnt/code && helpers/build.sh 'npm install'";
        let result = sanitize_tar_flags(cmd);
        assert!(
            result.contains("--no-same-permissions"),
            "expected --no-same-permissions in: {}",
            result
        );
        assert!(result.contains(" -o "), "expected -o in: {}", result);
        assert!(
            !result.contains("--no-acls"),
            "unexpected GNU-only --no-acls in: {}",
            result
        );
        assert!(
            !result.contains("--no-xattrs"),
            "unexpected GNU-only --no-xattrs in: {}",
            result
        );
        // Non-tar parts of the command must be preserved.
        assert!(
            result.contains("helpers/build.sh"),
            "expected helpers/build.sh to be preserved in: {}",
            result
        );
    }

    #[test]
    fn test_sanitize_tar_flags_xzf_variant() {
        let cmd = "tar -xzf /tmp/code.tar.gz -C /mnt/code";
        let result = sanitize_tar_flags(cmd);
        assert!(result.contains("--no-same-permissions"));
        assert!(result.contains(" -o "));
    }

    #[test]
    fn test_sanitize_tar_flags_xf_variant() {
        let cmd = "tar -xf /tmp/code.tar -C /mnt/code";
        let result = sanitize_tar_flags(cmd);
        assert!(result.contains("--no-same-permissions"));
        assert!(result.contains(" -o "));
    }

    #[test]
    fn test_sanitize_tar_flags_no_change_for_create() {
        // tar -czf is a create command and must not be modified.
        let cmd = "tar -czf output.tar.gz /mnt/code";
        let result = sanitize_tar_flags(cmd);
        assert!(
            !result.contains("--no-same-permissions"),
            "create command must not be modified, got: {}",
            result
        );
    }

    #[test]
    fn test_sanitize_tar_flags_idempotent() {
        // Flags already present: must not be duplicated.
        let cmd = "tar --no-same-permissions -o -zxf /tmp/code.tar.gz -C /mnt/code";
        let result = sanitize_tar_flags(cmd);
        assert_eq!(
            result.matches("--no-same-permissions").count(),
            1,
            "flags must appear exactly once, got: {}",
            result
        );
        assert_eq!(
            result.matches(" -o ").count(),
            1,
            "flags must appear exactly once, got: {}",
            result
        );
    }

    #[test]
    fn test_sanitize_tar_flags_no_tar_in_command() {
        // Command with no tar invocation must be returned unchanged.
        let cmd = "npm install && npm run build";
        let result = sanitize_tar_flags(cmd);
        assert_eq!(result, cmd);
    }

    #[test]
    fn test_keep_alive_registration_guard_rolls_back_owner_on_drop() {
        let registry = KeepAliveRegistry::new();
        registry.register("svc-a", "runtime-old");

        {
            let mut guard = KeepAliveRegistrationGuard::new(
                registry.clone(),
                Some("svc-a".to_string()),
                "runtime-new".to_string(),
            );
            let previous = registry.register("svc-a", "runtime-new");
            guard.set_previous_owner(previous);
            // no commit => drop rolls back to previous owner
        }

        assert_eq!(registry.get_owner("svc-a"), Some("runtime-old".to_string()));
    }

    #[test]
    fn test_keep_alive_registration_guard_commit_keeps_new_owner() {
        let registry = KeepAliveRegistry::new();
        registry.register("svc-b", "runtime-old");

        {
            let mut guard = KeepAliveRegistrationGuard::new(
                registry.clone(),
                Some("svc-b".to_string()),
                "runtime-new".to_string(),
            );
            let previous = registry.register("svc-b", "runtime-new");
            guard.set_previous_owner(previous);
            guard.commit();
        }

        assert_eq!(registry.get_owner("svc-b"), Some("runtime-new".to_string()));
    }

    #[test]
    fn test_version_helpers_treat_only_v2_as_legacy() {
        assert!(is_legacy_v2("v2"));
        assert!(is_legacy_v2(" V2 "));
        assert!(!is_legacy_v2("v4"));
        assert!(uses_modern_runtime_layout("v4"));
        assert!(uses_modern_runtime_layout("v5"));
    }

    #[test]
    fn test_live_container_state_includes_running_and_created_states() {
        assert!(is_live_container_state("running", ""));
        assert!(is_live_container_state("created", ""));
        assert!(is_live_container_state("", "Up 10 seconds"));
        assert!(!is_live_container_state("exited", ""));
    }

    #[test]
    fn test_apply_runtime_env_vars_uses_executor_hostname_for_modern_runtimes() {
        let runtime = Runtime::new("rt1", "executor-a", "img", "v5", None);
        let mut env = HashMap::new();

        apply_runtime_env_vars(
            &mut env,
            &runtime,
            RuntimeEnvVars {
                version: "v5",
                entrypoint: "index.js",
                executor_hostname: "executor-a",
                cpus: 1.0,
                memory: 512,
                output_directory: "dist",
                source: "",
            },
        );

        assert_eq!(
            env.get("OPEN_RUNTIMES_HOSTNAME"),
            Some(&"executor-a".to_string())
        );
        assert_eq!(
            env.get("OPEN_RUNTIMES_ENTRYPOINT"),
            Some(&"index.js".to_string())
        );
        assert_eq!(
            env.get("OPEN_RUNTIMES_OUTPUT_DIRECTORY"),
            Some(&"dist".to_string())
        );
        assert_ne!(
            env.get("OPEN_RUNTIMES_HOSTNAME"),
            Some(&runtime.hostname),
            "executor hostname must not be replaced with the random container hostname"
        );
    }

    #[test]
    fn test_apply_runtime_env_vars_sets_legacy_hostname_aliases() {
        let runtime = Runtime::new("rt2", "executor-a", "img", "v2", None);
        let mut env = HashMap::new();

        apply_runtime_env_vars(
            &mut env,
            &runtime,
            RuntimeEnvVars {
                version: "v2",
                entrypoint: "index.php",
                executor_hostname: "executor-a",
                cpus: 1.0,
                memory: 512,
                output_directory: "",
                source: "",
            },
        );

        assert_eq!(
            env.get("INTERNAL_EXECUTOR_HOSTNAME"),
            Some(&"executor-a".to_string())
        );
        assert_eq!(
            env.get("INERNAL_EXECUTOR_HOSTNAME"),
            Some(&"executor-a".to_string())
        );
    }

    fn env_for_source(version: &str, source: &str, env: &mut HashMap<String, String>) {
        let runtime = Runtime::new("rt-code-path", "executor-a", "img", version, None);
        apply_runtime_env_vars(
            env,
            &runtime,
            RuntimeEnvVars {
                version,
                entrypoint: "index.js",
                executor_hostname: "executor-a",
                cpus: 1.0,
                memory: 512,
                output_directory: "",
                source,
            },
        );
    }

    fn modern_env_with(variables: &[(&str, &str)]) -> HashMap<String, String> {
        let runtime = Runtime::new("rt-bind", "executor-a", "img", "v5", None);
        let mut env: HashMap<String, String> = variables
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        apply_runtime_env_vars(
            &mut env,
            &runtime,
            RuntimeEnvVars {
                version: "v5",
                entrypoint: "index.js",
                executor_hostname: "executor-a",
                cpus: 1.0,
                memory: 512,
                output_directory: "",
                source: "",
            },
        );

        env
    }

    #[test]
    fn test_code_path_points_at_gzipped_tar_mount_for_modern_runtimes() {
        let mut env = HashMap::new();
        env_for_source("v5", "5f2a/code.tar.gz", &mut env);

        assert_eq!(
            env.get("OPEN_RUNTIMES_CODE_PATH"),
            Some(&"/tmp/code.tar.gz".to_string())
        );
    }

    #[test]
    fn test_code_path_keeps_plain_tar_extension() {
        let mut env = HashMap::new();
        env_for_source("v5", "5f2a/code.tar", &mut env);

        assert_eq!(
            env.get("OPEN_RUNTIMES_CODE_PATH"),
            Some(&"/tmp/code.tar".to_string())
        );
    }

    #[test]
    fn test_code_path_absent_without_source() {
        let mut env = HashMap::new();
        env_for_source("v5", "", &mut env);

        assert_eq!(env.get("OPEN_RUNTIMES_CODE_PATH"), None);
    }

    #[test]
    fn test_code_path_absent_for_legacy_v2() {
        let mut env = HashMap::new();
        env_for_source("v2", "5f2a/code.tar.gz", &mut env);

        assert_eq!(env.get("OPEN_RUNTIMES_CODE_PATH"), None);
    }

    #[test]
    fn test_code_path_preserves_caller_supplied_value() {
        let mut env = HashMap::new();
        env.insert(
            "OPEN_RUNTIMES_CODE_PATH".to_string(),
            "/mnt/code/.extracted".to_string(),
        );
        env_for_source("v5", "5f2a/code.tar.gz", &mut env);

        assert_eq!(
            env.get("OPEN_RUNTIMES_CODE_PATH"),
            Some(&"/mnt/code/.extracted".to_string())
        );
    }

    #[test]
    fn test_source_mount_file_name_covers_known_archive_extensions() {
        assert_eq!(source_mount_file_name("a/code.tar.gz"), "code.tar.gz");
        assert_eq!(source_mount_file_name("a/code.tar"), "code.tar");
        assert_eq!(source_mount_file_name("a/code.tgz"), "code.tgz");
        assert_eq!(source_mount_file_name("a/code.sqfs"), "code.sqfs");
        assert_eq!(source_mount_file_name("a/code.gz"), "code.gz");
        assert_eq!(source_mount_file_name("a/CODE.TAR"), "code.tar");
        // Unknown or missing extensions fall back to the gzipped-tar default.
        assert_eq!(source_mount_file_name("a/code"), "code.tar.gz");
        assert_eq!(source_mount_file_name("a/code.zip"), "code.tar.gz");
    }

    #[test]
    fn test_apply_runtime_env_vars_defaults_bind_hostname_to_wildcard() {
        let env = modern_env_with(&[]);

        assert_eq!(
            env.get(RUNTIME_BIND_HOSTNAME_VAR),
            Some(&DEFAULT_RUNTIME_BIND_HOSTNAME.to_string()),
            "runtimes must bind to the wildcard address so the executor can reach them"
        );
    }

    #[test]
    fn test_apply_runtime_env_vars_keeps_caller_supplied_bind_hostname() {
        let env = modern_env_with(&[(RUNTIME_BIND_HOSTNAME_VAR, "127.0.0.1")]);

        assert_eq!(
            env.get(RUNTIME_BIND_HOSTNAME_VAR),
            Some(&"127.0.0.1".to_string()),
            "a caller-supplied HOSTNAME is the escape hatch and must survive"
        );
    }

    #[test]
    fn test_apply_runtime_env_vars_replaces_blank_bind_hostname() {
        let env = modern_env_with(&[(RUNTIME_BIND_HOSTNAME_VAR, "   ")]);

        assert_eq!(
            env.get(RUNTIME_BIND_HOSTNAME_VAR),
            Some(&DEFAULT_RUNTIME_BIND_HOSTNAME.to_string()),
            "a blank value is not a bind address and must not defeat the default"
        );
    }

    #[test]
    fn test_apply_runtime_env_vars_does_not_set_bind_hostname_for_legacy_v2() {
        let runtime = Runtime::new("rt-legacy-bind", "executor-a", "img", "v2", None);
        let mut env = HashMap::new();

        apply_runtime_env_vars(
            &mut env,
            &runtime,
            RuntimeEnvVars {
                version: "v2",
                entrypoint: "index.php",
                executor_hostname: "executor-a",
                cpus: 1.0,
                memory: 512,
                output_directory: "",
                source: "",
            },
        );

        assert_eq!(
            env.get(RUNTIME_BIND_HOSTNAME_VAR),
            None,
            "legacy v2 images keep the Docker-provided container identity"
        );
    }

    #[test]
    fn test_apply_runtime_env_vars_leaves_executor_hostname_variables_untouched() {
        let env = modern_env_with(&[]);

        assert_eq!(
            env.get("OPEN_RUNTIMES_HOSTNAME"),
            Some(&"executor-a".to_string()),
            "OPEN_RUNTIMES_HOSTNAME addresses the executor and is unrelated to the bind address"
        );
    }
}
