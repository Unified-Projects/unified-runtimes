//! Runtime CRUD endpoints

use super::executions::VariablesInput;
use super::logs::{parse_build_logs, LogEntry};
use super::AppState;
use crate::docker::container::ContainerConfig;
use crate::error::{ExecutorError, Result};
use crate::runtime::Runtime;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;
use tracing::{error, info};

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
/// Default CPU allocation - 4 cores for maximum throughput
pub fn default_cpus() -> f64 {
    4.0
}
/// Default memory allocation - 2GB for high-performance workloads
pub fn default_memory() -> u64 {
    2048
}
pub fn default_version() -> String {
    "v5".to_string()
}
const DEFAULT_RESTART_POLICY: &str = "no";
pub fn default_restart_policy() -> String {
    DEFAULT_RESTART_POLICY.to_string()
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

/// Response for creating a runtime
/// Field names must match executor-main exactly for Appwrite compatibility
#[derive(Debug, Serialize)]
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

/// POST /v1/runtimes - Create a new runtime
/// Note: Accepts JSON regardless of Content-Type header for backwards compatibility
pub async fn create_runtime(
    State(state): State<AppState>,
    body: String,
) -> Result<(StatusCode, Json<CreateRuntimeResponse>)> {
    let start_time = std::time::Instant::now();
    let start_timestamp = chrono::Utc::now().timestamp_millis() as f64 / 1000.0;

    // Parse JSON body manually for backwards compatibility (no Content-Type requirement)
    let req: CreateRuntimeRequest = serde_json::from_str(&body)
        .map_err(|e| ExecutorError::BadRequest(format!("Invalid JSON: {}", e)))?;

    info!(
        "Creating runtime: {} with image {}",
        req.runtime_id, req.image
    );

    // Validate runtime ID and image name
    validate_runtime_id(&req.runtime_id)?;
    validate_image_name(&req.image)?;

    // Check if runtime already exists
    let full_name = format!("{}-{}", state.config.hostname, req.runtime_id);
    if state.registry.exists(&full_name).await {
        return Err(ExecutorError::RuntimeConflict);
    }

    // Check if image is allowed
    if !state.config.is_runtime_allowed(&req.image) {
        return Err(ExecutorError::BadRequest(format!(
            "Image {} is not in allowed runtimes list",
            req.image
        )));
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

    // Create runtime entry
    let runtime = Runtime::new(
        &req.runtime_id,
        &state.config.hostname,
        &req.image,
        &req.version,
        keep_alive_id.clone(),
    );

    // Register as pending
    state.registry.insert(runtime.clone()).await?;

    // Register keep-alive ownership (if applicable)
    // This also revokes protection from any previous owner with the same ID
    if let Some(ref ka_id) = keep_alive_id {
        let previous_owner = state.keep_alive_registry.register(ka_id, &runtime.name);
        if let Some(prev) = previous_owner {
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

    // Add version-specific variables
    match req.version.as_str() {
        "v2" => {
            env.insert("INTERNAL_RUNTIME_KEY".to_string(), runtime.key.clone());
            env.insert(
                "INTERNAL_RUNTIME_ENTRYPOINT".to_string(),
                req.entrypoint.clone(),
            );
            env.insert(
                "INTERNAL_EXECUTOR_HOSTNAME".to_string(),
                runtime.hostname.clone(),
            );
        }
        _ => {
            // v4/v5
            env.insert("OPEN_RUNTIMES_SECRET".to_string(), runtime.key.clone());
            env.insert(
                "OPEN_RUNTIMES_ENTRYPOINT".to_string(),
                req.entrypoint.clone(),
            );
            env.insert(
                "OPEN_RUNTIMES_HOSTNAME".to_string(),
                runtime.hostname.clone(),
            );
            env.insert("OPEN_RUNTIMES_CPUS".to_string(), cpus.to_string());
            env.insert("OPEN_RUNTIMES_MEMORY".to_string(), memory.to_string());

            if !req.output_directory.is_empty() {
                env.insert(
                    "OPEN_RUNTIMES_OUTPUT_DIRECTORY".to_string(),
                    req.output_directory.clone(),
                );
            }
        }
    }

    // Always set CI=true
    env.insert("CI".to_string(), "true".to_string());

    // Build container config
    let mut container = ContainerConfig::new(&full_name, &req.image)
        .with_hostname(&runtime.hostname)
        .with_cpus(cpus)
        .with_memory_mb(memory)
        .with_envs(env)
        .with_restart_policy(&req.restart_policy)
        .with_label("urt.managed", "true")
        .with_label("urt.runtime_id", &req.runtime_id);

    // Add network
    if let Some(network) = state.config.random_network() {
        container = container.with_network(network);
    }

    // Volume mounts - exactly matches Docker.php lines 471-479
    let tmp_folder = format!("/tmp/{}", full_name);
    let code_mount_path = if req.version == "v2" {
        "/usr/code"
    } else {
        "/mnt/code"
    };

    // Create mount directories (Docker.php line 448)
    let src_dir = format!("{}/src", tmp_folder);
    let builds_dir = format!("{}/builds", tmp_folder);
    if let Err(e) = tokio::fs::create_dir_all(&src_dir).await {
        error!("Failed to create src directory {}: {}", src_dir, e);
        state.registry.remove(&full_name).await;
        return Err(ExecutorError::RuntimeFailed(format!(
            "Failed to create source directory: {}",
            e
        )));
    }
    // Set directory permissions to 0777 to allow tar extraction with preserved permissions
    if let Err(e) =
        tokio::fs::set_permissions(&src_dir, std::fs::Permissions::from_mode(0o777)).await
    {
        error!("Failed to set src directory permissions: {}", e);
        state.registry.remove(&full_name).await;
        return Err(ExecutorError::RuntimeFailed(format!(
            "Failed to set source directory permissions: {}",
            e
        )));
    }
    if let Err(e) = tokio::fs::create_dir_all(&builds_dir).await {
        error!("Failed to create builds directory {}: {}", builds_dir, e);
        state.registry.remove(&full_name).await;
        return Err(ExecutorError::RuntimeFailed(format!(
            "Failed to create builds directory: {}",
            e
        )));
    }
    // Set directory permissions to 0777 to allow tar extraction with preserved permissions
    if let Err(e) =
        tokio::fs::set_permissions(&builds_dir, std::fs::Permissions::from_mode(0o777)).await
    {
        error!("Failed to set builds directory permissions: {}", e);
        state.registry.remove(&full_name).await;
        return Err(ExecutorError::RuntimeFailed(format!(
            "Failed to set builds directory permissions: {}",
            e
        )));
    }

    // Copy source file from storage to local tmp (Docker.php lines 439-443)
    // This is required because Docker can only mount local paths
    if !req.source.is_empty() {
        // Determine source filename based on extension
        let source_file = if req.source.ends_with(".tar") {
            "code.tar"
        } else {
            "code.tar.gz"
        };
        let local_source = format!("{}/{}", src_dir, source_file);

        info!("Downloading source {} to {}", req.source, local_source);
        if let Err(e) = state.storage.download(&req.source, &local_source).await {
            error!("Failed to download source: {}", e);
            state.registry.remove(&full_name).await;
            return Err(ExecutorError::RuntimeFailed(format!(
                "Failed to copy source code: {}",
                e
            )));
        }

        // Verify download and log file size
        if let Ok(metadata) = tokio::fs::metadata(&local_source).await {
            info!("Source downloaded successfully: {} bytes", metadata.len());
        }
    }

    // Add standard mounts (Docker.php lines 471-474)
    container = container.with_mount(&src_dir, "/tmp", false).with_mount(
        &builds_dir,
        code_mount_path,
        false,
    );

    // Add v5-specific mounts (Docker.php lines 476-479)
    if req.version == "v5" {
        let logs_dir = format!("{}/logs", tmp_folder);
        let logging_dir = format!("{}/logging", tmp_folder);
        tokio::fs::create_dir_all(&logs_dir).await.ok();
        tokio::fs::create_dir_all(&logging_dir).await.ok();
        container = container
            .with_mount(&logs_dir, "/mnt/logs", false)
            .with_mount(&logging_dir, "/tmp/logging", false);
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
    } else if req.version == "v2" && req.command.is_empty() {
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

    match state.docker.create_container(container).await {
        Ok(container_id) => {
            output_logs.push(LogEntry {
                timestamp: chrono::Utc::now().to_rfc3339(),
                content: format!("Container created: {}", container_id),
            });
        }
        Err(e) => {
            error!("Failed to create container: {}", e);
            // Remove from registry on failure
            state.registry.remove(&full_name).await;
            return Err(ExecutorError::RuntimeFailed(format!(
                "Failed to create container: {}",
                e
            )));
        }
    }

    // Note: OPR doesn't wait for port during runtime creation (Docker.php lines 482-496)
    // Port readiness is only checked during execution (Docker.php line 1088)
    // Just verify container is running
    tokio::time::sleep(Duration::from_millis(100)).await;
    match state.docker.inspect_container(&full_name).await {
        Ok(info) if info.status.to_lowercase().contains("running") => {
            // Container is running, good to go
        }
        Ok(info) => {
            error!("Container not running, status: {}", info.status);
            state.docker.remove_container(&full_name, true).await.ok();
            state.registry.remove(&full_name).await;
            return Err(ExecutorError::RuntimeFailed(format!(
                "Container exited with status: {}",
                info.status
            )));
        }
        Err(e) => {
            error!("Failed to inspect container: {}", e);
            state.docker.remove_container(&full_name, true).await.ok();
            state.registry.remove(&full_name).await;
            return Err(ExecutorError::RuntimeFailed(format!(
                "Failed to inspect container: {}",
                e
            )));
        }
    }

    // Note: runtime_entrypoint is now the container CMD (Docker.php line 463)
    // It runs as the main container process, not via exec

    // Execute additional command if provided (Docker.php lines 505-545)
    // v5 uses script command for log capture, v2 uses simple shell
    if !req.command.is_empty() {
        info!("Executing build command: {}", req.command);

        let wrapped_command = if req.version == "v2" {
            // v2: simple shell with log capture
            format!(
                "touch /var/tmp/logs.txt && ({}) >> /var/tmp/logs.txt 2>&1 && cat /var/tmp/logs.txt",
                req.command
            )
        } else {
            // v5: use script for proper TTY logging
            format!(
                "mkdir -p /tmp/logging && touch /tmp/logging/timings.txt && touch /tmp/logging/logs.txt && script --log-out /tmp/logging/logs.txt --flush --log-timing /tmp/logging/timings.txt --return --quiet --command \"{}\"",
                req.command.replace('"', "\\\"")
            )
        };

        // Execute using the appropriate shell for the version
        // v2 uses sh, v5 uses bash (matches executor-main Docker.php lines 507-517)
        let exec_result = if req.version == "v2" {
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
                if req.version != "v2" {
                    let logging_dir = format!("{}/logging", tmp_folder);
                    let parsed_logs = parse_build_logs(&logging_dir).await;
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
                    state.docker.remove_container(&full_name, true).await.ok();
                    tokio::fs::remove_dir_all(&tmp_folder).await.ok();
                    state.registry.remove(&full_name).await;

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
                state.docker.remove_container(&full_name, true).await.ok();
                tokio::fs::remove_dir_all(&tmp_folder).await.ok();
                state.registry.remove(&full_name).await;
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
        // Determine build file path
        let build_file = "code.tar.gz";
        let local_build = format!("{}/{}", builds_dir, build_file);

        // Check if build artifact exists
        if tokio::fs::metadata(&local_build).await.is_ok() {
            // Get file size
            if let Ok(metadata) = tokio::fs::metadata(&local_build).await {
                result_size = Some(metadata.len());
            }

            // Generate unique destination path
            let unique_id = uuid::Uuid::new_v4().to_string();
            let dest_path = format!(
                "{}/{}.tar.gz",
                req.destination.trim_end_matches('/'),
                unique_id
            );

            // Upload to storage
            info!("Uploading build artifact to {}", dest_path);
            if let Err(e) = state.storage.upload(&local_build, &dest_path).await {
                error!("Failed to upload build artifact: {}", e);
                // Continue anyway, just won't have the path
            } else {
                result_path = Some(dest_path);
            }
        } else {
            error!("Build artifact not found at {}", local_build);
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

        // Remove from registry
        state.registry.remove(&full_name).await;

        info!("Cleaned up runtime {} after build", req.runtime_id);
    } else {
        // Update runtime status if keeping it running
        if let Ok(info) = state.docker.inspect_container(&full_name).await {
            let mut updated_runtime = runtime.clone();
            updated_runtime.mark_running(&info.status);
            state.registry.update(updated_runtime).await.ok();
        }
    }

    let duration = start_time.elapsed().as_secs_f64();

    info!("Runtime {} created in {:.2}s", req.runtime_id, duration);

    Ok((
        StatusCode::CREATED,
        Json(CreateRuntimeResponse {
            output: output_logs,
            path: result_path,
            size: result_size,
            start_time: start_timestamp,
            duration,
        }),
    ))
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
    let runtime = state
        .registry
        .get_by_id(&runtime_id, &state.config.hostname)
        .await
        .ok_or(ExecutorError::RuntimeNotFound)?;

    Ok(Json(runtime))
}

/// DELETE /v1/runtimes/:runtime_id - Delete a runtime (idempotent, best-effort cleanup)
/// DELETE /v1/runtimes/:runtime_id - Delete a runtime (label-based, no name guessing)
pub async fn delete_runtime(
    State(state): State<AppState>,
    Path(runtime_id): Path<String>,
) -> Result<StatusCode> {
    let full_name = format!("{}-{}", state.config.hostname, runtime_id);

    info!("Deleting runtime: {}", full_name);

    // Get runtime info before deletion to check keep_alive_id
    let runtime_info = state.registry.get(&full_name).await;

    // DO NOT GUESS THE NAME — ASK DOCKER
    let label = format!("urt.runtime_id={}", runtime_id);

    if let Ok(containers) = state.docker.list_containers(Some(&label)).await {
        for container in containers {
            // Uses your existing remove_container implementation
            let _ = state.docker.remove_container(&container.name, true).await;
        }
    }

    // Remove runtime-owned tmp directory
    let tmp_folder = format!("/tmp/{}", full_name);
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
    state.registry.remove(&full_name).await;

    info!("Delete runtime finished: {}", full_name);

    Ok(StatusCode::NO_CONTENT)
}
