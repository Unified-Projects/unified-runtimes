//! Docker manager - main interface for container operations

#![allow(deprecated)]

use super::build::{build_image, BuildRequest, BuildResult};
use super::container::{ContainerConfig, ContainerInfo};
use super::exec::{exec_bash, exec_shell, ExecResult};
use super::network::{connect_container, ensure_network};
use super::stats::{get_container_stats, get_host_stats, ContainerStats, HostStats, StatsCache};
use crate::config::ExecutorConfig;
use crate::error::{ExecutorError, Result};
use crate::storage::{BuildCache, Storage};
use bollard::auth::DockerCredentials;
use bollard::models::{ContainerCreateBody, HostConfig, RestartPolicy, RestartPolicyNameEnum};
use bollard::query_parameters::{
    CreateContainerOptions, CreateImageOptions, InspectContainerOptions, ListContainersOptions,
    RemoveContainerOptions, StartContainerOptions, StopContainerOptions,
};
use bollard::Docker;
use bollard::API_DEFAULT_VERSION;
use futures_util::StreamExt;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::warn;
use tracing::{debug, error, info};

fn is_missing_image_error(message: &str) -> bool {
    let normalized = message.to_ascii_lowercase();
    normalized.contains("no such image")
        || normalized.contains("not found: openruntimes/")
        || normalized.contains("pull access denied")
}

fn map_create_container_error(message: String) -> ExecutorError {
    if message.contains("Conflict")
        || message.contains("already in use")
        || message.contains("is already in use")
    {
        return ExecutorError::RuntimeConflict;
    }

    ExecutorError::Docker(message)
}

fn restart_policy_for(policy: &str) -> Option<RestartPolicy> {
    let name = match policy {
        "always" => RestartPolicyNameEnum::ALWAYS,
        "on-failure" => {
            return Some(RestartPolicy {
                name: Some(RestartPolicyNameEnum::ON_FAILURE),
                maximum_retry_count: Some(3),
            })
        }
        "unless-stopped" => RestartPolicyNameEnum::UNLESS_STOPPED,
        _ => RestartPolicyNameEnum::NO,
    };

    Some(RestartPolicy {
        name: Some(name),
        maximum_retry_count: None,
    })
}

/// Host configuration for a runtime container: resource limits, mounts, the
/// security hardening URT adds over executor-main, and the network the
/// container is created on.
///
/// The network is set as the container's network mode rather than attached
/// afterwards. Creating on the default bridge and connecting later leaves the
/// container on both networks, so a server that binds to its container address
/// binds to the bridge address the executor cannot reach, and every runtime
/// gets L2 reach to everything else on the bridge. executor-main runs its
/// runtimes with `--network` and never touches the bridge; this matches it.
fn build_host_config(container_config: &ContainerConfig) -> HostConfig {
    HostConfig {
        memory: Some(container_config.memory as i64),
        nano_cpus: Some((container_config.cpus * 1_000_000_000.0) as i64),
        restart_policy: restart_policy_for(&container_config.restart_policy),
        network_mode: container_config.network.clone(),
        binds: Some(
            container_config
                .mounts
                .iter()
                .map(|m| {
                    if m.read_only {
                        format!("{}:{}:ro", m.source, m.target)
                    } else {
                        format!("{}:{}", m.source, m.target)
                    }
                })
                .collect(),
        ),
        // Security hardening: drop all capabilities first
        cap_drop: Some(vec!["ALL".to_string()]),
        // Add back only essential capabilities for runtime operation
        cap_add: Some(vec![
            "CHOWN".to_string(),  // Change file ownership
            "SETGID".to_string(), // Set group ID
            "SETUID".to_string(), // Set user ID
        ]),
        // Prevent privilege escalation
        security_opt: Some(vec!["no-new-privileges:true".to_string()]),
        // Limit PIDs to prevent fork bombs
        // 6144 is enough for complex builds (Next.js, webpack) while still providing protection
        // executor-main doesn't set a limit, but we add one for safety
        pids_limit: Some(6144),
        ..Default::default()
    }
}

/// Create body for a runtime container.
///
/// The container hostname is left unset so Docker seeds it with the container
/// ID, as executor-main does. Nothing in the executor reaches a runtime by its
/// hostname: every caller uses the container name over the runtimes network.
fn build_create_body(container_config: &ContainerConfig) -> ContainerCreateBody {
    ContainerCreateBody {
        image: Some(container_config.image.clone()),
        env: Some(container_config.env_vec()),
        entrypoint: container_config.entrypoint.clone(),
        cmd: container_config.cmd.clone(),
        host_config: Some(build_host_config(container_config)),
        labels: Some(container_config.labels.clone()),
        ..Default::default()
    }
}

/// Parse Docker environment format (`KEY=VALUE`) into a map.
fn parse_env_vars(env: Option<Vec<String>>) -> HashMap<String, String> {
    let mut vars = HashMap::new();

    if let Some(entries) = env {
        for entry in entries {
            if let Some((key, value)) = entry.split_once('=') {
                vars.insert(key.to_string(), value.to_string());
            }
        }
    }

    vars
}

/// Main Docker manager for container operations
#[derive(Clone)]
pub struct DockerManager {
    docker: Docker,
    config: ExecutorConfig,
    stats_cache: StatsCache,
    pull_semaphore: Arc<Semaphore>,
}

impl DockerManager {
    async fn create_container_inner(
        &self,
        options: CreateContainerOptions,
        config: ContainerCreateBody,
    ) -> std::result::Result<bollard::models::ContainerCreateResponse, bollard::errors::Error> {
        self.docker.create_container(Some(options), config).await
    }

    /// Stop and remove all containers managed by URT
    #[allow(dead_code)]
    pub async fn cleanup_managed_containers(&self) -> Vec<String> {
        use tracing::{info, warn};

        let containers = match self.list_containers(Some("urt.managed=true")).await {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to list managed containers during shutdown: {}", e);
                return Vec::new();
            }
        };

        let mut containers = containers;
        containers.sort_by_key(|c| c.created);
        let mut cleaned_names = Vec::with_capacity(containers.len());

        // Get executor container ID ONCE
        let self_id = self
            .docker
            .info()
            .await
            .ok()
            .and_then(|i| i.id)
            .unwrap_or_default();

        for container in containers {
            // Skip executor container by ID
            if container.id == self_id {
                info!("Skipping executor container {}", container.name);
                continue;
            }

            let name = container.name;

            info!("Cleaning up runtime {}", name);

            if let Err(e) = self.remove_container(&name, true).await {
                warn!("Failed to remove {}: {}", name, e);
            }

            cleaned_names.push(name);
        }

        cleaned_names
    }

    /// Create a new DockerManager
    pub async fn new(config: ExecutorConfig) -> Result<Self> {
        let docker = connect_to_docker()?;

        // Verify connection
        docker
            .ping()
            .await
            .map_err(|e| ExecutorError::Docker(format!("Failed to connect to Docker: {}", e)))?;

        info!("Connected to Docker daemon");

        Ok(Self {
            docker,
            config,
            stats_cache: StatsCache::new(),
            pull_semaphore: Arc::new(Semaphore::new(4)), // Max 4 concurrent pulls
        })
    }

    /// Ensure all configured networks exist
    pub async fn ensure_networks(&self) -> Result<()> {
        for network in &self.config.networks {
            ensure_network(&self.docker, network).await?;
        }
        Ok(())
    }

    /// Resolve a container name by hostname (best-effort)
    pub async fn resolve_container_name_by_hostname(&self, hostname: &str) -> Option<String> {
        let mut filters = HashMap::new();
        filters.insert("name".to_string(), vec![hostname.to_string()]);

        let options = ListContainersOptions {
            all: true,
            filters: Some(filters),
            ..Default::default()
        };

        let containers = self.docker.list_containers(Some(options)).await.ok()?;
        let name = containers
            .into_iter()
            .find_map(|c| c.names.and_then(|n| n.first().cloned()))
            .unwrap_or_default()
            .trim_start_matches('/')
            .to_string();

        if name.is_empty() {
            None
        } else {
            Some(name)
        }
    }

    /// Connect a container to all configured networks (best-effort)
    pub async fn connect_container_to_networks(&self, container: &str) {
        for network in &self.config.networks {
            match connect_container(&self.docker, network, container).await {
                Ok(_) => {}
                Err(ExecutorError::RuntimeNotFound) => {
                    debug!(
                        "Skipping network attach for missing container {} on {}",
                        container, network
                    );
                }
                Err(e) => {
                    crate::telemetry::metrics().inc_network_attach_failure(network, container);
                    warn!(
                        "Failed to connect container {} to network {}: {}",
                        container, network, e
                    );
                }
            }
        }
    }

    /// Pull a Docker image
    pub async fn pull_image(&self, image: &str) -> Result<()> {
        let _permit = self.pull_semaphore.acquire().await.unwrap();

        info!("Pulling image: {}", image);

        let options = CreateImageOptions {
            from_image: Some(image.to_string()),
            ..Default::default()
        };

        // Build credentials if Docker Hub auth is configured
        let credentials = match (
            &self.config.docker_hub_username,
            &self.config.docker_hub_password,
        ) {
            (Some(username), Some(password)) => {
                debug!("Using Docker Hub credentials for pull");
                Some(DockerCredentials {
                    username: Some(username.clone()),
                    password: Some(password.clone()),
                    ..Default::default()
                })
            }
            _ => None,
        };

        let mut stream = self.docker.create_image(Some(options), None, credentials);

        while let Some(result) = stream.next().await {
            match result {
                Ok(info) => {
                    if let Some(status) = info.status {
                        debug!("Pull {}: {}", image, status);
                    }
                }
                Err(e) => {
                    error!("Failed to pull {}: {}", image, e);
                    return Err(ExecutorError::Docker(e.to_string()));
                }
            }
        }

        info!("Successfully pulled: {}", image);
        Ok(())
    }

    /// Create and start a container
    pub async fn create_container(&self, container_config: ContainerConfig) -> Result<String> {
        debug!("Creating container: {}", container_config.name);

        let config = build_create_body(&container_config);

        let options = CreateContainerOptions {
            name: Some(container_config.name.clone()),
            platform: String::new(),
        };

        // Create container
        let response = match self
            .create_container_inner(options.clone(), config.clone())
            .await
        {
            Ok(response) => response,
            Err(error) => {
                let message = error.to_string();

                if self.config.image_pull_enabled && is_missing_image_error(&message) {
                    info!(
                        "Image {} missing locally, pulling before retry",
                        container_config.image
                    );
                    self.pull_image(&container_config.image).await?;
                    self.create_container_inner(options.clone(), config.clone())
                        .await
                        .map_err(|e| map_create_container_error(e.to_string()))?
                } else {
                    return Err(map_create_container_error(message));
                }
            }
        };

        debug!(
            "Created container {} with id {}",
            container_config.name, response.id
        );

        // The primary network was applied as the container's network mode at
        // create, so there is nothing to attach here. Secondary networks are
        // connected by the caller once the container is running.

        // Start container
        self.docker
            .start_container(&container_config.name, None::<StartContainerOptions>)
            .await
            .map_err(|e| ExecutorError::Docker(e.to_string()))?;

        info!("Started container: {}", container_config.name);

        Ok(response.id)
    }

    /// Stop a container
    pub async fn stop_container(&self, name: &str, timeout_secs: i64) -> Result<()> {
        debug!("Stopping container: {}", name);

        let options = StopContainerOptions {
            t: Some(timeout_secs as i32),
            ..Default::default()
        };

        match self.docker.stop_container(name, Some(options)).await {
            Ok(_) => {
                info!("Stopped container: {}", name);
                Ok(())
            }
            Err(e) => {
                let message = e.to_string();
                if message.contains("not running") {
                    debug!("Container {} already stopped", name);
                    return Ok(());
                }
                if message.contains("No such container") {
                    debug!("Container {} not found while stopping", name);
                    return Err(ExecutorError::RuntimeNotFound);
                }
                Err(ExecutorError::Docker(message))
            }
        }
    }

    /// Remove a container
    pub async fn remove_container(&self, name: &str, force: bool) -> Result<()> {
        debug!("Removing container: {} (force={})", name, force);

        let options = RemoveContainerOptions {
            force,
            v: true, // Remove volumes
            ..Default::default()
        };

        self.docker
            .remove_container(name, Some(options))
            .await
            .map_err(|e| {
                // Ignore "not found" errors
                if e.to_string().contains("No such container") {
                    debug!("Container {} not found", name);
                    return ExecutorError::RuntimeNotFound;
                }
                ExecutorError::Docker(e.to_string())
            })?;

        // Remove from stats cache (lock-free operation)
        self.stats_cache.remove_container(name);

        info!("Removed container: {}", name);
        Ok(())
    }

    /// Get container info
    pub async fn inspect_container(&self, name: &str) -> Result<ContainerInfo> {
        let info = self
            .docker
            .inspect_container(name, None::<InspectContainerOptions>)
            .await
            .map_err(|e| {
                if e.to_string().contains("No such container") {
                    return ExecutorError::RuntimeNotFound;
                }
                ExecutorError::Docker(e.to_string())
            })?;

        let config = info.config.unwrap_or_default();
        let state = info.state.unwrap_or_default();

        Ok(ContainerInfo {
            id: info.id.unwrap_or_default(),
            name: info
                .name
                .unwrap_or_default()
                .trim_start_matches('/')
                .to_string(),
            image: config.image.unwrap_or_default(),
            state: state.status.map(|s| s.to_string()).unwrap_or_default(),
            status: state.status.map(|s| s.to_string()).unwrap_or_default(),
            created: info
                .created
                .and_then(|c| chrono::DateTime::parse_from_rfc3339(&c).ok())
                .map(|dt| dt.timestamp())
                .unwrap_or(0),
            labels: config.labels.unwrap_or_default(),
            env: parse_env_vars(config.env),
            hostname: config.hostname.unwrap_or_default(),
        })
    }

    /// List containers with a specific label
    pub async fn list_containers(&self, label_filter: Option<&str>) -> Result<Vec<ContainerInfo>> {
        let mut filters = HashMap::new();
        if let Some(label) = label_filter {
            filters.insert("label".to_string(), vec![label.to_string()]);
        }

        let options = ListContainersOptions {
            all: true,
            filters: Some(filters),
            ..Default::default()
        };

        let containers = self
            .docker
            .list_containers(Some(options))
            .await
            .map_err(|e| ExecutorError::Docker(e.to_string()))?;

        Ok(containers
            .into_iter()
            .map(|c| ContainerInfo {
                id: c.id.unwrap_or_default(),
                name: c
                    .names
                    .and_then(|n| n.first().cloned())
                    .unwrap_or_default()
                    .trim_start_matches('/')
                    .to_string(),
                image: c.image.unwrap_or_default(),
                state: c.state.map(|s| s.to_string()).unwrap_or_default(),
                status: c.status.unwrap_or_default(),
                created: c.created.unwrap_or(0),
                labels: c.labels.unwrap_or_default(),
                env: HashMap::new(),
                hostname: String::new(),
            })
            .collect())
    }

    /// Execute a shell command in a container (using sh -c)
    /// Used for v2 runtimes
    pub async fn exec_shell(
        &self,
        container: &str,
        command: &str,
        timeout_secs: u64,
    ) -> Result<ExecResult> {
        exec_shell(&self.docker, container, command, timeout_secs).await
    }

    /// Execute a bash command in a container (using bash -c)
    /// Used for v5 runtimes - matches executor-main behavior
    pub async fn exec_bash(
        &self,
        container: &str,
        command: &str,
        timeout_secs: u64,
    ) -> Result<ExecResult> {
        exec_bash(&self.docker, container, command, timeout_secs).await
    }

    /// Get container stats
    pub async fn get_container_stats(&self, container: &str) -> Result<ContainerStats> {
        get_container_stats(&self.docker, container).await
    }

    /// Get host stats
    pub async fn get_host_stats(&self) -> Result<HostStats> {
        get_host_stats(&self.docker).await
    }

    /// Get stats cache
    pub fn stats_cache(&self) -> &StatsCache {
        &self.stats_cache
    }

    /// Build a Docker image from source code
    ///
    /// # Arguments
    /// * `source_dir` - Directory containing the source code and Dockerfile
    /// * `request` - Build request configuration
    /// * `cache` - Optional build cache for layer caching
    pub async fn build_image<S: Storage>(
        &self,
        source_dir: &Path,
        request: &BuildRequest,
        cache: Option<&BuildCache<S>>,
    ) -> Result<BuildResult> {
        build_image(&self.docker, source_dir, request, cache).await
    }
}

fn connect_to_docker() -> Result<Docker> {
    let mut attempts: Vec<(
        &'static str,
        std::result::Result<Docker, bollard::errors::Error>,
    )> = vec![("socket_defaults", Docker::connect_with_socket_defaults())];

    #[cfg(unix)]
    {
        if let Some(home) = std::env::var_os("HOME") {
            let user_socket = Path::new(&home).join(".docker/run/docker.sock");
            if user_socket.exists() {
                if let Some(socket_path) = user_socket.to_str() {
                    attempts.push((
                        "user_socket",
                        Docker::connect_with_unix(socket_path, 120, API_DEFAULT_VERSION),
                    ));
                }
            }
        }
    }

    let mut errors = Vec::new();
    for (label, attempt) in attempts {
        match attempt {
            Ok(docker) => return Ok(docker),
            Err(error) => errors.push(format!("{}: {}", label, error)),
        }
    }

    Err(ExecutorError::Docker(errors.join("; ")))
}

impl std::fmt::Debug for DockerManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DockerManager")
            .field("config", &self.config)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_create_body, build_host_config, is_missing_image_error, map_create_container_error,
    };
    use crate::docker::container::ContainerConfig;
    use crate::error::ExecutorError;

    #[test]
    fn test_host_config_creates_the_container_on_the_configured_network() {
        let config = ContainerConfig::new("exc1-fn-1", "openruntimes/node:v5-25")
            .with_network("openruntimes-runtimes");

        let host_config = build_host_config(&config);

        assert_eq!(
            host_config.network_mode.as_deref(),
            Some("openruntimes-runtimes")
        );
    }

    #[test]
    fn test_host_config_without_a_network_leaves_the_mode_unset() {
        let config = ContainerConfig::new("exc1-fn-1", "openruntimes/node:v5-25");

        assert!(build_host_config(&config).network_mode.is_none());
    }

    #[test]
    fn test_create_body_leaves_the_hostname_to_docker() {
        let config =
            ContainerConfig::new("exc1-fn-1", "openruntimes/node:v5-25").with_network("runtimes");

        assert!(build_create_body(&config).hostname.is_none());
    }

    #[test]
    fn test_create_body_keeps_security_hardening_and_resource_limits() {
        let config = ContainerConfig::new("exc1-fn-1", "openruntimes/node:v5-25")
            .with_network("runtimes")
            .with_cpus(2.0)
            .with_memory_mb(1024)
            .with_mount("/tmp/src", "/tmp", false)
            .with_mount("/tmp/builds", "/mnt/code", true);

        let host_config = build_create_body(&config).host_config.unwrap();

        assert_eq!(host_config.memory, Some(1024 * 1024 * 1024));
        assert_eq!(host_config.nano_cpus, Some(2_000_000_000));
        assert_eq!(host_config.cap_drop, Some(vec!["ALL".to_string()]));
        assert_eq!(
            host_config.security_opt,
            Some(vec!["no-new-privileges:true".to_string()])
        );
        assert_eq!(host_config.pids_limit, Some(6144));
        assert_eq!(
            host_config.binds,
            Some(vec![
                "/tmp/src:/tmp".to_string(),
                "/tmp/builds:/mnt/code:ro".to_string(),
            ])
        );
    }

    #[test]
    fn test_is_missing_image_error_detects_docker_not_found() {
        assert!(is_missing_image_error(
            "Docker responded with status code 404: No such image: openruntimes/node:v5-25"
        ));
        assert!(is_missing_image_error(
            "pull access denied for openruntimes/node, repository does not exist or may require authorization"
        ));
        assert!(!is_missing_image_error(
            "Docker responded with status code 409: Conflict. The container name is already in use."
        ));
    }

    #[test]
    fn test_map_create_container_error_maps_conflict() {
        let err = map_create_container_error(
            "Docker responded with status code 409: Conflict. The container name is already in use."
                .to_string(),
        );
        assert!(matches!(err, ExecutorError::RuntimeConflict));
    }
}
