//! Docker manager - main interface for container operations

#![allow(deprecated)]

use super::build::{build_image, BuildRequest, BuildResult};
use super::container::{ContainerConfig, ContainerInfo, RestartPolicySpec};
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
use dashmap::DashMap;
use futures_util::StreamExt;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
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

/// Translate a `restartPolicy` request value into the Docker host config form.
fn docker_restart_policy(value: &str) -> RestartPolicy {
    match RestartPolicySpec::parse(value) {
        RestartPolicySpec::Always => RestartPolicy {
            name: Some(RestartPolicyNameEnum::ALWAYS),
            maximum_retry_count: None,
        },
        RestartPolicySpec::UnlessStopped => RestartPolicy {
            name: Some(RestartPolicyNameEnum::UNLESS_STOPPED),
            maximum_retry_count: None,
        },
        RestartPolicySpec::OnFailure(max_retries) => RestartPolicy {
            name: Some(RestartPolicyNameEnum::ON_FAILURE),
            maximum_retry_count: max_retries.map(i64::from),
        },
        RestartPolicySpec::No => RestartPolicy {
            name: Some(RestartPolicyNameEnum::NO),
            maximum_retry_count: None,
        },
    }
}

/// How long a deliberate stop or removal is remembered so the Docker events
/// task can tell it from a crash.
const DELIBERATE_REMOVAL_TTL: Duration = Duration::from_secs(60);

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
    /// Containers this executor has stopped or removed on purpose, with the
    /// time the operation was issued. Consulted by the Docker events task so a
    /// `die` caused by our own `stop` or `rm` is not counted as a crash.
    deliberate_removals: Arc<DashMap<String, Instant>>,
}

impl DockerManager {
    /// Remember that `name` is being stopped or removed by this executor.
    fn note_deliberate_removal(&self, name: &str) {
        let now = Instant::now();
        self.deliberate_removals
            .retain(|_, issued| now.duration_since(*issued) < DELIBERATE_REMOVAL_TTL);
        self.deliberate_removals.insert(name.to_string(), now);
    }

    /// Whether a stop or removal of `name` was issued by this executor within
    /// the last minute.
    pub fn was_removed_deliberately(&self, name: &str) -> bool {
        self.deliberate_removals
            .get(name)
            .map(|issued| issued.elapsed() < DELIBERATE_REMOVAL_TTL)
            .unwrap_or(false)
    }

    /// Raw bollard client, for callers that stream from the daemon directly.
    pub fn client(&self) -> &Docker {
        &self.docker
    }

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
            deliberate_removals: Arc::new(DashMap::new()),
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

        let restart_policy = Some(docker_restart_policy(&container_config.restart_policy));

        // Build host config with security hardening
        let host_config = HostConfig {
            memory: Some(container_config.memory as i64),
            nano_cpus: Some((container_config.cpus * 1_000_000_000.0) as i64),
            restart_policy,
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
        };

        // Build container config
        let config = ContainerCreateBody {
            image: Some(container_config.image.clone()),
            hostname: if container_config.hostname.is_empty() {
                None
            } else {
                Some(container_config.hostname.clone())
            },
            env: Some(container_config.env_vec()),
            entrypoint: container_config.entrypoint.clone(),
            cmd: container_config.cmd.clone(),
            host_config: Some(host_config),
            labels: Some(container_config.labels.clone()),
            ..Default::default()
        };

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

        // Connect to network if specified
        if let Some(ref network) = container_config.network {
            connect_container(&self.docker, network, &container_config.name).await?;
        }

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
        self.note_deliberate_removal(name);

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
        self.note_deliberate_removal(name);

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
        let restart_policy = info
            .host_config
            .and_then(|host| host.restart_policy)
            .unwrap_or_default();

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
            exit_code: state.exit_code,
            oom_killed: state.oom_killed.unwrap_or(false),
            restart_policy: restart_policy
                .name
                .map(|name| name.to_string())
                .unwrap_or_default(),
            restart_max_retries: restart_policy.maximum_retry_count.unwrap_or(0),
            restart_count: info.restart_count.unwrap_or(0),
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
                exit_code: None,
                oom_killed: false,
                restart_policy: String::new(),
                restart_max_retries: 0,
                restart_count: 0,
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

type ConnectAttempt = (
    &'static str,
    std::result::Result<Docker, bollard::errors::Error>,
);

/// Docker Desktop and rootless installs expose a per-user socket.
#[cfg(unix)]
fn user_socket_attempt() -> Option<ConnectAttempt> {
    let home = std::env::var_os("HOME")?;
    let user_socket = Path::new(&home).join(".docker/run/docker.sock");
    if !user_socket.exists() {
        return None;
    }
    let socket_path = user_socket.to_str()?;
    Some((
        "user_socket",
        Docker::connect_with_unix(socket_path, 120, bollard::API_DEFAULT_VERSION),
    ))
}

#[cfg(not(unix))]
fn user_socket_attempt() -> Option<ConnectAttempt> {
    None
}

fn connect_to_docker() -> Result<Docker> {
    let mut attempts: Vec<ConnectAttempt> =
        vec![("socket_defaults", Docker::connect_with_socket_defaults())];
    attempts.extend(user_socket_attempt());

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
    use super::{docker_restart_policy, is_missing_image_error, map_create_container_error};
    use crate::docker::container::RestartPolicySpec;
    use crate::error::ExecutorError;
    use bollard::models::RestartPolicyNameEnum;

    #[test]
    fn test_restart_policy_spec_parses_docker_spellings() {
        assert_eq!(RestartPolicySpec::parse("no"), RestartPolicySpec::No);
        assert_eq!(RestartPolicySpec::parse(""), RestartPolicySpec::No);
        assert_eq!(
            RestartPolicySpec::parse("always"),
            RestartPolicySpec::Always
        );
        assert_eq!(
            RestartPolicySpec::parse("unless-stopped"),
            RestartPolicySpec::UnlessStopped
        );
        assert_eq!(
            RestartPolicySpec::parse("on-failure"),
            RestartPolicySpec::OnFailure(None)
        );
        assert_eq!(
            RestartPolicySpec::parse("on-failure:3"),
            RestartPolicySpec::OnFailure(Some(3))
        );
        assert_eq!(
            RestartPolicySpec::parse(" On-Failure:5 "),
            RestartPolicySpec::OnFailure(Some(5))
        );
        assert_eq!(
            RestartPolicySpec::parse("on-failure:0"),
            RestartPolicySpec::OnFailure(None)
        );
        assert_eq!(
            RestartPolicySpec::parse("on-failure:x"),
            RestartPolicySpec::No
        );
        assert_eq!(RestartPolicySpec::parse("sometimes"), RestartPolicySpec::No);
    }

    #[test]
    fn test_docker_restart_policy_carries_retry_cap() {
        let policy = docker_restart_policy("on-failure:3");
        assert_eq!(policy.name, Some(RestartPolicyNameEnum::ON_FAILURE));
        assert_eq!(policy.maximum_retry_count, Some(3));

        let unlimited = docker_restart_policy("on-failure");
        assert_eq!(unlimited.name, Some(RestartPolicyNameEnum::ON_FAILURE));
        assert_eq!(unlimited.maximum_retry_count, None);

        let none = docker_restart_policy("no");
        assert_eq!(none.name, Some(RestartPolicyNameEnum::NO));
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
