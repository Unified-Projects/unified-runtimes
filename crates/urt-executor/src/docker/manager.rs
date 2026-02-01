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
use bollard::container::{
    Config, CreateContainerOptions, ListContainersOptions, LogOutput, LogsOptions,
    RemoveContainerOptions, StartContainerOptions, StopContainerOptions,
};
use bollard::image::CreateImageOptions;
use bollard::models::{HostConfig, RestartPolicy, RestartPolicyNameEnum};
use bollard::Docker;
use futures_util::StreamExt;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::warn;
use tracing::{debug, error, info};

/// Main Docker manager for container operations
#[derive(Clone)]
pub struct DockerManager {
    docker: Docker,
    config: ExecutorConfig,
    stats_cache: StatsCache,
    pull_semaphore: Arc<Semaphore>,
}

impl DockerManager {
    /// Stop and remove all containers managed by URT
    #[allow(dead_code)]
    pub async fn cleanup_managed_containers(&self) {
        use tracing::{info, warn};

        let containers = match self.list_containers(Some("urt.managed=true")).await {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to list managed containers during shutdown: {}", e);
                return;
            }
        };

        let mut containers = containers;
        containers.sort_by_key(|c| c.created);

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

            let name = &container.name;

            info!("Cleaning up runtime {}", name);

            if let Err(e) = self.remove_container(name, true).await {
                warn!("Failed to remove {}: {}", name, e);
            }
        }
    }

    /// Create a new DockerManager
    pub async fn new(config: ExecutorConfig) -> Result<Self> {
        let docker = Docker::connect_with_socket_defaults()
            .map_err(|e| ExecutorError::Docker(e.to_string()))?;

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
            filters,
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
            if let Err(e) = connect_container(&self.docker, network, container).await {
                warn!(
                    "Failed to connect container {} to network {}: {}",
                    container, network, e
                );
            }
        }
    }

    /// Pull a Docker image
    pub async fn pull_image(&self, image: &str) -> Result<()> {
        let _permit = self.pull_semaphore.acquire().await.unwrap();

        info!("Pulling image: {}", image);

        let options = CreateImageOptions {
            from_image: image,
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

        // Convert restart policy
        let restart_policy = match container_config.restart_policy.as_str() {
            "always" => Some(RestartPolicy {
                name: Some(RestartPolicyNameEnum::ALWAYS),
                maximum_retry_count: None,
            }),
            "on-failure" => Some(RestartPolicy {
                name: Some(RestartPolicyNameEnum::ON_FAILURE),
                maximum_retry_count: Some(3),
            }),
            "unless-stopped" => Some(RestartPolicy {
                name: Some(RestartPolicyNameEnum::UNLESS_STOPPED),
                maximum_retry_count: None,
            }),
            _ => Some(RestartPolicy {
                name: Some(RestartPolicyNameEnum::NO),
                maximum_retry_count: None,
            }),
        };

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
        let config = Config {
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
            name: &container_config.name,
            platform: None,
        };

        // Create container
        let response = self
            .docker
            .create_container(Some(options), config)
            .await
            .map_err(|e| ExecutorError::Docker(e.to_string()))?;

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
            .start_container(
                &container_config.name,
                None::<StartContainerOptions<String>>,
            )
            .await
            .map_err(|e| ExecutorError::Docker(e.to_string()))?;

        info!("Started container: {}", container_config.name);

        Ok(response.id)
    }

    /// Stop a container
    pub async fn stop_container(&self, name: &str, timeout_secs: i64) -> Result<()> {
        debug!("Stopping container: {}", name);

        let options = StopContainerOptions { t: timeout_secs };

        self.docker
            .stop_container(name, Some(options))
            .await
            .map_err(|e| {
                // Ignore "not running" errors
                if e.to_string().contains("not running") {
                    debug!("Container {} already stopped", name);
                    return ExecutorError::Docker("already stopped".to_string());
                }
                ExecutorError::Docker(e.to_string())
            })?;

        info!("Stopped container: {}", name);
        Ok(())
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
            .inspect_container(name, None::<bollard::container::InspectContainerOptions>)
            .await
            .map_err(|e| {
                if e.to_string().contains("No such container") {
                    return ExecutorError::RuntimeNotFound;
                }
                ExecutorError::Docker(e.to_string())
            })?;

        Ok(ContainerInfo {
            id: info.id.unwrap_or_default(),
            name: info
                .name
                .unwrap_or_default()
                .trim_start_matches('/')
                .to_string(),
            image: info.config.and_then(|c| c.image).unwrap_or_default(),
            status: info
                .state
                .and_then(|s| s.status)
                .map(|s| s.to_string())
                .unwrap_or_default(),
            created: info
                .created
                .and_then(|c| chrono::DateTime::parse_from_rfc3339(&c).ok())
                .map(|dt| dt.timestamp())
                .unwrap_or(0),
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
            filters,
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
                status: c.status.unwrap_or_default(),
                created: c.created.unwrap_or(0),
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

    /// Stream container logs
    pub async fn stream_logs(
        &self,
        container: &str,
        follow: bool,
        tail: Option<&str>,
    ) -> impl futures_util::Stream<Item = Result<String>> + '_ {
        let options = LogsOptions::<String> {
            follow,
            stdout: true,
            stderr: true,
            tail: tail.unwrap_or("all").to_string(),
            timestamps: true,
            ..Default::default()
        };

        self.docker.logs(container, Some(options)).map(|result| {
            result
                .map(|output| match output {
                    LogOutput::StdOut { message } => String::from_utf8_lossy(&message).to_string(),
                    LogOutput::StdErr { message } => String::from_utf8_lossy(&message).to_string(),
                    _ => String::new(),
                })
                .map_err(|e| ExecutorError::Docker(e.to_string()))
        })
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

impl std::fmt::Debug for DockerManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DockerManager")
            .field("config", &self.config)
            .finish()
    }
}
