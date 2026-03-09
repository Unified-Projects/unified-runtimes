//! Maintenance task for cleaning up inactive runtimes

use crate::config::ExecutorConfig;
use crate::docker::container::ContainerInfo;
use crate::docker::DockerManager;
use crate::error::ExecutorError;
use crate::runtime::{wait_for_runtime_port, KeepAliveRegistry, Runtime, RuntimeRegistry};
use crate::storage::{BuildCache, Storage};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{debug, info, warn};

/// Maximum build cache size in bytes (1GB)
const MAX_BUILD_CACHE_BYTES: u64 = 1024 * 1024 * 1024;

fn infer_runtime_version(image: &str, labels: &HashMap<String, String>) -> String {
    if let Some(version) = labels.get("urt.version").filter(|v| !v.is_empty()) {
        return version.clone();
    }

    for version in ["v5", "v4", "v3", "v2"] {
        if image.contains(&format!(":{version}")) || image.contains(&format!(":{version}-")) {
            return version.to_string();
        }
    }

    "v5".to_string()
}

fn is_managed_container(container: &ContainerInfo) -> bool {
    container
        .labels
        .get("urt.managed")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn is_container_running(container: &ContainerInfo) -> bool {
    let state = container.state.to_ascii_lowercase();
    if !state.is_empty() {
        return state == "running";
    }

    let status = container.status.to_ascii_lowercase();
    status == "running" || status == "up" || status.starts_with("up ")
}

fn belongs_to_hostname(container: &ContainerInfo, hostname: &str) -> bool {
    if let Some(executor_hostname) = container
        .labels
        .get("urt.executor_hostname")
        .filter(|value| !value.is_empty())
    {
        return executor_hostname == hostname;
    }

    container
        .name
        .strip_prefix(&format!("{}-", hostname))
        .is_some()
}

fn runtime_id_from_container(container: &ContainerInfo, hostname: &str) -> Option<String> {
    if !belongs_to_hostname(container, hostname) {
        return None;
    }

    if let Some(runtime_id) = container
        .labels
        .get("urt.runtime_id")
        .filter(|id| !id.is_empty())
    {
        return Some(runtime_id.clone());
    }

    container
        .name
        .strip_prefix(&format!("{}-", hostname))
        .map(|id| id.to_string())
}

fn keep_alive_id_from_container(container: &ContainerInfo) -> Option<String> {
    container
        .labels
        .get("urt.keep_alive_id")
        .cloned()
        .filter(|v| !v.is_empty())
        .or_else(|| {
            container
                .env
                .get("URT_KEEP_ALIVE")
                .cloned()
                .filter(|v| !v.is_empty())
        })
}

fn keep_alive_generation_from_container(container: &ContainerInfo) -> Option<u64> {
    container
        .labels
        .get("urt.keep_alive_generation")
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
}

fn runtime_from_container(container: &ContainerInfo, hostname: &str) -> Option<Runtime> {
    let runtime_id = runtime_id_from_container(container, hostname)?;
    let version = infer_runtime_version(&container.image, &container.labels);
    let keep_alive_id = keep_alive_id_from_container(container);

    let mut runtime = Runtime::new(
        &runtime_id,
        hostname,
        &container.image,
        &version,
        keep_alive_id,
    );

    // Preserve actual container identity and metadata.
    runtime.name = container.name.clone();
    runtime.image = container.image.clone();
    runtime.version = version;
    runtime.status = if container.state.is_empty() {
        container.status.clone()
    } else {
        container.state.clone()
    };
    runtime.initialised = if is_container_running(container) {
        1
    } else {
        0
    };

    if container.created > 0 {
        runtime.created = container.created as f64;
    }

    if let Some(secret) = container
        .env
        .get("OPEN_RUNTIMES_SECRET")
        .or_else(|| container.env.get("INTERNAL_RUNTIME_KEY"))
    {
        runtime.key = secret.clone();
    }

    if !container.hostname.is_empty() {
        runtime.hostname = container.hostname.clone();
    }

    runtime.refresh_cached_auth();

    Some(runtime)
}

async fn adopt_inspected_container(
    registry: &RuntimeRegistry,
    keep_alive_registry: &KeepAliveRegistry,
    hostname: &str,
    inspected: ContainerInfo,
) -> bool {
    let name = inspected.name.clone();

    if registry.exists(&name).await {
        return false;
    }

    if !is_managed_container(&inspected) {
        debug!(
            "Skipping unmanaged container {} during adoption attempt",
            inspected.name
        );
        return false;
    }

    if !is_container_running(&inspected) {
        debug!(
            "Skipping non-running container {} during adoption (state: {}, status: {})",
            inspected.name, inspected.state, inspected.status
        );
        return false;
    }

    let runtime = match runtime_from_container(&inspected, hostname) {
        Some(rt) => rt,
        None => {
            warn!(
                "Could not derive runtime metadata from managed container {}",
                inspected.name
            );
            return false;
        }
    };

    let mut runtime = runtime;
    if wait_for_runtime_port(&runtime.name, 3000, Duration::from_millis(200))
        .await
        .is_ok()
    {
        runtime.listening = 1;
    }

    if let Err(e) = registry.insert(runtime.clone()).await {
        if matches!(e, ExecutorError::RuntimeConflict) {
            return false;
        }
        warn!("Failed to adopt container {}: {}", inspected.name, e);
        return false;
    }

    if let Some(ref ka_id) = runtime.keep_alive_id {
        if let Some(generation) = keep_alive_generation_from_container(&inspected) {
            keep_alive_registry.observe_generation(ka_id, generation);
        }
        if let Some(prev_owner) = keep_alive_registry.restore_owner(ka_id, &runtime.name) {
            if prev_owner != runtime.name {
                debug!(
                    "Keep-alive ID '{}' ownership restored from {} to {}",
                    ka_id, prev_owner, runtime.name
                );
            }
        }
    }

    info!(
        "Adopted container: {} (state: {}, status: {})",
        inspected.name, runtime.status, inspected.status
    );
    true
}

async fn remove_container_for_cleanup(docker: &DockerManager, name: &str, context: &str) -> bool {
    match docker.remove_container(name, true).await {
        Ok(_) => true,
        Err(ExecutorError::RuntimeNotFound) => true,
        Err(e) => {
            warn!("Failed to remove {} container {}: {}", context, name, e);
            false
        }
    }
}

/// Adopt a specific container by name if it is managed and running.
/// Returns true when the runtime is already present or successfully adopted.
pub async fn adopt_container_by_name(
    docker: &DockerManager,
    registry: &RuntimeRegistry,
    keep_alive_registry: &KeepAliveRegistry,
    hostname: &str,
    container_name: &str,
) -> bool {
    if registry.exists(container_name).await {
        return true;
    }

    let inspected = match docker.inspect_container(container_name).await {
        Ok(info) => info,
        Err(_) => return false,
    };

    adopt_inspected_container(registry, keep_alive_registry, hostname, inspected).await
}

/// Adopt existing managed containers on startup
///
/// Queries Docker for containers with `urt.managed=true` label that are not
/// already in the registry and registers them. This handles the case where
/// the executor restarts while containers are still running.
pub async fn adopt_existing_containers(
    docker: &DockerManager,
    registry: &RuntimeRegistry,
    keep_alive_registry: &KeepAliveRegistry,
    hostname: &str,
) {
    let label = "urt.managed=true";

    let mut containers = match docker.list_containers(Some(label)).await {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to list managed containers for adoption: {}", e);
            return;
        }
    };

    if containers.is_empty() {
        debug!("No existing containers to adopt");
        return;
    }

    // Oldest first so keep-alive ownership naturally settles on the newest runtime.
    containers.sort_by_key(|c| c.created);

    let mut adopted_count = 0usize;

    for container in containers {
        let name = container.name.clone();

        if !belongs_to_hostname(&container, hostname) {
            debug!(
                "Skipping managed container {} during adoption for hostname {}",
                name, hostname
            );
            continue;
        }

        // Skip if already in registry
        if registry.exists(&name).await {
            debug!("Container {} already in registry, skipping", name);
            continue;
        }

        // Only adopt live containers.
        if !is_container_running(&container) {
            debug!(
                "Skipping non-running container {} (state: {}, status: {})",
                name, container.state, container.status
            );
            continue;
        }

        // Use inspect to recover runtime secrets/hostname/env used by active runtimes.
        let inspected = match docker.inspect_container(&name).await {
            Ok(info) => info,
            Err(e) => {
                warn!(
                    "Failed to inspect container {} during adoption: {}",
                    name, e
                );
                continue;
            }
        };

        if !is_container_running(&inspected) {
            debug!(
                "Skipping container {} after inspect (state: {}, status: {})",
                name, inspected.state, inspected.status
            );
            continue;
        }

        if adopt_inspected_container(registry, keep_alive_registry, hostname, inspected).await {
            adopted_count += 1;
        }
    }

    if adopted_count > 0 {
        info!("Adopted {} managed containers", adopted_count);
    }
}

/// Run the maintenance worker
///
/// Idle runtimes are always eligible for cleanup, but runtimes that currently
/// own a keep-alive ID stay protected.
pub async fn run_maintenance<S: Storage + 'static>(
    docker: Arc<DockerManager>,
    registry: RuntimeRegistry,
    keep_alive_registry: KeepAliveRegistry,
    config: ExecutorConfig,
    storage: S,
    mut shutdown: watch::Receiver<bool>,
) {
    let interval = Duration::from_secs(config.maintenance_interval);
    let build_cache = BuildCache::new(storage, "builds");

    info!(
        "Starting maintenance worker (interval: {}s, keep_alive: {})",
        config.maintenance_interval, config.keep_alive
    );

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    info!("Shutdown signal received, stopping maintenance worker");
                    break;
                }
            }
            _ = tokio::time::sleep(interval) => {
                // Always check for orphaned keepalive containers (runs regardless of keep_alive setting)
                // This catches cases where a container was replaced but previous owner wasn't cleaned up
                cleanup_orphaned_keepalive(&docker, &registry, &keep_alive_registry, &config.hostname).await;

                cleanup_idle(&docker, &registry, &keep_alive_registry, config.inactive_threshold).await;
                cleanup_untracked_managed_containers(&docker, &registry, &config.hostname).await;

                if config.keep_alive {
                    let count = registry.count().await;
                    debug!(
                        "Maintenance check: {} active runtimes (keep_alive=true, protected runtimes preserved)",
                        count
                    );
                }

                // Always clean up temporary build directories
                cleanup_temp_dirs(&config.hostname, &registry).await;

                // Clean up build cache if it exceeds size limit
                cleanup_build_cache(&build_cache).await;
            }
        }
    }

    info!("Maintenance worker stopped");
}

/// Clean up build cache if it exceeds the size limit
async fn cleanup_build_cache<S: Storage>(cache: &BuildCache<S>) {
    match cache.total_size().await {
        Ok(size) => {
            debug!("Build cache size: {} bytes", size);
            if size > MAX_BUILD_CACHE_BYTES {
                match cache.cleanup(MAX_BUILD_CACHE_BYTES).await {
                    Ok(deleted) => {
                        if deleted > 0 {
                            info!("Cleaned up {} build cache entries", deleted);
                        }
                    }
                    Err(e) => {
                        warn!("Failed to clean up build cache: {}", e);
                    }
                }
            }
        }
        Err(e) => {
            debug!("Failed to get build cache size: {}", e);
        }
    }
}

/// Clean up runtimes that have been idle longer than threshold
/// Runtimes with a keep_alive_id that they currently own are protected from cleanup.
async fn cleanup_idle(
    docker: &DockerManager,
    registry: &RuntimeRegistry,
    keep_alive_registry: &KeepAliveRegistry,
    threshold: u64,
) {
    let idle_runtimes = registry.get_idle(threshold).await;

    if idle_runtimes.is_empty() {
        debug!("No idle runtimes to clean up");
        return;
    }

    // Filter out runtimes that are protected by keep-alive ownership
    let runtimes_to_cleanup: Vec<_> = idle_runtimes
        .into_iter()
        .filter(|runtime| {
            // If runtime has a keep_alive_id AND owns it, skip cleanup
            if let Some(ref ka_id) = runtime.keep_alive_id {
                if keep_alive_registry.is_owner(ka_id, &runtime.name) {
                    debug!(
                        "Skipping cleanup of {} - protected by keep-alive ID '{}'",
                        runtime.name, ka_id
                    );
                    return false;
                }
            }
            true
        })
        .collect();

    if runtimes_to_cleanup.is_empty() {
        debug!("No idle runtimes to clean up (all protected or none idle)");
        return;
    }

    info!("Cleaning up {} idle runtimes", runtimes_to_cleanup.len());

    for runtime in runtimes_to_cleanup {
        let _keep_alive_lock = match runtime.keep_alive_id.as_ref() {
            Some(ka_id) => Some(keep_alive_registry.lock(ka_id).await),
            None => None,
        };

        let name = &runtime.name;
        if let Some(ref ka_id) = runtime.keep_alive_id {
            if keep_alive_registry.is_owner(ka_id, name) {
                debug!(
                    "Skipping cleanup of {} - keep-alive ID '{}' transferred during cleanup cycle",
                    name, ka_id
                );
                continue;
            }
        }

        let removed = remove_container_for_cleanup(docker, name, "idle").await;
        if !removed {
            debug!(
                "Keeping idle runtime {} in registry for retry after failed Docker removal",
                name
            );
            continue;
        }

        // Unregister keep-alive ownership if this runtime had one
        // (even if not owner, calling unregister is safe - it only removes if owner)
        if let Some(ref ka_id) = runtime.keep_alive_id {
            keep_alive_registry.unregister(ka_id, name);
        }

        // Remove from registry AFTER Docker is done
        registry.remove(name).await;
    }
}

async fn cleanup_untracked_managed_containers(
    docker: &DockerManager,
    registry: &RuntimeRegistry,
    hostname: &str,
) {
    let containers = match docker.list_containers(Some("urt.managed=true")).await {
        Ok(containers) => containers,
        Err(error) => {
            warn!(
                "Failed to list containers for untracked managed cleanup: {}",
                error
            );
            return;
        }
    };

    for container in containers {
        if !belongs_to_hostname(&container, hostname) {
            continue;
        }

        if registry.exists(&container.name).await {
            continue;
        }

        if let Some(keep_alive_id) = keep_alive_id_from_container(&container) {
            debug!(
                "Skipping untracked managed container {} because it carries keep-alive ID '{}'",
                container.name, keep_alive_id
            );
            continue;
        }

        info!(
            "Cleaning up untracked managed container {} (state: {}, status: {})",
            container.name, container.state, container.status
        );

        let removed =
            remove_container_for_cleanup(docker, &container.name, "untracked managed").await;

        if removed {
            registry.remove(&container.name).await;
        }
    }
}

/// Clean up orphaned keepalive containers
///
/// This function handles cases where a container with a keep_alive_id was
/// replaced by a new runtime but the previous owner wasn't cleaned up.
/// It queries Docker directly for managed containers and compares against
/// the keep_alive registry to find orphaned containers.
async fn cleanup_orphaned_keepalive(
    docker: &DockerManager,
    registry: &RuntimeRegistry,
    keep_alive_registry: &KeepAliveRegistry,
    hostname: &str,
) {
    // Get all managed containers from Docker
    let containers = match docker.list_containers(Some("urt.managed=true")).await {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to list containers for orphaned cleanup: {}", e);
            return;
        }
    };

    if containers.is_empty() {
        return;
    }

    let mut container_names = HashSet::new();
    let mut by_keep_alive: HashMap<String, Vec<ContainerInfo>> = HashMap::new();

    for container in containers {
        if !belongs_to_hostname(&container, hostname) {
            continue;
        }

        container_names.insert(container.name.clone());
        if let Some(ka_id) = container
            .labels
            .get("urt.keep_alive_id")
            .cloned()
            .filter(|v| !v.is_empty())
        {
            by_keep_alive.entry(ka_id).or_default().push(container);
        }
    }

    // Drop stale owners whose container no longer exists.
    for (ka_id, owner_name) in keep_alive_registry.get_all_owners() {
        if !container_names.contains(&owner_name) {
            debug!(
                "Unregistering missing keep-alive owner '{}' for '{}'",
                owner_name, ka_id
            );
            keep_alive_registry.unregister(&ka_id, &owner_name);
            registry.remove(&owner_name).await;
        }
    }

    if by_keep_alive.is_empty() {
        debug!("No keep-alive labeled containers to reconcile");
        return;
    }

    for (ka_id, mut group) in by_keep_alive {
        let _keep_alive_lock = keep_alive_registry.lock(&ka_id).await;

        // Oldest first: newest running container is the preferred owner.
        group.sort_by_key(|c| c.created);

        let running: Vec<&ContainerInfo> =
            group.iter().filter(|c| is_container_running(c)).collect();
        let current_owner = keep_alive_registry.get_owner(&ka_id);
        let current_owner_valid = current_owner
            .as_ref()
            .map(|owner| running.iter().any(|c| c.name == *owner))
            .unwrap_or(false);

        let owner = if current_owner_valid {
            current_owner.unwrap()
        } else if let Some(new_owner) = running.last() {
            if let Some(generation) = keep_alive_generation_from_container(new_owner) {
                keep_alive_registry.observe_generation(&ka_id, generation);
            }
            if let Some(prev_owner) = keep_alive_registry.restore_owner(&ka_id, &new_owner.name) {
                if prev_owner != new_owner.name {
                    info!(
                        "Keep-alive '{}' owner changed from {} to {}",
                        ka_id, prev_owner, new_owner.name
                    );
                }
            }
            new_owner.name.clone()
        } else {
            if let Some(stale_owner) = current_owner {
                keep_alive_registry.unregister(&ka_id, &stale_owner);
            }
            String::new()
        };

        for container in group {
            if !owner.is_empty() && container.name == owner {
                // Keep live owner.
                continue;
            }

            info!(
                "Cleaning up orphaned keep-alive container {} for '{}'",
                container.name, ka_id
            );

            if !is_container_running(&container) {
                continue;
            }

            let removed =
                remove_container_for_cleanup(docker, &container.name, "orphaned keep-alive").await;
            if !removed {
                debug!(
                    "Keeping orphaned runtime {} in registry for retry after failed Docker removal",
                    container.name
                );
                continue;
            }

            if let Some(runtime) = registry.get(&container.name).await {
                if let Some(ref rt_ka) = runtime.keep_alive_id {
                    keep_alive_registry.unregister(rt_ka, &container.name);
                }
            }

            registry.remove(&container.name).await;
        }
    }
}

// Shutdown cleanup is now handled in main.rs via with_graceful_shutdown.

/// Clean up temporary build directories
async fn cleanup_temp_dirs(hostname: &str, registry: &RuntimeRegistry) {
    let tmp_dir = std::env::temp_dir();
    let prefix = format!("{}-", hostname);

    let entries = match tokio::fs::read_dir(&tmp_dir).await {
        Ok(entries) => entries,
        Err(e) => {
            debug!("Failed to read {}: {}", tmp_dir.display(), e);
            return;
        }
    };

    let mut entries = entries;
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();

        if name.starts_with(&prefix) {
            // Skip active runtimes to avoid breaking live containers
            if registry.exists(&name).await {
                continue;
            }

            let path = entry.path();
            if path.is_dir() {
                debug!("Removing temp dir: {}", path.display());
                if let Err(e) = tokio::fs::remove_dir_all(&path).await {
                    warn!("Failed to remove temp dir {}: {}", path.display(), e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        belongs_to_hostname, infer_runtime_version, is_container_running,
        keep_alive_id_from_container, runtime_id_from_container,
    };
    use crate::docker::container::ContainerInfo;
    use std::collections::HashMap;

    fn container(name: &str) -> ContainerInfo {
        ContainerInfo {
            id: "id".to_string(),
            name: name.to_string(),
            image: "openruntimes/node:v4-20".to_string(),
            state: "running".to_string(),
            status: "Up 5 seconds".to_string(),
            created: 1,
            labels: HashMap::new(),
            env: HashMap::new(),
            hostname: String::new(),
        }
    }

    #[test]
    fn test_infer_runtime_version_prefers_label_and_supports_older_modern_versions() {
        let mut labels = HashMap::new();
        labels.insert("urt.version".to_string(), "v3".to_string());
        assert_eq!(
            infer_runtime_version("openruntimes/node:v5-22", &labels),
            "v3"
        );

        let labels = HashMap::new();
        assert_eq!(
            infer_runtime_version("openruntimes/node:v4-20", &labels),
            "v4"
        );
        assert_eq!(
            infer_runtime_version("openruntimes/node:v2-18", &labels),
            "v2"
        );
    }

    #[test]
    fn test_runtime_id_and_keep_alive_fallbacks_use_labels_then_env() {
        let mut container = container("executor-my-runtime");
        container.labels.insert(
            "urt.runtime_id".to_string(),
            "runtime-from-label".to_string(),
        );
        container
            .env
            .insert("URT_KEEP_ALIVE".to_string(), "svc-a".to_string());

        assert_eq!(
            runtime_id_from_container(&container, "executor"),
            Some("runtime-from-label".to_string())
        );
        assert_eq!(
            keep_alive_id_from_container(&container),
            Some("svc-a".to_string())
        );
    }

    #[test]
    fn test_belongs_to_hostname_uses_label_or_name_prefix() {
        let mut labeled = container("other-host-runtime");
        labeled
            .labels
            .insert("urt.executor_hostname".to_string(), "executor".to_string());
        assert!(belongs_to_hostname(&labeled, "executor"));
        assert!(!belongs_to_hostname(&labeled, "someone-else"));

        let prefixed = container("executor-my-runtime");
        assert!(belongs_to_hostname(&prefixed, "executor"));
        assert!(!belongs_to_hostname(&prefixed, "other-host"));
    }

    #[test]
    fn test_is_container_running_checks_state_and_status() {
        let mut container = container("executor-my-runtime");
        assert!(is_container_running(&container));

        container.state.clear();
        container.status = "Exited (0)".to_string();
        assert!(!is_container_running(&container));
    }

    #[test]
    fn test_runtime_from_container_accepts_legacy_executor_hostname_typo() {
        let mut container = container("executor-my-runtime");
        container.env.insert(
            "INERNAL_EXECUTOR_HOSTNAME".to_string(),
            "executor-a".to_string(),
        );
        container.hostname = "runtime-host-123".to_string();

        let runtime = super::runtime_from_container(&container, "executor").unwrap();
        assert_eq!(runtime.hostname, "runtime-host-123");
    }
}
