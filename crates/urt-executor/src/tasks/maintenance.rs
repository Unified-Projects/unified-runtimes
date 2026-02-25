//! Maintenance task for cleaning up inactive runtimes

use crate::config::ExecutorConfig;
use crate::docker::container::ContainerInfo;
use crate::docker::DockerManager;
use crate::error::ExecutorError;
use crate::runtime::{KeepAliveRegistry, Runtime, RuntimeRegistry};
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

    if image.contains(":v5") || image.contains(":v5-") {
        "v5".to_string()
    } else if image.contains(":v2") || image.contains(":v2-") {
        "v2".to_string()
    } else {
        "v5".to_string()
    }
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

fn runtime_id_from_container(container: &ContainerInfo, hostname: &str) -> Option<String> {
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

    if let Some(internal_hostname) = container
        .env
        .get("OPEN_RUNTIMES_HOSTNAME")
        .or_else(|| container.env.get("INTERNAL_EXECUTOR_HOSTNAME"))
    {
        runtime.hostname = internal_hostname.clone();
    } else if !container.hostname.is_empty() {
        runtime.hostname = container.hostname.clone();
    }

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

    if let Err(e) = registry.insert(runtime.clone()).await {
        if matches!(e, ExecutorError::RuntimeConflict) {
            return false;
        }
        warn!("Failed to adopt container {}: {}", inspected.name, e);
        return false;
    }

    if let Some(ref ka_id) = runtime.keep_alive_id {
        if let Some(prev_owner) = keep_alive_registry.register(ka_id, &runtime.name) {
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

async fn remove_container_for_cleanup(
    docker: &DockerManager,
    name: &str,
    attempt_stop: bool,
    context: &str,
) -> bool {
    if attempt_stop {
        if let Err(e) = docker.stop_container(name, 10).await {
            warn!("Failed to stop {} container {}: {}", context, name, e);
        }
    }

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
/// When keep_alive is true (default), this only runs cleanup on shutdown.
/// When keep_alive is false, this removes runtimes that have been idle
/// longer than inactive_threshold.
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
                cleanup_orphaned_keepalive(&docker, &registry, &keep_alive_registry).await;

                if config.keep_alive {
                    // Keep-alive mode: only log stats, no cleanup
                    let count = registry.count().await;
                    debug!("Maintenance check: {} active runtimes (keep_alive=true, no cleanup)", count);
                } else {
                    // Normal mode: clean up idle runtimes (respects per-runtime keep-alive IDs)
                    cleanup_idle(&docker, &registry, &keep_alive_registry, config.inactive_threshold).await;
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
        let name = &runtime.name;

        let removed = remove_container_for_cleanup(docker, name, true, "idle").await;
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
            if let Some(prev_owner) = keep_alive_registry.register(&ka_id, &new_owner.name) {
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

            let removed = remove_container_for_cleanup(
                docker,
                &container.name,
                is_container_running(&container),
                "orphaned keep-alive",
            )
            .await;
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
