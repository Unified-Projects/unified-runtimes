//! Maintenance task for cleaning up inactive runtimes

use crate::config::ExecutorConfig;
use crate::docker::container::{belongs_to_executor as belongs_to_hostname, ContainerInfo};
use crate::docker::DockerManager;
use crate::error::ExecutorError;
use crate::resilience::retry_with_backoff;
use crate::runtime::{
    wait_for_runtime_port, CreateTracker, KeepAliveRegistry, Runtime, RuntimeHealth,
    RuntimeLifecycle, RuntimeRegistry, RUNTIME_PORT,
};
use crate::storage::{BuildCache, Storage};
use dashmap::DashMap;
use futures_util::StreamExt;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{watch, Notify};
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

/// Rebuild a registry entry from a container the executor is adopting.
///
/// The lifecycle knobs come back off the container's labels, so a runtime
/// created with a longer startup window or a concurrency cap keeps them across
/// an executor restart; `defaults` covers containers created before the labels
/// existed.
fn runtime_from_container(
    container: &ContainerInfo,
    hostname: &str,
    defaults: RuntimeLifecycle,
) -> Option<Runtime> {
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
    // Adoption describes a container that already exists, so the entry is
    // published straight away: no create owns it and nothing else will clear
    // its pending state.
    runtime.publish_status(if container.state.is_empty() {
        &container.status
    } else {
        &container.state
    });
    // A running container has not proved it can serve; only an observed listener
    // sets `initialised`, which the caller does after probing the port.
    runtime.initialised = 0;
    runtime.apply_lifecycle(RuntimeLifecycle::from_labels(&container.labels, defaults));

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
    defaults: RuntimeLifecycle,
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

    let runtime = match runtime_from_container(&inspected, hostname, defaults) {
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
    if wait_for_runtime_port(&runtime.name, RUNTIME_PORT, Duration::from_millis(200))
        .await
        .is_ok()
    {
        runtime.set_listening();
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
    let result = retry_with_backoff("remove_container_cleanup", 3, 100, |_| async {
        docker.remove_container(name, true).await
    })
    .await;

    match result {
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
    defaults: RuntimeLifecycle,
) -> bool {
    if registry.exists(container_name).await {
        return true;
    }

    let inspected = match docker.inspect_container(container_name).await {
        Ok(info) => info,
        Err(_) => return false,
    };

    adopt_inspected_container(registry, keep_alive_registry, hostname, inspected, defaults).await
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
    defaults: RuntimeLifecycle,
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

    // Filter to candidates before issuing any network calls.
    let candidates: Vec<ContainerInfo> = containers
        .into_iter()
        .filter(|c| {
            if !belongs_to_hostname(c, hostname) {
                debug!(
                    "Skipping managed container {} during adoption for hostname {}",
                    c.name, hostname
                );
                return false;
            }
            if !is_container_running(c) {
                debug!(
                    "Skipping non-running container {} (state: {}, status: {})",
                    c.name, c.state, c.status
                );
                return false;
            }
            true
        })
        .collect();

    if candidates.is_empty() {
        debug!("No existing containers to adopt");
        return;
    }

    // Fan out Docker inspect calls in parallel, capped to avoid overwhelming the socket (H3).
    let concurrency = 16_usize.min(num_cpus::get().saturating_mul(2).max(4));

    let results: Vec<(String, Option<ContainerInfo>)> =
        futures_util::stream::iter(candidates.into_iter().map(|c| {
            let docker = docker.clone();
            async move {
                // Skip if registry already has this container (checked again after fanout).
                let name = c.name.clone();
                match docker.inspect_container(&name).await {
                    Ok(info) => (name, Some(info)),
                    Err(e) => {
                        warn!(
                            "Failed to inspect container {} during adoption: {}",
                            name, e
                        );
                        (name, None)
                    }
                }
            }
        }))
        .buffer_unordered(concurrency)
        .collect()
        .await;

    let mut adopted_count = 0usize;

    for (name, maybe_info) in results {
        // Skip if already in registry (could have been inserted by a concurrent call).
        if registry.exists(&name).await {
            debug!("Container {} already in registry, skipping", name);
            continue;
        }

        let inspected = match maybe_info {
            Some(info) => info,
            None => continue,
        };

        if !is_container_running(&inspected) {
            debug!(
                "Skipping container {} after inspect (state: {}, status: {})",
                name, inspected.state, inspected.status
            );
            continue;
        }

        if adopt_inspected_container(registry, keep_alive_registry, hostname, inspected, defaults)
            .await
        {
            adopted_count += 1;
        }
    }

    if adopted_count > 0 {
        info!("Adopted {} managed containers", adopted_count);
    }
}

/// The state the maintenance worker shares with the request path.
#[derive(Clone)]
pub struct MaintenanceHandles {
    pub docker: Arc<DockerManager>,
    pub registry: RuntimeRegistry,
    pub keep_alive_registry: KeepAliveRegistry,
    pub readiness: Arc<DashMap<String, Arc<Notify>>>,
    pub create_tracker: CreateTracker,
    pub health: RuntimeHealth,
}

/// Run the maintenance worker
///
/// Idle runtimes are always eligible for cleanup, but runtimes that currently
/// own a keep-alive ID stay protected.
pub async fn run_maintenance<S: Storage + 'static>(
    handles: MaintenanceHandles,
    config: ExecutorConfig,
    storage: S,
    mut shutdown: watch::Receiver<bool>,
) {
    let MaintenanceHandles {
        docker,
        registry,
        keep_alive_registry,
        readiness,
        create_tracker,
        health,
    } = handles;
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
                // Fetch the managed-container list once and share it across both
                // cleanup functions to avoid duplicate Docker API calls (M4).
                let managed_containers = match docker.list_containers(Some("urt.managed=true")).await {
                    Ok(c) => c,
                    Err(e) => {
                        warn!("Failed to list managed containers for maintenance: {}", e);
                        vec![]
                    }
                };

                // Always check for orphaned keepalive containers (runs regardless of keep_alive setting)
                // This catches cases where a container was replaced but previous owner wasn't cleaned up
                cleanup_orphaned_keepalive(&docker, &registry, &keep_alive_registry, &config.hostname, &managed_containers).await;

                cleanup_idle(&docker, &registry, &keep_alive_registry, config.inactive_threshold).await;

                // Runs before the untracked-container sweep so a container left
                // behind by a reaped entry is cleaned up in the same cycle.
                cleanup_stale_pending(&registry, &readiness, &create_tracker, config.pending_max_age_secs).await;

                let released = crate::runtime::liveness::sweep_expired_quarantines(&registry, &health).await;
                if released > 0 {
                    info!("Released {} runtimes whose quarantine expired", released);
                }

                cleanup_untracked_managed_containers(&docker, &registry, &config.hostname, &managed_containers).await;

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

/// Clean up runtimes that have been idle longer than they tolerate.
///
/// Each runtime is measured against its own `inactiveThreshold`, so a caller can
/// keep a rarely-used runtime warm for longer than the executor default without
/// changing it for everything else; `default_threshold` covers runtimes that
/// asked for nothing. Runtimes that currently own a keep-alive ID are protected.
pub async fn cleanup_idle(
    docker: &DockerManager,
    registry: &RuntimeRegistry,
    keep_alive_registry: &KeepAliveRegistry,
    default_threshold: u64,
) {
    let idle_runtimes = registry.get_idle(default_threshold).await;

    if idle_runtimes.is_empty() {
        debug!("No idle runtimes to clean up");
        return;
    }

    // Filter out runtimes that are protected by keep-alive ownership or still pending
    let runtimes_to_cleanup: Vec<_> = idle_runtimes
        .into_iter()
        .filter(|runtime| {
            if runtime.is_pending() {
                debug!(
                    "Skipping cleanup of {} - still in pending state",
                    runtime.name
                );
                return false;
            }
            // Quarantined entries have no container; they stay listed until the
            // quarantine lapses and the sweep above releases them.
            if runtime.is_quarantined() {
                return false;
            }
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

/// Whether a registry entry is a pending entry that nothing will ever resolve.
///
/// Pending entries are only produced by `create_runtime`, which keeps its build
/// registered in the `CreateTracker` for the whole time it runs. An entry that
/// is pending with no create behind it is therefore orphaned, and once it is
/// past `max_age_secs` it is not a create that has only just registered either.
fn is_orphaned_pending(
    runtime: &Runtime,
    create_tracker: &CreateTracker,
    max_age_secs: u64,
) -> bool {
    runtime.is_pending()
        && !create_tracker.is_in_flight(&runtime.name)
        && runtime.age_seconds() >= max_age_secs
}

/// Reap pending registry entries whose create is no longer in flight.
///
/// An orphaned pending entry is what wedges a runtime ID: every later create
/// trips the existing-runtime guard and gets `RuntimeConflict`, and every
/// execution parks on a readiness notifier that nothing will fire. This is the
/// safety net for the cases the create path cannot clean up itself, such as a
/// build task that panicked. Returns the number of entries reaped.
pub async fn cleanup_stale_pending(
    registry: &RuntimeRegistry,
    readiness: &DashMap<String, Arc<Notify>>,
    create_tracker: &CreateTracker,
    max_age_secs: u64,
) -> usize {
    let orphaned: Vec<Runtime> = registry
        .list()
        .await
        .into_iter()
        .filter(|runtime| is_orphaned_pending(runtime, create_tracker, max_age_secs))
        .collect();

    for runtime in &orphaned {
        warn!(
            "Reaping orphaned pending runtime {} ({}s old, no create in flight)",
            runtime.name,
            runtime.age_seconds()
        );

        // Wake parked waiters before the entry disappears so they re-check and
        // return a deterministic 404 instead of waiting out their deadline.
        if let Some((_, notify)) = readiness.remove(&runtime.name) {
            notify.notify_waiters();
        }
        registry.remove(&runtime.name).await;

        let tmp_folder = crate::platform::temp_dir().join(&runtime.name);
        if let Err(e) = tokio::fs::remove_dir_all(&tmp_folder).await {
            debug!(
                "No temp directory removed for reaped runtime {}: {}",
                runtime.name, e
            );
        }
    }

    orphaned.len()
}

async fn cleanup_untracked_managed_containers(
    docker: &DockerManager,
    registry: &RuntimeRegistry,
    hostname: &str,
    containers: &[ContainerInfo],
) {
    for container in containers {
        if !belongs_to_hostname(container, hostname) {
            continue;
        }

        if registry.exists(&container.name).await {
            continue;
        }

        if let Some(keep_alive_id) = keep_alive_id_from_container(container) {
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

/// Drop keep-alive owners whose container is not in the observed set.
///
/// A create registers ownership as soon as it inserts its pending entry, long
/// before the container exists: it still has the source to download. Sweeping
/// that owner away would leave the create to fail at its own registry update and
/// tear down the container it had just built. Two rules keep that from
/// happening: a pending entry is never touched, and the check and the removal
/// both run under the per-ID keep-alive lock, which every create holds for the
/// length of its build.
async fn drop_missing_keep_alive_owners(
    registry: &RuntimeRegistry,
    keep_alive_registry: &KeepAliveRegistry,
    container_names: &HashSet<String>,
) {
    for (ka_id, owner_name) in keep_alive_registry.get_all_owners() {
        if container_names.contains(&owner_name) {
            continue;
        }

        let _keep_alive_lock = keep_alive_registry.lock(&ka_id).await;

        // Ownership can have moved on while this task waited for the lock.
        if !keep_alive_registry.is_owner(&ka_id, &owner_name) {
            continue;
        }

        if registry
            .get(&owner_name)
            .await
            .is_some_and(|runtime| runtime.is_pending())
        {
            debug!(
                "Keeping keep-alive owner '{}' for '{}': its create is still running",
                owner_name, ka_id
            );
            continue;
        }

        debug!(
            "Unregistering missing keep-alive owner '{}' for '{}'",
            owner_name, ka_id
        );
        keep_alive_registry.unregister(&ka_id, &owner_name);
        registry.remove(&owner_name).await;
    }
}

/// Clean up orphaned keepalive containers
///
/// This function handles cases where a container with a keep_alive_id was
/// replaced by a new runtime but the previous owner wasn't cleaned up.
/// It uses the pre-fetched container list from the maintenance cycle (M4).
async fn cleanup_orphaned_keepalive(
    docker: &DockerManager,
    registry: &RuntimeRegistry,
    keep_alive_registry: &KeepAliveRegistry,
    hostname: &str,
    containers: &[ContainerInfo],
) {
    if containers.is_empty() {
        return;
    }

    let mut container_names = HashSet::new();
    let mut by_keep_alive: HashMap<String, Vec<ContainerInfo>> = HashMap::new();

    for container in containers {
        if !belongs_to_hostname(container, hostname) {
            continue;
        }

        container_names.insert(container.name.clone());
        if let Some(ka_id) = container
            .labels
            .get("urt.keep_alive_id")
            .cloned()
            .filter(|v| !v.is_empty())
        {
            by_keep_alive
                .entry(ka_id)
                .or_default()
                .push(container.clone());
        }
    }

    drop_missing_keep_alive_owners(registry, keep_alive_registry, &container_names).await;

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

            // Skip containers whose registry entry is actively pending — they are
            // in the middle of create_runtime and must not be torn down here.
            // This mirrors the invariant established in cleanup_idle.
            if let Some(rt) = registry.get(&container.name).await {
                if rt.is_pending() {
                    debug!(
                        "Skipping orphaned keep-alive cleanup of {} — still pending in registry",
                        container.name
                    );
                    continue;
                }
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
        belongs_to_hostname, cleanup_stale_pending, infer_runtime_version, is_container_running,
        keep_alive_id_from_container, runtime_id_from_container,
    };
    use crate::docker::container::ContainerInfo;
    use crate::runtime::create_tracker::BeginCreate;
    use crate::runtime::{
        CreateTracker, KeepAliveRegistry, Runtime, RuntimeLifecycle, RuntimeRegistry,
    };
    use dashmap::DashMap;
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;
    use tokio::sync::Notify;

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
            exit_code: None,
            oom_killed: false,
            restart_policy: String::new(),
            restart_max_retries: 0,
            restart_count: 0,
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

        let runtime =
            super::runtime_from_container(&container, "executor", RuntimeLifecycle::default())
                .unwrap();
        assert_eq!(runtime.hostname, "runtime-host-123");
    }

    #[test]
    fn test_runtime_from_container_restores_lifecycle_labels() {
        let mut container = container("executor-my-runtime");
        container
            .labels
            .insert("urt.startup_timeout".to_string(), "300".to_string());
        container
            .labels
            .insert("urt.inactive_threshold".to_string(), "900".to_string());
        container
            .labels
            .insert("urt.max_concurrency".to_string(), "4".to_string());

        let runtime =
            super::runtime_from_container(&container, "executor", RuntimeLifecycle::default())
                .unwrap();

        assert_eq!(runtime.startup_timeout, 300);
        assert_eq!(runtime.inactive_threshold, 900);
        assert_eq!(runtime.max_concurrency, Some(4));
    }

    #[test]
    fn test_runtime_from_container_falls_back_to_executor_defaults() {
        let container = container("executor-my-runtime");
        let defaults = RuntimeLifecycle {
            startup_timeout: 45,
            inactive_threshold: 120,
            max_concurrency: Some(8),
        };

        let runtime = super::runtime_from_container(&container, "executor", defaults).unwrap();

        assert_eq!(runtime.startup_timeout, 45);
        assert_eq!(runtime.inactive_threshold, 120);
        assert_eq!(runtime.max_concurrency, Some(8));
    }

    #[test]
    fn test_runtime_from_container_never_adopts_as_initialised() {
        let container = container("executor-my-runtime");

        let runtime =
            super::runtime_from_container(&container, "executor", RuntimeLifecycle::default())
                .unwrap();

        assert!(is_container_running(&container));
        assert_eq!(runtime.initialised, 0);
        assert_eq!(runtime.listening, 0);
    }

    /// A pending entry aged `age_secs` seconds.
    fn aged_pending(runtime_id: &str, age_secs: f64) -> Runtime {
        let mut runtime = Runtime::new(runtime_id, "executor", "img", "v5", None);
        runtime.created -= age_secs;
        runtime.updated -= age_secs;
        runtime
    }

    #[tokio::test]
    async fn reaps_pending_entries_with_no_create_in_flight() {
        let registry = RuntimeRegistry::new();
        let readiness: DashMap<String, Arc<Notify>> = DashMap::new();
        let create_tracker = CreateTracker::new();

        registry
            .insert(aged_pending("wedged", 600.0))
            .await
            .unwrap();
        readiness.insert("executor-wedged".to_string(), Arc::new(Notify::new()));

        let reaped = cleanup_stale_pending(&registry, &readiness, &create_tracker, 300).await;

        assert_eq!(reaped, 1);
        assert!(
            registry.get("executor-wedged").await.is_none(),
            "an orphaned pending entry must be reaped so later creates stop getting 409"
        );
        assert!(
            !readiness.contains_key("executor-wedged"),
            "the readiness notifier must go with the entry"
        );
    }

    #[tokio::test]
    async fn does_not_reap_a_pending_entry_whose_build_is_still_running() {
        let registry = RuntimeRegistry::new();
        let readiness: DashMap<String, Arc<Notify>> = DashMap::new();
        let create_tracker = CreateTracker::new();

        registry
            .insert(aged_pending("building", 6_000.0))
            .await
            .unwrap();

        // Hold the create slot for the whole check, as a running build does.
        let _slot = match create_tracker.begin("executor-building") {
            BeginCreate::Started(slot) => slot,
            BeginCreate::Joined(_) => panic!("slot must be free"),
        };

        let reaped = cleanup_stale_pending(&registry, &readiness, &create_tracker, 300).await;

        assert_eq!(reaped, 0);
        assert!(
            registry.get("executor-building").await.is_some(),
            "a build that is still running must keep its pending entry, however long it takes"
        );
    }

    #[tokio::test]
    async fn does_not_reap_young_pending_or_running_entries() {
        let registry = RuntimeRegistry::new();
        let readiness: DashMap<String, Arc<Notify>> = DashMap::new();
        let create_tracker = CreateTracker::new();

        registry.insert(aged_pending("fresh", 5.0)).await.unwrap();

        let mut running = aged_pending("live", 6_000.0);
        running.mark_running("running");
        registry.insert(running).await.unwrap();

        let reaped = cleanup_stale_pending(&registry, &readiness, &create_tracker, 300).await;

        assert_eq!(reaped, 0);
        assert!(registry.get("executor-fresh").await.is_some());
        assert!(registry.get("executor-live").await.is_some());
    }

    #[tokio::test]
    async fn reaping_wakes_readiness_waiters() {
        let registry = RuntimeRegistry::new();
        let readiness: DashMap<String, Arc<Notify>> = DashMap::new();
        let create_tracker = CreateTracker::new();

        registry
            .insert(aged_pending("wedged", 600.0))
            .await
            .unwrap();
        let notify = Arc::new(Notify::new());
        readiness.insert("executor-wedged".to_string(), notify.clone());

        let waiter = tokio::spawn(async move { notify.notified().await });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        cleanup_stale_pending(&registry, &readiness, &create_tracker, 300).await;

        tokio::time::timeout(std::time::Duration::from_secs(2), waiter)
            .await
            .expect("a parked waiter must be woken by the reap, not left to its deadline")
            .unwrap();
    }

    #[tokio::test]
    async fn stale_owner_sweep_leaves_a_pending_create_alone() {
        let registry = RuntimeRegistry::new();
        let keep_alive_registry = KeepAliveRegistry::new();

        // A create that has registered its ownership and is still downloading:
        // pending entry, no container yet.
        registry
            .insert(Runtime::new(
                "building",
                "executor",
                "img",
                "v5",
                Some("svc".to_string()),
            ))
            .await
            .unwrap();
        keep_alive_registry.register("svc", "executor-building");

        super::drop_missing_keep_alive_owners(&registry, &keep_alive_registry, &HashSet::new())
            .await;

        assert!(
            keep_alive_registry.is_owner("svc", "executor-building"),
            "a create in flight must keep the ownership it registered"
        );
        assert!(
            registry.get("executor-building").await.is_some(),
            "sweeping the entry would make the create fail at its own registry update"
        );
    }

    #[tokio::test]
    async fn stale_owner_sweep_drops_a_published_owner_with_no_container() {
        let registry = RuntimeRegistry::new();
        let keep_alive_registry = KeepAliveRegistry::new();

        let mut runtime = Runtime::new("gone", "executor", "img", "v5", Some("svc".to_string()));
        runtime.mark_running("running");
        registry.insert(runtime).await.unwrap();
        keep_alive_registry.register("svc", "executor-gone");

        super::drop_missing_keep_alive_owners(&registry, &keep_alive_registry, &HashSet::new())
            .await;

        assert!(!keep_alive_registry.is_owner("svc", "executor-gone"));
        assert!(registry.get("executor-gone").await.is_none());
    }

    #[tokio::test]
    async fn stale_owner_sweep_waits_for_the_keep_alive_lock() {
        let registry = RuntimeRegistry::new();
        let keep_alive_registry = KeepAliveRegistry::new();

        let mut runtime = Runtime::new("gone", "executor", "img", "v5", Some("svc".to_string()));
        runtime.mark_running("running");
        registry.insert(runtime).await.unwrap();
        keep_alive_registry.register("svc", "executor-gone");

        // A replacement create holds the per-ID lock.
        let held = keep_alive_registry.lock("svc").await;

        let sweep_registry = registry.clone();
        let sweep_keep_alive = keep_alive_registry.clone();
        let sweep = tokio::spawn(async move {
            super::drop_missing_keep_alive_owners(
                &sweep_registry,
                &sweep_keep_alive,
                &HashSet::new(),
            )
            .await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            keep_alive_registry.is_owner("svc", "executor-gone"),
            "the sweep must not touch ownership while a create holds the lock"
        );

        drop(held);
        tokio::time::timeout(std::time::Duration::from_secs(2), sweep)
            .await
            .expect("the sweep must proceed once the lock is free")
            .unwrap();

        assert!(!keep_alive_registry.is_owner("svc", "executor-gone"));
    }
}
