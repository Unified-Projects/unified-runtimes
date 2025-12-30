//! Maintenance task for cleaning up inactive runtimes

use crate::config::ExecutorConfig;
use crate::docker::DockerManager;
use crate::runtime::RuntimeRegistry;
use crate::storage::{BuildCache, Storage};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{debug, info, warn};

/// Maximum build cache size in bytes (1GB)
const MAX_BUILD_CACHE_BYTES: u64 = 1024 * 1024 * 1024;

/// Run the maintenance worker
///
/// When keep_alive is true (default), this only runs cleanup on shutdown.
/// When keep_alive is false, this removes runtimes that have been idle
/// longer than inactive_threshold.
pub async fn run_maintenance<S: Storage + 'static>(
    docker: Arc<DockerManager>,
    registry: RuntimeRegistry,
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
                    info!("Shutdown signal received, running final cleanup");
                    cleanup_all(&docker, &registry).await;
                    break;
                }
            }
            _ = tokio::time::sleep(interval) => {
                if config.keep_alive {
                    // Keep-alive mode: only log stats, no cleanup
                    let count = registry.count().await;
                    debug!("Maintenance check: {} active runtimes (keep_alive=true, no cleanup)", count);
                } else {
                    // Normal mode: clean up idle runtimes
                    cleanup_idle(&docker, &registry, config.inactive_threshold).await;
                }

                // Always clean up temporary build directories
                cleanup_temp_dirs(&config.hostname).await;

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
async fn cleanup_idle(docker: &DockerManager, registry: &RuntimeRegistry, threshold: u64) {
    let idle_runtimes = registry.get_idle(threshold).await;

    if idle_runtimes.is_empty() {
        debug!("No idle runtimes to clean up");
    } else {
        info!("Cleaning up {} idle runtimes", idle_runtimes.len());

        for runtime in idle_runtimes {
            info!(
                "Removing idle runtime: {} (idle for {}s)",
                runtime.runtime_id(),
                runtime.idle_seconds()
            );

            // Stop container
            if let Err(e) = docker.stop_container(&runtime.name, 10).await {
                warn!("Failed to stop container {}: {}", runtime.runtime_id(), e);
            }

            // Remove container
            if let Err(e) = docker.remove_container(&runtime.name, true).await {
                warn!("Failed to remove container {}: {}", runtime.runtime_id(), e);
            }

            // Remove from registry
            registry.remove(&runtime.name).await;
        }
    }

    // Also clean up orphaned containers (in Docker but not in registry)
    cleanup_orphaned_containers(docker, registry).await;
}

/// Clean up orphaned containers that exist in Docker but not in registry
async fn cleanup_orphaned_containers(docker: &DockerManager, registry: &RuntimeRegistry) {
    // List containers with our label
    let containers = match docker.list_containers(Some("urt.managed=true")).await {
        Ok(c) => c,
        Err(e) => {
            debug!("Failed to list containers for orphan detection: {}", e);
            return;
        }
    };

    for container in containers {
        // Check if this container is in the registry
        if !registry.exists(&container.name).await {
            info!(
                "Found orphaned container: {} (not in registry, removing)",
                container.name
            );

            // Stop and remove orphaned container
            if let Err(e) = docker.stop_container(&container.name, 5).await {
                debug!(
                    "Failed to stop orphaned container {}: {}",
                    container.name, e
                );
            }

            if let Err(e) = docker.remove_container(&container.name, true).await {
                warn!(
                    "Failed to remove orphaned container {}: {}",
                    container.name, e
                );
            }
        }
    }
}

/// Clean up all runtimes (used during shutdown)
async fn cleanup_all(docker: &DockerManager, registry: &RuntimeRegistry) {
    let all_runtimes = registry.clear().await;

    if all_runtimes.is_empty() {
        info!("No runtimes to clean up");
        return;
    }

    info!("Cleaning up {} runtimes on shutdown", all_runtimes.len());

    for runtime in all_runtimes {
        info!("Removing runtime: {}", runtime.name);

        // Force stop and remove
        if let Err(e) = docker.stop_container(&runtime.name, 5).await {
            debug!("Failed to stop container {}: {}", runtime.name, e);
        }

        if let Err(e) = docker.remove_container(&runtime.name, true).await {
            warn!("Failed to remove container {}: {}", runtime.name, e);
        }
    }

    info!("Shutdown cleanup complete");
}

/// Clean up temporary build directories
async fn cleanup_temp_dirs(hostname: &str) {
    let tmp_dir = "/tmp";
    let prefix = format!("{}-", hostname);

    let entries = match tokio::fs::read_dir(tmp_dir).await {
        Ok(entries) => entries,
        Err(e) => {
            debug!("Failed to read /tmp: {}", e);
            return;
        }
    };

    let mut entries = entries;
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();

        if name.starts_with(&prefix) {
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
