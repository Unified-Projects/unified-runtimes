//! Maintenance task for cleaning up inactive runtimes

use crate::config::ExecutorConfig;
use crate::docker::DockerManager;
use crate::runtime::{KeepAliveRegistry, RuntimeRegistry};
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
                if config.keep_alive {
                    // Keep-alive mode: only log stats, no cleanup
                    let count = registry.count().await;
                    debug!("Maintenance check: {} active runtimes (keep_alive=true, no cleanup)", count);
                } else {
                    // Normal mode: clean up idle runtimes (respects per-runtime keep-alive IDs)
                    cleanup_idle(&docker, &registry, &keep_alive_registry, config.inactive_threshold).await;
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

        // Stop container (best effort)
        if let Err(e) = docker.stop_container(name, 10).await {
            warn!("Failed to stop idle container {}: {}", name, e);
        }

        // Force remove container
        if let Err(e) = docker.remove_container(name, true).await {
            warn!("Failed to remove idle container {}: {}", name, e);
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

// Shutdown cleanup is now handled in main.rs via with_graceful_shutdown.

/// Clean up temporary build directories
async fn cleanup_temp_dirs(hostname: &str) {
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
