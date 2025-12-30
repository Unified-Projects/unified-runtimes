//! Background stats collection
//!
//! Uses batch updates for efficiency: collects all stats first, then
//! performs a single atomic swap of the entire snapshot.

use crate::docker::{DockerManager, StatsSnapshot};
use crate::runtime::RuntimeRegistry;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tracing::debug;

/// Run the stats collector
///
/// Periodically collects CPU and memory stats for all active containers
/// and updates the stats cache with a single atomic operation.
pub async fn run_stats_collector(
    docker: Arc<DockerManager>,
    registry: RuntimeRegistry,
    mut shutdown: watch::Receiver<bool>,
) {
    let interval = Duration::from_secs(1);

    debug!("Starting stats collector (interval: 1s)");

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    debug!("Stats collector shutting down");
                    break;
                }
            }
            _ = tokio::time::sleep(interval) => {
                collect_stats(&docker, &registry).await;
            }
        }
    }

    debug!("Stats collector stopped");
}

/// Collect stats for all active runtimes using batch updates
///
/// This function collects all stats first, then performs a single
/// atomic update to the cache. This is more efficient than multiple
/// individual updates and ensures consistent reads.
async fn collect_stats(docker: &DockerManager, registry: &RuntimeRegistry) {
    // Collect host stats (use default if unavailable)
    let host_stats = docker.get_host_stats().await.unwrap_or_default();

    // Collect all container stats into a map
    let runtimes = registry.list().await;
    let mut container_map = HashMap::new();

    for runtime in runtimes {
        if runtime.is_running() {
            match docker.get_container_stats(&runtime.name).await {
                Ok(stats) => {
                    container_map.insert(runtime.name.clone(), stats);
                }
                Err(e) => {
                    debug!("Failed to get stats for {}: {}", runtime.name, e);
                }
            }
        }
    }

    // Single atomic update - replaces entire snapshot at once
    let snapshot = StatsSnapshot::from_parts(host_stats, container_map);
    docker.stats_cache().update_snapshot(snapshot);
}
