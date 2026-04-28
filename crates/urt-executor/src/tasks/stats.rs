//! Background stats collection
//!
//! Uses batch updates for efficiency: collects all stats first, then
//! performs a single atomic swap of the entire snapshot.

use crate::docker::{DockerManager, StatsSnapshot};
use crate::runtime::RuntimeRegistry;
use futures_util::StreamExt;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tracing::debug;

/// Maximum concurrent Docker stats calls (M7).
const STATS_CONCURRENCY: usize = 20;

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
/// This function collects all stats first using bounded concurrency, then
/// performs a single atomic update to the cache.
async fn collect_stats(docker: &DockerManager, registry: &RuntimeRegistry) {
    // Collect host stats (use default if unavailable)
    let host_stats = docker.get_host_stats().await.unwrap_or_default();

    // Collect all container stats with bounded concurrency (M7).
    let runtimes = registry.list().await;

    let container_map: HashMap<String, _> =
        futures_util::stream::iter(runtimes.into_iter().filter(|r| r.is_running()).map(|rt| {
            let docker = docker.clone();
            async move {
                match docker.get_container_stats(&rt.name).await {
                    Ok(stats) => Some((rt.name, stats)),
                    Err(e) => {
                        debug!("Failed to get stats for {}: {}", rt.name, e);
                        None
                    }
                }
            }
        }))
        .buffer_unordered(STATS_CONCURRENCY)
        .filter_map(|x| async move { x })
        .collect()
        .await;

    // Single atomic update - replaces entire snapshot at once
    let snapshot = StatsSnapshot::from_parts(host_stats, container_map);
    docker.stats_cache().update_snapshot(snapshot);
}
