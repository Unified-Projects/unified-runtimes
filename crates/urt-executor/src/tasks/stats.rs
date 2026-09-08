//! Background stats collection
//!
//! Uses batch updates for efficiency: collects all stats first, then
//! performs a single atomic swap of the entire snapshot.

use crate::docker::{DockerManager, HostStats, StatsSnapshot};
use crate::runtime::RuntimeRegistry;
use futures_util::StreamExt;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tracing::debug;

/// Maximum concurrent Docker stats calls (M7).
const STATS_CONCURRENCY: usize = 20;

/// Cycles between calls to the daemon-wide `info` endpoint.
///
/// Host stats amount to the machine's total memory, which does not move while
/// the executor runs. Asking every second put one extra daemon call per second
/// on top of the per-container ones.
const HOST_INFO_REFRESH_CYCLES: u64 = 60;

/// Whether this cycle should call `info` again.
///
/// Refreshes on the first cycle, whenever nothing is cached (the previous call
/// failed), and once every `HOST_INFO_REFRESH_CYCLES` after that.
fn should_refresh_host_stats(cycle: u64, has_cached: bool) -> bool {
    !has_cached || cycle.is_multiple_of(HOST_INFO_REFRESH_CYCLES)
}

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
    let mut cycle: u64 = 0;
    let mut host_stats: Option<HostStats> = None;

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
                if should_refresh_host_stats(cycle, host_stats.is_some()) {
                    match docker.get_host_stats().await {
                        Ok(stats) => host_stats = Some(stats),
                        Err(e) => debug!("Failed to get host stats: {}", e),
                    }
                }

                collect_stats(&docker, &registry, host_stats.clone().unwrap_or_default()).await;
                cycle = cycle.wrapping_add(1);
            }
        }
    }

    debug!("Stats collector stopped");
}

/// Collect stats for all active runtimes using batch updates
///
/// This function collects all stats first using bounded concurrency, then
/// performs a single atomic update to the cache.
async fn collect_stats(docker: &DockerManager, registry: &RuntimeRegistry, host_stats: HostStats) {
    // Collect all container stats with bounded concurrency (M7). Each call is a
    // one-shot `stats` request, never a stream.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_cycle_always_asks_the_daemon() {
        assert!(should_refresh_host_stats(0, false));
        assert!(should_refresh_host_stats(0, true));
    }

    #[test]
    fn a_cached_value_is_reused_between_refreshes() {
        for cycle in 1..HOST_INFO_REFRESH_CYCLES {
            assert!(
                !should_refresh_host_stats(cycle, true),
                "cycle {cycle} should reuse the cached host stats"
            );
        }
    }

    #[test]
    fn the_refresh_comes_round_again() {
        assert!(should_refresh_host_stats(HOST_INFO_REFRESH_CYCLES, true));
        assert!(should_refresh_host_stats(
            HOST_INFO_REFRESH_CYCLES * 3,
            true
        ));
    }

    #[test]
    fn a_failed_call_is_retried_on_the_next_cycle() {
        assert!(should_refresh_host_stats(7, false));
    }
}
