//! Docker stats collection with lock-free reads
//!
//! Uses arc-swap for zero-contention reads on the hot path (health checks).
//! Stats are updated atomically as a single snapshot.

#![allow(deprecated)]

use crate::error::{ExecutorError, Result};
use arc_swap::ArcSwap;
use bollard::container::StatsOptions;
use bollard::Docker;
use futures_util::StreamExt;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::debug;

/// Host-level resource usage
#[derive(Debug, Clone, Serialize, Default)]
pub struct HostStats {
    pub memory_percentage: f64,
    pub memory_limit: u64,
    pub cpu_percentage: f64,
}

/// Container-level resource usage
#[derive(Debug, Clone, Serialize)]
pub struct ContainerStats {
    pub name: String,
    pub cpu: f64,
    pub memory: u64,
}

/// Atomic snapshot of all stats - host + containers together
/// This eliminates the need for multiple lock acquisitions
#[derive(Debug, Clone, Default)]
pub struct StatsSnapshot {
    pub host: HostStats,
    pub containers: Vec<ContainerStats>,
    /// Internal map for efficient updates (not serialized)
    container_map: HashMap<String, ContainerStats>,
}

impl StatsSnapshot {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create snapshot from host and container map (for batch updates)
    pub fn from_parts(host: HostStats, container_map: HashMap<String, ContainerStats>) -> Self {
        let containers: Vec<ContainerStats> = container_map.values().cloned().collect();
        Self {
            host,
            containers,
            container_map,
        }
    }

    /// Create a new snapshot with a container removed
    pub fn without_container(&self, name: &str) -> Self {
        let mut container_map = self.container_map.clone();
        container_map.remove(name);
        Self::from_parts(self.host.clone(), container_map)
    }
}

/// Shared stats cache with lock-free reads
///
/// Read operations use atomic pointer loads - zero contention.
/// Write operations atomically swap the entire snapshot.
#[derive(Debug, Clone)]
pub struct StatsCache {
    snapshot: Arc<ArcSwap<StatsSnapshot>>,
}

impl Default for StatsCache {
    fn default() -> Self {
        Self::new()
    }
}

impl StatsCache {
    pub fn new() -> Self {
        Self {
            snapshot: Arc::new(ArcSwap::from_pointee(StatsSnapshot::new())),
        }
    }

    /// Get the current stats snapshot - LOCK FREE
    /// This is the hot path - zero contention under any load
    #[inline]
    pub fn get_snapshot(&self) -> Arc<StatsSnapshot> {
        self.snapshot.load_full()
    }

    /// Update the entire snapshot atomically (preferred for batch updates)
    pub fn update_snapshot(&self, new_snapshot: StatsSnapshot) {
        self.snapshot.store(Arc::new(new_snapshot));
    }

    /// Remove a container (creates new snapshot and swaps)
    pub fn remove_container(&self, name: &str) {
        let current = self.snapshot.load_full();
        let new_snapshot = current.without_container(name);
        self.snapshot.store(Arc::new(new_snapshot));
    }
}

/// Get stats for a single container
pub async fn get_container_stats(docker: &Docker, container_name: &str) -> Result<ContainerStats> {
    debug!("Getting stats for container: {}", container_name);

    let options = StatsOptions {
        stream: false,
        ..Default::default()
    };

    let mut stream = docker.stats(container_name, Some(options));

    if let Some(result) = stream.next().await {
        let stats = result.map_err(|e| ExecutorError::Docker(e.to_string()))?;

        // Calculate CPU percentage (handle nested Options from Bollard 0.19)
        let (cpu_percent, memory) = if let (Some(cpu_stats), Some(precpu_stats), Some(mem_stats)) =
            (&stats.cpu_stats, &stats.precpu_stats, &stats.memory_stats)
        {
            // cpu_usage is also an Option in Bollard 0.19
            let cpu_usage = cpu_stats.cpu_usage.as_ref();
            let precpu_usage = precpu_stats.cpu_usage.as_ref();

            let cpu_delta = cpu_usage.and_then(|u| u.total_usage).unwrap_or(0) as f64
                - precpu_usage.and_then(|u| u.total_usage).unwrap_or(0) as f64;
            let system_delta = cpu_stats.system_cpu_usage.unwrap_or(0) as f64
                - precpu_stats.system_cpu_usage.unwrap_or(0) as f64;
            let num_cpus = cpu_stats.online_cpus.unwrap_or(1) as f64;

            let cpu_pct = if system_delta > 0.0 && cpu_delta > 0.0 {
                (cpu_delta / system_delta) * num_cpus * 100.0
            } else {
                0.0
            };

            let mem = mem_stats.usage.unwrap_or(0);

            (cpu_pct, mem)
        } else {
            (0.0, 0)
        };

        return Ok(ContainerStats {
            name: container_name.to_string(),
            cpu: cpu_percent,
            memory,
        });
    }

    Err(ExecutorError::Docker("No stats available".to_string()))
}

/// Get host-level stats by reading system info
pub async fn get_host_stats(docker: &Docker) -> Result<HostStats> {
    let info = docker
        .info()
        .await
        .map_err(|e| ExecutorError::Docker(e.to_string()))?;

    let mem_total = info.mem_total.unwrap_or(0) as u64;

    // We can't get accurate host CPU from Docker API alone
    // Return placeholder values; real implementation would read /proc/stat
    Ok(HostStats {
        memory_percentage: 0.0, // Would need to read from /proc/meminfo
        memory_limit: mem_total,
        cpu_percentage: 0.0, // Would need to read from /proc/stat
    })
}
