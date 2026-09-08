//! Image pre-warming task

use crate::config::ExecutorConfig;
use crate::docker::DockerManager;
use crate::resilience::retry_with_backoff;
use futures_util::StreamExt;
use std::sync::Arc;
use tracing::{info, warn};

/// Maximum concurrent image pulls (matches the pull_semaphore inside DockerManager).
const WARMUP_CONCURRENCY: usize = 4;

/// Pre-pull allowed runtime images on startup
pub async fn run_warmup(docker: Arc<DockerManager>, config: ExecutorConfig) {
    if !config.image_pull_enabled {
        info!("Image pull disabled, skipping warmup");
        return;
    }

    if config.allowed_runtimes.is_empty() {
        info!("No allowed runtimes configured, skipping warmup");
        return;
    }

    // Expand shorthand runtime names to full image references
    // e.g., "node-22" -> "openruntimes/node:v5-22"
    let expanded_runtimes = config.expanded_runtimes();

    info!(
        "Starting image warmup for {} runtimes",
        expanded_runtimes.len()
    );

    let mut success_count = 0usize;
    let mut fail_count = 0usize;

    // Pull images with bounded concurrency and per-image retry (M5, W1).
    let results: Vec<bool> =
        futures_util::stream::iter(expanded_runtimes.into_iter().map(|image| {
            let docker = docker.clone();
            async move {
                info!("Pulling image: {}", image);
                let outcome = retry_with_backoff("warmup_pull", 3, 500, |_| {
                    let docker = docker.clone();
                    let image = image.clone();
                    async move { docker.pull_image(&image).await }
                })
                .await;

                match outcome {
                    Ok(_) => {
                        info!("Successfully pulled: {}", image);
                        true
                    }
                    Err(e) => {
                        warn!("Failed to pull {} after retries: {}", image, e);
                        false
                    }
                }
            }
        }))
        .buffer_unordered(WARMUP_CONCURRENCY)
        .collect()
        .await;

    for ok in results {
        if ok {
            success_count += 1;
        } else {
            fail_count += 1;
        }
    }

    info!(
        "Warmup complete: {} succeeded, {} failed",
        success_count, fail_count
    );
}
