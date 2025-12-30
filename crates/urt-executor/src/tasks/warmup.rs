//! Image pre-warming task

use crate::config::ExecutorConfig;
use crate::docker::DockerManager;
use std::sync::Arc;
use tracing::{error, info, warn};

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
    // e.g., "node-22" -> "openruntimes/node-22:v5"
    let expanded_runtimes = config.expanded_runtimes();

    info!(
        "Starting image warmup for {} runtimes",
        expanded_runtimes.len()
    );

    // Pull images concurrently (Bollard's pull_image handles semaphore internally)
    let mut handles = Vec::new();

    for image in expanded_runtimes {
        let docker = docker.clone();

        let handle = tokio::spawn(async move {
            info!("Pulling image: {}", image);
            match docker.pull_image(&image).await {
                Ok(_) => {
                    info!("Successfully pulled: {}", image);
                    true
                }
                Err(e) => {
                    warn!("Failed to pull {}: {}", image, e);
                    false
                }
            }
        });

        handles.push(handle);
    }

    // Wait for all pulls to complete
    let mut success_count = 0;
    let mut fail_count = 0;

    for handle in handles {
        match handle.await {
            Ok(true) => success_count += 1,
            Ok(false) => fail_count += 1,
            Err(e) => {
                error!("Pull task panicked: {}", e);
                fail_count += 1;
            }
        }
    }

    info!(
        "Warmup complete: {} succeeded, {} failed",
        success_count, fail_count
    );
}
