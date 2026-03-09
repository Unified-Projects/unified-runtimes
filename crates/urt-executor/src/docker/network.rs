//! Docker network management

#![allow(deprecated)]

use crate::error::{ExecutorError, Result};
use bollard::models::{NetworkConnectRequest, NetworkCreateRequest};
use bollard::query_parameters::InspectNetworkOptions;
use bollard::Docker;
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// Create a Docker network if it doesn't exist
pub async fn ensure_network(docker: &Docker, name: &str) -> Result<()> {
    // Check if network exists
    match docker
        .inspect_network(
            name,
            Some(InspectNetworkOptions {
                verbose: false,
                scope: Some("local".to_string()),
            }),
        )
        .await
    {
        Ok(_) => {
            debug!("Network {} already exists", name);
            return Ok(());
        }
        Err(bollard::errors::Error::DockerResponseServerError {
            status_code: 404, ..
        }) => {
            // Network doesn't exist, create it
        }
        Err(e) => {
            return Err(ExecutorError::Docker(e.to_string()));
        }
    }

    // Create network
    info!("Creating network: {}", name);
    let options = NetworkCreateRequest {
        name: name.to_string(),
        driver: Some("bridge".to_string()),
        labels: Some(HashMap::from([(
            "urt.managed".to_string(),
            "true".to_string(),
        )])),
        ..Default::default()
    };

    docker.create_network(options).await.map_err(|e| {
        warn!("Failed to create network {}: {}", name, e);
        ExecutorError::Docker(e.to_string())
    })?;

    info!("Created network: {}", name);
    Ok(())
}

/// Remove a Docker network
#[allow(dead_code)]
pub async fn remove_network(docker: &Docker, name: &str) -> Result<()> {
    info!("Removing network: {}", name);
    docker.remove_network(name).await.map_err(|e| {
        warn!("Failed to remove network {}: {}", name, e);
        ExecutorError::Docker(e.to_string())
    })?;
    Ok(())
}

/// Connect a container to a network
pub async fn connect_container(docker: &Docker, network: &str, container: &str) -> Result<()> {
    debug!("Connecting container {} to network {}", container, network);

    let config = NetworkConnectRequest {
        container: container.to_string(),
        endpoint_config: None,
    };

    match docker.connect_network(network, config).await {
        Ok(_) => {}
        Err(e) => {
            let message = e.to_string();
            if message.contains("No such container") {
                debug!(
                    "Container {} not found while connecting to network {} (non-fatal)",
                    container, network
                );
                return Err(ExecutorError::RuntimeNotFound);
            }
            if message.contains("already exists")
                || message.contains("already been joined")
                || message.contains("endpoint with name")
            {
                debug!(
                    "Container {} already attached to network {} (non-fatal)",
                    container, network
                );
                return Ok(());
            }
            warn!(
                "Failed to connect {} to {}: {}",
                container, network, message
            );
            return Err(ExecutorError::Docker(message));
        }
    }

    Ok(())
}
