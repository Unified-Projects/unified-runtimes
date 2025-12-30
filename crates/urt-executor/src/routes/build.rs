//! Build endpoint for building Docker images from source code

use super::AppState;
use crate::docker::build::{extract_source_tarball, BuildRequest};
use crate::error::{ExecutorError, Result};
use crate::storage::BuildCache;
use axum::{
    extract::{Multipart, Path, State},
    http::StatusCode,
    Json,
};
use serde::Serialize;
use std::collections::HashMap;
use tempfile::tempdir;
use tracing::{debug, info};

/// Response from a build request
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildResponse {
    /// The built image ID
    pub image_id: String,
    /// The image tag
    pub image_tag: String,
    /// Build duration in seconds
    pub duration_secs: f64,
    /// Whether cache was used
    pub cache_hit: bool,
    /// Build logs
    pub logs: Vec<String>,
}

/// POST /v1/runtimes/{runtime_id}/build - Build a runtime from source
///
/// Accepts multipart/form-data with the following fields:
/// - source: The source tarball (tar.gz or tar)
/// - dockerfile: (optional) Dockerfile content
/// - buildArgs: (optional) JSON object of build arguments
/// - cacheEnabled: (optional) Whether to enable layer caching (default: true)
pub async fn build_runtime(
    State(state): State<AppState>,
    Path(runtime_id): Path<String>,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<BuildResponse>)> {
    info!("Building runtime: {}", runtime_id);

    // Validate runtime_id
    if runtime_id.is_empty() || runtime_id.len() > 64 {
        return Err(ExecutorError::ExecutionBadRequest(
            "Invalid runtime ID".to_string(),
        ));
    }

    if !runtime_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ExecutorError::ExecutionBadRequest(
            "Runtime ID must contain only alphanumeric characters, dashes, or underscores"
                .to_string(),
        ));
    }

    // Parse multipart form
    let mut source_data: Option<Vec<u8>> = None;
    let mut dockerfile: Option<String> = None;
    let mut build_args: HashMap<String, String> = HashMap::new();
    let mut cache_enabled = true;

    while let Some(field) = multipart.next_field().await.map_err(|e| {
        ExecutorError::ExecutionBadRequest(format!("Failed to read multipart field: {}", e))
    })? {
        let name = field.name().unwrap_or("").to_string();

        match name.as_str() {
            "source" => {
                source_data = Some(
                    field
                        .bytes()
                        .await
                        .map_err(|e| {
                            ExecutorError::ExecutionBadRequest(format!(
                                "Failed to read source: {}",
                                e
                            ))
                        })?
                        .to_vec(),
                );
            }
            "dockerfile" => {
                dockerfile = Some(field.text().await.map_err(|e| {
                    ExecutorError::ExecutionBadRequest(format!("Failed to read dockerfile: {}", e))
                })?);
            }
            "buildArgs" => {
                let text = field.text().await.map_err(|e| {
                    ExecutorError::ExecutionBadRequest(format!("Failed to read buildArgs: {}", e))
                })?;
                build_args = serde_json::from_str(&text).map_err(|e| {
                    ExecutorError::ExecutionBadRequest(format!("Invalid buildArgs JSON: {}", e))
                })?;
            }
            "cacheEnabled" => {
                let text = field.text().await.map_err(|e| {
                    ExecutorError::ExecutionBadRequest(format!(
                        "Failed to read cacheEnabled: {}",
                        e
                    ))
                })?;
                cache_enabled = text.to_lowercase() != "false";
            }
            _ => {
                debug!("Ignoring unknown field: {}", name);
            }
        }
    }

    // Ensure we have source data
    let source_data = source_data.ok_or_else(|| {
        ExecutorError::ExecutionBadRequest("Missing 'source' field in multipart form".to_string())
    })?;

    // Create temp directory for build
    let build_dir = tempdir()
        .map_err(|e| ExecutorError::Storage(format!("Failed to create temp directory: {}", e)))?;

    // Extract source tarball
    extract_source_tarball(&source_data, build_dir.path()).await?;
    info!("Extracted source to {:?}", build_dir.path());

    // Build image tag
    let image_tag = format!("urt-{}:{}", runtime_id, chrono::Utc::now().timestamp());

    // Create build request
    let mut request = BuildRequest::new(&runtime_id, &image_tag).with_cache(cache_enabled);

    if let Some(df) = dockerfile {
        request = request.with_dockerfile(df);
    }

    for (key, value) in build_args {
        request = request.with_build_arg(&key, &value);
    }

    // Create build cache using the configured storage backend
    let build_cache = BuildCache::new(state.storage.clone(), "builds");

    // Build the image
    let result = state
        .docker
        .build_image(build_dir.path(), &request, Some(&build_cache))
        .await?;

    info!(
        "Built image {} in {:.2}s (cache_hit={})",
        result.image_tag, result.duration_secs, result.cache_hit
    );

    Ok((
        StatusCode::OK,
        Json(BuildResponse {
            image_id: result.image_id,
            image_tag: result.image_tag,
            duration_secs: result.duration_secs,
            cache_hit: result.cache_hit,
            logs: result.logs,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_response_serialization() {
        let response = BuildResponse {
            image_id: "sha256:abc123".to_string(),
            image_tag: "test:latest".to_string(),
            duration_secs: 10.5,
            cache_hit: false,
            logs: vec!["Step 1/3".to_string(), "Step 2/3".to_string()],
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("imageId"));
        assert!(json.contains("imageTag"));
        assert!(json.contains("durationSecs"));
        assert!(json.contains("cacheHit"));
    }
}
