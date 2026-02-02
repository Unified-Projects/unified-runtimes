//! Docker image build functionality
//!
//! This module handles building Docker images from source code and Dockerfiles,
//! with support for layer caching via the BuildCache.

use crate::error::{ExecutorError, Result};
use crate::storage::{BuildCache, Storage};
use bollard::query_parameters::BuildImageOptionsBuilder;
use bollard::Docker;
use bytes::Bytes;
use flate2::read::GzDecoder;
use futures_util::StreamExt;
use http_body_util::{Either, Full};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use tar::Archive;
use tokio::fs;
use tokio::io::AsyncReadExt;
use tracing::{debug, error, info};

/// Request to build a Docker image
#[derive(Debug, Clone)]
pub struct BuildRequest {
    /// Unique identifier for the build
    pub build_id: String,
    /// Docker image tag for the built image
    pub image_tag: String,
    /// Optional Dockerfile content (if not provided, looks for Dockerfile in source)
    pub dockerfile: Option<String>,
    /// Optional build arguments
    pub build_args: HashMap<String, String>,
    /// Enable layer caching
    pub cache_enabled: bool,
}

impl BuildRequest {
    pub fn new(build_id: &str, image_tag: &str) -> Self {
        Self {
            build_id: build_id.to_string(),
            image_tag: image_tag.to_string(),
            dockerfile: None,
            build_args: HashMap::new(),
            cache_enabled: true,
        }
    }

    pub fn with_dockerfile(mut self, dockerfile: String) -> Self {
        self.dockerfile = Some(dockerfile);
        self
    }

    pub fn with_build_arg(mut self, key: &str, value: &str) -> Self {
        self.build_args.insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_cache(mut self, enabled: bool) -> Self {
        self.cache_enabled = enabled;
        self
    }
}

/// Result of a Docker image build
#[derive(Debug, Clone)]
pub struct BuildResult {
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

/// Dependency file patterns for different runtimes
static DEP_FILE_PATTERNS: &[&str] = &[
    // Node.js
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    // Python
    "requirements.txt",
    "Pipfile",
    "Pipfile.lock",
    "pyproject.toml",
    "poetry.lock",
    // Rust
    "Cargo.toml",
    "Cargo.lock",
    // Go
    "go.mod",
    "go.sum",
    // Ruby
    "Gemfile",
    "Gemfile.lock",
    // PHP
    "composer.json",
    "composer.lock",
    // .NET
    "*.csproj",
    "*.fsproj",
    "packages.config",
    // Java/Kotlin
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    // Deno
    "deno.json",
    "deno.lock",
    // Bun
    "bun.lockb",
];

/// Cacheable layer directories for different runtimes
static CACHE_LAYER_DIRS: &[&str] = &[
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".pip",
    "target",
    "vendor",
    ".cargo",
    ".gradle",
    ".m2",
    "packages",
];

/// Build a Docker image from source code
pub async fn build_image<S: Storage>(
    docker: &Docker,
    source_dir: &Path,
    request: &BuildRequest,
    cache: Option<&BuildCache<S>>,
) -> Result<BuildResult> {
    let start_time = std::time::Instant::now();
    let mut logs = Vec::new();
    let mut cache_hit = false;

    info!("Building image {} from {:?}", request.image_tag, source_dir);

    // Detect dependency files
    let dep_files = detect_dependency_files(source_dir).await?;
    debug!("Found {} dependency files", dep_files.len());

    // Check cache if enabled
    if request.cache_enabled {
        if let Some(build_cache) = cache {
            let deps_hash = hash_files(&dep_files).await?;
            let cache_key = build_cache.cache_key(&request.build_id, &deps_hash);

            if build_cache.has_cache(&cache_key).await? {
                info!("Cache hit for {}", cache_key);
                logs.push(format!("Cache hit: {}", cache_key));

                // Restore cached layers
                let source_dir_str = source_dir.to_string_lossy();
                if build_cache
                    .restore_layers(&cache_key, &source_dir_str)
                    .await?
                {
                    cache_hit = true;
                    logs.push("Restored cached layers".to_string());
                }
            } else {
                debug!("Cache miss for {}", cache_key);
                logs.push(format!("Cache miss: {}", cache_key));
            }
        }
    }

    // Ensure Dockerfile exists
    let dockerfile_path = source_dir.join("Dockerfile");
    if let Some(ref dockerfile_content) = request.dockerfile {
        fs::write(&dockerfile_path, dockerfile_content)
            .await
            .map_err(|e| ExecutorError::Storage(format!("Failed to write Dockerfile: {}", e)))?;
        logs.push("Using provided Dockerfile".to_string());
    } else if !dockerfile_path.exists() {
        return Err(ExecutorError::ExecutionBadRequest(
            "No Dockerfile provided or found in source".to_string(),
        ));
    }

    // Create build context tarball
    let context_tar = create_build_context(source_dir).await?;
    logs.push(format!(
        "Created build context: {} bytes",
        context_tar.len()
    ));

    // Build the image using the new builder API
    let build_options = BuildImageOptionsBuilder::default()
        .t(&request.image_tag)
        .dockerfile("Dockerfile")
        .rm(true)
        .forcerm(true)
        .build();

    // Stream build output - wrap in Either::Left(Full) for bollard
    let body = Either::Left(Full::new(Bytes::from(context_tar)));
    let mut stream = docker.build_image(build_options, None, Some(body));

    let mut image_id = String::new();

    while let Some(result) = stream.next().await {
        match result {
            Ok(info) => {
                if let Some(stream_msg) = info.stream {
                    let msg = stream_msg.trim();
                    if !msg.is_empty() {
                        debug!("Build: {}", msg);
                        logs.push(msg.to_string());
                    }
                }
                if let Some(aux) = info.aux {
                    if let Some(id) = aux.id {
                        image_id = id;
                    }
                }
                if let Some(error_msg) = info.error {
                    error!("Build error: {}", error_msg);
                    return Err(ExecutorError::RuntimeFailed(format!(
                        "Build failed: {}",
                        error_msg
                    )));
                }
            }
            Err(e) => {
                error!("Build stream error: {}", e);
                return Err(ExecutorError::Docker(format!("Build failed: {}", e)));
            }
        }
    }

    // Cache layers if build succeeded and cache is enabled
    if request.cache_enabled && !cache_hit {
        if let Some(build_cache) = cache {
            let deps_hash = hash_files(&dep_files).await?;
            let cache_key = build_cache.cache_key(&request.build_id, &deps_hash);

            // Find and cache layer directories
            let layer_dirs: Vec<&str> = CACHE_LAYER_DIRS
                .iter()
                .filter(|dir| source_dir.join(dir).exists())
                .copied()
                .collect();

            if !layer_dirs.is_empty() {
                let source_dir_str = source_dir.to_string_lossy();
                match build_cache
                    .cache_layers(&cache_key, &source_dir_str, &layer_dirs)
                    .await
                {
                    Ok(_) => {
                        info!("Cached {} layers for {}", layer_dirs.len(), cache_key);
                        logs.push(format!("Cached {} layers", layer_dirs.len()));
                    }
                    Err(e) => {
                        // Non-fatal error - log but continue
                        error!("Failed to cache layers: {}", e);
                    }
                }
            }
        }
    }

    let duration = start_time.elapsed().as_secs_f64();
    info!(
        "Built image {} in {:.2}s (cache_hit={})",
        request.image_tag, duration, cache_hit
    );

    Ok(BuildResult {
        image_id,
        image_tag: request.image_tag.clone(),
        duration_secs: duration,
        cache_hit,
        logs,
    })
}

/// Detect dependency files in a directory
pub async fn detect_dependency_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut dep_files = Vec::new();

    for pattern in DEP_FILE_PATTERNS {
        if pattern.contains('*') {
            // Handle glob patterns
            let base_pattern = pattern.trim_start_matches('*');
            let mut entries = match fs::read_dir(dir).await {
                Ok(entries) => entries,
                Err(_) => continue,
            };

            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.ends_with(base_pattern) {
                        dep_files.push(path);
                    }
                }
            }
        } else {
            let path = dir.join(pattern);
            if path.exists() {
                dep_files.push(path);
            }
        }
    }

    Ok(dep_files)
}

/// Hash a list of files to create a cache key
pub async fn hash_files(files: &[PathBuf]) -> Result<String> {
    let mut hasher = Sha256::new();

    for file in files {
        if file.exists() {
            let mut f = fs::File::open(file)
                .await
                .map_err(|e| ExecutorError::Storage(format!("Failed to open {:?}: {}", file, e)))?;

            let mut contents = Vec::new();
            f.read_to_end(&mut contents)
                .await
                .map_err(|e| ExecutorError::Storage(format!("Failed to read {:?}: {}", file, e)))?;

            hasher.update(&contents);
        }
    }

    let hash = hasher.finalize();
    Ok(hex::encode(hash))
}

/// Create a build context tarball from a directory
async fn create_build_context(source_dir: &Path) -> Result<Vec<u8>> {
    use tar::Builder;

    let mut tar_bytes = Vec::new();
    {
        let mut builder = Builder::new(&mut tar_bytes);

        // Walk directory and add files
        add_dir_to_tar(&mut builder, source_dir, Path::new(""))?;

        builder
            .finish()
            .map_err(|e| ExecutorError::Storage(format!("Failed to finish tar: {}", e)))?;
    }

    Ok(tar_bytes)
}

/// Recursively add directory contents to a tar archive
fn add_dir_to_tar<W: std::io::Write>(
    builder: &mut tar::Builder<W>,
    source_dir: &Path,
    prefix: &Path,
) -> Result<()> {
    let entries = std::fs::read_dir(source_dir)
        .map_err(|e| ExecutorError::Storage(format!("Failed to read dir: {}", e)))?;

    for entry in entries {
        let entry =
            entry.map_err(|e| ExecutorError::Storage(format!("Failed to read entry: {}", e)))?;
        let path = entry.path();
        let name = path.file_name().unwrap_or_default();
        let target_path = prefix.join(name);

        if path.is_dir() {
            // Skip common ignorable directories
            let name_str = name.to_str().unwrap_or("");
            if name_str == ".git" || name_str == ".svn" || name_str == ".hg" {
                continue;
            }

            add_dir_to_tar(builder, &path, &target_path)?;
        } else if path.is_file() {
            builder
                .append_path_with_name(&path, &target_path)
                .map_err(|e| ExecutorError::Storage(format!("Failed to add file to tar: {}", e)))?;
        }
    }

    Ok(())
}

/// Extract a source tarball to a directory
pub async fn extract_source_tarball(tarball: &[u8], dest_dir: &Path) -> Result<()> {
    // Ensure destination exists
    fs::create_dir_all(dest_dir)
        .await
        .map_err(|e| ExecutorError::Storage(format!("Failed to create dest dir: {}", e)))?;

    fn ignore_permission_error(err: &io::Error) -> bool {
        err.kind() == io::ErrorKind::PermissionDenied
            && err.to_string().starts_with("failed to set permissions to")
    }

    fn unpack_archive<R: io::Read>(mut archive: Archive<R>, dest_dir: &Path) -> Result<()> {
        let entries = archive
            .entries()
            .map_err(|e| ExecutorError::Storage(format!("Failed to read tar entries: {}", e)))?;

        for entry in entries {
            let mut entry = entry
                .map_err(|e| ExecutorError::Storage(format!("Failed to read tar entry: {}", e)))?;
            if let Err(err) = entry.unpack_in(dest_dir) {
                if ignore_permission_error(&err) {
                    debug!("Ignoring tar permission error during extract: {}", err);
                    continue;
                }
                return Err(ExecutorError::Storage(format!(
                    "Failed to extract tar entry: {}",
                    err
                )));
            }
        }

        Ok(())
    }

    // Try gzip first, then plain tar
    if tarball.starts_with(&[0x1f, 0x8b]) {
        // gzip magic bytes
        let decoder = GzDecoder::new(tarball);
        unpack_archive(Archive::new(decoder), dest_dir)?;
    } else {
        // Plain tar
        unpack_archive(Archive::new(tarball), dest_dir)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_detect_dependency_files() {
        let dir = tempdir().unwrap();
        let dir_path = dir.path();

        // Create some dependency files
        std::fs::write(dir_path.join("package.json"), "{}").unwrap();
        std::fs::write(dir_path.join("requirements.txt"), "flask").unwrap();
        std::fs::write(dir_path.join("random.txt"), "data").unwrap();

        let deps = detect_dependency_files(dir_path).await.unwrap();

        assert_eq!(deps.len(), 2);
        assert!(deps.iter().any(|p| p.ends_with("package.json")));
        assert!(deps.iter().any(|p| p.ends_with("requirements.txt")));
    }

    #[tokio::test]
    async fn test_hash_files() {
        let dir = tempdir().unwrap();
        let dir_path = dir.path();

        let file1 = dir_path.join("file1.txt");
        let file2 = dir_path.join("file2.txt");

        std::fs::write(&file1, "hello").unwrap();
        std::fs::write(&file2, "world").unwrap();

        let hash1 = hash_files(&[file1.clone(), file2.clone()]).await.unwrap();
        let hash2 = hash_files(&[file1.clone(), file2.clone()]).await.unwrap();

        // Same files should produce same hash
        assert_eq!(hash1, hash2);

        // Different content should produce different hash
        std::fs::write(&file1, "changed").unwrap();
        let hash3 = hash_files(&[file1, file2]).await.unwrap();
        assert_ne!(hash1, hash3);
    }

    #[tokio::test]
    async fn test_extract_source_tarball() {
        let dir = tempdir().unwrap();
        let source_dir = dir.path().join("source");
        let dest_dir = dir.path().join("dest");

        std::fs::create_dir_all(&source_dir).unwrap();
        std::fs::write(source_dir.join("test.txt"), "test content").unwrap();

        // Create tarball
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            builder
                .append_path_with_name(source_dir.join("test.txt"), "test.txt")
                .unwrap();
            builder.finish().unwrap();
        }

        // Extract
        extract_source_tarball(&tar_bytes, &dest_dir).await.unwrap();

        // Verify
        let content = std::fs::read_to_string(dest_dir.join("test.txt")).unwrap();
        assert_eq!(content, "test content");
    }

    #[test]
    fn test_build_request_builder() {
        let req = BuildRequest::new("test-build", "test:latest")
            .with_dockerfile("FROM alpine".to_string())
            .with_build_arg("VERSION", "1.0")
            .with_cache(false);

        assert_eq!(req.build_id, "test-build");
        assert_eq!(req.image_tag, "test:latest");
        assert!(req.dockerfile.is_some());
        assert_eq!(req.build_args.get("VERSION"), Some(&"1.0".to_string()));
        assert!(!req.cache_enabled);
    }
}
