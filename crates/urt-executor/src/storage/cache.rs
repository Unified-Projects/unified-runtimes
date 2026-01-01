//! Build cache for incremental builds

use super::Storage;
use crate::docker::build::hash_files;
use crate::error::{ExecutorError, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::{debug, info, warn};

/// Build cache for layer caching and incremental builds
pub struct BuildCache<S: Storage> {
    storage: S,
    cache_prefix: String,
}

impl<S: Storage> BuildCache<S> {
    /// Create a new build cache
    pub fn new(storage: S, cache_prefix: &str) -> Self {
        Self {
            storage,
            cache_prefix: cache_prefix.to_string(),
        }
    }

    /// Calculate hash of dependency files
    ///
    /// This is a convenience wrapper around `hash_files` that accepts string paths.
    ///
    /// Note: Public for use in integration and e2e tests.
    #[doc(hidden)]
    pub async fn hash_deps(&self, dep_files: &[&str]) -> Result<String> {
        let paths: Vec<PathBuf> = dep_files.iter().map(PathBuf::from).collect();
        hash_files(&paths).await
    }

    /// Get cache key for a runtime and dependencies
    pub fn cache_key(&self, runtime: &str, deps_hash: &str) -> String {
        format!("{}/{}/{}", self.cache_prefix, runtime, deps_hash)
    }

    /// Check if cache exists for given key
    pub async fn has_cache(&self, key: &str) -> Result<bool> {
        self.storage.exists(&format!("{}/manifest.json", key)).await
    }

    /// Get cached layer paths
    pub async fn get_cached_layers(&self, key: &str) -> Result<Vec<String>> {
        let manifest_path = format!("{}/manifest.json", key);

        if !self.storage.exists(&manifest_path).await? {
            return Ok(Vec::new());
        }

        let manifest_data = self.storage.read(&manifest_path).await?;
        let manifest: HashMap<String, serde_json::Value> =
            serde_json::from_slice(&manifest_data)
                .map_err(|e| ExecutorError::Storage(format!("Invalid manifest: {}", e)))?;

        let layers = manifest
            .get("layers")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| format!("{}/{}", key, s)))
                    .collect()
            })
            .unwrap_or_default();

        Ok(layers)
    }

    /// Restore cached layers to build directory
    pub async fn restore_layers(&self, key: &str, build_dir: &str) -> Result<bool> {
        let layers = self.get_cached_layers(key).await?;

        if layers.is_empty() {
            debug!("No cached layers found for {}", key);
            return Ok(false);
        }

        info!("Restoring {} cached layers for {}", layers.len(), key);

        for layer_path in &layers {
            let layer_name = layer_path.rsplit('/').next().unwrap_or("layer");
            let local_path = format!("{}/{}", build_dir, layer_name);

            self.storage.download(layer_path, &local_path).await?;

            // Extract if it's a tarball
            if layer_name.ends_with(".tar.zst") || layer_name.ends_with(".tar.gz") {
                Self::extract_layer(&local_path, build_dir).await?;
                fs::remove_file(&local_path).await.ok();
            }
        }

        Ok(true)
    }

    /// Cache layers from build directory
    pub async fn cache_layers(
        &self,
        key: &str,
        build_dir: &str,
        layer_dirs: &[&str],
    ) -> Result<()> {
        info!("Caching {} layers for {}", layer_dirs.len(), key);

        let mut layer_names = Vec::new();

        for dir in layer_dirs {
            let full_path = format!("{}/{}", build_dir, dir);
            if !Path::new(&full_path).exists() {
                continue;
            }

            let layer_name = format!("{}.tar.zst", dir.replace('/', "_"));
            let layer_path = format!("/tmp/{}", layer_name);

            // Create compressed tarball
            Self::create_layer(&full_path, &layer_path).await?;

            // Upload to storage
            let remote_path = format!("{}/{}", key, layer_name);
            self.storage.upload(&layer_path, &remote_path).await?;

            // Cleanup temp file
            fs::remove_file(&layer_path).await.ok();

            layer_names.push(layer_name);
        }

        // Write manifest
        let manifest = serde_json::json!({
            "layers": layer_names,
            "created": chrono::Utc::now().to_rfc3339(),
        });

        let manifest_data = serde_json::to_vec(&manifest)
            .map_err(|e| ExecutorError::Storage(format!("Failed to serialize manifest: {}", e)))?;

        self.storage
            .write(&format!("{}/manifest.json", key), &manifest_data)
            .await?;

        Ok(())
    }

    /// Get total cache size in bytes
    pub async fn total_size(&self) -> Result<u64> {
        let entries = self.storage.list(&self.cache_prefix).await?;
        let mut total = 0u64;

        for entry in entries {
            match self.storage.size(&entry).await {
                Ok(size) => total += size,
                Err(e) => {
                    debug!("Failed to get size of {}: {}", entry, e);
                }
            }
        }

        Ok(total)
    }

    /// List all cached runtime IDs
    #[allow(dead_code)] // Public API for cache management
    pub async fn list_runtimes(&self) -> Result<Vec<String>> {
        let entries = self.storage.list(&self.cache_prefix).await?;

        // Extract unique runtime IDs from paths like "builds/runtime_id/hash/..."
        let mut runtimes: Vec<String> = entries
            .iter()
            .filter_map(|path| {
                let stripped = path
                    .strip_prefix(&self.cache_prefix)?
                    .trim_start_matches('/');
                stripped.split('/').next().map(|s| s.to_string())
            })
            .collect();

        runtimes.sort();
        runtimes.dedup();

        Ok(runtimes)
    }

    /// Delete cache for a specific runtime
    #[allow(dead_code)] // Public API for cache management
    pub async fn delete_runtime_cache(&self, runtime: &str) -> Result<u64> {
        let prefix = format!("{}/{}", self.cache_prefix, runtime);
        let entries = self.storage.list(&prefix).await?;
        let mut deleted = 0u64;

        for entry in entries {
            match self.storage.delete(&entry).await {
                Ok(()) => {
                    deleted += 1;
                    debug!("Deleted cache entry: {}", entry);
                }
                Err(e) => {
                    warn!("Failed to delete cache entry {}: {}", entry, e);
                }
            }
        }

        info!("Deleted {} cache entries for runtime {}", deleted, runtime);
        Ok(deleted)
    }

    /// Clean up old cache entries exceeding max size
    ///
    /// Deletes oldest entries first until cache size is below max_bytes.
    /// Returns number of entries deleted.
    pub async fn cleanup(&self, max_bytes: u64) -> Result<u64> {
        let current_size = self.total_size().await?;

        if current_size <= max_bytes {
            debug!(
                "Cache size {} bytes is within limit {} bytes",
                current_size, max_bytes
            );
            return Ok(0);
        }

        info!(
            "Cache size {} bytes exceeds limit {} bytes, cleaning up",
            current_size, max_bytes
        );

        let entries = self.storage.list(&self.cache_prefix).await?;

        // Group entries by manifest to delete entire cache entries atomically
        let mut manifests: Vec<String> = entries
            .iter()
            .filter(|e| e.ends_with("/manifest.json"))
            .cloned()
            .collect();

        // Sort by name (older entries tend to have older timestamps in their hash paths)
        manifests.sort();

        let mut deleted = 0u64;
        let mut freed_bytes = 0u64;

        for manifest in manifests {
            if current_size - freed_bytes <= max_bytes {
                break;
            }

            // Get the cache key directory from manifest path
            let cache_dir = manifest.trim_end_matches("/manifest.json");
            let dir_entries = self.storage.list(cache_dir).await.unwrap_or_default();

            for entry in dir_entries {
                if let Ok(size) = self.storage.size(&entry).await {
                    freed_bytes += size;
                }

                if let Err(e) = self.storage.delete(&entry).await {
                    warn!("Failed to delete {}: {}", entry, e);
                } else {
                    deleted += 1;
                }
            }
        }

        info!(
            "Cleaned up {} entries, freed {} bytes",
            deleted, freed_bytes
        );
        Ok(deleted)
    }

    /// Create a compressed layer tarball
    async fn create_layer(source_dir: &str, output_path: &str) -> Result<()> {
        use std::path::Path;
        use std::process::Command;

        // Validate and normalize source and output paths before invoking external tar.
        let source_path = Path::new(source_dir);
        if !source_path.is_dir() {
            return Err(ExecutorError::Storage(format!(
                "Source directory does not exist or is not a directory: {}",
                source_dir
            )));
        }

        let output_path_obj = Path::new(output_path);
        if let Some(parent) = output_path_obj.parent() {
            // Ensure parent directory exists; do not create it implicitly.
            if !parent.exists() {
                return Err(ExecutorError::Storage(format!(
                    "Output directory does not exist: {}",
                    parent.to_string_lossy()
                )));
            }
        }

        let output = Command::new("tar")
            .arg("--zstd")
            .arg("-cf")
            .arg(output_path_obj.to_string_lossy().to_string())
            .arg("-C")
            .arg(source_path.to_string_lossy().to_string())
            .arg(".")
            .output()
            .map_err(|e| ExecutorError::Storage(format!("Failed to create tar: {}", e)))?;

        if !output.status.success() {
            return Err(ExecutorError::Storage(format!(
                "tar failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(())
    }

    /// Extract a layer tarball
    async fn extract_layer(layer_path: &str, target_dir: &str) -> Result<()> {
        let layer_path_obj = std::path::Path::new(layer_path);
        if !layer_path_obj.is_file() {
            return Err(ExecutorError::Storage(format!(
                "Layer path does not exist or is not a file: {}",
                layer_path
            )));
        }
        let target_dir_path = std::path::Path::new(target_dir);
        // Ensure target directory exists and is a directory; do not follow arbitrary file paths.
        if !target_dir_path.exists() {
            fs::create_dir_all(target_dir_path).await.map_err(|e| {
                ExecutorError::Storage(format!("Failed to create target dir: {}", e))
            })?;
        }
        if !target_dir_path.is_dir() {
            return Err(ExecutorError::Storage(format!(
                "Target path is not a directory: {}",
                target_dir
            )));
        }

        use std::process::Command;

        let output = Command::new("tar")
            .arg("--zstd")
            .arg("-xf")
            .arg(layer_path_obj.to_string_lossy().to_string())
            .arg("-C")
            .arg(target_dir_path.to_string_lossy().to_string())
            .output()
            .map_err(|e| ExecutorError::Storage(format!("Failed to extract tar: {}", e)))?;

        if !output.status.success() {
            return Err(ExecutorError::Storage(format!(
                "tar extraction failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::LocalStorage;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_cache_key_format() {
        let storage = LocalStorage::new();
        let cache = BuildCache::new(storage, "builds");

        let key = cache.cache_key("node-22", "abc123");
        assert_eq!(key, "builds/node-22/abc123");
    }

    #[tokio::test]
    async fn test_has_cache_empty() {
        let dir = tempdir().unwrap();
        let storage = LocalStorage::with_base_path(dir.path().to_str().unwrap());
        let cache = BuildCache::new(storage, "test-cache");

        let has_cache = cache.has_cache("nonexistent/key").await.unwrap();
        assert!(!has_cache);
    }

    #[tokio::test]
    async fn test_get_cached_layers_empty() {
        let dir = tempdir().unwrap();
        let storage = LocalStorage::with_base_path(dir.path().to_str().unwrap());
        let cache = BuildCache::new(storage, "test-cache");

        let layers = cache.get_cached_layers("nonexistent/key").await.unwrap();
        assert!(layers.is_empty());
    }

    #[tokio::test]
    async fn test_cache_key_with_special_chars() {
        let storage = LocalStorage::new();
        let cache = BuildCache::new(storage, "builds");

        // Test with various characters
        let key = cache.cache_key("python-v3.12", "hash-with-dashes");
        assert!(key.starts_with("builds/python-v3.12/"));
    }

    #[tokio::test]
    async fn test_list_runtimes_empty() {
        let dir = tempdir().unwrap();
        let storage = LocalStorage::with_base_path(dir.path().to_str().unwrap());
        let cache = BuildCache::new(storage, "test-cache");

        let runtimes = cache.list_runtimes().await.unwrap();
        assert!(runtimes.is_empty());
    }

    #[tokio::test]
    async fn test_delete_runtime_cache_nonexistent() {
        let dir = tempdir().unwrap();
        let storage = LocalStorage::with_base_path(dir.path().to_str().unwrap());
        let cache = BuildCache::new(storage, "test-cache");

        let deleted = cache.delete_runtime_cache("nonexistent").await.unwrap();
        assert_eq!(deleted, 0);
    }

    #[tokio::test]
    async fn test_cleanup_empty_cache() {
        let dir = tempdir().unwrap();
        let storage = LocalStorage::with_base_path(dir.path().to_str().unwrap());
        let cache = BuildCache::new(storage, "test-cache");

        let cleaned = cache.cleanup(1024 * 1024).await.unwrap();
        assert_eq!(cleaned, 0);
    }

    #[tokio::test]
    async fn test_total_size_empty() {
        let dir = tempdir().unwrap();
        let storage = LocalStorage::with_base_path(dir.path().to_str().unwrap());
        let cache = BuildCache::new(storage, "test-cache");

        let size = cache.total_size().await.unwrap();
        assert_eq!(size, 0);
    }

    #[tokio::test]
    async fn test_manifest_write_and_read() {
        let dir = tempdir().unwrap();
        let storage = LocalStorage::with_base_path(dir.path().to_str().unwrap());
        let cache = BuildCache::new(storage.clone(), "test-cache");

        let key = "runtime-1/hash123";

        // Simulate writing a manifest (like cache_layers would do)
        let manifest = serde_json::json!({
            "layers": ["layer1.tar.zst", "layer2.tar.zst"],
            "created": "2024-01-01T00:00:00Z",
        });
        let manifest_data = serde_json::to_vec(&manifest).unwrap();
        storage
            .write(&format!("{}/manifest.json", key), &manifest_data)
            .await
            .unwrap();

        // Now test has_cache and get_cached_layers
        let has_cache = cache.has_cache(key).await.unwrap();
        assert!(has_cache);

        let layers = cache.get_cached_layers(key).await.unwrap();
        assert_eq!(layers.len(), 2);
        assert!(layers[0].contains("layer1.tar.zst"));
        assert!(layers[1].contains("layer2.tar.zst"));
    }
}
