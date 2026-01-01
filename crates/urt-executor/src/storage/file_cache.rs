//! Local file cache for storage downloads
//!
//! This module provides a local file cache that speeds up cold starts by
//! caching downloaded artifacts locally. Cache entries expire after a
//! configurable TTL (default: 30 days).
//!
//! Cache structure:
//!   /tmp/urt-storage-cache/
//!     ab/abc123def456...  (cached file, named by SHA256 of remote path)
//!     ab/abc123def456.meta (metadata with expiry timestamp)
//!
//! Features:
//! - TTL-based expiry (default 30 days)
//! - Automatic cleanup of expired files
//! - Shutdown cleanup to remove all cached files
//! - Thread-safe with async support

use crate::error::{ExecutorError, Result};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use tokio::fs::{self, File};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, warn};

/// Default cache TTL: 30 days
pub const DEFAULT_CACHE_TTL_DAYS: u64 = 30;

/// Default max cache size: 1 GB
pub const DEFAULT_MAX_CACHE_SIZE: u64 = 1024 * 1024 * 1024;

/// Cache directory name
const CACHE_DIR: &str = "urt-storage-cache";

/// Metadata file extension
const META_EXT: &str = ".meta";

/// Local file cache for storage downloads
#[derive(Clone)]
pub struct StorageFileCache {
    /// Base cache directory (public for logging/debugging)
    pub cache_dir: PathBuf,
    /// Default TTL for cache entries
    ttl: Duration,
    /// Maximum cache size in bytes
    max_size: u64,
}

impl StorageFileCache {
    /// Create a new storage file cache
    ///
    /// # Arguments
    /// * `cache_dir` - Base directory for cache (defaults to /tmp)
    /// * `ttl` - Time-to-live for cache entries (defaults to 30 days)
    /// * `max_size` - Maximum cache size in bytes (defaults to 1GB)
    pub fn new(cache_dir: Option<&str>, ttl: Option<Duration>, max_size: Option<u64>) -> Self {
        let cache_dir = PathBuf::from(cache_dir.unwrap_or("/tmp")).join(CACHE_DIR);

        Self {
            cache_dir,
            ttl: ttl.unwrap_or(Duration::from_secs(DEFAULT_CACHE_TTL_DAYS * 24 * 60 * 60)),
            max_size: max_size.unwrap_or(DEFAULT_MAX_CACHE_SIZE),
        }
    }

    /// Initialize the cache directory
    pub async fn initialize(&self) -> Result<()> {
        if !self.cache_dir.exists() {
            fs::create_dir_all(&self.cache_dir).await.map_err(|e| {
                ExecutorError::Storage(format!("Failed to create cache directory: {}", e))
            })?;
            info!(
                "Created storage cache directory: {}",
                self.cache_dir.display()
            );
        }
        Ok(())
    }

    /// Get the cache key (first 2 chars of SHA256 hash) for sharding
    fn get_cache_key(remote_path: &str) -> String {
        let hash = Sha256::digest(remote_path.as_bytes());
        let hash_hex = hex::encode(hash);
        // Use first 2 chars for sharding (creates 256 buckets)
        hash_hex[..2].to_string()
    }

    /// Get the full cache file path for a remote path
    pub(crate) fn get_cache_path(&self, remote_path: &str) -> (PathBuf, PathBuf) {
        let key = Self::get_cache_key(remote_path);
        let hash = Sha256::digest(remote_path.as_bytes());
        let hash_hex = hex::encode(hash);

        let cache_file = self.cache_dir.join(&key).join(&hash_hex);
        let meta_file = self
            .cache_dir
            .join(&key)
            .join(&hash_hex)
            .with_extension(META_EXT);

        (cache_file, meta_file)
    }

    /// Check if a cached file exists and is valid (not expired)
    pub async fn exists(&self, remote_path: &str) -> bool {
        let (cache_file, meta_file) = self.get_cache_path(remote_path);

        if !cache_file.exists() {
            return false;
        }

        // Check metadata for expiry
        if let Ok(meta) = self.read_metadata(&meta_file).await {
            if self.is_expired(&meta.created) {
                // File is expired, clean it up
                let _ = self.remove(remote_path).await;
                return false;
            }
            return true;
        }

        // No valid metadata, assume expired
        false
    }

    /// Check if a timestamp is expired based on TTL
    fn is_expired(&self, created: &SystemTime) -> bool {
        match created.elapsed() {
            Ok(elapsed) => elapsed > self.ttl,
            Err(_) => true, // If time went backwards, consider expired
        }
    }

    /// Read metadata from file
    async fn read_metadata(&self, path: &Path) -> Result<CacheMetadata> {
        let mut file = File::open(path)
            .await
            .map_err(|e| ExecutorError::Storage(format!("Failed to open cache metadata: {}", e)))?;

        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .await
            .map_err(|e| ExecutorError::Storage(format!("Failed to read cache metadata: {}", e)))?;

        serde_json::from_str(&contents)
            .map_err(|e| ExecutorError::Storage(format!("Invalid cache metadata format: {}", e)))
    }

    /// Write metadata to file
    pub(crate) async fn write_metadata(&self, path: &Path, meta: &CacheMetadata) -> Result<()> {
        let mut file = File::create(path).await.map_err(|e| {
            ExecutorError::Storage(format!("Failed to create cache metadata: {}", e))
        })?;

        let contents = serde_json::to_string(meta).map_err(|e| {
            ExecutorError::Storage(format!("Failed to serialize cache metadata: {}", e))
        })?;

        file.write_all(contents.as_bytes()).await.map_err(|e| {
            ExecutorError::Storage(format!("Failed to write cache metadata: {}", e))
        })?;

        Ok(())
    }

    /// Get the local path for a cached file, downloading if necessary
    ///
    /// # Arguments
    /// * `remote_path` - The remote S3 path
    /// * `fetch_fn` - Async function to fetch the file content from remote
    ///
    /// Returns the local path to the cached file
    #[allow(dead_code)]
    pub async fn get_or_fetch<F, Fut>(&self, remote_path: &str, fetch_fn: F) -> Result<PathBuf>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<Vec<u8>>>,
    {
        // Check if already cached
        if self.exists(remote_path).await {
            let (cache_file, _) = self.get_cache_path(remote_path);
            debug!("Cache hit for: {}", remote_path);
            return Ok(cache_file);
        }

        // Cache miss - fetch from remote
        debug!("Cache miss for: {}, fetching from remote", remote_path);
        let data = fetch_fn().await?;

        // Write to cache
        self.put(remote_path, &data).await?;

        let (cache_file, _) = self.get_cache_path(remote_path);
        Ok(cache_file)
    }

    /// Store data in the cache
    pub async fn put(&self, remote_path: &str, data: &[u8]) -> Result<()> {
        let (cache_file, meta_file) = self.get_cache_path(remote_path);

        // Ensure parent directory exists
        if let Some(parent) = cache_file.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent).await.map_err(|e| {
                    ExecutorError::Storage(format!("Failed to create cache directory: {}", e))
                })?;
            }
        }

        // Write data file
        let mut file = File::create(&cache_file)
            .await
            .map_err(|e| ExecutorError::Storage(format!("Failed to create cache file: {}", e)))?;

        file.write_all(data)
            .await
            .map_err(|e| ExecutorError::Storage(format!("Failed to write cache file: {}", e)))?;

        // Write metadata
        let meta = CacheMetadata {
            remote_path: remote_path.to_string(),
            created: SystemTime::now(),
            size: data.len() as u64,
        };

        self.write_metadata(&meta_file, &meta).await?;

        // Check cache size and cleanup if necessary
        self.maybe_cleanup().await?;

        Ok(())
    }

    /// Remove a file from the cache
    pub async fn remove(&self, remote_path: &str) -> Result<()> {
        let (cache_file, meta_file) = self.get_cache_path(remote_path);

        if cache_file.exists() {
            fs::remove_file(&cache_file).await.map_err(|e| {
                ExecutorError::Storage(format!("Failed to remove cache file: {}", e))
            })?;
        }

        if meta_file.exists() {
            fs::remove_file(&meta_file).await.ok();
        }

        Ok(())
    }

    /// Get the current cache size
    pub async fn size(&self) -> Result<u64> {
        let mut total = 0u64;
        let mut stack = Vec::new();

        if self.cache_dir.exists() {
            stack.push(self.cache_dir.clone());

            while let Some(dir) = stack.pop() {
                if let Ok(mut entries) = fs::read_dir(&dir).await {
                    while let Some(entry) = entries.next_entry().await.ok().flatten() {
                        let path = entry.path();
                        if path.is_dir() {
                            stack.push(path);
                        } else if path.is_file() {
                            if let Ok(metadata) = fs::metadata(&path).await {
                                total += metadata.len();
                            }
                        }
                    }
                }
            }
        }

        Ok(total)
    }

    /// Clean up expired cache entries
    pub async fn cleanup_expired(&self) -> Result<u64> {
        let mut cleaned = 0u64;

        if !self.cache_dir.exists() {
            return Ok(0);
        }

        let mut stack = Vec::new();
        stack.push(self.cache_dir.clone());

        while let Some(dir) = stack.pop() {
            if let Ok(mut entries) = fs::read_dir(&dir).await {
                while let Some(entry) = entries.next_entry().await.ok().flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        stack.push(path);
                    } else if path.is_file() && !path.to_string_lossy().ends_with(META_EXT) {
                        let meta_path = path.with_extension(META_EXT);
                        if let Ok(meta) = self.read_metadata(&meta_path).await {
                            if self.is_expired(&meta.created) {
                                // Remove expired file and metadata
                                if let Err(e) = fs::remove_file(&path).await {
                                    warn!(
                                        "Failed to remove expired cache file {}: {}",
                                        path.display(),
                                        e
                                    );
                                } else {
                                    cleaned += 1;
                                }
                                let _ = fs::remove_file(&meta_path).await;
                            }
                        }
                    }
                }
            }
        }

        if cleaned > 0 {
            info!("Cleaned up {} expired cache entries", cleaned);
        }

        Ok(cleaned)
    }

    /// Clean up cache if it exceeds max size
    async fn maybe_cleanup(&self) -> Result<()> {
        let current_size = self.size().await?;

        if current_size > self.max_size {
            warn!(
                "Cache size {} bytes exceeds limit {} bytes, cleaning up",
                current_size, self.max_size
            );

            // Clean up expired entries first
            self.cleanup_expired().await?;

            // If still over limit, remove oldest entries
            let new_size = self.size().await?;
            if new_size > self.max_size {
                self.evict_oldest().await?;
            }
        }

        Ok(())
    }

    /// Evict oldest entries until cache is under limit
    async fn evict_oldest(&self) -> Result<u64> {
        let mut entries: Vec<(PathBuf, SystemTime)> = Vec::new();

        // Collect all entries with their creation times using iterative traversal
        let mut stack = Vec::new();
        if self.cache_dir.exists() {
            stack.push(self.cache_dir.clone());

            while let Some(dir) = stack.pop() {
                if let Ok(mut read_dir) = fs::read_dir(&dir).await {
                    while let Some(entry) = read_dir.next_entry().await.ok().flatten() {
                        let path = entry.path();
                        if path.is_dir() {
                            stack.push(path);
                        } else if path.is_file() && !path.to_string_lossy().ends_with(META_EXT) {
                            let meta_path = path.with_extension(META_EXT);
                            if let Ok(meta) = self.read_metadata(&meta_path).await {
                                entries.push((path, meta.created));
                            }
                        }
                    }
                }
            }
        }

        // Sort by creation time (oldest first)
        entries.sort_by_key(|(_, created)| *created);

        let mut evicted = 0u64;
        let target_size = self.max_size / 2; // Target 50% of max after cleanup

        for (path, _) in entries {
            if self.size().await? <= target_size {
                break;
            }

            if let Err(e) = fs::remove_file(&path).await {
                warn!("Failed to evict cache file {}: {}", path.display(), e);
            } else {
                evicted += 1;
            }

            // Also remove metadata
            let meta_path = path.with_extension(META_EXT);
            let _ = fs::remove_file(&meta_path).await;
        }

        if evicted > 0 {
            info!("Evicted {} oldest cache entries", evicted);
        }

        Ok(evicted)
    }

    /// Clean up all cache entries (called on shutdown)
    pub async fn cleanup_all(&self) -> Result<u64> {
        if !self.cache_dir.exists() {
            return Ok(0);
        }

        let mut removed = 0u64;
        let mut dirs_to_remove: Vec<PathBuf> = Vec::new();

        // First pass: collect all subdirectories and remove all files
        let mut stack = Vec::new();
        stack.push(self.cache_dir.clone());

        while let Some(dir) = stack.pop() {
            if let Ok(mut entries) = fs::read_dir(&dir).await {
                while let Some(entry) = entries.next_entry().await.ok().flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        stack.push(path.clone());
                        dirs_to_remove.push(path);
                    } else if let Err(e) = fs::remove_file(&path).await {
                        warn!("Failed to remove {}: {}", path.display(), e);
                    } else {
                        removed += 1;
                    }
                }
            }
        }

        // Remove subdirectories (in reverse order to remove children before parents)
        dirs_to_remove.sort_by_key(|p| std::cmp::Reverse(p.clone()));
        for dir in dirs_to_remove {
            if let Err(e) = fs::remove_dir(&dir).await {
                warn!("Failed to remove directory {}: {}", dir.display(), e);
            }
        }

        // Remove cache directory
        if self.cache_dir.exists() {
            if let Err(e) = fs::remove_dir(&self.cache_dir).await {
                warn!(
                    "Failed to remove cache directory {}: {}",
                    self.cache_dir.display(),
                    e
                );
            }
        }

        info!("Cleaned up {} cache entries on shutdown", removed);
        Ok(removed)
    }

    /// Get cache statistics
    #[allow(dead_code)]
    pub async fn stats(&self) -> CacheStats {
        let mut stats = CacheStats {
            entry_count: 0,
            total_size: 0,
            expired_count: 0,
            cache_dir: self.cache_dir.clone(),
        };

        if !self.cache_dir.exists() {
            return stats;
        }

        let mut stack = Vec::new();
        stack.push(self.cache_dir.clone());

        while let Some(dir) = stack.pop() {
            if let Ok(mut entries) = fs::read_dir(&dir).await {
                while let Some(entry) = entries.next_entry().await.ok().flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        stack.push(path);
                    } else if path.is_file() && !path.to_string_lossy().ends_with(META_EXT) {
                        stats.entry_count += 1;

                        if let Ok(metadata) = fs::metadata(&path).await {
                            stats.total_size += metadata.len();
                        }

                        let meta_path = path.with_extension(META_EXT);
                        if let Ok(meta) = self.read_metadata(&meta_path).await {
                            if self.is_expired(&meta.created) {
                                stats.expired_count += 1;
                            }
                        }
                    }
                }
            }
        }

        stats
    }
}

/// Cache metadata stored alongside each cached file
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct CacheMetadata {
    pub remote_path: String,
    pub created: SystemTime,
    pub size: u64,
}

/// Statistics about the cache
#[derive(Debug)]
#[allow(dead_code)]
pub struct CacheStats {
    pub entry_count: u64,
    pub total_size: u64,
    pub expired_count: u64,
    pub cache_dir: PathBuf,
}

impl std::fmt::Display for CacheStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Cache stats: {} entries, {} bytes total, {} expired",
            self.entry_count, self.total_size, self.expired_count
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_cache_key_generation() {
        let _cache = StorageFileCache::new(None, None, None);

        // Same path should produce same key
        let key1 = StorageFileCache::get_cache_key("builds/func.tar.gz");
        let key2 = StorageFileCache::get_cache_key("builds/func.tar.gz");
        assert_eq!(key1, key2);

        // Different paths should produce different keys (with high probability)
        let key3 = StorageFileCache::get_cache_key("other/func.tar.gz");
        assert_ne!(key1, key3);

        // Key should be 2 characters
        assert_eq!(key1.len(), 2);
    }

    #[tokio::test]
    async fn test_cache_put_and_exists() {
        let dir = tempdir().unwrap();
        let cache_dir = dir.path().to_str().unwrap().to_string();

        let cache = StorageFileCache::new(
            Some(&cache_dir),
            Some(Duration::from_secs(60)), // 1 minute TTL
            Some(1024 * 1024),
        );
        cache.initialize().await.unwrap();

        let remote_path = "test/artifact.tar.gz";
        let data = b"test data content";

        // Should not exist initially
        assert!(!cache.exists(remote_path).await);

        // Put data in cache
        cache.put(remote_path, data).await.unwrap();

        // Should exist now
        assert!(cache.exists(remote_path).await);
    }

    #[tokio::test]
    async fn test_cache_expiry() {
        let dir = tempdir().unwrap();
        let cache_dir = dir.path().to_str().unwrap().to_string();

        let cache = StorageFileCache::new(
            Some(&cache_dir),
            Some(Duration::from_millis(10)), // Very short TTL
            Some(1024 * 1024),
        );
        cache.initialize().await.unwrap();

        let remote_path = "test/expired.tar.gz";
        let data = b"this will expire";

        // Put data
        cache.put(remote_path, data).await.unwrap();
        assert!(cache.exists(remote_path).await);

        // Wait for expiry
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Should be expired now
        assert!(!cache.exists(remote_path).await);
    }

    #[tokio::test]
    async fn test_cache_cleanup_all() {
        let dir = tempdir().unwrap();
        let cache_dir = dir.path().to_str().unwrap().to_string();

        let cache = StorageFileCache::new(
            Some(&cache_dir),
            Some(Duration::from_secs(3600)),
            Some(1024 * 1024),
        );
        cache.initialize().await.unwrap();

        // Add some files
        for i in 0..5 {
            cache
                .put(
                    &format!("test/{}.tar.gz", i),
                    format!("data {}", i).as_bytes(),
                )
                .await
                .unwrap();
        }

        // Verify files exist by checking stats
        let stats_before = cache.stats().await;
        assert_eq!(
            stats_before.entry_count, 5,
            "Expected 5 entries before cleanup"
        );

        // Cleanup all
        let removed = cache.cleanup_all().await.unwrap();
        assert_eq!(removed, 10, "Should remove 5 data files + 5 metadata files");

        // Cache dir should be gone
        assert!(!cache.cache_dir.exists());
    }

    #[tokio::test]
    async fn test_cache_stats() {
        let dir = tempdir().unwrap();
        let cache_dir = dir.path().to_str().unwrap().to_string();

        let cache = StorageFileCache::new(
            Some(&cache_dir),
            Some(Duration::from_secs(3600)),
            Some(1024 * 1024),
        );
        cache.initialize().await.unwrap();

        // Add files
        cache.put("valid/file1.tar.gz", b"data1").await.unwrap();
        cache.put("expired/file2.tar.gz", b"data2").await.unwrap();

        // Check stats immediately - both should exist
        let stats = cache.stats().await;
        assert_eq!(stats.entry_count, 2, "Should have 2 entries");
        assert!(stats.total_size > 0, "Should have non-zero size");
        assert_eq!(stats.expired_count, 0, "No entries should be expired yet");
    }
}
