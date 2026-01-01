//! Storage module for build artifacts
//!
//! Supports multiple storage backends:
//! - Local filesystem
//! - AWS S3
//! - DigitalOcean Spaces
//! - Backblaze B2
//! - Linode Object Storage
//! - Wasabi
//!
//! Also provides a local file cache for speeding up cold starts.

mod cache;
mod file_cache;
mod local;
mod s3;

use crate::config::{StorageConfig, StorageDevice};
use crate::error::Result;
use async_trait::async_trait;
pub use cache::BuildCache;
pub use file_cache::StorageFileCache;
pub use local::LocalStorage;
pub use s3::S3Storage;

/// Trait for storage backends
#[async_trait]
pub trait Storage: Send + Sync {
    /// Check if a file exists
    async fn exists(&self, path: &str) -> Result<bool>;

    /// Read a file
    async fn read(&self, path: &str) -> Result<Vec<u8>>;

    /// Write a file
    async fn write(&self, path: &str, data: &[u8]) -> Result<()>;

    /// Delete a file
    async fn delete(&self, path: &str) -> Result<()>;

    /// List files in a directory
    async fn list(&self, prefix: &str) -> Result<Vec<String>>;

    /// Get file size
    async fn size(&self, path: &str) -> Result<u64>;

    /// Transfer a file from this storage to local filesystem
    async fn download(&self, remote_path: &str, local_path: &str) -> Result<()>;

    /// Transfer a file from local filesystem to this storage
    async fn upload(&self, local_path: &str, remote_path: &str) -> Result<()>;
}

/// Implement Storage for Arc<dyn Storage> to allow cloning and sharing
#[async_trait]
impl Storage for std::sync::Arc<dyn Storage> {
    async fn exists(&self, path: &str) -> Result<bool> {
        (**self).exists(path).await
    }

    async fn read(&self, path: &str) -> Result<Vec<u8>> {
        (**self).read(path).await
    }

    async fn write(&self, path: &str, data: &[u8]) -> Result<()> {
        (**self).write(path, data).await
    }

    async fn delete(&self, path: &str) -> Result<()> {
        (**self).delete(path).await
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        (**self).list(prefix).await
    }

    async fn size(&self, path: &str) -> Result<u64> {
        (**self).size(path).await
    }

    async fn download(&self, remote_path: &str, local_path: &str) -> Result<()> {
        (**self).download(remote_path, local_path).await
    }

    async fn upload(&self, local_path: &str, remote_path: &str) -> Result<()> {
        (**self).upload(local_path, remote_path).await
    }
}

/// Parse a storage DSN and create the appropriate storage backend (legacy)
#[allow(dead_code)]
pub fn from_dsn(dsn: &str) -> Result<Box<dyn Storage>> {
    if dsn.starts_with("s3://") {
        Ok(Box::new(S3Storage::from_dsn(dsn)?))
    } else if dsn.starts_with("local://") {
        Ok(Box::new(LocalStorage::new()))
    } else {
        // Default to local
        Ok(Box::new(LocalStorage::new()))
    }
}

/// Create storage backend from StorageConfig (executor-main compatible)
/// Uses STORAGE_DEVICE and individual provider env vars
pub fn from_config(config: &StorageConfig) -> Result<Box<dyn Storage>> {
    match config.device {
        StorageDevice::Local => Ok(Box::new(LocalStorage::new())),
        StorageDevice::S3 => {
            let cfg = config
                .s3
                .as_ref()
                .ok_or_else(|| crate::error::ExecutorError::Storage(
                    "S3 storage selected but STORAGE_S3_ACCESS_KEY and STORAGE_S3_SECRET not configured".to_string()
                ))?;
            Ok(Box::new(S3Storage::new_s3(cfg)?))
        }
        StorageDevice::DoSpaces => {
            let cfg = config
                .do_spaces
                .as_ref()
                .ok_or_else(|| crate::error::ExecutorError::Storage(
                    "DO Spaces storage selected but STORAGE_DO_SPACES_ACCESS_KEY and STORAGE_DO_SPACES_SECRET not configured".to_string()
                ))?;
            Ok(Box::new(S3Storage::new_do_spaces(cfg)?))
        }
        StorageDevice::Backblaze => {
            let cfg = config
                .backblaze
                .as_ref()
                .ok_or_else(|| crate::error::ExecutorError::Storage(
                    "Backblaze storage selected but STORAGE_BACKBLAZE_ACCESS_KEY and STORAGE_BACKBLAZE_SECRET not configured".to_string()
                ))?;
            Ok(Box::new(S3Storage::new_backblaze(cfg)?))
        }
        StorageDevice::Linode => {
            let cfg = config
                .linode
                .as_ref()
                .ok_or_else(|| crate::error::ExecutorError::Storage(
                    "Linode storage selected but STORAGE_LINODE_ACCESS_KEY and STORAGE_LINODE_SECRET not configured".to_string()
                ))?;
            Ok(Box::new(S3Storage::new_linode(cfg)?))
        }
        StorageDevice::Wasabi => {
            let cfg = config
                .wasabi
                .as_ref()
                .ok_or_else(|| crate::error::ExecutorError::Storage(
                    "Wasabi storage selected but STORAGE_WASABI_ACCESS_KEY and STORAGE_WASABI_SECRET not configured".to_string()
                ))?;
            Ok(Box::new(S3Storage::new_wasabi(cfg)?))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_from_dsn_local() {
        let storage = from_dsn("local://localhost").unwrap();
        // Verify it works by checking a non-existent path
        let exists = storage.exists("/nonexistent/path/12345").await.unwrap();
        assert!(!exists);
    }

    #[tokio::test]
    async fn test_from_dsn_default() {
        // Unknown schemes should default to local
        let storage = from_dsn("unknown://something").unwrap();
        let exists = storage.exists("/nonexistent/path/12345").await.unwrap();
        assert!(!exists);
    }

    #[test]
    fn test_from_dsn_s3() {
        // S3 DSN should create S3Storage without error
        let result = from_dsn("s3://user:pass@localhost:9000/bucket");
        assert!(result.is_ok());
    }
}
