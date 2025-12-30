//! Storage module for build artifacts

mod cache;
mod local;
mod s3;

use crate::error::Result;
use async_trait::async_trait;
pub use cache::BuildCache;
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

/// Parse a storage DSN and create the appropriate storage backend
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
