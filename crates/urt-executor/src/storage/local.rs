//! Local filesystem storage

use super::Storage;
use crate::error::{ExecutorError, Result};
use async_trait::async_trait;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::path::Path;
use tar::Builder;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Local filesystem storage backend
#[derive(Debug, Clone, Default)]
pub struct LocalStorage {
    base_path: String,
}

impl LocalStorage {
    /// Create a new local storage with default base path
    pub fn new() -> Self {
        Self {
            base_path: "/tmp".to_string(),
        }
    }

    /// Create a new local storage with a specific base path
    #[allow(dead_code)] // Used in tests
    pub fn with_base_path(base_path: &str) -> Self {
        Self {
            base_path: base_path.to_string(),
        }
    }

    fn full_path(&self, path: &str) -> String {
        if path.starts_with('/') {
            path.to_string()
        } else {
            format!("{}/{}", self.base_path, path)
        }
    }
}

#[async_trait]
impl Storage for LocalStorage {
    async fn exists(&self, path: &str) -> Result<bool> {
        let full_path = self.full_path(path);
        Ok(Path::new(&full_path).exists())
    }

    async fn read(&self, path: &str) -> Result<Vec<u8>> {
        let full_path = self.full_path(path);
        let mut file = fs::File::open(&full_path)
            .await
            .map_err(|e| ExecutorError::Storage(format!("Failed to open {}: {}", full_path, e)))?;

        let mut contents = Vec::new();
        file.read_to_end(&mut contents)
            .await
            .map_err(|e| ExecutorError::Storage(format!("Failed to read {}: {}", full_path, e)))?;

        Ok(contents)
    }

    async fn write(&self, path: &str, data: &[u8]) -> Result<()> {
        let full_path = self.full_path(path);

        // Ensure parent directory exists
        if let Some(parent) = Path::new(&full_path).parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| ExecutorError::Storage(format!("Failed to create dir: {}", e)))?;
        }

        let mut file = fs::File::create(&full_path).await.map_err(|e| {
            ExecutorError::Storage(format!("Failed to create {}: {}", full_path, e))
        })?;

        file.write_all(data)
            .await
            .map_err(|e| ExecutorError::Storage(format!("Failed to write {}: {}", full_path, e)))?;

        Ok(())
    }

    async fn delete(&self, path: &str) -> Result<()> {
        let full_path = self.full_path(path);

        if Path::new(&full_path).is_dir() {
            fs::remove_dir_all(&full_path).await.map_err(|e| {
                ExecutorError::Storage(format!("Failed to delete dir {}: {}", full_path, e))
            })?;
        } else {
            fs::remove_file(&full_path).await.map_err(|e| {
                ExecutorError::Storage(format!("Failed to delete {}: {}", full_path, e))
            })?;
        }

        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let full_path = self.full_path(prefix);
        let mut entries = Vec::new();

        if !Path::new(&full_path).exists() {
            return Ok(entries);
        }

        let mut read_dir = fs::read_dir(&full_path)
            .await
            .map_err(|e| ExecutorError::Storage(format!("Failed to list {}: {}", full_path, e)))?;

        while let Ok(Some(entry)) = read_dir.next_entry().await {
            if let Ok(name) = entry.file_name().into_string() {
                entries.push(name);
            }
        }

        Ok(entries)
    }

    async fn size(&self, path: &str) -> Result<u64> {
        let full_path = self.full_path(path);
        let metadata = fs::metadata(&full_path)
            .await
            .map_err(|e| ExecutorError::Storage(format!("Failed to stat {}: {}", full_path, e)))?;

        Ok(metadata.len())
    }

    async fn download(&self, remote_path: &str, local_path: &str) -> Result<()> {
        // For local storage, this is just a copy
        let src = self.full_path(remote_path);
        let dst = local_path;

        if let Ok(metadata) = fs::metadata(&src).await {
            if metadata.is_dir() {
                if let Some(parent) = Path::new(dst).parent() {
                    fs::create_dir_all(parent).await.map_err(|e| {
                        ExecutorError::Storage(format!("Failed to create dir: {}", e))
                    })?;
                }

                let src_owned = src.clone();
                let dst_owned = dst.to_string();
                tokio::task::spawn_blocking(move || create_tarball(&src_owned, &dst_owned))
                    .await
                    .map_err(|e| {
                        ExecutorError::Storage(format!("Failed to create tarball task: {}", e))
                    })??;
                return Ok(());
            }
        }

        // Ensure parent directory exists
        if let Some(parent) = Path::new(dst).parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| ExecutorError::Storage(format!("Failed to create dir: {}", e)))?;
        }

        fs::copy(&src, dst).await.map_err(|e| {
            ExecutorError::Storage(format!("Failed to copy {} to {}: {}", src, dst, e))
        })?;

        Ok(())
    }

    async fn upload(&self, local_path: &str, remote_path: &str) -> Result<()> {
        // For local storage, this is just a copy
        let dst = self.full_path(remote_path);

        // Ensure parent directory exists
        if let Some(parent) = Path::new(&dst).parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| ExecutorError::Storage(format!("Failed to create dir: {}", e)))?;
        }

        fs::copy(local_path, &dst).await.map_err(|e| {
            ExecutorError::Storage(format!("Failed to copy {} to {}: {}", local_path, dst, e))
        })?;

        Ok(())
    }
}

fn create_tarball(src_dir: &str, dst_path: &str) -> Result<()> {
    let file = std::fs::File::create(dst_path).map_err(|e| {
        ExecutorError::Storage(format!("Failed to create tarball {}: {}", dst_path, e))
    })?;

    if dst_path.ends_with(".tar.gz") || dst_path.ends_with(".tgz") {
        let encoder = GzEncoder::new(file, Compression::default());
        let mut builder = Builder::new(encoder);
        builder
            .append_dir_all(".", src_dir)
            .map_err(|e| ExecutorError::Storage(format!("Failed to add files: {}", e)))?;
        builder
            .finish()
            .map_err(|e| ExecutorError::Storage(format!("Failed to finish tar: {}", e)))?;
        let encoder = builder
            .into_inner()
            .map_err(|e| ExecutorError::Storage(format!("Failed to finish tar: {}", e)))?;
        encoder
            .finish()
            .map_err(|e| ExecutorError::Storage(format!("Failed to finish gzip: {}", e)))?;
    } else {
        let mut builder = Builder::new(file);
        builder
            .append_dir_all(".", src_dir)
            .map_err(|e| ExecutorError::Storage(format!("Failed to add files: {}", e)))?;
        builder
            .finish()
            .map_err(|e| ExecutorError::Storage(format!("Failed to finish tar: {}", e)))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_write_and_read() {
        let dir = tempdir().unwrap();
        let storage = LocalStorage::with_base_path(dir.path().to_str().unwrap());

        storage.write("test.txt", b"hello").await.unwrap();
        let data = storage.read("test.txt").await.unwrap();
        assert_eq!(data, b"hello");
    }

    #[tokio::test]
    async fn test_exists() {
        let dir = tempdir().unwrap();
        let storage = LocalStorage::with_base_path(dir.path().to_str().unwrap());

        assert!(!storage.exists("missing.txt").await.unwrap());
        storage.write("exists.txt", b"data").await.unwrap();
        assert!(storage.exists("exists.txt").await.unwrap());
    }
}
