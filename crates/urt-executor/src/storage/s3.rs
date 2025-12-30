//! S3/MinIO storage backend

use super::Storage;
use crate::error::{ExecutorError, Result};
use async_trait::async_trait;
use s3::creds::Credentials;
use s3::{Bucket, Region};
use std::path::Path;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;
use url::Url;

/// S3-compatible storage backend
pub struct S3Storage {
    bucket: Box<Bucket>,
}

impl S3Storage {
    /// Create from S3 DSN: s3://key:secret@host:port/bucket?region=us-east-1
    pub fn from_dsn(dsn: &str) -> Result<Self> {
        let url = Url::parse(dsn)
            .map_err(|e| ExecutorError::Storage(format!("Invalid S3 DSN: {}", e)))?;

        let access_key = url.username();
        let secret_key = url.password().unwrap_or("");
        let host = url.host_str().unwrap_or("localhost");
        let port = url.port().unwrap_or(9000);

        // Extract bucket name from path (first segment)
        let bucket_name = url
            .path_segments()
            .and_then(|mut s| s.next())
            .unwrap_or("builds");

        // Extract region from query params
        let region_name = url
            .query_pairs()
            .find(|(k, _)| k == "region")
            .map(|(_, v)| v.to_string())
            .unwrap_or_else(|| "us-east-1".to_string());

        let endpoint = format!("http://{}:{}", host, port);
        let region = Region::Custom {
            region: region_name,
            endpoint,
        };

        let credentials = Credentials::new(Some(access_key), Some(secret_key), None, None, None)
            .map_err(|e| ExecutorError::Storage(format!("Invalid credentials: {}", e)))?;

        let bucket = Bucket::new(bucket_name, region, credentials)
            .map_err(|e| ExecutorError::Storage(format!("Failed to create bucket: {}", e)))?
            .with_path_style();

        debug!(
            "Created S3 storage for bucket {} at {}:{}",
            bucket_name, host, port
        );

        Ok(Self { bucket })
    }
}

#[async_trait]
impl Storage for S3Storage {
    async fn exists(&self, path: &str) -> Result<bool> {
        match self.bucket.head_object(path).await {
            Ok(_) => Ok(true),
            Err(s3::error::S3Error::HttpFailWithBody(404, _)) => Ok(false),
            Err(e) => Err(ExecutorError::Storage(format!(
                "S3 head_object failed: {}",
                e
            ))),
        }
    }

    async fn read(&self, path: &str) -> Result<Vec<u8>> {
        let response = self
            .bucket
            .get_object(path)
            .await
            .map_err(|e| ExecutorError::Storage(format!("S3 get_object failed: {}", e)))?;

        Ok(response.to_vec())
    }

    async fn write(&self, path: &str, data: &[u8]) -> Result<()> {
        self.bucket
            .put_object(path, data)
            .await
            .map_err(|e| ExecutorError::Storage(format!("S3 put_object failed: {}", e)))?;

        Ok(())
    }

    async fn delete(&self, path: &str) -> Result<()> {
        self.bucket
            .delete_object(path)
            .await
            .map_err(|e| ExecutorError::Storage(format!("S3 delete_object failed: {}", e)))?;

        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let results = self
            .bucket
            .list(prefix.to_string(), None)
            .await
            .map_err(|e| ExecutorError::Storage(format!("S3 list failed: {}", e)))?;

        let mut keys = Vec::new();
        for result in results {
            for object in result.contents {
                keys.push(object.key);
            }
        }

        Ok(keys)
    }

    async fn size(&self, path: &str) -> Result<u64> {
        let (head, _) = self
            .bucket
            .head_object(path)
            .await
            .map_err(|e| ExecutorError::Storage(format!("S3 head_object failed: {}", e)))?;

        Ok(head.content_length.unwrap_or(0) as u64)
    }

    async fn download(&self, remote_path: &str, local_path: &str) -> Result<()> {
        let data = self.read(remote_path).await?;

        // Ensure parent directory exists
        if let Some(parent) = Path::new(local_path).parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| ExecutorError::Storage(format!("Failed to create dir: {}", e)))?;
        }

        let mut file = fs::File::create(local_path)
            .await
            .map_err(|e| ExecutorError::Storage(format!("Failed to create file: {}", e)))?;

        file.write_all(&data)
            .await
            .map_err(|e| ExecutorError::Storage(format!("Failed to write file: {}", e)))?;

        Ok(())
    }

    async fn upload(&self, local_path: &str, remote_path: &str) -> Result<()> {
        let mut file = fs::File::open(local_path)
            .await
            .map_err(|e| ExecutorError::Storage(format!("Failed to open file: {}", e)))?;

        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .await
            .map_err(|e| ExecutorError::Storage(format!("Failed to read file: {}", e)))?;

        self.write(remote_path, &data).await
    }
}

impl std::fmt::Debug for S3Storage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Storage")
            .field("bucket", &self.bucket.name())
            .finish()
    }
}
