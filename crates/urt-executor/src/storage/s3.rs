//! S3/MinIO storage backend
//!
//! Supports multiple S3-compatible providers:
//! - AWS S3
//! - DigitalOcean Spaces
//! - Backblaze B2
//! - Linode Object Storage
//! - Wasabi

use super::Storage;
use crate::config::S3ProviderConfig;
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
    // ========================================================================
    // Provider-specific factory methods (matching executor-main endpoints)
    // ========================================================================

    /// Create S3 storage with custom endpoint (for AWS S3 or custom S3-compatible)
    pub fn new_with_endpoint(
        access_key: &str,
        secret: &str,
        region: &str,
        bucket: &str,
        endpoint: &str,
    ) -> Result<Self> {
        let region = Region::Custom {
            region: region.to_string(),
            endpoint: endpoint.to_string(),
        };

        let credentials = Credentials::new(Some(access_key), Some(secret), None, None, None)
            .map_err(|e| ExecutorError::Storage(format!("Invalid credentials: {}", e)))?;

        let bucket = Bucket::new(bucket, region, credentials)
            .map_err(|e| ExecutorError::Storage(format!("Failed to create bucket: {}", e)))?
            .with_path_style();

        debug!(
            "Created S3 storage for bucket {} at {}",
            bucket.name(),
            endpoint
        );

        Ok(Self { bucket })
    }

    /// Create AWS S3 storage from config
    pub fn new_s3(config: &S3ProviderConfig) -> Result<Self> {
        let endpoint = config
            .endpoint
            .as_deref()
            .map(|e| e.to_string())
            .unwrap_or_else(|| format!("https://s3.{}.amazonaws.com", config.region));

        Self::new_with_endpoint(
            &config.access_key,
            &config.secret,
            &config.region,
            &config.bucket,
            &endpoint,
        )
    }

    /// Create DigitalOcean Spaces storage from config
    /// Endpoint: https://{region}.digitaloceanspaces.com
    pub fn new_do_spaces(config: &S3ProviderConfig) -> Result<Self> {
        let endpoint = format!("https://{}.digitaloceanspaces.com", config.region);
        Self::new_with_endpoint(
            &config.access_key,
            &config.secret,
            &config.region,
            &config.bucket,
            &endpoint,
        )
    }

    /// Create Backblaze B2 storage from config
    /// Endpoint: https://s3.{region}.backblazeb2.com
    pub fn new_backblaze(config: &S3ProviderConfig) -> Result<Self> {
        let endpoint = format!("https://s3.{}.backblazeb2.com", config.region);
        Self::new_with_endpoint(
            &config.access_key,
            &config.secret,
            &config.region,
            &config.bucket,
            &endpoint,
        )
    }

    /// Create Linode Object Storage from config
    /// Endpoint: https://{region}.linodeobjects.com
    pub fn new_linode(config: &S3ProviderConfig) -> Result<Self> {
        let endpoint = format!("https://{}.linodeobjects.com", config.region);
        Self::new_with_endpoint(
            &config.access_key,
            &config.secret,
            &config.region,
            &config.bucket,
            &endpoint,
        )
    }

    /// Create Wasabi storage from config
    /// Endpoint: https://s3.{region}.wasabisys.com
    pub fn new_wasabi(config: &S3ProviderConfig) -> Result<Self> {
        let endpoint = format!("https://s3.{}.wasabisys.com", config.region);
        Self::new_with_endpoint(
            &config.access_key,
            &config.secret,
            &config.region,
            &config.bucket,
            &endpoint,
        )
    }

    // ========================================================================
    // DSN-based factory method (legacy support)
    // ========================================================================

    /// Create from S3 DSN: s3://key:secret@host:port/bucket?region=us-east-1
    #[allow(dead_code)]
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
