//! S3/MinIO storage backend
//!
//! Supports multiple S3-compatible providers:
//! - AWS S3
//! - DigitalOcean Spaces
//! - Backblaze B2
//! - Linode Object Storage
//! - Wasabi
//!
//! Features local file caching to speed up cold starts.

use super::file_cache::StorageFileCache;
use super::Storage;
use crate::config::S3ProviderConfig;
use crate::error::{ExecutorError, Result};
use async_trait::async_trait;
use s3::creds::Credentials;
use s3::{Bucket, Region};
use std::path::Path;
use std::sync::Arc;
use tokio::fs;
use tokio::io::AsyncReadExt;
use tracing::debug;
use url::Url;

/// S3-compatible storage backend with optional local file caching
pub struct S3Storage {
    bucket: Box<Bucket>,
    /// Optional file cache for faster cold starts
    file_cache: Option<Arc<StorageFileCache>>,
}

impl S3Storage {
    // ========================================================================
    // Provider-specific factory methods (matching executor-main endpoints)
    // ========================================================================

    #[allow(dead_code)]
    /// Create S3 storage with custom endpoint (for AWS S3 or custom S3-compatible)
    /// with optional file caching for faster cold starts
    pub fn new_with_endpoint(
        access_key: &str,
        secret: &str,
        region: &str,
        bucket: &str,
        endpoint: &str,
    ) -> Result<Self> {
        Self::new_with_endpoint_and_cache(access_key, secret, region, bucket, endpoint, None)
    }

    /// Create S3 storage with custom endpoint and file cache
    pub fn new_with_endpoint_and_cache(
        access_key: &str,
        secret: &str,
        region: &str,
        bucket: &str,
        endpoint: &str,
        file_cache: Option<Arc<StorageFileCache>>,
    ) -> Result<Self> {
        let region = Region::Custom {
            region: region.to_string(),
            endpoint: endpoint.to_string(),
        };

        let credentials = Credentials::new(Some(access_key), Some(secret), None, None, None)
            .map_err(|e| ExecutorError::Storage(format!("Invalid S3 credentials: {}", e)))?;

        let bucket = Bucket::new(bucket, region, credentials)
            .map_err(|e| {
                ExecutorError::Storage(format!(
                    "Failed to create S3 bucket '{}' at {}: {}",
                    bucket, endpoint, e
                ))
            })?
            .with_path_style();

        debug!(
            "Created S3 storage for bucket '{}' at {}",
            bucket.name(),
            endpoint
        );

        Ok(Self { bucket, file_cache })
    }

    /// Create AWS S3 storage from config
    pub fn new_s3(config: &S3ProviderConfig) -> Result<Self> {
        Self::new_s3_with_cache(config, None)
    }

    /// Create AWS S3 storage from config with file cache
    pub fn new_s3_with_cache(
        config: &S3ProviderConfig,
        file_cache: Option<Arc<StorageFileCache>>,
    ) -> Result<Self> {
        let endpoint = config
            .endpoint
            .as_deref()
            .map(|e| e.to_string())
            .unwrap_or_else(|| format!("https://s3.{}.amazonaws.com", config.region));

        Self::new_with_endpoint_and_cache(
            &config.access_key,
            &config.secret,
            &config.region,
            &config.bucket,
            &endpoint,
            file_cache,
        )
    }

    /// Create DigitalOcean Spaces storage from config
    /// Endpoint: https://{region}.digitaloceanspaces.com
    pub fn new_do_spaces(config: &S3ProviderConfig) -> Result<Self> {
        Self::new_do_spaces_with_cache(config, None)
    }

    /// Create DigitalOcean Spaces with file cache
    pub fn new_do_spaces_with_cache(
        config: &S3ProviderConfig,
        file_cache: Option<Arc<StorageFileCache>>,
    ) -> Result<Self> {
        let endpoint = format!("https://{}.digitaloceanspaces.com", config.region);
        Self::new_with_endpoint_and_cache(
            &config.access_key,
            &config.secret,
            &config.region,
            &config.bucket,
            &endpoint,
            file_cache,
        )
    }

    /// Create Backblaze B2 storage from config
    /// Endpoint: https://s3.{region}.backblazeb2.com
    pub fn new_backblaze(config: &S3ProviderConfig) -> Result<Self> {
        Self::new_backblaze_with_cache(config, None)
    }

    /// Create Backblaze with file cache
    pub fn new_backblaze_with_cache(
        config: &S3ProviderConfig,
        file_cache: Option<Arc<StorageFileCache>>,
    ) -> Result<Self> {
        let endpoint = format!("https://s3.{}.backblazeb2.com", config.region);
        Self::new_with_endpoint_and_cache(
            &config.access_key,
            &config.secret,
            &config.region,
            &config.bucket,
            &endpoint,
            file_cache,
        )
    }

    /// Create Linode Object Storage from config
    /// Endpoint: https://{region}.linodeobjects.com
    pub fn new_linode(config: &S3ProviderConfig) -> Result<Self> {
        Self::new_linode_with_cache(config, None)
    }

    /// Create Linode with file cache
    pub fn new_linode_with_cache(
        config: &S3ProviderConfig,
        file_cache: Option<Arc<StorageFileCache>>,
    ) -> Result<Self> {
        let endpoint = format!("https://{}.linodeobjects.com", config.region);
        Self::new_with_endpoint_and_cache(
            &config.access_key,
            &config.secret,
            &config.region,
            &config.bucket,
            &endpoint,
            file_cache,
        )
    }

    /// Create Wasabi storage from config
    /// Endpoint: https://s3.{region}.wasabisys.com
    pub fn new_wasabi(config: &S3ProviderConfig) -> Result<Self> {
        Self::new_wasabi_with_cache(config, None)
    }

    /// Create Wasabi with file cache
    pub fn new_wasabi_with_cache(
        config: &S3ProviderConfig,
        file_cache: Option<Arc<StorageFileCache>>,
    ) -> Result<Self> {
        let endpoint = format!("https://s3.{}.wasabisys.com", config.region);
        Self::new_with_endpoint_and_cache(
            &config.access_key,
            &config.secret,
            &config.region,
            &config.bucket,
            &endpoint,
            file_cache,
        )
    }

    // ========================================================================
    // DSN-based factory method (legacy support)
    // ========================================================================

    /// Create from S3 DSN: s3://key:secret@host:port/bucket?region=us-east-1&insecure=true
    ///
    /// Supports the following query parameters:
    /// - region: AWS region (default: us-east-1)
    /// - insecure: Use HTTP instead of HTTPS (default: false)
    /// - url: Custom endpoint URL (overrides host/port)
    pub fn from_dsn(dsn: &str) -> Result<Self> {
        Self::from_dsn_with_cache(dsn, None)
    }

    /// Create from S3 DSN with file cache
    pub fn from_dsn_with_cache(
        dsn: &str,
        file_cache: Option<Arc<StorageFileCache>>,
    ) -> Result<Self> {
        let url = Url::parse(dsn)
            .map_err(|e| ExecutorError::Storage(format!("Invalid S3 DSN: {}", e)))?;

        let access_key = url.username();
        let secret_key = url.password().unwrap_or("");
        let host = url
            .host_str()
            .ok_or_else(|| ExecutorError::Storage("S3 DSN missing host".to_string()))?;
        let port = url.port().unwrap_or(443);

        // Extract bucket name from path (first segment)
        let bucket_name = url
            .path_segments()
            .and_then(|mut s| s.next())
            .ok_or_else(|| ExecutorError::Storage("S3 DSN missing bucket name".to_string()))?;

        // Extract query parameters
        let mut region_name = "us-east-1".to_string();
        let mut insecure = false;
        let mut custom_url = None;

        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "region" => region_name = value.to_string(),
                "insecure" => insecure = value.eq_ignore_ascii_case("true"),
                "url" => custom_url = Some(value.to_string()),
                _ => {} // Ignore unknown parameters
            }
        }

        // Determine endpoint
        let endpoint = if let Some(url) = custom_url {
            url
        } else {
            let scheme = if insecure { "http" } else { "https" };
            format!("{}://{}:{}", scheme, host, port)
        };

        let region = Region::Custom {
            region: region_name,
            endpoint: endpoint.clone(),
        };

        let credentials = Credentials::new(Some(access_key), Some(secret_key), None, None, None)
            .map_err(|e| ExecutorError::Storage(format!("Invalid S3 credentials: {}", e)))?;

        let bucket = Bucket::new(bucket_name, region, credentials)
            .map_err(|e| {
                ExecutorError::Storage(format!(
                    "Failed to create S3 bucket '{}' at {}: {}",
                    bucket_name, endpoint, e
                ))
            })?
            .with_path_style();

        debug!(
            "Created S3 storage for bucket '{}' at {} (insecure: {})",
            bucket_name, endpoint, insecure
        );

        Ok(Self { bucket, file_cache })
    }

    /// Get the underlying bucket (for testing/debugging)
    #[allow(dead_code)]
    pub fn bucket(&self) -> &Bucket {
        &self.bucket
    }
}

/// Check if an S3 error indicates the object doesn't exist
fn is_not_found_error(err: &s3::error::S3Error) -> bool {
    // S3 errors that indicate the object doesn't exist
    // HttpFailWithBody contains (status_code, body)
    if let s3::error::S3Error::HttpFailWithBody(status, _) = err {
        return *status == 404;
    }
    false
}

#[async_trait]
impl Storage for S3Storage {
    async fn exists(&self, path: &str) -> Result<bool> {
        match self.bucket.head_object(path).await {
            Ok(_) => Ok(true),
            Err(ref e) if is_not_found_error(e) => Ok(false),
            Err(e) => Err(ExecutorError::Storage(format!(
                "S3 head_object failed for '{}': {}",
                path, e
            ))),
        }
    }

    async fn read(&self, path: &str) -> Result<Vec<u8>> {
        let response = self.bucket.get_object(path).await.map_err(|e| {
            ExecutorError::Storage(format!("S3 get_object failed for '{}': {}", path, e))
        })?;

        Ok(response.to_vec())
    }

    async fn write(&self, path: &str, data: &[u8]) -> Result<()> {
        self.bucket.put_object(path, data).await.map_err(|e| {
            ExecutorError::Storage(format!("S3 put_object failed for '{}': {}", path, e))
        })?;

        Ok(())
    }

    async fn delete(&self, path: &str) -> Result<()> {
        self.bucket.delete_object(path).await.map_err(|e| {
            ExecutorError::Storage(format!("S3 delete_object failed for '{}': {}", path, e))
        })?;

        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let results = self
            .bucket
            .list(prefix.to_string(), None)
            .await
            .map_err(|e| {
                ExecutorError::Storage(format!("S3 list failed for prefix '{}': {}", prefix, e))
            })?;

        let mut keys = Vec::new();
        for result in results {
            for object in result.contents {
                keys.push(object.key);
            }
        }

        Ok(keys)
    }

    async fn size(&self, path: &str) -> Result<u64> {
        let (head, _) = self.bucket.head_object(path).await.map_err(|e| {
            ExecutorError::Storage(format!("S3 head_object failed for '{}': {}", path, e))
        })?;

        Ok(head.content_length.unwrap_or(0) as u64)
    }

    async fn download(&self, remote_path: &str, local_path: &str) -> Result<()> {
        // If file cache is enabled, try to use it
        if let Some(ref cache) = self.file_cache {
            // Check if we have a cached version
            if cache.exists(remote_path).await {
                debug!("Using cached file for: {}", remote_path);

                let remote_path_clone = remote_path.to_string();
                let bucket = self.bucket.clone();
                let cache_path = cache
                    .get_or_fetch(remote_path, move || {
                        let remote_path = remote_path_clone.clone();
                        let bucket = bucket.clone();
                        async move {
                            bucket
                                .get_object(&remote_path)
                                .await
                                .map_err(|e| {
                                    ExecutorError::Storage(format!(
                                        "S3 get_object failed for '{}': {}",
                                        remote_path, e
                                    ))
                                })
                                .map(|r| r.to_vec())
                        }
                    })
                    .await?;

                // Copy from cache to local path
                fs::copy(&cache_path, local_path).await.map_err(|e| {
                    ExecutorError::Storage(format!(
                        "Failed to copy cached file to '{}': {}",
                        local_path, e
                    ))
                })?;

                return Ok(());
            }

            // Not cached, fetch and cache
            debug!("Fetching and caching: {}", remote_path);

            let data = self
                .bucket
                .get_object(remote_path)
                .await
                .map_err(|e| {
                    ExecutorError::Storage(format!(
                        "S3 get_object failed for '{}': {}",
                        remote_path, e
                    ))
                })?
                .to_vec();

            // Cache the data
            cache.put(remote_path, &data).await?;

            // Write to local path
            if let Some(parent) = Path::new(local_path).parent() {
                fs::create_dir_all(parent).await.map_err(|e| {
                    ExecutorError::Storage(format!("Failed to create local directory: {}", e))
                })?;
            }

            fs::write(local_path, &data).await.map_err(|e| {
                ExecutorError::Storage(format!(
                    "Failed to write local file '{}': {}",
                    local_path, e
                ))
            })?;

            return Ok(());
        }

        // No cache - direct download
        let data = self
            .bucket
            .get_object(remote_path)
            .await
            .map_err(|e| {
                ExecutorError::Storage(format!("S3 get_object failed for '{}': {}", remote_path, e))
            })?
            .to_vec();

        if let Some(parent) = Path::new(local_path).parent() {
            fs::create_dir_all(parent).await.map_err(|e| {
                ExecutorError::Storage(format!("Failed to create local directory: {}", e))
            })?;
        }

        fs::write(local_path, &data).await.map_err(|e| {
            ExecutorError::Storage(format!(
                "Failed to write local file '{}': {}",
                local_path, e
            ))
        })?;

        Ok(())
    }

    async fn upload(&self, local_path: &str, remote_path: &str) -> Result<()> {
        let mut file = fs::File::open(local_path).await.map_err(|e| {
            ExecutorError::Storage(format!("Failed to open local file '{}': {}", local_path, e))
        })?;

        let mut data = Vec::new();
        file.read_to_end(&mut data).await.map_err(|e| {
            ExecutorError::Storage(format!("Failed to read local file '{}': {}", local_path, e))
        })?;

        self.bucket
            .put_object(remote_path, &data)
            .await
            .map_err(|e| {
                ExecutorError::Storage(format!("S3 put_object failed for '{}': {}", remote_path, e))
            })?;

        Ok(())
    }
}
