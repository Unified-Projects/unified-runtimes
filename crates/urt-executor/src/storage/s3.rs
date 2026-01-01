//! S3-compatible storage backend using rust-s3 library
//!
//! Supports multiple S3-compatible providers:
//! - AWS S3
//! - DigitalOcean Spaces
//! - Backblaze B2
//! - Linode Object Storage
//! - Wasabi
//! - MinIO
//!
//! Features local file caching to speed up cold starts.

use super::file_cache::StorageFileCache;
use super::Storage;
use crate::config::S3ProviderConfig;
use crate::error::{ExecutorError, Result};
use async_trait::async_trait;
use s3::creds::Credentials;
use s3::region::Region;
use s3::Bucket;
use std::path::Path;
use std::sync::Arc;
use tokio::fs;

/// Check if an error indicates the object was not found
fn is_not_found_error(err: &s3::error::S3Error) -> bool {
    matches!(err, s3::error::S3Error::HttpFailWithBody(404, _))
}

/// S3-compatible storage backend with optional local file caching
pub struct S3Storage {
    bucket: Bucket,
    /// Bucket name (stored to strip from paths if needed for virtual-hosted style)
    bucket_name: String,
    /// Whether using path-style addressing
    use_path_style: bool,
    /// Optional file cache for faster cold starts
    file_cache: Option<Arc<StorageFileCache>>,
}

impl S3Storage {
    /// Helper to get the S3 key for a path
    /// With virtual-hosted style, we need to strip the bucket prefix from the path
    fn get_s3_key<'a>(&self, path: &'a str) -> &'a str {
        if !self.use_path_style {
            // Virtual-hosted style: bucket is subdomain, path shouldn't include bucket
            // AppWrite paths include bucket prefix (e.g., "appwrite/storage/sites/...")
            // We need to strip it for virtual-hosted style
            let bucket_prefix = format!("{}/", self.bucket_name);
            if path.starts_with(&bucket_prefix) {
                return &path[bucket_prefix.len()..];
            }
            // Also handle path without trailing slash
            if path == self.bucket_name {
                return "";
            }
        }
        path
    }

    /// Create S3 storage with custom endpoint
    #[allow(dead_code)]
    pub fn new_with_endpoint(
        access_key: &str,
        secret: &str,
        region: &str,
        bucket_name: &str,
        endpoint: &str,
    ) -> Result<Self> {
        Self::new_with_endpoint_and_cache(access_key, secret, region, bucket_name, endpoint, None)
    }

    /// Check if endpoint looks like a container name (for Docker networking)
    fn is_container_endpoint(endpoint: &str) -> bool {
        // Check if endpoint is a Docker service name (no dots, or .docker.internal)
        let clean_endpoint = endpoint
            .strip_prefix("http://")
            .or_else(|| endpoint.strip_prefix("https://"))
            .unwrap_or(endpoint);

        // Container names typically don't have dots or are .internal domains
        // e.g., "appwrite-minio", "minio", "minio:9000"
        clean_endpoint.contains("docker.internal")
            || (!clean_endpoint.contains('.') && !clean_endpoint.contains(':'))
    }

    /// Create S3 storage with custom endpoint and file cache
    pub fn new_with_endpoint_and_cache(
        access_key: &str,
        secret: &str,
        region: &str,
        bucket_name: &str,
        endpoint: &str,
        file_cache: Option<Arc<StorageFileCache>>,
    ) -> Result<Self> {
        let region = Region::Custom {
            region: region.to_string(),
            endpoint: endpoint.to_string(),
        };

        let credentials = Credentials::new(Some(access_key), Some(secret), None, None, None)
            .map_err(|e| ExecutorError::Storage(format!("Invalid S3 credentials: {}", e)))?;

        // Detect if we're connecting to a container endpoint (Docker networking)
        // In Docker, service names like "appwrite-minio" resolve, but subdomains like
        // "appwrite.appwrite-minio" don't. So we use path-style for container endpoints.
        let use_path_style = Self::is_container_endpoint(endpoint);

        if use_path_style {
            tracing::debug!(
                "Using path-style addressing for container endpoint '{}'",
                endpoint
            );
        }

        let bucket = *Bucket::new(bucket_name, region, credentials)
            .map_err(|e| {
                ExecutorError::Storage(format!(
                    "Failed to create S3 bucket '{}' at {}: {}",
                    bucket_name, endpoint, e
                ))
            })?
            .with_path_style();

        tracing::debug!(
            "Created S3 storage for bucket '{}' at {} (path_style: {})",
            bucket_name,
            endpoint,
            use_path_style
        );

        Ok(Self {
            bucket,
            bucket_name: bucket_name.to_string(),
            use_path_style, // For container endpoints, use path-style
            file_cache,
        })
    }

    /// Create AWS S3 storage from config
    pub fn new_s3(config: &S3ProviderConfig) -> Result<Self> {
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
            None,
        )
    }

    /// Create AWS S3 storage from config with file cache
    #[allow(dead_code)]
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
    #[allow(dead_code)]
    pub fn new_do_spaces(config: &S3ProviderConfig) -> Result<Self> {
        let endpoint = config
            .endpoint
            .as_deref()
            .or(Some("https://nyc3.digitaloceanspaces.com"))
            .map(|e| e.to_string())
            .unwrap();

        Self::new_with_endpoint_and_cache(
            &config.access_key,
            &config.secret,
            &config.region,
            &config.bucket,
            &endpoint,
            None,
        )
    }

    /// Create Backblaze B2 storage from config
    #[allow(dead_code)]
    pub fn new_backblaze(config: &S3ProviderConfig) -> Result<Self> {
        let endpoint = config
            .endpoint
            .as_deref()
            .or(Some("https://s3.us-west-004.backblazeb2.com"))
            .map(|e| e.to_string())
            .unwrap();

        Self::new_with_endpoint_and_cache(
            &config.access_key,
            &config.secret,
            &config.region,
            &config.bucket,
            &endpoint,
            None,
        )
    }

    /// Create Linode Object Storage from config
    #[allow(dead_code)]
    pub fn new_linode(config: &S3ProviderConfig) -> Result<Self> {
        let endpoint = config
            .endpoint
            .as_deref()
            .or(Some("https://linode.com"))
            .map(|e| e.to_string())
            .unwrap();

        Self::new_with_endpoint_and_cache(
            &config.access_key,
            &config.secret,
            &config.region,
            &config.bucket,
            &endpoint,
            None,
        )
    }

    /// Create Wasabi storage from config
    #[allow(dead_code)]
    pub fn new_wasabi(config: &S3ProviderConfig) -> Result<Self> {
        let endpoint = config
            .endpoint
            .as_deref()
            .or(Some("https://s3.wasabisys.com"))
            .map(|e| e.to_string())
            .unwrap();

        Self::new_with_endpoint_and_cache(
            &config.access_key,
            &config.secret,
            &config.region,
            &config.bucket,
            &endpoint,
            None,
        )
    }

    /// Parse S3 DSN and create storage
    #[allow(dead_code)]
    pub fn from_dsn(dsn: &str) -> Result<Self> {
        // Format: s3://access_key:secret@endpoint/bucket
        let without_prefix = dsn.strip_prefix("s3://").unwrap_or(dsn);

        // Split at @ to get credentials and rest
        let (creds_part, rest) = without_prefix
            .split_once('@')
            .ok_or_else(|| ExecutorError::Storage("Invalid S3 DSN format".to_string()))?;

        let (access_key, secret) = creds_part
            .split_once(':')
            .ok_or_else(|| ExecutorError::Storage("Invalid S3 credentials format".to_string()))?;

        // Parse endpoint and bucket from rest
        // Format: endpoint/bucket or endpoint:port/bucket
        let (endpoint, bucket) = rest
            .split_once('/')
            .ok_or_else(|| ExecutorError::Storage("Invalid S3 bucket format".to_string()))?;

        Self::new_with_endpoint_and_cache(access_key, secret, "us-east-1", bucket, endpoint, None)
    }
}

#[async_trait]
impl Storage for S3Storage {
    async fn read(&self, path: &str) -> Result<Vec<u8>> {
        let s3_key = self.get_s3_key(path);
        self.bucket
            .get_object(s3_key)
            .await
            .map_err(|e| {
                ExecutorError::Storage(format!("S3 get_object failed for '{}': {}", path, e))
            })
            .map(|response| response.to_vec())
    }

    async fn write(&self, path: &str, data: &[u8]) -> Result<()> {
        let s3_key = self.get_s3_key(path);
        self.bucket.put_object(s3_key, data).await.map_err(|e| {
            ExecutorError::Storage(format!("S3 put_object failed for '{}': {}", path, e))
        })?;
        Ok(())
    }

    async fn exists(&self, path: &str) -> Result<bool> {
        let s3_key = self.get_s3_key(path);
        match self.bucket.head_object(s3_key).await {
            Ok(_) => Ok(true),
            Err(e) if is_not_found_error(&e) => Ok(false),
            Err(e) => Err(ExecutorError::Storage(format!(
                "Failed to check if object exists '{}': {}",
                path, e
            ))),
        }
    }

    async fn upload(&self, local_path: &str, remote_path: &str) -> Result<()> {
        let data = fs::read(local_path).await.map_err(|e| {
            ExecutorError::Storage(format!("Failed to read local file '{}': {}", local_path, e))
        })?;

        let s3_key = self.get_s3_key(remote_path);
        self.bucket.put_object(s3_key, &data).await.map_err(|e| {
            ExecutorError::Storage(format!("S3 put_object failed for '{}': {}", remote_path, e))
        })?;

        Ok(())
    }

    async fn download(&self, remote_path: &str, local_path: &str) -> Result<()> {
        tracing::info!("Downloading from S3: {}", remote_path);

        if let Some(parent) = Path::new(local_path).parent() {
            fs::create_dir_all(parent).await.map_err(|e| {
                ExecutorError::Storage(format!("Failed to create local directory: {}", e))
            })?;
        }

        // First try to use cache if available
        if let Some(ref cache) = self.file_cache {
            if cache.exists(remote_path).await {
                tracing::info!("Cache hit for {}, using cached file", remote_path);
                // Copy from cache to local path
                let (cache_file, _) = cache.get_cache_path(remote_path);
                if cache_file.exists() {
                    fs::copy(&cache_file, local_path).await.map_err(|e| {
                        ExecutorError::Storage(format!(
                            "Failed to copy cached file to '{}': {}",
                            local_path, e
                        ))
                    })?;
                    return Ok(());
                }
            }
        }

        // Direct download from S3
        tracing::info!("Direct download from S3: {}", remote_path);

        let s3_key = self.get_s3_key(remote_path);
        tracing::debug!("S3 key after stripping bucket prefix: '{}'", s3_key);

        // Use get_object and write bytes manually to avoid issues with get_object_to_writer
        let data = self
            .bucket
            .get_object(s3_key)
            .await
            .map_err(|e| {
                ExecutorError::Storage(format!(
                    "S3 get_object failed for '{}' (original: '{}'): {}",
                    s3_key, remote_path, e
                ))
            })?
            .to_vec();

        // Debug: log first bytes if response is small (likely error XML)
        if data.len() < 1024 {
            let preview = String::from_utf8_lossy(&data);
            tracing::warn!(
                "S3 response small ({} bytes), possible error: {}",
                data.len(),
                preview
            );
        }

        fs::write(local_path, &data).await.map_err(|e| {
            ExecutorError::Storage(format!(
                "Failed to write downloaded file to '{}': {}",
                local_path, e
            ))
        })?;

        tracing::info!(
            "Download completed for {} ({} bytes)",
            remote_path,
            data.len()
        );

        // If cache is configured, cache the file
        if let Some(ref cache) = self.file_cache {
            let data = fs::read(local_path).await.map_err(|e| {
                ExecutorError::Storage(format!("Failed to read local file for caching: {}", e))
            })?;
            cache.put(remote_path, &data).await.ok();
        }

        Ok(())
    }

    async fn delete(&self, path: &str) -> Result<()> {
        let s3_key = self.get_s3_key(path);
        self.bucket.delete_object(s3_key).await.map_err(|e| {
            ExecutorError::Storage(format!("S3 delete_object failed for '{}': {}", path, e))
        })?;

        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let s3_key = self.get_s3_key(prefix);
        let response = self
            .bucket
            .list(s3_key.to_string(), Some("/".to_string()))
            .await
            .map_err(|e| {
                ExecutorError::Storage(format!("S3 list_objects failed for '{}': {}", prefix, e))
            })?;

        let mut keys = Vec::new();
        for result in response {
            for object in result.contents {
                keys.push(object.key.clone());
            }
        }

        Ok(keys)
    }

    async fn size(&self, path: &str) -> Result<u64> {
        let s3_key = self.get_s3_key(path);
        let response = self.bucket.head_object(s3_key).await.map_err(|e| {
            ExecutorError::Storage(format!("S3 head_object failed for '{}': {}", path, e))
        })?;

        let content_length = response.0.content_length.ok_or_else(|| {
            ExecutorError::Storage(format!("S3 object '{}' has no content length", path))
        })?;

        Ok(content_length as u64)
    }
}
