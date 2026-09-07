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

use super::archive::{body_preview, validate_archive_bytes, validate_archive_file};
use super::file_cache::StorageFileCache;
use super::Storage;
use crate::config::S3ProviderConfig;
use crate::error::{ExecutorError, Result};
use async_trait::async_trait;
use s3::creds::Credentials;
use s3::region::Region;
use s3::Bucket;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::fs;

/// Distinguishes concurrent partial downloads writing to the same directory.
static PARTIAL_DOWNLOAD_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Check if an error indicates the object was not found
fn is_not_found_error(err: &s3::error::S3Error) -> bool {
    matches!(err, s3::error::S3Error::HttpFailWithBody(404, _))
}

/// Whether a response status means the request succeeded.
///
/// The `fail-on-err` feature of `rust-s3` is not enabled, so a failing request
/// arrives as `Ok(ResponseData)` carrying the status and the error body. Every
/// call site has to check the status itself; without that, a 503 and its XML
/// body are indistinguishable from an object.
fn is_success_status(status: u16) -> bool {
    (200..300).contains(&status)
}

/// Error for a request that completed with a non-success status.
fn status_error(operation: &str, path: &str, status: u16, body: &[u8]) -> ExecutorError {
    ExecutorError::Storage(format!(
        "S3 {} for '{}' returned HTTP {}: {}",
        operation,
        path,
        status,
        body_preview(body)
    ))
}

/// Error for a request that did not complete.
///
/// `HttpFailWithBody` carries a status, so it is rendered in the same shape as
/// `status_error` and stays visible to the retry classifier.
fn transport_error(operation: &str, path: &str, err: s3::error::S3Error) -> ExecutorError {
    match err {
        s3::error::S3Error::HttpFailWithBody(status, body) => ExecutorError::Storage(format!(
            "S3 {} for '{}' returned HTTP {}: {}",
            operation,
            path,
            status,
            body_preview(body.as_bytes())
        )),
        other => {
            ExecutorError::Storage(format!("S3 {} failed for '{}': {}", operation, path, other))
        }
    }
}

/// Path used while a download is in flight, so a partial or rejected body never
/// appears at the destination.
fn partial_download_path(local_path: &str) -> PathBuf {
    let sequence = PARTIAL_DOWNLOAD_COUNTER.fetch_add(1, Ordering::Relaxed);
    PathBuf::from(format!(
        "{}.part.{}.{}",
        local_path,
        std::process::id(),
        sequence
    ))
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

    /// Fetch an object, treating any non-success status as an error rather than
    /// as data.
    async fn get_object_checked(&self, path: &str) -> Result<Vec<u8>> {
        let s3_key = self.get_s3_key(path);
        let response = self
            .bucket
            .get_object(s3_key)
            .await
            .map_err(|e| transport_error("get_object", path, e))?;

        let status = response.status_code();
        if !is_success_status(status) {
            return Err(status_error(
                "get_object",
                path,
                status,
                response.as_slice(),
            ));
        }

        Ok(response.to_vec())
    }

    /// Serve a download from the file cache.
    ///
    /// The cached artefact is validated first: an entry written before the
    /// status check existed, or by an older binary, can hold an error document,
    /// and the default cache TTL is 30 days.
    async fn install_from_cache(
        cache_file: &Path,
        remote_path: &str,
        local_path: &str,
    ) -> Result<()> {
        validate_archive_file(remote_path, cache_file).await?;

        let partial = partial_download_path(local_path);
        if let Err(e) = fs::copy(cache_file, &partial).await {
            fs::remove_file(&partial).await.ok();
            return Err(ExecutorError::Storage(format!(
                "Failed to copy cached file to '{}': {}",
                local_path, e
            )));
        }

        if let Err(e) = fs::rename(&partial, local_path).await {
            fs::remove_file(&partial).await.ok();
            return Err(ExecutorError::Storage(format!(
                "Failed to move cached file into place at '{}': {}",
                local_path, e
            )));
        }

        Ok(())
    }

    /// Write a downloaded body to a temporary path and move it into place, so
    /// the destination only ever holds a complete artefact.
    async fn write_atomically(local_path: &str, data: &[u8]) -> Result<()> {
        let partial = partial_download_path(local_path);

        if let Err(e) = fs::write(&partial, data).await {
            fs::remove_file(&partial).await.ok();
            return Err(ExecutorError::Storage(format!(
                "Failed to write downloaded file to '{}': {}",
                local_path, e
            )));
        }

        if let Err(e) = fs::rename(&partial, local_path).await {
            fs::remove_file(&partial).await.ok();
            return Err(ExecutorError::Storage(format!(
                "Failed to move downloaded file into place at '{}': {}",
                local_path, e
            )));
        }

        Ok(())
    }
}

#[async_trait]
impl Storage for S3Storage {
    async fn read(&self, path: &str) -> Result<Vec<u8>> {
        self.get_object_checked(path).await
    }

    async fn write(&self, path: &str, data: &[u8]) -> Result<()> {
        let s3_key = self.get_s3_key(path);
        let response = self
            .bucket
            .put_object(s3_key, data)
            .await
            .map_err(|e| transport_error("put_object", path, e))?;

        let status = response.status_code();
        if !is_success_status(status) {
            return Err(status_error(
                "put_object",
                path,
                status,
                response.as_slice(),
            ));
        }

        Ok(())
    }

    async fn exists(&self, path: &str) -> Result<bool> {
        let s3_key = self.get_s3_key(path);
        match self.bucket.head_object(s3_key).await {
            Ok((_, status)) if is_success_status(status) => Ok(true),
            Ok((_, 404)) => Ok(false),
            Ok((_, status)) => Err(status_error("head_object", path, status, &[])),
            Err(e) if is_not_found_error(&e) => Ok(false),
            Err(e) => Err(transport_error("head_object", path, e)),
        }
    }

    async fn upload(&self, local_path: &str, remote_path: &str) -> Result<()> {
        let data = fs::read(local_path).await.map_err(|e| {
            ExecutorError::Storage(format!("Failed to read local file '{}': {}", local_path, e))
        })?;

        self.write(remote_path, &data).await
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
                let (cache_file, _) = cache.get_cache_path(remote_path);
                if cache_file.exists() {
                    match Self::install_from_cache(&cache_file, remote_path, local_path).await {
                        Ok(()) => {
                            tracing::info!("Cache hit for {}, using cached file", remote_path);
                            return Ok(());
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Discarding unusable cache entry for {}: {}",
                                remote_path,
                                e
                            );
                            cache.remove(remote_path).await.ok();
                        }
                    }
                }
            }
        }

        // Direct download from S3
        tracing::info!("Direct download from S3: {}", remote_path);
        tracing::debug!(
            "S3 key after stripping bucket prefix: '{}'",
            self.get_s3_key(remote_path)
        );

        let data = self.get_object_checked(remote_path).await?;
        validate_archive_bytes(remote_path, &data)?;

        Self::write_atomically(local_path, &data).await?;

        tracing::info!(
            "Download completed for {} ({} bytes)",
            remote_path,
            data.len()
        );

        // Only a body that passed the status and format checks reaches the cache.
        if let Some(ref cache) = self.file_cache {
            if let Err(e) = cache.put(remote_path, &data).await {
                tracing::warn!("Failed to cache {}: {}", remote_path, e);
            }
        }

        Ok(())
    }

    async fn delete(&self, path: &str) -> Result<()> {
        let s3_key = self.get_s3_key(path);
        let response = self
            .bucket
            .delete_object(s3_key)
            .await
            .map_err(|e| transport_error("delete_object", path, e))?;

        let status = response.status_code();
        if !is_success_status(status) && status != 404 {
            return Err(status_error(
                "delete_object",
                path,
                status,
                response.as_slice(),
            ));
        }

        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let s3_key = self.get_s3_key(prefix);
        let response = self
            .bucket
            .list(s3_key.to_string(), None)
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
        let response = self
            .bucket
            .head_object(s3_key)
            .await
            .map_err(|e| transport_error("head_object", path, e))?;

        if !is_success_status(response.1) {
            return Err(status_error("head_object", path, response.1, &[]));
        }

        let content_length = response.0.content_length.ok_or_else(|| {
            ExecutorError::Storage(format!("S3 object '{}' has no content length", path))
        })?;

        Ok(content_length as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resilience::is_transient_error;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    const S3_ERROR_BODY: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>ServiceUnavailable</Code><Message>Service is unable to handle request.</Message></Error>"#;

    fn gzip_archive() -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(b"function code").unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn only_2xx_counts_as_success() {
        assert!(is_success_status(200));
        assert!(is_success_status(204));
        assert!(!is_success_status(304));
        assert!(!is_success_status(404));
        assert!(!is_success_status(503));
    }

    #[test]
    fn status_error_names_status_key_and_body() {
        let error = status_error(
            "get_object",
            "unified/builds/app-1/code.tar.gz",
            503,
            S3_ERROR_BODY,
        );
        let message = error.to_string();
        assert!(message.contains("HTTP 503"), "{}", message);
        assert!(
            message.contains("unified/builds/app-1/code.tar.gz"),
            "{}",
            message
        );
        assert!(message.contains("ServiceUnavailable"), "{}", message);
    }

    #[test]
    fn server_errors_are_retryable_and_missing_objects_are_not() {
        let unavailable = status_error("get_object", "builds/code.tar.gz", 503, S3_ERROR_BODY);
        assert!(is_transient_error(&unavailable));

        let throttled = status_error("get_object", "builds/code.tar.gz", 429, b"<Error/>");
        assert!(is_transient_error(&throttled));

        let missing = status_error(
            "get_object",
            "builds/code.tar.gz",
            404,
            b"<Error><Code>NoSuchKey</Code></Error>",
        );
        assert!(!is_transient_error(&missing));
    }

    #[test]
    fn missing_object_body_mentioning_503_is_still_not_retryable() {
        let missing = status_error(
            "get_object",
            "builds/code.tar.gz",
            404,
            b"<Error><Code>NoSuchKey</Code><Message>the previous request failed with 503</Message></Error>",
        );
        assert!(!is_transient_error(&missing));
    }

    #[test]
    fn transport_failure_with_body_keeps_the_status_visible() {
        let error = transport_error(
            "get_object",
            "builds/code.tar.gz",
            s3::error::S3Error::HttpFailWithBody(
                500,
                "<Error><Code>InternalError</Code></Error>".to_string(),
            ),
        );
        assert!(error.to_string().contains("HTTP 500"));
        assert!(is_transient_error(&error));
    }

    #[test]
    fn partial_download_paths_are_distinct() {
        let first = partial_download_path("/tmp/runtime/src/code.tar.gz");
        let second = partial_download_path("/tmp/runtime/src/code.tar.gz");
        assert_ne!(first, second);
        assert!(first
            .to_string_lossy()
            .starts_with("/tmp/runtime/src/code.tar.gz.part."));
    }

    #[tokio::test]
    async fn cached_error_document_is_rejected_and_nothing_lands_locally() {
        let dir = tempfile::tempdir().unwrap();
        let cache_file = dir.path().join("cached");
        tokio::fs::write(&cache_file, S3_ERROR_BODY).await.unwrap();
        let local_path = dir.path().join("code.tar.gz");
        let local_path_str = local_path.display().to_string();

        let error = S3Storage::install_from_cache(
            &cache_file,
            "unified/builds/app-1/code.tar.gz",
            &local_path_str,
        )
        .await
        .expect_err("a cached error document must not be served as a build");

        assert!(error.to_string().contains("it is an error document"));
        assert!(!local_path.exists());
    }

    #[tokio::test]
    async fn cached_archive_is_installed_at_the_destination() {
        let dir = tempfile::tempdir().unwrap();
        let cache_file = dir.path().join("cached");
        let archive = gzip_archive();
        tokio::fs::write(&cache_file, &archive).await.unwrap();
        let local_path = dir.path().join("code.tar.gz");
        let local_path_str = local_path.display().to_string();

        S3Storage::install_from_cache(
            &cache_file,
            "unified/builds/app-1/code.tar.gz",
            &local_path_str,
        )
        .await
        .expect("a valid cached archive is served");

        assert_eq!(tokio::fs::read(&local_path).await.unwrap(), archive);
    }

    #[tokio::test]
    async fn atomic_write_leaves_no_partial_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        let local_path = dir.path().join("code.tar.gz");
        let archive = gzip_archive();

        S3Storage::write_atomically(&local_path.display().to_string(), &archive)
            .await
            .expect("write succeeds");

        assert_eq!(tokio::fs::read(&local_path).await.unwrap(), archive);

        let mut entries = tokio::fs::read_dir(dir.path()).await.unwrap();
        while let Some(entry) = entries.next_entry().await.unwrap() {
            let name = entry.file_name().to_string_lossy().to_string();
            assert!(!name.contains(".part."), "left a partial file: {}", name);
        }
    }
}
