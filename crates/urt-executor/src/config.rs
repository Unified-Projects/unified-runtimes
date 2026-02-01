//! Configuration for the URT Executor
//!
//! Environment variable priority:
//! 1. URT_* variables (new branding)
//! 2. OPR_EXECUTOR_* variables (backwards compatibility)
//!
//! This allows existing OpenRuntimes deployments to work as drop-in replacements
//! while new deployments can use the URT prefix.

use std::env;

// ============================================================================
// Storage Configuration
// ============================================================================

/// Storage device type - matches executor-main's STORAGE_DEVICE values
#[derive(Debug, Clone, PartialEq, Default)]
pub enum StorageDevice {
    #[default]
    Local,
    S3,
    DoSpaces,
    Backblaze,
    Linode,
    Wasabi,
}

use std::str::FromStr;

impl FromStr for StorageDevice {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "s3" => StorageDevice::S3,
            "dospaces" => StorageDevice::DoSpaces,
            "backblaze" => StorageDevice::Backblaze,
            "linode" => StorageDevice::Linode,
            "wasabi" => StorageDevice::Wasabi,
            _ => StorageDevice::Local,
        })
    }
}

/// S3-compatible storage configuration
#[derive(Debug, Clone)]
pub struct S3ProviderConfig {
    pub access_key: String,
    pub secret: String,
    pub region: String,
    pub bucket: String,
    pub endpoint: Option<String>, // Only for S3, others have fixed endpoints
}

/// Storage configuration - supports all executor-main storage providers
#[derive(Debug, Clone)]
pub struct StorageConfig {
    pub device: StorageDevice,
    pub s3: Option<S3ProviderConfig>,
    pub do_spaces: Option<S3ProviderConfig>,
    pub backblaze: Option<S3ProviderConfig>,
    pub linode: Option<S3ProviderConfig>,
    pub wasabi: Option<S3ProviderConfig>,
}

impl StorageConfig {
    /// Load storage configuration from environment variables
    /// Matches executor-main's individual env var pattern:
    /// - STORAGE_DEVICE = "local" | "s3" | "dospaces" | "backblaze" | "linode" | "wasabi"
    /// - STORAGE_{PROVIDER}_ACCESS_KEY, _SECRET, _REGION, _BUCKET, _ENDPOINT
    pub fn from_env() -> Self {
        let device = env_urt_or_opr("STORAGE_DEVICE")
            .as_deref()
            .unwrap_or("local")
            .parse::<StorageDevice>()
            .unwrap_or(StorageDevice::Local);

        Self {
            device,
            s3: Self::load_provider_config("S3"),
            do_spaces: Self::load_provider_config("DO_SPACES"),
            backblaze: Self::load_provider_config("BACKBLAZE"),
            linode: Self::load_provider_config("LINODE"),
            wasabi: Self::load_provider_config("WASABI"),
        }
    }

    /// Load configuration for a specific storage provider
    fn load_provider_config(prefix: &str) -> Option<S3ProviderConfig> {
        // Access key and secret are required - if not present, config is None
        let access_key = env_urt_or_opr(&format!("STORAGE_{}_ACCESS_KEY", prefix))?;
        let secret = env_urt_or_opr(&format!("STORAGE_{}_SECRET", prefix))?;

        let region = env_urt_or_opr(&format!("STORAGE_{}_REGION", prefix))
            .unwrap_or_else(|| "us-east-1".to_string());
        let bucket = env_urt_or_opr(&format!("STORAGE_{}_BUCKET", prefix))
            .unwrap_or_else(|| "builds".to_string());
        let endpoint = env_urt_or_opr(&format!("STORAGE_{}_ENDPOINT", prefix));

        Some(S3ProviderConfig {
            access_key,
            secret,
            region,
            bucket,
            endpoint,
        })
    }

    #[allow(dead_code)]
    /// Get the active provider configuration based on device type
    pub fn get_active_config(&self) -> Option<&S3ProviderConfig> {
        match self.device {
            StorageDevice::Local => None,
            StorageDevice::S3 => self.s3.as_ref(),
            StorageDevice::DoSpaces => self.do_spaces.as_ref(),
            StorageDevice::Backblaze => self.backblaze.as_ref(),
            StorageDevice::Linode => self.linode.as_ref(),
            StorageDevice::Wasabi => self.wasabi.as_ref(),
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            device: StorageDevice::Local,
            s3: None,
            do_spaces: None,
            backblaze: None,
            linode: None,
            wasabi: None,
        }
    }
}

/// Get env var with URT_ prefix first, falling back to OPR_EXECUTOR_ prefix
fn env_urt_or_opr(name: &str) -> Option<String> {
    env::var(format!("URT_{}", name))
        .ok()
        .or_else(|| env::var(format!("OPR_EXECUTOR_{}", name)).ok())
}

/// Get env var with URT_ prefix first, falling back to OPR_EXECUTOR_ prefix, with default
fn env_urt_or_opr_default(name: &str, default: &str) -> String {
    env_urt_or_opr(name).unwrap_or_else(|| default.to_string())
}

/// Parse a size string like "20MB", "1GB", "512KB" or raw bytes
fn parse_size(s: &str) -> Option<usize> {
    let s = s.trim().to_uppercase();

    if let Ok(bytes) = s.parse::<usize>() {
        return Some(bytes);
    }

    let (num_str, multiplier) = if s.ends_with("GB") {
        (&s[..s.len() - 2], 1024 * 1024 * 1024)
    } else if s.ends_with("MB") {
        (&s[..s.len() - 2], 1024 * 1024)
    } else if s.ends_with("KB") {
        (&s[..s.len() - 2], 1024)
    } else if s.ends_with("G") {
        (&s[..s.len() - 1], 1024 * 1024 * 1024)
    } else if s.ends_with("M") {
        (&s[..s.len() - 1], 1024 * 1024)
    } else if s.ends_with("K") {
        (&s[..s.len() - 1], 1024)
    } else {
        return None;
    };

    num_str.trim().parse::<usize>().ok().map(|n| n * multiplier)
}

/// Main configuration for the executor
#[derive(Debug, Clone)]
pub struct ExecutorConfig {
    // Server configuration
    pub host: String,
    pub port: u16,
    pub secret: String,

    // Environment mode
    #[allow(dead_code)]
    pub env: String, // "development" or "production"

    // Docker configuration
    pub networks: Vec<String>,
    pub hostname: String,
    pub docker_hub_username: Option<String>,
    pub docker_hub_password: Option<String>,

    // Runtime configuration
    pub allowed_runtimes: Vec<String>,
    #[allow(dead_code)]
    pub runtime_versions: Vec<String>,
    pub image_pull_enabled: bool,

    // Resource overrides (URT enhancement)
    pub min_cpus: f64,
    pub min_memory: u64, // MB

    // Lifecycle configuration
    pub keep_alive: bool,
    pub inactive_threshold: u64,   // seconds
    pub maintenance_interval: u64, // seconds

    // Request limits
    pub max_body_size: usize, // bytes

    // Storage configuration
    pub storage: StorageConfig,

    // Logging configuration
    #[allow(dead_code)]
    pub logging_config: Option<String>,

    // Retry configuration
    #[allow(dead_code)]
    pub retry_attempts: u32,
    #[allow(dead_code)]
    pub retry_delay_ms: u64,
}

impl ExecutorConfig {
    /// Create configuration from environment variables
    pub fn from_env() -> Self {
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "executor".to_string());

        Self {
            // Server
            host: env::var("URT_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: env::var("URT_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(80),
            secret: env_urt_or_opr_default("SECRET", ""),

            // Environment mode
            env: env_urt_or_opr_default("ENV", "production"),

            // Docker
            networks: env_urt_or_opr_default("NETWORK", "executor_runtimes")
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            hostname,
            docker_hub_username: env_urt_or_opr("DOCKER_HUB_USERNAME").filter(|s| !s.is_empty()),
            docker_hub_password: env_urt_or_opr("DOCKER_HUB_PASSWORD").filter(|s| !s.is_empty()),

            // Runtimes
            allowed_runtimes: env_urt_or_opr_default("RUNTIMES", "")
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| s.trim().to_string())
                .collect(),
            runtime_versions: env_urt_or_opr_default("RUNTIME_VERSIONS", "v5")
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            image_pull_enabled: env_urt_or_opr("IMAGE_PULL")
                .map(|v| v.to_lowercase() != "disabled")
                .unwrap_or(true),

            // Resource overrides
            min_cpus: env_urt_or_opr("MIN_CPUS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0.0),
            min_memory: env_urt_or_opr("MIN_MEMORY")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),

            // Lifecycle - keep_alive defaults to false
            keep_alive: env_urt_or_opr("KEEP_ALIVE")
                .map(|v| v.to_lowercase() != "false")
                .unwrap_or(false),
            inactive_threshold: env_urt_or_opr("INACTIVE_THRESHOLD")
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
            maintenance_interval: env_urt_or_opr("MAINTENANCE_INTERVAL")
                .and_then(|v| v.parse().ok())
                .unwrap_or(3600),

            // Request limits - default 20MB
            max_body_size: env_urt_or_opr("MAX_BODY_SIZE")
                .and_then(|v| parse_size(&v))
                .unwrap_or(20 * 1024 * 1024),

            // Storage - load from individual env vars like executor-main
            storage: StorageConfig::from_env(),

            // Logging
            logging_config: env_urt_or_opr("LOGGING_CONFIG"),

            // Retry
            retry_attempts: env_urt_or_opr("RETRY_ATTEMPTS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
            retry_delay_ms: env_urt_or_opr("RETRY_DELAY_MS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(500),
        }
    }

    /// Apply minimum resource constraints
    /// Returns (effective_cpus, effective_memory)
    pub fn apply_min_resources(&self, cpus: f64, memory: u64) -> (f64, u64) {
        (
            if self.min_cpus > 0.0 {
                cpus.max(self.min_cpus)
            } else {
                cpus
            },
            if self.min_memory > 0 {
                memory.max(self.min_memory)
            } else {
                memory
            },
        )
    }

    /// Check if a runtime image is allowed
    /// Matches against both raw allowed runtimes and their expanded forms
    /// e.g., if allowed_runtimes contains "node-22", it will match "openruntimes/node:v5-22"
    pub fn is_runtime_allowed(&self, image: &str) -> bool {
        // Always allow the official static runtime for sites/assets
        if Self::is_static_runtime_image(image) {
            return true;
        }

        if self.allowed_runtimes.is_empty() {
            return true; // No allowlist means all are allowed
        }

        // Check both the raw shorthand and the expanded form
        self.allowed_runtimes.iter().any(|r| {
            // Direct contains check (backwards compatible)
            if image.contains(r) {
                return true;
            }
            // Check if image matches the expanded form of this runtime
            let expanded = self.expand_runtime_name(r);
            image == expanded
        })
    }

    /// Detect the official OpenRuntimes static image (always allowed)
    fn is_static_runtime_image(image: &str) -> bool {
        let img = image.to_ascii_lowercase();
        if let Some(rest) = img.strip_prefix("openruntimes/static") {
            return rest.is_empty() || rest.starts_with(':');
        }
        false
    }

    /// Get a random network from the configured networks
    pub fn random_network(&self) -> Option<&str> {
        if self.networks.is_empty() {
            None
        } else {
            use rand::Rng;
            let idx = rand::rng().random_range(0..self.networks.len());
            Some(&self.networks[idx])
        }
    }

    /// Expand a shorthand runtime name to a full image reference
    /// OpenRuntimes format: openruntimes/{runtime}:{version}-{runtime_version}
    /// Examples:
    ///   "node-22" -> "openruntimes/node:v5-22"
    ///   "node-20.0" -> "openruntimes/node:v5-20.0"
    ///   "python-3.11" -> "openruntimes/python:v5-3.11"
    ///   "openruntimes/node:v5-22" -> "openruntimes/node:v5-22" (unchanged)
    ///   "myregistry/custom:latest" -> "myregistry/custom:latest" (unchanged)
    pub fn expand_runtime_name(&self, name: &str) -> String {
        let default_version = self
            .runtime_versions
            .first()
            .map(|s| s.as_str())
            .unwrap_or("v5");

        if name.contains(':') {
            // Already has a tag, use as-is
            name.to_string()
        } else if name.contains('/') {
            // Has registry/namespace but no tag, add default version
            format!("{}:{}", name, default_version)
        } else if let Some((runtime, runtime_version)) = name.split_once('-') {
            // Shorthand like "node-22" -> "openruntimes/node:v5-22"
            format!(
                "openruntimes/{}:{}-{}",
                runtime, default_version, runtime_version
            )
        } else {
            // Just a runtime name without version, use as-is with version tag
            format!("openruntimes/{}:{}", name, default_version)
        }
    }

    /// Get expanded runtime names for warmup
    /// Converts shorthand names to full image references
    pub fn expanded_runtimes(&self) -> Vec<String> {
        self.allowed_runtimes
            .iter()
            .map(|r| self.expand_runtime_name(r))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apply_min_resources() {
        let mut config = ExecutorConfig::from_env();
        config.min_cpus = 2.0;
        config.min_memory = 1024;

        // Below minimum - should be raised
        let (cpus, mem) = config.apply_min_resources(0.5, 512);
        assert_eq!(cpus, 2.0);
        assert_eq!(mem, 1024);

        // Above minimum - should stay as-is
        let (cpus, mem) = config.apply_min_resources(4.0, 2048);
        assert_eq!(cpus, 4.0);
        assert_eq!(mem, 2048);
    }

    #[test]
    fn test_is_runtime_allowed_empty() {
        let mut config = ExecutorConfig::from_env();
        config.allowed_runtimes = vec![];
        assert!(config.is_runtime_allowed("any-image"));
    }

    #[test]
    fn test_is_runtime_allowed_with_list() {
        let mut config = ExecutorConfig::from_env();
        config.runtime_versions = vec!["v5".to_string()];
        config.allowed_runtimes = vec!["node-22".to_string(), "python-3.11".to_string()];

        // Expanded format (what Appwrite sends)
        assert!(config.is_runtime_allowed("openruntimes/node:v5-22"));
        assert!(config.is_runtime_allowed("openruntimes/python:v5-3.11"));

        // Contains match (backwards compatible)
        assert!(config.is_runtime_allowed("something-with-node-22-in-it"));

        // Not allowed
        assert!(!config.is_runtime_allowed("openruntimes/ruby:v5-3.2"));
        assert!(!config.is_runtime_allowed("openruntimes/node:v5-20.0"));
    }

    #[test]
    fn test_is_runtime_allowed_static_always() {
        let mut config = ExecutorConfig::from_env();
        config.runtime_versions = vec!["v5".to_string()];
        config.allowed_runtimes = vec!["node-22".to_string()];

        // Static runtime should always be allowed, even if not in allowlist
        assert!(config.is_runtime_allowed("openruntimes/static:v5-1"));
        assert!(config.is_runtime_allowed("openruntimes/static"));
    }

    #[test]
    fn test_parse_size() {
        // Raw bytes
        assert_eq!(parse_size("1024"), Some(1024));
        assert_eq!(parse_size("20971520"), Some(20971520));

        // KB
        assert_eq!(parse_size("1KB"), Some(1024));
        assert_eq!(parse_size("1K"), Some(1024));
        assert_eq!(parse_size("512kb"), Some(512 * 1024));

        // MB
        assert_eq!(parse_size("1MB"), Some(1024 * 1024));
        assert_eq!(parse_size("1M"), Some(1024 * 1024));
        assert_eq!(parse_size("20MB"), Some(20 * 1024 * 1024));
        assert_eq!(parse_size("20mb"), Some(20 * 1024 * 1024));

        // GB
        assert_eq!(parse_size("1GB"), Some(1024 * 1024 * 1024));
        assert_eq!(parse_size("1G"), Some(1024 * 1024 * 1024));
        assert_eq!(parse_size("2gb"), Some(2 * 1024 * 1024 * 1024));

        // With whitespace
        assert_eq!(parse_size(" 20MB "), Some(20 * 1024 * 1024));
        assert_eq!(parse_size("20 MB"), Some(20 * 1024 * 1024));

        // Invalid
        assert_eq!(parse_size("invalid"), None);
        assert_eq!(parse_size("20TB"), None);
    }

    #[test]
    fn test_expand_runtime_name() {
        let mut config = ExecutorConfig::from_env();
        config.runtime_versions = vec!["v5".to_string()];

        // Shorthand -> openruntimes/{runtime}:{version}-{runtime_version}
        assert_eq!(
            config.expand_runtime_name("node-22"),
            "openruntimes/node:v5-22"
        );
        assert_eq!(
            config.expand_runtime_name("node-20.0"),
            "openruntimes/node:v5-20.0"
        );
        assert_eq!(
            config.expand_runtime_name("python-3.11"),
            "openruntimes/python:v5-3.11"
        );

        // With namespace but no tag -> add version
        assert_eq!(
            config.expand_runtime_name("openruntimes/node"),
            "openruntimes/node:v5"
        );
        assert_eq!(
            config.expand_runtime_name("myregistry/custom"),
            "myregistry/custom:v5"
        );

        // Already has tag -> unchanged
        assert_eq!(
            config.expand_runtime_name("openruntimes/node:v5-22"),
            "openruntimes/node:v5-22"
        );
        assert_eq!(
            config.expand_runtime_name("myregistry/custom:latest"),
            "myregistry/custom:latest"
        );
    }

    #[test]
    fn test_expanded_runtimes() {
        let mut config = ExecutorConfig::from_env();
        config.runtime_versions = vec!["v5".to_string()];
        config.allowed_runtimes = vec![
            "node-22".to_string(),
            "python-3.11".to_string(),
            "openruntimes/bun:v4-1.0".to_string(),
        ];

        let expanded = config.expanded_runtimes();
        assert_eq!(expanded.len(), 3);
        assert_eq!(expanded[0], "openruntimes/node:v5-22");
        assert_eq!(expanded[1], "openruntimes/python:v5-3.11");
        assert_eq!(expanded[2], "openruntimes/bun:v4-1.0"); // Already had tag, unchanged
    }
}
