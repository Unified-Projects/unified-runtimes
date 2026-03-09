//! Configuration for the URT Executor
//!
//! Environment variable priority:
//! 1. URT_* variables (new branding)
//! 2. OPR_EXECUTOR_* variables (backwards compatibility)
//!
//! This allows existing OpenRuntimes deployments to work as drop-in replacements
//! while new deployments can use the URT prefix.

use std::collections::HashSet;
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

fn parse_bool_flag(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on" | "enabled"
    )
}

fn dedupe_preserve_order(values: Vec<String>) -> Vec<String> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut deduped = Vec::with_capacity(values.len());

    for value in values {
        if seen.insert(value.clone()) {
            deduped.push(value);
        }
    }

    deduped
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OfficialRuntime {
    family: &'static str,
    latest_image: &'static str,
}

// Verified against Docker Hub on 2026-03-09.
const OFFICIAL_RUNTIMES: &[OfficialRuntime] = &[
    OfficialRuntime {
        family: "bun",
        latest_image: "openruntimes/bun:v5-1.3",
    },
    OfficialRuntime {
        family: "dart",
        latest_image: "openruntimes/dart:v5-3.10",
    },
    OfficialRuntime {
        family: "deno",
        latest_image: "openruntimes/deno:v5-2.6",
    },
    OfficialRuntime {
        family: "dotnet",
        latest_image: "openruntimes/dotnet:v5-10",
    },
    OfficialRuntime {
        family: "node",
        latest_image: "openruntimes/node:v5-25",
    },
    OfficialRuntime {
        family: "php",
        latest_image: "openruntimes/php:v5-8.4",
    },
    OfficialRuntime {
        family: "python",
        latest_image: "openruntimes/python:v5-3.14",
    },
    OfficialRuntime {
        family: "ruby",
        latest_image: "openruntimes/ruby:v5-4.0",
    },
    OfficialRuntime {
        family: "static",
        latest_image: "openruntimes/static:v5-1",
    },
];

fn official_runtime_by_family(family: &str) -> Option<&'static OfficialRuntime> {
    OFFICIAL_RUNTIMES
        .iter()
        .find(|runtime| runtime.family == family)
}

fn parse_supported_runtime_family(image: &str) -> Option<&'static str> {
    let trimmed = image.trim();

    if trimmed.is_empty() {
        return None;
    }

    if let Some(rest) = trimmed.strip_prefix("openruntimes/") {
        let repository = rest.split(':').next().unwrap_or(rest);
        return official_runtime_by_family(repository).map(|runtime| runtime.family);
    }

    if trimmed.contains('/') || trimmed.contains(':') {
        return None;
    }

    if let Some(runtime) = official_runtime_by_family(trimmed) {
        return Some(runtime.family);
    }

    let (family, _) = trimmed.split_once('-')?;
    official_runtime_by_family(family).map(|runtime| runtime.family)
}

fn is_official_runtime_image(image: &str) -> bool {
    parse_supported_runtime_family(image).is_some()
}

fn image_tag_numbers(image: &str) -> Vec<u32> {
    image
        .rsplit_once(':')
        .map(|(_, tag)| tag)
        .unwrap_or("")
        .split(|c: char| !c.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .filter_map(|part| part.parse::<u32>().ok())
        .collect()
}

/// Main configuration for the executor
#[derive(Debug, Clone)]
pub struct ExecutorConfig {
    // Server configuration
    pub host: String,
    pub port: u16,
    pub secret: String,
    pub metrics_enabled: bool,

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
    pub auto_runtime: bool,

    // Resource overrides (URT enhancement)
    pub min_cpus: f64,
    pub min_memory: u64, // MB

    // Lifecycle configuration
    pub keep_alive: bool,
    pub inactive_threshold: u64,   // seconds
    pub maintenance_interval: u64, // seconds
    pub autoscale: bool,
    pub max_concurrent_executions: Option<usize>,
    pub max_concurrent_runtime_creates: Option<usize>,
    pub execution_queue_wait_ms: u64,
    pub runtime_create_queue_wait_ms: u64,

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
            metrics_enabled: env_urt_or_opr("METRICS")
                .map(|v| parse_bool_flag(&v))
                .unwrap_or(false),

            // Environment mode
            env: env_urt_or_opr_default("ENV", "production"),

            // Docker
            networks: dedupe_preserve_order(
                env_urt_or_opr_default("NETWORK", "openruntimes-runtimes")
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect(),
            ),
            hostname,
            docker_hub_username: env_urt_or_opr("DOCKER_HUB_USERNAME").filter(|s| !s.is_empty()),
            docker_hub_password: env_urt_or_opr("DOCKER_HUB_PASSWORD").filter(|s| !s.is_empty()),

            // Runtimes
            allowed_runtimes: dedupe_preserve_order(
                env_urt_or_opr("RUNTIMES")
                    .or_else(|| env_urt_or_opr("IMAGES"))
                    .unwrap_or_default()
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.trim().to_string())
                    .collect(),
            ),
            runtime_versions: dedupe_preserve_order(
                env_urt_or_opr_default("RUNTIME_VERSIONS", "v5")
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect(),
            ),
            image_pull_enabled: env_urt_or_opr("IMAGE_PULL")
                .map(|v| v.to_lowercase() != "disabled")
                .unwrap_or(true),
            auto_runtime: env_urt_or_opr("AUTO_RUNTIME")
                .map(|v| v.to_lowercase() != "false")
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
            autoscale: env_urt_or_opr("AUTOSCALE")
                .map(|v| parse_bool_flag(&v))
                .unwrap_or(false),
            max_concurrent_executions: env_urt_or_opr("MAX_CONCURRENT_EXECUTIONS")
                .and_then(|v| v.parse::<usize>().ok())
                .filter(|v| *v > 0),
            max_concurrent_runtime_creates: env_urt_or_opr("MAX_CONCURRENT_RUNTIME_CREATES")
                .and_then(|v| v.parse::<usize>().ok())
                .filter(|v| *v > 0),
            execution_queue_wait_ms: env_urt_or_opr("EXECUTION_QUEUE_WAIT_MS")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(2_000)
                .max(1),
            runtime_create_queue_wait_ms: env_urt_or_opr("RUNTIME_CREATE_QUEUE_WAIT_MS")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(5_000)
                .max(1),

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
        if self.auto_runtime && is_official_runtime_image(image) {
            return true;
        }

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
        let default_version = self.default_runtime_version();

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

    fn default_runtime_version(&self) -> &str {
        self.runtime_versions
            .first()
            .map(|s| s.as_str())
            .unwrap_or("v5")
    }

    fn latest_allowed_official_image(&self, family: &str) -> Option<String> {
        let mut allowed_images: Vec<String> = self
            .allowed_runtimes
            .iter()
            .map(|image| self.normalize_runtime_image(image))
            .filter(|image| {
                image.starts_with("openruntimes/")
                    && parse_supported_runtime_family(image) == Some(family)
            })
            .collect();

        allowed_images.sort_by_key(|left| image_tag_numbers(left));
        allowed_images.pop()
    }

    fn preferred_official_image(&self, family: &str) -> Option<String> {
        if self.auto_runtime || self.allowed_runtimes.is_empty() {
            official_runtime_by_family(family).map(|runtime| runtime.latest_image.to_string())
        } else {
            self.latest_allowed_official_image(family)
        }
    }

    fn detect_runtime_family(
        &self,
        requested_family: Option<&'static str>,
        entrypoint: &str,
        runtime_entrypoint: &str,
        command: &str,
    ) -> Option<&'static str> {
        let command_context = format!(
            " {} {} ",
            runtime_entrypoint.to_ascii_lowercase(),
            command.to_ascii_lowercase()
        );

        if requested_family.is_some()
            && (command_context.contains("/usr/local/server/helpers/")
                || command_context.contains("helpers/build.sh"))
        {
            return requested_family;
        }

        for (family, markers) in [
            ("bun", &["bun ", "bunx "][..]),
            ("deno", &["deno ", "denon "][..]),
            (
                "php",
                &["composer ", "composer.phar", "php ", "artisan "][..],
            ),
            ("dotnet", &["dotnet ", "nuget "][..]),
            (
                "ruby",
                &["bundle ", "bundler ", "gem ", "ruby ", "rake ", "rails "][..],
            ),
            (
                "dart",
                &["dart ", "flutter pub ", "flutter run ", "flutter build "][..],
            ),
            (
                "python",
                &[
                    "python ",
                    "python3 ",
                    "pip ",
                    "pip3 ",
                    "pytest ",
                    "uv ",
                    "poetry ",
                    "gunicorn ",
                    "uvicorn ",
                    "flask ",
                    "django-admin ",
                ][..],
            ),
            (
                "node",
                &[
                    "npm ", "npx ", "pnpm ", "pnpx ", "yarn ", "node ", "tsx ", "ts-node ",
                ][..],
            ),
        ] {
            if markers
                .iter()
                .any(|marker| command_context.contains(marker))
            {
                return Some(family);
            }
        }

        let entrypoint = entrypoint.trim().to_ascii_lowercase();

        if entrypoint.ends_with(".php") {
            return Some("php");
        }
        if entrypoint.ends_with(".py") {
            return Some("python");
        }
        if entrypoint.ends_with(".rb") {
            return Some("ruby");
        }
        if entrypoint.ends_with(".dart") {
            return Some("dart");
        }
        if entrypoint.ends_with(".cs") || entrypoint.ends_with(".fs") || entrypoint.ends_with(".vb")
        {
            return Some("dotnet");
        }
        if entrypoint.ends_with(".js")
            || entrypoint.ends_with(".cjs")
            || entrypoint.ends_with(".mjs")
        {
            return match requested_family {
                Some("bun") => Some("bun"),
                Some("node") => Some("node"),
                Some("static") => Some("static"),
                _ => Some("node"),
            };
        }
        if entrypoint.ends_with(".ts") {
            return match requested_family {
                Some("bun") => Some("bun"),
                Some("deno") => Some("deno"),
                Some("node") => Some("node"),
                _ => None,
            };
        }

        requested_family
    }

    pub fn normalize_runtime_image(&self, image: &str) -> String {
        let trimmed = image.trim();

        if trimmed.is_empty() {
            return String::new();
        }

        if (trimmed.starts_with("openruntimes/") || !trimmed.contains('/'))
            && parse_supported_runtime_family(trimmed).is_some()
        {
            return self.expand_runtime_name(trimmed);
        }

        trimmed.to_string()
    }

    pub fn resolve_runtime_image(
        &self,
        image: &str,
        entrypoint: &str,
        runtime_entrypoint: &str,
        command: &str,
    ) -> String {
        let normalized_image = self.normalize_runtime_image(image);

        if !self.auto_runtime {
            return normalized_image;
        }

        let requested_family = parse_supported_runtime_family(image)
            .or_else(|| parse_supported_runtime_family(&normalized_image));
        let auto_managed_image = image.trim().is_empty() || requested_family.is_some();
        let detected_family =
            self.detect_runtime_family(requested_family, entrypoint, runtime_entrypoint, command);

        if auto_managed_image {
            if let Some(family) = detected_family {
                if let Some(image) = self.preferred_official_image(family) {
                    return image;
                }
            }

            if let Some(family) = requested_family {
                if let Some(image) = self.preferred_official_image(family) {
                    return image;
                }
            }
        }

        normalized_image
    }

    /// Get expanded runtime names for warmup
    /// Converts shorthand names to full image references
    pub fn expanded_runtimes(&self) -> Vec<String> {
        dedupe_preserve_order(
            self.allowed_runtimes
                .iter()
                .map(|r| self.expand_runtime_name(r))
                .collect(),
        )
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
    fn test_is_runtime_allowed_auto_runtime_bypasses_allowlist_for_official_images() {
        let mut config = ExecutorConfig::from_env();
        config.auto_runtime = true;
        config.allowed_runtimes = vec!["php-8.4".to_string()];

        assert!(config.is_runtime_allowed("openruntimes/node:v5-25"));
        assert!(config.is_runtime_allowed("openruntimes/bun:v5-1.3"));
        assert!(!config.is_runtime_allowed("custom/runtime:latest"));
    }

    #[test]
    fn test_is_runtime_allowed_with_list() {
        let mut config = ExecutorConfig::from_env();
        config.auto_runtime = false;
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
    fn test_parse_bool_flag() {
        assert!(parse_bool_flag("1"));
        assert!(parse_bool_flag("true"));
        assert!(parse_bool_flag("yes"));
        assert!(parse_bool_flag("on"));
        assert!(parse_bool_flag("enabled"));
        assert!(!parse_bool_flag("0"));
        assert!(!parse_bool_flag("false"));
        assert!(!parse_bool_flag("disabled"));
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

    #[test]
    fn test_expanded_runtimes_deduplicated() {
        let mut config = ExecutorConfig::from_env();
        config.runtime_versions = vec!["v5".to_string()];
        config.allowed_runtimes = vec![
            "node-22".to_string(),
            "node-22".to_string(),
            "openruntimes/node:v5-22".to_string(),
            "python-3.11".to_string(),
        ];

        let expanded = config.expanded_runtimes();
        assert_eq!(expanded.len(), 2);
        assert_eq!(expanded[0], "openruntimes/node:v5-22");
        assert_eq!(expanded[1], "openruntimes/python:v5-3.11");
    }

    #[test]
    fn test_normalize_runtime_image_supported_shorthand() {
        let mut config = ExecutorConfig::from_env();
        config.runtime_versions = vec!["v5".to_string()];

        assert_eq!(
            config.normalize_runtime_image("node-22"),
            "openruntimes/node:v5-22"
        );
        assert_eq!(
            config.normalize_runtime_image("node"),
            "openruntimes/node:v5"
        );
        assert_eq!(
            config.normalize_runtime_image("openruntimes/php"),
            "openruntimes/php:v5"
        );
    }

    #[test]
    fn test_resolve_runtime_image_auto_upgrades_requested_family() {
        let mut config = ExecutorConfig::from_env();
        config.auto_runtime = true;
        config.allowed_runtimes = vec![];

        assert_eq!(
            config.resolve_runtime_image("node-22", "index.js", "", ""),
            "openruntimes/node:v5-25"
        );
    }

    #[test]
    fn test_resolve_runtime_image_auto_switches_family_from_commands() {
        let mut config = ExecutorConfig::from_env();
        config.auto_runtime = true;
        config.allowed_runtimes = vec![];

        assert_eq!(
            config.resolve_runtime_image("node-22", "index.js", "", "bun install"),
            "openruntimes/bun:v5-1.3"
        );
    }

    #[test]
    fn test_resolve_runtime_image_keeps_requested_family_for_helper_scaffolded_builds() {
        let mut config = ExecutorConfig::from_env();
        config.auto_runtime = true;
        config.allowed_runtimes = vec![];

        assert_eq!(
            config.resolve_runtime_image(
                "node-22",
                "index.js",
                "",
                "tar -zxf /tmp/code.tar.gz -C /mnt/code && helpers/build.sh 'source /usr/local/server/helpers/next-js/env.sh && bun install && bun run build'"
            ),
            "openruntimes/node:v5-25"
        );
    }

    #[test]
    fn test_resolve_runtime_image_prefers_latest_allowed_official_image() {
        let mut config = ExecutorConfig::from_env();
        config.auto_runtime = false;
        config.allowed_runtimes = vec!["node-22".to_string(), "node-24".to_string()];

        assert_eq!(
            config.preferred_official_image("node").as_deref(),
            Some("openruntimes/node:v5-24")
        );
    }

    #[test]
    fn test_resolve_runtime_image_auto_runtime_ignores_allowlist_pin() {
        let mut config = ExecutorConfig::from_env();
        config.auto_runtime = true;
        config.allowed_runtimes = vec!["node-22".to_string()];

        assert_eq!(
            config.resolve_runtime_image("node-22", "index.js", "", "npm install"),
            "openruntimes/node:v5-25"
        );
    }

    #[test]
    fn test_resolve_runtime_image_keeps_custom_images() {
        let mut config = ExecutorConfig::from_env();
        config.auto_runtime = true;
        config.allowed_runtimes = vec![];

        assert_eq!(
            config.resolve_runtime_image("custom/runtime:latest", "index.js", "", "bun install"),
            "custom/runtime:latest"
        );
    }

    #[test]
    fn test_resolve_runtime_image_uses_entrypoint_when_image_missing() {
        let mut config = ExecutorConfig::from_env();
        config.auto_runtime = true;
        config.allowed_runtimes = vec![];

        assert_eq!(
            config.resolve_runtime_image("", "index.php", "", ""),
            "openruntimes/php:v5-8.4"
        );
    }
}
