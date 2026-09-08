//! Configuration for the URT Executor
//!
//! Environment variable priority:
//! 1. URT_* variables (new branding)
//! 2. OPR_EXECUTOR_* variables (backwards compatibility)
//!
//! This allows existing OpenRuntimes deployments to work as drop-in replacements
//! while new deployments can use the URT prefix.

use crate::runtime::{DEFAULT_INACTIVE_THRESHOLD_SECS, DEFAULT_STARTUP_TIMEOUT_SECS};
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

/// Docker Hub namespace that publishes the official OpenRuntimes images.
const DEFAULT_RUNTIME_NAMESPACE: &str = "openruntimes";

/// Tag generation the runtime table describes. Tags are `<generation>-<version>`.
const OFFICIAL_RUNTIME_GENERATION: &str = "v5";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OfficialRuntime {
    family: &'static str,
    /// Published `v5-*` versions, newest first.
    versions: &'static [&'static str],
}

impl OfficialRuntime {
    fn latest_version(&self) -> Option<&'static str> {
        self.versions.first().copied()
    }

    /// Map a caller-supplied version onto a published tag.
    ///
    /// An exact match wins. Otherwise the newest version whose leading
    /// dot-separated components match is used, so `node-20` reaches the
    /// published `v5-20.0` tag and `java-21` reaches `v5-21.0`.
    fn resolve_version(&self, requested: &str) -> Option<&'static str> {
        if requested.is_empty() {
            return self.latest_version();
        }

        if let Some(exact) = self.versions.iter().find(|version| **version == requested) {
            return Some(exact);
        }

        self.versions
            .iter()
            .find(|version| {
                version
                    .strip_prefix(requested)
                    .is_some_and(|rest| rest.starts_with('.'))
            })
            .copied()
    }
}

// Verified against Docker Hub on 2026-09-08.
// Regenerate with `python scripts/refresh-runtime-table.py`.
const OFFICIAL_RUNTIMES: &[OfficialRuntime] = &[
    OfficialRuntime {
        family: "bun",
        versions: &["1.4", "1.3", "1.2", "1.1", "1.0"],
    },
    OfficialRuntime {
        family: "cpp",
        versions: &["23", "20", "17"],
    },
    OfficialRuntime {
        family: "dart",
        versions: &[
            "3.13", "3.12", "3.11", "3.10", "3.9", "3.8", "3.5", "3.3", "3.1", "3.0", "2.19",
            "2.18", "2.17", "2.16", "2.15",
        ],
    },
    OfficialRuntime {
        family: "deno",
        versions: &["2.6", "2.5", "2.0", "1.46", "1.40", "1.35", "1.24", "1.21"],
    },
    OfficialRuntime {
        family: "dotnet",
        versions: &["10", "8.0", "7.0", "6.0"],
    },
    OfficialRuntime {
        family: "flutter",
        versions: &[
            "3.47", "3.44", "3.41", "3.38", "3.35", "3.32", "3.29", "3.27", "3.24",
        ],
    },
    OfficialRuntime {
        family: "go",
        versions: &["1.26", "1.25", "1.24", "1.23"],
    },
    OfficialRuntime {
        family: "java",
        versions: &["25", "22", "21.0", "18.0", "17.0", "11.0", "8.0"],
    },
    OfficialRuntime {
        family: "kotlin",
        versions: &["2.3", "2.0", "1.9", "1.8", "1.6"],
    },
    OfficialRuntime {
        family: "node",
        versions: &[
            "26", "25", "24", "23", "22", "21.0", "20.0", "19.0", "18.0", "16.0", "14.5",
        ],
    },
    OfficialRuntime {
        family: "php",
        versions: &["8.4", "8.3", "8.2", "8.1", "8.0"],
    },
    OfficialRuntime {
        family: "python",
        versions: &["3.14", "3.13", "3.12", "3.11", "3.10", "3.9", "3.8"],
    },
    OfficialRuntime {
        family: "python-ml",
        versions: &["3.13", "3.12", "3.11"],
    },
    OfficialRuntime {
        family: "ruby",
        versions: &["4.0", "3.4", "3.3", "3.2", "3.1", "3.0"],
    },
    OfficialRuntime {
        family: "rust",
        versions: &["1.83"],
    },
    OfficialRuntime {
        family: "static",
        versions: &["1"],
    },
    OfficialRuntime {
        family: "swift",
        versions: &["6.2", "5.10", "5.9", "5.8"],
    },
];

fn official_runtime_by_family(family: &str) -> Option<&'static OfficialRuntime> {
    OFFICIAL_RUNTIMES
        .iter()
        .find(|runtime| runtime.family == family)
}

/// Split a shorthand such as `node-22` or `python-ml-3.13` into its family and
/// requested version. The longest matching family name wins, so `python-ml`
/// is not read as the `python` family at version `ml`.
fn split_official_shorthand(name: &str) -> Option<(&'static OfficialRuntime, &str)> {
    let mut best: Option<(&'static OfficialRuntime, &str)> = None;

    for runtime in OFFICIAL_RUNTIMES {
        let version = if name == runtime.family {
            ""
        } else if let Some(rest) = name
            .strip_prefix(runtime.family)
            .and_then(|rest| rest.strip_prefix('-'))
        {
            rest
        } else {
            continue;
        };

        if best.is_none_or(|(current, _)| current.family.len() < runtime.family.len()) {
            best = Some((runtime, version));
        }
    }

    best
}

/// True when a caller-requested family is a more specific form of the family
/// that entrypoint or command detection found, so the request is kept.
fn family_covers(requested: &str, detected: &str) -> bool {
    requested == detected
        || matches!(
            (requested, detected),
            ("python-ml", "python") | ("flutter", "dart")
        )
}

fn reconcile_family(requested: Option<&'static str>, detected: &'static str) -> &'static str {
    match requested {
        Some(requested) if family_covers(requested, detected) => requested,
        _ => detected,
    }
}

/// Command fragments that identify a runtime family, most specific first.
const COMMAND_MARKERS: &[(&str, &[&str])] = &[
    ("flutter", &["flutter ", "flutter/bin"]),
    ("bun", &["bun ", "bunx "]),
    ("deno", &["deno ", "denon "]),
    ("php", &["composer ", "composer.phar", "php ", "artisan "]),
    ("dotnet", &["dotnet ", "nuget "]),
    (
        "ruby",
        &["bundle ", "bundler ", "gem ", "ruby ", "rake ", "rails "],
    ),
    ("dart", &["dart ", "pub get"]),
    ("rust", &["cargo ", "cargo.toml", "rustc ", "rustup "]),
    (
        "go",
        &[
            "go build",
            "go run ",
            "go mod ",
            "go get ",
            "go test ",
            "go install ",
            "gofmt ",
        ],
    ),
    ("swift", &["swift ", "swiftc ", "package.swift"]),
    ("kotlin", &["gradlew", "kotlinc ", "kotlin "]),
    // Plain `gradle` is deliberately absent: Kotlin and Java both use it, so a
    // caller that asked for either keeps the family it asked for.
    ("java", &["javac ", "java ", "mvn ", "maven "]),
    ("cpp", &["cmake ", "cmakelists", "g++ ", "clang++ "]),
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
        ],
    ),
    (
        "node",
        &[
            "npm ", "npx ", "pnpm ", "pnpx ", "yarn ", "node ", "tsx ", "ts-node ",
        ],
    ),
];

/// Entrypoint file extensions that identify a runtime family. `.js` and `.ts`
/// are handled separately because several families share them.
const ENTRYPOINT_EXTENSIONS: &[(&str, &[&str])] = &[
    ("php", &[".php"]),
    ("python", &[".py"]),
    ("ruby", &[".rb"]),
    ("dart", &[".dart"]),
    ("dotnet", &[".cs", ".fs", ".vb"]),
    ("go", &[".go"]),
    ("rust", &[".rs"]),
    ("swift", &[".swift"]),
    ("kotlin", &[".kt", ".kts"]),
    ("java", &[".java"]),
    ("cpp", &[".cc", ".cpp", ".cxx", ".c++", ".hpp", ".hh"]),
];

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
    /// Registry host preferred for auto-resolved official runtimes.
    /// Empty means Docker Hub.
    pub runtime_registry: String,
    /// Namespace preferred for auto-resolved official runtimes.
    pub runtime_namespace: String,
    /// Families served from the preferred namespace. Empty means all of them.
    pub runtime_namespace_families: Vec<String>,

    // Resource overrides (URT enhancement)
    pub min_cpus: f64,
    pub min_memory: u64, // MB

    // Lifecycle configuration
    pub keep_alive: bool,
    /// Default seconds of inactivity before a runtime is reclaimed. A runtime
    /// created with `inactiveThreshold` overrides this for itself.
    pub inactive_threshold: u64, // seconds
    /// Default seconds a runtime has to start listening before it is marked
    /// failed. A runtime created with `startupTimeout` overrides this.
    pub startup_timeout_secs: u64,
    /// Default cap on executions in flight against a single runtime. `None` is
    /// unlimited. A runtime created with `maxConcurrency` overrides this.
    pub runtime_max_concurrency: Option<usize>,
    pub maintenance_interval: u64, // seconds
    pub autoscale: bool,
    pub eager_runtime_readiness: bool,
    pub max_concurrent_executions: Option<usize>,
    pub max_concurrent_runtime_creates: Option<usize>,
    /// Permits for build-style creates (a create carrying a build command, or
    /// one that removes its container afterwards). Separate from the serve-style
    /// limit so a run of builds cannot starve cold starts.
    pub max_concurrent_builds: Option<usize>,
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

    /// When true, the server waits for warmup to complete before accepting requests.
    pub warmup_required: bool,

    /// Maximum seconds a request is allowed to block waiting for a pending
    /// runtime to become ready.  Applies as a cap on top of (not instead of)
    /// the per-request deadline.  Defaults to 60 seconds.
    pub pending_wait_max_secs: u64,

    /// Age in seconds after which maintenance reaps a pending registry entry
    /// that has no build behind it.  Entries whose create is still in flight are
    /// never reaped, whatever their age.  Defaults to 300 seconds.
    pub pending_max_age_secs: u64,

    /// How long, in milliseconds, a failed adoption attempt is remembered so
    /// that repeated requests for an unknown runtime ID do not each cost a
    /// Docker inspect.  Zero disables the cache.  Defaults to 2000 ms.
    pub adoption_negative_cache_ms: u64,

    /// Subscribe to Docker container events so a runtime death is noticed the
    /// moment the daemon reports it. Defaults to true.
    pub docker_events: bool,

    /// Cap in seconds on the backoff between executor-initiated recreates of a
    /// runtime that keeps dying (1s, 2s, 4s ... up to this). Defaults to 30.
    pub restart_backoff_max_secs: u64,

    /// Deaths inside `crash_loop_window_secs` that put a runtime into
    /// quarantine. Defaults to 3.
    pub crash_loop_threshold: u32,

    /// Window in seconds over which deaths are counted. Defaults to 60.
    pub crash_loop_window_secs: u64,

    /// How long a crash-looping runtime stays quarantined, in seconds.
    /// Defaults to 300.
    pub quarantine_secs: u64,
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
            runtime_registry: env_urt_or_opr("RUNTIME_REGISTRY")
                .map(|v| v.trim().trim_matches('/').to_string())
                .unwrap_or_default(),
            runtime_namespace: env_urt_or_opr("RUNTIME_NAMESPACE")
                .map(|v| v.trim().trim_matches('/').to_string())
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| DEFAULT_RUNTIME_NAMESPACE.to_string()),
            runtime_namespace_families: dedupe_preserve_order(
                env_urt_or_opr("RUNTIME_NAMESPACE_FAMILIES")
                    .unwrap_or_default()
                    .split(',')
                    .map(|s| s.trim().to_ascii_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect(),
            ),

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
                .unwrap_or(DEFAULT_INACTIVE_THRESHOLD_SECS),
            startup_timeout_secs: env_urt_or_opr("STARTUP_TIMEOUT_SECS")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(DEFAULT_STARTUP_TIMEOUT_SECS)
                .max(1),
            runtime_max_concurrency: env_urt_or_opr("RUNTIME_MAX_CONCURRENCY")
                .and_then(|v| v.parse::<usize>().ok())
                .filter(|v| *v > 0),
            maintenance_interval: env_urt_or_opr("MAINTENANCE_INTERVAL")
                .and_then(|v| v.parse().ok())
                .unwrap_or(3600),
            autoscale: env_urt_or_opr("AUTOSCALE")
                .map(|v| parse_bool_flag(&v))
                .unwrap_or(false),
            eager_runtime_readiness: env_urt_or_opr("EAGER_RUNTIME_READINESS")
                .map(|v| parse_bool_flag(&v))
                .unwrap_or(false),
            max_concurrent_executions: env_urt_or_opr("MAX_CONCURRENT_EXECUTIONS")
                .and_then(|v| v.parse::<usize>().ok())
                .filter(|v| *v > 0),
            max_concurrent_runtime_creates: env_urt_or_opr("MAX_CONCURRENT_RUNTIME_CREATES")
                .and_then(|v| v.parse::<usize>().ok())
                .filter(|v| *v > 0),
            max_concurrent_builds: env_urt_or_opr("MAX_CONCURRENT_BUILDS")
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

            // Warmup
            warmup_required: env_urt_or_opr("WARMUP_REQUIRED")
                .map(|v| parse_bool_flag(&v))
                .unwrap_or(false),

            // Pending-runtime readiness wait cap
            pending_wait_max_secs: env_urt_or_opr("PENDING_WAIT_MAX_SECS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(60)
                .max(1),

            // Age at which an orphaned pending entry is reaped by maintenance
            pending_max_age_secs: env_urt_or_opr("PENDING_MAX_AGE_SECS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(300)
                .max(1),

            // How long a failed adoption attempt suppresses the next inspect
            adoption_negative_cache_ms: env_urt_or_opr("ADOPTION_NEGATIVE_CACHE_MS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(2000),

            // Dead-runtime detection and crash-loop protection
            docker_events: env_urt_or_opr("DOCKER_EVENTS")
                .map(|v| parse_bool_flag(&v))
                .unwrap_or(true),
            restart_backoff_max_secs: env_urt_or_opr("RESTART_BACKOFF_MAX_SECS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(30)
                .max(1),
            crash_loop_threshold: env_urt_or_opr("CRASH_LOOP_THRESHOLD")
                .and_then(|v| v.parse().ok())
                .unwrap_or(3)
                .max(1),
            crash_loop_window_secs: env_urt_or_opr("CRASH_LOOP_WINDOW_SECS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(60)
                .max(1),
            quarantine_secs: env_urt_or_opr("QUARANTINE_SECS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(300)
                .max(1),
        }
    }

    /// The lifecycle knobs a runtime gets when the request sets none of its own.
    pub fn runtime_lifecycle_defaults(&self) -> crate::runtime::RuntimeLifecycle {
        crate::runtime::RuntimeLifecycle {
            startup_timeout: self.startup_timeout_secs,
            inactive_threshold: self.inactive_threshold,
            max_concurrency: self.runtime_max_concurrency,
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
        let family = self.supported_runtime_family(image);

        if self.auto_runtime && family.is_some() {
            return true;
        }

        // Always allow the official static runtime for sites/assets
        if family == Some("static") {
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

    /// Expand a shorthand runtime name to a full image reference.
    ///
    /// Official families resolve through the runtime table, so a pinned
    /// shorthand lands on a published tag and a bare family name lands on the
    /// newest published version. The repository comes from the preferred
    /// namespace when one is configured for that family.
    ///
    /// Examples with the default namespace:
    ///   "node-22" -> "openruntimes/node:v5-22"
    ///   "node-20" -> "openruntimes/node:v5-20.0"
    ///   "python-3.11" -> "openruntimes/python:v5-3.11"
    ///   "openruntimes/node:v5-22" -> "openruntimes/node:v5-22" (unchanged)
    ///   "myregistry/custom:latest" -> "myregistry/custom:latest" (unchanged)
    pub fn expand_runtime_name(&self, name: &str) -> String {
        let name = name.trim();
        let generation = self.default_runtime_version();

        if name.contains(':') {
            // Already has a tag, use as-is
            return name.to_string();
        }

        if let Some((runtime, requested_version)) = self.official_shorthand(name) {
            let version = self
                .table_version(runtime, requested_version)
                .unwrap_or(requested_version);
            return self.official_image(runtime.family, version);
        }

        if name.contains('/') {
            // Has registry/namespace but no tag, add default version
            format!("{}:{}", name, generation)
        } else {
            // Unknown family without a version, keep the historical shape
            format!("{}/{}:{}", DEFAULT_RUNTIME_NAMESPACE, name, generation)
        }
    }

    fn default_runtime_version(&self) -> &str {
        self.runtime_versions
            .first()
            .map(|s| s.as_str())
            .unwrap_or(OFFICIAL_RUNTIME_GENERATION)
    }

    /// Version tags are only known for the generation the table describes; a
    /// deployment pinned to an older generation keeps whatever it asked for.
    fn table_version(
        &self,
        runtime: &'static OfficialRuntime,
        requested: &str,
    ) -> Option<&'static str> {
        if self.default_runtime_version() != OFFICIAL_RUNTIME_GENERATION {
            return None;
        }

        runtime.resolve_version(requested)
    }

    /// True when `family` should be served from the configured namespace
    /// instead of the official `openruntimes` one.
    fn uses_preferred_namespace(&self, family: &str) -> bool {
        if self.runtime_registry.is_empty() && self.runtime_namespace == DEFAULT_RUNTIME_NAMESPACE {
            return false;
        }

        self.runtime_namespace_families.is_empty()
            || self
                .runtime_namespace_families
                .iter()
                .any(|listed| listed == family)
    }

    /// Repository prefix (`<registry>/<namespace>/`) of the preferred
    /// namespace, or `None` when the default namespace is in use.
    fn preferred_repository_prefix(&self) -> Option<String> {
        if self.runtime_registry.is_empty() && self.runtime_namespace == DEFAULT_RUNTIME_NAMESPACE {
            return None;
        }

        if self.runtime_registry.is_empty() {
            Some(format!("{}/", self.runtime_namespace))
        } else {
            Some(format!(
                "{}/{}/",
                self.runtime_registry, self.runtime_namespace
            ))
        }
    }

    fn runtime_repository(&self, family: &str) -> String {
        match self.preferred_repository_prefix() {
            Some(prefix) if self.uses_preferred_namespace(family) => {
                format!("{}{}", prefix, family)
            }
            _ => format!("{}/{}", DEFAULT_RUNTIME_NAMESPACE, family),
        }
    }

    fn official_image(&self, family: &str, version: &str) -> String {
        let repository = self.runtime_repository(family);
        let generation = self.default_runtime_version();

        if version.is_empty() {
            format!("{}:{}", repository, generation)
        } else {
            format!("{}:{}-{}", repository, generation, version)
        }
    }

    /// Family and requested version of an untagged official reference, whether
    /// written as a bare shorthand (`node-22`) or with a recognised repository
    /// (`openruntimes/node`, `ghcr.io/unified-runtimes/node`).
    fn official_shorthand<'a>(&self, name: &'a str) -> Option<(&'static OfficialRuntime, &'a str)> {
        if name.is_empty() {
            return None;
        }

        if let Some(family) = name.strip_prefix(&format!("{}/", DEFAULT_RUNTIME_NAMESPACE)) {
            return official_runtime_by_family(family).map(|runtime| (runtime, ""));
        }

        if let Some(prefix) = self.preferred_repository_prefix() {
            if let Some(family) = name.strip_prefix(prefix.as_str()) {
                return official_runtime_by_family(family)
                    .filter(|runtime| self.uses_preferred_namespace(runtime.family))
                    .map(|runtime| (runtime, ""));
            }
        }

        if name.contains('/') {
            return None;
        }

        split_official_shorthand(name)
    }

    /// Family of an official runtime image, or `None` for third-party images.
    pub fn supported_runtime_family(&self, image: &str) -> Option<&'static str> {
        let trimmed = image.trim();

        if trimmed.is_empty() {
            return None;
        }

        let repository = trimmed.split(':').next().unwrap_or(trimmed);

        if repository.contains('/') {
            return self
                .official_shorthand(repository)
                .map(|(runtime, _)| runtime.family);
        }

        if trimmed.contains(':') {
            return None;
        }

        split_official_shorthand(trimmed).map(|(runtime, _)| runtime.family)
    }

    fn latest_allowed_official_image(&self, family: &str) -> Option<String> {
        let mut allowed_images: Vec<String> = self
            .allowed_runtimes
            .iter()
            .map(|image| self.normalize_runtime_image(image))
            .filter(|image| {
                image.contains('/') && self.supported_runtime_family(image) == Some(family)
            })
            .collect();

        allowed_images.sort_by_key(|left| image_tag_numbers(left));
        allowed_images.pop()
    }

    fn preferred_official_image(&self, family: &str) -> Option<String> {
        if self.auto_runtime || self.allowed_runtimes.is_empty() {
            let runtime = official_runtime_by_family(family)?;
            if let Some(version) = self.table_version(runtime, "") {
                return Some(self.official_image(family, version));
            }
        }

        self.latest_allowed_official_image(family)
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

        for (family, markers) in COMMAND_MARKERS {
            if markers
                .iter()
                .any(|marker| command_context.contains(marker))
            {
                return Some(reconcile_family(requested_family, family));
            }
        }

        let entrypoint = entrypoint.trim().to_ascii_lowercase();

        for (family, extensions) in ENTRYPOINT_EXTENSIONS {
            if extensions
                .iter()
                .any(|extension| entrypoint.ends_with(extension))
            {
                return Some(reconcile_family(requested_family, family));
            }
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

        if self.supported_runtime_family(trimmed).is_some() {
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

        let requested_family = self
            .supported_runtime_family(image)
            .or_else(|| self.supported_runtime_family(&normalized_image));
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
            "openruntimes/node:v5-26"
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
            "openruntimes/node:v5-26"
        );
        assert_eq!(
            config.normalize_runtime_image("openruntimes/php"),
            "openruntimes/php:v5-8.4"
        );
    }

    #[test]
    fn test_resolve_runtime_image_auto_upgrades_requested_family() {
        let mut config = ExecutorConfig::from_env();
        config.auto_runtime = true;
        config.allowed_runtimes = vec![];

        assert_eq!(
            config.resolve_runtime_image("node-22", "index.js", "", ""),
            "openruntimes/node:v5-26"
        );
    }

    #[test]
    fn test_resolve_runtime_image_auto_switches_family_from_commands() {
        let mut config = ExecutorConfig::from_env();
        config.auto_runtime = true;
        config.allowed_runtimes = vec![];

        assert_eq!(
            config.resolve_runtime_image("node-22", "index.js", "", "bun install"),
            "openruntimes/bun:v5-1.4"
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
            "openruntimes/node:v5-26"
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
            "openruntimes/node:v5-26"
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

    fn version_components(version: &str) -> Vec<u32> {
        version
            .split('.')
            .map(|part| part.parse::<u32>().expect("version component is numeric"))
            .collect()
    }

    fn auto_config() -> ExecutorConfig {
        let mut config = ExecutorConfig::from_env();
        config.auto_runtime = true;
        config.allowed_runtimes = vec![];
        config.runtime_versions = vec!["v5".to_string()];
        config.runtime_registry = String::new();
        config.runtime_namespace = DEFAULT_RUNTIME_NAMESPACE.to_string();
        config.runtime_namespace_families = vec![];
        config
    }

    fn namespaced_config(families: Vec<String>) -> ExecutorConfig {
        let mut config = auto_config();
        config.runtime_registry = "ghcr.io".to_string();
        config.runtime_namespace = "unified-runtimes".to_string();
        config.runtime_namespace_families = families;
        config
    }

    #[test]
    fn test_official_runtime_table_is_well_formed() {
        let mut families: Vec<&str> = Vec::new();

        for runtime in OFFICIAL_RUNTIMES {
            assert!(
                !runtime.versions.is_empty(),
                "{} has no versions",
                runtime.family
            );
            assert!(
                !families.contains(&runtime.family),
                "{} is listed twice",
                runtime.family
            );
            assert!(
                runtime
                    .family
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c == '-'),
                "{} is not a lowercase family name",
                runtime.family
            );
            families.push(runtime.family);

            assert_eq!(
                runtime.latest_version(),
                runtime.versions.first().copied(),
                "{} latest version is not the head of its version list",
                runtime.family
            );

            let mut previous: Option<Vec<u32>> = None;
            for version in runtime.versions {
                assert!(
                    !version.is_empty()
                        && version.chars().all(|c| c.is_ascii_digit() || c == '.')
                        && !version.starts_with('.')
                        && !version.ends_with('.'),
                    "{}:{} is not a well-formed version",
                    runtime.family,
                    version
                );

                let components = version_components(version);
                if let Some(previous) = previous {
                    assert!(
                        previous > components,
                        "{} versions are not ordered newest first ({:?} then {:?})",
                        runtime.family,
                        previous,
                        components
                    );
                }
                previous = Some(components);
            }
        }

        assert!(
            families.windows(2).all(|pair| pair[0] < pair[1]),
            "families are not in alphabetical order"
        );
    }

    #[test]
    fn test_official_latest_images_are_well_formed_v5_tags() {
        let config = auto_config();

        for runtime in OFFICIAL_RUNTIMES {
            let latest = runtime
                .latest_version()
                .expect("family has a latest version");
            let image = config.official_image(runtime.family, latest);

            assert_eq!(
                image,
                format!("openruntimes/{}:v5-{}", runtime.family, latest)
            );
            assert_eq!(
                config.supported_runtime_family(&image),
                Some(runtime.family)
            );
            assert!(
                runtime.versions.contains(&latest),
                "{} latest tag is missing from its version list",
                runtime.family
            );
        }
    }

    #[test]
    fn test_every_family_resolves_from_its_bare_shorthand() {
        let config = auto_config();

        for runtime in OFFICIAL_RUNTIMES {
            let latest = runtime
                .latest_version()
                .expect("family has a latest version");

            assert_eq!(
                config.normalize_runtime_image(runtime.family),
                format!("openruntimes/{}:v5-{}", runtime.family, latest),
                "bare {} shorthand did not resolve to its latest tag",
                runtime.family
            );
        }
    }

    #[test]
    fn test_expand_runtime_name_new_families() {
        let config = auto_config();

        assert_eq!(
            config.expand_runtime_name("go-1.23"),
            "openruntimes/go:v5-1.23"
        );
        assert_eq!(
            config.expand_runtime_name("rust-1.83"),
            "openruntimes/rust:v5-1.83"
        );
        assert_eq!(
            config.expand_runtime_name("swift-6.2"),
            "openruntimes/swift:v5-6.2"
        );
        assert_eq!(
            config.expand_runtime_name("kotlin-2.3"),
            "openruntimes/kotlin:v5-2.3"
        );
        assert_eq!(
            config.expand_runtime_name("cpp-23"),
            "openruntimes/cpp:v5-23"
        );
        assert_eq!(
            config.expand_runtime_name("flutter-3.47"),
            "openruntimes/flutter:v5-3.47"
        );
        assert_eq!(
            config.expand_runtime_name("python-ml-3.12"),
            "openruntimes/python-ml:v5-3.12"
        );
    }

    #[test]
    fn test_expand_runtime_name_maps_pins_onto_published_tags() {
        let config = auto_config();

        // Published tags carry a trailing ".0" for these versions.
        assert_eq!(
            config.expand_runtime_name("node-20"),
            "openruntimes/node:v5-20.0"
        );
        assert_eq!(
            config.expand_runtime_name("java-21"),
            "openruntimes/java:v5-21.0"
        );
        assert_eq!(
            config.expand_runtime_name("dotnet-8"),
            "openruntimes/dotnet:v5-8.0"
        );

        // Exact matches are preserved.
        assert_eq!(
            config.expand_runtime_name("node-22"),
            "openruntimes/node:v5-22"
        );
        assert_eq!(
            config.expand_runtime_name("go-1.26"),
            "openruntimes/go:v5-1.26"
        );

        // A version the table does not know is passed through untouched so a
        // deployment can pin a tag published after the last table refresh.
        assert_eq!(
            config.expand_runtime_name("node-99"),
            "openruntimes/node:v5-99"
        );
    }

    #[test]
    fn test_python_ml_shorthand_is_not_read_as_python() {
        let config = auto_config();

        assert_eq!(
            config.supported_runtime_family("python-ml-3.11"),
            Some("python-ml")
        );
        assert_eq!(
            config.expand_runtime_name("python-ml-3.11"),
            "openruntimes/python-ml:v5-3.11"
        );
        assert_eq!(
            config.resolve_runtime_image(
                "python-ml-3.13",
                "main.py",
                "",
                "pip install -r requirements.txt"
            ),
            "openruntimes/python-ml:v5-3.13"
        );
    }

    #[test]
    fn test_preferred_namespace_used_for_auto_resolution() {
        let config = namespaced_config(vec![]);

        assert_eq!(
            config.resolve_runtime_image("node-22", "index.js", "", "npm install"),
            "ghcr.io/unified-runtimes/node:v5-26"
        );
        assert_eq!(
            config.normalize_runtime_image("node-22"),
            "ghcr.io/unified-runtimes/node:v5-22"
        );
        assert_eq!(
            config.normalize_runtime_image("openruntimes/go"),
            "ghcr.io/unified-runtimes/go:v5-1.26"
        );
        assert_eq!(
            config.supported_runtime_family("ghcr.io/unified-runtimes/node:v5-24"),
            Some("node")
        );
    }

    #[test]
    fn test_preferred_namespace_falls_back_for_unlisted_families() {
        let config = namespaced_config(vec!["node".to_string(), "go".to_string()]);

        assert_eq!(
            config.resolve_runtime_image("", "main.go", "", ""),
            "ghcr.io/unified-runtimes/go:v5-1.26"
        );
        assert_eq!(
            config.resolve_runtime_image("", "index.php", "", ""),
            "openruntimes/php:v5-8.4"
        );
        assert_eq!(
            config.normalize_runtime_image("python-3.11"),
            "openruntimes/python:v5-3.11"
        );

        // An unlisted family stays a third-party reference when a caller spells
        // it out against the preferred namespace.
        assert_eq!(
            config.supported_runtime_family("ghcr.io/unified-runtimes/python:v5-3.11"),
            None
        );
    }

    #[test]
    fn test_namespace_without_registry_targets_docker_hub() {
        let mut config = auto_config();
        config.runtime_namespace = "unifiedruntimes".to_string();

        assert_eq!(
            config.resolve_runtime_image("node-22", "index.js", "", ""),
            "unifiedruntimes/node:v5-26"
        );
    }

    #[test]
    fn test_preferred_namespace_never_rewrites_explicit_images() {
        let config = namespaced_config(vec![]);

        assert_eq!(
            config.resolve_runtime_image("custom/runtime:latest", "index.js", "", "npm install"),
            "custom/runtime:latest"
        );
        assert_eq!(
            config.resolve_runtime_image("ghcr.io/someone-else/node:v5-22", "index.js", "", ""),
            "ghcr.io/someone-else/node:v5-22"
        );
    }

    #[test]
    fn test_detect_runtime_family_from_new_entrypoints() {
        let config = auto_config();

        for (entrypoint, expected) in [
            ("main.go", "openruntimes/go:v5-1.26"),
            ("src/main.rs", "openruntimes/rust:v5-1.83"),
            ("Sources/Tests.swift", "openruntimes/swift:v5-6.2"),
            ("Tests.kt", "openruntimes/kotlin:v5-2.3"),
            ("Tests.java", "openruntimes/java:v5-25"),
            ("tests.cc", "openruntimes/cpp:v5-23"),
            ("src/main.cpp", "openruntimes/cpp:v5-23"),
        ] {
            assert_eq!(
                config.resolve_runtime_image("", entrypoint, "", ""),
                expected,
                "entrypoint {} was not detected",
                entrypoint
            );
        }
    }

    #[test]
    fn test_detect_runtime_family_from_new_commands() {
        let config = auto_config();

        for (command, expected) in [
            ("go build -o server .", "openruntimes/go:v5-1.26"),
            ("cargo build --release", "openruntimes/rust:v5-1.83"),
            ("cat Cargo.toml", "openruntimes/rust:v5-1.83"),
            ("swift build -c release", "openruntimes/swift:v5-6.2"),
            ("bash gradlew build", "openruntimes/kotlin:v5-2.3"),
            ("mvn package", "openruntimes/java:v5-25"),
            ("cmake -S . -B build", "openruntimes/cpp:v5-23"),
            ("flutter build web", "openruntimes/flutter:v5-3.47"),
        ] {
            assert_eq!(
                config.resolve_runtime_image("", "", "", command),
                expected,
                "command {} was not detected",
                command
            );
        }
    }

    #[test]
    fn test_detect_runtime_family_keeps_more_specific_request() {
        let config = auto_config();

        // Flutter builds run Dart code; a flutter request is not downgraded.
        assert_eq!(
            config.resolve_runtime_image("flutter-3.47", "lib/main.dart", "", "dart pub get"),
            "openruntimes/flutter:v5-3.47"
        );

        // A dart request still resolves to dart.
        assert_eq!(
            config.resolve_runtime_image("dart-3.13", "lib/main.dart", "", "dart pub get"),
            "openruntimes/dart:v5-3.13"
        );

        // A flutter command overrides a dart request.
        assert_eq!(
            config.resolve_runtime_image("dart-3.13", "", "", "flutter build web"),
            "openruntimes/flutter:v5-3.47"
        );
    }

    #[test]
    fn test_is_runtime_allowed_covers_new_families() {
        let mut config = ExecutorConfig::from_env();
        config.auto_runtime = true;
        config.allowed_runtimes = vec!["node-22".to_string()];

        assert!(config.is_runtime_allowed("openruntimes/go:v5-1.26"));
        assert!(config.is_runtime_allowed("openruntimes/python-ml:v5-3.13"));
        assert!(!config.is_runtime_allowed("custom/go:v5-1.26"));
    }
}
