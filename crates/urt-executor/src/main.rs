//! URT Executor - Drop-in Rust replacement for OpenRuntimes Executor
//!
//! A high-performance executor for managing containerized function runtimes
//! with full API compatibility with the PHP OpenRuntimes Executor.

use dashmap::DashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::{watch, Semaphore};
use tracing::{debug, info, warn};

mod config;
mod docker;
mod error;
mod execution_counter;
mod middleware;
mod platform;
mod resilience;
mod routes;
mod runtime;
mod storage;
mod tasks;
mod telemetry;

use config::ExecutorConfig;
use docker::DockerManager;
use execution_counter::active_executions;
use platform::temp_dir;
use routes::{create_router, AppState};
use runtime::{
    AdoptionNegativeCache, CrashLoopConfig, CreateTracker, KeepAliveRegistry, RuntimeConcurrency,
    RuntimeHealth, RuntimeRegistry,
};
use storage::{Storage, StorageFileCache};

/// Main entry point with optimized Tokio runtime configuration
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Build Tokio runtime with optimized settings for high throughput
    let runtime = tokio::runtime::Builder::new_multi_thread()
        // Use all available CPU cores for maximum parallelism
        .worker_threads(num_cpus::get())
        // Enable all Tokio features (IO, time, etc.)
        .enable_all()
        // Increase thread stack size for complex async operations (3MB)
        .thread_stack_size(3 * 1024 * 1024)
        // Name threads for easier debugging
        .thread_name("urt-worker")
        .build()
        .expect("Failed to create Tokio runtime");

    runtime.block_on(async_main())
}

/// Async main function containing the actual server logic
async fn async_main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    // Use compact format by default for better performance
    // Set RUST_LOG_FORMAT=json for JSON output in production
    let use_json = std::env::var("RUST_LOG_FORMAT")
        .map(|v| v.to_lowercase() == "json")
        .unwrap_or(false);

    let filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());

    if use_json {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .compact()
            .init();
    }

    info!("URT Executor starting...");

    // Load configuration
    let config = ExecutorConfig::from_env();
    info!("Configuration loaded:");
    info!("  Host: {}:{}", config.host, config.port);
    info!("  Keep-alive: {}", config.keep_alive);
    info!("  Autoscale: {}", config.autoscale);
    info!("  Warmup required: {}", config.warmup_required);
    info!(
        "  Eager runtime readiness: {}",
        config.eager_runtime_readiness
    );
    info!("  Metrics endpoint: {}", config.metrics_enabled);
    info!("  Auto runtime: {}", config.auto_runtime);
    info!("  Min CPUs: {}", config.min_cpus);
    info!("  Min Memory: {} MB", config.min_memory);
    info!("  Networks: {:?}", config.networks);
    info!("  Allowed runtimes: {:?}", config.allowed_runtimes);
    if config.autoscale {
        info!(
            "  Autoscale concurrency limits: executions={:?}, runtime_creates={:?}",
            config.max_concurrent_executions, config.max_concurrent_runtime_creates
        );
        info!(
            "  Autoscale queue waits (ms): execution={}, runtime_create={}",
            config.execution_queue_wait_ms, config.runtime_create_queue_wait_ms
        );
    }

    // Create Docker manager
    let docker = Arc::new(
        DockerManager::new(config.clone())
            .await
            .expect("Failed to connect to Docker"),
    );

    // Ensure networks exist
    docker
        .ensure_networks()
        .await
        .expect("Failed to create networks");

    // Connect executor container to configured runtime networks (best-effort)
    // This mirrors executor-main behavior and ensures DNS/port checks work.
    if let Some(executor_container) = docker.resolve_own_container().await {
        docker
            .connect_container_to_networks(&executor_container.name)
            .await;
    } else {
        debug!(
            "Could not resolve the executor's own container (hostname '{}'); skipping startup network attach",
            config.hostname
        );
    }

    // Create runtime registry
    let registry = RuntimeRegistry::new();

    // Create keep-alive registry for per-runtime cleanup protection
    let keep_alive_registry = KeepAliveRegistry::new();

    // Adopt any existing managed containers from previous runs
    tasks::adopt_existing_containers(
        &docker,
        &registry,
        &keep_alive_registry,
        &config.hostname,
        config.runtime_lifecycle_defaults(),
    )
    .await;

    let mut default_headers = reqwest::header::HeaderMap::new();
    // Force no compression, matches curl / Docker.php behavior
    default_headers.insert(
        reqwest::header::ACCEPT_ENCODING,
        reqwest::header::HeaderValue::from_static("identity"),
    );

    // Create HTTP client for runtime communication
    // Aggressively tuned for maximum throughput and minimum latency
    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(600))
        .connect_timeout(Duration::from_secs(5))
        .pool_max_idle_per_host(500)
        .pool_idle_timeout(Duration::from_secs(300))
        .tcp_keepalive(Duration::from_secs(15))
        .tcp_nodelay(true)
        .http1_only()
        .redirect(reqwest::redirect::Policy::none())
        // CRITICAL: disable compression at the protocol level
        .default_headers(default_headers)
        .build()
        .expect("Failed to create HTTP client");

    // Initialize file cache for faster cold starts (30 day TTL, 1GB max size).
    // Only a download that passed the status and archive-format checks is ever
    // cached, so a failed fetch cannot be served from here later.
    let file_cache = Arc::new(StorageFileCache::new(None, None, None));
    let storage_cache = match file_cache.initialize().await {
        Ok(()) => {
            info!(
                "Storage file cache initialized at {}",
                file_cache.cache_dir.display()
            );
            Some(file_cache.clone())
        }
        Err(e) => {
            warn!(
                "Failed to initialize file cache at {}, cold starts will always hit storage: {}",
                file_cache.cache_dir.display(),
                e
            );
            None
        }
    };

    // Create storage backend. For drop-in compatibility, support legacy
    // OPR_EXECUTOR_CONNECTION_STORAGE DSN when STORAGE_DEVICE is not explicitly set.
    let storage: Arc<dyn Storage> = {
        let explicit_storage_device = std::env::var("URT_STORAGE_DEVICE")
            .ok()
            .or_else(|| std::env::var("OPR_EXECUTOR_STORAGE_DEVICE").ok())
            .filter(|v| !v.trim().is_empty());

        let connection_dsn = std::env::var("URT_CONNECTION_STORAGE")
            .ok()
            .or_else(|| std::env::var("OPR_EXECUTOR_CONNECTION_STORAGE").ok())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());

        if explicit_storage_device.is_none() {
            if let Some(dsn) = connection_dsn {
                let scheme = dsn.split("://").next().unwrap_or("unknown");
                info!("Storage backend initialized from DSN: {}", scheme);
                Arc::from(
                    storage::from_dsn_with_cache(&dsn, storage_cache)
                        .expect("Failed to create storage from connection DSN"),
                )
            } else {
                info!("Storage backend initialized: {:?}", config.storage.device);
                Arc::from(
                    storage::from_config_with_cache(&config.storage, storage_cache)
                        .expect("Failed to create storage"),
                )
            }
        } else {
            info!("Storage backend initialized: {:?}", config.storage.device);
            Arc::from(
                storage::from_config_with_cache(&config.storage, storage_cache)
                    .expect("Failed to create storage"),
            )
        }
    };

    // Autoscale mode applies adaptive concurrency limits to smooth queueing under burst traffic.
    let (execution_limiter, execution_limiter_capacity): (Option<Arc<Semaphore>>, Option<usize>) =
        if config.autoscale {
            let default_limit = num_cpus::get().saturating_mul(64).max(32);
            let limit = config
                .max_concurrent_executions
                .unwrap_or(default_limit)
                .max(1);
            (Some(Arc::new(Semaphore::new(limit))), Some(limit))
        } else {
            (None, None)
        };
    let (runtime_create_limiter, runtime_create_limiter_capacity): (
        Option<Arc<Semaphore>>,
        Option<usize>,
    ) = {
        let default_limit = if config.autoscale {
            num_cpus::get().saturating_mul(4).max(4)
        } else {
            // Always apply a static cap when autoscale is off to prevent unbounded
            // concurrent runtime creates (M10).
            num_cpus::get().max(4)
        };
        let limit = config
            .max_concurrent_runtime_creates
            .unwrap_or(default_limit)
            .max(1);
        (Some(Arc::new(Semaphore::new(limit))), Some(limit))
    };
    // Builds run a user command inside the container and can last minutes, so
    // they draw on their own, smaller pool. Serve-style creates keep the pool
    // above to themselves and stay answerable during a run of builds.
    let runtime_build_limiter: Option<Arc<Semaphore>> = {
        let default_limit = (num_cpus::get() / 2).max(2);
        let limit = config.max_concurrent_builds.unwrap_or(default_limit).max(1);
        info!(
            "  Create concurrency: serve={:?}, build={}",
            runtime_create_limiter_capacity, limit
        );
        Some(Arc::new(Semaphore::new(limit)))
    };

    // Create shutdown channel
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Spawn warmup task. When warmup_required=true, await it before binding the
    // listener so the server only accepts requests once all images are pulled (W1).
    let warmup_docker = docker.clone();
    let warmup_config = config.clone();
    let warmup_handle = tokio::spawn(async move {
        tasks::run_warmup(warmup_docker, warmup_config).await;
    });

    if config.warmup_required {
        info!("Waiting for warmup to complete (URT_WARMUP_REQUIRED=true)...");
        warmup_handle.await.ok();
        info!("Warmup complete, proceeding to bind listener");
    }

    // Shared with the maintenance worker so it can tell a pending registry entry
    // that still has a build behind it from one that was orphaned.
    let readiness: Arc<DashMap<String, Arc<tokio::sync::Notify>>> = Arc::new(DashMap::new());
    let create_tracker = CreateTracker::new();
    let runtime_concurrency = RuntimeConcurrency::new();
    let health = RuntimeHealth::new(CrashLoopConfig::from_executor_config(&config));

    let maintenance_handles = tasks::MaintenanceHandles {
        docker: docker.clone(),
        registry: registry.clone(),
        keep_alive_registry: keep_alive_registry.clone(),
        readiness: readiness.clone(),
        create_tracker: create_tracker.clone(),
        health: health.clone(),
    };
    let maintenance_config = config.clone();
    let maintenance_storage = storage.clone();
    let maintenance_shutdown = shutdown_rx.clone();
    tokio::spawn(async move {
        tasks::run_maintenance(
            maintenance_handles,
            maintenance_config,
            maintenance_storage,
            maintenance_shutdown,
        )
        .await;
    });

    let stats_docker = docker.clone();
    let stats_registry = registry.clone();
    let stats_shutdown = shutdown_rx.clone();
    tokio::spawn(async move {
        tasks::run_stats_collector(stats_docker, stats_registry, stats_shutdown).await;
    });

    let listening_watch_handles = tasks::ListeningWatchHandles {
        docker: docker.clone(),
        registry: registry.clone(),
        keep_alive_registry: keep_alive_registry.clone(),
        runtime_concurrency: runtime_concurrency.clone(),
        readiness: readiness.clone(),
        health: health.clone(),
    };
    let listening_watch_shutdown = shutdown_rx.clone();
    tokio::spawn(async move {
        tasks::run_listening_watch(listening_watch_handles, listening_watch_shutdown).await;
    });

    // Create application state
    let state = AppState {
        config: config.clone(),
        docker: docker.clone(),
        registry: registry.clone(),
        keep_alive_registry,
        http_client,
        storage,
        execution_limiter,
        runtime_create_limiter,
        runtime_build_limiter,
        execution_limiter_capacity,
        runtime_create_limiter_capacity,
        readiness,
        runtime_concurrency,
        create_tracker,
        adoption_negative_cache: AdoptionNegativeCache::new(Duration::from_millis(
            config.adoption_negative_cache_ms,
        )),
        health,
    };

    if config.docker_events {
        let events_state = state.clone();
        let events_shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            tasks::run_docker_events(events_state, events_shutdown).await;
        });
    } else {
        info!("Docker events subscription disabled (URT_DOCKER_EVENTS=false)");
    }

    // Create router
    let app = create_router(state);

    // Bind server
    let addr = format!("{}:{}", config.host, config.port);
    let listener = TcpListener::bind(&addr).await?;
    info!("Listening on {}", addr);

    // Create shutdown signal handler
    let shutdown_signal = async move {
        let ctrl_c = async {
            signal::ctrl_c()
                .await
                .expect("Failed to install Ctrl+C handler");
        };

        #[cfg(unix)]
        let terminate = async {
            signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("Failed to install SIGTERM handler")
                .recv()
                .await;
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {
                info!("Received Ctrl+C, initiating graceful shutdown...");
            }
            _ = terminate => {
                info!("Received SIGTERM, initiating graceful shutdown...");
            }
        }

        // Signal shutdown to background tasks
        shutdown_tx.send(true).ok();

        // Wait for active executions to complete
        let max_wait = Duration::from_secs(30);
        let start = std::time::Instant::now();

        while active_executions() > 0 {
            if start.elapsed() > max_wait {
                warn!(
                    "Timeout waiting for {} active executions",
                    active_executions()
                );
                break;
            }
            info!(
                "Waiting for {} active executions to complete...",
                active_executions()
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        info!("All executions completed, shutting down...");
    };

    // Serve with graceful shutdown
    let docker_for_shutdown = docker.clone();
    let file_cache_for_shutdown = file_cache.clone();
    let cleanup_cache_on_shutdown = std::env::var("URT_CACHE_CLEANUP_ON_SHUTDOWN")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await?;

    info!("Server stopped");

    let managed_runtimes = docker_for_shutdown.cleanup_managed_containers().await;
    let mut runtime_dirs = managed_runtimes;

    for runtime in registry.clear().await {
        runtime_dirs.push(runtime.name);
    }

    runtime_dirs.sort();
    runtime_dirs.dedup();

    for runtime_name in runtime_dirs {
        let tmp_folder = temp_dir().join(&runtime_name);
        if let Err(err) = tokio::fs::remove_dir_all(&tmp_folder).await {
            if err.kind() != std::io::ErrorKind::NotFound {
                warn!(
                    "Failed to remove runtime temp dir {} during shutdown: {}",
                    tmp_folder.display(),
                    err
                );
            }
        }
    }

    // Final cleanup (optional to preserve cold-start cache between restarts).
    if cleanup_cache_on_shutdown {
        info!("Performing final cleanup...");
        file_cache_for_shutdown
            .cleanup_all()
            .await
            .inspect_err(|e| warn!("Failed to clean up file cache: {}", e))
            .ok();
    }

    Ok(())
}
