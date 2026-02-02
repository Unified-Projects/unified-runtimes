//! URT Executor - Drop-in Rust replacement for OpenRuntimes Executor
//!
//! A high-performance executor for managing containerized function runtimes
//! with full API compatibility with the PHP OpenRuntimes Executor.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::watch;
use tracing::{info, warn};

mod config;
mod docker;
mod error;
mod middleware;
mod platform;
mod routes;
mod runtime;
mod storage;
mod tasks;

use config::ExecutorConfig;
use docker::DockerManager;
use routes::{create_router, AppState};
use runtime::{KeepAliveRegistry, RuntimeRegistry};
use storage::{Storage, StorageFileCache};

/// Track active executions for graceful shutdown
static ACTIVE_EXECUTIONS: AtomicUsize = AtomicUsize::new(0);

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
    info!("  Min CPUs: {}", config.min_cpus);
    info!("  Min Memory: {} MB", config.min_memory);
    info!("  Networks: {:?}", config.networks);
    info!("  Allowed runtimes: {:?}", config.allowed_runtimes);

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
    let executor_container = docker
        .resolve_container_name_by_hostname(&config.hostname)
        .await
        .unwrap_or_else(|| {
            warn!(
                "Could not resolve container name for hostname '{}', using hostname directly",
                config.hostname
            );
            config.hostname.clone()
        });
    docker
        .connect_container_to_networks(&executor_container)
        .await;

    // Create runtime registry
    let registry = RuntimeRegistry::new();

    // Create keep-alive registry for per-runtime cleanup protection
    let keep_alive_registry = KeepAliveRegistry::new();

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

    // Create storage backend from config (supports individual env vars like executor-main)
    let storage: Arc<dyn Storage> =
        Arc::from(storage::from_config(&config.storage).expect("Failed to create storage"));
    info!("Storage backend initialized: {:?}", config.storage.device);

    // Initialize file cache for faster cold starts (30 day TTL, 1GB max size)
    let file_cache = Arc::new(StorageFileCache::new(None, None, None));
    file_cache
        .initialize()
        .await
        .inspect_err(|e| warn!("Failed to initialize file cache: {}", e))
        .ok();
    info!(
        "Storage file cache initialized at {}",
        file_cache.cache_dir.display()
    );

    // Create shutdown channel
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Spawn background tasks
    let warmup_docker = docker.clone();
    let warmup_config = config.clone();
    tokio::spawn(async move {
        tasks::run_warmup(warmup_docker, warmup_config).await;
    });

    let maintenance_docker = docker.clone();
    let maintenance_registry = registry.clone();
    let maintenance_keep_alive = keep_alive_registry.clone();
    let maintenance_config = config.clone();
    let maintenance_storage = storage.clone();
    let maintenance_shutdown = shutdown_rx.clone();
    tokio::spawn(async move {
        tasks::run_maintenance(
            maintenance_docker,
            maintenance_registry,
            maintenance_keep_alive,
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

    // Create application state
    let state = AppState {
        config: config.clone(),
        docker: docker.clone(),
        registry: registry.clone(),
        keep_alive_registry,
        http_client,
        storage,
    };

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

        while ACTIVE_EXECUTIONS.load(Ordering::Relaxed) > 0 {
            if start.elapsed() > max_wait {
                warn!(
                    "Timeout waiting for {} active executions",
                    ACTIVE_EXECUTIONS.load(Ordering::Relaxed)
                );
                break;
            }
            info!(
                "Waiting for {} active executions to complete...",
                ACTIVE_EXECUTIONS.load(Ordering::Relaxed)
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        info!("All executions completed, shutting down...");
    };

    // Serve with graceful shutdown
    let docker_for_shutdown = docker.clone();
    let file_cache_for_shutdown = file_cache.clone();

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown_signal.await;

            // BLOCK HERE UNTIL DOCKER FINISHES
            docker_for_shutdown.cleanup_managed_containers().await;

            // Clean up file cache on shutdown
            info!("Cleaning up file cache...");
            file_cache_for_shutdown
                .cleanup_all()
                .await
                .inspect_err(|e| warn!("Failed to clean up file cache: {}", e))
                .ok();
        })
        .await?;

    info!("Server stopped");

    // Final cleanup
    info!("Performing final cleanup...");
    file_cache
        .cleanup_all()
        .await
        .inspect_err(|e| warn!("Failed to clean up file cache: {}", e))
        .ok();

    Ok(())
}
