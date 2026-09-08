//! HTTP routes module

mod build;
mod commands;
mod executions;
mod health;
mod logs;
mod metrics;
pub(crate) mod runtimes;

pub(crate) use runtimes::{DEFAULT_RUNTIME_BIND_HOSTNAME, RUNTIME_BIND_HOSTNAME_VAR};

use crate::config::ExecutorConfig;
use crate::docker::DockerManager;
use crate::error::ExecutorError;
use crate::middleware::{
    auth::auth_middleware, request_context_middleware, security_headers_middleware,
};
use crate::runtime::{AdoptionNegativeCache, CreateTracker, KeepAliveRegistry, RuntimeRegistry};
use crate::storage::Storage;
use axum::{
    extract::DefaultBodyLimit,
    middleware,
    routing::{delete, get, post},
    Router,
};
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::{Notify, Semaphore};

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    pub config: ExecutorConfig,
    pub docker: Arc<DockerManager>,
    pub registry: RuntimeRegistry,
    pub keep_alive_registry: KeepAliveRegistry,
    pub http_client: reqwest::Client,
    pub storage: Arc<dyn Storage>,
    pub execution_limiter: Option<Arc<Semaphore>>,
    /// Permits for serve-style creates: a container to start and hand traffic to.
    pub runtime_create_limiter: Option<Arc<Semaphore>>,
    /// Permits for build-style creates, which run a user command inside the
    /// container and can occupy their permit for minutes.
    pub runtime_build_limiter: Option<Arc<Semaphore>>,
    pub execution_limiter_capacity: Option<usize>,
    pub runtime_create_limiter_capacity: Option<usize>,
    /// Per-runtime readiness notifiers. Inserted when a runtime enters pending state,
    /// fired (notify_waiters) and removed when it leaves pending (success or failure).
    pub readiness: Arc<DashMap<String, Arc<Notify>>>,
    /// Runtime creates that are currently building. A create is registered for the
    /// whole duration of its build, so concurrent creates can join it and
    /// maintenance can tell an orphaned pending entry from a live one.
    pub create_tracker: CreateTracker,
    /// Container names a recent adoption attempt did not find. Keeps a scan over
    /// unknown runtime IDs from costing one Docker inspect per request.
    pub adoption_negative_cache: AdoptionNegativeCache,
}

impl AppState {
    /// Return the existing notifier for `name`, or create and insert a new one.
    /// Used exclusively by the runtime *inserter* (create_runtime).  Callers
    /// that need to park on a pending runtime acquire the notifier before
    /// re-checking the registry so they cannot miss a wakeup that fires between
    /// the check and the park.
    pub fn readiness_notifier(&self, name: &str) -> Arc<Notify> {
        self.readiness
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(Notify::new()))
            .clone()
    }

    /// Return the existing notifier for `name` without creating one.
    /// Returns `None` when no pending entry exists for `name`, which prevents
    /// dangling DashMap entries for requests targeting non-existent runtimes.
    pub fn readiness_notifier_existing(&self, name: &str) -> Option<Arc<Notify>> {
        self.readiness.get(name).map(|n| n.clone())
    }

    /// Wake all waiters parked on `name` and remove the entry from the map.
    /// Must be called BEFORE removing the registry entry so that woken waiters
    /// can observe the registry state (present-and-non-pending, or absent).
    pub fn readiness_notify_and_remove(&self, name: &str) {
        if let Some((_, notify)) = self.readiness.remove(name) {
            notify.notify_waiters();
        }
    }
}

/// Create the main router with all routes
pub fn create_router(state: AppState) -> Router {
    let secret = state.config.secret.clone();
    // Add 2MB overhead for headers/metadata, matching executor-main's 22MB transport
    // cap over a 20MB payload limit.
    let max_body_size = state.config.max_body_size + (2 * 1024 * 1024);

    // Public routes - MINIMAL overhead for max performance
    // No auth, no security headers, no body limit (GET only)
    let mut public_routes = Router::new()
        .route("/v1/health", get(health::health_handler))
        .route("/v1/health/stats", get(health::health_stats_handler))
        .route("/v1/ping", get(health::ping_handler));
    if state.config.metrics_enabled {
        public_routes = public_routes.route("/metrics", get(metrics::metrics_handler));
    }

    // Protected routes (auth + security headers + body limit)
    let protected_routes = Router::new()
        // Runtime CRUD
        .route("/v1/runtimes", post(runtimes::create_runtime))
        .route("/v1/runtimes", get(runtimes::list_runtimes))
        .route("/v1/runtimes/{runtime_id}", get(runtimes::get_runtime))
        .route(
            "/v1/runtimes/{runtime_id}",
            delete(runtimes::delete_runtime),
        )
        // Executions
        .route(
            "/v1/runtimes/{runtime_id}/executions",
            post(executions::create_execution),
        )
        .route(
            "/v1/runtimes/{runtime_id}/execution",
            post(executions::create_execution),
        )
        // Logs
        .route("/v1/runtimes/{runtime_id}/logs", get(logs::stream_logs))
        // Commands
        .route(
            "/v1/runtimes/{runtime_id}/commands",
            post(commands::exec_command),
        )
        // Build
        .route(
            "/v1/runtimes/{runtime_id}/build",
            post(build::build_runtime),
        )
        // Body size limit only on protected routes (POST endpoints need it)
        .layer(DefaultBodyLimit::max(max_body_size))
        // Security headers only on protected routes
        .layer(middleware::from_fn(security_headers_middleware))
        // Auth middleware
        .layer(middleware::from_fn_with_state(secret, auth_middleware));

    // Combine routes - public routes have NO middleware overhead
    Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .fallback(fallback_handler)
        .layer(middleware::from_fn(request_context_middleware))
        .with_state(state)
}

/// Fallback handler for unmatched routes
async fn fallback_handler() -> ExecutorError {
    ExecutorError::RouteNotFound
}
