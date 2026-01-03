//! HTTP routes module

mod build;
mod commands;
mod executions;
mod health;
mod logs;
mod runtimes;

use crate::config::ExecutorConfig;
use crate::docker::DockerManager;
use crate::error::ExecutorError;
use crate::middleware::{auth::auth_middleware, security_headers_middleware};
use crate::runtime::{KeepAliveRegistry, RuntimeRegistry};
use crate::storage::Storage;
use axum::{
    extract::DefaultBodyLimit,
    middleware,
    routing::{delete, get, post},
    Router,
};
use std::sync::Arc;

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    pub config: ExecutorConfig,
    pub docker: Arc<DockerManager>,
    pub registry: RuntimeRegistry,
    pub keep_alive_registry: KeepAliveRegistry,
    pub http_client: reqwest::Client,
    pub storage: Arc<dyn Storage>,
}

/// Create the main router with all routes
pub fn create_router(state: AppState) -> Router {
    let secret = state.config.secret.clone();
    // Add 1MB overhead for headers/metadata
    let max_body_size = state.config.max_body_size + (1024 * 1024);

    // Public routes - MINIMAL overhead for max performance
    // No auth, no security headers, no body limit (GET only)
    let public_routes = Router::new()
        .route("/v1/health", get(health::health_handler))
        .route("/v1/ping", get(health::ping_handler));

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
        .with_state(state)
}

/// Fallback handler for unmatched routes
async fn fallback_handler() -> ExecutorError {
    ExecutorError::RouteNotFound
}
