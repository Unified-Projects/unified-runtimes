//! Prometheus metrics endpoint

use super::AppState;
use crate::execution_counter::active_executions;
use crate::middleware::auth::constant_time_compare;
use crate::telemetry::metrics;
use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use tracing::warn;

/// GET /metrics - Prometheus scrape endpoint
///
/// Requires a valid bearer token when `URT_SECRET` is configured.
pub async fn metrics_handler(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !is_authorized(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    match build_metrics_payload(&state).await {
        Ok((content_type, payload)) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, content_type)],
            payload,
        )
            .into_response(),
        Err(error) => {
            warn!("Failed to build Prometheus metrics payload: {}", error);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn is_authorized(state: &AppState, headers: &HeaderMap) -> bool {
    if state.config.secret.is_empty() {
        return true;
    }

    headers
        .get("Authorization")
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.starts_with("Bearer "))
        .map(|value| value.trim_start_matches("Bearer ").trim())
        .map(|token| constant_time_compare(token, &state.config.secret))
        .unwrap_or(false)
}

async fn build_metrics_payload(state: &AppState) -> Result<(String, Vec<u8>), String> {
    let runtimes = state.registry.list().await;
    let mut running = 0;
    let mut pending = 0;
    let mut listening = 0;

    for runtime in &runtimes {
        if runtime.is_running() {
            running += 1;
        }
        if runtime.is_pending() {
            pending += 1;
        }
        if runtime.is_listening() {
            listening += 1;
        }
    }

    let snapshot = state.docker.stats_cache().get_snapshot();
    let cpu_sum: f64 = snapshot
        .containers
        .iter()
        .map(|container| container.cpu)
        .sum();
    let memory_sum: f64 = snapshot
        .containers
        .iter()
        .map(|container| container.memory as f64)
        .sum();

    let execution_queue_capacity = state.execution_limiter_capacity.unwrap_or(0);
    let runtime_create_queue_capacity = state.runtime_create_limiter_capacity.unwrap_or(0);
    let execution_queue_depth = state
        .execution_limiter
        .as_ref()
        .map(|limiter| execution_queue_capacity.saturating_sub(limiter.available_permits()) as i64)
        .unwrap_or(0);
    let runtime_create_queue_depth = state
        .runtime_create_limiter
        .as_ref()
        .map(|limiter| {
            runtime_create_queue_capacity.saturating_sub(limiter.available_permits()) as i64
        })
        .unwrap_or(0);

    let metrics = metrics();
    metrics.set_runtime_counts(runtimes.len() as i64, running, pending, listening);
    metrics.set_active_executions(active_executions() as i64);
    metrics.set_stats_snapshot(
        snapshot.containers.len() as i64,
        cpu_sum,
        memory_sum,
        snapshot.host.memory_limit as f64,
        snapshot.host.memory_percentage,
        snapshot.host.cpu_percentage,
    );
    metrics.set_queue_depths(
        execution_queue_depth,
        runtime_create_queue_depth,
        execution_queue_capacity as i64,
        runtime_create_queue_capacity as i64,
    );

    metrics.encode()
}
