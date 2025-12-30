//! Health check endpoint

use super::AppState;
use crate::error::Result;
use crate::middleware::auth::constant_time_compare;
use axum::{
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

/// Health check response
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub usage: UsageStats,
    pub runtimes: Vec<RuntimeStats>,
}

/// Host usage statistics
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageStats {
    pub memory: MemoryStats,
    pub cpu: CpuStats,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryStats {
    pub percentage: f64,
    pub memory_limit: u64,
}

#[derive(Debug, Serialize)]
pub struct CpuStats {
    pub percentage: f64,
}

/// Runtime statistics
#[derive(Debug, Serialize)]
pub struct RuntimeStats {
    pub name: String,
    pub cpu: f64,
    pub memory: u64,
}

/// Minimal health response for unauthenticated requests
/// This prevents information leakage about running runtimes
#[derive(Debug, Serialize)]
pub struct MinimalHealthResponse {
    pub status: &'static str,
}

/// GET /v1/ping - Ultra-fast health check (no auth, no stats)
///
/// This is the fastest possible endpoint for load balancer checks.
/// Returns just {"status":"ok"} with no processing.
#[inline]
pub async fn ping_handler() -> Json<MinimalHealthResponse> {
    Json(MinimalHealthResponse { status: "ok" })
}

/// GET /v1/health - Health check with stats
///
/// Returns minimal info for unauthenticated requests (just status: "ok")
/// Returns full stats for authenticated requests.
///
/// This is the hot path - uses lock-free reads via ArcSwap for zero contention
/// under high concurrency (50+ concurrent connections).
pub async fn health_handler(State(state): State<AppState>, headers: HeaderMap) -> Result<Response> {
    // Fast path: if auth is required, check header existence first
    // This short-circuits before any string parsing for unauthenticated requests
    if !state.config.secret.is_empty() {
        match headers.get("Authorization") {
            None => {
                // No auth header - return minimal response immediately (HOT PATH)
                return Ok(Json(MinimalHealthResponse { status: "ok" }).into_response());
            }
            Some(auth_header) => {
                // Have auth header - validate it
                let is_valid = auth_header
                    .to_str()
                    .ok()
                    .filter(|h| h.starts_with("Bearer "))
                    .map(|h| h.trim_start_matches("Bearer ").trim())
                    .map(|t| constant_time_compare(t, &state.config.secret))
                    .unwrap_or(false);

                if !is_valid {
                    // Invalid auth - minimal response
                    return Ok(Json(MinimalHealthResponse { status: "ok" }).into_response());
                }
                // Valid auth - fall through to full stats
            }
        }
    }
    // No secret configured OR valid auth - return full stats

    // Single atomic load - ZERO LOCKS
    // This is the key optimization: one pointer load instead of two lock acquisitions
    let snapshot = state.docker.stats_cache().get_snapshot();

    let runtimes: Vec<RuntimeStats> = snapshot
        .containers
        .iter()
        .map(|s| RuntimeStats {
            name: s.name.clone(),
            cpu: s.cpu,
            memory: s.memory,
        })
        .collect();

    Ok(Json(HealthResponse {
        usage: UsageStats {
            memory: MemoryStats {
                percentage: snapshot.host.memory_percentage,
                memory_limit: snapshot.host.memory_limit,
            },
            cpu: CpuStats {
                percentage: snapshot.host.cpu_percentage,
            },
        },
        runtimes,
    })
    .into_response())
}
