//! Log streaming and parsing
//!
//! This module handles log streaming for runtime containers and parsing
//! build logs to match executor-main's Logs.php format.

use super::AppState;
use crate::error::{ExecutorError, Result};
use axum::{
    extract::{Path, Query, State},
    response::{
        sse::{Event, Sse},
        IntoResponse,
    },
};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use futures_util::stream::{Stream, StreamExt};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::time::Duration;
use tracing::{debug, error, warn};

/// Maximum build log size (1MB) - matches executor-main MAX_BUILD_LOG_SIZE
const MAX_BUILD_LOG_SIZE: usize = 1_000_000;

/// A parsed log entry with timestamp and content
/// Matches executor-main's log chunk format
#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub content: String,
}

/// Parse build logs from the logging directory
/// This matches executor-main's Logs::get() function
pub async fn parse_build_logs(logging_dir: &str) -> Vec<LogEntry> {
    let logs_file = format!("{}/logs.txt", logging_dir);
    let timings_file = format!("{}/timings.txt", logging_dir);

    // Read both files
    let logs = match tokio::fs::read_to_string(&logs_file).await {
        Ok(content) => content,
        Err(e) => {
            warn!("Failed to read logs.txt: {}", e);
            return Vec::new();
        }
    };

    let timings = match tokio::fs::read_to_string(&timings_file).await {
        Ok(content) => content,
        Err(e) => {
            warn!("Failed to read timings.txt: {}", e);
            // Return raw logs as single chunk if no timing file
            return vec![LogEntry {
                timestamp: get_timestamp(),
                content: logs,
            }];
        }
    };

    // Parse logs with timing info
    parse_logs_with_timing(&logs, &timings)
}

/// Parse logs using timing information
/// Matches executor-main's Logs::get() logic
fn parse_logs_with_timing(logs: &str, timings: &str) -> Vec<LogEntry> {
    let mut output = Vec::new();
    let now = Utc::now();

    // Get intro offset (skip "Script started on..." line)
    let intro_offset = get_log_offset(logs);

    // Parse timing entries
    let parts = parse_timing(timings, now);

    let mut offset: usize = 0;
    let logs_bytes = logs.as_bytes();

    for part in parts {
        // Check if we've exceeded max log size
        if offset >= MAX_BUILD_LOG_SIZE {
            output.push(LogEntry {
                timestamp: part.timestamp,
                content: format!(
                    "Logs truncated due to size exceeding {:.2}MB.",
                    MAX_BUILD_LOG_SIZE as f64 / 1048576.0
                ),
            });
            break;
        }

        // Extract log content for this chunk
        let start = intro_offset + offset;
        let length = part.length.unsigned_abs() as usize;
        let end = (start + length).min(logs_bytes.len());

        let content = if start < logs_bytes.len() {
            String::from_utf8_lossy(&logs_bytes[start..end]).to_string()
        } else {
            String::new()
        };

        output.push(LogEntry {
            timestamp: part.timestamp,
            content,
        });

        offset += length;
    }

    output
}

/// Get the offset to skip the "Script started on..." intro line
/// Matches executor-main's Logs::getLogOffset()
fn get_log_offset(logs: &str) -> usize {
    // Find first newline to identify prefix
    if let Some(newline_pos) = logs.find('\n') {
        // Return length of first line + 1 for the newline itself
        newline_pos + 1
    } else {
        0
    }
}

/// Parsed timing entry
struct TimingEntry {
    timestamp: String,
    length: i64,
}

/// Parse timing file content
/// Matches executor-main's Logs::parseTiming()
fn parse_timing(timing: &str, base_datetime: DateTime<Utc>) -> Vec<TimingEntry> {
    if timing.is_empty() {
        return Vec::new();
    }

    let mut parts = Vec::new();
    let mut current_datetime = base_datetime;

    for row in timing.lines() {
        if row.is_empty() {
            continue;
        }

        // Each line is: "{timing_seconds} {length_bytes}"
        let mut split = row.splitn(2, ' ');
        let timing_str = split.next().unwrap_or("0");
        let length_str = split.next().unwrap_or("0");

        let timing_secs: f64 = timing_str.parse().unwrap_or(0.0);
        let length: i64 = length_str.parse().unwrap_or(0);

        // Convert to microseconds and add to datetime
        let microseconds = (timing_secs * 1_000_000.0).ceil() as i64;
        current_datetime = current_datetime + ChronoDuration::microseconds(microseconds);

        // Format timestamp as ISO-8601 with milliseconds
        // Format: 2024-01-15T10:30:45.123+00:00
        let timestamp = current_datetime
            .format("%Y-%m-%dT%H:%M:%S%.3f%:z")
            .to_string();

        parts.push(TimingEntry { timestamp, length });
    }

    parts
}

/// Get current timestamp in executor-main format
pub fn get_timestamp() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%S%.3f%:z").to_string()
}

/// Query parameters for log streaming
#[derive(Debug, Deserialize)]
pub struct LogsQuery {
    #[serde(default = "default_timeout")]
    pub timeout: String,
}

fn default_timeout() -> String {
    "600".to_string()
}

/// GET /v1/runtimes/:runtime_id/logs - Stream logs
pub async fn stream_logs(
    State(state): State<AppState>,
    Path(runtime_id): Path<String>,
    Query(query): Query<LogsQuery>,
) -> Result<impl IntoResponse> {
    let full_name = format!("{}-{}", state.config.hostname, runtime_id);

    debug!("Streaming logs for: {}", full_name);

    // Check if runtime exists
    if !state.registry.exists(&full_name).await {
        return Err(ExecutorError::RuntimeNotFound);
    }

    // Parse timeout with validation
    let timeout_secs: u64 = query.timeout.parse().unwrap_or(600);
    if timeout_secs == 0 {
        return Err(ExecutorError::LogsTimeout);
    }
    if timeout_secs > 3600 {
        return Err(ExecutorError::LogsTimeout);
    }

    // Create SSE stream
    let stream = create_log_stream(state, full_name, timeout_secs);

    Ok(Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(30))
            .text("keep-alive"),
    ))
}

fn create_log_stream(
    state: AppState,
    container_name: String,
    timeout_secs: u64,
) -> impl Stream<Item = std::result::Result<Event, Infallible>> {
    async_stream::stream! {
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(timeout_secs);

        // Get log stream from Docker
        let mut log_stream = state.docker.stream_logs(&container_name, true, Some("100")).await;

        loop {
            // Check timeout
            if start.elapsed() > timeout {
                yield Ok(Event::default().data("Timeout reached"));
                break;
            }

            tokio::select! {
                log_result = log_stream.next() => {
                    match log_result {
                        Some(Ok(log_line)) => {
                            if !log_line.is_empty() {
                                yield Ok(Event::default().data(log_line));
                            }
                        }
                        Some(Err(e)) => {
                            error!("Error reading logs: {}", e);
                            yield Ok(Event::default().data(format!("Error: {}", e)));
                            break;
                        }
                        None => {
                            // Stream ended
                            break;
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    // Small delay to prevent busy loop
                }
            }
        }
    }
}
