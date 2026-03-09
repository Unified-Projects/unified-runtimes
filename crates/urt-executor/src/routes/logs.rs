//! Log streaming and parsing
//!
//! This module handles log streaming for runtime containers and parsing
//! build logs to match executor-main's Logs.php format.

use super::AppState;
use crate::error::{ExecutorError, Result};
use crate::platform;
use crate::runtime::Runtime;
use crate::tasks;
use axum::{
    body::Body,
    extract::{Path, Query, State},
    response::Response,
};
use bytes::Bytes;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use futures_util::stream::{BoxStream, StreamExt};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::path::Path as StdPath;
use std::time::Duration;
use tracing::{debug, warn};

/// Maximum build log size (1MB) - matches executor-main MAX_BUILD_LOG_SIZE
const MAX_BUILD_LOG_SIZE: usize = 1_000_000;
const LOG_STREAM_POLL_INTERVAL: Duration = Duration::from_millis(100);
const LOG_SEGMENT_WAIT_CAP: Duration = Duration::from_millis(750);
const LOG_RUNTIME_LOOKUP_GRACE: Duration = Duration::from_secs(2);

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
        if row.is_empty() || row == "0" {
            continue;
        }

        if let Some(entry) = parse_timing_row(row, &mut current_datetime) {
            parts.push(entry);
        }
    }

    parts
}

fn parse_timing_row(row: &str, current_datetime: &mut DateTime<Utc>) -> Option<TimingEntry> {
    let trimmed = row.trim();
    if trimmed.is_empty() || trimmed == "0" {
        return None;
    }

    // Each line is: "{timing_seconds} {length_bytes}"
    let mut split = trimmed.splitn(2, ' ');
    let timing_str = split.next().unwrap_or("0");
    let length_str = split.next().unwrap_or("0");

    let timing_secs: f64 = timing_str.parse().unwrap_or(0.0);
    let length: i64 = length_str.parse().unwrap_or(0);

    let microseconds = (timing_secs * 1_000_000.0).ceil() as i64;
    *current_datetime += ChronoDuration::microseconds(microseconds);

    Some(TimingEntry {
        timestamp: current_datetime
            .format("%Y-%m-%dT%H:%M:%S%.3f%:z")
            .to_string(),
        length,
    })
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
) -> Result<Response> {
    let full_name = format!("{}-{}", state.config.hostname, runtime_id);

    debug!("Streaming logs for: {}", full_name);
    let runtime = resolve_runtime(&state, &full_name).await?;

    // Parse timeout with validation
    let timeout_secs: u64 = query.timeout.parse().unwrap_or(600);
    if timeout_secs == 0 {
        return Err(ExecutorError::LogsTimeout);
    }
    if timeout_secs > 3600 {
        return Err(ExecutorError::LogsTimeout);
    }

    let stream = if runtime.version.eq_ignore_ascii_case("v2") {
        create_empty_log_stream()
    } else {
        create_build_log_stream(state, full_name, timeout_secs)
    };

    Ok(Response::builder()
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .body(Body::from_stream(stream))
        .unwrap())
}

type EventStream = BoxStream<'static, std::result::Result<Bytes, Infallible>>;

async fn resolve_runtime(state: &AppState, full_name: &str) -> Result<Runtime> {
    let deadline = tokio::time::Instant::now() + LOG_RUNTIME_LOOKUP_GRACE;

    loop {
        if let Some(runtime) = current_runtime(state, full_name).await {
            return Ok(runtime);
        }

        if tokio::time::Instant::now() >= deadline {
            return Err(ExecutorError::RuntimeNotFound);
        }

        tokio::time::sleep(LOG_STREAM_POLL_INTERVAL).await;
    }
}

async fn current_runtime(state: &AppState, full_name: &str) -> Option<Runtime> {
    if let Some(runtime) = state.registry.sync_status(full_name, &state.docker).await {
        return Some(runtime);
    }

    if let Some(runtime) = state.registry.get(full_name).await {
        return Some(runtime);
    }

    let _ = tasks::adopt_container_by_name(
        &state.docker,
        &state.registry,
        &state.keep_alive_registry,
        &state.config.hostname,
        full_name,
    )
    .await;

    if let Some(runtime) = state.registry.sync_status(full_name, &state.docker).await {
        return Some(runtime);
    }

    state.registry.get(full_name).await
}

fn create_empty_log_stream() -> EventStream {
    futures_util::stream::empty().boxed()
}

fn create_build_log_stream(
    state: AppState,
    container_name: String,
    timeout_secs: u64,
) -> EventStream {
    async_stream::stream! {
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(timeout_secs);
        let logs_path = platform::temp_dir().join(&container_name).join("logging").join("logs.txt");
        let timings_path = platform::temp_dir().join(&container_name).join("logging").join("timings.txt");
        let mut timing_read_offset = 0usize;
        let mut timing_buffer = String::new();
        let mut current_datetime = Utc::now();
        let mut intro_offset: Option<usize> = None;
        let mut log_offset = 0usize;

        loop {
            if start.elapsed() > timeout {
                yield Ok(Bytes::from_static(b"Timeout reached\n"));
                break;
            }

            let runtime = match current_runtime(&state, &container_name).await {
                Some(runtime) => runtime,
                None => break,
            };

            if intro_offset.is_none() {
                if let Ok(logs) = tokio::fs::read_to_string(&logs_path).await {
                    intro_offset = Some(get_log_offset(&logs));
                }
            }

            match read_new_text(&timings_path, &mut timing_read_offset).await {
                Ok(chunk) if !chunk.is_empty() => {
                    timing_buffer.push_str(&chunk);

                    for row in drain_timing_rows(&mut timing_buffer, runtime.initialised == 1) {
                        let Some(part) = parse_timing_row(&row, &mut current_datetime) else {
                            continue;
                        };

                        let length = part.length.unsigned_abs() as usize;
                        let segment_timeout = timeout
                            .saturating_sub(start.elapsed())
                            .min(LOG_SEGMENT_WAIT_CAP);
                        let content = read_log_segment_with_wait(
                            &logs_path,
                            intro_offset.unwrap_or(0).saturating_add(log_offset),
                            length,
                            segment_timeout,
                        )
                        .await;

                        log_offset = log_offset.saturating_add(length);

                        if !content.is_empty() {
                            yield Ok(Bytes::from(format_log_line(&part.timestamp, &content)));
                        }
                    }
                }
                Ok(_) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    warn!("Failed to stream build timings for {}: {}", container_name, err);
                    yield Ok(Bytes::from(format!("Error: {}\n", err)));
                    break;
                }
            }

            let timings_fully_consumed = tokio::fs::metadata(&timings_path)
                .await
                .map(|metadata| metadata.len() as usize <= timing_read_offset)
                .unwrap_or(true);

            if runtime.initialised == 1
                && timing_buffer.trim().is_empty()
                && timings_fully_consumed
            {
                break;
            }

            tokio::time::sleep(LOG_STREAM_POLL_INTERVAL).await;
        }
    }
    .boxed()
}

fn format_log_line(timestamp: &str, content: &str) -> String {
    format!("{} {}\n", timestamp, content.replace('\n', "\\n"))
}

async fn read_new_text(path: &StdPath, offset: &mut usize) -> std::io::Result<String> {
    let bytes = tokio::fs::read(path).await?;
    if *offset >= bytes.len() {
        *offset = bytes.len();
        return Ok(String::new());
    }

    let chunk = String::from_utf8_lossy(&bytes[*offset..]).into_owned();
    *offset = bytes.len();
    Ok(chunk)
}

fn drain_timing_rows(buffer: &mut String, flush_partial: bool) -> Vec<String> {
    let mut rows = Vec::new();
    let mut consumed = 0usize;

    for segment in buffer.split_inclusive('\n') {
        if !segment.ends_with('\n') {
            break;
        }
        consumed += segment.len();
        rows.push(segment.trim_end_matches('\n').to_string());
    }

    if flush_partial && consumed < buffer.len() {
        rows.push(buffer[consumed..].to_string());
        consumed = buffer.len();
    }

    if consumed > 0 {
        buffer.drain(..consumed);
    }

    rows
}

async fn read_log_segment_with_wait(
    path: &StdPath,
    start: usize,
    length: usize,
    timeout: Duration,
) -> String {
    use tokio::fs::File;
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    if length == 0 {
        return String::new();
    }

    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match tokio::fs::metadata(path).await {
            Ok(metadata) if metadata.len() as usize >= start.saturating_add(length) => break,
            Ok(_) | Err(_) if tokio::time::Instant::now() >= deadline => break,
            Ok(_) | Err(_) => tokio::time::sleep(Duration::from_millis(25)).await,
        }
    }

    let mut file = match File::open(path).await {
        Ok(file) => file,
        Err(_) => return String::new(),
    };

    if file
        .seek(std::io::SeekFrom::Start(start as u64))
        .await
        .is_err()
    {
        return String::new();
    }

    let mut buffer = vec![0u8; length];
    let bytes_read = match file.read(&mut buffer).await {
        Ok(bytes_read) => bytes_read,
        Err(_) => return String::new(),
    };
    buffer.truncate(bytes_read);

    String::from_utf8_lossy(&buffer).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_timing_skips_zero_rows() {
        let now = Utc::now();
        let parts = parse_timing("0\n0.1 5\n", now);

        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].length, 5);
    }

    #[test]
    fn drain_timing_rows_keeps_partial_rows_until_flush() {
        let mut buffer = "0.1 5\n0.2 7".to_string();
        let rows = drain_timing_rows(&mut buffer, false);

        assert_eq!(rows, vec!["0.1 5".to_string()]);
        assert_eq!(buffer, "0.2 7");

        let flushed = drain_timing_rows(&mut buffer, true);
        assert_eq!(flushed, vec!["0.2 7".to_string()]);
        assert!(buffer.is_empty());
    }

    #[test]
    fn format_log_line_matches_php_chunk_shape() {
        let line = format_log_line("2026-03-09T12:00:00.000+00:00", "hello\nworld");
        assert_eq!(line, "2026-03-09T12:00:00.000+00:00 hello\\nworld\n");
    }
}
