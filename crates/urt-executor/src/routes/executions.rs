//! Execution endpoint
//!
//! Includes TCP port readiness check (matching executor-main Docker.php:1088-1115)

use super::runtimes::{
    default_cpus, default_memory, default_restart_policy, default_timeout, default_version,
};
use super::AppState;
use crate::error::{ExecutorError, Result};
use crate::execution_counter::ExecutionGuard;
use crate::resilience::retry_with_backoff;
use crate::runtime::{get_protocol, wait_for_runtime_port, ExecuteRequest, ExecuteResponse};
use crate::tasks;
use crate::telemetry::{metrics, LatencyKind, OperationTimer};
use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue},
    response::{IntoResponse, Response},
    Json,
};
use bytes::{Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::debug;

/// Request body for execution
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionRequest {
    // Execution parameters
    #[serde(default)]
    pub body: String,
    #[serde(default = "default_path")]
    pub path: String,
    #[serde(default = "default_method")]
    pub method: String,
    #[serde(default)]
    pub headers: HeadersInput,
    #[serde(default = "default_exec_timeout")]
    pub timeout: u32,

    // Runtime creation parameters (for on-the-fly)
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub entrypoint: String,
    #[serde(default)]
    pub variables: VariablesInput,
    #[serde(default = "default_cpus")]
    pub cpus: f64,
    #[serde(default = "default_memory")]
    pub memory: u64,
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default)]
    pub runtime_entrypoint: String,
    #[serde(default = "default_logging")]
    pub logging: bool,
    #[serde(default = "default_restart_policy")]
    pub restart_policy: String,
}

fn default_path() -> String {
    "/".to_string()
}
fn default_method() -> String {
    "GET".to_string()
}
fn default_exec_timeout() -> u32 {
    15
}
fn default_logging() -> bool {
    true
}

const LEGACY_RESPONSE_FORMAT_CUTOFF: [u32; 3] = [0, 11, 0];

fn should_flatten_headers_for_legacy_response_format(response_format: &str) -> bool {
    let mut current = response_format.split('.');

    for rhs in LEGACY_RESPONSE_FORMAT_CUTOFF {
        let lhs = current
            .next()
            .and_then(|segment| segment.parse::<u32>().ok())
            .unwrap_or(0);
        if lhs != rhs {
            return lhs < rhs;
        }
    }

    false
}

fn flatten_headers_for_legacy_clients(headers: &mut HashMap<String, serde_json::Value>) {
    for value in headers.values_mut() {
        if let serde_json::Value::Array(items) = value {
            let replacement = items
                .iter()
                .rev()
                .find(|item| !item.is_null())
                .cloned()
                .unwrap_or(serde_json::Value::String(String::new()));
            *value = replacement;
        }
    }
}

/// Headers can be a string (JSON) or object
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(untagged)]
pub enum HeadersInput {
    #[default]
    Empty,
    String(String),
    Object(HashMap<String, String>),
}

impl HeadersInput {
    /// Consume the input into a HashMap, avoiding clones for object inputs.
    pub fn into_map(self) -> HashMap<String, String> {
        match self {
            HeadersInput::Empty => HashMap::new(),
            HeadersInput::String(s) => serde_json::from_str(&s).unwrap_or_default(),
            HeadersInput::Object(m) => m,
        }
    }
}

/// Variables can be a string (JSON) or object with any JSON values
/// Values are converted to strings (integers, booleans, etc become their string representation)
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(untagged)]
pub enum VariablesInput {
    #[default]
    Empty,
    String(String),
    Object(HashMap<String, serde_json::Value>),
}

impl VariablesInput {
    /// Convert any JSON value to a string representation
    fn value_to_string(v: &serde_json::Value) -> String {
        match v {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::Bool(b) => b.to_string(),
            serde_json::Value::Null => String::new(),
            // For arrays/objects, serialize to JSON string
            other => other.to_string(),
        }
    }

    /// Convert to HashMap<String, String>, converting all values to strings
    pub fn to_map(&self) -> HashMap<String, String> {
        match self {
            VariablesInput::Empty => HashMap::new(),
            VariablesInput::String(s) => {
                // Try to parse as HashMap<String, Value> first for flexibility
                if let Ok(map) = serde_json::from_str::<HashMap<String, serde_json::Value>>(s) {
                    map.iter()
                        .map(|(k, v)| (k.clone(), Self::value_to_string(v)))
                        .collect()
                } else {
                    HashMap::new()
                }
            }
            VariablesInput::Object(m) => m
                .iter()
                .map(|(k, v)| (k.clone(), Self::value_to_string(v)))
                .collect(),
        }
    }
}

/// JSON response format - matches Appwrite executor format
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonExecutionResponse {
    pub status_code: u16,
    pub body: String,
    pub logs: String,
    pub errors: String,
    pub headers: HashMap<String, serde_json::Value>,
    /// Execution duration in seconds
    pub duration: f64,
    /// Start time as Unix timestamp
    pub start_time: f64,
}

/// Build a multipart response from execution result
/// Optimized with BytesMut for pre-allocated buffer and zero-copy writes
fn build_multipart_response(response: &ExecuteResponse) -> Response {
    // Generate a unique boundary
    let boundary = format!("----UrtBoundary{:x}", rand::random::<u64>());

    // Pre-calculate approximate size for buffer allocation
    // This avoids repeated reallocations during building
    let estimated_size = response.body.len() +
        response.logs.len() +
        response.errors.len() +
        256 * 5 + // Headers overhead per part (~256 bytes each)
        64; // Status code and closing boundary

    let mut buf = BytesMut::with_capacity(estimated_size);

    // Helper macro to write a multipart part efficiently
    macro_rules! write_part {
        ($name:expr, $content_type:expr, $content:expr) => {
            buf.extend_from_slice(b"--");
            buf.extend_from_slice(boundary.as_bytes());
            buf.extend_from_slice(b"\r\nContent-Disposition: form-data; name=\"");
            buf.extend_from_slice($name);
            buf.extend_from_slice(b"\"\r\nContent-Type: ");
            buf.extend_from_slice($content_type);
            buf.extend_from_slice(b"\r\n\r\n");
            buf.extend_from_slice($content);
            buf.extend_from_slice(b"\r\n");
        };
    }

    // Add parts using zero-copy writes - field names match Appwrite executor format
    write_part!(b"body", b"text/plain", &response.body);
    write_part!(b"logs", b"text/plain", response.logs.as_bytes());
    write_part!(b"errors", b"text/plain", response.errors.as_bytes());

    // Status code - use itoa for fast integer formatting
    let mut status_buf = itoa::Buffer::new();
    let status_str = status_buf.format(response.status_code);
    write_part!(b"statusCode", b"text/plain", status_str.as_bytes());

    // Duration in seconds
    let duration_str = format!("{:.6}", response.duration);
    write_part!(b"duration", b"text/plain", duration_str.as_bytes());

    // Start time as Unix timestamp
    let start_time_str = format!("{:.6}", response.start_time);
    write_part!(b"startTime", b"text/plain", start_time_str.as_bytes());

    // Headers as JSON - serialize directly to Vec to avoid intermediate String
    let headers_json = serde_json::to_vec(&response.headers).unwrap_or_default();
    write_part!(b"headers", b"application/json", &headers_json);

    // Add closing boundary (terminate with CRLF for stricter multipart parsers)
    buf.extend_from_slice(b"--");
    buf.extend_from_slice(boundary.as_bytes());
    buf.extend_from_slice(b"--\r\n");

    let body = buf.freeze();
    let len = body.len();

    Response::builder()
        .status(200)
        .header(
            header::CONTENT_TYPE,
            HeaderValue::from_str(&format!("multipart/form-data; boundary={}", boundary)).unwrap(),
        )
        .header(
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&len.to_string()).unwrap(),
        )
        .header(
            "x-open-runtimes-status-code",
            HeaderValue::from_str(status_str).unwrap(),
        )
        .body(Body::from(body))
        .unwrap()
}

/// Parse multipart form data into ExecutionRequest
/// Handles the multipart/form-data format sent by PHP Appwrite executor client
#[allow(dead_code)]
fn parse_multipart_execution_request(body: &str, content_type: &str) -> Result<ExecutionRequest> {
    // Extract boundary from content-type header
    let boundary = content_type
        .split("boundary=")
        .nth(1)
        .map(|b| b.trim_matches('"'))
        .ok_or_else(|| {
            ExecutorError::ExecutionBadRequest("Missing multipart boundary".to_string())
        })?;

    let mut fields: HashMap<String, String> = HashMap::new();

    // Parse multipart parts
    let delimiter = format!("--{}", boundary);
    let parts: Vec<&str> = body.split(&delimiter).collect();

    for part in parts {
        let part = part.trim();
        if part.is_empty() || part == "--" {
            continue;
        }

        // Split headers from content
        if let Some(header_end) = part.find("\r\n\r\n") {
            let headers_section = &part[..header_end];
            let content = &part[header_end + 4..];
            let content = content.trim_end_matches("\r\n");

            // Extract field name from Content-Disposition
            if let Some(name_start) = headers_section.find("name=\"") {
                let name_start = name_start + 6;
                if let Some(name_end) = headers_section[name_start..].find('"') {
                    let name = &headers_section[name_start..name_start + name_end];
                    fields.insert(name.to_string(), content.to_string());
                }
            }
        }
    }

    // Build ExecutionRequest from parsed fields
    Ok(ExecutionRequest {
        body: fields.get("body").cloned().unwrap_or_default(),
        path: fields.get("path").cloned().unwrap_or_else(default_path),
        method: fields.get("method").cloned().unwrap_or_else(default_method),
        headers: fields
            .get("headers")
            .map(|s| HeadersInput::String(s.clone()))
            .unwrap_or_default(),
        timeout: fields
            .get("timeout")
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(default_exec_timeout),
        image: fields.get("image").cloned().unwrap_or_default(),
        source: fields.get("source").cloned().unwrap_or_default(),
        entrypoint: fields.get("entrypoint").cloned().unwrap_or_default(),
        variables: fields
            .get("variables")
            .map(|s| VariablesInput::String(s.clone()))
            .unwrap_or_default(),
        cpus: fields
            .get("cpus")
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(default_cpus),
        memory: fields
            .get("memory")
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(default_memory),
        version: fields
            .get("version")
            .cloned()
            .unwrap_or_else(default_version),
        runtime_entrypoint: fields.get("runtimeEntrypoint").cloned().unwrap_or_default(),
        logging: fields
            .get("logging")
            .map(|s| s == "true" || s == "1")
            .unwrap_or_else(default_logging),
        restart_policy: fields
            .get("restartPolicy")
            .cloned()
            .unwrap_or_else(default_restart_policy),
    })
}

/// POST /v1/runtimes/:runtime_id/executions - Execute a function
/// Note: Accepts both JSON and multipart/form-data for backwards compatibility
pub async fn create_execution(
    State(state): State<AppState>,
    Path(runtime_id): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response> {
    let mut operation_timer = OperationTimer::new(LatencyKind::Execution);
    let _execution_guard = ExecutionGuard::new();

    debug!(runtime_id = %runtime_id, "Executing function in runtime");

    // Check Content-Type to determine parsing strategy
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    debug!(
        "Execution request content-type: {}, body length: {}",
        content_type,
        body.len()
    );

    let req: ExecutionRequest = if content_type.contains("application/json") {
        serde_json::from_slice(&body)
            .map_err(|e| ExecutorError::ExecutionBadRequest(format!("Invalid JSON body: {}", e)))?
    } else if content_type.contains("multipart/form-data") {
        parse_multipart_execution_request_bytes(&body, content_type)?
    } else {
        return Err(ExecutorError::ExecutionBadRequest(format!(
            "Unsupported Content-Type: {}",
            content_type
        )));
    };

    // Validate execution request
    if req.timeout == 0 {
        return Err(ExecutorError::ExecutionBadRequest(
            "Timeout must be greater than 0".to_string(),
        ));
    }
    if req.timeout > 900 {
        return Err(ExecutorError::ExecutionBadRequest(
            "Timeout cannot exceed 900 seconds".to_string(),
        ));
    }

    let queue_wait_started = Instant::now();
    let _execution_permit = match &state.execution_limiter {
        Some(limiter) => {
            let queue_wait_timeout = Duration::from_millis(state.config.execution_queue_wait_ms);
            match tokio::time::timeout(queue_wait_timeout, limiter.clone().acquire_owned()).await {
                Ok(Ok(permit)) => {
                    metrics().observe_execution_queue_wait(queue_wait_started.elapsed());
                    Some(permit)
                }
                Ok(Err(_)) => return Err(ExecutorError::Unknown),
                Err(_) => {
                    metrics().observe_execution_queue_wait(queue_wait_timeout);
                    metrics().inc_error_class("create_execution", "overload");
                    operation_timer.mark_overload();
                    return Err(ExecutorError::ExecutionOverloaded);
                }
            }
        }
        None => None,
    };

    let full_name = format!("{}-{}", state.config.hostname, runtime_id);

    let runtime = resolve_runtime(&state, &runtime_id, &full_name, &req).await?;

    // Coalesce activity updates to reduce write contention on the runtime registry.
    state.registry.touch_if_stale(&full_name, 1.0).await.ok();

    // TCP port readiness check (matching executor-main Docker.php:1088-1115)
    // On first execution, wait for the runtime to start listening on port 3000
    if !runtime.is_listening() {
        debug!(
            "Checking if runtime {} is listening on port 3000",
            runtime.name
        );
        let port_timeout = Duration::from_secs(req.timeout as u64);
        wait_for_runtime_port(&runtime.name, 3000, port_timeout).await?;

        // Mark runtime as listening so we skip this check on subsequent executions
        if let Err(e) = state.registry.set_listening(&full_name).await {
            debug!("Failed to mark runtime as listening: {}", e);
        }
        debug!("Runtime {} is now listening", runtime.hostname);
    }

    // Build execution request
    // IMPORTANT: Always force identity encoding when talking to the runtime.
    // If we forward an incoming `accept-encoding` (e.g. gzip), different HTTP clients/proxies may
    // transparently decode/encode which can lead to mismatched lengths / truncated bodies.
    let ExecutionRequest {
        body,
        path,
        method,
        headers: request_headers,
        timeout,
        logging,
        ..
    } = req;

    let mut exec_headers = request_headers.into_map();
    exec_headers.insert("accept-encoding".to_string(), "identity".to_string());

    let mut method = method;
    method.make_ascii_uppercase();

    let exec_req = ExecuteRequest {
        body: Bytes::from(body),
        path,
        method,
        headers: exec_headers,
        timeout,
        logging,
    };

    debug!("Executing with protocol {}", runtime.version);

    // Get protocol handler
    let protocol = get_protocol(&runtime.version);

    // Execute with jittered retries for transient runtime networking failures.
    let response: ExecuteResponse = retry_with_backoff(
        "execution_protocol",
        state.config.retry_attempts,
        state.config.retry_delay_ms,
        |_| async {
            protocol
                .execute(&runtime, &exec_req, &state.http_client)
                .await
        },
    )
    .await
    .map_err(|err| {
        if matches!(err, ExecutorError::Network(_)) {
            ExecutorError::RuntimeTimeout
        } else {
            err
        }
    })?;

    let response_format = headers
        .get("x-executor-response-format")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("0.10.0");

    let mut response = response;
    if should_flatten_headers_for_legacy_response_format(response_format) {
        flatten_headers_for_legacy_clients(&mut response.headers);
    }

    // Determine response format based on Accept header
    // Matches executor-main: default to multipart unless JSON is explicitly requested.
    let accept = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("multipart/form-data");

    if !accepts_json(accept) {
        // Return multipart response
        operation_timer.mark_success();
        return Ok(build_multipart_response(&response));
    }

    // JSON response - reject binary bodies like executor-main
    let body = std::str::from_utf8(response.body.as_ref()).map_err(|_| {
        ExecutorError::ExecutionBadJson(
            "Execution resulted in binary response, but JSON response does not allow binaries. Use \"Accept: multipart/form-data\" header to support binaries.".to_string(),
        )
    })?;

    operation_timer.mark_success();
    Ok(Json(JsonExecutionResponse {
        status_code: response.status_code,
        body: body.to_owned(),
        logs: response.logs,
        errors: response.errors,
        headers: response.headers,
        duration: response.duration,
        start_time: response.start_time,
    })
    .into_response())
}

async fn resolve_runtime(
    state: &AppState,
    runtime_id: &str,
    full_name: &str,
    req: &ExecutionRequest,
) -> Result<crate::runtime::Runtime> {
    if let Some(runtime) = state.registry.get(full_name).await {
        if runtime.is_pending() {
            state.registry.sync_status(full_name, &state.docker).await;
            match state.registry.get(full_name).await {
                Some(updated) if !updated.is_pending() => return Ok(updated),
                Some(_) => return Err(ExecutorError::RuntimeTimeout),
                None => {}
            }
        } else {
            return Ok(runtime);
        }
    }

    // If runtime metadata is missing (e.g., executor restart), attempt on-demand re-adoption.
    let _ = tasks::adopt_container_by_name(
        &state.docker,
        &state.registry,
        &state.keep_alive_registry,
        &state.config.hostname,
        full_name,
    )
    .await;

    if let Some(runtime) = state.registry.get(full_name).await {
        if runtime.is_pending() {
            state.registry.sync_status(full_name, &state.docker).await;
            return match state.registry.get(full_name).await {
                Some(updated) if !updated.is_pending() => Ok(updated),
                Some(_) => Err(ExecutorError::RuntimeTimeout),
                None => Err(ExecutorError::RuntimeNotFound),
            };
        }

        return Ok(runtime);
    }

    // On-the-fly creation if image is provided
    if req.image.is_empty() {
        return Err(ExecutorError::RuntimeNotFound);
    }

    debug!("Creating runtime on-the-fly: {}", runtime_id);

    let create_req_json = serde_json::json!({
        "runtimeId": runtime_id,
        "image": req.image,
        "entrypoint": req.entrypoint,
        "source": req.source,
        "destination": "",
        "outputDirectory": "",
        "variables": req.variables.to_map(),
        "runtimeEntrypoint": req.runtime_entrypoint,
        "command": "",
        "timeout": default_timeout(),
        "remove": false,
        "cpus": req.cpus,
        "memory": req.memory,
        "version": req.version,
        "restartPolicy": req.restart_policy,
        "dockerCmd": []
    });

    let _ = super::runtimes::create_runtime(
        State(state.clone()),
        serde_json::to_string(&create_req_json).unwrap_or_default(),
    )
    .await?;

    state
        .registry
        .get(full_name)
        .await
        .ok_or(ExecutorError::RuntimeNotFound)
}

fn parse_multipart_execution_request_bytes(
    body: &[u8],
    content_type: &str,
) -> Result<ExecutionRequest> {
    fn parse_field_name(headers: &[u8]) -> Result<&str> {
        let name_marker = b"name=\"";
        let name_start = memchr::memmem::find(headers, name_marker)
            .ok_or_else(|| ExecutorError::ExecutionBadRequest("Missing field name".into()))?
            + name_marker.len();
        let name_len = memchr::memchr(b'"', &headers[name_start..])
            .ok_or_else(|| ExecutorError::ExecutionBadRequest("Missing field name".into()))?;

        std::str::from_utf8(&headers[name_start..name_start + name_len]).map_err(|_| {
            ExecutorError::ExecutionBadRequest("Multipart field name must be valid UTF-8".into())
        })
    }

    fn parse_string(value: &[u8]) -> String {
        String::from_utf8_lossy(value).into_owned()
    }

    fn parse_u32(value: &[u8]) -> Option<u32> {
        std::str::from_utf8(value).ok()?.parse().ok()
    }

    fn parse_u64(value: &[u8]) -> Option<u64> {
        std::str::from_utf8(value).ok()?.parse().ok()
    }

    fn parse_f64(value: &[u8]) -> Option<f64> {
        std::str::from_utf8(value).ok()?.parse().ok()
    }

    let boundary = content_type
        .split("boundary=")
        .nth(1)
        .map(|b| b.trim_matches('"'))
        .ok_or_else(|| {
            ExecutorError::ExecutionBadRequest("Missing multipart boundary".to_string())
        })?;

    let boundary_bytes = format!("--{}", boundary).into_bytes();
    let mut request = ExecutionRequest {
        body: String::new(),
        path: default_path(),
        method: default_method(),
        headers: HeadersInput::default(),
        timeout: default_exec_timeout(),
        image: String::new(),
        source: String::new(),
        entrypoint: String::new(),
        variables: VariablesInput::default(),
        cpus: default_cpus(),
        memory: default_memory(),
        version: default_version(),
        runtime_entrypoint: String::new(),
        logging: default_logging(),
        restart_policy: default_restart_policy(),
    };

    let mut i = 0;
    while i < body.len() {
        if body[i..].starts_with(&boundary_bytes) {
            i += boundary_bytes.len();

            // Skip CRLF
            if body[i..].starts_with(b"\r\n") {
                i += 2;
            }

            // End boundary
            if body[i..].starts_with(b"--") {
                break;
            }

            // Headers
            let headers_end = memchr::memmem::find(&body[i..], b"\r\n\r\n")
                .ok_or_else(|| ExecutorError::ExecutionBadRequest("Malformed multipart".into()))?;
            let headers = &body[i..i + headers_end];
            i += headers_end + 4;

            let name = parse_field_name(headers)?;

            let next_boundary = memchr::memmem::find(&body[i..], &boundary_bytes)
                .ok_or_else(|| ExecutorError::ExecutionBadRequest("Malformed multipart".into()))?;

            let mut value = &body[i..i + next_boundary];

            // Trim trailing CRLF
            if value.ends_with(b"\r\n") {
                value = &value[..value.len() - 2];
            }

            match name {
                "body" => request.body = parse_string(value),
                "path" => request.path = parse_string(value),
                "method" => request.method = parse_string(value),
                "headers" => request.headers = HeadersInput::String(parse_string(value)),
                "timeout" => {
                    if let Some(timeout) = parse_u32(value) {
                        request.timeout = timeout;
                    }
                }
                "image" => request.image = parse_string(value),
                "source" => request.source = parse_string(value),
                "entrypoint" => request.entrypoint = parse_string(value),
                "variables" => request.variables = VariablesInput::String(parse_string(value)),
                "cpus" => {
                    if let Some(cpus) = parse_f64(value) {
                        request.cpus = cpus;
                    }
                }
                "memory" => {
                    if let Some(memory) = parse_u64(value) {
                        request.memory = memory;
                    }
                }
                "version" => request.version = parse_string(value),
                "runtimeEntrypoint" => request.runtime_entrypoint = parse_string(value),
                "logging" => request.logging = value == b"true" || value == b"1",
                "restartPolicy" => request.restart_policy = parse_string(value),
                _ => {}
            }
            i += next_boundary;
        } else {
            i += 1;
        }
    }

    Ok(request)
}

/// Determine if the Accept header requests JSON.
/// Matches executor-main: JSON only when Accept contains application/json or application/*.
fn accepts_json(accept: &str) -> bool {
    accept
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .any(|entry| {
            let mime = entry.split(';').next().unwrap_or(entry).trim();
            mime.starts_with("application/json") || mime.starts_with("application/*")
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // HeadersInput tests
    mod headers_input {
        use super::*;

        #[test]
        fn test_empty() {
            let headers = HeadersInput::Empty;
            let map = headers.into_map();
            assert!(map.is_empty());
        }

        #[test]
        fn test_object() {
            let mut map = HashMap::new();
            map.insert("content-type".to_string(), "application/json".to_string());
            map.insert("accept".to_string(), "*/*".to_string());

            let headers = HeadersInput::Object(map.clone());
            let result = headers.into_map();
            assert_eq!(result.len(), 2);
            assert_eq!(
                result.get("content-type"),
                Some(&"application/json".to_string())
            );
        }

        #[test]
        fn test_string_json() {
            let headers = HeadersInput::String(
                r#"{"content-type": "text/html", "x-custom": "value"}"#.to_string(),
            );
            let map = headers.into_map();
            assert_eq!(map.get("content-type"), Some(&"text/html".to_string()));
            assert_eq!(map.get("x-custom"), Some(&"value".to_string()));
        }

        #[test]
        fn test_string_invalid_json_returns_empty() {
            let headers = HeadersInput::String("not json".to_string());
            let map = headers.into_map();
            assert!(map.is_empty());
        }

        #[test]
        fn test_string_empty_json() {
            let headers = HeadersInput::String("{}".to_string());
            let map = headers.into_map();
            assert!(map.is_empty());
        }
    }

    // VariablesInput tests
    mod variables_input {
        use super::*;
        use serde_json::json;

        #[test]
        fn test_empty() {
            let vars = VariablesInput::Empty;
            let map = vars.to_map();
            assert!(map.is_empty());
        }

        #[test]
        fn test_object_string_values() {
            let mut map = HashMap::new();
            map.insert("KEY1".to_string(), json!("value1"));
            map.insert("KEY2".to_string(), json!("value2"));

            let vars = VariablesInput::Object(map);
            let result = vars.to_map();
            assert_eq!(result.get("KEY1"), Some(&"value1".to_string()));
            assert_eq!(result.get("KEY2"), Some(&"value2".to_string()));
        }

        #[test]
        fn test_object_number_values() {
            let mut map = HashMap::new();
            map.insert("PORT".to_string(), json!(8080));
            map.insert("RATIO".to_string(), json!(std::f64::consts::PI));

            let vars = VariablesInput::Object(map);
            let result = vars.to_map();
            assert_eq!(result.get("PORT"), Some(&"8080".to_string()));
            assert_eq!(result.get("RATIO"), Some(&"3.141592653589793".to_string()));
        }

        #[test]
        fn test_object_bool_values() {
            let mut map = HashMap::new();
            map.insert("DEBUG".to_string(), json!(true));
            map.insert("VERBOSE".to_string(), json!(false));

            let vars = VariablesInput::Object(map);
            let result = vars.to_map();
            assert_eq!(result.get("DEBUG"), Some(&"true".to_string()));
            assert_eq!(result.get("VERBOSE"), Some(&"false".to_string()));
        }

        #[test]
        fn test_object_null_values() {
            let mut map = HashMap::new();
            map.insert("NULL_VAR".to_string(), json!(null));

            let vars = VariablesInput::Object(map);
            let result = vars.to_map();
            assert_eq!(result.get("NULL_VAR"), Some(&"".to_string()));
        }

        #[test]
        fn test_object_array_values() {
            let mut map = HashMap::new();
            map.insert("ARRAY".to_string(), json!(["a", "b", "c"]));

            let vars = VariablesInput::Object(map);
            let result = vars.to_map();
            assert_eq!(
                result.get("ARRAY"),
                Some(&"[\"a\",\"b\",\"c\"]".to_string())
            );
        }

        #[test]
        fn test_object_nested_object() {
            let mut map = HashMap::new();
            map.insert("NESTED".to_string(), json!({"inner": "value"}));

            let vars = VariablesInput::Object(map);
            let result = vars.to_map();
            assert!(result.get("NESTED").unwrap().contains("inner"));
        }

        #[test]
        fn test_string_json() {
            let vars = VariablesInput::String(r#"{"KEY": "value", "NUM": 42}"#.to_string());
            let result = vars.to_map();
            assert_eq!(result.get("KEY"), Some(&"value".to_string()));
            assert_eq!(result.get("NUM"), Some(&"42".to_string()));
        }

        #[test]
        fn test_string_invalid_json_returns_empty() {
            let vars = VariablesInput::String("not json".to_string());
            let result = vars.to_map();
            assert!(result.is_empty());
        }

        #[test]
        fn test_value_to_string_string() {
            assert_eq!(VariablesInput::value_to_string(&json!("test")), "test");
        }

        #[test]
        fn test_value_to_string_number() {
            assert_eq!(VariablesInput::value_to_string(&json!(42)), "42");
            assert_eq!(
                VariablesInput::value_to_string(&json!(std::f64::consts::PI)),
                "3.141592653589793"
            );
        }

        #[test]
        fn test_value_to_string_bool() {
            assert_eq!(VariablesInput::value_to_string(&json!(true)), "true");
            assert_eq!(VariablesInput::value_to_string(&json!(false)), "false");
        }

        #[test]
        fn test_value_to_string_null() {
            assert_eq!(VariablesInput::value_to_string(&json!(null)), "");
        }
    }

    // Multipart parsing tests
    mod multipart_parsing {
        use super::*;

        #[test]
        fn test_parse_multipart_basic() {
            // Use \r\n format as expected by implementation
            let body = "--boundary\r\nContent-Disposition: form-data; name=\"body\"\r\n\r\ntest body\r\n--boundary\r\nContent-Disposition: form-data; name=\"path\"\r\n\r\n/api/test\r\n--boundary\r\nContent-Disposition: form-data; name=\"method\"\r\n\r\nPOST\r\n--boundary--";
            let result =
                parse_multipart_execution_request(body, "multipart/form-data; boundary=boundary");
            assert!(result.is_ok());
            let req = result.unwrap();
            assert_eq!(req.body, "test body");
            assert_eq!(req.path, "/api/test");
            assert_eq!(req.method, "POST");
        }

        #[test]
        fn test_parse_multipart_with_headers() {
            let body = "--boundary\r\nContent-Disposition: form-data; name=\"body\"\r\n\r\n{\"key\":\"value\"}\r\n--boundary\r\nContent-Disposition: form-data; name=\"headers\"\r\n\r\n{\"content-type\": \"application/json\"}\r\n--boundary--";
            let result =
                parse_multipart_execution_request(body, "multipart/form-data; boundary=boundary");
            assert!(result.is_ok());
            let req = result.unwrap();
            assert_eq!(req.body, r#"{"key":"value"}"#);
            let headers = req.headers.into_map();
            assert_eq!(
                headers.get("content-type"),
                Some(&"application/json".to_string())
            );
        }

        #[test]
        fn test_parse_multipart_with_variables() {
            let body = "--boundary\r\nContent-Disposition: form-data; name=\"body\"\r\n\r\ntest\r\n--boundary\r\nContent-Disposition: form-data; name=\"variables\"\r\n\r\n{\"DATABASE_URL\": \"postgres://localhost/db\", \"POOL_SIZE\": 10}\r\n--boundary--";
            let result =
                parse_multipart_execution_request(body, "multipart/form-data; boundary=boundary");
            assert!(result.is_ok());
            let req = result.unwrap();
            let vars = req.variables.to_map();
            assert_eq!(
                vars.get("DATABASE_URL"),
                Some(&"postgres://localhost/db".to_string())
            );
            assert_eq!(vars.get("POOL_SIZE"), Some(&"10".to_string()));
        }

        #[test]
        fn test_parse_multipart_with_numeric_fields() {
            let body = "--boundary\r\nContent-Disposition: form-data; name=\"body\"\r\n\r\ntest\r\n--boundary\r\nContent-Disposition: form-data; name=\"timeout\"\r\n\r\n30\r\n--boundary\r\nContent-Disposition: form-data; name=\"cpus\"\r\n\r\n2.5\r\n--boundary\r\nContent-Disposition: form-data; name=\"memory\"\r\n\r\n512\r\n--boundary--";
            let result =
                parse_multipart_execution_request(body, "multipart/form-data; boundary=boundary");
            assert!(result.is_ok());
            let req = result.unwrap();
            assert_eq!(req.timeout, 30);
            assert_eq!(req.cpus, 2.5);
            assert_eq!(req.memory, 512);
        }

        #[test]
        fn test_parse_multipart_invalid_boundary() {
            let body = "--boundary\r\nContent-Disposition: form-data; name=\"body\"\r\n\r\ntest\r\n--boundary--";
            let result = parse_multipart_execution_request(body, "multipart/form-data");
            assert!(result.is_err());
        }

        #[test]
        fn test_parse_multipart_empty_body() {
            let body = "--boundary--";
            let result =
                parse_multipart_execution_request(body, "multipart/form-data; boundary=boundary");
            assert!(result.is_ok());
            let req = result.unwrap();
            assert!(req.body.is_empty());
            assert_eq!(req.path, "/"); // default
            assert_eq!(req.method, "GET"); // default
        }

        #[test]
        fn test_parse_multipart_bytes_basic() {
            let body = "--boundary\r\nContent-Disposition: form-data; name=\"body\"\r\n\r\ntest body\r\n--boundary\r\nContent-Disposition: form-data; name=\"path\"\r\n\r\n/test\r\n--boundary--".to_string();
            let result = parse_multipart_execution_request_bytes(
                body.as_bytes(),
                "multipart/form-data; boundary=boundary",
            );
            assert!(result.is_ok());
            let req = result.unwrap();
            assert_eq!(req.body, "test body");
            assert_eq!(req.path, "/test");
        }

        #[test]
        fn test_parse_multipart_bytes_with_binary_body() {
            let body = "--boundary\r\nContent-Disposition: form-data; name=\"body\"; filename=\"test.txt\"\r\n\r\n\x00\x01\x02\x03\r\n--boundary--".to_string();
            let result = parse_multipart_execution_request_bytes(
                body.as_bytes(),
                "multipart/form-data; boundary=boundary",
            );
            assert!(result.is_ok());
            let req = result.unwrap();
            // Binary content should be preserved
            assert_eq!(req.body.as_bytes(), vec![0, 1, 2, 3]);
        }

        #[test]
        fn test_parse_multipart_quoted_boundary() {
            let body = "--boundary\r\nContent-Disposition: form-data; name=\"body\"\r\n\r\ntest\r\n--boundary--";
            let result = parse_multipart_execution_request(
                body,
                r#"multipart/form-data; boundary="boundary""#,
            );
            assert!(result.is_ok());
            let req = result.unwrap();
            assert_eq!(req.body, "test");
        }

        #[test]
        fn test_parse_multipart_missing_content_disposition() {
            let body = "--boundary\r\nContent-Type: text/plain\r\n\r\ntest\r\n--boundary--";
            let result =
                parse_multipart_execution_request(body, "multipart/form-data; boundary=boundary");
            assert!(result.is_ok()); // Should still parse, just skip this part
            let req = result.unwrap();
            assert!(req.body.is_empty()); // Body part was skipped
        }
    }

    // JSON response format tests
    mod json_response_format {
        use super::*;

        #[test]
        fn test_json_execution_response_serialization() {
            let response = JsonExecutionResponse {
                status_code: 200,
                body: "response body".to_string(),
                logs: "info: started\ninfo: done".to_string(),
                errors: "".to_string(),
                headers: HashMap::from([
                    ("content-type".to_string(), json!("application/json")),
                    ("x-request-id".to_string(), json!("abc123")),
                ]),
                duration: 0.123456,
                start_time: 1699999999.123456,
            };

            let json = serde_json::to_string(&response).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

            assert_eq!(parsed["statusCode"], 200);
            assert_eq!(parsed["body"], "response body");
            assert_eq!(parsed["logs"], "info: started\ninfo: done");
            assert_eq!(parsed["errors"], "");
            assert_eq!(parsed["duration"], 0.123456);
            assert!(parsed["startTime"].is_number());
        }

        #[test]
        fn test_legacy_response_format_requires_header_flattening() {
            assert!(should_flatten_headers_for_legacy_response_format("0.10.0"));
            assert!(should_flatten_headers_for_legacy_response_format("0.10.9"));
            assert!(!should_flatten_headers_for_legacy_response_format("0.11.0"));
            assert!(!should_flatten_headers_for_legacy_response_format("0.11"));
            assert!(!should_flatten_headers_for_legacy_response_format(
                "0.11.0.1"
            ));
            assert!(!should_flatten_headers_for_legacy_response_format("0.12.1"));
        }

        #[test]
        fn test_flatten_headers_for_legacy_clients_keeps_last_value() {
            let mut headers = HashMap::from([
                (
                    "set-cookie".to_string(),
                    json!(["first=value", "second=value"]),
                ),
                ("content-type".to_string(), json!("application/json")),
            ]);

            flatten_headers_for_legacy_clients(&mut headers);

            assert_eq!(headers.get("set-cookie"), Some(&json!("second=value")));
            assert_eq!(
                headers.get("content-type"),
                Some(&json!("application/json"))
            );
        }
    }

    // Default values tests
    mod default_values {
        use super::*;

        #[test]
        fn test_default_path() {
            assert_eq!(default_path(), "/");
        }

        #[test]
        fn test_default_method() {
            assert_eq!(default_method(), "GET");
        }

        #[test]
        fn test_default_exec_timeout() {
            assert_eq!(default_exec_timeout(), 15);
        }

        #[test]
        fn test_default_logging() {
            assert!(default_logging());
        }
    }

    // ExecutionRequest parsing tests
    mod execution_request_parsing {
        use super::*;

        #[test]
        fn test_execution_request_from_json() {
            let json = r#"{
                "body": "test body",
                "path": "/api/endpoint",
                "method": "POST",
                "headers": {"content-type": "application/json"},
                "timeout": 30,
                "variables": {"KEY": "value"}
            }"#;

            let req: ExecutionRequest = serde_json::from_str(json).unwrap();
            assert_eq!(req.body, "test body");
            assert_eq!(req.path, "/api/endpoint");
            assert_eq!(req.method, "POST");
            assert_eq!(req.timeout, 30);
            assert_eq!(
                req.headers.into_map().get("content-type"),
                Some(&"application/json".to_string())
            );
            assert_eq!(
                req.variables.to_map().get("KEY"),
                Some(&"value".to_string())
            );
        }

        #[test]
        fn test_execution_request_defaults() {
            let req: ExecutionRequest = serde_json::from_str("{}").unwrap();
            assert!(req.body.is_empty());
            assert_eq!(req.path, "/");
            assert_eq!(req.method, "GET");
            assert_eq!(req.timeout, 15); // default_exec_timeout
            assert!(req.logging); // default_logging
        }

        #[test]
        fn test_execution_request_headers_as_string() {
            let json = r#"{
                "headers": "{\"content-type\": \"text/html\"}"
            }"#;

            let req: ExecutionRequest = serde_json::from_str(json).unwrap();
            let headers = req.headers.into_map();
            assert_eq!(headers.get("content-type"), Some(&"text/html".to_string()));
        }

        #[test]
        fn test_execution_request_variables_as_string() {
            let json = r#"{
                "variables": "{\"DATABASE_URL\": \"postgres://localhost\"}"
            }"#;

            let req: ExecutionRequest = serde_json::from_str(json).unwrap();
            let vars = req.variables.to_map();
            assert_eq!(
                vars.get("DATABASE_URL"),
                Some(&"postgres://localhost".to_string())
            );
        }
    }
}
