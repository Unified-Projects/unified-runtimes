//! Execution endpoint
//!
//! Includes TCP port readiness check (matching executor-main Docker.php:1088-1115)

use super::runtimes::{
    default_cpus, default_memory, default_restart_policy, default_timeout, default_version,
};
use super::AppState;
use crate::error::{ExecutorError, Result};
use crate::runtime::{get_protocol, ExecuteRequest, ExecuteResponse};
use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue},
    response::{IntoResponse, Response},
    Json,
};
use bytes::BytesMut;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
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
    /// Returns a reference or owned HashMap - avoids clone when already Object
    /// Uses Cow for zero-copy when the data is already in the right format
    #[inline]
    pub fn to_map_cow(&self) -> Cow<'_, HashMap<String, String>> {
        match self {
            HeadersInput::Empty => Cow::Owned(HashMap::new()),
            HeadersInput::String(s) => Cow::Owned(serde_json::from_str(s).unwrap_or_default()),
            HeadersInput::Object(m) => Cow::Borrowed(m),
        }
    }

    /// Legacy method for compatibility - clones the data
    pub fn to_map(&self) -> HashMap<String, String> {
        self.to_map_cow().into_owned()
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
    debug!("Executing function in runtime: {}", runtime_id);

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

    let full_name = format!("{}-{}", state.config.hostname, runtime_id);

    // Get or create runtime
    let runtime = match state.registry.get(&full_name).await {
        Some(rt) => {
            // Check if runtime is ready
            if rt.is_pending() {
                return Err(ExecutorError::RuntimeTimeout);
            }
            rt
        }
        None => {
            // On-the-fly creation if image is provided
            if req.image.is_empty() {
                return Err(ExecutorError::RuntimeNotFound);
            }

            debug!("Creating runtime on-the-fly: {}", runtime_id);

            // Create runtime request as JSON for internal call
            let create_req_json = serde_json::json!({
                "runtimeId": runtime_id.clone(),
                "image": req.image.clone(),
                "entrypoint": req.entrypoint.clone(),
                "source": req.source.clone(),
                "destination": "",
                "outputDirectory": "",
                "variables": req.variables.to_map(),
                "runtimeEntrypoint": req.runtime_entrypoint.clone(),
                "command": "",
                "timeout": default_timeout(),
                "remove": false,
                "cpus": req.cpus,
                "memory": req.memory,
                "version": req.version.clone(),
                "restartPolicy": req.restart_policy.clone(),
                "dockerCmd": []
            });

            // Call create_runtime internally
            let _ = super::runtimes::create_runtime(
                State(state.clone()),
                serde_json::to_string(&create_req_json).unwrap_or_default(),
            )
            .await?;

            // Get the created runtime
            state
                .registry
                .get(&full_name)
                .await
                .ok_or(ExecutorError::RuntimeNotFound)?
        }
    };

    // Touch runtime to update last activity
    state.registry.touch(&full_name).await.ok();

    // TCP port readiness check (matching executor-main Docker.php:1088-1115)
    // On first execution, wait for the runtime to start listening on port 3000
    if !runtime.is_listening() {
        debug!(
            "Checking if runtime {} is listening on port 3000",
            runtime.hostname
        );
        let port_timeout = Duration::from_secs(req.timeout as u64);
        wait_for_port(&runtime.hostname, 3000, port_timeout).await?;

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
    let mut exec_headers = req.headers.to_map();
    exec_headers.insert("accept-encoding".to_string(), "identity".to_string());

    let exec_req = ExecuteRequest {
        body: req.body,
        path: req.path,
        method: req.method.to_uppercase(),
        headers: exec_headers,
        timeout: req.timeout,
        logging: req.logging,
    };

    debug!("Executing with protocol {}", runtime.version);

    // Get protocol handler
    let protocol = get_protocol(&runtime.version);

    // Execute with retries for transient network errors while the runtime boots.
    let mut attempt = 0;
    let max_attempts = state.config.retry_attempts.max(1);
    let response = loop {
        match protocol
            .execute(&runtime, &exec_req, &state.http_client)
            .await
        {
            Ok(response) => break response,
            Err(ExecutorError::Network(err)) => {
                attempt += 1;
                if attempt >= max_attempts {
                    return Err(ExecutorError::RuntimeTimeout);
                }
                debug!(
                    "Execution network error (attempt {}/{}): {}",
                    attempt, max_attempts, err
                );
                tokio::time::sleep(Duration::from_millis(state.config.retry_delay_ms)).await;
            }
            Err(err) => return Err(err),
        }
    };

    // Determine response format based on Accept header
    let accept = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json");

    if accept.contains("multipart/form-data") {
        // Return multipart response
        return Ok(build_multipart_response(&response));
    }

    if accept.contains("text/plain") {
        // Return plain text (just body)
        let mut res = Response::builder()
            .status(200)
            .header(
                header::CONTENT_TYPE,
                response
                    .headers
                    .get("content-type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("text/plain"),
            )
            .header(
                "x-open-runtimes-status-code",
                response.status_code.to_string(),
            )
            .header("x-open-runtimes-logs", base64_encode(&response.logs))
            .header("x-open-runtimes-errors", base64_encode(&response.errors))
            .body(Body::from(response.body))
            .unwrap();

        for (key, value) in &response.headers {
            if !should_forward_header(key) {
                continue;
            }

            let name = match header::HeaderName::from_bytes(key.as_bytes()) {
                Ok(n) => n,
                Err(_) => continue,
            };

            match value {
                serde_json::Value::String(s) => {
                    if let Ok(hv) = HeaderValue::from_str(s) {
                        res.headers_mut().insert(name, hv);
                    }
                }
                serde_json::Value::Array(arr) => {
                    for item in arr {
                        if let Some(s) = item.as_str() {
                            if let Ok(hv) = HeaderValue::from_str(s) {
                                res.headers_mut().append(name.clone(), hv);
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        return Ok(res);
    }

    // Default: JSON response
    Ok(Json(JsonExecutionResponse {
        status_code: response.status_code,
        body: String::from_utf8_lossy(&response.body).into_owned(),
        logs: response.logs,
        errors: response.errors,
        headers: response.headers,
        duration: response.duration,
        start_time: response.start_time,
    })
    .into_response())
}

fn parse_multipart_execution_request_bytes(
    body: &[u8],
    content_type: &str,
) -> Result<ExecutionRequest> {
    let boundary = content_type
        .split("boundary=")
        .nth(1)
        .map(|b| b.trim_matches('"'))
        .ok_or_else(|| {
            ExecutorError::ExecutionBadRequest("Missing multipart boundary".to_string())
        })?;

    let boundary_bytes = format!("--{}", boundary).into_bytes();
    let mut fields: HashMap<String, Vec<u8>> = HashMap::new();

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

            let headers_str = String::from_utf8_lossy(headers);

            let name = headers_str
                .split("name=\"")
                .nth(1)
                .and_then(|s| s.split('"').next())
                .ok_or_else(|| ExecutorError::ExecutionBadRequest("Missing field name".into()))?
                .to_string();

            let next_boundary = memchr::memmem::find(&body[i..], &boundary_bytes)
                .ok_or_else(|| ExecutorError::ExecutionBadRequest("Malformed multipart".into()))?;

            let mut value = body[i..i + next_boundary].to_vec();

            // Trim trailing CRLF
            if value.ends_with(b"\r\n") {
                value.truncate(value.len() - 2);
            }

            fields.insert(name, value);
            i += next_boundary;
        } else {
            i += 1;
        }
    }

    Ok(ExecutionRequest {
        body: fields
            .get("body")
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .unwrap_or_default(),
        path: fields
            .get("path")
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .unwrap_or_else(default_path),
        method: fields
            .get("method")
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .unwrap_or_else(default_method),
        headers: fields
            .get("headers")
            .map(|v| HeadersInput::String(String::from_utf8_lossy(v).into_owned()))
            .unwrap_or_default(),
        timeout: fields
            .get("timeout")
            .and_then(|v| std::str::from_utf8(v).ok()?.parse().ok())
            .unwrap_or_else(default_exec_timeout),
        image: fields
            .get("image")
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .unwrap_or_default(),
        source: fields
            .get("source")
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .unwrap_or_default(),
        entrypoint: fields
            .get("entrypoint")
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .unwrap_or_default(),
        variables: fields
            .get("variables")
            .map(|v| VariablesInput::String(String::from_utf8_lossy(v).into_owned()))
            .unwrap_or_default(),
        cpus: fields
            .get("cpus")
            .and_then(|v| std::str::from_utf8(v).ok()?.parse().ok())
            .unwrap_or_else(default_cpus),
        memory: fields
            .get("memory")
            .and_then(|v| std::str::from_utf8(v).ok()?.parse().ok())
            .unwrap_or_else(default_memory),
        version: fields
            .get("version")
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .unwrap_or_else(default_version),
        runtime_entrypoint: fields
            .get("runtimeEntrypoint")
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .unwrap_or_default(),
        logging: fields
            .get("logging")
            .map(|v| v == b"true" || v == b"1")
            .unwrap_or_else(default_logging),
        restart_policy: fields
            .get("restartPolicy")
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .unwrap_or_else(default_restart_policy),
    })
}

/// Whether an upstream header should be forwarded to the client.
///
/// We deliberately strip headers that can cause browser/client decoding issues when the upstream
/// payload has already been decompressed (e.g. by reqwest) or when Axum will re-derive them.
fn should_forward_header(key: &str) -> bool {
    let k = key.to_ascii_lowercase();

    // Hop-by-hop headers (RFC 7230) + encoding/length/type headers we should not copy verbatim.
    !matches!(
        k.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "content-encoding"
            | "content-length"
            | "content-type"
    )
}

/// Base64 encode a string for header transport
fn base64_encode(s: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
}

/// Wait for a runtime to start listening on a TCP port
/// (matching executor-main Docker.php:1088-1115 TCP validator)
async fn wait_for_port(hostname: &str, port: u16, timeout: Duration) -> Result<()> {
    let addr = format!("{}:{}", hostname, port);
    let start = Instant::now();

    debug!(
        "Waiting for {} to be available (timeout: {:?})",
        addr, timeout
    );

    while start.elapsed() < timeout {
        // Try to connect using tokio's TcpStream which handles DNS resolution
        match tokio::time::timeout(
            Duration::from_secs(1),
            tokio::net::TcpStream::connect(&addr),
        )
        .await
        {
            Ok(Ok(_)) => {
                debug!("Port {} is now available", addr);
                return Ok(());
            }
            _ => {
                // Wait 500ms before retrying (matching executor-main usleep(500000))
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }

    debug!("Timeout waiting for {} after {:?}", addr, timeout);
    Err(ExecutorError::RuntimeTimeout)
}
