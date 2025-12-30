//! Execution endpoint

use super::runtimes::{
    default_cpus, default_memory, default_restart_policy, default_timeout, default_version,
    CreateRuntimeRequest,
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

/// JSON response format
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonExecutionResponse {
    pub status_code: u16,
    pub body: String,
    pub logs: String,
    pub errors: String,
    pub headers: HashMap<String, serde_json::Value>,
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

    // Add parts using zero-copy writes
    write_part!(b"body", b"text/plain", response.body.as_bytes());
    write_part!(b"logs", b"text/plain", response.logs.as_bytes());
    write_part!(b"errors", b"text/plain", response.errors.as_bytes());

    // Status code - use itoa for fast integer formatting
    let mut status_buf = itoa::Buffer::new();
    let status_str = status_buf.format(response.status_code);
    write_part!(b"statusCode", b"text/plain", status_str.as_bytes());

    // Headers as JSON - serialize directly to Vec to avoid intermediate String
    let headers_json = serde_json::to_vec(&response.headers).unwrap_or_default();
    write_part!(b"headers", b"application/json", &headers_json);

    // Add closing boundary
    buf.extend_from_slice(b"--");
    buf.extend_from_slice(boundary.as_bytes());
    buf.extend_from_slice(b"--");

    Response::builder()
        .status(200)
        .header(
            header::CONTENT_TYPE,
            HeaderValue::from_str(&format!("multipart/form-data; boundary={}", boundary)).unwrap(),
        )
        .header(
            "x-open-runtimes-status-code",
            HeaderValue::from_str(status_str).unwrap(),
        )
        .body(Body::from(buf.freeze()))
        .unwrap()
}

/// POST /v1/runtimes/:runtime_id/executions - Execute a function
pub async fn create_execution(
    State(state): State<AppState>,
    Path(runtime_id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<ExecutionRequest>,
) -> Result<Response> {
    debug!("Executing function in runtime: {}", runtime_id);

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

            // Create runtime request
            let create_req = CreateRuntimeRequest {
                runtime_id: runtime_id.clone(),
                image: req.image.clone(),
                entrypoint: req.entrypoint.clone(),
                source: req.source.clone(),
                destination: String::new(),
                output_directory: String::new(),
                variables: req.variables.clone(),
                runtime_entrypoint: req.runtime_entrypoint.clone(),
                command: String::new(),
                timeout: default_timeout(),
                remove: false,
                cpus: req.cpus,
                memory: req.memory,
                version: req.version.clone(),
                restart_policy: req.restart_policy.clone(),
                docker_cmd: Vec::new(),
            };

            // Call create_runtime internally
            let _ = super::runtimes::create_runtime(State(state.clone()), Json(create_req)).await?;

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

    // Build execution request
    let exec_req = ExecuteRequest {
        body: req.body,
        path: req.path,
        method: req.method.to_uppercase(),
        headers: req.headers.to_map(),
        timeout: req.timeout,
        logging: req.logging,
    };

    debug!("Executing with protocol {}", runtime.version);

    // Get protocol handler
    let protocol = get_protocol(&runtime.version);

    // Execute
    let response = protocol
        .execute(&runtime, &exec_req, &state.http_client)
        .await?;

    // Determine response format based on Accept header
    let accept = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json");

    if accept.contains("multipart/form-data") {
        // Return multipart response
        Ok(build_multipart_response(&response))
    } else if accept.contains("text/plain") {
        // Return plain text (just body)
        let mut res = Response::builder()
            .status(200)
            .header(header::CONTENT_TYPE, "text/plain")
            .header(
                "x-open-runtimes-status-code",
                response.status_code.to_string(),
            )
            .header("x-open-runtimes-logs", base64_encode(&response.logs))
            .header("x-open-runtimes-errors", base64_encode(&response.errors))
            .body(Body::from(response.body))
            .unwrap();

        // Add response headers
        for (key, value) in &response.headers {
            if let Some(s) = value.as_str() {
                if let Ok(hv) = HeaderValue::from_str(s) {
                    res.headers_mut().insert(
                        header::HeaderName::from_bytes(key.as_bytes())
                            .unwrap_or(header::HeaderName::from_static("x-custom")),
                        hv,
                    );
                }
            }
        }

        Ok(res)
    } else {
        // Default: JSON response
        Ok(Json(JsonExecutionResponse {
            status_code: response.status_code,
            body: response.body,
            logs: response.logs,
            errors: response.errors,
            headers: response.headers,
        })
        .into_response())
    }
}

/// Base64 encode a string for header transport
fn base64_encode(s: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
}
