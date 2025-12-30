//! Runtime protocol handlers for v2 and v5

use crate::error::{ExecutorError, Result};
use crate::runtime::Runtime;
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use memchr::memchr_iter;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::collections::HashMap;
use std::fmt::Write;
use std::time::Duration;

/// Request to execute a function
#[derive(Debug, Clone)]
pub struct ExecuteRequest {
    pub body: String,
    pub path: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub timeout: u32,
    pub logging: bool,
}

impl Default for ExecuteRequest {
    fn default() -> Self {
        Self {
            body: String::new(),
            path: "/".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            timeout: 15,
            logging: true,
        }
    }
}

/// Response from function execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteResponse {
    #[serde(rename = "statusCode")]
    pub status_code: u16,
    pub body: String,
    pub logs: String,
    pub errors: String,
    pub headers: HashMap<String, serde_json::Value>,
}

/// Trait for runtime protocol implementations
#[async_trait]
pub trait RuntimeProtocol: Send + Sync {
    async fn execute(
        &self,
        runtime: &Runtime,
        request: &ExecuteRequest,
        client: &reqwest::Client,
    ) -> Result<ExecuteResponse>;
}

/// v2 protocol implementation (legacy)
pub struct V2Protocol;

#[async_trait]
impl RuntimeProtocol for V2Protocol {
    async fn execute(
        &self,
        runtime: &Runtime,
        request: &ExecuteRequest,
        client: &reqwest::Client,
    ) -> Result<ExecuteResponse> {
        let url = format!("http://{}:3000/", runtime.hostname);

        // v2 payload format
        let payload = serde_json::json!({
            "variables": {},
            "payload": request.body,
            "headers": request.headers,
        });

        let response = client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("x-internal-challenge", &runtime.key)
            .header("host", "null")
            .timeout(Duration::from_secs((request.timeout + 5) as u64))
            .json(&payload)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    ExecutorError::ExecutionTimeout
                } else {
                    ExecutorError::Network(e.to_string())
                }
            })?;

        let status = response.status().as_u16();

        // v2 response format
        #[derive(Deserialize)]
        struct V2Response {
            response: Option<String>,
            stdout: Option<String>,
            stderr: Option<String>,
        }

        let v2_resp: V2Response = response
            .json()
            .await
            .map_err(|e| ExecutorError::ExecutionBadJson(e.to_string()))?;

        Ok(ExecuteResponse {
            status_code: status,
            body: v2_resp.response.unwrap_or_default(),
            logs: v2_resp.stdout.unwrap_or_default(),
            errors: v2_resp.stderr.unwrap_or_default(),
            headers: HashMap::new(),
        })
    }
}

/// v5 protocol implementation (current)
pub struct V5Protocol;

#[async_trait]
impl RuntimeProtocol for V5Protocol {
    async fn execute(
        &self,
        runtime: &Runtime,
        request: &ExecuteRequest,
        client: &reqwest::Client,
    ) -> Result<ExecuteResponse> {
        let url = format!("http://{}:3000{}", runtime.hostname, request.path);

        // Build Basic auth header
        let auth = format!("opr:{}", runtime.key);
        let auth_encoded = BASE64.encode(auth.as_bytes());
        let auth_header = format!("Basic {}", auth_encoded);

        // Build the request
        let method: reqwest::Method = request.method.parse().unwrap_or(reqwest::Method::GET);

        let mut req_builder = client
            .request(method, &url)
            .header("Authorization", &auth_header)
            .header("x-open-runtimes-secret", &runtime.key)
            .header("x-open-runtimes-timeout", request.timeout.to_string())
            .header(
                "x-open-runtimes-logging",
                if request.logging {
                    "enabled"
                } else {
                    "disabled"
                },
            )
            .timeout(Duration::from_secs((request.timeout + 5) as u64));

        // Add custom headers
        for (key, value) in &request.headers {
            req_builder = req_builder.header(key, value);
        }

        // Add body if not empty
        if !request.body.is_empty() {
            req_builder = req_builder.body(request.body.clone());
        }

        let response = req_builder.send().await.map_err(|e| {
            if e.is_timeout() {
                ExecutorError::ExecutionTimeout
            } else {
                ExecutorError::Network(e.to_string())
            }
        })?;

        let status = response.status().as_u16();

        // Extract log ID and error ID from headers (used to fetch actual log content)
        let log_id = response
            .headers()
            .get("x-open-runtimes-log-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let error_id = response
            .headers()
            .get("x-open-runtimes-error-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // Extract response headers (excluding internal headers)
        // Use SmallVec to avoid heap allocation for typical responses (<8 headers)
        type HeaderVec = SmallVec<[(String, serde_json::Value); 8]>;
        let mut response_headers_vec: HeaderVec = SmallVec::new();

        for (key, value) in response.headers() {
            let key_str = key.as_str().to_lowercase();
            // Skip internal headers
            if key_str.starts_with("x-open-runtimes-") {
                continue;
            }
            if let Ok(v) = value.to_str() {
                // Check if key already exists (handle multiple values)
                let existing = response_headers_vec.iter_mut().find(|(k, _)| k == &key_str);
                if let Some((_, existing_val)) = existing {
                    // Handle multiple values for same header
                    if let serde_json::Value::Array(arr) = existing_val {
                        arr.push(serde_json::Value::String(v.to_string()));
                    } else if let serde_json::Value::String(s) = existing_val {
                        *existing_val = serde_json::Value::Array(vec![
                            serde_json::Value::String(s.clone()),
                            serde_json::Value::String(v.to_string()),
                        ]);
                    }
                } else {
                    response_headers_vec.push((key_str, serde_json::Value::String(v.to_string())));
                }
            }
        }

        // Convert SmallVec to HashMap at the end
        let response_headers: HashMap<String, serde_json::Value> =
            response_headers_vec.into_iter().collect();

        let body = response
            .text()
            .await
            .map_err(|e| ExecutorError::Network(e.to_string()))?;

        // Parse logs and errors
        // v5 logs are written to /mnt/logs/{log_id}/logs and /mnt/logs/{log_id}/errors
        // If log_id is provided, we'd need to read from the container's filesystem
        // For now, decode any URL-encoded log content from the IDs
        let logs = log_id
            .map(|id| {
                // Log ID might be URL-encoded log content directly in some cases
                urlencoding::decode(&id)
                    .map(|s| parse_v5_log_format(&s))
                    .unwrap_or_else(|_| id.clone())
            })
            .unwrap_or_default();

        let errors = error_id
            .map(|id| {
                urlencoding::decode(&id)
                    .map(|s| parse_v5_log_format(&s))
                    .unwrap_or_else(|_| id.clone())
            })
            .unwrap_or_default();

        Ok(ExecuteResponse {
            status_code: status,
            body,
            logs,
            errors,
            headers: response_headers,
        })
    }
}

/// Parse v5 log format - optimized with memchr and capacity pre-allocation
/// v5 logs are JSON lines with format: {"type":"log|error","message":"...","timestamp":"..."}
fn parse_v5_log_format(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }

    // Count lines for capacity estimation using memchr (faster than raw iteration)
    let line_count = memchr_iter(b'\n', raw.as_bytes()).count() + 1;
    let mut output: Vec<String> = Vec::with_capacity(line_count);

    // Pre-allocate a reusable buffer for formatted output
    let mut fmt_buf = String::with_capacity(128);

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Fast path: check if line starts with '{' before attempting JSON parse
        // This avoids expensive JSON parsing for non-JSON lines
        if trimmed.starts_with('{') {
            if let Ok(entry) = serde_json::from_str::<serde_json::Value>(trimmed) {
                let message = entry
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or(trimmed);

                let log_type = entry.get("type").and_then(|v| v.as_str()).unwrap_or("log");

                let timestamp = entry
                    .get("timestamp")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                // Reuse buffer to avoid repeated allocations
                fmt_buf.clear();
                if !timestamp.is_empty() {
                    let _ = write!(fmt_buf, "[{}] [{}] {}", timestamp, log_type, message);
                } else {
                    let _ = write!(fmt_buf, "[{}] {}", log_type, message);
                }
                output.push(fmt_buf.clone());
            } else {
                // JSON parse failed, use raw line
                output.push(trimmed.to_string());
            }
        } else {
            // Not JSON, just use the raw line
            output.push(trimmed.to_string());
        }
    }

    output.join("\n")
}

/// Get the appropriate protocol handler for a version
pub fn get_protocol(version: &str) -> Box<dyn RuntimeProtocol> {
    match version {
        "v2" => Box::new(V2Protocol),
        _ => Box::new(V5Protocol),
    }
}
