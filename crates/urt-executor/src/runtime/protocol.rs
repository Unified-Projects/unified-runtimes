//! Runtime protocol handlers for v2 and v5
//!
//! v5 protocol reads logs from files on disk (shared /tmp volume), matching executor-main.

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
use tracing::debug;

/// Maximum log file size (5MB, matching executor-main)
const MAX_LOG_SIZE: usize = 5 * 1024 * 1024;

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

    #[serde(skip)]
    pub body: Vec<u8>,

    pub logs: String,
    pub errors: String,
    pub headers: HashMap<String, serde_json::Value>,

    /// Execution duration in seconds
    pub duration: f64,

    /// Start time as Unix timestamp
    pub start_time: f64,
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
        use std::time::{SystemTime, UNIX_EPOCH};

        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        let start_instant = std::time::Instant::now();

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

        let duration = start_instant.elapsed().as_secs_f64();

        Ok(ExecuteResponse {
            status_code: status,
            body: v2_resp.response.unwrap_or_default().into_bytes(),
            logs: v2_resp.stdout.unwrap_or_default(),
            errors: v2_resp.stderr.unwrap_or_default(),
            headers: HashMap::new(),
            duration,
            start_time,
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
        use std::time::{SystemTime, UNIX_EPOCH};

        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        let start_instant = std::time::Instant::now();

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

        // Extract log ID from header - this is a FILE ID used to read logs from disk
        // (matching executor-main Docker.php:1027)
        let log_id = response
            .headers()
            .get("x-open-runtimes-log-id")
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
            .bytes()
            .await
            .map_err(|e| ExecutorError::Network(e.to_string()))?
            .to_vec();

        // Read logs and errors from FILES on disk (matching executor-main Docker.php:1027-1063)
        // The header x-open-runtimes-log-id contains a FILE ID, not the actual logs.
        // Logs are stored at /tmp/{hostname}/logs/{file_id}_logs.log
        // Errors are stored at /tmp/{hostname}/logs/{file_id}_errors.log
        let (logs, errors) = if let Some(ref file_id) = log_id {
            // URL decode the file ID
            let decoded_id = urlencoding::decode(file_id)
                .map(|s| s.to_string())
                .unwrap_or_else(|_| file_id.clone());

            read_log_files(&runtime.hostname, &decoded_id).await
        } else {
            (String::new(), String::new())
        };

        let duration = start_instant.elapsed().as_secs_f64();

        Ok(ExecuteResponse {
            status_code: status,
            body,
            logs,
            errors,
            headers: response_headers,
            duration,
            start_time,
        })
    }
}

/// Read log files from disk and clean up (matching executor-main behavior)
/// Log files are stored at /tmp/{runtime_name}/logs/{file_id}_logs.log
async fn read_log_files(runtime_name: &str, file_id: &str) -> (String, String) {
    let log_path = format!("/tmp/{}/logs/{}_logs.log", runtime_name, file_id);
    let error_path = format!("/tmp/{}/logs/{}_errors.log", runtime_name, file_id);

    debug!("Reading log files: {} and {}", log_path, error_path);

    let logs = read_and_cleanup_log(&log_path).await;
    let errors = read_and_cleanup_log(&error_path).await;

    (logs, errors)
}

/// Read a log file, truncate if too large, and delete after reading
async fn read_and_cleanup_log(path: &str) -> String {
    use tokio::fs;

    match fs::read_to_string(path).await {
        Ok(content) => {
            // Truncate if too large (matching executor-main MAX_LOG_SIZE)
            let result = if content.len() > MAX_LOG_SIZE {
                let truncated = &content[..MAX_LOG_SIZE];
                format!(
                    "{}\n[Log file has been truncated. Max size: {:.2}MB]",
                    truncated,
                    MAX_LOG_SIZE as f64 / 1_048_576.0
                )
            } else {
                content
            };

            // Delete the file after reading (matching executor-main cleanup)
            if let Err(e) = fs::remove_file(path).await {
                debug!("Failed to cleanup log file {}: {}", path, e);
            }

            result
        }
        Err(e) => {
            debug!("Failed to read log file {}: {}", path, e);
            String::new()
        }
    }
}

/// Parse v5 log format - optimized with memchr and capacity pre-allocation
/// v5 logs are JSON lines with format: {"type":"log|error","message":"...","timestamp":"..."}
#[allow(dead_code)]
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
