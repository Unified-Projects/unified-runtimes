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
use std::path::Path;
use std::time::Duration;
use tracing::debug;

/// Maximum log file size (5MB, matching executor-main)
const MAX_LOG_SIZE: usize = 5 * 1024 * 1024;
const MAX_BUILD_LOG_SIZE: usize = 1_000_000;
const LOG_FILE_WAIT_TIMEOUT: Duration = Duration::from_millis(500);
const LOG_FILE_WAIT_INTERVAL: Duration = Duration::from_millis(25);

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
static V2_PROTOCOL: V2Protocol = V2Protocol;

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

        let url = format!("http://{}:3000/", runtime_network_host(runtime));

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
            logs: truncate_build_logs(v2_resp.stdout.unwrap_or_default()),
            errors: truncate_build_logs(v2_resp.stderr.unwrap_or_default()),
            headers: HashMap::new(),
            duration,
            start_time,
        })
    }
}

/// v5 protocol implementation (current)
pub struct V5Protocol;
static V5_PROTOCOL: V5Protocol = V5Protocol;

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

        let url = if request.path.starts_with('/') {
            format!(
                "http://{}:3000{}",
                runtime_network_host(runtime),
                request.path
            )
        } else {
            format!(
                "http://{}:3000/{}",
                runtime_network_host(runtime),
                request.path
            )
        };

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
            let key_str = key.as_str().to_ascii_lowercase();
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
        // Logs are stored at /tmp/{runtime.name}/logs/{file_id}_logs.log
        // Errors are stored at /tmp/{runtime.name}/logs/{file_id}_errors.log
        let (logs, errors) = if let Some(ref file_id) = log_id {
            // URL decode the file ID
            let decoded_id = urlencoding::decode(file_id)
                .map(|s| s.to_string())
                .unwrap_or_else(|_| file_id.clone());

            // Use runtime.name (container name) - logs are stored at /tmp/{runtime.name}/logs/
            read_log_files(&runtime.name, &decoded_id).await
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

pub fn runtime_network_host(runtime: &Runtime) -> &str {
    if runtime.hostname.trim().is_empty() {
        &runtime.name
    } else {
        &runtime.hostname
    }
}

/// Read log files from disk and clean up (matching executor-main behavior)
/// Log files are stored at /tmp/{runtime_name}/logs/{file_id}_logs.log
async fn read_log_files(runtime_name: &str, file_id: &str) -> (String, String) {
    let base = std::env::temp_dir();
    let log_path = base
        .join(runtime_name)
        .join("logs")
        .join(format!("{}_logs.log", file_id));
    let error_path = base
        .join(runtime_name)
        .join("logs")
        .join(format!("{}_errors.log", file_id));

    debug!(
        "Reading log files: {} and {}",
        log_path.display(),
        error_path.display()
    );

    wait_for_log_file(&log_path).await;
    wait_for_log_file(&error_path).await;

    let logs = read_and_cleanup_log(&log_path, "Log").await;
    let errors = read_and_cleanup_log(&error_path, "Error").await;

    (logs, errors)
}

async fn wait_for_log_file(path: &Path) {
    let deadline = tokio::time::Instant::now() + LOG_FILE_WAIT_TIMEOUT;

    loop {
        if tokio::fs::try_exists(path).await.unwrap_or(false)
            || tokio::time::Instant::now() >= deadline
        {
            break;
        }

        tokio::time::sleep(LOG_FILE_WAIT_INTERVAL).await;
    }
}

/// Read a log file, truncate if too large, and delete after reading
async fn read_and_cleanup_log(path: &Path, label: &str) -> String {
    use tokio::fs;

    match fs::read(path).await {
        Ok(content) => {
            // Truncate if too large (matching executor-main MAX_LOG_SIZE)
            let result = if content.len() > MAX_LOG_SIZE {
                let truncated = String::from_utf8_lossy(&content[..MAX_LOG_SIZE]);
                format!(
                    "{}\n{} file has been truncated to {:.2}MB.",
                    truncated,
                    label,
                    MAX_LOG_SIZE as f64 / 1_048_576.0
                )
            } else {
                String::from_utf8_lossy(&content).into_owned()
            };

            // Delete the file after reading (matching executor-main cleanup)
            if let Err(e) = fs::remove_file(path).await {
                debug!("Failed to cleanup log file {}: {}", path.display(), e);
            }

            result
        }
        Err(e) => {
            debug!("Failed to read log file {}: {}", path.display(), e);
            String::new()
        }
    }
}

fn truncate_build_logs(content: String) -> String {
    if content.len() <= MAX_BUILD_LOG_SIZE {
        return content;
    }

    let mut cutoff = MAX_BUILD_LOG_SIZE;
    while cutoff > 0 && !content.is_char_boundary(cutoff) {
        cutoff -= 1;
    }
    content[..cutoff].to_string()
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
pub fn get_protocol(version: &str) -> &'static dyn RuntimeProtocol {
    match version {
        "v2" => &V2_PROTOCOL,
        _ => &V5_PROTOCOL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Build the runtime URL for HTTP requests
    #[inline]
    fn build_runtime_url(host: &str, port: u16, path: &str) -> String {
        format!("http://{}:{}{}", host, port, path)
    }

    /// Build the log file path for a runtime
    /// IMPORTANT: Uses runtime.name (container name) to match the volume mount at temp_dir/{name}/
    #[inline]
    fn build_log_path(runtime_name: &str, file_id: &str, log_type: &str) -> String {
        std::env::temp_dir()
            .join(runtime_name)
            .join("logs")
            .join(format!("{}_{}.log", file_id, log_type))
            .to_string_lossy()
            .to_string()
    }

    #[test]
    fn test_runtime_network_host_prefers_hostname() {
        let runtime = Runtime {
            version: "v5".to_string(),
            created: 0.0,
            updated: 0.0,
            name: "exc1-myruntime123".to_string(),
            hostname: "1ca14d56857971dfad412b32f66e6466".to_string(),
            status: "running".to_string(),
            key: "secret".to_string(),
            listening: 1,
            image: "openruntimes/node:v5-22".to_string(),
            initialised: 1,
            keep_alive_id: None,
        };

        assert_eq!(
            runtime_network_host(&runtime),
            "1ca14d56857971dfad412b32f66e6466"
        );
        let url = build_runtime_url(runtime_network_host(&runtime), 3000, "/");
        assert_eq!(url, "http://1ca14d56857971dfad412b32f66e6466:3000/");
    }

    #[test]
    fn test_runtime_network_host_falls_back_to_container_name() {
        let runtime = Runtime {
            version: "v5".to_string(),
            created: 0.0,
            updated: 0.0,
            name: "exc1-myruntime123".to_string(),
            hostname: String::new(),
            status: "running".to_string(),
            key: "secret".to_string(),
            listening: 1,
            image: "openruntimes/node:v5-22".to_string(),
            initialised: 1,
            keep_alive_id: None,
        };

        assert_eq!(runtime_network_host(&runtime), "exc1-myruntime123");
    }

    #[test]
    fn test_build_log_path_uses_container_name() {
        // Log files are stored at {temp_dir}/{runtime.name}/logs/
        // The mount is: host {temp_dir}/{full_name} -> container /tmp
        // So we need to use runtime.name to find logs on the executor's filesystem
        let container_name = "exc1-myruntime123";
        let file_id = "abc123";

        let expected_log = std::env::temp_dir()
            .join("exc1-myruntime123")
            .join("logs")
            .join("abc123_logs.log");
        let expected_error = std::env::temp_dir()
            .join("exc1-myruntime123")
            .join("logs")
            .join("abc123_errors.log");

        let log_path = build_log_path(container_name, file_id, "logs");
        assert_eq!(log_path, expected_log.to_string_lossy());

        let error_path = build_log_path(container_name, file_id, "errors");
        assert_eq!(error_path, expected_error.to_string_lossy());
    }

    #[tokio::test]
    async fn read_log_files_waits_for_async_flush() {
        let runtime_name = format!("urt-log-wait-{}", uuid::Uuid::new_v4());
        let file_id = "late";
        let base = std::env::temp_dir().join(&runtime_name).join("logs");
        tokio::fs::create_dir_all(&base).await.unwrap();

        let log_path = base.join(format!("{}_logs.log", file_id));
        let error_path = base.join(format!("{}_errors.log", file_id));

        let writer_log_path = log_path.clone();
        let writer_error_path = error_path.clone();
        let writer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(60)).await;
            tokio::fs::write(&writer_log_path, b"stdout line")
                .await
                .unwrap();
            tokio::fs::write(&writer_error_path, b"stderr line")
                .await
                .unwrap();
        });

        let (logs, errors) = read_log_files(&runtime_name, file_id).await;
        writer.await.unwrap();

        assert_eq!(logs, "stdout line");
        assert_eq!(errors, "stderr line");
        assert!(!tokio::fs::try_exists(&log_path).await.unwrap());
        assert!(!tokio::fs::try_exists(&error_path).await.unwrap());

        tokio::fs::remove_dir_all(base.parent().unwrap()).await.ok();
    }

    #[test]
    fn truncate_build_logs_matches_executor_limit() {
        let content = "a".repeat(MAX_BUILD_LOG_SIZE + 50);
        let truncated = truncate_build_logs(content);
        assert_eq!(truncated.len(), MAX_BUILD_LOG_SIZE);
    }
}
