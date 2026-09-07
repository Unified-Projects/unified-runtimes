//! Load testing primitives for the executor benchmark suite.
//!
//! - Open-loop benchmarking (no artificial throttling)
//! - Concurrent warmup for proper connection pooling
//! - Latency measured per request, including body read
//! - Pooled results with percentile calculation
//! - Container resource sampling via the Docker CLI

use std::collections::HashMap;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::{Client, RequestBuilder};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

/// Benchmark configuration for one executor target
#[derive(Debug, Clone)]
pub struct BenchmarkConfig {
    /// Base URL of the executor
    pub base_url: String,
    /// Authentication secret
    pub secret: String,
    /// Number of concurrent workers
    pub concurrency: usize,
    /// Duration of the benchmark
    pub duration: Duration,
    /// Request timeout
    pub timeout: Duration,
    /// Warmup duration before measuring
    pub warmup: Duration,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            base_url: "http://localhost:9900".to_string(),
            secret: "benchmark-secret".to_string(),
            concurrency: 50,
            duration: Duration::from_secs(30),
            timeout: Duration::from_secs(10),
            warmup: Duration::from_secs(5),
        }
    }
}

/// Single request result
#[derive(Debug, Clone)]
struct RequestResult {
    latency_ns: u64,
    status: u16,
}

/// Results from a benchmark run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResults {
    /// Name of the benchmark
    pub name: String,
    /// Total requests made
    pub total_requests: u64,
    /// Successful requests
    pub successful_requests: u64,
    /// Failed requests
    pub failed_requests: u64,
    /// Requests per second
    pub rps: f64,
    /// Duration of the benchmark
    pub duration_secs: f64,
    /// Latency statistics in milliseconds
    pub latency: LatencyStats,
    /// Status code distribution
    pub status_codes: HashMap<u16, u64>,
    /// Error messages
    pub errors: Vec<String>,
}

impl BenchmarkResults {
    pub fn success_pct(&self) -> f64 {
        if self.total_requests == 0 {
            0.0
        } else {
            self.successful_requests as f64 / self.total_requests as f64 * 100.0
        }
    }
}

/// Latency statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyStats {
    pub min_ms: f64,
    pub max_ms: f64,
    pub mean_ms: f64,
    pub p50_ms: f64,
    pub p90_ms: f64,
    pub p99_ms: f64,
    pub p999_ms: f64,
}

/// Function source handed to both executors when creating a runtime
#[derive(Debug, Clone)]
pub struct FunctionSpec {
    pub image: String,
    /// Path to the code archive as seen by the executor's storage device
    pub source: Option<String>,
    pub entrypoint: String,
    pub runtime_entrypoint: String,
    pub variables: serde_json::Map<String, serde_json::Value>,
}

/// Outcome of one request, as judged by the benchmark
pub struct Outcome {
    /// Effective status code (HTTP status, or the function status for executions)
    pub status: u16,
    pub success: bool,
}

/// High-performance load tester using open-loop benchmarking
pub struct LoadTester {
    config: BenchmarkConfig,
    client: Client,
}

pub fn apply_auth_headers(builder: RequestBuilder, secret: &str) -> RequestBuilder {
    builder
        .header("Authorization", format!("Bearer {}", secret))
        .header("x-open-runtimes-secret", secret)
}

/// Build the execution request body
fn execution_payload(path: &str) -> serde_json::Value {
    serde_json::json!({
        "body": "{}",
        "path": path,
        "method": "GET",
        "headers": {}
    })
}

/// Read an execution response and judge it by the function's own status code,
/// so a runtime that answers 503 to every call is not counted as a success just
/// because the executor wrapped it in an HTTP 200.
async fn judge_execution(resp: reqwest::Response) -> Result<Outcome, reqwest::Error> {
    let http_status = resp.status().as_u16();
    let body = resp.bytes().await?;
    if !(200..300).contains(&http_status) {
        return Ok(Outcome {
            status: http_status,
            success: false,
        });
    }
    let function_status = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v.get("statusCode").and_then(|s| s.as_u64()))
        .map(|s| s as u16)
        .unwrap_or(http_status);
    Ok(Outcome {
        status: function_status,
        success: (200..300).contains(&function_status),
    })
}

impl LoadTester {
    pub fn new(config: BenchmarkConfig) -> Self {
        let client = Client::builder()
            .timeout(config.timeout)
            .pool_max_idle_per_host(config.concurrency * 2)
            .pool_idle_timeout(Duration::from_secs(30))
            .tcp_keepalive(Duration::from_secs(60))
            .build()
            .expect("Failed to create HTTP client");

        Self { config, client }
    }

    pub fn with_concurrency(&self, concurrency: usize) -> Self {
        Self::new(BenchmarkConfig {
            concurrency,
            ..self.config.clone()
        })
    }

    pub fn with_timing(&self, duration: Duration, warmup: Duration) -> Self {
        Self::new(BenchmarkConfig {
            duration,
            warmup,
            ..self.config.clone()
        })
    }

    /// Run a benchmark against the health endpoint
    pub async fn benchmark_health(&self) -> BenchmarkResults {
        let url = format!("{}/v1/health", self.config.base_url);
        let secret = self.config.secret.clone();
        self.run_benchmark("health_endpoint", move |client| {
            let url = url.clone();
            let secret = secret.clone();
            async move {
                let resp = apply_auth_headers(client.get(&url), &secret).send().await?;
                let status = resp.status();
                Ok(Outcome {
                    status: status.as_u16(),
                    success: status.is_success(),
                })
            }
        })
        .await
    }

    /// Run a benchmark against the ping endpoint (minimal, no auth)
    pub async fn benchmark_ping(&self) -> BenchmarkResults {
        let url = format!("{}/v1/ping", self.config.base_url);
        self.run_benchmark("ping_endpoint", move |client| {
            let url = url.clone();
            async move {
                let resp = client.get(&url).send().await?;
                let status = resp.status();
                Ok(Outcome {
                    status: status.as_u16(),
                    success: status.is_success(),
                })
            }
        })
        .await
    }

    /// Run a benchmark against the runtimes list endpoint
    pub async fn benchmark_list_runtimes(&self) -> BenchmarkResults {
        let url = format!("{}/v1/runtimes", self.config.base_url);
        let secret = self.config.secret.clone();
        self.run_benchmark("list_runtimes", move |client| {
            let url = url.clone();
            let secret = secret.clone();
            async move {
                let resp = apply_auth_headers(client.get(&url), &secret).send().await?;
                let status = resp.status();
                Ok(Outcome {
                    status: status.as_u16(),
                    success: status.is_success(),
                })
            }
        })
        .await
    }

    /// Run a benchmark against the execution endpoint
    pub async fn benchmark_execution(&self, runtime_id: &str) -> BenchmarkResults {
        self.benchmark_execution_with_path(runtime_id, "/").await
    }

    /// Run a benchmark against the execution endpoint with a specific path
    pub async fn benchmark_execution_with_path(
        &self,
        runtime_id: &str,
        path: &str,
    ) -> BenchmarkResults {
        let url = format!(
            "{}/v1/runtimes/{}/executions",
            self.config.base_url, runtime_id
        );
        let secret = self.config.secret.clone();
        let payload = execution_payload(path);

        let bench_name = if path == "/" {
            "function_execution".to_string()
        } else {
            format!(
                "execution_{}",
                path.trim_start_matches('/').replace('/', "_")
            )
        };

        self.run_benchmark(&bench_name, move |client| {
            let url = url.clone();
            let secret = secret.clone();
            let payload = payload.clone();
            async move {
                let resp = apply_auth_headers(client.post(&url), &secret)
                    .header("Content-Type", "application/json")
                    .json(&payload)
                    .send()
                    .await?;
                judge_execution(resp).await
            }
        })
        .await
    }

    /// Open-loop benchmark runner - no artificial throttling
    async fn run_benchmark<F, Fut>(&self, name: &str, request_fn: F) -> BenchmarkResults
    where
        F: Fn(Client) -> Fut + Send + Sync + Clone + 'static,
        Fut: std::future::Future<Output = Result<Outcome, reqwest::Error>> + Send,
    {
        // Phase 1: Concurrent warmup
        let warmup_handles: Vec<_> = (0..self.config.concurrency)
            .map(|_| {
                let client = self.client.clone();
                let request_fn = request_fn.clone();
                let warmup_duration = self.config.warmup;
                tokio::spawn(async move {
                    let start = Instant::now();
                    while start.elapsed() < warmup_duration {
                        let _ = request_fn(client.clone()).await;
                    }
                })
            })
            .collect();
        futures::future::join_all(warmup_handles).await;

        // Phase 2: Main benchmark - fire as fast as possible
        let total_requests = Arc::new(AtomicU64::new(0));
        let successful_requests = Arc::new(AtomicU64::new(0));
        let failed_requests = Arc::new(AtomicU64::new(0));
        let results = Arc::new(Mutex::new(Vec::with_capacity(100_000)));
        let errors = Arc::new(Mutex::new(Vec::new()));

        let benchmark_start = Instant::now();

        let handles: Vec<_> = (0..self.config.concurrency)
            .map(|_| {
                let client = self.client.clone();
                let request_fn = request_fn.clone();
                let duration = self.config.duration;
                let total_requests = total_requests.clone();
                let successful_requests = successful_requests.clone();
                let failed_requests = failed_requests.clone();
                let results = results.clone();
                let errors = errors.clone();

                tokio::spawn(async move {
                    let worker_start = Instant::now();
                    let mut local_results = Vec::with_capacity(10_000);

                    while worker_start.elapsed() < duration {
                        let req_start = Instant::now();
                        let response = request_fn(client.clone()).await;
                        let latency_ns = req_start.elapsed().as_nanos() as u64;

                        total_requests.fetch_add(1, Ordering::Relaxed);

                        match response {
                            Ok(outcome) => {
                                if outcome.success {
                                    successful_requests.fetch_add(1, Ordering::Relaxed);
                                } else {
                                    failed_requests.fetch_add(1, Ordering::Relaxed);
                                }
                                local_results.push(RequestResult {
                                    latency_ns,
                                    status: outcome.status,
                                });
                            }
                            Err(e) => {
                                failed_requests.fetch_add(1, Ordering::Relaxed);
                                let mut errs = errors.lock().await;
                                if errs.len() < 10 {
                                    errs.push(e.to_string());
                                }
                            }
                        }
                    }

                    let mut global_results = results.lock().await;
                    global_results.extend(local_results);
                })
            })
            .collect();

        futures::future::join_all(handles).await;

        let actual_duration = benchmark_start.elapsed();

        // Phase 3: Calculate stats from pooled results
        let total = total_requests.load(Ordering::Relaxed);
        let successful = successful_requests.load(Ordering::Relaxed);
        let failed = failed_requests.load(Ordering::Relaxed);
        let rps = total as f64 / actual_duration.as_secs_f64();

        let results_guard = results.lock().await;
        let mut latencies: Vec<f64> = results_guard
            .iter()
            .map(|r| r.latency_ns as f64 / 1_000_000.0)
            .collect();
        latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let latency = if latencies.is_empty() {
            LatencyStats {
                min_ms: 0.0,
                max_ms: 0.0,
                mean_ms: 0.0,
                p50_ms: 0.0,
                p90_ms: 0.0,
                p99_ms: 0.0,
                p999_ms: 0.0,
            }
        } else {
            let len = latencies.len();
            LatencyStats {
                min_ms: latencies[0],
                max_ms: latencies[len - 1],
                mean_ms: latencies.iter().sum::<f64>() / len as f64,
                p50_ms: latencies[len * 50 / 100],
                p90_ms: latencies[len * 90 / 100],
                p99_ms: latencies[len * 99 / 100],
                p999_ms: latencies[len.saturating_sub(1).min(len * 999 / 1000)],
            }
        };

        let mut status_codes_map = HashMap::new();
        for result in results_guard.iter() {
            *status_codes_map.entry(result.status).or_insert(0) += 1;
        }

        let errors_vec = errors.lock().await.clone();

        BenchmarkResults {
            name: name.to_string(),
            total_requests: total,
            successful_requests: successful,
            failed_requests: failed,
            rps,
            duration_secs: actual_duration.as_secs_f64(),
            latency,
            status_codes: status_codes_map,
            errors: errors_vec,
        }
    }
}

/// Create a runtime for benchmarking. Returns the time the create call took.
pub async fn create_benchmark_runtime(
    base_url: &str,
    secret: &str,
    runtime_id: &str,
    function: &FunctionSpec,
) -> Result<Duration, Box<dyn std::error::Error>> {
    let client = Client::new();
    let url = format!("{}/v1/runtimes", base_url);

    let mut payload = serde_json::json!({
        "runtimeId": runtime_id,
        "image": function.image,
        "entrypoint": function.entrypoint,
        "version": "v5",
        "variables": function.variables,
        "runtimeEntrypoint": function.runtime_entrypoint
    });
    if let Some(ref source) = function.source {
        payload["source"] = serde_json::Value::String(source.clone());
    }

    let start = Instant::now();
    let response = apply_auth_headers(client.post(&url), secret)
        .header("Content-Type", "application/json")
        .json(&payload)
        .timeout(Duration::from_secs(120))
        .send()
        .await?;
    let elapsed = start.elapsed();

    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .bytes()
            .await
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default();

        return Err(format!("Failed to create runtime: {} - {}", status, body).into());
    }

    Ok(elapsed)
}

/// Poll executions until the function answers with a 2xx status. Returns the
/// time from the first attempt to the first successful response.
pub async fn wait_for_first_execution(
    base_url: &str,
    secret: &str,
    runtime_id: &str,
    max_wait: Duration,
) -> Result<Duration, Box<dyn std::error::Error>> {
    let client = Client::builder().timeout(Duration::from_secs(30)).build()?;
    let url = format!("{}/v1/runtimes/{}/executions", base_url, runtime_id);
    let payload = execution_payload("/");

    let start = Instant::now();
    let mut last_status: Option<u16> = None;
    let mut last_body = String::new();
    while start.elapsed() < max_wait {
        let resp = apply_auth_headers(client.post(&url), secret)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await;
        match resp {
            Ok(resp) => {
                let http_status = resp.status().as_u16();
                let body = resp.bytes().await.unwrap_or_default();
                let function_status = serde_json::from_slice::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|v| v.get("statusCode").and_then(|s| s.as_u64()))
                    .map(|s| s as u16);
                let effective = if (200..300).contains(&http_status) {
                    function_status.unwrap_or(http_status)
                } else {
                    http_status
                };
                if (200..300).contains(&effective) {
                    return Ok(start.elapsed());
                }
                last_status = Some(effective);
                last_body = String::from_utf8_lossy(&body).chars().take(300).collect();
            }
            Err(e) => {
                last_body = e.to_string();
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    Err(format!(
        "runtime {} never answered a successful execution within {:?} (last status {:?}: {})",
        runtime_id, max_wait, last_status, last_body
    )
    .into())
}

/// Delete a benchmark runtime
pub async fn delete_benchmark_runtime(
    base_url: &str,
    secret: &str,
    runtime_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    let url = format!("{}/v1/runtimes/{}", base_url, runtime_id);

    apply_auth_headers(client.delete(&url), secret)
        .timeout(Duration::from_secs(60))
        .send()
        .await?;

    Ok(())
}

/// Package a function source directory into a gzipped tarball at a path the
/// executors can read. The archive is produced inside a throwaway container so
/// the output lands on the Docker host's filesystem, which both executors mount
/// at /tmp, regardless of where this binary runs.
///
/// The archive mirrors a build artefact: the runtime start lifecycle sources a
/// `.open-runtimes` env file from the extracted tree, so an empty one is added.
pub fn package_function_source(
    source_dir: &str,
    archive_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let archive_dir = std::path::Path::new(archive_path)
        .parent()
        .ok_or("archive path has no parent directory")?
        .to_string_lossy()
        .into_owned();
    let archive_name = std::path::Path::new(archive_path)
        .file_name()
        .ok_or("archive path has no file name")?
        .to_string_lossy()
        .into_owned();

    let output = Command::new("docker")
        .args([
            "run",
            "--rm",
            "-v",
            &format!("{}:/src:ro", source_dir),
            "-v",
            &format!("{}:/out", archive_dir),
            "alpine:latest",
            "sh",
            "-c",
            &format!(
                "cp -r /src /work && touch /work/.open-runtimes && tar czf /out/{} -C /work . && chmod 644 /out/{}",
                archive_name, archive_name
            ),
        ])
        .output()?;

    if !output.status.success() {
        return Err(format!(
            "failed to package function source: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(())
}

/// One `docker stats` sample for a container
#[derive(Debug, Clone, Copy)]
pub struct ResourceSample {
    pub mem_mb: f64,
    pub cpu_pct: f64,
}

/// Summary of resource samples taken while a benchmark ran
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceStats {
    pub container: String,
    pub samples: usize,
    pub idle_mem_mb: f64,
    pub mean_mem_mb: f64,
    pub peak_mem_mb: f64,
    pub mean_cpu_pct: f64,
    pub peak_cpu_pct: f64,
}

/// Parse a docker size string such as "123.4MiB" or "1.2GB" into megabytes
fn parse_docker_size_mb(s: &str) -> Option<f64> {
    let s = s.trim();
    let split = s.find(|c: char| c.is_ascii_alphabetic()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let value: f64 = num.trim().parse().ok()?;
    let factor = match unit.trim() {
        "B" => 1.0 / (1024.0 * 1024.0),
        "KiB" | "kB" | "KB" => 1.0 / 1024.0,
        "MiB" | "MB" => 1.0,
        "GiB" | "GB" => 1024.0,
        "TiB" | "TB" => 1024.0 * 1024.0,
        _ => return None,
    };
    Some(value * factor)
}

/// Take one resource sample of a container via `docker stats`
pub fn sample_container(container: &str) -> Option<ResourceSample> {
    let output = Command::new("docker")
        .args([
            "stats",
            "--no-stream",
            "--format",
            "{{.MemUsage}}|{{.CPUPerc}}",
            container,
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().next()?;
    let (mem, cpu) = line.split_once('|')?;
    let mem_used = mem.split('/').next()?;
    let mem_mb = parse_docker_size_mb(mem_used)?;
    let cpu_pct: f64 = cpu.trim().trim_end_matches('%').parse().ok()?;
    Some(ResourceSample { mem_mb, cpu_pct })
}

/// Samples a container's resource usage on a background thread until stopped
pub struct ResourceSampler {
    stop: Arc<AtomicBool>,
    handle: std::thread::JoinHandle<Vec<ResourceSample>>,
    container: String,
    idle: Option<ResourceSample>,
}

impl ResourceSampler {
    pub fn start(container: &str) -> Self {
        let idle = sample_container(container);
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = stop.clone();
        let name = container.to_string();
        let handle = std::thread::spawn(move || {
            let mut samples = Vec::new();
            while !stop_flag.load(Ordering::Relaxed) {
                if let Some(sample) = sample_container(&name) {
                    samples.push(sample);
                }
            }
            samples
        });
        Self {
            stop,
            handle,
            container: container.to_string(),
            idle,
        }
    }

    pub fn finish(self) -> Option<ResourceStats> {
        self.stop.store(true, Ordering::Relaxed);
        let samples = self.handle.join().unwrap_or_default();
        if samples.is_empty() {
            return None;
        }
        let n = samples.len() as f64;
        Some(ResourceStats {
            container: self.container,
            samples: samples.len(),
            idle_mem_mb: self.idle.map(|s| s.mem_mb).unwrap_or(0.0),
            mean_mem_mb: samples.iter().map(|s| s.mem_mb).sum::<f64>() / n,
            peak_mem_mb: samples.iter().map(|s| s.mem_mb).fold(0.0, f64::max),
            mean_cpu_pct: samples.iter().map(|s| s.cpu_pct).sum::<f64>() / n,
            peak_cpu_pct: samples.iter().map(|s| s.cpu_pct).fold(0.0, f64::max),
        })
    }
}

/// Print benchmark results in a nice format
pub fn print_results(results: &BenchmarkResults) {
    let title = format!(" {} ", results.name);
    let padding = (60_usize.saturating_sub(title.len())) / 2;
    println!(
        "\n{:=<pad$}{}{:=<rest$}",
        "",
        title,
        "",
        pad = padding,
        rest = 60 - padding - title.len()
    );
    println!("Duration:           {:.2}s", results.duration_secs);
    println!("Total Requests:     {}", results.total_requests);
    println!("Successful:         {}", results.successful_requests);
    println!("Failed:             {}", results.failed_requests);
    println!("RPS:                {:.2}", results.rps);
    println!();
    println!("Latency:");
    println!("  Min:              {:.2}ms", results.latency.min_ms);
    println!("  Mean:             {:.2}ms", results.latency.mean_ms);
    println!("  p50:              {:.2}ms", results.latency.p50_ms);
    println!("  p90:              {:.2}ms", results.latency.p90_ms);
    println!("  p99:              {:.2}ms", results.latency.p99_ms);
    println!("  p99.9:            {:.2}ms", results.latency.p999_ms);
    println!("  Max:              {:.2}ms", results.latency.max_ms);
    println!();
    println!("Status Codes:");
    let mut codes: Vec<_> = results.status_codes.iter().collect();
    codes.sort();
    for (code, count) in codes {
        println!("  {}: {}", code, count);
    }
    if !results.errors.is_empty() {
        println!();
        println!("Sample Errors:");
        for (i, error) in results.errors.iter().enumerate().take(5) {
            println!("  {}: {}", i + 1, error);
        }
    }
    println!("{:=<60}", "");
}

/// Print state and recent logs of every container whose name contains the
/// runtime ID, so a runtime that died under load can be diagnosed before the
/// executor removes it.
pub fn dump_runtime_diagnostics(runtime_id: &str) {
    let list = Command::new("docker")
        .args([
            "ps",
            "-a",
            "--filter",
            &format!("name={}", runtime_id),
            "--format",
            "{{.Names}}",
        ])
        .output();
    let names: Vec<String> = match list {
        Ok(out) => String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect(),
        Err(e) => {
            println!("  docker ps failed: {}", e);
            return;
        }
    };
    if names.is_empty() {
        println!("  no container matching {} exists", runtime_id);
        return;
    }
    for name in names {
        let state = Command::new("docker")
            .args([
                "inspect",
                "--format",
                "status={{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} restarts={{.RestartCount}} started={{.State.StartedAt}} finished={{.State.FinishedAt}}",
                &name,
            ])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|e| format!("inspect failed: {}", e));
        println!("  {}: {}", name, state);
        if let Ok(logs) = Command::new("docker")
            .args(["logs", "--tail", "60", &name])
            .output()
        {
            for line in String::from_utf8_lossy(&logs.stdout)
                .lines()
                .chain(String::from_utf8_lossy(&logs.stderr).lines())
            {
                println!("    | {}", line);
            }
        }
    }
}

/// Remove leftover runtime containers created by URT during benchmark runs
pub async fn cleanup_benchmark_containers() {
    let output = Command::new("docker")
        .args([
            "ps",
            "-a",
            "--filter",
            "label=urt.managed=true",
            "--format",
            "{{.Names}}",
        ])
        .output();

    if let Ok(result) = output {
        let stdout = String::from_utf8_lossy(&result.stdout);
        let mut cleaned = 0;

        for name in stdout.lines() {
            let name = name.trim();
            if name.is_empty() {
                continue;
            }

            if name.contains("panini")
                || name.contains("redis")
                || name.contains("minio")
                || name.contains("postgres")
                || name == "urt-executor"
            {
                continue;
            }

            let rm_result = Command::new("docker").args(["rm", "-f", name]).output();

            if rm_result.is_ok() {
                cleaned += 1;
            }
        }

        if cleaned > 0 {
            println!("  Removed {} leftover container(s)", cleaned);
        } else {
            println!("  No leftover containers to clean");
        }
    }
}
