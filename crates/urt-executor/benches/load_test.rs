//! Load testing benchmark suite for URT Executor
//!
//! This module provides high-performance load testing:
//! - Open-loop benchmarking (no artificial throttling)
//! - Concurrent warmup for proper connection pooling
//! - Accurate latency measurement (request time only)
//! - Pooled results with percentile calculation

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::{Client, RequestBuilder};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

/// Benchmark configuration
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
            base_url: "http://localhost:9901".to_string(),
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
    /// HTTP status code distribution
    pub status_codes: HashMap<u16, u64>,
    /// Error messages
    pub errors: Vec<String>,
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

    /// Run a benchmark against the health endpoint
    pub async fn benchmark_health(&self) -> BenchmarkResults {
        let url = format!("{}/v1/health", self.config.base_url);
        let secret = self.config.secret.clone();
        self.run_benchmark("health_endpoint", move |client| {
            let url = url.clone();
            let secret = secret.clone();
            async move { apply_auth_headers(client.get(&url), &secret).send().await }
        })
        .await
    }

    /// Run a benchmark against the ping endpoint (minimal, no auth)
    pub async fn benchmark_ping(&self) -> BenchmarkResults {
        let url = format!("{}/v1/ping", self.config.base_url);
        self.run_benchmark("ping_endpoint", move |client| {
            let url = url.clone();
            async move { client.get(&url).send().await }
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
            async move { apply_auth_headers(client.get(&url), &secret).send().await }
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
        let payload = serde_json::json!({
            "body": "{}",
            "path": path,
            "method": "GET",
            "headers": {}
        });

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
                apply_auth_headers(client.post(&url), &secret)
                    .header("Content-Type", "application/json")
                    .json(&payload)
                    .send()
                    .await
            }
        })
        .await
    }

    /// Open-loop benchmark runner - no artificial throttling
    async fn run_benchmark<F, Fut>(&self, name: &str, request_fn: F) -> BenchmarkResults
    where
        F: Fn(Client) -> Fut + Send + Sync + Clone + 'static,
        Fut: std::future::Future<Output = Result<reqwest::Response, reqwest::Error>> + Send,
    {
        // Phase 1: Concurrent warmup
        println!("Warming up for {:?}...", self.config.warmup);
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
        println!(
            "Running benchmark for {:?} with {} workers...",
            self.config.duration, self.config.concurrency
        );

        let total_requests = Arc::new(AtomicU64::new(0));
        let successful_requests = Arc::new(AtomicU64::new(0));
        let failed_requests = Arc::new(AtomicU64::new(0));
        let results = Arc::new(Mutex::new(Vec::with_capacity(100_000)));
        let status_codes = Arc::new(Mutex::new(HashMap::new()));
        let errors = Arc::new(Mutex::new(Vec::new()));

        let benchmark_start = Instant::now();

        // Spawn workers that hammer the endpoint
        let handles: Vec<_> = (0..self.config.concurrency)
            .map(|_| {
                let client = self.client.clone();
                let request_fn = request_fn.clone();
                let duration = self.config.duration;
                let total_requests = total_requests.clone();
                let successful_requests = successful_requests.clone();
                let failed_requests = failed_requests.clone();
                let results = results.clone();
                let status_codes = status_codes.clone();
                let errors = errors.clone();

                tokio::spawn(async move {
                    let worker_start = Instant::now();
                    let mut local_results = Vec::with_capacity(10_000);

                    while worker_start.elapsed() < duration {
                        // Measure ONLY the request time
                        let req_start = Instant::now();
                        let response = request_fn(client.clone()).await;
                        let latency_ns = req_start.elapsed().as_nanos() as u64;

                        total_requests.fetch_add(1, Ordering::Relaxed);

                        match response {
                            Ok(resp) => {
                                let status = resp.status().as_u16();

                                if resp.status().is_success() {
                                    successful_requests.fetch_add(1, Ordering::Relaxed);
                                } else {
                                    failed_requests.fetch_add(1, Ordering::Relaxed);
                                }

                                local_results.push(RequestResult { latency_ns, status });

                                // Update status codes less frequently
                                if local_results.len() % 100 == 0 {
                                    let mut codes = status_codes.lock().await;
                                    *codes.entry(status).or_insert(0) += 100;
                                }
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

                    // Merge local results at end
                    let mut global_results = results.lock().await;
                    global_results.extend(local_results);
                })
            })
            .collect();

        // Wait for all workers
        futures::future::join_all(handles).await;

        let actual_duration = benchmark_start.elapsed();

        // Phase 3: Calculate stats from pooled results
        let total = total_requests.load(Ordering::Relaxed);
        let successful = successful_requests.load(Ordering::Relaxed);
        let failed = failed_requests.load(Ordering::Relaxed);
        let rps = total as f64 / actual_duration.as_secs_f64();

        // Calculate latency percentiles
        let results_guard = results.lock().await;
        let mut latencies: Vec<f64> = results_guard
            .iter()
            .map(|r| r.latency_ns as f64 / 1_000_000.0) // Convert to ms
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

        // Rebuild accurate status code counts from collected results
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

/// Create a runtime for benchmarking
pub async fn create_benchmark_runtime(
    base_url: &str,
    secret: &str,
    runtime_id: &str,
    image: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    let url = format!("{}/v1/runtimes", base_url);

    // The runtimeEntrypoint becomes the container CMD via `bash -c runtimeEntrypoint`
    // Run the server in foreground to keep the container alive (Docker.php line 463)
    let payload = serde_json::json!({
        "runtimeId": runtime_id,
        "image": image,
        "entrypoint": "",
        "variables": {},
        "runtimeEntrypoint": "cd /usr/local/server && exec node src/server.js"
    });

    let response = apply_auth_headers(client.post(&url), secret)
        .header("Content-Type", "application/json")
        .json(&payload)
        .timeout(Duration::from_secs(120))
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Failed to create runtime: {} - {}", status, body).into());
    }

    // Wait for runtime to be ready
    tokio::time::sleep(Duration::from_secs(3)).await;
    Ok(())
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
        .send()
        .await?;

    Ok(())
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
    for (code, count) in &results.status_codes {
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

/// Cleanup Docker containers from benchmark runs
/// Removes containers with urt.managed=true label, excluding panini and known services
pub async fn cleanup_benchmark_containers() {
    use std::process::Command;

    // Get containers with urt.managed=true label
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

            // Skip panini and known service containers
            if name.contains("panini")
                || name.contains("redis")
                || name.contains("minio")
                || name.contains("postgres")
                || name == "urt-executor"
            {
                continue;
            }

            // Remove the container
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

/// Run Apache Bench (ab) and parse results
/// Returns BenchmarkResults with ab metrics
/// Set quiet=true to suppress console output
pub async fn run_ab_benchmark(
    url: &str,
    requests: u64,
    concurrency: usize,
    quiet: bool,
    secret: &str,
) -> Option<BenchmarkResults> {
    use std::process::Command;

    if !quiet {
        println!("\n### Apache Bench (ab) Validation ###");
        println!("Running: ab -n {} -c {} -k {}", requests, concurrency, url);
    }

    let output = Command::new("ab")
        .args([
            "-n",
            &requests.to_string(),
            "-c",
            &concurrency.to_string(),
            "-k", // Keep-alive
            "-H",
            &format!("Authorization: Bearer {}", secret),
            "-H",
            &format!("x-open-runtimes-secret: {}", secret),
            url,
        ])
        .output();

    match output {
        Ok(result) => {
            let stdout = String::from_utf8_lossy(&result.stdout);
            let stderr = String::from_utf8_lossy(&result.stderr);

            if !result.status.success() {
                eprintln!("ab failed: {}", stderr);
                return None;
            }

            // Parse ab output
            let mut rps = 0.0;
            let mut total_requests = 0u64;
            let mut failed_requests = 0u64;
            let mut mean_ms = 0.0;
            let mut p50_ms = 0.0;
            let mut p99_ms = 0.0;
            let mut min_ms = 0.0;
            let mut max_ms = 0.0;

            for line in stdout.lines() {
                let line = line.trim();

                if line.starts_with("Requests per second:") {
                    if let Some(val) = line.split_whitespace().nth(3) {
                        rps = val.parse().unwrap_or(0.0);
                    }
                } else if line.starts_with("Complete requests:") {
                    if let Some(val) = line.split_whitespace().nth(2) {
                        total_requests = val.parse().unwrap_or(0);
                    }
                } else if line.starts_with("Failed requests:") {
                    if let Some(val) = line.split_whitespace().nth(2) {
                        failed_requests = val.parse().unwrap_or(0);
                    }
                } else if line.starts_with("Time per request:")
                    && line.contains("(mean)")
                    && !line.contains("across")
                {
                    if let Some(val) = line.split_whitespace().nth(3) {
                        mean_ms = val.parse().unwrap_or(0.0);
                    }
                } else if line.starts_with("50%") {
                    if let Some(val) = line.split_whitespace().nth(1) {
                        p50_ms = val.parse().unwrap_or(0.0);
                    }
                } else if line.starts_with("99%") {
                    if let Some(val) = line.split_whitespace().nth(1) {
                        p99_ms = val.parse().unwrap_or(0.0);
                    }
                } else if line.contains("min") && line.contains("mean") && line.contains("max") {
                    // Skip header line
                } else if line.starts_with("Total:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 5 {
                        min_ms = parts[1].parse().unwrap_or(0.0);
                        max_ms = parts[4].parse().unwrap_or(0.0);
                    }
                }
            }

            if !quiet {
                println!("\n==================== ab_benchmark ====================");
                println!("Requests per second:    {:.2}", rps);
                println!("Complete requests:      {}", total_requests);
                println!("Failed requests:        {}", failed_requests);
                println!("Mean latency:           {:.2}ms", mean_ms);
                println!("p50 latency:            {:.2}ms", p50_ms);
                println!("p99 latency:            {:.2}ms", p99_ms);
                println!("========================================================\n");
            }

            Some(BenchmarkResults {
                name: "ab_benchmark".to_string(),
                total_requests,
                successful_requests: total_requests - failed_requests,
                failed_requests,
                rps,
                duration_secs: total_requests as f64 / rps,
                latency: LatencyStats {
                    min_ms,
                    max_ms,
                    mean_ms,
                    p50_ms,
                    p90_ms: 0.0, // ab doesn't report p90 in standard output
                    p99_ms,
                    p999_ms: 0.0, // ab doesn't report p999
                },
                status_codes: HashMap::new(),
                errors: Vec::new(),
            })
        }
        Err(e) => {
            eprintln!("Failed to run ab: {} (is Apache Bench installed?)", e);
            None
        }
    }
}
