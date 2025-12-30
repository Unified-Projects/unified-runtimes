//! Benchmark runner for URT Executor
//!
//! Run with: cargo bench --bench benchmark
//! Or use: ./benchmark.sh [OPTIONS]
//!
//! Environment variables:
//! - URT_URL: URL of URT executor (default: http://localhost:9900)
//! - BENCH_SECRET: Authentication secret (default: benchmark-secret)
//! - URT_SECRET: Authentication secret override for URT (default: BENCH_SECRET)
//! - BENCH_CONCURRENCY: Number of concurrent connections (default: 50)
//! - BENCH_DURATION: Duration in seconds (default: 30)
//! - BENCH_WARMUP: Warmup duration in seconds (default: 3)
//! - BENCH_TIMEOUT: Request timeout in seconds (default: 30)
//! - BENCH_RUNTIME_IMAGE: Runtime image to use (default: openruntimes/node:v5-22)
//! - BENCH_FUNCTION: Function type (node, nextjs) - default: node
//! - BENCH_FUNCTION_SOURCE: Path to function source directory
//! - BENCH_OUTPUT_JSON: Path to write JSON results

mod load_test;

use load_test::{cleanup_benchmark_containers, run_ab_benchmark, *};
use std::env;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Concurrency levels to test in CI
const CONCURRENCY_LEVELS: &[usize] = &[1, 10, 25, 50, 100];

struct BenchmarkRunner {
    urt_config: BenchmarkConfig,
    runtime_image: String,
    function_type: String,
    function_source: Option<String>,
}

impl BenchmarkRunner {
    fn from_env() -> Self {
        let urt_url = env::var("URT_URL").unwrap_or_else(|_| "http://localhost:9900".to_string());
        let bench_secret =
            env::var("BENCH_SECRET").unwrap_or_else(|_| "benchmark-secret".to_string());
        let urt_secret = env::var("URT_SECRET").unwrap_or_else(|_| bench_secret.clone());

        let concurrency: usize = env::var("BENCH_CONCURRENCY")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(50);

        let duration_secs: u64 = env::var("BENCH_DURATION")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);

        let warmup_secs: u64 = env::var("BENCH_WARMUP")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3);

        let timeout_secs: u64 = env::var("BENCH_TIMEOUT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);

        let runtime_image = env::var("BENCH_RUNTIME_IMAGE")
            .unwrap_or_else(|_| "openruntimes/node:v5-22".to_string());

        let function_type = env::var("BENCH_FUNCTION").unwrap_or_else(|_| "node".to_string());

        let function_source = env::var("BENCH_FUNCTION_SOURCE").ok();

        let urt_config = BenchmarkConfig {
            base_url: urt_url,
            secret: urt_secret,
            concurrency,
            duration: Duration::from_secs(duration_secs),
            timeout: Duration::from_secs(timeout_secs),
            warmup: Duration::from_secs(warmup_secs),
        };

        Self {
            urt_config,
            runtime_image,
            function_type,
            function_source,
        }
    }

    fn print_config(&self) {
        println!("=== URT Executor Benchmark Suite ===");
        println!();
        println!("Configuration:");
        println!("  URT URL:        {}", self.urt_config.base_url);
        println!("  Concurrency:    {}", self.urt_config.concurrency);
        println!("  Duration:       {:?}", self.urt_config.duration);
        println!("  Warmup:         {:?}", self.urt_config.warmup);
        println!("  Timeout:        {:?}", self.urt_config.timeout);
        println!("  Runtime Image:  {}", self.runtime_image);
        println!("  Function Type:  {}", self.function_type);
        if let Some(ref source) = self.function_source {
            println!("  Function Src:   {}", source);
        }
        println!();
    }
}

#[tokio::main]
async fn main() {
    let runner = BenchmarkRunner::from_env();
    runner.print_config();

    let mut urt_results = BenchmarkResultSet::default();

    // Ping endpoint benchmark (minimal, no auth)
    println!("\n### Ping Endpoint Benchmark (Minimal) ###");

    println!("\nBenchmarking URT Executor ping endpoint...");
    let tester = LoadTester::new(runner.urt_config.clone());
    let result = tester.benchmark_ping().await;
    print_results(&result);
    urt_results.ping = Some(result);

    // Health endpoint benchmarks with multiple concurrency levels
    println!("\n### Health Endpoint Benchmark (Multi-Concurrency) ###");

    {
        let cfg = &runner.urt_config;
        println!("\nBenchmarking URT Executor across concurrency levels...");

        // Run ab benchmarks at each concurrency level
        let ab_url = format!("{}/v1/health", cfg.base_url);
        let mut ab_results: Vec<(usize, Option<BenchmarkResults>)> = Vec::new();

        for &c in CONCURRENCY_LEVELS {
            print!("  Testing c={}... ", c);
            std::io::Write::flush(&mut std::io::stdout()).ok();
            let result = run_ab_benchmark(&ab_url, 50000, c, true, &cfg.secret).await;
            if let Some(ref r) = result {
                println!("{:.0} RPS", r.rps);
            } else {
                println!("FAILED");
            }
            ab_results.push((c, result));
        }

        // Print concurrency scaling table (markdown format for CI)
        println!("\n## URT Concurrency Scaling (ab)\n");
        println!("| Concurrency | RPS | p50 (ms) | p99 (ms) |");
        println!("|-------------|-----|----------|----------|");

        for (c, result) in &ab_results {
            if let Some(ref r) = result {
                println!(
                    "| {} | {:.2} | {:.2} | {:.2} |",
                    c, r.rps, r.latency.p50_ms, r.latency.p99_ms
                );
            } else {
                println!("| {} | FAILED | - | - |", c);
            }
        }
        println!();

        // Also run the Rust benchmark at configured concurrency for detailed stats
        println!("\nRust benchmark at c={}...", cfg.concurrency);
        let tester = LoadTester::new(cfg.clone());
        let result = tester.benchmark_health().await;
        print_results(&result);
        urt_results.health = Some(result);
    }

    // Function execution benchmarks
    println!("\n### Function Execution Benchmark ###");

    // Generate unique runtime IDs for this benchmark run
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let urt_runtime_id = format!("bench-{}", timestamp);

    // Create URT runtime
    {
        let cfg = &runner.urt_config;
        println!("\nCreating URT runtime: {}...", urt_runtime_id);
        if let Err(e) = create_benchmark_runtime(
            &cfg.base_url,
            &cfg.secret,
            &urt_runtime_id,
            &runner.runtime_image,
        )
        .await
        {
            eprintln!("Failed to create URT runtime: {}", e);
        }
    }

    // Wait for runtimes to be ready
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Benchmark function execution
    println!("\nBenchmarking URT Executor function execution...");
    let tester = LoadTester::new(runner.urt_config.clone());
    let result = tester.benchmark_execution(&urt_runtime_id).await;
    print_results(&result);
    urt_results.execution = Some(result);

    // Next.js specific benchmarks (multiple endpoints)
    if runner.function_type == "nextjs" {
        println!("\n### Next.js API Endpoints Benchmark ###");

        // Benchmark /api/data endpoint (data processing workload)
        println!("\nBenchmarking URT /api/data endpoint...");
        let tester = LoadTester::new(runner.urt_config.clone());
        let result = tester
            .benchmark_execution_with_path(&urt_runtime_id, "/api/data")
            .await;
        print_results(&result);

        // Benchmark /api/compute endpoint (CPU-bound workload)
        println!("\nBenchmarking URT /api/compute endpoint...");
        let tester = LoadTester::new(runner.urt_config.clone());
        let result = tester
            .benchmark_execution_with_path(&urt_runtime_id, "/api/compute")
            .await;
        print_results(&result);
    }

    // List runtimes benchmark
    println!("\n### List Runtimes Benchmark ###");

    println!("\nBenchmarking URT Executor...");
    let tester = LoadTester::new(runner.urt_config.clone());
    let result = tester.benchmark_list_runtimes().await;
    print_results(&result);
    urt_results.list_runtimes = Some(result);

    // Cleanup runtimes via API
    println!("\n### Cleanup ###\n");
    println!("Cleaning up benchmark runtimes...");
    {
        let cfg = &runner.urt_config;
        let _ = delete_benchmark_runtime(&cfg.base_url, &cfg.secret, &urt_runtime_id).await;
    }

    // Cleanup leftover Docker containers (except panini and known services)
    println!("Cleaning up Docker containers...");
    cleanup_benchmark_containers().await;

    // Print summary
    print_summary(&urt_results);

    // Output JSON results for CI
    let results = build_json_results(&urt_results);

    if let Ok(json_path) = env::var("BENCH_OUTPUT_JSON") {
        std::fs::write(&json_path, serde_json::to_string_pretty(&results).unwrap())
            .expect("Failed to write JSON results");
        println!("\nResults written to: {}", json_path);
    }
}

#[derive(Default)]
struct BenchmarkResultSet {
    ping: Option<BenchmarkResults>,
    health: Option<BenchmarkResults>,
    execution: Option<BenchmarkResults>,
    list_runtimes: Option<BenchmarkResults>,
}

fn print_summary(urt_results: &BenchmarkResultSet) {
    println!("\n## Summary\n");
    println!("| Benchmark | URT RPS |");
    println!("|-----------|---------|");
    if let Some(ref r) = urt_results.ping {
        println!("| Ping Endpoint | {:.2} |", r.rps);
    }
    if let Some(ref r) = urt_results.health {
        println!("| Health Endpoint | {:.2} |", r.rps);
    }
    if let Some(ref r) = urt_results.execution {
        println!("| Function Execution | {:.2} |", r.rps);
    }
    if let Some(ref r) = urt_results.list_runtimes {
        println!("| List Runtimes | {:.2} |", r.rps);
    }
    println!();
}

fn build_json_results(urt_results: &BenchmarkResultSet) -> serde_json::Value {
    serde_json::json!({
        "target": "urt",
        "urt": {
            "ping": urt_results.ping,
            "health": urt_results.health,
            "execution": urt_results.execution,
            "list_runtimes": urt_results.list_runtimes,
        }
    })
}
