//! Benchmark runner for URT Executor
//!
//! Run with: cargo bench --bench benchmark
//! Or use: ./benchmark.sh [OPTIONS]
//!
//! Environment variables:
//! - BENCH_RUNTIME_TARGET: Which runtime to benchmark (urt, opr, both) - default: both
//! - URT_URL: URL of URT executor (default: http://localhost:9900)
//! - OPR_URL: URL of OpenRuntimes executor (default: http://localhost:9902)
//! - BENCH_SECRET: Authentication secret (default: benchmark-secret)
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

#[derive(Debug, Clone, PartialEq)]
enum RuntimeTarget {
    Urt,
    Opr,
    Both,
}

impl RuntimeTarget {
    fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "urt" => RuntimeTarget::Urt,
            "opr" => RuntimeTarget::Opr,
            _ => RuntimeTarget::Both,
        }
    }

    fn includes_urt(&self) -> bool {
        matches!(self, RuntimeTarget::Urt | RuntimeTarget::Both)
    }

    fn includes_opr(&self) -> bool {
        matches!(self, RuntimeTarget::Opr | RuntimeTarget::Both)
    }
}

struct BenchmarkRunner {
    target: RuntimeTarget,
    urt_config: Option<BenchmarkConfig>,
    opr_config: Option<BenchmarkConfig>,
    runtime_image: String,
    function_type: String,
    function_source: Option<String>,
}

impl BenchmarkRunner {
    fn from_env() -> Self {
        let target = RuntimeTarget::from_str(
            &env::var("BENCH_RUNTIME_TARGET").unwrap_or_else(|_| "both".to_string()),
        );

        let urt_url = env::var("URT_URL").unwrap_or_else(|_| "http://localhost:9900".to_string());
        let opr_url = env::var("OPR_URL").unwrap_or_else(|_| "http://localhost:9902".to_string());
        let bench_secret =
            env::var("BENCH_SECRET").unwrap_or_else(|_| "benchmark-secret".to_string());
        let urt_secret = env::var("URT_SECRET").unwrap_or_else(|_| bench_secret.clone());
        let opr_secret = env::var("OPR_EXECUTOR_SECRET").unwrap_or_else(|_| bench_secret.clone());

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

        let urt_config = if target.includes_urt() {
            Some(BenchmarkConfig {
                base_url: urt_url,
                secret: urt_secret.clone(),
                concurrency,
                duration: Duration::from_secs(duration_secs),
                timeout: Duration::from_secs(timeout_secs),
                warmup: Duration::from_secs(warmup_secs),
            })
        } else {
            None
        };

        let opr_config = if target.includes_opr() {
            Some(BenchmarkConfig {
                base_url: opr_url,
                secret: opr_secret,
                concurrency,
                duration: Duration::from_secs(duration_secs),
                timeout: Duration::from_secs(timeout_secs),
                warmup: Duration::from_secs(warmup_secs),
            })
        } else {
            None
        };

        Self {
            target,
            urt_config,
            opr_config,
            runtime_image,
            function_type,
            function_source,
        }
    }

    fn print_config(&self) {
        println!("=== URT Executor Benchmark Suite ===");
        println!();
        println!("Configuration:");
        println!(
            "  Target:         {:?}",
            match self.target {
                RuntimeTarget::Urt => "URT only",
                RuntimeTarget::Opr => "OPR only",
                RuntimeTarget::Both => "Both (URT vs OPR)",
            }
        );
        if let Some(ref cfg) = self.urt_config {
            println!("  URT URL:        {}", cfg.base_url);
        }
        if let Some(ref cfg) = self.opr_config {
            println!("  OPR URL:        {}", cfg.base_url);
        }
        if let Some(cfg) = self.urt_config.as_ref().or(self.opr_config.as_ref()) {
            println!("  Concurrency:    {}", cfg.concurrency);
            println!("  Duration:       {:?}", cfg.duration);
            println!("  Warmup:         {:?}", cfg.warmup);
            println!("  Timeout:        {:?}", cfg.timeout);
        }
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
    let mut opr_results = BenchmarkResultSet::default();

    // Ping endpoint benchmark (minimal, no auth)
    println!("\n### Ping Endpoint Benchmark (Minimal) ###");

    if let Some(ref cfg) = runner.urt_config {
        println!("\nBenchmarking URT Executor ping endpoint...");
        let tester = LoadTester::new(cfg.clone());
        let result = tester.benchmark_ping().await;
        print_results(&result);
        urt_results.ping = Some(result);
    }

    if let Some(ref cfg) = runner.opr_config {
        println!("\nBenchmarking OpenRuntimes Executor ping endpoint...");
        let tester = LoadTester::new(cfg.clone());
        let result = tester.benchmark_ping().await;
        print_results(&result);
        opr_results.ping = Some(result);
    }

    if let (Some(ref urt), Some(ref opr)) = (&urt_results.ping, &opr_results.ping) {
        compare_results(urt, opr);
    }

    // Health endpoint benchmarks with multiple concurrency levels
    println!("\n### Health Endpoint Benchmark (Multi-Concurrency) ###");

    if let Some(ref cfg) = runner.urt_config {
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

    if let Some(ref cfg) = runner.opr_config {
        println!("\nBenchmarking OpenRuntimes Executor across concurrency levels...");

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
        println!("\n## OPR Concurrency Scaling (ab)\n");
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

        // Also run the Rust benchmark at configured concurrency
        println!("\nRust benchmark at c={}...", cfg.concurrency);
        let tester = LoadTester::new(cfg.clone());
        let result = tester.benchmark_health().await;
        print_results(&result);
        opr_results.health = Some(result);
    }

    if let (Some(ref urt), Some(ref opr)) = (&urt_results.health, &opr_results.health) {
        compare_results(urt, opr);
    }

    // Function execution benchmarks
    println!("\n### Function Execution Benchmark ###");

    // Generate unique runtime IDs for this benchmark run
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let urt_runtime_id = format!("bench-{}", timestamp);
    let opr_runtime_id = format!(
        "{}-{}",
        runner.runtime_image.replace(['/', ':'], "-"),
        timestamp
    );

    // Create URT runtime
    if let Some(ref cfg) = runner.urt_config {
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

    // Create OPR runtime
    if let Some(ref cfg) = runner.opr_config {
        println!("Creating OpenRuntimes runtime...");
        let client = reqwest::Client::new();
        let opr_payload = serde_json::json!({
            "image": runner.runtime_image,
            "entrypoint": "",
            "variables": {}
        });
        if let Err(e) = apply_auth_headers(
            client.post(format!("{}/v1/runtimes", cfg.base_url)),
            &cfg.secret,
        )
        .json(&opr_payload)
        .timeout(Duration::from_secs(120))
        .send()
        .await
        {
            eprintln!("Failed to create OPR runtime: {}", e);
        }
    }

    // Wait for runtimes to be ready
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Benchmark function execution
    if let Some(ref cfg) = runner.urt_config {
        println!("\nBenchmarking URT Executor function execution...");
        let tester = LoadTester::new(cfg.clone());
        let result = tester.benchmark_execution(&urt_runtime_id).await;
        print_results(&result);
        urt_results.execution = Some(result);
    }

    if let Some(ref cfg) = runner.opr_config {
        println!("\nBenchmarking OpenRuntimes Executor function execution...");
        let tester = LoadTester::new(cfg.clone());
        let result = tester.benchmark_execution(&opr_runtime_id).await;
        print_results(&result);
        opr_results.execution = Some(result);
    }

    if let (Some(ref urt), Some(ref opr)) = (&urt_results.execution, &opr_results.execution) {
        compare_results(urt, opr);
    }

    // Next.js specific benchmarks (multiple endpoints)
    if runner.function_type == "nextjs" {
        println!("\n### Next.js API Endpoints Benchmark ###");

        // Benchmark /api/data endpoint (data processing workload)
        if let Some(ref cfg) = runner.urt_config {
            println!("\nBenchmarking URT /api/data endpoint...");
            let tester = LoadTester::new(cfg.clone());
            let result = tester
                .benchmark_execution_with_path(&urt_runtime_id, "/api/data")
                .await;
            print_results(&result);
        }

        if let Some(ref cfg) = runner.opr_config {
            println!("\nBenchmarking OPR /api/data endpoint...");
            let tester = LoadTester::new(cfg.clone());
            let result = tester
                .benchmark_execution_with_path(&opr_runtime_id, "/api/data")
                .await;
            print_results(&result);
        }

        // Benchmark /api/compute endpoint (CPU-bound workload)
        if let Some(ref cfg) = runner.urt_config {
            println!("\nBenchmarking URT /api/compute endpoint...");
            let tester = LoadTester::new(cfg.clone());
            let result = tester
                .benchmark_execution_with_path(&urt_runtime_id, "/api/compute")
                .await;
            print_results(&result);
        }

        if let Some(ref cfg) = runner.opr_config {
            println!("\nBenchmarking OPR /api/compute endpoint...");
            let tester = LoadTester::new(cfg.clone());
            let result = tester
                .benchmark_execution_with_path(&opr_runtime_id, "/api/compute")
                .await;
            print_results(&result);
        }
    }

    // List runtimes benchmark
    println!("\n### List Runtimes Benchmark ###");

    if let Some(ref cfg) = runner.urt_config {
        println!("\nBenchmarking URT Executor...");
        let tester = LoadTester::new(cfg.clone());
        let result = tester.benchmark_list_runtimes().await;
        print_results(&result);
        urt_results.list_runtimes = Some(result);
    }

    if let Some(ref cfg) = runner.opr_config {
        println!("\nBenchmarking OpenRuntimes Executor...");
        let tester = LoadTester::new(cfg.clone());
        let result = tester.benchmark_list_runtimes().await;
        print_results(&result);
        opr_results.list_runtimes = Some(result);
    }

    if let (Some(ref urt), Some(ref opr)) = (&urt_results.list_runtimes, &opr_results.list_runtimes)
    {
        compare_results(urt, opr);
    }

    // Cleanup runtimes via API
    println!("\n### Cleanup ###\n");
    println!("Cleaning up benchmark runtimes...");
    if let Some(ref cfg) = runner.urt_config {
        let _ = delete_benchmark_runtime(&cfg.base_url, &cfg.secret, &urt_runtime_id).await;
    }
    if let Some(ref cfg) = runner.opr_config {
        let _ = delete_benchmark_runtime(&cfg.base_url, &cfg.secret, &opr_runtime_id).await;
    }

    // Cleanup leftover Docker containers (except panini and known services)
    println!("Cleaning up Docker containers...");
    cleanup_benchmark_containers().await;

    // Print summary
    print_summary(&runner.target, &urt_results, &opr_results);

    // Output JSON results for CI
    let results = build_json_results(&runner.target, &urt_results, &opr_results);

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

fn print_summary(
    target: &RuntimeTarget,
    urt_results: &BenchmarkResultSet,
    opr_results: &BenchmarkResultSet,
) {
    println!("\n## Summary\n");

    match target {
        RuntimeTarget::Urt => {
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
        }
        RuntimeTarget::Opr => {
            println!("| Benchmark | OPR RPS |");
            println!("|-----------|---------|");
            if let Some(ref r) = opr_results.ping {
                println!("| Ping Endpoint | {:.2} |", r.rps);
            }
            if let Some(ref r) = opr_results.health {
                println!("| Health Endpoint | {:.2} |", r.rps);
            }
            if let Some(ref r) = opr_results.execution {
                println!("| Function Execution | {:.2} |", r.rps);
            }
            if let Some(ref r) = opr_results.list_runtimes {
                println!("| List Runtimes | {:.2} |", r.rps);
            }
        }
        RuntimeTarget::Both => {
            println!("| Benchmark | URT RPS | OPR RPS | Diff |");
            println!("|-----------|---------|---------|------|");

            if let (Some(urt), Some(opr)) = (&urt_results.ping, &opr_results.ping) {
                let diff = if opr.rps > 0.0 {
                    (urt.rps - opr.rps) / opr.rps * 100.0
                } else {
                    0.0
                };
                println!(
                    "| Ping Endpoint | {:.2} | {:.2} | {:+.1}% |",
                    urt.rps, opr.rps, diff
                );
            }

            if let (Some(urt), Some(opr)) = (&urt_results.health, &opr_results.health) {
                let diff = if opr.rps > 0.0 {
                    (urt.rps - opr.rps) / opr.rps * 100.0
                } else {
                    0.0
                };
                println!(
                    "| Health Endpoint | {:.2} | {:.2} | {:+.1}% |",
                    urt.rps, opr.rps, diff
                );
            }

            if let (Some(urt), Some(opr)) = (&urt_results.execution, &opr_results.execution) {
                let diff = if opr.rps > 0.0 {
                    (urt.rps - opr.rps) / opr.rps * 100.0
                } else {
                    0.0
                };
                println!(
                    "| Function Execution | {:.2} | {:.2} | {:+.1}% |",
                    urt.rps, opr.rps, diff
                );
            }

            if let (Some(urt), Some(opr)) = (&urt_results.list_runtimes, &opr_results.list_runtimes)
            {
                let diff = if opr.rps > 0.0 {
                    (urt.rps - opr.rps) / opr.rps * 100.0
                } else {
                    0.0
                };
                println!(
                    "| List Runtimes | {:.2} | {:.2} | {:+.1}% |",
                    urt.rps, opr.rps, diff
                );
            }
        }
    }
    println!();
}

fn build_json_results(
    target: &RuntimeTarget,
    urt_results: &BenchmarkResultSet,
    opr_results: &BenchmarkResultSet,
) -> serde_json::Value {
    let mut results = serde_json::json!({
        "target": match target {
            RuntimeTarget::Urt => "urt",
            RuntimeTarget::Opr => "opr",
            RuntimeTarget::Both => "both",
        }
    });

    if target.includes_urt() {
        results["urt"] = serde_json::json!({
            "ping": urt_results.ping,
            "health": urt_results.health,
            "execution": urt_results.execution,
            "list_runtimes": urt_results.list_runtimes,
        });
    }

    if target.includes_opr() {
        results["opr"] = serde_json::json!({
            "ping": opr_results.ping,
            "health": opr_results.health,
            "execution": opr_results.execution,
            "list_runtimes": opr_results.list_runtimes,
        });
    }

    results
}
