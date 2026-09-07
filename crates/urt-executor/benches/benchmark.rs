//! Benchmark runner for URT Executor, optionally side by side with the
//! OpenRuntimes executor driving the same runtime image and function.
//!
//! Run with: cargo bench --package urt-executor --bench benchmark
//!
//! Environment variables:
//! - URT_URL: URL of URT executor (default: http://localhost:9900)
//! - OPR_URL: URL of an OpenRuntimes executor to compare against (optional)
//! - BENCH_SECRET: Authentication secret (default: benchmark-secret)
//! - URT_SECRET / OPR_SECRET: per-executor secret overrides (default: BENCH_SECRET)
//! - BENCH_URT_CONTAINER / BENCH_OPR_CONTAINER: executor container names for
//!   resource sampling (default: urt-bench-executor / opr-bench-executor)
//! - BENCH_CONCURRENCY: Number of concurrent connections (default: 50)
//! - BENCH_DURATION: Duration in seconds for the main runs (default: 30)
//! - BENCH_SWEEP_DURATION: Duration in seconds per concurrency level (default: 10)
//! - BENCH_WARMUP: Warmup duration in seconds (default: 3)
//! - BENCH_TIMEOUT: Request timeout in seconds (default: 30)
//! - BENCH_COLD_STARTS: Cold-start rounds per executor (default: 3)
//! - BENCH_RUNTIME_IMAGE: Runtime image to use (default: openruntimes/node:v5-22)
//! - BENCH_FUNCTION: Function type (node, nextjs) - default: node
//! - BENCH_FUNCTION_SOURCE: Host path to a function source directory. When set
//!   it is packaged into BENCH_SOURCE_ARCHIVE and handed to both executors.
//! - BENCH_SOURCE_ARCHIVE: Archive path as seen by the executors
//!   (default: /tmp/urt-bench/code.tar.gz)
//! - BENCH_OUTPUT_JSON: Path to write JSON results

mod load_test;

use load_test::*;
use serde::Serialize;
use std::env;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Concurrency levels for the scaling sweeps
const CONCURRENCY_LEVELS: &[usize] = &[1, 10, 25, 50, 100];

/// Default archive location shared through the Docker host's /tmp
const DEFAULT_SOURCE_ARCHIVE: &str = "/tmp/urt-bench/code.tar.gz";

/// One executor under test
struct Target {
    /// Short key used in JSON output
    key: &'static str,
    /// Human-readable name for tables
    label: &'static str,
    config: BenchmarkConfig,
    container: String,
}

#[derive(Serialize)]
struct SweepPoint {
    concurrency: usize,
    result: BenchmarkResults,
}

#[derive(Serialize)]
struct ColdStart {
    create_ms: f64,
    first_execution_ms: f64,
    total_ms: f64,
}

#[derive(Default, Serialize)]
struct TargetResults {
    ping: Option<BenchmarkResults>,
    health: Option<BenchmarkResults>,
    health_sweep: Vec<SweepPoint>,
    cold_starts: Vec<ColdStart>,
    execution: Option<BenchmarkResults>,
    execution_sweep: Vec<SweepPoint>,
    list_runtimes: Option<BenchmarkResults>,
    resources: Option<ResourceStats>,
    errors: Vec<String>,
}

impl TargetResults {
    fn median_cold_start_ms(&self) -> Option<f64> {
        median(self.cold_starts.iter().map(|c| c.total_ms))
    }
}

fn median<I: Iterator<Item = f64>>(values: I) -> Option<f64> {
    let mut v: Vec<f64> = values.collect();
    if v.is_empty() {
        return None;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    Some(v[v.len() / 2])
}

struct BenchmarkRunner {
    targets: Vec<Target>,
    function: FunctionSpec,
    function_type: String,
    function_source: Option<String>,
    source_archive: String,
    sweep_duration: Duration,
    cold_starts: usize,
}

fn env_or<T: std::str::FromStr>(key: &str, default: T) -> T {
    env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

impl BenchmarkRunner {
    fn from_env() -> Self {
        let bench_secret =
            env::var("BENCH_SECRET").unwrap_or_else(|_| "benchmark-secret".to_string());

        let base = BenchmarkConfig {
            base_url: String::new(),
            secret: bench_secret.clone(),
            concurrency: env_or("BENCH_CONCURRENCY", 50),
            duration: Duration::from_secs(env_or("BENCH_DURATION", 30)),
            timeout: Duration::from_secs(env_or("BENCH_TIMEOUT", 30)),
            warmup: Duration::from_secs(env_or("BENCH_WARMUP", 3)),
        };

        let mut targets = vec![Target {
            key: "urt",
            label: "URT",
            config: BenchmarkConfig {
                base_url: env::var("URT_URL").unwrap_or_else(|_| "http://localhost:9900".into()),
                secret: env::var("URT_SECRET").unwrap_or_else(|_| bench_secret.clone()),
                ..base.clone()
            },
            container: env::var("BENCH_URT_CONTAINER")
                .unwrap_or_else(|_| "urt-bench-executor".into()),
        }];

        if let Ok(opr_url) = env::var("OPR_URL") {
            if !opr_url.trim().is_empty() {
                targets.push(Target {
                    key: "opr",
                    label: "OpenRuntimes",
                    config: BenchmarkConfig {
                        base_url: opr_url,
                        secret: env::var("OPR_SECRET").unwrap_or_else(|_| bench_secret.clone()),
                        ..base.clone()
                    },
                    container: env::var("BENCH_OPR_CONTAINER")
                        .unwrap_or_else(|_| "opr-bench-executor".into()),
                });
            }
        }

        let runtime_image = env::var("BENCH_RUNTIME_IMAGE")
            .unwrap_or_else(|_| "openruntimes/node:v5-22".to_string());
        let function_type = env::var("BENCH_FUNCTION").unwrap_or_else(|_| "node".to_string());
        let function_source = env::var("BENCH_FUNCTION_SOURCE")
            .ok()
            .filter(|s| !s.trim().is_empty());
        let source_archive =
            env::var("BENCH_SOURCE_ARCHIVE").unwrap_or_else(|_| DEFAULT_SOURCE_ARCHIVE.into());

        // With a real function the runtime goes through the standard start
        // lifecycle (extract archive, then serve). Without one the server is
        // started bare, which keeps the executor path measurable but every
        // execution will report the runtime's "no entrypoint" error.
        let mut variables = serde_json::Map::new();
        let (entrypoint, runtime_entrypoint) = if function_source.is_some() {
            // The runtime locates the archive through OPEN_RUNTIMES_CODE_PATH.
            // The OpenRuntimes executor sets it itself; passing it as a user
            // variable gives both executors the same runtime configuration.
            variables.insert(
                "OPEN_RUNTIMES_CODE_PATH".to_string(),
                serde_json::Value::String("/tmp/code.tar.gz".to_string()),
            );
            (
                "index.js".to_string(),
                "helpers/start.sh \"node src/server.js\"".to_string(),
            )
        } else {
            (
                String::new(),
                "cd /usr/local/server && exec node src/server.js".to_string(),
            )
        };

        let function = FunctionSpec {
            image: runtime_image,
            source: function_source.as_ref().map(|_| source_archive.clone()),
            entrypoint,
            runtime_entrypoint,
            variables,
        };

        Self {
            targets,
            function,
            function_type,
            function_source,
            source_archive,
            sweep_duration: Duration::from_secs(env_or("BENCH_SWEEP_DURATION", 10)),
            cold_starts: env_or("BENCH_COLD_STARTS", 3),
        }
    }

    fn print_config(&self) {
        println!("=== Executor Benchmark Suite ===");
        println!();
        println!("Configuration:");
        for t in &self.targets {
            println!(
                "  {:<14} {} (container {})",
                format!("{} URL:", t.label),
                t.config.base_url,
                t.container
            );
        }
        let cfg = &self.targets[0].config;
        println!("  Concurrency:    {}", cfg.concurrency);
        println!("  Duration:       {:?}", cfg.duration);
        println!("  Sweep duration: {:?}", self.sweep_duration);
        println!("  Warmup:         {:?}", cfg.warmup);
        println!("  Timeout:        {:?}", cfg.timeout);
        println!("  Cold starts:    {}", self.cold_starts);
        println!("  Runtime Image:  {}", self.function.image);
        println!("  Function Type:  {}", self.function_type);
        match &self.function_source {
            Some(src) => println!("  Function Src:   {} -> {}", src, self.source_archive),
            None => println!("  Function Src:   (none, bare runtime server)"),
        }
        println!();
    }

    fn prepare_source(&self) {
        if let Some(ref dir) = self.function_source {
            println!("Packaging function source into {}...", self.source_archive);
            if let Err(e) = package_function_source(dir, &self.source_archive) {
                eprintln!("Failed to package function source: {}", e);
                std::process::exit(1);
            }
        }
    }

    async fn run_target(&self, target: &Target) -> TargetResults {
        let mut out = TargetResults::default();
        let cfg = &target.config;
        let tester = LoadTester::new(cfg.clone());
        let sweep_warmup = Duration::from_secs(2).min(cfg.warmup);

        println!("\n\n######## {} ({}) ########", target.label, cfg.base_url);

        println!("\n### Ping endpoint ###");
        let result = tester.benchmark_ping().await;
        print_results(&result);
        out.ping = Some(result);

        println!("\n### Health endpoint (c={}) ###", cfg.concurrency);
        let result = tester.benchmark_health().await;
        print_results(&result);
        out.health = Some(result);

        println!("\n### Health endpoint concurrency sweep ###");
        for &c in CONCURRENCY_LEVELS {
            let sweep = tester
                .with_concurrency(c)
                .with_timing(self.sweep_duration, sweep_warmup);
            let result = sweep.benchmark_health().await;
            println!(
                "  c={:<4} {:>10.2} RPS  p50 {:>7.2}ms  p99 {:>7.2}ms  ok {:>6.2}%",
                c,
                result.rps,
                result.latency.p50_ms,
                result.latency.p99_ms,
                result.success_pct()
            );
            out.health_sweep.push(SweepPoint {
                concurrency: c,
                result,
            });
        }

        println!("\n### Cold starts ({} rounds) ###", self.cold_starts);
        for round in 0..self.cold_starts {
            let runtime_id = format!("cold-{}-{}", round, unique_suffix());
            match self.cold_start(target, &runtime_id).await {
                Ok(cs) => {
                    println!(
                        "  round {}: create {:.0}ms, first execution {:.0}ms, total {:.0}ms",
                        round, cs.create_ms, cs.first_execution_ms, cs.total_ms
                    );
                    out.cold_starts.push(cs);
                }
                Err(e) => {
                    eprintln!("  round {}: failed: {}", round, e);
                    out.errors
                        .push(format!("cold start round {}: {}", round, e));
                }
            }
            let _ = delete_benchmark_runtime(&cfg.base_url, &cfg.secret, &runtime_id).await;
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        println!("\n### Function execution ###");
        let runtime_id = format!("bench-{}", unique_suffix());
        match self.cold_start(target, &runtime_id).await {
            Ok(_) => {
                let sampler = ResourceSampler::start(&target.container);
                let result = tester.benchmark_execution(&runtime_id).await;
                print_results(&result);
                out.resources = sampler.finish();
                if let Some(ref r) = out.resources {
                    println!(
                        "Executor {}: idle {:.1}MB, mean {:.1}MB, peak {:.1}MB, mean CPU {:.1}%, peak CPU {:.1}% ({} samples)",
                        r.container, r.idle_mem_mb, r.mean_mem_mb, r.peak_mem_mb, r.mean_cpu_pct, r.peak_cpu_pct, r.samples
                    );
                } else {
                    println!(
                        "Executor {}: no resource samples (is docker on PATH?)",
                        target.container
                    );
                }
                out.execution = Some(result);

                println!("\n### Function execution concurrency sweep ###");
                for &c in CONCURRENCY_LEVELS {
                    let sweep = tester
                        .with_concurrency(c)
                        .with_timing(self.sweep_duration, sweep_warmup);
                    let result = sweep.benchmark_execution(&runtime_id).await;
                    println!(
                        "  c={:<4} {:>10.2} RPS  p50 {:>7.2}ms  p99 {:>7.2}ms  ok {:>6.2}%",
                        c,
                        result.rps,
                        result.latency.p50_ms,
                        result.latency.p99_ms,
                        result.success_pct()
                    );
                    out.execution_sweep.push(SweepPoint {
                        concurrency: c,
                        result,
                    });
                }

                if self.function_type == "nextjs" {
                    println!("\n### Next.js API endpoints ###");
                    for path in ["/api/data", "/api/compute"] {
                        let result = tester
                            .benchmark_execution_with_path(&runtime_id, path)
                            .await;
                        print_results(&result);
                    }
                }

                println!("\n### List runtimes ###");
                let result = tester.benchmark_list_runtimes().await;
                print_results(&result);
                out.list_runtimes = Some(result);
            }
            Err(e) => {
                eprintln!("Failed to start benchmark runtime: {}", e);
                out.errors.push(format!("execution runtime: {}", e));
            }
        }

        println!("\nRemoving runtime {}...", runtime_id);
        let _ = delete_benchmark_runtime(&cfg.base_url, &cfg.secret, &runtime_id).await;

        out
    }

    /// Create a runtime and wait for its first successful execution
    async fn cold_start(
        &self,
        target: &Target,
        runtime_id: &str,
    ) -> Result<ColdStart, Box<dyn std::error::Error>> {
        let cfg = &target.config;
        let create =
            create_benchmark_runtime(&cfg.base_url, &cfg.secret, runtime_id, &self.function)
                .await?;
        let first = wait_for_first_execution(
            &cfg.base_url,
            &cfg.secret,
            runtime_id,
            Duration::from_secs(120),
        )
        .await?;
        Ok(ColdStart {
            create_ms: create.as_secs_f64() * 1000.0,
            first_execution_ms: first.as_secs_f64() * 1000.0,
            total_ms: (create + first).as_secs_f64() * 1000.0,
        })
    }
}

fn unique_suffix() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
}

#[tokio::main]
async fn main() {
    let runner = BenchmarkRunner::from_env();
    runner.print_config();
    runner.prepare_source();

    let mut all: Vec<(&Target, TargetResults)> = Vec::new();
    for target in &runner.targets {
        let results = runner.run_target(target).await;
        all.push((target, results));
    }

    println!("\n### Cleanup ###\n");
    cleanup_benchmark_containers().await;

    print_summary(&all);

    if let Ok(json_path) = env::var("BENCH_OUTPUT_JSON") {
        let mut doc = serde_json::Map::new();
        for (target, results) in &all {
            doc.insert(
                target.key.to_string(),
                serde_json::to_value(results).expect("serialisable results"),
            );
        }
        std::fs::write(
            &json_path,
            serde_json::to_string_pretty(&serde_json::Value::Object(doc)).unwrap(),
        )
        .expect("Failed to write JSON results");
        println!("\nResults written to: {}", json_path);
    }
}

fn fmt_rps(r: &Option<BenchmarkResults>) -> String {
    match r {
        Some(r) => format!("{:.2} ({:.1}% ok)", r.rps, r.success_pct()),
        None => "-".to_string(),
    }
}

fn fmt_p99(r: &Option<BenchmarkResults>) -> String {
    match r {
        Some(r) => format!("{:.2}", r.latency.p99_ms),
        None => "-".to_string(),
    }
}

/// A summary row: label plus the cell formatter applied to each target
type SummaryRow = (&'static str, fn(&TargetResults) -> String);

fn print_summary(all: &[(&Target, TargetResults)]) {
    let header: String = all.iter().map(|(t, _)| format!(" {} |", t.label)).collect();
    let divider: String = all.iter().map(|_| "---|").collect();

    println!("\n## Summary\n");
    println!("| Benchmark |{}", header);
    println!("|-----------|{}", divider);

    let rows: [SummaryRow; 8] = [
        ("Ping RPS", |r| fmt_rps(&r.ping)),
        ("Health RPS", |r| fmt_rps(&r.health)),
        ("Health p99 (ms)", |r| fmt_p99(&r.health)),
        ("Execution RPS", |r| fmt_rps(&r.execution)),
        ("Execution p99 (ms)", |r| fmt_p99(&r.execution)),
        ("List runtimes RPS", |r| fmt_rps(&r.list_runtimes)),
        ("Cold start median (ms)", |r| {
            r.median_cold_start_ms()
                .map(|v| format!("{:.0}", v))
                .unwrap_or_else(|| "-".into())
        }),
        ("Executor memory mean/peak (MB)", |r| {
            r.resources
                .as_ref()
                .map(|s| format!("{:.1} / {:.1}", s.mean_mem_mb, s.peak_mem_mb))
                .unwrap_or_else(|| "-".into())
        }),
    ];
    for (name, f) in rows {
        let cells: String = all.iter().map(|(_, r)| format!(" {} |", f(r))).collect();
        println!("| {} |{}", name, cells);
    }

    for (title, pick) in [
        (
            "Health Concurrency Scaling",
            (|r: &TargetResults| &r.health_sweep) as fn(&TargetResults) -> &Vec<SweepPoint>,
        ),
        ("Execution Concurrency Scaling", |r: &TargetResults| {
            &r.execution_sweep
        }),
    ] {
        println!("\n## {}\n", title);
        let cols: String = all
            .iter()
            .map(|(t, _)| format!(" {} RPS | {} p99 (ms) |", t.label, t.label))
            .collect();
        let div: String = all.iter().map(|_| "---|---|").collect();
        println!("| Concurrency |{}", cols);
        println!("|-------------|{}", div);
        for &c in CONCURRENCY_LEVELS {
            let cells: String = all
                .iter()
                .map(|(_, r)| match pick(r).iter().find(|p| p.concurrency == c) {
                    Some(p) => format!(" {:.2} | {:.2} |", p.result.rps, p.result.latency.p99_ms),
                    None => " - | - |".to_string(),
                })
                .collect();
            println!("| {} |{}", c, cells);
        }
    }

    for (target, results) in all {
        if !results.errors.is_empty() {
            println!("\n{} errors:", target.label);
            for e in &results.errors {
                println!("  - {}", e);
            }
        }
    }
    println!();
}
