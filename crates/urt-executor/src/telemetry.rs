//! Shared Prometheus telemetry for URT executor.

use prometheus::{
    Encoder, Gauge, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge,
    Opts, Registry, TextEncoder,
};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

#[derive(Copy, Clone)]
pub enum LatencyKind {
    Execution,
    RuntimeCreate,
}

pub struct OperationTimer {
    kind: LatencyKind,
    start: Instant,
    outcome: &'static str,
}

impl OperationTimer {
    pub fn new(kind: LatencyKind) -> Self {
        Self {
            kind,
            start: Instant::now(),
            outcome: "error",
        }
    }

    pub fn mark_success(&mut self) {
        self.outcome = "success";
    }

    pub fn mark_overload(&mut self) {
        self.outcome = "overload";
    }
}

impl Drop for OperationTimer {
    fn drop(&mut self) {
        let elapsed = self.start.elapsed();
        match self.kind {
            LatencyKind::Execution => {
                metrics().observe_execution_latency(self.outcome, elapsed);
            }
            LatencyKind::RuntimeCreate => {
                metrics().observe_runtime_create_latency(self.outcome, elapsed);
            }
        }
    }
}

pub struct ExecutorMetrics {
    registry: Registry,
    runtimes_total: IntGauge,
    runtimes_running: IntGauge,
    runtimes_pending: IntGauge,
    runtimes_listening: IntGauge,
    executions_active: IntGauge,
    stat_containers: IntGauge,
    runtime_cpu_percent_sum: Gauge,
    runtime_memory_bytes_sum: Gauge,
    host_memory_limit_bytes: Gauge,
    host_memory_usage_percent: Gauge,
    host_cpu_usage_percent: Gauge,
    execution_queue_depth: IntGauge,
    runtime_create_queue_depth: IntGauge,
    execution_queue_capacity: IntGauge,
    runtime_create_queue_capacity: IntGauge,
    execution_queue_wait_seconds: Histogram,
    runtime_create_queue_wait_seconds: Histogram,
    execution_latency_seconds: HistogramVec,
    runtime_create_latency_seconds: HistogramVec,
    keep_alive_transfers_total: IntCounter,
    keep_alive_cleanup_total: IntCounterVec,
    retry_attempts_total: IntCounterVec,
    errors_total: IntCounterVec,
    network_attach_failures_total: IntCounterVec,
    readiness_wait_seconds: HistogramVec,
    readiness_timeout_total: IntCounter,
    runtime_deaths_total: IntCounterVec,
    runtime_quarantined_total: IntCounter,
    runtime_unreachable_total: IntCounter,
}

impl ExecutorMetrics {
    fn register_int_gauge(registry: &Registry, name: &str, help: &str) -> Result<IntGauge, String> {
        let metric = IntGauge::new(name, help).map_err(|e| e.to_string())?;
        registry
            .register(Box::new(metric.clone()))
            .map_err(|e| e.to_string())?;
        Ok(metric)
    }

    fn register_gauge(registry: &Registry, name: &str, help: &str) -> Result<Gauge, String> {
        let metric = Gauge::with_opts(Opts::new(name, help)).map_err(|e| e.to_string())?;
        registry
            .register(Box::new(metric.clone()))
            .map_err(|e| e.to_string())?;
        Ok(metric)
    }

    fn register_histogram(
        registry: &Registry,
        name: &str,
        help: &str,
        buckets: Vec<f64>,
    ) -> Result<Histogram, String> {
        let metric = Histogram::with_opts(HistogramOpts::new(name, help).buckets(buckets))
            .map_err(|e| e.to_string())?;
        registry
            .register(Box::new(metric.clone()))
            .map_err(|e| e.to_string())?;
        Ok(metric)
    }

    fn register_histogram_vec(
        registry: &Registry,
        name: &str,
        help: &str,
        labels: &[&str],
        buckets: Vec<f64>,
    ) -> Result<HistogramVec, String> {
        let metric = HistogramVec::new(HistogramOpts::new(name, help).buckets(buckets), labels)
            .map_err(|e| e.to_string())?;
        registry
            .register(Box::new(metric.clone()))
            .map_err(|e| e.to_string())?;
        Ok(metric)
    }

    fn register_int_counter(
        registry: &Registry,
        name: &str,
        help: &str,
    ) -> Result<IntCounter, String> {
        let metric = IntCounter::new(name, help).map_err(|e| e.to_string())?;
        registry
            .register(Box::new(metric.clone()))
            .map_err(|e| e.to_string())?;
        Ok(metric)
    }

    fn register_int_counter_vec(
        registry: &Registry,
        name: &str,
        help: &str,
        labels: &[&str],
    ) -> Result<IntCounterVec, String> {
        let metric =
            IntCounterVec::new(Opts::new(name, help), labels).map_err(|e| e.to_string())?;
        registry
            .register(Box::new(metric.clone()))
            .map_err(|e| e.to_string())?;
        Ok(metric)
    }

    fn new() -> Self {
        let registry = Registry::new();

        let runtimes_total = Self::register_int_gauge(
            &registry,
            "urt_executor_runtimes",
            "Total runtimes currently tracked by URT Executor",
        )
        .expect("failed to register runtimes_total");
        let runtimes_running = Self::register_int_gauge(
            &registry,
            "urt_executor_runtimes_running",
            "Number of runtimes currently in running state",
        )
        .expect("failed to register runtimes_running");
        let runtimes_pending = Self::register_int_gauge(
            &registry,
            "urt_executor_runtimes_pending",
            "Number of runtimes currently in pending state",
        )
        .expect("failed to register runtimes_pending");
        let runtimes_listening = Self::register_int_gauge(
            &registry,
            "urt_executor_runtimes_listening",
            "Number of runtimes currently marked as listening",
        )
        .expect("failed to register runtimes_listening");
        let executions_active = Self::register_int_gauge(
            &registry,
            "urt_executor_executions_active",
            "Active execution count currently in-flight",
        )
        .expect("failed to register executions_active");
        let stat_containers = Self::register_int_gauge(
            &registry,
            "urt_executor_stat_containers",
            "Number of containers currently present in the in-memory stats snapshot",
        )
        .expect("failed to register stat_containers");
        let runtime_cpu_percent_sum = Self::register_gauge(
            &registry,
            "urt_executor_runtime_cpu_percent_sum",
            "Sum of CPU percentages across containers in the stats snapshot",
        )
        .expect("failed to register runtime_cpu_percent_sum");
        let runtime_memory_bytes_sum = Self::register_gauge(
            &registry,
            "urt_executor_runtime_memory_bytes_sum",
            "Sum of runtime container memory usage in bytes from the stats snapshot",
        )
        .expect("failed to register runtime_memory_bytes_sum");
        let host_memory_limit_bytes = Self::register_gauge(
            &registry,
            "urt_executor_host_memory_limit_bytes",
            "Host memory limit in bytes as reported by Docker",
        )
        .expect("failed to register host_memory_limit_bytes");
        let host_memory_usage_percent = Self::register_gauge(
            &registry,
            "urt_executor_host_memory_usage_percent",
            "Host memory usage percentage as reported by URT",
        )
        .expect("failed to register host_memory_usage_percent");
        let host_cpu_usage_percent = Self::register_gauge(
            &registry,
            "urt_executor_host_cpu_usage_percent",
            "Host CPU usage percentage as reported by URT",
        )
        .expect("failed to register host_cpu_usage_percent");
        let execution_queue_depth = Self::register_int_gauge(
            &registry,
            "urt_executor_execution_queue_depth",
            "Current queued executions waiting for a concurrency slot",
        )
        .expect("failed to register execution_queue_depth");
        let runtime_create_queue_depth = Self::register_int_gauge(
            &registry,
            "urt_executor_runtime_create_queue_depth",
            "Current queued runtime creations waiting for a concurrency slot",
        )
        .expect("failed to register runtime_create_queue_depth");
        let execution_queue_capacity = Self::register_int_gauge(
            &registry,
            "urt_executor_execution_queue_capacity",
            "Configured execution concurrency capacity",
        )
        .expect("failed to register execution_queue_capacity");
        let runtime_create_queue_capacity = Self::register_int_gauge(
            &registry,
            "urt_executor_runtime_create_queue_capacity",
            "Configured runtime creation concurrency capacity",
        )
        .expect("failed to register runtime_create_queue_capacity");
        let execution_queue_wait_seconds = Self::register_histogram(
            &registry,
            "urt_executor_execution_queue_wait_seconds",
            "Time spent waiting for an execution concurrency slot",
            vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0,
            ],
        )
        .expect("failed to register execution_queue_wait_seconds");
        let runtime_create_queue_wait_seconds = Self::register_histogram(
            &registry,
            "urt_executor_runtime_create_queue_wait_seconds",
            "Time spent waiting for a runtime creation concurrency slot",
            vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0,
            ],
        )
        .expect("failed to register runtime_create_queue_wait_seconds");
        let execution_latency_seconds = Self::register_histogram_vec(
            &registry,
            "urt_executor_execution_latency_seconds",
            "Execution endpoint latency in seconds",
            &["outcome"],
            vec![
                0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 40.0,
            ],
        )
        .expect("failed to register execution_latency_seconds");
        let runtime_create_latency_seconds = Self::register_histogram_vec(
            &registry,
            "urt_executor_runtime_create_latency_seconds",
            "Runtime create endpoint latency in seconds",
            &["outcome"],
            vec![
                0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 40.0, 80.0,
            ],
        )
        .expect("failed to register runtime_create_latency_seconds");
        let keep_alive_transfers_total = Self::register_int_counter(
            &registry,
            "urt_executor_keep_alive_transfers_total",
            "Number of keep-alive ownership transfers",
        )
        .expect("failed to register keep_alive_transfers_total");
        let keep_alive_cleanup_total = Self::register_int_counter_vec(
            &registry,
            "urt_executor_keep_alive_cleanup_total",
            "Keep-alive cleanup outcomes for previous owners",
            &["outcome"],
        )
        .expect("failed to register keep_alive_cleanup_total");
        let retry_attempts_total = Self::register_int_counter_vec(
            &registry,
            "urt_executor_retry_attempts_total",
            "Retry outcomes for transient operations",
            &["operation", "outcome"],
        )
        .expect("failed to register retry_attempts_total");
        let errors_total = Self::register_int_counter_vec(
            &registry,
            "urt_executor_errors_total",
            "Executor error counts grouped by route and class",
            &["route", "class"],
        )
        .expect("failed to register errors_total");

        let network_attach_failures_total = Self::register_int_counter_vec(
            &registry,
            "urt_executor_network_attach_failures_total",
            "Number of secondary network attach failures",
            &["network"],
        )
        .expect("failed to register network_attach_failures_total");

        let readiness_wait_seconds = Self::register_histogram_vec(
            &registry,
            "urt_executor_readiness_wait_seconds",
            "Time spent waiting for a runtime to leave pending state",
            &["outcome"],
            vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0,
            ],
        )
        .expect("failed to register readiness_wait_seconds");

        let readiness_timeout_total = Self::register_int_counter(
            &registry,
            "urt_executor_readiness_timeout_total",
            "Number of readiness waits that timed out before the runtime was ready",
        )
        .expect("failed to register readiness_timeout_total");

        let runtime_deaths_total = Self::register_int_counter_vec(
            &registry,
            "urt_runtime_deaths_total",
            "Runtime container deaths observed, by exit code",
            &["exit_code"],
        )
        .expect("failed to register runtime_deaths_total");

        let runtime_quarantined_total = Self::register_int_counter(
            &registry,
            "urt_runtime_quarantined_total",
            "Runtimes placed in crash-loop quarantine",
        )
        .expect("failed to register runtime_quarantined_total");

        let runtime_unreachable_total = Self::register_int_counter(
            &registry,
            "urt_runtime_unreachable_total",
            "Executions that could not connect to their runtime",
        )
        .expect("failed to register runtime_unreachable_total");

        Self {
            registry,
            runtimes_total,
            runtimes_running,
            runtimes_pending,
            runtimes_listening,
            executions_active,
            stat_containers,
            runtime_cpu_percent_sum,
            runtime_memory_bytes_sum,
            host_memory_limit_bytes,
            host_memory_usage_percent,
            host_cpu_usage_percent,
            execution_queue_depth,
            runtime_create_queue_depth,
            execution_queue_capacity,
            runtime_create_queue_capacity,
            execution_queue_wait_seconds,
            runtime_create_queue_wait_seconds,
            execution_latency_seconds,
            runtime_create_latency_seconds,
            keep_alive_transfers_total,
            keep_alive_cleanup_total,
            retry_attempts_total,
            errors_total,
            network_attach_failures_total,
            readiness_wait_seconds,
            readiness_timeout_total,
            runtime_deaths_total,
            runtime_quarantined_total,
            runtime_unreachable_total,
        }
    }

    pub fn inc_runtime_death(&self, exit_code: Option<i64>) {
        let label = exit_code
            .map(|code| code.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        self.runtime_deaths_total
            .with_label_values(&[label.as_str()])
            .inc();
    }

    pub fn inc_runtime_quarantined(&self) {
        self.runtime_quarantined_total.inc();
    }

    pub fn inc_runtime_unreachable(&self) {
        self.runtime_unreachable_total.inc();
    }

    pub fn set_runtime_counts(&self, total: i64, running: i64, pending: i64, listening: i64) {
        self.runtimes_total.set(total.max(0));
        self.runtimes_running.set(running.max(0));
        self.runtimes_pending.set(pending.max(0));
        self.runtimes_listening.set(listening.max(0));
    }

    pub fn set_active_executions(&self, active: i64) {
        self.executions_active.set(active.max(0));
    }

    pub fn set_stats_snapshot(
        &self,
        stat_containers: i64,
        runtime_cpu_percent_sum: f64,
        runtime_memory_bytes_sum: f64,
        host_memory_limit_bytes: f64,
        host_memory_usage_percent: f64,
        host_cpu_usage_percent: f64,
    ) {
        self.stat_containers.set(stat_containers.max(0));
        self.runtime_cpu_percent_sum
            .set(runtime_cpu_percent_sum.max(0.0));
        self.runtime_memory_bytes_sum
            .set(runtime_memory_bytes_sum.max(0.0));
        self.host_memory_limit_bytes
            .set(host_memory_limit_bytes.max(0.0));
        self.host_memory_usage_percent
            .set(host_memory_usage_percent);
        self.host_cpu_usage_percent.set(host_cpu_usage_percent);
    }

    pub fn set_queue_depths(
        &self,
        execution_queue_depth: i64,
        runtime_create_queue_depth: i64,
        execution_queue_capacity: i64,
        runtime_create_queue_capacity: i64,
    ) {
        self.execution_queue_depth.set(execution_queue_depth.max(0));
        self.runtime_create_queue_depth
            .set(runtime_create_queue_depth.max(0));
        self.execution_queue_capacity
            .set(execution_queue_capacity.max(0));
        self.runtime_create_queue_capacity
            .set(runtime_create_queue_capacity.max(0));
    }

    pub fn observe_execution_queue_wait(&self, duration: Duration) {
        self.execution_queue_wait_seconds
            .observe(duration.as_secs_f64());
    }

    pub fn observe_runtime_create_queue_wait(&self, duration: Duration) {
        self.runtime_create_queue_wait_seconds
            .observe(duration.as_secs_f64());
    }

    pub fn observe_execution_latency(&self, outcome: &str, duration: Duration) {
        self.execution_latency_seconds
            .with_label_values(&[outcome])
            .observe(duration.as_secs_f64());
    }

    pub fn observe_runtime_create_latency(&self, outcome: &str, duration: Duration) {
        self.runtime_create_latency_seconds
            .with_label_values(&[outcome])
            .observe(duration.as_secs_f64());
    }

    pub fn inc_keep_alive_transfer(&self) {
        self.keep_alive_transfers_total.inc();
    }

    pub fn inc_keep_alive_cleanup(&self, outcome: &str) {
        self.keep_alive_cleanup_total
            .with_label_values(&[outcome])
            .inc();
    }

    pub fn inc_retry(&self, operation: &str, outcome: &str) {
        self.retry_attempts_total
            .with_label_values(&[operation, outcome])
            .inc();
    }

    pub fn inc_error_class(&self, route: &str, class: &str) {
        self.errors_total.with_label_values(&[route, class]).inc();
    }

    pub fn inc_network_attach_failure(&self, network: &str, _container: &str) {
        self.network_attach_failures_total
            .with_label_values(&[network])
            .inc();
    }

    pub fn observe_readiness_wait(&self, outcome: &str, duration: Duration) {
        self.readiness_wait_seconds
            .with_label_values(&[outcome])
            .observe(duration.as_secs_f64());
    }

    pub fn inc_readiness_timeout(&self) {
        self.readiness_timeout_total.inc();
    }

    pub fn encode(&self) -> Result<(String, Vec<u8>), String> {
        let metric_families = self.registry.gather();
        let encoder = TextEncoder::new();
        let mut payload = Vec::new();
        encoder
            .encode(&metric_families, &mut payload)
            .map_err(|e| e.to_string())?;
        Ok((encoder.format_type().to_string(), payload))
    }
}

static METRICS: OnceLock<ExecutorMetrics> = OnceLock::new();

pub fn metrics() -> &'static ExecutorMetrics {
    METRICS.get_or_init(ExecutorMetrics::new)
}
