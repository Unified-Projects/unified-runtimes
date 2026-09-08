//! Dead-runtime handling shared by the execution path and the Docker events task.
//!
//! Two observations feed in: an execution that could not connect to its
//! runtime, and a `die` event from the Docker daemon. Both end up here, take
//! the runtime's single-flight lock, and apply the same policy:
//!
//! 1. the death is recorded once (`observe_death`), which may quarantine the
//!    runtime;
//! 2. if Docker's own restart policy will bring the container back, the
//!    registry entry is kept and the execution path waits for the port;
//! 3. otherwise the container, registry entry and working directory are
//!    removed so the next execution that supplies an image recreates it, and
//!    one that does not gets a fast 404.

use crate::docker::container::ContainerInfo;
use crate::error::{ExecutorError, QuarantineDetail};
use crate::platform;
use crate::routes::AppState;
use crate::runtime::health::{ContainerObservation, DeathOutcome, QuarantineState};
use crate::runtime::{wait_for_runtime_port, RuntimeHealth, RuntimeRegistry};
use crate::telemetry::metrics;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::Instant;
use tracing::{debug, info, warn};

/// How long requests fail fast after a runtime is found unreachable while its
/// container is being checked.
const UNREACHABLE_MARKER_TTL: Duration = Duration::from_secs(10);

/// Age below which a cached inspect result is reused by concurrent callers.
const LIVENESS_CACHE_TTL: Duration = Duration::from_secs(2);

/// Longest the execution path waits for Docker to restart a runtime.
pub const RESTART_WAIT_MAX: Duration = Duration::from_secs(30);

/// Longest the execution path waits for a container that Docker reports as
/// running to answer on its port after a refused connection.
const RUNNING_PROBE_MAX: Duration = Duration::from_secs(2);

const RUNTIME_PORT: u16 = 3000;

/// What the execution path should do after an unreachable runtime was checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryOutcome {
    /// The runtime answers on its port again; retry the execution once.
    Ready,
    /// The registry entry is gone; resolve the runtime again so an execution
    /// carrying an image recreates it and one without gets a 404.
    Removed,
    /// The container is up but does not accept connections; give up.
    Unresponsive,
    /// The runtime crashed too often and is quarantined.
    Quarantined(QuarantineDetail),
}

/// What handling a reported container death did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeathHandling {
    Quarantined(QuarantineDetail),
    /// Docker will restart the container; the entry stays and the next
    /// execution probes the port again.
    AwaitingDockerRestart,
    /// Container, entry and working directory were removed.
    Removed,
    Ignored(&'static str),
}

fn unix_now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Record a death against the registry entry and the health tracker.
///
/// Only the transition out of `running` counts, so the same death reported by
/// the Docker events task and by an execution is recorded once. When the death
/// tips the runtime into quarantine the registry entry is marked accordingly.
/// Returns `None` when there was nothing new to record.
pub async fn observe_death(
    registry: &RuntimeRegistry,
    health: &RuntimeHealth,
    name: &str,
    exit_code: Option<i64>,
) -> Option<DeathOutcome> {
    let (runtime, was_running) = registry.mark_dead(name, "exited", exit_code).await?;
    if !was_running {
        return None;
    }

    let outcome = health.record_death(name, &runtime.runtime_id, exit_code);
    match &outcome {
        DeathOutcome::Recorded {
            deaths_in_window,
            restart_delay,
        } => {
            warn!(
                runtime = %name,
                runtime_id = %runtime.runtime_id,
                exit_code = ?exit_code,
                deaths_in_window,
                window_secs = health.config().crash_loop_window.as_secs(),
                restart_backoff_ms = restart_delay.as_millis() as u64,
                "Runtime {} died (exit code {})",
                name,
                exit_code
                    .map(|code| code.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            );
        }
        DeathOutcome::Quarantined(detail) => {
            let until = unix_now() + detail.retry_after_secs as f64;
            registry
                .mark_quarantined(name, until, detail.last_exit_code)
                .await;
            warn!(
                runtime = %name,
                runtime_id = %runtime.runtime_id,
                exit_code = ?exit_code,
                deaths = detail.deaths,
                expires_at = %detail.expires_at,
                "Runtime {} quarantined after {} deaths in {}s; executions and creates refused until {}",
                name,
                detail.deaths,
                health.config().crash_loop_window.as_secs(),
                detail.expires_at
            );
        }
    }
    Some(outcome)
}

/// Inspect the container behind `name`, reusing a result another caller
/// fetched within the last two seconds.
async fn observe_container(
    state: &AppState,
    name: &str,
    cache: &mut crate::runtime::health::LivenessCache,
) -> Option<ContainerObservation> {
    if let Some(observation) = cache.fresh(LIVENESS_CACHE_TTL) {
        return Some(observation.clone());
    }

    let observation = match state.docker.inspect_container(name).await {
        Ok(info) => ContainerObservation::Found(Box::new(info)),
        Err(ExecutorError::RuntimeNotFound) => ContainerObservation::Gone,
        Err(error) => {
            warn!(
                runtime = %name,
                "Could not inspect runtime container while checking liveness: {}",
                error
            );
            return None;
        }
    };
    cache.store(observation.clone());
    Some(observation)
}

/// Remove everything a dead runtime owns.
async fn remove_dead_runtime(state: &AppState, name: &str, remove_container: bool) {
    if remove_container {
        match state.docker.remove_container(name, true).await {
            Ok(()) | Err(ExecutorError::RuntimeNotFound) => {}
            Err(error) => warn!(
                runtime = %name,
                "Failed to remove dead runtime container: {}",
                error
            ),
        }
    }

    if let Some(runtime) = state.registry.get(name).await {
        if let Some(ref keep_alive_id) = runtime.keep_alive_id {
            state.keep_alive_registry.unregister(keep_alive_id, name);
        }
    }

    state.readiness_notify_and_remove(name);
    state.registry.remove(name).await;
    tokio::fs::remove_dir_all(platform::temp_dir().join(name))
        .await
        .ok();
    state.health.clear_unreachable(name);
    state.health.invalidate_liveness(name);

    info!(
        runtime = %name,
        "Removed dead runtime; the next execution with an image recreates it"
    );
}

/// Docker-side part of a quarantine: stop the restart loop by removing the
/// container and drop the working directory. The registry entry stays as a
/// visible record until the quarantine expires.
async fn quarantine_runtime(state: &AppState, name: &str) {
    match state.docker.remove_container(name, true).await {
        Ok(()) | Err(ExecutorError::RuntimeNotFound) => {}
        Err(error) => warn!(
            runtime = %name,
            "Failed to remove quarantined runtime container: {}",
            error
        ),
    }
    state.readiness_notify_and_remove(name);
    tokio::fs::remove_dir_all(platform::temp_dir().join(name))
        .await
        .ok();
    state.health.clear_unreachable(name);
    state.health.invalidate_liveness(name);
}

/// Wait for a container that Docker is restarting to answer on its port.
async fn wait_for_docker_restart(
    state: &AppState,
    name: &str,
    deadline: Instant,
) -> RecoveryOutcome {
    let now = Instant::now();
    let bound = deadline.min(now + RESTART_WAIT_MAX);
    let wait = bound.saturating_duration_since(now);

    state.registry.set_status(name, "restarting").await;
    state
        .health
        .mark_unreachable(name, wait.max(Duration::from_millis(100)));

    info!(
        runtime = %name,
        wait_ms = wait.as_millis() as u64,
        "Waiting for Docker to restart runtime"
    );

    probe_port(state, name, wait).await
}

/// Probe the runtime port for up to `wait` and report whether executions can
/// resume.
async fn probe_port(state: &AppState, name: &str, wait: Duration) -> RecoveryOutcome {
    if wait.is_zero() {
        return RecoveryOutcome::Unresponsive;
    }
    match wait_for_runtime_port(name, RUNTIME_PORT, wait).await {
        Ok(()) => {
            state.registry.set_listening(name).await.ok();
            state.health.clear_unreachable(name);
            state.health.invalidate_liveness(name);
            info!(runtime = %name, "Runtime is listening again");
            RecoveryOutcome::Ready
        }
        Err(_) => {
            warn!(
                runtime = %name,
                waited_ms = wait.as_millis() as u64,
                "Runtime container is up but did not start listening"
            );
            RecoveryOutcome::Unresponsive
        }
    }
}

/// Handle an execution that could not connect to its runtime.
///
/// Concurrent callers for the same runtime serialise on its liveness lock and
/// share one Docker inspect; the first to arrive does the work and the rest
/// see its outcome. `deadline` bounds any wait for a Docker restart.
pub async fn recover_unreachable(
    state: &AppState,
    name: &str,
    deadline: Instant,
) -> RecoveryOutcome {
    metrics().inc_runtime_unreachable();
    state.health.mark_unreachable(name, UNREACHABLE_MARKER_TTL);

    let flight = state.health.liveness_flight(name);
    let mut cache = flight.lock().await;

    let Some(runtime) = state.registry.get(name).await else {
        state.health.clear_unreachable(name);
        return RecoveryOutcome::Removed;
    };
    if runtime.is_quarantined() {
        if let Some(detail) = state.health.active_quarantine(name) {
            return RecoveryOutcome::Quarantined(detail);
        }
    }

    let Some(observation) = observe_container(state, name, &mut cache).await else {
        return RecoveryOutcome::Unresponsive;
    };

    match observation {
        ContainerObservation::Gone => {
            debug!(runtime = %name, "Runtime container no longer exists");
            remove_dead_runtime(state, name, false).await;
            RecoveryOutcome::Removed
        }
        ContainerObservation::Found(info) => {
            recover_from_inspect(state, name, &runtime, *info, deadline).await
        }
    }
}

async fn recover_from_inspect(
    state: &AppState,
    name: &str,
    runtime: &crate::runtime::Runtime,
    info: ContainerInfo,
    deadline: Instant,
) -> RecoveryOutcome {
    let state_lower = info.state.to_ascii_lowercase();

    if state_lower == "running" {
        let restarted_since_sync = info.restart_count > runtime.restart_count;
        if restarted_since_sync && !state.config.docker_events {
            // Without the events task nobody else records the death that led
            // to this restart.
            if let Some(DeathOutcome::Quarantined(detail)) =
                observe_death(&state.registry, &state.health, name, None).await
            {
                quarantine_runtime(state, name).await;
                return RecoveryOutcome::Quarantined(detail);
            }
        }
        state.registry.apply_container_state(name, &info);
        let wait = deadline
            .saturating_duration_since(Instant::now())
            .min(RUNNING_PROBE_MAX);
        return probe_port(state, name, wait).await;
    }

    if state_lower == "restarting" {
        if let Some(DeathOutcome::Quarantined(detail)) =
            observe_death(&state.registry, &state.health, name, info.exit_code).await
        {
            quarantine_runtime(state, name).await;
            return RecoveryOutcome::Quarantined(detail);
        }
        return wait_for_docker_restart(state, name, deadline).await;
    }

    if state.docker.was_removed_deliberately(name) {
        debug!(runtime = %name, "Runtime container was stopped by this executor");
        remove_dead_runtime(state, name, false).await;
        return RecoveryOutcome::Removed;
    }

    let will_restart = info.docker_will_restart();
    if info.oom_killed {
        warn!(runtime = %name, "Runtime container was killed by the OOM killer");
    }
    match observe_death(&state.registry, &state.health, name, info.exit_code).await {
        Some(DeathOutcome::Quarantined(detail)) => {
            quarantine_runtime(state, name).await;
            RecoveryOutcome::Quarantined(detail)
        }
        _ if will_restart => wait_for_docker_restart(state, name, deadline).await,
        _ => {
            remove_dead_runtime(state, name, true).await;
            RecoveryOutcome::Removed
        }
    }
}

/// Handle a container death reported by the Docker events task.
pub async fn handle_container_death(
    state: &AppState,
    name: &str,
    exit_code: Option<i64>,
    oom_killed: bool,
) -> DeathHandling {
    if state.docker.was_removed_deliberately(name) {
        return DeathHandling::Ignored("stopped by this executor");
    }
    let Some(runtime) = state.registry.get(name).await else {
        return DeathHandling::Ignored("not in registry");
    };
    if runtime.is_pending() {
        return DeathHandling::Ignored("create in progress");
    }
    if runtime.is_quarantined() {
        return DeathHandling::Ignored("already quarantined");
    }

    let flight = state.health.liveness_flight(name);
    let mut cache = flight.lock().await;

    if oom_killed {
        warn!(runtime = %name, "Runtime container was killed by the OOM killer");
    }

    let Some(outcome) = observe_death(&state.registry, &state.health, name, exit_code).await else {
        return DeathHandling::Ignored("death already recorded");
    };

    if let DeathOutcome::Quarantined(detail) = outcome {
        quarantine_runtime(state, name).await;
        return DeathHandling::Quarantined(detail);
    }

    // The entry is marked dead so nothing dials it as if it were listening.
    // Whether it stays depends on Docker's restart policy for the container.
    cache.checked_at = None;
    let Some(observation) = observe_container(state, name, &mut cache).await else {
        return DeathHandling::AwaitingDockerRestart;
    };

    match observation {
        ContainerObservation::Gone => {
            remove_dead_runtime(state, name, false).await;
            DeathHandling::Removed
        }
        ContainerObservation::Found(info) => {
            let state_lower = info.state.to_ascii_lowercase();
            if state_lower == "running" || state_lower == "restarting" || info.docker_will_restart()
            {
                state.registry.apply_container_state(name, &info);
                info!(
                    runtime = %name,
                    container_state = %info.state,
                    restart_count = info.restart_count,
                    "Docker is restarting the runtime; port will be probed on the next execution"
                );
                DeathHandling::AwaitingDockerRestart
            } else {
                remove_dead_runtime(state, name, true).await;
                DeathHandling::Removed
            }
        }
    }
}

/// Handle a `destroy` event: the container is gone, so an entry that still
/// points at it is dropped. Deaths are counted on `die`, not here.
pub async fn handle_container_destroyed(state: &AppState, name: &str) -> DeathHandling {
    if state.docker.was_removed_deliberately(name) {
        return DeathHandling::Ignored("removed by this executor");
    }
    let Some(runtime) = state.registry.get(name).await else {
        return DeathHandling::Ignored("not in registry");
    };
    if runtime.is_pending() || runtime.is_quarantined() {
        return DeathHandling::Ignored("entry owned by create or quarantine");
    }

    let flight = state.health.liveness_flight(name);
    let _cache = flight.lock().await;
    warn!(
        runtime = %name,
        "Runtime container was destroyed outside the executor; dropping its entry"
    );
    remove_dead_runtime(state, name, false).await;
    DeathHandling::Removed
}

/// The active quarantine for `name`, clearing the registry record when the
/// quarantine has lapsed.
pub async fn quarantine_for(state: &AppState, name: &str) -> Option<QuarantineDetail> {
    match state.health.quarantine_state(name) {
        QuarantineState::Active(detail) => Some(detail),
        QuarantineState::Expired => {
            release_quarantined_entry(&state.registry, name).await;
            None
        }
        QuarantineState::None => None,
    }
}

async fn release_quarantined_entry(registry: &RuntimeRegistry, name: &str) {
    if registry.remove_if_quarantined(name).await.is_some() {
        info!(runtime = %name, "Quarantine expired; runtime may be created again");
    }
}

/// Drop registry entries whose quarantine has lapsed. Run by maintenance so a
/// runtime nobody asks for again does not stay listed forever.
pub async fn sweep_expired_quarantines(
    registry: &RuntimeRegistry,
    health: &RuntimeHealth,
) -> usize {
    let mut released = 0;
    for name in health.quarantined_names() {
        if health.quarantine_state(&name) == QuarantineState::Expired {
            release_quarantined_entry(registry, &name).await;
            released += 1;
        }
    }
    released
}
