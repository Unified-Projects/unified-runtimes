//! Watchdog for runtimes that start but never listen
//!
//! A container can report `running` and still be unreachable, most commonly
//! when its server binds to a per-container address rather than the wildcard
//! address, or when the code it was given is not a build at all. The executor
//! only sets `initialised` once a runtime has been observed listening, and this
//! task is what observes it: it probes every running runtime that has not
//! listened yet, records the ones that answer, and gives up on the ones still
//! silent at the end of their startup window.
//!
//! A runtime it gives up on is marked `failed`, which is visible in
//! `GET /v1/runtimes`, and removed on the following cycle so the next request
//! for that runtime ID creates a fresh one. The cycle is deliberately short:
//! the hourly maintenance sweep is far too coarse to sit in front of a
//! function that is returning errors.

use crate::docker::DockerManager;
use crate::runtime::liveness::{release_runtime, OnContainerFailure, RuntimeTeardown};
use crate::runtime::{
    is_runtime_listening, KeepAliveRegistry, Runtime, RuntimeConcurrency, RuntimeHealth,
    RuntimeRegistry, RUNTIME_PORT,
};
use futures_util::stream::{self, StreamExt};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{debug, info, warn};

/// How often the registry is swept. Short enough that a runtime which never
/// comes up is out of the way well inside a user's patience.
const SCAN_INTERVAL: Duration = Duration::from_secs(5);

/// How long a single probe waits for the runtime to accept a connection. A
/// listening runtime accepts immediately even when it is busy, because the
/// kernel completes the handshake from the accept backlog.
const PROBE_TIMEOUT: Duration = Duration::from_millis(250);

/// Probes issued at once, so a host with many silent runtimes still finishes a
/// sweep well inside the scan interval.
const PROBE_CONCURRENCY: usize = 8;

/// What the watchdog needs to see and act on runtime state.
#[derive(Clone)]
pub struct ListeningWatchHandles {
    pub docker: Arc<DockerManager>,
    pub registry: RuntimeRegistry,
    pub keep_alive_registry: KeepAliveRegistry,
    pub runtime_concurrency: RuntimeConcurrency,
    /// Readiness notifiers, so reaping a failed runtime wakes anyone parked on
    /// it instead of leaving them to their own deadlines.
    pub readiness: Arc<dashmap::DashMap<String, Arc<tokio::sync::Notify>>>,
    /// Health markers, cleared alongside the entry.
    pub health: RuntimeHealth,
}

/// Worth probing: up, not pending, not failed, and not yet known to listen.
fn is_probe_candidate(runtime: &Runtime) -> bool {
    runtime.is_running() && !runtime.is_listening()
}

/// Probe every runtime that has not listened yet, record the ones that answer,
/// and mark the ones that have run out of startup window as failed.
///
/// Returns the names newly marked failed. Needs nothing but the registry, so a
/// caller can drive one sweep directly.
pub async fn sweep_listening_state(registry: &RuntimeRegistry) -> Vec<String> {
    let candidates: Vec<Runtime> = registry
        .list()
        .await
        .into_iter()
        .filter(is_probe_candidate)
        .collect();

    if candidates.is_empty() {
        return Vec::new();
    }

    let probed: Vec<(Runtime, bool)> = stream::iter(candidates)
        .map(|runtime| async move {
            let listening = is_runtime_listening(&runtime.name, PROBE_TIMEOUT).await;
            (runtime, listening)
        })
        .buffer_unordered(PROBE_CONCURRENCY)
        .collect()
        .await;

    let mut failed = Vec::new();

    for (runtime, listening) in probed {
        if listening {
            if registry.set_listening(&runtime.name).await.is_ok() {
                debug!(
                    "Runtime {} is listening on port {}",
                    runtime.name, RUNTIME_PORT
                );
            }
            continue;
        }

        if !runtime.missed_startup_window() {
            continue;
        }

        // The runtime may have been removed or have started listening between
        // the sweep's snapshot and here; `mark_failed` leaves both alone.
        match registry.mark_failed(&runtime.name).await {
            Ok(marked) if marked.is_failed() => {
                warn!(
                    runtime = %runtime.name,
                    runtime_id = %runtime.runtime_id,
                    image = %runtime.image,
                    elapsed_seconds = runtime.age_seconds(),
                    startup_timeout_seconds = runtime.startup_timeout,
                    "Runtime {} on image {} has been running for {}s without listening on port \
                     {} and is past its {}s startup window; marking it failed. It is most likely \
                     bound to its container address instead of 0.0.0.0, or was created from a \
                     source archive that is not a build.",
                    runtime.name,
                    runtime.image,
                    runtime.age_seconds(),
                    RUNTIME_PORT,
                    runtime.startup_timeout,
                );
                failed.push(runtime.name.clone());
            }
            _ => {}
        }
    }

    failed
}

/// Remove the runtimes the previous sweep gave up on, along with their
/// containers, so the next request for that runtime ID builds a fresh one.
///
/// Returns the number removed.
pub async fn reap_failed_runtimes(targets: &RuntimeTeardown<'_>) -> usize {
    let failed: Vec<Runtime> = targets
        .registry
        .list()
        .await
        .into_iter()
        .filter(|runtime| runtime.is_failed())
        .collect();

    let mut reaped = 0;

    for runtime in failed {
        info!(
            "Removing failed runtime {} (never listened on port {})",
            runtime.name, RUNTIME_PORT
        );

        // The same teardown the execution path uses for a dead runtime, so a
        // failed one releases its keep-alive ownership, readiness waiters,
        // working directory and health markers alongside its container.
        if release_runtime(targets, &runtime.name, true, OnContainerFailure::Retain).await {
            reaped += 1;
        }
    }

    reaped
}

/// Run the listening watchdog until shutdown.
pub async fn run_listening_watch(
    handles: ListeningWatchHandles,
    mut shutdown: watch::Receiver<bool>,
) {
    let ListeningWatchHandles {
        docker,
        registry,
        keep_alive_registry,
        runtime_concurrency,
        readiness,
        health,
    } = handles;

    let teardown = RuntimeTeardown {
        docker: &docker,
        registry: &registry,
        keep_alive_registry: &keep_alive_registry,
        readiness: &readiness,
        health: &health,
    };

    debug!(
        "Starting listening watchdog (scan interval: {}s)",
        SCAN_INTERVAL.as_secs()
    );

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    debug!("Listening watchdog shutting down");
                    break;
                }
            }
            _ = tokio::time::sleep(SCAN_INTERVAL) => {
                // Reap before sweeping, so a runtime marked failed on the last
                // cycle is visible as failed for one full cycle before it goes.
                reap_failed_runtimes(&teardown).await;
                sweep_listening_state(&registry).await;

                let live: HashSet<String> = registry
                    .list()
                    .await
                    .into_iter()
                    .map(|runtime| runtime.name)
                    .collect();
                runtime_concurrency.retain_known(&live);
            }
        }
    }

    debug!("Listening watchdog stopped");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn running(name: &str, age_secs: f64, startup_timeout: u64) -> Runtime {
        let mut runtime = Runtime::new(name, "executor-a", "node:v5", "v5", None);
        runtime.startup_timeout = startup_timeout;
        runtime.mark_running("running");
        runtime.created -= age_secs;
        runtime
    }

    #[test]
    fn probes_running_runtimes_that_have_not_listened() {
        assert!(is_probe_candidate(&running("rt-silent", 5.0, 60)));
    }

    #[test]
    fn does_not_probe_listening_pending_or_stopped_runtimes() {
        let mut listening = running("rt-listening", 300.0, 60);
        listening.set_listening();

        let pending = Runtime::new("rt-pending", "executor-a", "node:v5", "v5", None);

        let mut exited = running("rt-exited", 300.0, 60);
        exited.status = "exited".to_string();

        let mut failed = running("rt-failed", 300.0, 60);
        failed.mark_failed();

        for runtime in [listening, pending, exited, failed] {
            assert!(!is_probe_candidate(&runtime), "{}", runtime.name);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn marks_a_runtime_that_never_listened_as_failed() {
        let registry = RuntimeRegistry::new();
        let runtime = running("rt-silent", 300.0, 60);
        let name = runtime.name.clone();
        registry.insert(runtime).await.unwrap();

        let failed = sweep_listening_state(&registry).await;

        assert_eq!(failed, vec![name.clone()]);

        let after = registry.get(&name).await.unwrap();
        assert!(after.is_failed());
        assert_eq!(after.initialised, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn leaves_a_runtime_inside_its_startup_window_alone() {
        let registry = RuntimeRegistry::new();
        let runtime = running("rt-young", 5.0, 60);
        let name = runtime.name.clone();
        registry.insert(runtime).await.unwrap();

        assert!(sweep_listening_state(&registry).await.is_empty());

        let after = registry.get(&name).await.unwrap();
        assert!(after.is_running());
        assert_eq!(after.initialised, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn honours_a_longer_per_runtime_startup_window() {
        let registry = RuntimeRegistry::new();
        // Well past the default window, still inside its own.
        let runtime = running("rt-slow-builder", 120.0, 600);
        let name = runtime.name.clone();
        registry.insert(runtime).await.unwrap();

        assert!(sweep_listening_state(&registry).await.is_empty());
        assert!(!registry.get(&name).await.unwrap().is_failed());
    }

    #[tokio::test(start_paused = true)]
    async fn a_runtime_is_only_reported_once() {
        let registry = RuntimeRegistry::new();
        registry
            .insert(running("rt-silent", 300.0, 60))
            .await
            .unwrap();

        assert_eq!(sweep_listening_state(&registry).await.len(), 1);
        // Now failed, so no longer a probe candidate.
        assert!(sweep_listening_state(&registry).await.is_empty());
    }
}
