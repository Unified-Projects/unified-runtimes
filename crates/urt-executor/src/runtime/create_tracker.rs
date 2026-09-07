//! Tracking for runtime creates that are currently building.
//!
//! `create_runtime` registers a build here for its whole duration and runs the
//! build itself on a detached task, so the work is independent of the HTTP
//! handler that started it. Two behaviours depend on that record:
//!
//! - a second create for the same runtime joins the build already running
//!   instead of being rejected with `RuntimeConflict`;
//! - maintenance can tell a pending registry entry that still has a build behind
//!   it from one that was orphaned, and only reap the latter.
//!
//! The slot is released by `CreateSlot`, whose `Drop` publishes a failure when
//! the build task ends without producing an outcome. No caller can therefore be
//! parked on a slot that nothing will resolve.

use crate::error::{ExecutorError, Result};
use crate::routes::runtimes::CreateRuntimeResponse;
use dashmap::DashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Instant;
use tracing::{info, warn};

/// Outcome of a finished create, shared by every caller that joined it.
type SharedOutcome = Arc<Result<CreateRuntimeResponse>>;

#[derive(Clone)]
enum CreateState {
    InFlight,
    Finished(SharedOutcome),
}

struct InFlightCreate {
    outcome: tokio::sync::watch::Sender<CreateState>,
    started_at: Instant,
}

/// Registry of runtime creates that are currently building, keyed by the full
/// container name (`{hostname}-{runtimeId}`).
#[derive(Clone, Default)]
pub struct CreateTracker {
    inner: Arc<DashMap<String, Arc<InFlightCreate>>>,
}

impl std::fmt::Debug for CreateTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateTracker")
            .field("in_flight", &self.inner.len())
            .finish()
    }
}

impl CreateTracker {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
        }
    }

    /// Whether a build for `name` is currently running.
    pub fn is_in_flight(&self, name: &str) -> bool {
        self.inner.contains_key(name)
    }

    /// Seconds since the build for `name` started, or `None` when no build is
    /// running for that name.
    pub fn in_flight_secs(&self, name: &str) -> Option<u64> {
        self.inner
            .get(name)
            .map(|entry| entry.started_at.elapsed().as_secs())
    }

    /// Claim the slot for `name`, or hand back a join handle when another build
    /// already owns it. The claim is atomic against concurrent callers.
    pub(crate) fn begin(&self, name: &str) -> BeginCreate {
        use dashmap::mapref::entry::Entry;

        match self.inner.entry(name.to_string()) {
            Entry::Occupied(entry) => {
                let shared = entry.get().clone();
                BeginCreate::Joined(CreateJoin::new(shared))
            }
            Entry::Vacant(entry) => {
                let (outcome, _) = tokio::sync::watch::channel(CreateState::InFlight);
                let shared = Arc::new(InFlightCreate {
                    outcome,
                    started_at: Instant::now(),
                });
                entry.insert(Arc::clone(&shared));
                BeginCreate::Started(CreateSlot {
                    tracker: self.clone(),
                    name: name.to_string(),
                    shared,
                    published: false,
                })
            }
        }
    }
}

pub(crate) enum BeginCreate {
    /// The caller owns the build and must run it.
    Started(CreateSlot),
    /// Another build for the same name is already running.
    Joined(CreateJoin),
}

/// Ownership token for an in-flight build. Publishing the outcome releases the
/// slot; dropping without publishing releases it with a failure.
pub(crate) struct CreateSlot {
    tracker: CreateTracker,
    name: String,
    shared: Arc<InFlightCreate>,
    published: bool,
}

impl CreateSlot {
    /// A handle that resolves when this build publishes its outcome.
    pub(crate) fn join(&self) -> CreateJoin {
        CreateJoin::new(Arc::clone(&self.shared))
    }

    /// Publish the build outcome and release the slot.
    pub(crate) fn finish(mut self, outcome: Result<CreateRuntimeResponse>) {
        self.publish(Arc::new(outcome));
    }

    fn publish(&mut self, outcome: SharedOutcome) {
        if self.published {
            return;
        }
        self.published = true;
        // Set the value before releasing the slot so a caller that subscribed
        // just before the removal still observes the result.
        self.shared
            .outcome
            .send_replace(CreateState::Finished(outcome));
        self.tracker.inner.remove(&self.name);
    }
}

impl Drop for CreateSlot {
    fn drop(&mut self) {
        if self.published {
            return;
        }

        warn!(
            runtime = %self.name,
            "Runtime create task ended without an outcome; releasing the create slot"
        );
        self.publish(Arc::new(Err(ExecutorError::RuntimeFailed(
            "Runtime create task ended before completing".to_string(),
        ))));
    }
}

/// Handle held by a caller waiting on a build it does not own.
pub(crate) struct CreateJoin {
    // Keeps the sender alive so `changed()` cannot fail while this handle
    // exists; the outcome is always published before the sender is dropped.
    _shared: Arc<InFlightCreate>,
    receiver: tokio::sync::watch::Receiver<CreateState>,
}

impl CreateJoin {
    fn new(shared: Arc<InFlightCreate>) -> Self {
        let receiver = shared.outcome.subscribe();
        Self {
            _shared: shared,
            receiver,
        }
    }

    /// Wait for the build to publish its outcome.
    pub(crate) async fn outcome(mut self) -> Result<CreateRuntimeResponse> {
        loop {
            let finished = match &*self.receiver.borrow_and_update() {
                CreateState::Finished(outcome) => Some(Arc::clone(outcome)),
                CreateState::InFlight => None,
            };

            if let Some(outcome) = finished {
                return (*outcome).clone();
            }

            if self.receiver.changed().await.is_err() {
                // Unreachable while `_shared` holds the sender alive, but a
                // definite error beats parking forever if that ever changes.
                return Err(ExecutorError::RuntimeFailed(
                    "Runtime create ended without publishing an outcome".to_string(),
                ));
            }
        }
    }
}

/// Run `build` on a detached task keyed by `full_name`, or join the build
/// already running for that name.
///
/// The returned future only observes the build; dropping it (an axum handler
/// whose client disconnected) does not cancel the work. The build therefore
/// always runs to the point where it resolves its own registry entry, and a
/// later caller can adopt the result instead of hitting the conflict guard.
pub(crate) async fn spawn_or_join<F>(
    tracker: &CreateTracker,
    full_name: &str,
    build: F,
) -> Result<CreateRuntimeResponse>
where
    F: Future<Output = Result<CreateRuntimeResponse>> + Send + 'static,
{
    let join = match tracker.begin(full_name) {
        BeginCreate::Joined(join) => {
            info!(
                runtime = %full_name,
                in_flight_secs = tracker.in_flight_secs(full_name).unwrap_or(0),
                "Joining runtime create already in flight"
            );
            join
        }
        BeginCreate::Started(slot) => {
            let join = slot.join();
            let name = full_name.to_string();
            tokio::spawn(async move {
                let outcome = build.await;
                if let Err(error) = &outcome {
                    warn!(runtime = %name, "Runtime create failed: {}", error);
                }
                slot.finish(outcome);
            });
            join
        }
    };

    join.outcome().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{Runtime, RuntimeRegistry};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    fn response() -> CreateRuntimeResponse {
        CreateRuntimeResponse {
            output: vec![],
            path: None,
            size: None,
            start_time: 0.0,
            duration: 0.0,
        }
    }

    /// Model of the conflict guard at the top of `create_runtime`: a create for
    /// a runtime that already has a registry entry is refused.
    async fn guarded_build(
        registry: RuntimeRegistry,
        name: &str,
        hostname: &str,
    ) -> Result<CreateRuntimeResponse> {
        if registry.exists(name).await {
            return Err(ExecutorError::RuntimeConflict);
        }
        registry
            .insert(Runtime::new("wedge", hostname, "img", "v5", None))
            .await?;
        Ok(response())
    }

    #[tokio::test]
    async fn cancelled_caller_does_not_abort_the_build() {
        let tracker = CreateTracker::new();
        let registry = RuntimeRegistry::new();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();

        let build_registry = registry.clone();
        let build = async move {
            // Stands in for the source download: the registry entry is already
            // pending at this point, and this is where a disconnecting client
            // used to abort the handler future.
            build_registry
                .insert(Runtime::new("wedge", "exec", "img", "v5", None))
                .await?;
            let _ = release_rx.await;
            let mut running = build_registry.get("exec-wedge").await.unwrap();
            running.mark_running("running");
            build_registry.update(running).await?;
            Ok(response())
        };

        // The caller gives up while the build is still downloading.
        let caller = tokio::spawn({
            let tracker = tracker.clone();
            async move { spawn_or_join(&tracker, "exec-wedge", build).await }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(tracker.is_in_flight("exec-wedge"));
        caller.abort();
        let _ = caller.await;

        // The build keeps going and resolves the entry it owns.
        release_tx.send(()).unwrap();
        for _ in 0..200 {
            if !tracker.is_in_flight("exec-wedge") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        assert!(
            !tracker.is_in_flight("exec-wedge"),
            "the detached build must finish and release its slot"
        );
        let entry = registry.get("exec-wedge").await.expect("entry must exist");
        assert!(
            !entry.is_pending(),
            "no pending entry may outlive the build that would resolve it"
        );
    }

    #[tokio::test]
    async fn cancelled_create_leaves_no_pending_entry_when_the_build_fails() {
        let tracker = CreateTracker::new();
        let registry = RuntimeRegistry::new();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();

        let build_registry = registry.clone();
        let build = async move {
            build_registry
                .insert(Runtime::new("wedge", "exec", "img", "v5", None))
                .await?;
            let _ = release_rx.await;
            // Download failure: the build cleans up the entry it inserted.
            build_registry.remove("exec-wedge").await;
            Err(ExecutorError::RuntimeFailed("download failed".to_string()))
        };

        let caller = tokio::spawn({
            let tracker = tracker.clone();
            async move { spawn_or_join(&tracker, "exec-wedge", build).await }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        caller.abort();
        let _ = caller.await;

        release_tx.send(()).unwrap();
        for _ in 0..200 {
            if !tracker.is_in_flight("exec-wedge") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        assert!(
            registry.get("exec-wedge").await.is_none(),
            "a failed build must leave no registry entry behind"
        );

        // The retry is free to start a fresh build: nothing blocks it.
        let outcome = spawn_or_join(&tracker, "exec-wedge", {
            let registry = registry.clone();
            async move { guarded_build(registry, "exec-wedge", "exec").await }
        })
        .await;

        assert!(
            outcome.is_ok(),
            "retry after a cancelled create must get past the conflict guard, got {:?}",
            outcome.err()
        );
    }

    #[tokio::test]
    async fn retry_during_an_in_flight_build_joins_it_instead_of_conflicting() {
        let tracker = CreateTracker::new();
        let registry = RuntimeRegistry::new();
        let builds = Arc::new(AtomicUsize::new(0));
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();

        let first_builds = Arc::clone(&builds);
        let first_registry = registry.clone();
        let first = tokio::spawn({
            let tracker = tracker.clone();
            async move {
                spawn_or_join(&tracker, "exec-wedge", async move {
                    first_builds.fetch_add(1, Ordering::SeqCst);
                    first_registry
                        .insert(Runtime::new("wedge", "exec", "img", "v5", None))
                        .await?;
                    let _ = release_rx.await;
                    let mut running = first_registry.get("exec-wedge").await.unwrap();
                    running.mark_running("running");
                    first_registry.update(running).await?;
                    Ok(response())
                })
                .await
            }
        });

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(tracker.is_in_flight("exec-wedge"));

        // The caller retried after giving up on the first attempt. Without the
        // join it would hit the conflict guard against its own pending entry.
        let retry_builds = Arc::clone(&builds);
        let retry_registry = registry.clone();
        let retry = tokio::spawn({
            let tracker = tracker.clone();
            async move {
                spawn_or_join(&tracker, "exec-wedge", async move {
                    retry_builds.fetch_add(1, Ordering::SeqCst);
                    guarded_build(retry_registry, "exec-wedge", "exec").await
                })
                .await
            }
        });

        tokio::time::sleep(Duration::from_millis(20)).await;
        release_tx.send(()).unwrap();

        let first = first.await.unwrap();
        let retry = retry.await.unwrap();

        assert!(first.is_ok(), "first build must succeed: {:?}", first.err());
        assert!(
            retry.is_ok(),
            "the retry must adopt the running build, got {:?}",
            retry.err()
        );
        assert_eq!(
            builds.load(Ordering::SeqCst),
            1,
            "the retry must join the running build rather than start a second one"
        );
    }

    #[tokio::test]
    async fn a_panicking_build_releases_the_slot_and_wakes_joiners() {
        let tracker = CreateTracker::new();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();

        let owner = tokio::spawn({
            let tracker = tracker.clone();
            async move {
                spawn_or_join(&tracker, "exec-wedge", async move {
                    let _ = release_rx.await;
                    panic!("build task exploded");
                })
                .await
            }
        });

        tokio::time::sleep(Duration::from_millis(20)).await;
        let joiner = tokio::spawn({
            let tracker = tracker.clone();
            async move { spawn_or_join(&tracker, "exec-wedge", async move { Ok(response()) }).await }
        });

        tokio::time::sleep(Duration::from_millis(20)).await;
        release_tx.send(()).unwrap();

        let owner = tokio::time::timeout(Duration::from_secs(5), owner)
            .await
            .expect("owner must not park forever")
            .unwrap();
        let joiner = tokio::time::timeout(Duration::from_secs(5), joiner)
            .await
            .expect("joiner must not park forever")
            .unwrap();

        assert!(owner.is_err(), "a panicking build must surface an error");
        assert!(joiner.is_err(), "joiners must be woken with the failure");
        assert!(
            !tracker.is_in_flight("exec-wedge"),
            "the slot must be released so a retry can start"
        );
    }
}
