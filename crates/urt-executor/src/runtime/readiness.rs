//! Shared readiness-wait helper used by executions, commands and logs routes.
//!
//! Centralises the Notify-based pending-state park so all three routes behave
//! identically and the logic only needs to exist in one place.

use crate::error::ExecutorError;
use crate::routes::AppState;
use crate::runtime::Runtime;
use crate::telemetry::metrics;
use std::sync::Arc;
use std::time::{Duration, Instant};

// ============================================================================
// RAII readiness guard (Fix D)
// ============================================================================

/// RAII guard that ensures the readiness notifier for `full_name` is always
/// woken and removed from the map, even on error paths.
///
/// On `Drop`, calls `readiness_notify_and_remove` unless `disarm()` was called
/// first.  The success path should call `disarm()` after the registry entry has
/// been promoted to non-pending, then perform `readiness_notify_and_remove`
/// explicitly at the right moment (after the registry update, before returning).
///
/// This prevents the DashMap leak where error paths between notifier insertion
/// and the explicit success remove leave entries that park future waiters forever.
pub(crate) struct ReadinessGuard {
    full_name: String,
    readiness: Arc<dashmap::DashMap<String, Arc<tokio::sync::Notify>>>,
    armed: bool,
}

impl ReadinessGuard {
    /// Create a guard.  The caller is responsible for having already inserted the
    /// notifier via `AppState::readiness_notifier` before constructing this guard.
    pub(crate) fn new(
        full_name: String,
        readiness: Arc<dashmap::DashMap<String, Arc<tokio::sync::Notify>>>,
    ) -> Self {
        Self {
            full_name,
            readiness,
            armed: true,
        }
    }

    /// Disarm the guard.  After calling this the `Drop` impl is a no-op.
    /// The caller must perform `readiness_notify_and_remove` explicitly at the
    /// correct ordering point (after registry.update, before returning).
    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ReadinessGuard {
    fn drop(&mut self) {
        if self.armed {
            if let Some((_, notify)) = self.readiness.remove(&self.full_name) {
                notify.notify_waiters();
            }
        }
    }
}

// ============================================================================
// Pending-state wait helpers
// ============================================================================

/// Wait until the registry entry for `full_name` transitions out of pending state,
/// or until `deadline` is reached.
///
/// Uses `readiness_notifier_existing` (get-only) so that requests targeting
/// runtimes that are genuinely absent do not create dangling DashMap entries.
/// Acquires the `Notify` future BEFORE each registry check so that a notification
/// fired between the check and the park is not missed.  On wake the registry is
/// re-checked: non-pending -> Ok, absent -> None, deadline -> RuntimeTimeout.
/// When the notifier entry has been removed in the narrow race between the
/// pending check and the park (i.e. `readiness_notifier_existing` returns None
/// while the registry still shows pending), a bounded re-check loop of up to
/// ~100 ms is used before treating the result as a timeout or absence.
pub(crate) async fn wait_for_pending(
    state: &AppState,
    full_name: &str,
    deadline: tokio::time::Instant,
) -> Option<crate::error::Result<Runtime>> {
    let wait_start = Instant::now();

    let result = wait_for_pending_inner(state, full_name, deadline).await;

    // Record readiness wait metrics (M11).
    let elapsed = wait_start.elapsed();
    match &result {
        Some(Ok(_)) => metrics().observe_readiness_wait("ready", elapsed),
        Some(Err(ExecutorError::RuntimeTimeout)) => {
            metrics().observe_readiness_wait("timeout", elapsed);
            metrics().inc_readiness_timeout();
        }
        None => metrics().observe_readiness_wait("absent", elapsed),
        Some(Err(_)) => {}
    }

    result
}

async fn wait_for_pending_inner(
    state: &AppState,
    full_name: &str,
    deadline: tokio::time::Instant,
) -> Option<crate::error::Result<Runtime>> {
    loop {
        match state.readiness_notifier_existing(full_name) {
            Some(notify) => {
                let notified = notify.notified();
                tokio::pin!(notified);

                match state.registry.get(full_name).await {
                    Some(rt) if !rt.is_pending() => return Some(Ok(rt)),
                    Some(_) => {}
                    None => return None,
                }

                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    return Some(Err(ExecutorError::RuntimeTimeout));
                }

                match tokio::time::timeout(remaining, notified).await {
                    Ok(()) => {}
                    Err(_) => return Some(Err(ExecutorError::RuntimeTimeout)),
                }
            }
            None => {
                // Notifier was removed in the narrow window between our pending
                // check and this call. Poll the registry briefly (<=100 ms total)
                // to allow the transition to settle.
                let poll_bound = deadline
                    .saturating_duration_since(tokio::time::Instant::now())
                    .min(Duration::from_millis(100));

                if poll_bound.is_zero() {
                    return Some(Err(ExecutorError::RuntimeTimeout));
                }

                let poll_deadline = tokio::time::Instant::now() + poll_bound;
                let mut delay = Duration::from_millis(5);
                loop {
                    tokio::time::sleep(delay).await;
                    match state.registry.get(full_name).await {
                        Some(rt) if !rt.is_pending() => return Some(Ok(rt)),
                        None => return None,
                        Some(_) => {}
                    }
                    if tokio::time::Instant::now() >= poll_deadline {
                        break;
                    }
                    delay = (delay * 2).min(Duration::from_millis(20));
                }

                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    return Some(Err(ExecutorError::RuntimeTimeout));
                }
                // Re-enter the outer loop: the notifier may have reappeared or
                // the entry may now be non-pending.
            }
        }
    }
}

// ============================================================================
// Primary resolution entry-point
// ============================================================================

/// Resolve a runtime by name using the Notify-based readiness gate, mirroring
/// the full pattern from executions.rs (R1 race handling, adoption fallback).
///
/// # Parameters
///
/// - `timeout_secs`: per-request deadline in seconds.
/// - `wait_for_pending`: when `false`, an entry that is currently in pending
///   state returns `Err(RuntimeNotFound)` immediately instead of parking.
///   Pass `true` only when the caller is the owner of the pending build (i.e.
///   it supplied an `image` and created the runtime itself).
/// - `adopt`: when `true`, an on-demand Docker-inspect re-adoption attempt is
///   made when the runtime is not found in the registry.
///
/// # Pending-wait cap (Fix A)
///
/// Even when `wait_for_pending = true`, the park duration is bounded by
/// `min(config.pending_wait_max_secs, deadline_remaining)`.  This prevents a
/// bot-scan flood from parking every request for the full caller deadline while
/// a legitimate build is mid-flight.
pub(crate) async fn resolve_runtime_with_readiness(
    state: &AppState,
    full_name: &str,
    timeout_secs: u64,
    should_wait_for_pending: bool,
    adopt: bool,
) -> crate::error::Result<Runtime> {
    let caller_deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs.max(1));

    // Compute the effective deadline for any pending-state park: the stricter of
    // the caller's full timeout and the configured cap.
    let pending_deadline = if should_wait_for_pending {
        let cap = Duration::from_secs(state.config.pending_wait_max_secs);
        let remaining = caller_deadline.saturating_duration_since(tokio::time::Instant::now());
        tokio::time::Instant::now() + remaining.min(cap)
    } else {
        // Not used in the !should_wait_for_pending branch, but needs a value.
        caller_deadline
    };

    // Fast path: notifier exists -- acquire the Notified future BEFORE the first
    // registry check so a wakeup in the gap is not missed.
    if let Some(notify) = state.readiness_notifier_existing(full_name) {
        let initial_notified = notify.notified();
        tokio::pin!(initial_notified);

        if let Some(runtime) = state.registry.get(full_name).await {
            if !runtime.is_pending() {
                return Ok(runtime);
            }
            // Entry is pending.
            if !should_wait_for_pending {
                return Err(ExecutorError::RuntimeNotFound);
            }
            // Wait for it to transition, bounded by pending_deadline.
            if let Some(result) = wait_for_pending(state, full_name, pending_deadline).await {
                return result;
            }
        } else {
            // Notifier present but no registry entry (R1 race).
            // Fix E: limit this speculative wait to a single short iteration
            // (10ms) since the entry has not appeared yet and may never appear
            // for a truly unknown ID.  The full 200ms ceiling only makes sense
            // when a notifier exists because a concurrent create is mid-flight;
            // here we do one short poll and move on.
            let r1_bound = caller_deadline
                .saturating_duration_since(tokio::time::Instant::now())
                .min(Duration::from_millis(10));

            if !r1_bound.is_zero() {
                let _ = tokio::time::timeout(r1_bound, initial_notified).await;
            }

            if let Some(runtime) = state.registry.get(full_name).await {
                if !runtime.is_pending() {
                    return Ok(runtime);
                }
                if !should_wait_for_pending {
                    return Err(ExecutorError::RuntimeNotFound);
                }
                if let Some(result) = wait_for_pending(state, full_name, pending_deadline).await {
                    return result;
                }
            }
        }
    } else if let Some(runtime) = state.registry.get(full_name).await {
        if !runtime.is_pending() {
            return Ok(runtime);
        }
        // Pending but notifier already removed: bounded poll.
        if !should_wait_for_pending {
            return Err(ExecutorError::RuntimeNotFound);
        }
        let r1_bound = pending_deadline
            .saturating_duration_since(tokio::time::Instant::now())
            .min(Duration::from_millis(200));
        if !r1_bound.is_zero() {
            if let Some(result) = wait_for_pending(state, full_name, pending_deadline).await {
                return result;
            }
        }
    } else {
        // R1: no notifier, no entry.  Fix E: one short poll (~10ms) is enough.
        // Only escalate to the full 200ms loop when a notifier races in, which
        // indicates a genuine concurrent create.
        let r1_bound = caller_deadline
            .saturating_duration_since(tokio::time::Instant::now())
            .min(Duration::from_millis(10));

        if !r1_bound.is_zero() {
            // Fix E: one short sleep (~10ms) to cover the narrow create-race
            // window.  If a notifier or registry entry appears during that
            // window we handle it; otherwise we fall through to the adoption
            // path below.  A full iterating poll is deliberately avoided for
            // unknown IDs because they cannot legitimately appear.
            tokio::time::sleep(Duration::from_millis(10)).await;
            if let Some(notify) = state.readiness_notifier_existing(full_name) {
                // A concurrent create raced in.  Afford up to 200ms additional
                // wait for the registry to catch up.
                let notified = notify.notified();
                tokio::pin!(notified);
                if let Some(runtime) = state.registry.get(full_name).await {
                    if !runtime.is_pending() {
                        return Ok(runtime);
                    }
                    if !should_wait_for_pending {
                        return Err(ExecutorError::RuntimeNotFound);
                    }
                    let remaining =
                        pending_deadline.saturating_duration_since(tokio::time::Instant::now());
                    if !remaining.is_zero() {
                        let _ = tokio::time::timeout(
                            remaining.min(Duration::from_millis(200)),
                            notified,
                        )
                        .await;
                    }
                    if let Some(result) = wait_for_pending(state, full_name, pending_deadline).await
                    {
                        return result;
                    }
                }
            } else if let Some(runtime) = state.registry.get(full_name).await {
                if !runtime.is_pending() {
                    return Ok(runtime);
                }
                if !should_wait_for_pending {
                    return Err(ExecutorError::RuntimeNotFound);
                }
                if let Some(result) = wait_for_pending(state, full_name, pending_deadline).await {
                    return result;
                }
            }
        }
    }

    if !adopt {
        return state
            .registry
            .get(full_name)
            .await
            .ok_or(ExecutorError::RuntimeNotFound);
    }

    // A name a recent attempt did not find is answered from memory: the
    // inspect that follows is one Docker call per request, and a scan over
    // unknown IDs would otherwise put all of it on the daemon.
    if state.adoption_negative_cache.is_absent(full_name) {
        return Err(ExecutorError::RuntimeNotFound);
    }

    // Attempt on-demand re-adoption (Fix F: only when adopt=true).
    let adopted = crate::tasks::adopt_container_by_name(
        &state.docker,
        &state.registry,
        &state.keep_alive_registry,
        &state.config.hostname,
        full_name,
        state.config.runtime_lifecycle_defaults(),
    )
    .await;

    if adopted {
        state.adoption_negative_cache.forget(full_name);
    } else {
        state.adoption_negative_cache.record_absent(full_name);
    }

    if let Some(runtime) = state.registry.get(full_name).await {
        if runtime.is_pending() {
            return match wait_for_pending(state, full_name, pending_deadline).await {
                Some(Ok(rt)) => Ok(rt),
                Some(Err(e)) => Err(e),
                None => Err(ExecutorError::RuntimeNotFound),
            };
        }
        return Ok(runtime);
    }

    Err(ExecutorError::RuntimeNotFound)
}
