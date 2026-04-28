//! Shared readiness-wait helper used by executions, commands and logs routes.
//!
//! Centralises the Notify-based pending-state park so all three routes behave
//! identically and the logic only needs to exist in one place.

use crate::error::ExecutorError;
use crate::routes::AppState;
use crate::runtime::Runtime;
use crate::telemetry::metrics;
use std::time::{Duration, Instant};

/// Wait until the registry entry for `full_name` transitions out of pending state,
/// or until `deadline` is reached.
///
/// Uses `readiness_notifier_existing` (get-only) so that requests targeting
/// runtimes that are genuinely absent do not create dangling DashMap entries.
/// Acquires the `Notify` future BEFORE each registry check so that a notification
/// fired between the check and the park is not missed.  On wake the registry is
/// re-checked: non-pending → Ok, absent → None, deadline → RuntimeTimeout.
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
                // check and this call. Poll the registry briefly (≤100 ms total)
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

/// Resolve a runtime by name using the Notify-based readiness gate, mirroring
/// the full pattern from executions.rs (R1 race handling, adoption fallback).
///
/// `timeout_secs` is the per-request deadline in seconds.
///
/// Returns Ok(Runtime) when the runtime is found and non-pending, or
/// Err(RuntimeTimeout | RuntimeNotFound) otherwise.
pub(crate) async fn resolve_runtime_with_readiness(
    state: &AppState,
    full_name: &str,
    timeout_secs: u64,
    adopt: bool,
) -> crate::error::Result<Runtime> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs.max(1));

    // Fast path: notifier exists — acquire the Notified future BEFORE the first
    // registry check so a wakeup in the gap is not missed.
    if let Some(notify) = state.readiness_notifier_existing(full_name) {
        let initial_notified = notify.notified();
        tokio::pin!(initial_notified);

        if let Some(runtime) = state.registry.get(full_name).await {
            if !runtime.is_pending() {
                return Ok(runtime);
            }
            // Entry is pending — wait for it to transition.
            if let Some(result) = wait_for_pending(state, full_name, deadline).await {
                return result;
            }
        } else {
            // Notifier present but no registry entry (R1 race).
            let r1_bound = deadline
                .saturating_duration_since(tokio::time::Instant::now())
                .min(Duration::from_millis(200));

            if !r1_bound.is_zero() {
                let _ = tokio::time::timeout(r1_bound, initial_notified).await;
            }

            if let Some(runtime) = state.registry.get(full_name).await {
                if !runtime.is_pending() {
                    return Ok(runtime);
                }
                if let Some(result) = wait_for_pending(state, full_name, deadline).await {
                    return result;
                }
            }
        }
    } else if let Some(runtime) = state.registry.get(full_name).await {
        if !runtime.is_pending() {
            return Ok(runtime);
        }
        // Pending but notifier already removed: bounded poll.
        let r1_bound = deadline
            .saturating_duration_since(tokio::time::Instant::now())
            .min(Duration::from_millis(200));
        if !r1_bound.is_zero() {
            if let Some(result) = wait_for_pending(state, full_name, deadline).await {
                return result;
            }
        }
    } else {
        // R1: no notifier, no entry. Bounded plain registry poll (≤200 ms).
        let r1_bound = deadline
            .saturating_duration_since(tokio::time::Instant::now())
            .min(Duration::from_millis(200));

        if !r1_bound.is_zero() {
            let poll_deadline = tokio::time::Instant::now() + r1_bound;
            let mut delay = Duration::from_millis(10);
            loop {
                tokio::time::sleep(delay).await;
                if let Some(notify) = state.readiness_notifier_existing(full_name) {
                    let notified = notify.notified();
                    tokio::pin!(notified);
                    if let Some(runtime) = state.registry.get(full_name).await {
                        if !runtime.is_pending() {
                            return Ok(runtime);
                        }
                        let remaining =
                            deadline.saturating_duration_since(tokio::time::Instant::now());
                        if !remaining.is_zero() {
                            let _ = tokio::time::timeout(remaining.min(r1_bound), notified).await;
                        }
                        if let Some(result) = wait_for_pending(state, full_name, deadline).await {
                            return result;
                        }
                    }
                    break;
                }
                if let Some(runtime) = state.registry.get(full_name).await {
                    if !runtime.is_pending() {
                        return Ok(runtime);
                    }
                    if let Some(result) = wait_for_pending(state, full_name, deadline).await {
                        return result;
                    }
                    break;
                }
                if tokio::time::Instant::now() >= poll_deadline {
                    break;
                }
                delay = (delay * 2).min(Duration::from_millis(40));
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

    // Attempt on-demand re-adoption.
    let _ = crate::tasks::adopt_container_by_name(
        &state.docker,
        &state.registry,
        &state.keep_alive_registry,
        &state.config.hostname,
        full_name,
    )
    .await;

    if let Some(runtime) = state.registry.get(full_name).await {
        if runtime.is_pending() {
            return match wait_for_pending(state, full_name, deadline).await {
                Some(Ok(rt)) => Ok(rt),
                Some(Err(e)) => Err(e),
                None => Err(ExecutorError::RuntimeNotFound),
            };
        }
        return Ok(runtime);
    }

    Err(ExecutorError::RuntimeNotFound)
}
