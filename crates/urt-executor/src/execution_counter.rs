//! Process-wide execution counter used for graceful shutdown and autoscaling telemetry.

use std::sync::atomic::{AtomicUsize, Ordering};

static ACTIVE_EXECUTIONS: AtomicUsize = AtomicUsize::new(0);

/// RAII guard that increments the active execution counter on creation and
/// decrements it when dropped.
pub struct ExecutionGuard;

impl ExecutionGuard {
    pub fn new() -> Self {
        ACTIVE_EXECUTIONS.fetch_add(1, Ordering::Relaxed);
        Self
    }
}

impl Default for ExecutionGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ExecutionGuard {
    fn drop(&mut self) {
        let previous = ACTIVE_EXECUTIONS.fetch_sub(1, Ordering::Relaxed);
        debug_assert!(previous > 0, "active execution counter underflow");
    }
}

/// Current number of in-flight executions.
pub fn active_executions() -> usize {
    ACTIVE_EXECUTIONS.load(Ordering::Relaxed)
}
