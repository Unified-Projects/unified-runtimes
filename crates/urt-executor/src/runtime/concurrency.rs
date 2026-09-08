//! Per-runtime execution concurrency caps.
//!
//! A runtime created with `maxConcurrency` admits that many executions at once.
//! Requests beyond the cap queue for the executor's execution queue wait and
//! then fail with `RuntimeAtCapacity` rather than piling onto a runtime that
//! cannot keep up. The upstream open-runtimes node server retains one request's
//! worth of heap per in-flight execution for the whole timeout window, so an
//! unbounded runtime under sustained load dies of heap exhaustion.

use dashmap::DashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// One runtime's admission slots, along with the cap they were built for so a
/// runtime recreated with a different cap does not keep the old one.
#[derive(Debug, Clone)]
struct Slots {
    limit: usize,
    semaphore: Arc<Semaphore>,
}

/// Admission control for executions, keyed by container name.
#[derive(Debug, Clone, Default)]
pub struct RuntimeConcurrency {
    slots: Arc<DashMap<String, Slots>>,
}

impl RuntimeConcurrency {
    pub fn new() -> Self {
        Self {
            slots: Arc::new(DashMap::new()),
        }
    }

    /// Take a slot for `name`, waiting up to `wait` for one to free up.
    ///
    /// Returns `None` when the wait elapsed with the runtime still at its cap.
    /// The returned permit releases the slot when it is dropped, so a caller
    /// only needs to hold it for as long as the execution runs.
    pub async fn acquire(
        &self,
        name: &str,
        limit: usize,
        wait: Duration,
    ) -> Option<OwnedSemaphorePermit> {
        let semaphore = self.semaphore_for(name, limit);

        match tokio::time::timeout(wait, semaphore.acquire_owned()).await {
            Ok(Ok(permit)) => Some(permit),
            // The semaphore is never closed, so this arm is unreachable in
            // practice; treating it as "at capacity" keeps the cap honest.
            Ok(Err(_)) => None,
            Err(_) => None,
        }
    }

    /// Drop the slots of runtimes that no longer exist, so the map tracks the
    /// registry rather than growing with every runtime ID ever seen.
    pub fn retain_known(&self, live: &HashSet<String>) {
        self.slots.retain(|name, _| live.contains(name));
    }

    fn semaphore_for(&self, name: &str, limit: usize) -> Arc<Semaphore> {
        let limit = limit.max(1);

        if let Some(existing) = self.slots.get(name) {
            if existing.limit == limit {
                return Arc::clone(&existing.semaphore);
            }
        }

        // A changed cap means the runtime was recreated under the same name;
        // rebuild rather than serve the old width.
        let mut entry = self.slots.entry(name.to_string()).or_insert_with(|| Slots {
            limit,
            semaphore: Arc::new(Semaphore::new(limit)),
        });

        if entry.limit != limit {
            *entry = Slots {
                limit,
                semaphore: Arc::new(Semaphore::new(limit)),
            };
        }

        Arc::clone(&entry.semaphore)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn admits_up_to_the_cap() {
        let concurrency = RuntimeConcurrency::new();
        let wait = Duration::from_millis(50);

        let first = concurrency.acquire("rt", 2, wait).await;
        let second = concurrency.acquire("rt", 2, wait).await;
        let third = concurrency.acquire("rt", 2, wait).await;

        assert!(first.is_some());
        assert!(second.is_some());
        assert!(third.is_none());
    }

    #[tokio::test]
    async fn refuses_beyond_the_cap_after_the_wait() {
        let concurrency = RuntimeConcurrency::new();
        let wait = Duration::from_millis(50);

        let _held = concurrency.acquire("rt", 1, wait).await.unwrap();
        let refused = concurrency.acquire("rt", 1, wait).await;

        assert!(refused.is_none());
    }

    #[tokio::test]
    async fn a_released_slot_admits_the_next_caller() {
        let concurrency = RuntimeConcurrency::new();
        let wait = Duration::from_millis(200);

        let held = concurrency.acquire("rt", 1, wait).await.unwrap();
        drop(held);

        assert!(concurrency.acquire("rt", 1, wait).await.is_some());
    }

    #[tokio::test]
    async fn caps_are_independent_per_runtime() {
        let concurrency = RuntimeConcurrency::new();
        let wait = Duration::from_millis(50);

        let _held = concurrency.acquire("rt-a", 1, wait).await.unwrap();

        assert!(concurrency.acquire("rt-b", 1, wait).await.is_some());
    }

    #[tokio::test]
    async fn a_changed_cap_rebuilds_the_slots() {
        let concurrency = RuntimeConcurrency::new();
        let wait = Duration::from_millis(50);

        let first = concurrency.acquire("rt", 1, wait).await;
        assert!(first.is_some());
        drop(first);

        let a = concurrency.acquire("rt", 3, wait).await;
        let b = concurrency.acquire("rt", 3, wait).await;
        let c = concurrency.acquire("rt", 3, wait).await;

        assert!(a.is_some() && b.is_some() && c.is_some());
        assert!(concurrency.acquire("rt", 3, wait).await.is_none());
    }

    #[tokio::test]
    async fn retain_known_drops_runtimes_that_are_gone() {
        let concurrency = RuntimeConcurrency::new();
        let wait = Duration::from_millis(50);

        drop(concurrency.acquire("rt-a", 1, wait).await);
        drop(concurrency.acquire("rt-b", 1, wait).await);

        let live: HashSet<String> = ["rt-a".to_string()].into_iter().collect();
        concurrency.retain_known(&live);

        assert_eq!(concurrency.slots.len(), 1);
        assert!(concurrency.slots.contains_key("rt-a"));
    }
}
