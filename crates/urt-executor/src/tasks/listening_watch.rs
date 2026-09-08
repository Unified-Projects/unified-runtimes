//! Watchdog for runtimes that start but never listen
//!
//! A container can report `running` with `initialised = 1` and still be
//! unreachable, most commonly when its server binds to a per-container address
//! rather than the wildcard address. The registry records that as
//! `listening = 0` forever and nothing else surfaces it, so this task turns the
//! condition into a warning in the executor log.

use crate::runtime::{Runtime, RuntimeRegistry};
use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::watch;
use tracing::{debug, warn};

/// How often the registry is scanned for stuck runtimes.
const SCAN_INTERVAL: Duration = Duration::from_secs(30);

/// How long a runtime may be running and initialised without ever having been
/// observed listening before it is reported.
const LISTENING_GRACE: Duration = Duration::from_secs(120);

/// Port every managed runtime is expected to serve on.
const RUNTIME_PORT: u16 = 3000;

/// Remembers which runtimes have already been reported so the warning is logged
/// once per runtime instead of on every scan.
#[derive(Debug, Default)]
struct NonListeningWatch {
    reported: HashSet<String>,
}

impl NonListeningWatch {
    /// Return the runtimes that have just crossed the grace period without ever
    /// being observed listening. Names that have left the registry are forgotten,
    /// so a recreated runtime under the same name can be reported again.
    fn newly_stuck<'a>(
        &mut self,
        runtimes: &'a [Runtime],
        grace: Duration,
        now: f64,
    ) -> Vec<&'a Runtime> {
        let live: HashSet<&str> = runtimes.iter().map(|r| r.name.as_str()).collect();
        self.reported.retain(|name| live.contains(name.as_str()));

        let grace_secs = grace.as_secs_f64();
        runtimes
            .iter()
            .filter(|runtime| is_stuck_non_listening(runtime, grace_secs, now))
            .filter(|runtime| self.reported.insert(runtime.name.clone()))
            .collect()
    }
}

/// A runtime that Docker reports as up, that the executor has marked
/// initialised, that has never answered on its port, and that has had long
/// enough to do so.
fn is_stuck_non_listening(runtime: &Runtime, grace_secs: f64, now: f64) -> bool {
    runtime.is_running()
        && runtime.initialised > 0
        && !runtime.is_listening()
        && now - runtime.created >= grace_secs
}

fn unix_now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn report(runtimes: &[Runtime], watch: &mut NonListeningWatch, grace: Duration, now: f64) {
    for runtime in watch.newly_stuck(runtimes, grace, now) {
        let age_secs = (now - runtime.created).max(0.0) as u64;
        warn!(
            runtime = %runtime.name,
            runtime_id = %runtime.runtime_id,
            image = %runtime.image,
            age_seconds = age_secs,
            "Runtime {} has been running and initialised for {}s but has never been observed \
             listening on port {}; it is most likely bound to its container address instead of \
             {}. Set {}={} for it, or check its server logs for the address it reported.",
            runtime.name,
            age_secs,
            RUNTIME_PORT,
            crate::routes::DEFAULT_RUNTIME_BIND_HOSTNAME,
            crate::routes::RUNTIME_BIND_HOSTNAME_VAR,
            crate::routes::DEFAULT_RUNTIME_BIND_HOSTNAME,
        );
    }
}

/// Run the non-listening watchdog until shutdown.
pub async fn run_listening_watch(registry: RuntimeRegistry, mut shutdown: watch::Receiver<bool>) {
    debug!(
        "Starting non-listening watchdog (scan: {}s, grace: {}s)",
        SCAN_INTERVAL.as_secs(),
        LISTENING_GRACE.as_secs()
    );

    let mut watch = NonListeningWatch::default();

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    debug!("Non-listening watchdog shutting down");
                    break;
                }
            }
            _ = tokio::time::sleep(SCAN_INTERVAL) => {
                let runtimes = registry.list().await;
                report(&runtimes, &mut watch, LISTENING_GRACE, unix_now());
            }
        }
    }

    debug!("Non-listening watchdog stopped");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime_at(name: &str, created: f64) -> Runtime {
        let mut runtime = Runtime::new(name, "executor-a", "node:v5", "v5", None);
        runtime.created = created;
        runtime.updated = created;
        runtime
    }

    fn stuck_runtime(name: &str, created: f64) -> Runtime {
        let mut runtime = runtime_at(name, created);
        runtime.mark_running("running");
        runtime.created = created;
        runtime
    }

    #[test]
    fn reports_a_runtime_that_never_listened_once_past_the_grace_period() {
        let now = 10_000.0;
        let runtimes = vec![stuck_runtime("rt-stuck", now - 300.0)];
        let mut watch = NonListeningWatch::default();

        let stuck = watch.newly_stuck(&runtimes, Duration::from_secs(120), now);

        assert_eq!(stuck.len(), 1);
        assert_eq!(stuck[0].name, "executor-a-rt-stuck");
    }

    #[test]
    fn reports_each_runtime_only_once() {
        let now = 10_000.0;
        let runtimes = vec![stuck_runtime("rt-stuck", now - 300.0)];
        let mut watch = NonListeningWatch::default();

        assert_eq!(
            watch
                .newly_stuck(&runtimes, Duration::from_secs(120), now)
                .len(),
            1
        );
        assert!(watch
            .newly_stuck(&runtimes, Duration::from_secs(120), now + 30.0)
            .is_empty());
    }

    #[test]
    fn ignores_runtimes_inside_the_grace_period() {
        let now = 10_000.0;
        let runtimes = vec![stuck_runtime("rt-young", now - 30.0)];
        let mut watch = NonListeningWatch::default();

        assert!(watch
            .newly_stuck(&runtimes, Duration::from_secs(120), now)
            .is_empty());
    }

    #[test]
    fn ignores_listening_pending_and_stopped_runtimes() {
        let now = 10_000.0;

        let mut listening = stuck_runtime("rt-listening", now - 300.0);
        listening.set_listening();
        listening.created = now - 300.0;

        let pending = runtime_at("rt-pending", now - 300.0);

        let mut exited = stuck_runtime("rt-exited", now - 300.0);
        exited.status = "exited".to_string();

        let runtimes = vec![listening, pending, exited];
        let mut watch = NonListeningWatch::default();

        assert!(watch
            .newly_stuck(&runtimes, Duration::from_secs(120), now)
            .is_empty());
    }

    #[test]
    fn forgets_runtimes_that_leave_the_registry() {
        let now = 10_000.0;
        let runtimes = vec![stuck_runtime("rt-stuck", now - 300.0)];
        let mut watch = NonListeningWatch::default();

        assert_eq!(
            watch
                .newly_stuck(&runtimes, Duration::from_secs(120), now)
                .len(),
            1
        );
        assert!(watch
            .newly_stuck(&[], Duration::from_secs(120), now + 10.0)
            .is_empty());
        // Same name recreated later: reported again rather than suppressed forever.
        assert_eq!(
            watch
                .newly_stuck(&runtimes, Duration::from_secs(120), now + 20.0)
                .len(),
            1
        );
    }
}
