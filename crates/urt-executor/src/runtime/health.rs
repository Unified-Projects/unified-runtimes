//! Per-runtime death history, restart backoff and crash-loop quarantine.
//!
//! `RuntimeHealth` is the bookkeeping behind dead-runtime handling. It does not
//! talk to Docker or the registry; the execution path, the Docker events task
//! and maintenance feed it observations and act on what it returns:
//!
//! - every container death is recorded with its exit code, bounded per runtime;
//! - the delay before the executor recreates a runtime grows with the number
//!   of recent deaths (1s, 2s, 4s ... capped);
//! - a runtime that dies `crash_loop_threshold` times inside
//!   `crash_loop_window` is quarantined for `quarantine`, during which
//!   executions and creates are refused;
//! - a runtime found unreachable carries a short-lived marker so queued
//!   requests fail fast instead of each burning a connect timeout;
//! - a per-runtime lock coalesces concurrent liveness checks so a burst of
//!   failures costs one Docker inspect.

use crate::config::ExecutorConfig;
use crate::error::QuarantineDetail;
use crate::telemetry::metrics;
use dashmap::DashMap;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::time::Instant;

/// Deaths remembered per runtime.
const MAX_DEATH_HISTORY: usize = 16;

/// First step of the restart backoff.
const RESTART_BACKOFF_BASE: Duration = Duration::from_secs(1);

/// Thresholds for restart backoff and quarantine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrashLoopConfig {
    /// Cap on the delay between executor-initiated recreates.
    pub restart_backoff_max: Duration,
    /// Deaths inside `crash_loop_window` that trigger a quarantine.
    pub crash_loop_threshold: u32,
    /// Window over which deaths are counted.
    pub crash_loop_window: Duration,
    /// How long a quarantine lasts.
    pub quarantine: Duration,
}

impl CrashLoopConfig {
    pub fn from_executor_config(config: &ExecutorConfig) -> Self {
        Self {
            restart_backoff_max: Duration::from_secs(config.restart_backoff_max_secs.max(1)),
            crash_loop_threshold: config.crash_loop_threshold.max(1),
            crash_loop_window: Duration::from_secs(config.crash_loop_window_secs.max(1)),
            quarantine: Duration::from_secs(config.quarantine_secs.max(1)),
        }
    }
}

impl Default for CrashLoopConfig {
    fn default() -> Self {
        Self {
            restart_backoff_max: Duration::from_secs(30),
            crash_loop_threshold: 3,
            crash_loop_window: Duration::from_secs(60),
            quarantine: Duration::from_secs(300),
        }
    }
}

/// One observed container death.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeathRecord {
    pub at: Instant,
    pub exit_code: Option<i64>,
}

/// What recording a death decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeathOutcome {
    /// Below the crash-loop threshold; `restart_delay` is the backoff the
    /// executor should observe before recreating the runtime itself.
    Recorded {
        deaths_in_window: u32,
        restart_delay: Duration,
    },
    /// The threshold was reached (or a quarantine was already active).
    Quarantined(QuarantineDetail),
}

/// Whether a runtime is quarantined right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuarantineState {
    None,
    Active(QuarantineDetail),
    /// The quarantine has lapsed since the last check. Reported once; the
    /// tracker clears it when it reports this.
    Expired,
}

/// What a Docker inspect said about a runtime's container, as cached by the
/// single-flight liveness check.
#[derive(Debug, Clone)]
pub enum ContainerObservation {
    Found(Box<crate::docker::container::ContainerInfo>),
    Gone,
}

#[derive(Debug, Clone)]
struct ActiveQuarantine {
    until: Instant,
    detail: QuarantineDetail,
}

#[derive(Debug, Default)]
struct HealthEntry {
    deaths: VecDeque<DeathRecord>,
    quarantine: Option<ActiveQuarantine>,
    unreachable_until: Option<Instant>,
}

impl HealthEntry {
    fn prune(&mut self, now: Instant, window: Duration) {
        while let Some(oldest) = self.deaths.front() {
            if now.duration_since(oldest.at) > window {
                self.deaths.pop_front();
            } else {
                break;
            }
        }
    }

    fn deaths_in_window(&self, now: Instant, window: Duration) -> u32 {
        self.deaths
            .iter()
            .filter(|death| now.duration_since(death.at) <= window)
            .count() as u32
    }
}

/// Cached outcome of the most recent liveness check for one runtime, guarded
/// by the per-runtime single-flight lock.
#[derive(Debug, Default)]
pub struct LivenessCache {
    pub checked_at: Option<Instant>,
    pub observation: Option<ContainerObservation>,
}

impl LivenessCache {
    /// The cached observation when it is younger than `max_age`.
    pub fn fresh(&self, max_age: Duration) -> Option<&ContainerObservation> {
        match (self.checked_at, self.observation.as_ref()) {
            (Some(at), Some(observation)) if at.elapsed() < max_age => Some(observation),
            _ => None,
        }
    }

    pub fn store(&mut self, observation: ContainerObservation) {
        self.checked_at = Some(Instant::now());
        self.observation = Some(observation);
    }
}

/// Crash-loop and reachability state for every runtime this executor knows.
#[derive(Debug, Clone)]
pub struct RuntimeHealth {
    config: CrashLoopConfig,
    entries: Arc<DashMap<String, HealthEntry>>,
    liveness: Arc<DashMap<String, Arc<tokio::sync::Mutex<LivenessCache>>>>,
}

impl Default for RuntimeHealth {
    fn default() -> Self {
        Self::new(CrashLoopConfig::default())
    }
}

impl RuntimeHealth {
    pub fn new(config: CrashLoopConfig) -> Self {
        Self {
            config,
            entries: Arc::new(DashMap::new()),
            liveness: Arc::new(DashMap::new()),
        }
    }

    pub fn config(&self) -> &CrashLoopConfig {
        &self.config
    }

    /// Backoff before the executor recreates a runtime that has died
    /// `deaths_in_window` times: 1s doubling per death, capped.
    fn backoff_for(&self, deaths_in_window: u32) -> Duration {
        if deaths_in_window == 0 {
            return Duration::ZERO;
        }
        let exponent = deaths_in_window.saturating_sub(1).min(16);
        let delay = RESTART_BACKOFF_BASE.saturating_mul(1u32 << exponent);
        delay.min(self.config.restart_backoff_max)
    }

    fn build_quarantine(
        &self,
        runtime_id: &str,
        deaths: u32,
        exit_code: Option<i64>,
        now: Instant,
    ) -> ActiveQuarantine {
        let until = now + self.config.quarantine;
        let expires_at = SystemTime::now() + self.config.quarantine;
        let expires_at: chrono::DateTime<chrono::Utc> = expires_at.into();
        ActiveQuarantine {
            until,
            detail: QuarantineDetail {
                runtime_id: runtime_id.to_string(),
                deaths,
                last_exit_code: exit_code,
                expires_at: expires_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                retry_after_secs: self.config.quarantine.as_secs(),
            },
        }
    }

    fn detail_with_remaining(quarantine: &ActiveQuarantine, now: Instant) -> QuarantineDetail {
        let mut detail = quarantine.detail.clone();
        detail.retry_after_secs = quarantine
            .until
            .saturating_duration_since(now)
            .as_secs()
            .max(1);
        detail
    }

    /// Record a container death for `name` and decide what follows.
    pub fn record_death(
        &self,
        name: &str,
        runtime_id: &str,
        exit_code: Option<i64>,
    ) -> DeathOutcome {
        let now = Instant::now();
        let mut entry = self.entries.entry(name.to_string()).or_default();

        metrics().inc_runtime_death(exit_code);

        entry.deaths.push_back(DeathRecord { at: now, exit_code });
        while entry.deaths.len() > MAX_DEATH_HISTORY {
            entry.deaths.pop_front();
        }
        entry.prune(now, self.config.crash_loop_window);

        if let Some(active) = entry.quarantine.as_ref() {
            if active.until > now {
                return DeathOutcome::Quarantined(Self::detail_with_remaining(active, now));
            }
        }

        let deaths_in_window = entry.deaths_in_window(now, self.config.crash_loop_window);
        if deaths_in_window >= self.config.crash_loop_threshold {
            let quarantine = self.build_quarantine(runtime_id, deaths_in_window, exit_code, now);
            let detail = quarantine.detail.clone();
            entry.quarantine = Some(quarantine);
            metrics().inc_runtime_quarantined();
            return DeathOutcome::Quarantined(detail);
        }

        DeathOutcome::Recorded {
            deaths_in_window,
            restart_delay: self.backoff_for(deaths_in_window),
        }
    }

    /// Current quarantine state for `name`. An expired quarantine is reported
    /// as `Expired` exactly once and cleared, along with the death history that
    /// led to it.
    pub fn quarantine_state(&self, name: &str) -> QuarantineState {
        let now = Instant::now();
        let Some(mut entry) = self.entries.get_mut(name) else {
            return QuarantineState::None;
        };
        match entry.quarantine.as_ref() {
            None => QuarantineState::None,
            Some(active) if active.until > now => {
                QuarantineState::Active(Self::detail_with_remaining(active, now))
            }
            Some(_) => {
                entry.quarantine = None;
                entry.deaths.clear();
                QuarantineState::Expired
            }
        }
    }

    /// The active quarantine for `name`, if any. Expired quarantines are
    /// cleared as a side effect.
    pub fn active_quarantine(&self, name: &str) -> Option<QuarantineDetail> {
        match self.quarantine_state(name) {
            QuarantineState::Active(detail) => Some(detail),
            QuarantineState::None | QuarantineState::Expired => None,
        }
    }

    /// How long the executor should still wait before recreating `name`,
    /// measured from its most recent death.
    pub fn restart_wait(&self, name: &str) -> Duration {
        let now = Instant::now();
        let Some(entry) = self.entries.get(name) else {
            return Duration::ZERO;
        };
        let Some(last) = entry.deaths.back() else {
            return Duration::ZERO;
        };
        let deaths = entry.deaths_in_window(now, self.config.crash_loop_window);
        let ready_at = last.at + self.backoff_for(deaths);
        ready_at.saturating_duration_since(now)
    }

    /// Deaths currently remembered for `name`, oldest first.
    #[allow(dead_code)]
    pub fn deaths(&self, name: &str) -> Vec<DeathRecord> {
        self.entries
            .get(name)
            .map(|entry| entry.deaths.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Flag `name` as unreachable for `ttl`, so requests fail fast while the
    /// container is being checked or restarted.
    pub fn mark_unreachable(&self, name: &str, ttl: Duration) {
        let mut entry = self.entries.entry(name.to_string()).or_default();
        entry.unreachable_until = Some(Instant::now() + ttl);
    }

    /// Time left on the unreachable marker for `name`, if one is active.
    pub fn unreachable_remaining(&self, name: &str) -> Option<Duration> {
        let now = Instant::now();
        let entry = self.entries.get(name)?;
        let until = entry.unreachable_until?;
        if until > now {
            Some(until.duration_since(now))
        } else {
            None
        }
    }

    /// Lift the unreachable marker for `name`.
    pub fn clear_unreachable(&self, name: &str) {
        if let Some(mut entry) = self.entries.get_mut(name) {
            entry.unreachable_until = None;
        }
    }

    /// Per-runtime lock and verdict cache used to coalesce liveness checks.
    pub fn liveness_flight(&self, name: &str) -> Arc<tokio::sync::Mutex<LivenessCache>> {
        self.liveness
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(LivenessCache::default())))
            .clone()
    }

    /// Drop the cached liveness verdict for `name` so the next check inspects
    /// the container again.
    pub fn invalidate_liveness(&self, name: &str) {
        self.liveness.remove(name);
    }

    /// Runtimes with a quarantine on record, active or not yet reported expired.
    pub fn quarantined_names(&self) -> Vec<String> {
        self.entries
            .iter()
            .filter(|entry| entry.value().quarantine.is_some())
            .map(|entry| entry.key().clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> CrashLoopConfig {
        CrashLoopConfig {
            restart_backoff_max: Duration::from_secs(30),
            crash_loop_threshold: 3,
            crash_loop_window: Duration::from_secs(60),
            quarantine: Duration::from_secs(300),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn restart_backoff_doubles_per_death_and_caps() {
        let health = RuntimeHealth::new(CrashLoopConfig {
            crash_loop_threshold: 100,
            ..config()
        });

        let first = health.record_death("exec-rt", "rt", Some(1));
        assert_eq!(
            first,
            DeathOutcome::Recorded {
                deaths_in_window: 1,
                restart_delay: Duration::from_secs(1)
            }
        );
        assert_eq!(health.restart_wait("exec-rt"), Duration::from_secs(1));

        tokio::time::advance(Duration::from_millis(400)).await;
        assert_eq!(health.restart_wait("exec-rt"), Duration::from_millis(600));

        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(health.restart_wait("exec-rt"), Duration::ZERO);

        let mut delays = vec![];
        for _ in 0..6 {
            match health.record_death("exec-rt", "rt", Some(1)) {
                DeathOutcome::Recorded { restart_delay, .. } => delays.push(restart_delay),
                other => panic!("unexpected {:?}", other),
            }
        }
        assert_eq!(
            delays,
            vec![
                Duration::from_secs(2),
                Duration::from_secs(4),
                Duration::from_secs(8),
                Duration::from_secs(16),
                Duration::from_secs(30),
                Duration::from_secs(30),
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn three_deaths_inside_the_window_quarantine_the_runtime() {
        let health = RuntimeHealth::new(config());

        assert!(matches!(
            health.record_death("exec-rt", "rt", Some(134)),
            DeathOutcome::Recorded {
                deaths_in_window: 1,
                ..
            }
        ));
        tokio::time::advance(Duration::from_secs(20)).await;
        assert!(matches!(
            health.record_death("exec-rt", "rt", Some(134)),
            DeathOutcome::Recorded {
                deaths_in_window: 2,
                ..
            }
        ));
        tokio::time::advance(Duration::from_secs(20)).await;

        let outcome = health.record_death("exec-rt", "rt", Some(137));
        let DeathOutcome::Quarantined(detail) = outcome else {
            panic!(
                "third death inside the window must quarantine, got {:?}",
                outcome
            );
        };
        assert_eq!(detail.runtime_id, "rt");
        assert_eq!(detail.deaths, 3);
        assert_eq!(detail.last_exit_code, Some(137));
        assert_eq!(detail.retry_after_secs, 300);
        assert!(detail.expires_at.ends_with('Z'), "{}", detail.expires_at);

        let active = health.active_quarantine("exec-rt").expect("active");
        assert_eq!(active.last_exit_code, Some(137));

        // Further deaths while quarantined report the same quarantine.
        tokio::time::advance(Duration::from_secs(100)).await;
        match health.record_death("exec-rt", "rt", Some(1)) {
            DeathOutcome::Quarantined(detail) => assert_eq!(detail.retry_after_secs, 200),
            other => panic!("unexpected {:?}", other),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn deaths_spread_beyond_the_window_do_not_quarantine() {
        let health = RuntimeHealth::new(config());

        for _ in 0..5 {
            assert!(matches!(
                health.record_death("exec-rt", "rt", Some(1)),
                DeathOutcome::Recorded { .. }
            ));
            tokio::time::advance(Duration::from_secs(61)).await;
        }
        assert_eq!(health.active_quarantine("exec-rt"), None);
        assert_eq!(health.restart_wait("exec-rt"), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn quarantine_expires_once_and_clears_history() {
        let health = RuntimeHealth::new(config());
        for _ in 0..3 {
            health.record_death("exec-rt", "rt", Some(1));
        }
        assert!(matches!(
            health.quarantine_state("exec-rt"),
            QuarantineState::Active(_)
        ));

        tokio::time::advance(Duration::from_secs(299)).await;
        assert!(matches!(
            health.quarantine_state("exec-rt"),
            QuarantineState::Active(_)
        ));

        tokio::time::advance(Duration::from_secs(2)).await;
        assert_eq!(health.quarantine_state("exec-rt"), QuarantineState::Expired);
        assert_eq!(health.quarantine_state("exec-rt"), QuarantineState::None);
        assert!(health.deaths("exec-rt").is_empty());

        // A single death after expiry starts a fresh count.
        assert!(matches!(
            health.record_death("exec-rt", "rt", Some(1)),
            DeathOutcome::Recorded {
                deaths_in_window: 1,
                ..
            }
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn unreachable_marker_expires() {
        let health = RuntimeHealth::new(config());
        assert_eq!(health.unreachable_remaining("exec-rt"), None);

        health.mark_unreachable("exec-rt", Duration::from_secs(10));
        assert_eq!(
            health.unreachable_remaining("exec-rt"),
            Some(Duration::from_secs(10))
        );

        tokio::time::advance(Duration::from_secs(11)).await;
        assert_eq!(health.unreachable_remaining("exec-rt"), None);

        health.mark_unreachable("exec-rt", Duration::from_secs(10));
        health.clear_unreachable("exec-rt");
        assert_eq!(health.unreachable_remaining("exec-rt"), None);
    }

    #[test]
    fn death_history_is_bounded() {
        let health = RuntimeHealth::new(CrashLoopConfig {
            crash_loop_threshold: 1_000,
            ..config()
        });
        for code in 0..40 {
            health.record_death("exec-rt", "rt", Some(code));
        }
        let deaths = health.deaths("exec-rt");
        assert_eq!(deaths.len(), MAX_DEATH_HISTORY);
        assert_eq!(deaths.last().unwrap().exit_code, Some(39));
    }

    #[test]
    fn config_from_executor_config_reads_the_knobs() {
        let mut config = ExecutorConfig::from_env();
        config.restart_backoff_max_secs = 12;
        config.crash_loop_threshold = 5;
        config.crash_loop_window_secs = 90;
        config.quarantine_secs = 45;

        let parsed = CrashLoopConfig::from_executor_config(&config);
        assert_eq!(parsed.restart_backoff_max, Duration::from_secs(12));
        assert_eq!(parsed.crash_loop_threshold, 5);
        assert_eq!(parsed.crash_loop_window, Duration::from_secs(90));
        assert_eq!(parsed.quarantine, Duration::from_secs(45));
    }
}
