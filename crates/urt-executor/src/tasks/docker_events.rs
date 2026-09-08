//! Docker events subscription for runtime container deaths.
//!
//! Subscribes to the daemon's event stream for managed containers belonging to
//! this executor and hands `die` and `destroy` events to the shared
//! dead-runtime handling, so a crashed runtime is dealt with when it happens
//! rather than when the next execution trips over it. The stream is re-opened
//! with backoff whenever it ends.

use crate::routes::AppState;
use crate::runtime::liveness::{self, DeathHandling};
use bollard::models::{EventMessage, EventMessageTypeEnum};
use bollard::query_parameters::EventsOptions;
use futures_util::StreamExt;
use std::collections::HashMap;
use std::collections::HashSet;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{debug, info, warn};

const RECONNECT_BACKOFF_MIN: Duration = Duration::from_secs(1);
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(30);

/// A stream that stayed open at least this long resets the reconnect backoff.
const STABLE_STREAM_AGE: Duration = Duration::from_secs(60);

/// Container lifecycle actions the task subscribes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerEventKind {
    Die,
    Oom,
    Stop,
    Kill,
    Destroy,
}

impl ContainerEventKind {
    pub const ALL: [ContainerEventKind; 5] = [
        ContainerEventKind::Die,
        ContainerEventKind::Oom,
        ContainerEventKind::Stop,
        ContainerEventKind::Kill,
        ContainerEventKind::Destroy,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ContainerEventKind::Die => "die",
            ContainerEventKind::Oom => "oom",
            ContainerEventKind::Stop => "stop",
            ContainerEventKind::Kill => "kill",
            ContainerEventKind::Destroy => "destroy",
        }
    }

    fn parse(action: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == action)
    }
}

/// A container event that concerns one of this executor's runtimes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerEvent {
    pub kind: ContainerEventKind,
    /// Container name, which is the registry key.
    pub name: String,
    /// Exit code carried by `die` events.
    pub exit_code: Option<i64>,
}

/// What the task did with an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventDisposition {
    Death(DeathHandling),
    OomNoted,
    Skipped(&'static str),
}

fn attribute<'a>(attributes: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    attributes
        .get(key)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
}

/// Whether the event's container belongs to this executor, by label or by
/// the `{hostname}-` name prefix, mirroring the maintenance sweep.
fn belongs_to_hostname(attributes: &HashMap<String, String>, name: &str, hostname: &str) -> bool {
    match attribute(attributes, "urt.executor_hostname") {
        Some(owner) => owner == hostname,
        None => name.starts_with(&format!("{}-", hostname)),
    }
}

/// Extract the runtime-relevant part of a Docker event, or `None` when the
/// event is not a lifecycle action on one of this executor's managed
/// containers.
pub fn parse_container_event(event: &EventMessage, hostname: &str) -> Option<ContainerEvent> {
    if event.typ != Some(EventMessageTypeEnum::CONTAINER) {
        return None;
    }
    let kind = ContainerEventKind::parse(event.action.as_deref()?)?;
    let actor = event.actor.as_ref()?;
    let attributes = actor.attributes.as_ref()?;

    if !attribute(attributes, "urt.managed").is_some_and(|value| value.eq_ignore_ascii_case("true"))
    {
        return None;
    }
    let name = attribute(attributes, "name")?.to_string();
    if !belongs_to_hostname(attributes, &name, hostname) {
        return None;
    }

    let exit_code = attribute(attributes, "exitCode").and_then(|code| code.parse::<i64>().ok());

    Some(ContainerEvent {
        kind,
        name,
        exit_code,
    })
}

/// Names that reported an OOM kill and have not yet reported the matching
/// `die`, so the exit can be logged with its cause.
#[derive(Debug, Default)]
pub struct OomTracker {
    pending: HashSet<String>,
}

impl OomTracker {
    pub fn note(&mut self, name: &str) {
        self.pending.insert(name.to_string());
    }

    pub fn take(&mut self, name: &str) -> bool {
        self.pending.remove(name)
    }
}

/// Apply one parsed event to the executor state.
pub async fn apply_container_event(
    state: &AppState,
    oom: &mut OomTracker,
    event: ContainerEvent,
) -> EventDisposition {
    match event.kind {
        ContainerEventKind::Oom => {
            oom.note(&event.name);
            EventDisposition::OomNoted
        }
        ContainerEventKind::Die => {
            let oom_killed = oom.take(&event.name);
            let handling =
                liveness::handle_container_death(state, &event.name, event.exit_code, oom_killed)
                    .await;
            EventDisposition::Death(handling)
        }
        ContainerEventKind::Destroy => {
            oom.take(&event.name);
            let handling = liveness::handle_container_destroyed(state, &event.name).await;
            EventDisposition::Death(handling)
        }
        ContainerEventKind::Stop | ContainerEventKind::Kill => {
            EventDisposition::Skipped("die follows")
        }
    }
}

fn events_options() -> EventsOptions {
    let mut filters: HashMap<String, Vec<String>> = HashMap::new();
    filters.insert("type".to_string(), vec!["container".to_string()]);
    filters.insert(
        "event".to_string(),
        ContainerEventKind::ALL
            .iter()
            .map(|kind| kind.as_str().to_string())
            .collect(),
    );
    filters.insert("label".to_string(), vec!["urt.managed=true".to_string()]);
    EventsOptions {
        since: None,
        until: None,
        filters: Some(filters),
    }
}

/// Run the events subscription until shutdown.
pub async fn run_docker_events(state: AppState, mut shutdown: watch::Receiver<bool>) {
    let hostname = state.config.hostname.clone();
    let mut backoff = RECONNECT_BACKOFF_MIN;
    let mut oom = OomTracker::default();

    info!("Starting Docker events subscription for runtime container deaths");

    loop {
        let opened_at = tokio::time::Instant::now();
        let mut stream = state.docker.client().events(Some(events_options()));
        debug!("Docker events stream opened");

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("Shutdown signal received, stopping Docker events subscription");
                        return;
                    }
                }
                item = stream.next() => {
                    match item {
                        Some(Ok(event)) => {
                            if let Some(parsed) = parse_container_event(&event, &hostname) {
                                debug!(
                                    runtime = %parsed.name,
                                    action = parsed.kind.as_str(),
                                    exit_code = ?parsed.exit_code,
                                    "Docker container event"
                                );
                                let disposition =
                                    apply_container_event(&state, &mut oom, parsed.clone()).await;
                                debug!(
                                    runtime = %parsed.name,
                                    disposition = ?disposition,
                                    "Docker container event handled"
                                );
                            }
                        }
                        Some(Err(error)) => {
                            warn!("Docker events stream failed: {}", error);
                            break;
                        }
                        None => {
                            warn!("Docker events stream ended");
                            break;
                        }
                    }
                }
            }
        }

        if opened_at.elapsed() >= STABLE_STREAM_AGE {
            backoff = RECONNECT_BACKOFF_MIN;
        }
        info!("Reconnecting to Docker events in {}s", backoff.as_secs());
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
            }
            _ = tokio::time::sleep(backoff) => {}
        }
        backoff = (backoff * 2).min(RECONNECT_BACKOFF_MAX);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bollard::models::EventActor;

    fn event(action: &str, attributes: &[(&str, &str)]) -> EventMessage {
        EventMessage {
            typ: Some(EventMessageTypeEnum::CONTAINER),
            action: Some(action.to_string()),
            actor: Some(EventActor {
                id: Some("abc".to_string()),
                attributes: Some(
                    attributes
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect(),
                ),
            }),
            scope: None,
            time: None,
            time_nano: None,
        }
    }

    #[test]
    fn parses_a_die_event_for_a_managed_runtime() {
        let parsed = parse_container_event(
            &event(
                "die",
                &[
                    ("name", "exc1-fn-1"),
                    ("urt.managed", "true"),
                    ("urt.executor_hostname", "exc1"),
                    ("exitCode", "134"),
                ],
            ),
            "exc1",
        )
        .expect("event must parse");

        assert_eq!(parsed.kind, ContainerEventKind::Die);
        assert_eq!(parsed.name, "exc1-fn-1");
        assert_eq!(parsed.exit_code, Some(134));
    }

    #[test]
    fn ignores_events_for_other_executors_and_unmanaged_containers() {
        assert!(parse_container_event(
            &event(
                "die",
                &[
                    ("name", "exc2-fn-1"),
                    ("urt.managed", "true"),
                    ("urt.executor_hostname", "exc2"),
                ],
            ),
            "exc1",
        )
        .is_none());

        assert!(parse_container_event(
            &event("die", &[("name", "exc1-fn-1"), ("exitCode", "1")]),
            "exc1",
        )
        .is_none());
    }

    #[test]
    fn falls_back_to_the_name_prefix_when_the_hostname_label_is_missing() {
        let parsed = parse_container_event(
            &event("destroy", &[("name", "exc1-fn-1"), ("urt.managed", "true")]),
            "exc1",
        )
        .expect("prefix match");
        assert_eq!(parsed.kind, ContainerEventKind::Destroy);
        assert_eq!(parsed.exit_code, None);
    }

    #[test]
    fn ignores_non_container_and_unrelated_actions() {
        let mut image = event("die", &[("name", "exc1-fn-1"), ("urt.managed", "true")]);
        image.typ = Some(EventMessageTypeEnum::IMAGE);
        assert!(parse_container_event(&image, "exc1").is_none());

        assert!(parse_container_event(
            &event("start", &[("name", "exc1-fn-1"), ("urt.managed", "true")]),
            "exc1",
        )
        .is_none());
    }

    #[test]
    fn events_filter_covers_every_subscribed_action() {
        let options = events_options();
        let filters = options.filters.expect("filters");
        assert_eq!(filters["type"], vec!["container".to_string()]);
        assert_eq!(filters["label"], vec!["urt.managed=true".to_string()]);
        let mut actions = filters["event"].clone();
        actions.sort();
        assert_eq!(actions, vec!["destroy", "die", "kill", "oom", "stop"]);
    }

    #[test]
    fn oom_tracker_pairs_an_oom_with_the_following_die() {
        let mut tracker = OomTracker::default();
        tracker.note("exc1-fn-1");
        assert!(tracker.take("exc1-fn-1"));
        assert!(!tracker.take("exc1-fn-1"));
    }
}
