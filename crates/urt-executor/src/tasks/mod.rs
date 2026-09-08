//! Background tasks module

pub mod docker_events;
mod listening_watch;
mod maintenance;
mod stats;
mod warmup;

pub use docker_events::run_docker_events;
#[allow(unused_imports)]
pub use listening_watch::{
    reap_failed_runtimes, run_listening_watch, sweep_listening_state, ListeningWatchHandles,
};
#[allow(unused_imports)]
pub use maintenance::{
    adopt_container_by_name, adopt_existing_containers, cleanup_idle, cleanup_stale_pending,
    run_maintenance, MaintenanceHandles,
};
pub use stats::run_stats_collector;
pub use warmup::run_warmup;
