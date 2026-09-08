//! Background tasks module

mod listening_watch;
mod maintenance;
mod stats;
mod warmup;

pub use listening_watch::run_listening_watch;
pub use maintenance::{adopt_container_by_name, adopt_existing_containers, run_maintenance};
pub use stats::run_stats_collector;
pub use warmup::run_warmup;
