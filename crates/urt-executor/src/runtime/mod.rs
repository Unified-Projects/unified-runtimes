//! Runtime management module

mod adoption;
pub mod concurrency;
pub(crate) mod create_tracker;
mod keep_alive;
mod protocol;
pub(crate) mod readiness;
mod registry;
#[allow(clippy::module_inception)]
mod runtime;

pub use adoption::AdoptionNegativeCache;
pub use concurrency::RuntimeConcurrency;
pub use create_tracker::CreateTracker;
pub use keep_alive::KeepAliveRegistry;
#[allow(unused_imports)]
pub use protocol::{
    get_protocol, runtime_network_host, ExecuteRequest, ExecuteResponse, RuntimeProtocol,
    V2Protocol, V5Protocol,
};
pub use registry::RuntimeRegistry;
#[allow(unused_imports)]
pub use runtime::{
    is_runtime_listening, wait_for_runtime_port, Runtime, RuntimeLifecycle, RuntimeState,
    DEFAULT_INACTIVE_THRESHOLD_SECS, DEFAULT_STARTUP_TIMEOUT_SECS, RUNTIME_PORT,
};
