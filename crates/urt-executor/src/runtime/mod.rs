//! Runtime management module

pub(crate) mod create_tracker;
pub mod health;
mod keep_alive;
pub mod liveness;
mod protocol;
pub(crate) mod readiness;
mod registry;
#[allow(clippy::module_inception)]
mod runtime;

pub use create_tracker::CreateTracker;
pub use health::{CrashLoopConfig, RuntimeHealth};
pub use keep_alive::KeepAliveRegistry;
#[allow(unused_imports)]
pub use protocol::{
    classify_transport_error, error_chain, get_protocol, runtime_network_host, transport_error_for,
    ExecuteRequest, ExecuteResponse, RuntimeProtocol, TransportFailure, V2Protocol, V5Protocol,
};
pub use registry::RuntimeRegistry;
pub use runtime::{wait_for_runtime_port, Runtime};
