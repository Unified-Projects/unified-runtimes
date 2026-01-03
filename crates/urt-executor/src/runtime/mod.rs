//! Runtime management module

mod keep_alive;
mod protocol;
mod registry;
#[allow(clippy::module_inception)]
mod runtime;

pub use keep_alive::KeepAliveRegistry;
#[allow(unused_imports)]
pub use protocol::{
    get_protocol, ExecuteRequest, ExecuteResponse, RuntimeProtocol, V2Protocol, V5Protocol,
};
pub use registry::RuntimeRegistry;
pub use runtime::Runtime;
