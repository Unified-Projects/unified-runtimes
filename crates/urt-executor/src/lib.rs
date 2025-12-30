//! URT Executor - Drop-in Rust replacement for OpenRuntimes Executor
//!
//! This crate provides a high-performance executor for managing containerized
//! function runtimes with full API compatibility with the PHP OpenRuntimes Executor.

pub mod config;
pub mod docker;
pub mod error;
pub mod middleware;
pub mod routes;
pub mod runtime;
pub mod storage;
pub mod tasks;

pub use config::ExecutorConfig;
pub use error::{ExecutorError, Result};
pub use runtime::{Runtime, RuntimeRegistry};
