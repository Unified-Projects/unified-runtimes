//! Error types for the URT Executor
//!
//! These error types match the PHP executor's error codes for drop-in compatibility.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

/// Main error type for the executor
#[derive(Debug, Error)]
pub enum ExecutorError {
    #[error("Internal server error")]
    Unknown,

    #[error("The requested route was not found")]
    RouteNotFound,

    #[error("Missing or invalid executor key")]
    Unauthorized,

    #[error("{0}")]
    BadRequest(String),

    #[error("Execution request was invalid: {0}")]
    ExecutionBadRequest(String),

    #[error("Failed to parse JSON body: {0}")]
    ExecutionBadJson(String),

    #[error("Timed out waiting for execution")]
    ExecutionTimeout,

    #[error("Runtime not found")]
    RuntimeNotFound,

    #[error("A runtime with the same ID is already being created")]
    RuntimeConflict,

    #[error("{0}")]
    RuntimeFailed(String),

    #[error("Timed out waiting for runtime")]
    RuntimeTimeout,

    #[error("Timed out waiting for logs")]
    LogsTimeout,

    #[error("Operation timed out")]
    CommandTimeout,

    #[error("Failed to execute command: {0}")]
    CommandFailed(String),

    #[error("Docker error: {0}")]
    Docker(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Network error: {0}")]
    Network(String),
}

impl ExecutorError {
    /// Get the error type string (matching PHP)
    pub fn error_type(&self) -> &'static str {
        match self {
            Self::Unknown => "general_unknown",
            Self::RouteNotFound => "general_route_not_found",
            Self::Unauthorized => "general_unauthorized",
            Self::BadRequest(_) => "general_bad_request",
            Self::ExecutionBadRequest(_) => "execution_bad_request",
            Self::ExecutionBadJson(_) => "execution_bad_json",
            Self::ExecutionTimeout => "execution_timeout",
            Self::RuntimeNotFound => "runtime_not_found",
            Self::RuntimeConflict => "runtime_conflict",
            Self::RuntimeFailed(_) => "runtime_failed",
            Self::RuntimeTimeout => "runtime_timeout",
            Self::LogsTimeout => "logs_timeout",
            Self::CommandTimeout => "command_timeout",
            Self::CommandFailed(_) => "command_failed",
            Self::Docker(_) => "general_unknown",
            Self::Storage(_) => "general_unknown",
            Self::Network(_) => "general_unknown",
        }
    }

    /// Get the HTTP status code
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Unknown => StatusCode::INTERNAL_SERVER_ERROR,
            Self::RouteNotFound => StatusCode::NOT_FOUND,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::ExecutionBadRequest(_) => StatusCode::BAD_REQUEST,
            Self::ExecutionBadJson(_) => StatusCode::BAD_REQUEST,
            Self::ExecutionTimeout => StatusCode::BAD_REQUEST,
            Self::RuntimeNotFound => StatusCode::NOT_FOUND,
            Self::RuntimeConflict => StatusCode::CONFLICT,
            Self::RuntimeFailed(_) => StatusCode::BAD_REQUEST,
            Self::RuntimeTimeout => StatusCode::BAD_REQUEST,
            Self::LogsTimeout => StatusCode::GATEWAY_TIMEOUT,
            Self::CommandTimeout => StatusCode::INTERNAL_SERVER_ERROR,
            Self::CommandFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Docker(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Storage(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Network(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

/// JSON error response body
#[derive(Serialize)]
struct ErrorResponse {
    message: String,
    r#type: String,
    code: u16,
}

impl IntoResponse for ExecutorError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let body = ErrorResponse {
            message: self.to_string(),
            r#type: self.error_type().to_string(),
            code: status.as_u16(),
        };
        (status, Json(body)).into_response()
    }
}

impl From<bollard::errors::Error> for ExecutorError {
    fn from(err: bollard::errors::Error) -> Self {
        ExecutorError::Docker(err.to_string())
    }
}

impl From<std::io::Error> for ExecutorError {
    fn from(err: std::io::Error) -> Self {
        ExecutorError::Storage(err.to_string())
    }
}

impl From<reqwest::Error> for ExecutorError {
    fn from(err: reqwest::Error) -> Self {
        ExecutorError::Network(err.to_string())
    }
}

impl From<serde_json::Error> for ExecutorError {
    fn from(err: serde_json::Error) -> Self {
        ExecutorError::ExecutionBadJson(err.to_string())
    }
}

impl From<Box<dyn std::error::Error + Send + Sync>> for ExecutorError {
    fn from(_err: Box<dyn std::error::Error + Send + Sync>) -> Self {
        ExecutorError::Unknown
    }
}

impl From<anyhow::Error> for ExecutorError {
    fn from(_err: anyhow::Error) -> Self {
        ExecutorError::Unknown
    }
}

/// Result type alias for executor operations
pub type Result<T> = std::result::Result<T, ExecutorError>;
