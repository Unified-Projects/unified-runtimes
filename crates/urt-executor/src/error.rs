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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    /// Verify all error types have correct error_type mapping
    #[test]
    fn test_error_types_mapping() {
        assert_eq!(ExecutorError::Unknown.error_type(), "general_unknown");
        assert_eq!(
            ExecutorError::RouteNotFound.error_type(),
            "general_route_not_found"
        );
        assert_eq!(
            ExecutorError::Unauthorized.error_type(),
            "general_unauthorized"
        );
        assert_eq!(
            ExecutorError::BadRequest("test".to_string()).error_type(),
            "general_bad_request"
        );
        assert_eq!(
            ExecutorError::ExecutionBadRequest("test".to_string()).error_type(),
            "execution_bad_request"
        );
        assert_eq!(
            ExecutorError::ExecutionBadJson("test".to_string()).error_type(),
            "execution_bad_json"
        );
        assert_eq!(
            ExecutorError::ExecutionTimeout.error_type(),
            "execution_timeout"
        );
        assert_eq!(
            ExecutorError::RuntimeNotFound.error_type(),
            "runtime_not_found"
        );
        assert_eq!(
            ExecutorError::RuntimeConflict.error_type(),
            "runtime_conflict"
        );
        assert_eq!(
            ExecutorError::RuntimeFailed("test".to_string()).error_type(),
            "runtime_failed"
        );
        assert_eq!(
            ExecutorError::RuntimeTimeout.error_type(),
            "runtime_timeout"
        );
        assert_eq!(ExecutorError::LogsTimeout.error_type(), "logs_timeout");
        assert_eq!(
            ExecutorError::CommandTimeout.error_type(),
            "command_timeout"
        );
        assert_eq!(
            ExecutorError::CommandFailed("test".to_string()).error_type(),
            "command_failed"
        );
        assert_eq!(
            ExecutorError::Docker("test".to_string()).error_type(),
            "general_unknown"
        );
        assert_eq!(
            ExecutorError::Storage("test".to_string()).error_type(),
            "general_unknown"
        );
        assert_eq!(
            ExecutorError::Network("test".to_string()).error_type(),
            "general_unknown"
        );
    }

    /// Verify all error types have correct HTTP status codes
    #[test]
    fn test_error_status_codes() {
        assert_eq!(
            ExecutorError::Unknown.status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            ExecutorError::RouteNotFound.status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            ExecutorError::Unauthorized.status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            ExecutorError::BadRequest("test".to_string()).status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            ExecutorError::ExecutionBadRequest("test".to_string()).status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            ExecutorError::ExecutionBadJson("test".to_string()).status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            ExecutorError::ExecutionTimeout.status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            ExecutorError::RuntimeNotFound.status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            ExecutorError::RuntimeConflict.status_code(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            ExecutorError::RuntimeFailed("test".to_string()).status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            ExecutorError::RuntimeTimeout.status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            ExecutorError::LogsTimeout.status_code(),
            StatusCode::GATEWAY_TIMEOUT
        );
        assert_eq!(
            ExecutorError::CommandTimeout.status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            ExecutorError::CommandFailed("test".to_string()).status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            ExecutorError::Docker("test".to_string()).status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            ExecutorError::Storage("test".to_string()).status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            ExecutorError::Network("test".to_string()).status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    /// Verify error response format matches AppWrite executor format
    #[tokio::test]
    async fn test_error_response_format() {
        let error = ExecutorError::Unauthorized;
        let response = error.into_response();

        let status = response.status();
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // Extract body and verify structure
        let body = response.into_body();
        let bytes = to_bytes(body, 1024 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(json["code"], 401);
        assert_eq!(json["type"], "general_unauthorized");
        assert!(json["message"].is_string());
    }

    /// Verify error with message contains the message
    #[tokio::test]
    async fn test_error_message_preserved() {
        let error = ExecutorError::BadRequest("custom error message".to_string());
        let response = error.into_response();

        let body = response.into_body();
        let bytes = to_bytes(body, 1024 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert!(json["message"]
            .as_str()
            .unwrap()
            .contains("custom error message"));
    }

    /// Verify From implementations work correctly
    #[test]
    fn test_from_impls() {
        // Test From<std::io::Error>
        let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let executor_error: ExecutorError = io_error.into();
        matches!(executor_error, ExecutorError::Storage(_));

        // Test From<serde_json::Error>
        let json_error = serde_json::from_str::<serde_json::Value>("invalid json").unwrap_err();
        let executor_error: ExecutorError = json_error.into();
        matches!(executor_error, ExecutorError::ExecutionBadJson(_));

        // Test From<Box<dyn Error>>
        let boxed_error: Box<dyn std::error::Error + Send + Sync> =
            Box::new(std::io::Error::other("test"));
        let executor_error: ExecutorError = boxed_error.into();
        matches!(executor_error, ExecutorError::Unknown);

        // Test From<anyhow::Error>
        let anyhow_error = anyhow::anyhow!("test error");
        let executor_error: ExecutorError = anyhow_error.into();
        matches!(executor_error, ExecutorError::Unknown);
    }

    /// Verify error Display impl generates expected messages
    #[test]
    fn test_error_display() {
        assert_eq!(ExecutorError::Unknown.to_string(), "Internal server error");
        assert_eq!(
            ExecutorError::RouteNotFound.to_string(),
            "The requested route was not found"
        );
        assert_eq!(
            ExecutorError::Unauthorized.to_string(),
            "Missing or invalid executor key"
        );
        assert_eq!(
            ExecutorError::RuntimeNotFound.to_string(),
            "Runtime not found"
        );
        assert_eq!(
            ExecutorError::RuntimeConflict.to_string(),
            "A runtime with the same ID is already being created"
        );
        assert_eq!(
            ExecutorError::ExecutionTimeout.to_string(),
            "Timed out waiting for execution"
        );
    }
}
