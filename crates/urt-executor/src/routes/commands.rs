//! Command execution endpoint

use super::AppState;
use crate::error::{ExecutorError, Result};
use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

/// Request body for command execution
#[derive(Debug, Deserialize)]
pub struct CommandRequest {
    pub command: String,
    #[serde(default = "default_timeout")]
    pub timeout: u32,
}

fn default_timeout() -> u32 {
    600
}

/// Validate command for potentially dangerous patterns
/// This prevents command injection and unintended shell behavior
fn validate_command(command: &str) -> Result<()> {
    // Check for shell metacharacters that could enable injection
    let dangerous_patterns = [
        ("$(", "command substitution"),
        ("`", "backtick command substitution"),
        ("&&", "command chaining (AND)"),
        ("||", "command chaining (OR)"),
        (";", "command separator"),
        ("|", "pipe"),
        (">", "output redirection"),
        ("<", "input redirection"),
        (">>", "append redirection"),
        ("\n", "newline"),
        ("\r", "carriage return"),
        ("\0", "null byte"),
    ];

    for (pattern, description) in dangerous_patterns {
        if command.contains(pattern) {
            return Err(ExecutorError::BadRequest(format!(
                "Command contains disallowed pattern: {} ({})",
                if pattern == "\n" || pattern == "\r" || pattern == "\0" {
                    description
                } else {
                    pattern
                },
                description
            )));
        }
    }

    // Validate command doesn't start with dash (option injection for many commands)
    let first_word = command.split_whitespace().next().unwrap_or("");
    if first_word.starts_with('-') {
        return Err(ExecutorError::BadRequest(
            "Command cannot start with dash (potential option injection)".to_string(),
        ));
    }

    // Check for suspicious environment variable references that could be exploited
    if command.contains("$((") || command.contains("${") {
        return Err(ExecutorError::BadRequest(
            "Command contains suspicious variable expansion".to_string(),
        ));
    }

    Ok(())
}

/// Response for command execution
#[derive(Debug, Serialize)]
pub struct CommandResponse {
    pub output: String,
}

/// POST /v1/runtimes/:runtime_id/commands - Execute a command
pub async fn exec_command(
    State(state): State<AppState>,
    Path(runtime_id): Path<String>,
    Json(req): Json<CommandRequest>,
) -> Result<Json<CommandResponse>> {
    let full_name = format!("{}-{}", state.config.hostname, runtime_id);

    info!("Executing command in {}: {}", full_name, req.command);

    // Check if runtime exists
    if !state.registry.exists(&full_name).await {
        return Err(ExecutorError::RuntimeNotFound);
    }

    // Validate command length
    if req.command.is_empty() || req.command.len() > 1024 {
        return Err(ExecutorError::BadRequest(
            "Command must be between 1 and 1024 characters".to_string(),
        ));
    }

    // Validate command for injection attacks
    validate_command(&req.command)?;

    // Execute command
    let result = state
        .docker
        .exec_shell(&full_name, &req.command, req.timeout as u64)
        .await?;

    debug!("Command exited with code {}", result.exit_code);

    if result.exit_code != 0 {
        return Err(ExecutorError::CommandFailed(format!(
            "Command exited with code {}: {}",
            result.exit_code, result.stderr
        )));
    }

    Ok(Json(CommandResponse {
        output: result.stdout,
    }))
}
