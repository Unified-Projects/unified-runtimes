//! Container exec operations

use crate::error::{ExecutorError, Result};
use bollard::container::LogOutput;
use bollard::exec::{CreateExecOptions, StartExecResults};
use bollard::Docker;
use futures_util::StreamExt;
use std::time::Duration;
use tracing::{debug, warn};

/// Default buffer capacity for exec output (4KB)
/// Pre-allocating avoids repeated reallocations during output streaming
const EXEC_OUTPUT_INITIAL_CAPACITY: usize = 4096;

/// Result of executing a command in a container
#[derive(Debug, Clone)]
pub struct ExecResult {
    pub exit_code: i64,
    pub stdout: String,
    pub stderr: String,
}

/// Execute a command inside a running container
pub async fn exec_command(
    docker: &Docker,
    container_name: &str,
    command: &[&str],
    timeout_secs: u64,
) -> Result<ExecResult> {
    debug!("Executing command in {}: {:?}", container_name, command);

    // Create exec instance
    let exec = docker
        .create_exec(
            container_name,
            CreateExecOptions {
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                cmd: Some(command.iter().map(|s| s.to_string()).collect()),
                ..Default::default()
            },
        )
        .await
        .map_err(|e| ExecutorError::Docker(e.to_string()))?;

    // Start exec and collect output
    let start_result = docker
        .start_exec(&exec.id, None)
        .await
        .map_err(|e| ExecutorError::Docker(e.to_string()))?;

    // Pre-allocate buffers to avoid repeated reallocations during streaming
    let mut stdout = String::with_capacity(EXEC_OUTPUT_INITIAL_CAPACITY);
    let mut stderr = String::with_capacity(EXEC_OUTPUT_INITIAL_CAPACITY);

    if let StartExecResults::Attached { mut output, .. } = start_result {
        let timeout = tokio::time::timeout(Duration::from_secs(timeout_secs), async {
            while let Some(msg) = output.next().await {
                match msg {
                    Ok(LogOutput::StdOut { message }) => {
                        stdout.push_str(&String::from_utf8_lossy(&message));
                    }
                    Ok(LogOutput::StdErr { message }) => {
                        stderr.push_str(&String::from_utf8_lossy(&message));
                    }
                    Ok(_) => {}
                    Err(e) => {
                        warn!("Error reading exec output: {}", e);
                        break;
                    }
                }
            }
        });

        if timeout.await.is_err() {
            return Err(ExecutorError::CommandTimeout);
        }
    }

    // Get exit code
    let inspect = docker
        .inspect_exec(&exec.id)
        .await
        .map_err(|e| ExecutorError::Docker(e.to_string()))?;

    let exit_code = inspect.exit_code.unwrap_or(-1);

    debug!("Command exited with code {}", exit_code);

    Ok(ExecResult {
        exit_code,
        stdout,
        stderr,
    })
}

/// Execute a shell command (wraps in sh -c)
/// Used for v2 runtimes
pub async fn exec_shell(
    docker: &Docker,
    container_name: &str,
    command: &str,
    timeout_secs: u64,
) -> Result<ExecResult> {
    exec_command(docker, container_name, &["sh", "-c", command], timeout_secs).await
}

/// Execute a bash command (wraps in bash -c)
/// Used for v5 runtimes - matches executor-main behavior
pub async fn exec_bash(
    docker: &Docker,
    container_name: &str,
    command: &str,
    timeout_secs: u64,
) -> Result<ExecResult> {
    exec_command(
        docker,
        container_name,
        &["bash", "-c", command],
        timeout_secs,
    )
    .await
}
