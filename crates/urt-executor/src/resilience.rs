//! Retry and transient-failure resilience utilities.

use crate::error::{ExecutorError, Result};
use crate::telemetry::metrics;
use rand::Rng;
use std::future::Future;
use std::time::Duration;
use tracing::debug;

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    let lowered = haystack.to_ascii_lowercase();
    needles.iter().any(|needle| lowered.contains(needle))
}

pub fn is_transient_error(error: &ExecutorError) -> bool {
    match error {
        ExecutorError::Network(message) => contains_any(
            message,
            &[
                "timed out",
                "timeout",
                "connection reset",
                "connection refused",
                "temporarily unavailable",
                "broken pipe",
                "eof",
                "tls",
                "502",
                "503",
                "504",
                "429",
            ],
        ),
        ExecutorError::Storage(message) => contains_any(
            message,
            &[
                "slowdown",
                "requesttimeout",
                "temporarily unavailable",
                "throttl",
                "connection reset",
                "timeout",
                "503",
                "500",
            ],
        ),
        ExecutorError::Docker(message) => {
            if contains_any(
                message,
                &[
                    "no such container",
                    "not found",
                    "already exists",
                    "conflict",
                    "invalid",
                ],
            ) {
                return false;
            }
            contains_any(
                message,
                &[
                    "timed out",
                    "timeout",
                    "temporarily unavailable",
                    "connection reset",
                    "connection refused",
                    "broken pipe",
                    "context deadline exceeded",
                    "i/o timeout",
                    "too many requests",
                    "429",
                    "500",
                    "502",
                    "503",
                    "504",
                    "eof",
                ],
            )
        }
        _ => false,
    }
}

pub fn retry_delay_with_jitter(base_delay_ms: u64, attempt: u32) -> Duration {
    let base = base_delay_ms.max(1);
    let capped_power = attempt.saturating_sub(1).min(6);
    let exponential = base.saturating_mul(1u64 << capped_power);
    let jitter_max = (exponential / 5).max(1);
    let jitter = rand::rng().random_range(0..=jitter_max);
    Duration::from_millis(exponential.saturating_add(jitter))
}

pub async fn retry_with_backoff<T, F, Fut>(
    operation: &'static str,
    max_attempts: u32,
    base_delay_ms: u64,
    mut operation_fn: F,
) -> Result<T>
where
    F: FnMut(u32) -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let attempts = max_attempts.max(1);
    let mut attempt = 1;
    loop {
        match operation_fn(attempt).await {
            Ok(value) => {
                if attempt == 1 {
                    metrics().inc_retry(operation, "success");
                } else {
                    metrics().inc_retry(operation, "success_after_retry");
                }
                return Ok(value);
            }
            Err(error) => {
                let retryable = is_transient_error(&error);
                if !retryable || attempt >= attempts {
                    metrics().inc_retry(operation, "failed");
                    return Err(error);
                }

                metrics().inc_retry(operation, "retry");
                let delay = retry_delay_with_jitter(base_delay_ms, attempt);
                debug!(
                    operation,
                    attempt,
                    max_attempts = attempts,
                    retry_in_ms = delay.as_millis() as u64,
                    error = %error,
                    "Retrying transient failure"
                );
                tokio::time::sleep(delay).await;
                attempt += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_such_container_is_not_retryable() {
        let err = ExecutorError::Docker("No such container: exc1-some-id".to_string());
        assert!(!is_transient_error(&err));
    }

    #[test]
    fn test_network_timeout_is_retryable() {
        let err = ExecutorError::Network("connection reset by peer".to_string());
        assert!(is_transient_error(&err));
    }

    #[test]
    fn test_storage_slowdown_is_retryable() {
        let err = ExecutorError::Storage("S3 SlowDown throttling".to_string());
        assert!(is_transient_error(&err));
    }

    #[test]
    fn test_retry_delay_with_jitter_bounds() {
        let base = 100;
        let attempt_1 = retry_delay_with_jitter(base, 1);
        assert!(attempt_1 >= Duration::from_millis(100));
        assert!(attempt_1 <= Duration::from_millis(120));

        let attempt_3 = retry_delay_with_jitter(base, 3);
        assert!(attempt_3 >= Duration::from_millis(400));
        assert!(attempt_3 <= Duration::from_millis(480));
    }

    #[tokio::test]
    async fn test_retry_with_backoff_succeeds_after_retry() {
        let mut attempts = 0;
        let result = retry_with_backoff("test_retry", 3, 1, |_| {
            attempts += 1;
            async move {
                if attempts < 2 {
                    Err(ExecutorError::Network("timeout".to_string()))
                } else {
                    Ok(42)
                }
            }
        })
        .await
        .expect("retry should eventually succeed");
        assert_eq!(result, 42);
        assert_eq!(attempts, 2);
    }
}
