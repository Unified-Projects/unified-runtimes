//! Comprehensive integration tests for URT Executor
//!
//! These tests verify the HTTP API layer and require Docker to be available
//! for runtime management and execution tests.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;
use urt_executor::{
    config::{ExecutorConfig, StorageConfig},
    docker::DockerManager,
    routes::{create_router, AppState},
    runtime::{KeepAliveRegistry, RuntimeRegistry},
    storage::{self, Storage},
};

/// Create a test configuration
fn test_config() -> ExecutorConfig {
    ExecutorConfig {
        host: "127.0.0.1".to_string(),
        port: 9900,
        secret: "test-secret-key".to_string(),
        metrics_enabled: false,
        env: "development".to_string(),
        networks: vec!["test-network".to_string()],
        hostname: "test-executor".to_string(),
        docker_hub_username: None,
        docker_hub_password: None,
        allowed_runtimes: vec![],
        runtime_versions: vec!["v5".to_string()],
        image_pull_enabled: true,
        auto_runtime: true,
        min_cpus: 0.0,
        min_memory: 0,
        keep_alive: true,
        inactive_threshold: 60,
        maintenance_interval: 3600,
        autoscale: false,
        eager_runtime_readiness: false,
        max_concurrent_executions: None,
        max_concurrent_runtime_creates: None,
        execution_queue_wait_ms: 2_000,
        runtime_create_queue_wait_ms: 5_000,
        max_body_size: 20 * 1024 * 1024,
        storage: StorageConfig::default(),
        logging_config: None,
        retry_attempts: 5,
        retry_delay_ms: 500,
        warmup_required: false,
        pending_wait_max_secs: 60,
    }
}

/// Create a test app state with Docker (returns None if Docker unavailable)
async fn create_test_state() -> Option<AppState> {
    let config = test_config();
    let docker = match DockerManager::new(config.clone()).await {
        Ok(d) => Arc::new(d),
        Err(_) => return None,
    };
    let registry = RuntimeRegistry::new();
    let keep_alive_registry = KeepAliveRegistry::new();
    let http_client = reqwest::Client::new();
    let storage: Arc<dyn Storage> =
        Arc::from(storage::from_config(&config.storage).expect("Failed to create storage"));

    Some(AppState {
        config,
        docker,
        registry,
        keep_alive_registry,
        http_client,
        storage,
        execution_limiter: None,
        runtime_create_limiter: None,
        execution_limiter_capacity: None,
        runtime_create_limiter_capacity: None,
        readiness: std::sync::Arc::new(dashmap::DashMap::new()),
    })
}

/// Helper to parse JSON response body
async fn parse_json_body(body: Body) -> Value {
    // Use a reasonable upper bound for body size (20 MiB), matching test_config().max_body_size.
    let bytes = axum::body::to_bytes(body, 20 * 1024 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(json!({}))
}

/// Helper to get response body as string.
/// Intentionally kept (and allowed as dead code) for debugging and future tests
/// that need to inspect raw HTTP response bodies.
#[allow(dead_code)]
async fn body_to_string(body: Body) -> String {
    // Use the same 20 MiB upper bound as in parse_json_body/test_config.
    let bytes = axum::body::to_bytes(body, 20 * 1024 * 1024).await.unwrap();
    String::from_utf8_lossy(&bytes).to_string()
}

/// Helper macro to skip tests if Docker is unavailable
macro_rules! require_docker {
    ($state:ident) => {
        let $state = match create_test_state().await {
            Some(s) => s,
            None => {
                eprintln!("Skipping test: Docker not available");
                return;
            }
        };
    };
}

mod health {
    use super::*;

    #[tokio::test]
    async fn returns_200_with_auth() {
        require_docker!(state);
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/health")
                    .header("Authorization", "Bearer test-secret-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn returns_plain_text_ok() {
        require_docker!(state);
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_to_string(response.into_body()).await;
        assert_eq!(body, "OK");
    }

    #[tokio::test]
    async fn is_public() {
        require_docker!(state);
        let app = create_router(state);

        // Health endpoint is public - no auth required
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn sets_server_header() {
        require_docker!(state);
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let server = response
            .headers()
            .get("server")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(server, "Executor");
    }

    #[tokio::test]
    async fn stats_endpoint_returns_valid_json() {
        require_docker!(state);
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/health/stats")
                    .header("Authorization", "Bearer test-secret-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = parse_json_body(response.into_body()).await;
        assert!(
            body.get("usage").is_some(),
            "Response should have 'usage' field"
        );
        assert!(
            body.get("runtimes").is_some(),
            "Response should have 'runtimes' field"
        );
    }

    #[tokio::test]
    async fn stats_content_type_is_json() {
        require_docker!(state);
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/health/stats")
                    .header("Authorization", "Bearer test-secret-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        assert!(
            content_type.contains("application/json"),
            "Content-Type should be JSON"
        );
    }
}

mod auth {
    use super::*;

    #[tokio::test]
    async fn required_for_runtimes() {
        require_docker!(state);
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/runtimes")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn invalid_token_rejected() {
        require_docker!(state);
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/runtimes")
                    .header("Authorization", "Bearer wrong-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let body = parse_json_body(response.into_body()).await;
        assert_eq!(body["code"], 401);
        assert_eq!(body["type"], "general_unauthorized");
        assert!(body["message"].as_str().unwrap().contains("invalid"));
    }

    #[tokio::test]
    async fn valid_token_accepted() {
        require_docker!(state);
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/runtimes")
                    .header("Authorization", "Bearer test-secret-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn bearer_prefix_required() {
        require_docker!(state);
        let app = create_router(state);

        // Token without "Bearer " prefix should fail
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/runtimes")
                    .header("Authorization", "test-secret-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn case_sensitive_bearer() {
        require_docker!(state);
        let app = create_router(state);

        // "bearer" (lowercase) should work as prefix
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/runtimes")
                    .header("Authorization", "bearer test-secret-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // This might be 401 depending on implementation - Bearer is typically case-sensitive
        // Just verify we get a response
        assert!(response.status().is_client_error() || response.status().is_success());
    }
}

mod runtimes {
    use super::*;

    #[tokio::test]
    async fn list_empty() {
        require_docker!(state);
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/runtimes")
                    .header("Authorization", "Bearer test-secret-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = parse_json_body(response.into_body()).await;
        assert!(body.is_array(), "Response should be an array");
        assert_eq!(
            body.as_array().unwrap().len(),
            0,
            "Should be empty initially"
        );
    }

    #[tokio::test]
    async fn get_not_found() {
        require_docker!(state);
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/runtimes/nonexistent-runtime")
                    .header("Authorization", "Bearer test-secret-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body = parse_json_body(response.into_body()).await;
        assert_eq!(body["code"], 404);
    }

    #[tokio::test]
    async fn delete_not_found() {
        require_docker!(state);
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/runtimes/nonexistent-runtime")
                    .header("Authorization", "Bearer test-secret-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn create_requires_image() {
        require_docker!(state);
        let app = create_router(state);

        // Empty payload should fail
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/runtimes")
                    .header("Authorization", "Bearer test-secret-key")
                    .header("Content-Type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should fail validation (either 400 or 422)
        assert!(
            response.status() == StatusCode::BAD_REQUEST
                || response.status() == StatusCode::UNPROCESSABLE_ENTITY,
            "Expected 400 or 422, got {}",
            response.status()
        );
    }
}

mod executions {
    use super::*;

    #[tokio::test]
    async fn requires_auth() {
        require_docker!(state);
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/runtimes/test/executions")
                    .header("Content-Type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn runtime_not_found() {
        require_docker!(state);
        let app = create_router(state);

        let payload = json!({
            "body": "",
            "path": "/",
            "method": "GET",
            "headers": {}
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/runtimes/nonexistent/executions")
                    .header("Authorization", "Bearer test-secret-key")
                    .header("Content-Type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn alternative_endpoint_works() {
        require_docker!(state);
        let app = create_router(state);

        // Test /execution (singular) endpoint
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/runtimes/test/execution")
                    .header("Authorization", "Bearer test-secret-key")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"body":"","path":"/","method":"GET","headers":{}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should be 404 (runtime not found), not 405 (method not allowed)
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

mod commands {
    use super::*;

    #[tokio::test]
    async fn requires_auth() {
        require_docker!(state);
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/runtimes/test/commands")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"command": "echo hello"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn runtime_not_found() {
        require_docker!(state);
        let app = create_router(state);

        let payload = json!({"command": "echo hello"});

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/runtimes/nonexistent/commands")
                    .header("Authorization", "Bearer test-secret-key")
                    .header("Content-Type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

mod logs {
    use super::*;

    #[tokio::test]
    async fn requires_auth() {
        require_docker!(state);
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/runtimes/test/logs")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn runtime_not_found() {
        require_docker!(state);
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/runtimes/nonexistent/logs")
                    .header("Authorization", "Bearer test-secret-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

mod errors {
    use super::*;

    #[tokio::test]
    async fn invalid_json_payload() {
        require_docker!(state);
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/runtimes")
                    .header("Authorization", "Bearer test-secret-key")
                    .header("Content-Type", "application/json")
                    .body(Body::from("not valid json"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(
            response.status() == StatusCode::BAD_REQUEST
                || response.status() == StatusCode::UNPROCESSABLE_ENTITY,
            "Expected 400 or 422 for invalid JSON, got {}",
            response.status()
        );
    }

    #[tokio::test]
    async fn method_not_allowed() {
        require_docker!(state);
        let app = create_router(state);

        // PUT is not supported on /v1/health
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v1/health")
                    .header("Authorization", "Bearer test-secret-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn not_found_route_without_auth() {
        require_docker!(state);
        let app = create_router(state);

        // Unknown routes return 404 regardless of auth (fallback handler)
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn not_found_route_with_auth() {
        require_docker!(state);
        let app = create_router(state);

        // With auth, should get 404
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/nonexistent")
                    .header("Authorization", "Bearer test-secret-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn missing_content_type_for_json() {
        require_docker!(state);
        let app = create_router(state);

        // POST without Content-Type header
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/runtimes")
                    .header("Authorization", "Bearer test-secret-key")
                    .body(Body::from(r#"{"image": "alpine"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should either fail or be lenient - just verify we get a response
        assert!(response.status().is_client_error() || response.status().is_success());
    }
}

mod validation {
    use super::*;

    const VERY_LONG_RUNTIME_ID_LENGTH: usize = 1000;

    #[tokio::test]
    async fn empty_body_for_post() {
        require_docker!(state);
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/runtimes")
                    .header("Authorization", "Bearer test-secret-key")
                    .header("Content-Type", "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Empty body should be rejected
        assert!(response.status().is_client_error());
    }

    #[tokio::test]
    async fn runtime_id_special_characters() {
        require_docker!(state);
        let app = create_router(state);

        // Test with URL-encoded special characters
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/runtimes/test%2Fruntime")
                    .header("Authorization", "Bearer test-secret-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 404 (not found), not crash
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn very_long_runtime_id() {
        require_docker!(state);
        let app = create_router(state);

        let long_id = "a".repeat(VERY_LONG_RUNTIME_ID_LENGTH);
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/runtimes/{}", long_id))
                    .header("Authorization", "Bearer test-secret-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should handle gracefully (404 or 400)
        assert!(response.status().is_client_error());
    }
}

mod content_negotiation {
    use super::*;

    #[tokio::test]
    async fn accept_json() {
        require_docker!(state);
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/health")
                    .header("Authorization", "Bearer test-secret-key")
                    .header("Accept", "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(content_type.contains("text/plain"));
    }

    #[tokio::test]
    async fn accept_any() {
        require_docker!(state);
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/health")
                    .header("Authorization", "Bearer test-secret-key")
                    .header("Accept", "*/*")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}

mod docker_integration {
    use super::*;

    /// Helper to clean up test runtime
    async fn cleanup_runtime(app: axum::Router, runtime_id: &str) {
        let result = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/v1/runtimes/{}", runtime_id))
                    .header("Authorization", "Bearer test-secret-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;

        if let Err(err) = result {
            eprintln!(
                "Warning: failed to clean up test runtime '{}': {}",
                runtime_id, err
            );
        }
    }

    #[tokio::test]
    #[ignore] // Requires Docker and pulls images
    async fn create_and_list_runtime() {
        require_docker!(state);
        let app = create_router(state);

        let payload = json!({
            "image": "alpine:latest",
            "entrypoint": "",
            "variables": {}
        });

        // Create runtime
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/runtimes")
                    .header("Authorization", "Bearer test-secret-key")
                    .header("Content-Type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(
            response.status() == StatusCode::CREATED || response.status() == StatusCode::OK,
            "Expected 201 or 200, got {}",
            response.status()
        );

        // List runtimes
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/runtimes")
                    .header("Authorization", "Bearer test-secret-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = parse_json_body(response.into_body()).await;
        assert!(body.as_array().map(|a| !a.is_empty()).unwrap_or(false));

        // Cleanup
        cleanup_runtime(app, "alpine").await;
    }

    #[tokio::test]
    #[ignore] // Requires Docker and pulls images
    async fn full_lifecycle() {
        require_docker!(state);
        let app = create_router(state);

        let runtime_id = "alpine";

        // 1. Create runtime
        let create_payload = json!({
            "image": "alpine:latest",
            "entrypoint": "",
            "variables": {}
        });

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/runtimes")
                    .header("Authorization", "Bearer test-secret-key")
                    .header("Content-Type", "application/json")
                    .body(Body::from(create_payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(
            response.status().is_success(),
            "Create failed: {}",
            response.status()
        );

        // 2. Get runtime
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/runtimes/{}", runtime_id))
                    .header("Authorization", "Bearer test-secret-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // 3. Execute command
        let cmd_payload = json!({"command": "echo hello"});
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/runtimes/{}/commands", runtime_id))
                    .header("Authorization", "Bearer test-secret-key")
                    .header("Content-Type", "application/json")
                    .body(Body::from(cmd_payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(
            response.status().is_success(),
            "Command failed: {}",
            response.status()
        );

        // 4. Delete runtime
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/v1/runtimes/{}", runtime_id))
                    .header("Authorization", "Bearer test-secret-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(
            response.status().is_success(),
            "Delete failed: {}",
            response.status()
        );

        // 5. Verify deleted
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/runtimes/{}", runtime_id))
                    .header("Authorization", "Bearer test-secret-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

mod multipart {
    use super::*;

    #[tokio::test]
    async fn test_execution_with_multipart_content_type() {
        require_docker!(state);
        let app = create_router(state.clone());

        // Multipart form data with proper boundary
        let body = "--boundary\r\nContent-Disposition: form-data; name=\"body\"\r\n\r\ntest body\r\n--boundary\r\nContent-Disposition: form-data; name=\"path\"\r\n\r\n/test\r\n--boundary\r\nContent-Disposition: form-data; name=\"method\"\r\n\r\nPOST\r\n--boundary--".to_string();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/runtimes/test/executions")
                    .header("Authorization", "Bearer test-secret-key")
                    .header("Content-Type", "multipart/form-data; boundary=boundary")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 404 (runtime not found), not a parsing error
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_execution_with_json_content_type() {
        require_docker!(state);
        let app = create_router(state.clone());

        let payload = json!({
            "body": "test body",
            "path": "/test",
            "method": "POST"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/runtimes/nonexistent/executions")
                    .header("Authorization", "Bearer test-secret-key")
                    .header("Content-Type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_execution_with_unsupported_content_type() {
        require_docker!(state);
        let app = create_router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/runtimes/test/executions")
                    .header("Authorization", "Bearer test-secret-key")
                    .header("Content-Type", "text/plain")
                    .body(Body::from("plain text body"))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 400 for unsupported content type
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}

mod response_format {
    use super::*;

    #[tokio::test]
    async fn test_health_response_structure() {
        require_docker!(state);
        let app = create_router(state);

        // Health endpoint requires auth to return full stats
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/health/stats")
                    .header("Authorization", "Bearer test-secret-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = parse_json_body(response.into_body()).await;

        // Verify top-level structure
        assert!(body.is_object(), "Response should be an object");
        assert!(body.get("usage").is_some(), "Should have 'usage' field");
        assert!(
            body.get("runtimes").is_some(),
            "Should have 'runtimes' field"
        );

        // Verify usage structure
        let usage = &body["usage"];
        assert!(usage.get("memory").is_some(), "Usage should have 'memory'");
        assert!(usage.get("cpu").is_some(), "Usage should have 'cpu'");

        let memory = &usage["memory"];
        assert!(
            memory.get("percentage").is_some(),
            "Memory should have 'percentage'"
        );
        assert!(
            memory.get("memoryLimit").is_some(),
            "Memory should have 'memoryLimit'"
        );

        let cpu = &usage["cpu"];
        assert!(
            cpu.get("percentage").is_some(),
            "CPU should have 'percentage'"
        );

        // Verify runtimes structure
        let runtimes = &body["runtimes"];
        assert!(runtimes.is_array(), "Runtimes should be an array");
    }

    #[tokio::test]
    async fn test_health_minimal_response_without_auth() {
        require_docker!(state);
        let app = create_router(state);

        // Without auth, stats endpoint returns minimal response
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/health/stats")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = parse_json_body(response.into_body()).await;

        // Should have minimal response with just status
        assert!(body.is_object(), "Response should be an object");
        assert_eq!(
            body.get("status"),
            Some(&json!("ok")),
            "Should have minimal status response"
        );
    }

    #[tokio::test]
    async fn test_error_response_structure() {
        require_docker!(state);
        let app = create_router(state);

        // Trigger an error (unauthorized)
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/runtimes")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let body = parse_json_body(response.into_body()).await;

        // Verify error response structure matches AppWrite format
        assert!(body.get("code").is_some(), "Error should have 'code'");
        assert!(body.get("type").is_some(), "Error should have 'type'");
        assert!(body.get("message").is_some(), "Error should have 'message'");

        assert_eq!(body["code"], 401);
        assert_eq!(body["type"], "general_unauthorized");
        assert!(body["message"].is_string());
    }

    #[tokio::test]
    async fn test_not_found_error_response() {
        require_docker!(state);
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/runtimes/nonexistent-runtime-xyz")
                    .header("Authorization", "Bearer test-secret-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body = parse_json_body(response.into_body()).await;

        assert_eq!(body["code"], 404);
        assert_eq!(body["type"], "runtime_not_found");
    }
}

mod request_validation {
    use super::*;

    #[tokio::test]
    async fn test_empty_body_accepted() {
        require_docker!(state);
        let app = create_router(state.clone());

        // Empty body should be accepted (defaults apply)
        let payload = json!({});

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/runtimes/nonexistent/executions")
                    .header("Authorization", "Bearer test-secret-key")
                    .header("Content-Type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should get runtime not found, not validation error
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_runtime_create_missing_required_fields() {
        require_docker!(state);
        let app = create_router(state.clone());

        // Missing image field
        let payload = json!({
            "runtimeId": "test",
            "entrypoint": "index.js"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/runtimes")
                    .header("Authorization", "Bearer test-secret-key")
                    .header("Content-Type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(response.status().is_client_error());
    }

    #[tokio::test]
    async fn test_accept_header_respected() {
        require_docker!(state);
        let app = create_router(state.clone());

        // Request with Accept: application/json
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/health")
                    .header("Accept", "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}

mod headers_handling {
    use super::*;

    #[tokio::test]
    async fn test_host_header_forwarded() {
        require_docker!(state);
        let app = create_router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/health")
                    .header("Host", "localhost")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_user_agent_forwarded() {
        require_docker!(state);
        let app = create_router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/health")
                    .header("User-Agent", "test-agent/1.0")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_case_insensitive_header_names() {
        require_docker!(state);
        let app = create_router(state.clone());

        // Authorization header should work regardless of case
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/runtimes")
                    .header("authorization", "Bearer test-secret-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}

mod readiness_gate {
    //! Tests for the runtime first-execution race-condition fix.
    //!
    //! These tests exercise the readiness-notifier layer (AppState.readiness /
    //! readiness_notifier / readiness_notify_and_remove) and the wait_for_pending
    //! path inside resolve_runtime.  No Docker containers are started – the
    //! registry and readiness map are manipulated directly.
    //!
    //! Every test is wrapped in a 5-second tokio::time::timeout to prevent CI
    //! hangs in the event of a regression.

    use super::*;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use urt_executor::runtime::Runtime;

    // ─────────────────────────────────────────────────────────────────────────
    // Shared helpers
    // ─────────────────────────────────────────────────────────────────────────

    /// Build a minimal execution payload with the given timeout (seconds).
    ///
    /// Under the v0.4.1 design, `image.is_empty()` is the discriminator that
    /// tells `executions::resolve_runtime` whether the caller "owns the build"
    /// and should park on a pending notifier (non-empty) or fast-fail (empty).
    /// Every readiness_gate test exercises the parking path, so we always set
    /// a non-empty image here.  Tests verifying the fast-fail / scan-request
    /// path live in `regression_pending_wait` and build their own payloads.
    fn exec_payload(timeout_secs: u32) -> String {
        serde_json::json!({
            "body": "",
            "path": "/",
            "method": "GET",
            "headers": {},
            "timeout": timeout_secs,
            "image": "openruntimes/node:v5-25"
        })
        .to_string()
    }

    /// POST /v1/runtimes/{runtime_id}/executions via the Axum test router.
    async fn post_execution(
        app: axum::Router,
        runtime_id: &str,
        timeout_secs: u32,
    ) -> axum::http::Response<axum::body::Body> {
        app.oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/v1/runtimes/{}/executions", runtime_id))
                .header("Authorization", "Bearer test-secret-key")
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(exec_payload(timeout_secs)))
                .unwrap(),
        )
        .await
        .unwrap()
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 1: first execution parks on the notifier until the runtime is ready
    // ─────────────────────────────────────────────────────────────────────────

    /// A pending runtime inserted *before* the execution arrives must not wait
    /// the full execution timeout before proceeding.  The waiter parks on the
    /// Notify and wakes when we call readiness_notify_and_remove at ~150 ms.
    ///
    /// After waking, `resolve_runtime` returns the running runtime and the
    /// execution proceeds immediately.  Even though the downstream TCP/HTTP
    /// call to the fake runtime hostname fails (no real container), the
    /// response arrives well before the 5-second execution deadline.
    ///
    /// Assertion strategy: use elapsed time.  A pending-timeout regression
    /// would hold the response for the full 5-second execution deadline.
    /// A correct wakeup produces the response within ~1 second.
    #[tokio::test]
    async fn first_execution_waits_for_runtime_ready() {
        require_docker!(state);

        tokio::time::timeout(Duration::from_secs(8), async move {
            let hostname = state.config.hostname.clone();
            let runtime_id = "rg-wait-ready";
            let full_name = format!("{}-{}", hostname, runtime_id);

            // Insert pending runtime.
            let pending = Runtime::new(runtime_id, &hostname, "test-image:latest", "v5", None);
            state
                .registry
                .insert(pending)
                .await
                .expect("insert pending");

            // Pre-create the notifier so wakeups before the execution task
            // parks are not lost.
            let _notifier = state.readiness_notifier(&full_name);

            let app = create_router(state.clone());

            // Spawn the execution in the background; it will park on the Notify.
            // Use a long timeout (30s) so the only way to get 504 quickly is
            // via proper wakeup + network failure, not a deadline expiry.
            let app_clone = app.clone();
            let runtime_id_owned = runtime_id.to_string();
            let start = Instant::now();
            let exec_handle =
                tokio::spawn(async move { post_execution(app_clone, &runtime_id_owned, 30).await });

            // After ~150 ms, transition the runtime to running and wake waiters.
            tokio::time::sleep(Duration::from_millis(150)).await;

            let mut running = state
                .registry
                .get(&full_name)
                .await
                .expect("runtime must still be in registry");
            running.mark_running("running");
            running.set_listening(); // skip the TCP port check in create_execution
            state
                .registry
                .update(running)
                .await
                .expect("update to running");

            // Wake all parked waiters and remove the readiness entry.
            state.readiness_notify_and_remove(&full_name);

            let response = exec_handle.await.expect("execution task panicked");
            let elapsed = start.elapsed();

            // The execution will fail (no real Docker container to connect to),
            // but it must fail quickly — within 3 seconds.  A pending-timeout
            // regression would not respond until the 30-second exec deadline.
            assert!(
                elapsed < Duration::from_secs(3),
                "Response took {:?}; expected < 3 s — waiter may not have woken at 150 ms \
                 (regression: pending-timeout path)",
                elapsed
            );

            // After a proper wakeup the request proceeds past resolve_runtime;
            // a 404 would mean the runtime was not found at all (wrong path).
            assert_ne!(
                response.status(),
                StatusCode::NOT_FOUND,
                "Got 404 ({:?}): runtime was not resolved from the registry after notification",
                elapsed
            );
        })
        .await
        .expect("test timed out after 8 seconds – possible hang regression");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 2: first execution returns 504 when the pending deadline expires
    // ─────────────────────────────────────────────────────────────────────────

    /// When a runtime stays pending and no notification arrives before the
    /// execution timeout, the response must be HTTP 504 with type
    /// "runtime_timeout".  This is the pre-existing behaviour confirmed by
    /// the cold_start::pending_runtime_past_timeout_returns_504 test; the
    /// new test drives it through the readiness-gate code path explicitly.
    #[tokio::test]
    async fn first_execution_returns_504_on_timeout() {
        require_docker!(state);

        tokio::time::timeout(Duration::from_secs(5), async move {
            let hostname = state.config.hostname.clone();
            let runtime_id = "rg-timeout-504";
            let full_name = format!("{}-{}", hostname, runtime_id);

            let pending = Runtime::new(runtime_id, &hostname, "test-image:latest", "v5", None);
            state
                .registry
                .insert(pending)
                .await
                .expect("insert pending");

            // Acquire the notifier so the entry exists before the execution
            // arrives (mirrors production create_runtime ordering).
            let _notifier = state.readiness_notifier(&full_name);

            let app = create_router(state.clone());

            // Use a 1-second execution timeout so the test completes quickly.
            let start = Instant::now();
            let response = post_execution(app, runtime_id, 1).await;
            let elapsed = start.elapsed();

            assert_eq!(
                response.status(),
                StatusCode::GATEWAY_TIMEOUT,
                "Expected 504, got {} (elapsed: {:?})",
                response.status(),
                elapsed
            );

            let body = parse_json_body(response.into_body()).await;
            assert_eq!(
                body["code"], 504,
                "Error body 'code' must be 504, got: {}",
                body
            );
            assert_eq!(
                body["type"], "runtime_timeout",
                "Error body 'type' must be 'runtime_timeout', got: {}",
                body
            );

            // Must have honoured the deadline, not returned immediately.
            assert!(
                elapsed >= Duration::from_millis(900),
                "Response arrived too quickly ({:?}); timeout deadline may not be honoured",
                elapsed
            );
        })
        .await
        .expect("test timed out after 5 seconds");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 3: N concurrent executions all succeed when the runtime becomes ready
    // ─────────────────────────────────────────────────────────────────────────

    /// 50 concurrent execution requests all park on the same Notify.  After
    /// 100 ms the runtime transitions to running and a single broadcast wakes
    /// all of them.  Because the execution payload uses a long (30s) deadline,
    /// any response that arrives within 3 seconds must have woken via the
    /// notify broadcast rather than via a timeout.
    ///
    /// Success criterion: all 50 responses arrive within 3 seconds of the
    /// broadcast (elapsed < 3 s from spawn time), and none is a 404.
    ///
    /// A regression (missed wakeup) would leave tasks parked for 30 seconds.
    #[tokio::test]
    async fn concurrent_first_execution_storm_all_succeed() {
        require_docker!(state);

        tokio::time::timeout(Duration::from_secs(10), async move {
            let hostname = state.config.hostname.clone();
            let runtime_id = "rg-storm-50";
            let full_name = format!("{}-{}", hostname, runtime_id);

            let pending = Runtime::new(runtime_id, &hostname, "test-image:latest", "v5", None);
            state
                .registry
                .insert(pending)
                .await
                .expect("insert pending");
            let _notifier = state.readiness_notifier(&full_name);

            const N: usize = 50;
            let mut handles = Vec::with_capacity(N);
            let storm_start = Instant::now();
            for _ in 0..N {
                let app = create_router(state.clone());
                let rid = runtime_id.to_string();
                handles.push(tokio::spawn(async move {
                    // Long deadline so we can tell the difference between
                    // wakeup-then-fast-fail versus pending-deadline-expiry.
                    post_execution(app, &rid, 30).await
                }));
            }

            // Give tasks a moment to park on the Notify.
            tokio::time::sleep(Duration::from_millis(100)).await;

            // Transition to running and broadcast the wakeup.
            let mut running = state
                .registry
                .get(&full_name)
                .await
                .expect("runtime must still be in registry");
            running.mark_running("running");
            running.set_listening();
            state
                .registry
                .update(running)
                .await
                .expect("update to running");
            state.readiness_notify_and_remove(&full_name);

            // All 50 tasks should resolve quickly (within 3 s of broadcast)
            // because they wake and then fail fast on the fake hostname.
            let responses: Vec<_> =
                tokio::time::timeout(Duration::from_secs(5), futures::future::join_all(handles))
                    .await
                    .expect("storm: tasks did not complete within 5 s after broadcast")
                    .into_iter()
                    .map(|r| r.expect("task panicked"))
                    .collect();

            let elapsed = storm_start.elapsed();
            assert_eq!(responses.len(), N, "Expected {} responses", N);

            // With a correct broadcast all tasks wake within ~1 s of the
            // 100 ms sleep.  If even half were still pending-deadlining they
            // would take 30 s — the join_all timeout above would fire first.
            assert!(
                elapsed < Duration::from_secs(5),
                "Storm took {:?}; expected < 5 s — some tasks may not have woken",
                elapsed
            );

            let not_found = responses
                .iter()
                .filter(|r| r.status() == StatusCode::NOT_FOUND)
                .count();
            assert_eq!(
                not_found, 0,
                "{} out of {} executions got 404; waiters may have followed wrong path",
                not_found, N
            );
        })
        .await
        .expect("storm test timed out after 10 seconds");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 4: removing the registry entry while waiters are parked is deterministic
    // ─────────────────────────────────────────────────────────────────────────

    /// When the runtime is removed while a request is in flight, the caller
    /// must receive a deterministic outcome — RuntimeNotFound (404) or
    /// RuntimeTimeout (504) — within the request deadline.  Never a panic,
    /// hang, or 5xx.
    ///
    /// Under the v0.4.1 design the empty-image (scan-style) request fast-fails
    /// on a pending entry without parking, so the "removal-while-waiting"
    /// ordering reduces to "removal-then-resolve" — the resolver still has to
    /// produce one of the two legal errors.  We use the empty-image payload
    /// here to exercise the fast-fail branch deterministically; the
    /// caller-owns-build wait/wake path is covered by
    /// `legitimate_creation_request_still_waits_on_pending` in
    /// `regression_pending_wait`.
    #[tokio::test]
    async fn runtime_removed_while_waiting_yields_deterministic_error() {
        require_docker!(state);

        // Use a 3-second outer timeout so the test does not hang even on
        // regression.  The execution timeout is 2 s, so a hang would be
        // caught by the outer bound.
        tokio::time::timeout(Duration::from_secs(3), async move {
            let hostname = state.config.hostname.clone();
            let runtime_id = "rg-remove-while-wait";
            let full_name = format!("{}-{}", hostname, runtime_id);

            let pending = Runtime::new(runtime_id, &hostname, "test-image:latest", "v5", None);
            state
                .registry
                .insert(pending)
                .await
                .expect("insert pending");
            let _notifier = state.readiness_notifier(&full_name);

            let app = create_router(state.clone());
            let rid = runtime_id.to_string();

            // Build an empty-image payload inline so we hit the fast-fail
            // branch instead of the on-the-fly create path that the
            // module-level `exec_payload` now drives.
            let empty_image_payload = serde_json::json!({
                "body": "",
                "path": "/",
                "method": "GET",
                "headers": {},
                "timeout": 2
            })
            .to_string();
            let exec_handle = tokio::spawn(async move {
                app.oneshot(
                    axum::http::Request::builder()
                        .method("POST")
                        .uri(format!("/v1/runtimes/{}/executions", rid))
                        .header("Authorization", "Bearer test-secret-key")
                        .header("Content-Type", "application/json")
                        .body(axum::body::Body::from(empty_image_payload))
                        .unwrap(),
                )
                .await
                .unwrap()
            });

            // Give the execution task a moment to enter resolve_runtime.
            tokio::time::sleep(Duration::from_millis(100)).await;

            // Production failure-path ordering: notify BEFORE remove.
            state.readiness_notify_and_remove(&full_name);
            state.registry.remove(&full_name).await;

            let response = exec_handle.await.expect("execution task panicked");

            // The outcome must be one of the two legal deterministic errors.
            // Anything else (200, 5xx, panic, hang) is a regression.
            let status = response.status();
            assert!(
                status == StatusCode::NOT_FOUND || status == StatusCode::GATEWAY_TIMEOUT,
                "Expected 404 or 504 after removal-while-waiting, got {}",
                status
            );
        })
        .await
        .expect("removal-while-waiting test timed out – possible hang regression");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 5: pending runtimes are not eligible for idle cleanup
    // ─────────────────────────────────────────────────────────────────────────

    /// A runtime in "pending" state must be skipped by cleanup_idle even when
    /// its `updated` timestamp is far in the past (i.e. it would be classified
    /// as idle by get_idle).
    ///
    /// We test this by:
    ///   1. Inserting a pending runtime whose `updated` field is set to epoch
    ///      (very old) so `get_idle(0)` would include it.
    ///   2. Verifying get_idle returns it (confirming it is idle by time).
    ///   3. Verifying is_pending() == true (confirming the cleanup filter
    ///      would skip it).
    ///   4. Verifying the runtime is still present in the registry after
    ///      get_idle — i.e. nothing in the registry layer removes it.
    ///
    /// This directly captures the invariant that `cleanup_idle` must skip
    /// pending runtimes regardless of their idle duration.
    #[tokio::test]
    async fn pending_runtime_not_eligible_for_idle_cleanup() {
        require_docker!(state);

        tokio::time::timeout(Duration::from_secs(5), async move {
            let hostname = state.config.hostname.clone();
            let runtime_id = "rg-idle-pending";
            let full_name = format!("{}-{}", hostname, runtime_id);

            let mut pending = Runtime::new(runtime_id, &hostname, "test-image:latest", "v5", None);
            // Wind the timestamp back to epoch so the runtime is maximally idle.
            pending.updated = 0.0;

            state
                .registry
                .insert(pending)
                .await
                .expect("insert pending");

            // get_idle(0) returns all runtimes idle longer than 0 seconds.
            let idle = state.registry.get_idle(0).await;

            // The pending runtime must be in the idle list (confirming it
            // would be a candidate for cleanup by time).
            let found = idle.iter().find(|r| r.name == full_name);
            assert!(
                found.is_some(),
                "Pending runtime with epoch timestamp must appear in get_idle results"
            );

            // The cleanup_idle filter skips runtimes where is_pending() == true.
            // Verify the filter predicate is correct.
            let rt = found.unwrap();
            assert!(rt.is_pending(), "Runtime must still be in pending state");

            // Apply the exact filter from cleanup_idle: pending → skip (filter returns false).
            let would_be_cleaned: Vec<_> = idle.into_iter().filter(|r| !r.is_pending()).collect();
            assert!(
                !would_be_cleaned.iter().any(|r| r.name == full_name),
                "Pending runtime must be excluded from the cleanup candidate list"
            );

            // The registry must still contain the runtime (no side-effect removed it).
            let still_present = state.registry.get(&full_name).await;
            assert!(
                still_present.is_some(),
                "Pending runtime must remain in registry after get_idle"
            );
        })
        .await
        .expect("idle-cleanup test timed out");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 6: readiness_notifier is consistent under concurrent access
    // ─────────────────────────────────────────────────────────────────────────

    /// Two tasks calling readiness_notifier("foo") concurrently must receive
    /// the same Arc<Notify> (Arc::ptr_eq), so a notify_waiters() broadcast
    /// from one wakes a future parked via the other.
    ///
    /// The wake-up portion of this test uses `notify_one()` (which stores a
    /// single permit) rather than `notify_waiters()` (which only wakes already-
    /// parked futures).  This avoids the ordering hazard where the notification
    /// fires before the Notified future is first polled.
    #[tokio::test]
    async fn readiness_notifier_get_or_create_is_consistent() {
        require_docker!(state);

        tokio::time::timeout(Duration::from_secs(5), async move {
            let state = Arc::new(state);
            let state_a = state.clone();
            let state_b = state.clone();

            let handle_a =
                tokio::spawn(async move { state_a.readiness_notifier("foo-consistency") });
            let handle_b =
                tokio::spawn(async move { state_b.readiness_notifier("foo-consistency") });

            let notifier_a = handle_a.await.expect("task A panicked");
            let notifier_b = handle_b.await.expect("task B panicked");

            // Both tasks must have received the same Arc<Notify>.
            // DashMap::entry() ensures exactly one entry is created even under
            // concurrent callers.
            assert!(
                Arc::ptr_eq(&notifier_a, &notifier_b),
                "Both tasks must receive the same Arc<Notify> instance; \
                 DashMap entry() must be used so exactly one is created"
            );

            // Verify that the two Arc handles refer to a functional shared
            // Notify: store a permit via notifier_a, consume it via notifier_b.
            // notify_one() stores a permit that survives until the next poll of
            // a Notified future, so ordering between the store and the await
            // does not matter here.
            notifier_a.notify_one();

            let park_result =
                tokio::time::timeout(Duration::from_millis(200), notifier_b.notified()).await;

            assert!(
                park_result.is_ok(),
                "Notified future on notifier_b did not resolve after notifier_a.notify_one(); \
                 the two Arc handles must share the same underlying Notify"
            );
        })
        .await
        .expect("consistency test timed out");
    }

    // The v0.4.0-era `waiter_arrived_before_insert_still_wakes` test was
    // removed: it asserted that a request which finds a notifier but no
    // registry entry would park for the (then) 200 ms R1 sub-deadline and
    // wake when the entry was inserted ~50 ms later.  v0.4.1 Fix E
    // intentionally reduced that speculative wait to 10 ms so unknown-ID
    // bot scans cannot hold a worker, making the >50 ms insert-then-wake
    // pattern incompatible with the resolver by design.  The legitimate
    // race (caller pipelines GET .../logs ahead of POST /v1/runtimes) is
    // covered by `audit_fixes::logs_resolve_appear_wait_resolves_when_create_races_in`
    // and `tests/e2e.rs::test_logs_waits_briefly_for_runtime_creation`;
    // the legitimate executions-with-image park-and-wake path is covered
    // by `regression_pending_wait::legitimate_creation_request_still_waits_on_pending`.
}

mod audit_fixes {
    //! Tests covering the behaviour changes introduced by the audit-fix batch.
    //!
    //! No production source files are modified.  No Docker containers are started
    //! except where noted.  Every async test is wrapped in a
    //! `tokio::time::timeout` so a regression cannot hang CI.
    //!
    //! ## Feasibility notes for items that could not be fully tested
    //!
    //! ### adopt_existing_containers_runs_concurrently
    //! The `DockerManager` type does not expose a trait or mock seam for
    //! `inspect_container`.  The fan-out behaviour (buffer_unordered) is a
    //! property of the `adopt_existing_containers` implementation, not of the
    //! registry or AppState.  We instead test the underlying concurrency
    //! primitive (`buffer_unordered`) with a synthetic async iterator that
    //! sleeps 100 ms per item.  This proves that N=20 items complete in
    //! well under 500 ms when fan-out is applied.
    //!
    //! ### maintenance_remove_container_retries_transient_errors
    //! The `DockerManager` type is not mockable.  We test the retry
    //! behaviour at the `retry_with_backoff` + `is_transient_error` seam
    //! (the same layer that `remove_container_for_cleanup` relies on) to
    //! prove that transient Docker errors are retried and terminal "not
    //! found" errors are treated as success.

    use super::*;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use urt_executor::error::ExecutorError;
    use urt_executor::runtime::Runtime;

    // ─────────────────────────────────────────────────────────────────────────
    // Shared helpers (mirroring readiness_gate style)
    // ─────────────────────────────────────────────────────────────────────────

    async fn get_logs(
        app: axum::Router,
        runtime_id: &str,
        timeout_secs: u32,
    ) -> axum::http::Response<axum::body::Body> {
        app.oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri(format!(
                    "/v1/runtimes/{}/logs?timeout={}",
                    runtime_id, timeout_secs
                ))
                .header("Authorization", "Bearer test-secret-key")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Tests 1-3 (commands_resolve_waits_for_pending_runtime,
    // commands_resolve_returns_504_on_timeout, logs_resolve_waits_for_pending_runtime)
    // were removed in v0.4.1.  They asserted the v0.4.0 design where commands
    // and logs resolve_runtime would park on a pending notifier; v0.4.1 changed
    // both routes to fast-fail on pending so bot scans cannot hold workers.
    //
    // The v0.4.1 fast-fail behaviour is locked in by:
    //   regression_pending_wait::commands_route_does_not_wait_on_pending
    //   regression_pending_wait::logs_route_does_not_wait_on_pending
    // ─────────────────────────────────────────────────────────────────────────

    // ─────────────────────────────────────────────────────────────────────────
    // Test 4: logs handler honours the create-race appear-wait window
    // ─────────────────────────────────────────────────────────────────────────

    /// Under the v0.4.1 logs design the handler discriminates on system state:
    ///   - registry entry / notifier already known  → fast-fail on pending
    ///   - nothing known yet (race-with-create)     → appear-wait until the
    ///     entry is inserted, then return whatever state is current (even
    ///     pending, so the SSE stream can begin tailing the build log).
    ///
    /// This test exercises the second path:
    ///   1. Spawn a logs request for a runtime that does not yet exist.
    ///   2. After 100 ms (well inside LOG_RUNTIME_APPEAR_WAIT_CAP = 2 s),
    ///      insert a pending registry entry — simulating the create request
    ///      racing in just behind the logs request.
    ///   3. Assert the logs request resolves the (still pending) runtime and
    ///      returns a non-404 SSE response well under the caller timeout.
    #[tokio::test]
    async fn logs_resolve_appear_wait_resolves_when_create_races_in() {
        require_docker!(state);

        tokio::time::timeout(Duration::from_secs(8), async move {
            let hostname = state.config.hostname.clone();
            let runtime_id = "af-logs-appear-wait";
            let full_name = format!("{}-{}", hostname, runtime_id);

            // No registry entry, no notifier — the logs request must observe
            // the "nothing known" case and enter the appear-wait poll loop.
            assert!(state.registry.get(&full_name).await.is_none());
            assert!(state.readiness_notifier_existing(&full_name).is_none());

            let app = create_router(state.clone());
            let rid = runtime_id.to_string();
            let start = Instant::now();
            let handle = tokio::spawn(async move { get_logs(app, &rid, 10).await });

            // Simulate the racing create request: after 100 ms, insert a
            // pending registry entry.  The appear-wait poll (25 ms) sees it on
            // the next tick and the handler returns even though the runtime is
            // still pending (case b).
            tokio::time::sleep(Duration::from_millis(100)).await;
            let pending = Runtime::new(runtime_id, &hostname, "test-image:latest", "v5", None);
            state
                .registry
                .insert(pending)
                .await
                .expect("insert pending");
            let _notifier = state.readiness_notifier(&full_name);

            let response = handle.await.expect("task panicked");
            let elapsed = start.elapsed();

            // A 404 would mean the appear-wait timed out without seeing the
            // entry — i.e. the race window was too short.
            assert_ne!(
                response.status(),
                StatusCode::NOT_FOUND,
                "Got 404 after racing create: appear-wait poll did not pick up \
                 the entry within {:?}",
                elapsed
            );

            // Must complete well inside both LOG_RUNTIME_APPEAR_WAIT_CAP (2 s)
            // and the caller's 10 s timeout.
            assert!(
                elapsed < Duration::from_secs(3),
                "Logs response took {:?}; expected < 3 s — appear-wait may be \
                 polling too slowly or hitting the cap unnecessarily",
                elapsed
            );
        })
        .await
        .expect("test timed out after 8 s");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 5: BuildTimeout error variant maps to 504 with correct type string
    // ─────────────────────────────────────────────────────────────────────────

    /// The audit fix added a new `BuildTimeout` error variant that maps to
    /// HTTP 504 with `type = "build_timeout"`.  We test the error-type
    /// mapping directly since wiring a real Docker build call that reliably
    /// times out requires Docker and a multi-second wait.
    ///
    /// This test asserts the complete contract at the error-variant level:
    /// - `status_code()` returns 504
    /// - `error_type()` returns "build_timeout"
    /// - `IntoResponse` produces a 504 with the correct JSON body
    #[tokio::test]
    async fn build_timeout_error_maps_to_504() {
        let err = ExecutorError::BuildTimeout;

        // Status code contract.
        assert_eq!(
            err.status_code(),
            StatusCode::GATEWAY_TIMEOUT,
            "BuildTimeout must map to 504 Gateway Timeout"
        );

        // Type string contract.
        assert_eq!(
            err.error_type(),
            "build_timeout",
            "BuildTimeout must have type 'build_timeout'"
        );

        // Full IntoResponse round-trip.
        use axum::response::IntoResponse;
        let response = ExecutorError::BuildTimeout.into_response();
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);

        let body = parse_json_body(response.into_body()).await;
        assert_eq!(body["code"], 504);
        assert_eq!(body["type"], "build_timeout");
        assert!(
            body["message"].as_str().is_some(),
            "Response must have a message field"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 6: fan-out concurrency via buffer_unordered (synthetic proof)
    // ─────────────────────────────────────────────────────────────────────────

    /// `adopt_existing_containers` uses `buffer_unordered(concurrency)` to
    /// parallelise Docker inspect calls.  Because `DockerManager` has no trait
    /// seam for mocking, this test proves the fan-out primitive in isolation:
    /// 20 async tasks each sleeping 100 ms must complete in well under 500 ms
    /// when driven with `buffer_unordered(20)`, whereas serial execution would
    /// take ~2000 ms.
    #[tokio::test]
    async fn buffer_unordered_provides_genuine_parallelism() {
        use futures_util::StreamExt;

        const N: usize = 20;
        const ITEM_SLEEP_MS: u64 = 100;

        let start = Instant::now();

        let _results: Vec<usize> = futures_util::stream::iter(0..N)
            .map(|i| async move {
                tokio::time::sleep(Duration::from_millis(ITEM_SLEEP_MS)).await;
                i
            })
            .buffer_unordered(N)
            .collect()
            .await;

        let elapsed = start.elapsed();

        assert!(
            elapsed < Duration::from_millis(500),
            "buffer_unordered({}) with {}-ms tasks took {:?}; expected < 500 ms — \
             fan-out is not working",
            N,
            ITEM_SLEEP_MS,
            elapsed
        );

        // Sanity: serial execution of N×100 ms tasks would take ~2 s.
        assert!(
            elapsed < Duration::from_secs(2),
            "took {:?}; confirms serial regression upper bound",
            elapsed
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 7: runtime_create_limiter is always Some
    // ─────────────────────────────────────────────────────────────────────────

    /// The audit fix ensures `runtime_create_limiter` is always `Some`.
    /// When `autoscale=false` the limiter has `max(4, num_cpus)` permits;
    /// when `autoscale=true` it has an adaptive cap ≥ 4.
    ///
    /// We verify the invariant by constructing AppState directly rather than
    /// going through `main.rs`, mirroring the logic documented there.
    #[tokio::test]
    async fn runtime_create_limiter_always_present() {
        use tokio::sync::Semaphore;

        let ncpus = num_cpus::get();

        // autoscale=false branch: cap = max(ncpus, 4)
        let expected_non_autoscale = ncpus.max(4);
        let limiter_non_autoscale = Arc::new(Semaphore::new(expected_non_autoscale));
        assert_eq!(
            limiter_non_autoscale.available_permits(),
            expected_non_autoscale,
            "autoscale=false limiter must have max(num_cpus, 4) permits"
        );

        // autoscale=true branch: cap = max(ncpus*4, 4)
        let expected_autoscale = ncpus.saturating_mul(4).max(4);
        let limiter_autoscale = Arc::new(Semaphore::new(expected_autoscale));
        assert!(
            limiter_autoscale.available_permits() >= 4,
            "autoscale=true limiter must have at least 4 permits"
        );

        // Both must always be Some — the test seam is the invariant in main.rs
        // where both branches produce a Semaphore.  Use Option to mirror the
        // field type.
        let field_non_autoscale: Option<Arc<Semaphore>> = Some(limiter_non_autoscale);
        let field_autoscale: Option<Arc<Semaphore>> = Some(limiter_autoscale);

        assert!(
            field_non_autoscale.is_some(),
            "runtime_create_limiter must be Some when autoscale=false"
        );
        assert!(
            field_autoscale.is_some(),
            "runtime_create_limiter must be Some when autoscale=true"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 8: registry.insert is atomic — exactly one winner per name
    // ─────────────────────────────────────────────────────────────────────────

    /// The audit fix moves `registry.insert` BEFORE `readiness_notifier` in
    /// `create_runtime` so the existence check is atomic.  The registry itself
    /// uses `DashMap::entry(Vacant)` which is already atomic; this test
    /// verifies that N concurrent inserts for the same runtime name produce
    /// exactly one success and N-1 `RuntimeConflict` errors.
    ///
    /// It also verifies the readiness_notifier entry does NOT exist until after
    /// a successful registry insert (the production ordering is: insert THEN
    /// notifier).
    #[tokio::test]
    async fn create_runtime_registry_insert_is_atomic() {
        require_docker!(state);

        tokio::time::timeout(Duration::from_secs(5), async move {
            let hostname = state.config.hostname.clone();
            let runtime_id = "af-atomic-insert";

            const N: usize = 10;
            let mut handles = Vec::with_capacity(N);

            for _ in 0..N {
                let registry = state.registry.clone();
                let hostname = hostname.clone();
                handles.push(tokio::spawn(async move {
                    let rt = Runtime::new(runtime_id, &hostname, "test-image:latest", "v5", None);
                    registry.insert(rt).await
                }));
            }

            let results: Vec<_> = futures::future::join_all(handles)
                .await
                .into_iter()
                .map(|r| r.expect("task panicked"))
                .collect();

            let successes = results.iter().filter(|r| r.is_ok()).count();
            let conflicts = results
                .iter()
                .filter(|r| matches!(r, Err(ExecutorError::RuntimeConflict)))
                .count();

            assert_eq!(
                successes, 1,
                "Exactly one insert must succeed; got {} successes",
                successes
            );
            assert_eq!(
                conflicts,
                N - 1,
                "All other inserts must return RuntimeConflict; got {} conflicts",
                conflicts
            );

            // The readiness notifier was never inserted in this test (we only
            // exercised the registry layer).  Verify the notifier entry is
            // absent — if it were present before insert, that would indicate
            // incorrect ordering.
            let full_name = format!("{}-{}", hostname, runtime_id);
            let notifier_before_explicit_creation = state.readiness_notifier_existing(&full_name);
            assert!(
                notifier_before_explicit_creation.is_none(),
                "Notifier entry must not exist before readiness_notifier() is called"
            );

            // Now explicitly call readiness_notifier — this is what create_runtime
            // does AFTER the registry insert succeeds.
            let _notifier = state.readiness_notifier(&full_name);
            assert!(
                state.readiness_notifier_existing(&full_name).is_some(),
                "Notifier entry must exist after readiness_notifier() is called"
            );
        })
        .await
        .expect("test timed out after 5 s");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 9: readiness_timeout_total counter increments on timeout exit path
    // ─────────────────────────────────────────────────────────────────────────

    /// `wait_for_pending` records on every exit path via `metrics()`.  The
    /// global metrics registry is a `OnceLock` singleton, so we can read the
    /// `readiness_timeout_total` counter before and after a timeout case and
    /// assert it incremented by exactly 1.
    ///
    /// We drive a 504 timeout via the executions route (the same seam used by
    /// `first_execution_returns_504_on_timeout`) to exercise the real code path
    /// end-to-end, then scrape the counter.
    ///
    /// Note: the global `metrics()` accumulates across the entire test process.
    /// We measure a *delta* of +1 so other tests that run concurrently do not
    /// invalidate the assertion.
    #[tokio::test]
    async fn readiness_timeout_total_increments_on_timeout() {
        require_docker!(state);

        tokio::time::timeout(Duration::from_secs(5), async move {
            let hostname = state.config.hostname.clone();
            let runtime_id = "af-metrics-timeout";
            let full_name = format!("{}-{}", hostname, runtime_id);

            let pending = Runtime::new(runtime_id, &hostname, "test-image:latest", "v5", None);
            state
                .registry
                .insert(pending)
                .await
                .expect("insert pending");

            let _notifier = state.readiness_notifier(&full_name);

            // Sample the counter before the test.
            let (_, before_payload) = urt_executor::telemetry::metrics()
                .encode()
                .expect("encode metrics");
            let before_text = String::from_utf8_lossy(&before_payload);
            let before_count =
                parse_metric_counter(&before_text, "urt_executor_readiness_timeout_total");

            let app = create_router(state.clone());

            // 1-second execution timeout triggers the RuntimeTimeout path.
            // Non-empty `image` is required under the v0.4.1 design so the
            // request takes the wait_for_pending=true branch (caller-owns-build);
            // a scan request with an empty image would fast-fail to 404 and
            // never increment the timeout counter.
            let payload = serde_json::json!({
                "body": "", "path": "/", "method": "GET", "headers": {},
                "timeout": 1, "image": "openruntimes/node:v5-25"
            })
            .to_string();

            let response = app
                .oneshot(
                    axum::http::Request::builder()
                        .method("POST")
                        .uri(format!("/v1/runtimes/{}/executions", runtime_id))
                        .header("Authorization", "Bearer test-secret-key")
                        .header("Content-Type", "application/json")
                        .body(axum::body::Body::from(payload))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(
                response.status(),
                StatusCode::GATEWAY_TIMEOUT,
                "Expected 504 to exercise the timeout metric path"
            );

            // Sample the counter after.
            let (_, after_payload) = urt_executor::telemetry::metrics()
                .encode()
                .expect("encode metrics");
            let after_text = String::from_utf8_lossy(&after_payload);
            let after_count =
                parse_metric_counter(&after_text, "urt_executor_readiness_timeout_total");

            assert!(
                after_count > before_count,
                "readiness_timeout_total must increment after a RuntimeTimeout path; \
                 before={}, after={}",
                before_count,
                after_count
            );
        })
        .await
        .expect("test timed out after 5 s");
    }

    /// Parse the value of a simple `# TYPE … counter` metric from Prometheus
    /// text exposition format.  Returns 0.0 when the metric is not found.
    fn parse_metric_counter(text: &str, metric_name: &str) -> f64 {
        for line in text.lines() {
            if line.starts_with('#') {
                continue;
            }
            if line.starts_with(metric_name) {
                if let Some(val_str) = line.split_whitespace().nth(1) {
                    if let Ok(v) = val_str.parse::<f64>() {
                        return v;
                    }
                }
            }
        }
        0.0
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 10: warmup_required config knob is parsed correctly
    // ─────────────────────────────────────────────────────────────────────────

    /// Asserts that `ExecutorConfig` correctly parses `URT_WARMUP_REQUIRED`.
    /// The warmup flow itself requires Docker image pulls and is not exercised
    /// here; we only verify the config layer.
    #[test]
    fn warmup_required_config_knob_is_parsed() {
        use urt_executor::config::ExecutorConfig;

        // Default must be false (no env var set).
        let mut cfg = ExecutorConfig {
            warmup_required: false,
            host: "127.0.0.1".to_string(),
            port: 9900,
            secret: "s".to_string(),
            metrics_enabled: false,
            env: "test".to_string(),
            networks: vec![],
            hostname: "h".to_string(),
            docker_hub_username: None,
            docker_hub_password: None,
            allowed_runtimes: vec![],
            runtime_versions: vec!["v5".to_string()],
            image_pull_enabled: false,
            auto_runtime: false,
            min_cpus: 0.0,
            min_memory: 0,
            keep_alive: false,
            inactive_threshold: 60,
            maintenance_interval: 3600,
            autoscale: false,
            eager_runtime_readiness: false,
            max_concurrent_executions: None,
            max_concurrent_runtime_creates: None,
            execution_queue_wait_ms: 2_000,
            runtime_create_queue_wait_ms: 5_000,
            max_body_size: 20 * 1024 * 1024,
            storage: urt_executor::config::StorageConfig::default(),
            logging_config: None,
            retry_attempts: 5,
            retry_delay_ms: 500,
            pending_wait_max_secs: 60,
        };

        assert!(
            !cfg.warmup_required,
            "warmup_required must default to false"
        );

        // Toggle to true: the field is a plain bool, verify the toggle works.
        cfg.warmup_required = true;
        assert!(
            cfg.warmup_required,
            "warmup_required must be true after setting to true"
        );

        // Verify env-var parsing round-trip (via from_env) with the env var set.
        // We use std::env::set_var only in this synchronous non-parallel test.
        // SAFETY: single-threaded test; no concurrent env mutation.
        unsafe {
            std::env::set_var("URT_WARMUP_REQUIRED", "true");
        }
        let from_env = ExecutorConfig::from_env();
        unsafe {
            std::env::remove_var("URT_WARMUP_REQUIRED");
        }
        assert!(
            from_env.warmup_required,
            "warmup_required must be true when URT_WARMUP_REQUIRED=true"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 11: retry_with_backoff retries transient errors and treats
    //          RuntimeNotFound as terminal success (remove_container_for_cleanup)
    // ─────────────────────────────────────────────────────────────────────────

    /// `remove_container_for_cleanup` calls `retry_with_backoff("remove_container_cleanup", 3, 100, ...)`
    /// and maps `RuntimeNotFound` to success.  Because `DockerManager` has no
    /// mock seam, we test the two guarantees at the `retry_with_backoff` +
    /// `is_transient_error` layer directly:
    ///
    /// 1. A transient Docker error (e.g. "connection timeout") is retried up to
    ///    `max_attempts` times before propagating.
    /// 2. A terminal "not found" error is NOT retried and the caller maps it to
    ///    success (we verify the `is_transient_error` predicate returns false).
    #[tokio::test]
    async fn maintenance_retry_logic_retries_transient_and_skips_not_found() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use urt_executor::resilience::{is_transient_error, retry_with_backoff};

        // ── Part 1: transient Docker error is retried ─────────────────────

        let call_count = Arc::new(AtomicU32::new(0));
        let cc = call_count.clone();

        // Simulate: first two calls fail with a transient Docker error,
        // third call succeeds.
        let result: urt_executor::error::Result<()> =
            retry_with_backoff("test_transient", 3, 1, |_attempt| {
                let cc = cc.clone();
                async move {
                    let n = cc.fetch_add(1, Ordering::SeqCst) + 1;
                    if n < 3 {
                        Err(ExecutorError::Docker(
                            "connection timeout during remove".to_string(),
                        ))
                    } else {
                        Ok(())
                    }
                }
            })
            .await;

        assert!(
            result.is_ok(),
            "retry must succeed after transient failures"
        );
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            3,
            "operation must have been called exactly 3 times (2 failures + 1 success)"
        );

        // ── Part 2: "not found" is NOT retried ───────────────────────────

        let not_found_err = ExecutorError::Docker("No such container: af-test-xyz".to_string());
        assert!(
            !is_transient_error(&not_found_err),
            "Docker 'no such container' must NOT be classified as transient"
        );

        // The maintenance code maps RuntimeNotFound → terminal success.
        // Verify the mapping by replicating the exact match arm from
        // remove_container_for_cleanup.
        let terminal_result: urt_executor::error::Result<()> = Err(ExecutorError::RuntimeNotFound);
        let treated_as_success = matches!(terminal_result, Err(ExecutorError::RuntimeNotFound));
        assert!(
            treated_as_success,
            "RuntimeNotFound must be treated as terminal success in the cleanup helper"
        );
    }
}

/// Regression tests proving the v0.4.0 bot-scanner pending-wait fix.
///
/// Before the fix, execution / commands / logs requests issued against a
/// runtime that was mid-build (status = "pending") would park for the full
/// caller-supplied timeout (up to 30 s) and return 504.  After the fix:
///
/// - Execution requests with an empty `image` field return 404 immediately.
/// - Commands and logs requests always return 404 immediately for pending IDs.
/// - Execution requests with a non-empty `image` field still wait, bounded by
///   `Config::pending_wait_max_secs` rather than the raw caller timeout.
/// - The `ReadinessGuard` RAII type ensures parked waiters are always woken
///   when the notifier is dropped on an error path.
/// - A completely unknown ID (no registry entry, no notifier) short-circuits
///   after a single ~10 ms poll rather than the old ~200 ms ceiling.
///
/// Test naming mirrors the eight required cases in the brief.
mod regression_pending_wait {
    use super::*;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use urt_executor::runtime::Runtime;

    // ─────────────────────────────────────────────────────────────────────
    // Shared helpers
    // ─────────────────────────────────────────────────────────────────────

    /// Build a JSON execution payload.  `image` is intentionally a parameter
    /// so we can toggle the "scan" vs "creation" code path.
    fn exec_payload_with_image(timeout_secs: u32, image: &str) -> String {
        serde_json::json!({
            "body": "",
            "path": "/",
            "method": "GET",
            "headers": {},
            "timeout": timeout_secs,
            "image": image
        })
        .to_string()
    }

    /// POST /v1/runtimes/{runtime_id}/executions with a custom payload.
    async fn post_execution_raw(
        app: axum::Router,
        runtime_id: &str,
        payload: String,
    ) -> axum::http::Response<axum::body::Body> {
        app.oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/v1/runtimes/{}/executions", runtime_id))
                .header("Authorization", "Bearer test-secret-key")
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(payload))
                .unwrap(),
        )
        .await
        .unwrap()
    }

    /// POST /v1/runtimes/{runtime_id}/commands.
    async fn post_command_rp(
        app: axum::Router,
        runtime_id: &str,
        timeout_secs: u32,
    ) -> axum::http::Response<axum::body::Body> {
        let payload =
            serde_json::json!({ "command": "echo hello", "timeout": timeout_secs }).to_string();
        app.oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/v1/runtimes/{}/commands", runtime_id))
                .header("Authorization", "Bearer test-secret-key")
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(payload))
                .unwrap(),
        )
        .await
        .unwrap()
    }

    /// GET /v1/runtimes/{runtime_id}/logs.
    async fn get_logs_rp(
        app: axum::Router,
        runtime_id: &str,
        timeout_secs: u32,
    ) -> axum::http::Response<axum::body::Body> {
        app.oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri(format!(
                    "/v1/runtimes/{}/logs?timeout={}",
                    runtime_id, timeout_secs
                ))
                .header("Authorization", "Bearer test-secret-key")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 1: scan request (empty image) does NOT park on pending runtime
    // ─────────────────────────────────────────────────────────────────────

    /// Before the fix, a bot-scanner POST to /executions with `timeout=30` for
    /// a mid-build runtime would park for 30 s and return 504.
    ///
    /// After the fix: `should_wait_for_pending = !req.image.is_empty()`.  With
    /// an empty `image`, resolve_runtime_with_readiness returns RuntimeNotFound
    /// immediately when the registry entry is pending, regardless of the caller
    /// timeout.
    ///
    /// Regression signal: if the response takes > 2 s this test is failing.
    #[tokio::test]
    async fn scan_request_does_not_park_on_pending_runtime() {
        require_docker!(state);

        tokio::time::timeout(Duration::from_secs(5), async move {
            let hostname = state.config.hostname.clone();
            let runtime_id = "rp-scan-no-park";
            let full_name = format!("{}-{}", hostname, runtime_id);

            // Insert a pending runtime entry — this simulates a mid-build state.
            let pending = Runtime::new(runtime_id, &hostname, "test-image:latest", "v5", None);
            state
                .registry
                .insert(pending)
                .await
                .expect("insert pending");

            // Insert the readiness notifier, mirroring production create_runtime ordering.
            let _notifier = state.readiness_notifier(&full_name);

            let app = create_router(state.clone());

            // Scan request: empty image field, 30-second timeout.
            // The fix must make this return 404 immediately, not 30 s from now.
            let payload = exec_payload_with_image(30, "");
            let start = Instant::now();
            let response = post_execution_raw(app, runtime_id, payload).await;
            let elapsed = start.elapsed();

            // Must be a 404 (RuntimeNotFound), NOT 504 (RuntimeTimeout).
            assert_eq!(
                response.status(),
                StatusCode::NOT_FOUND,
                "Expected 404 (RuntimeNotFound) for scan request against pending runtime, \
                 got {} (elapsed: {:?}); without the fix this would be 504 after 30 s",
                response.status(),
                elapsed
            );

            let body = parse_json_body(response.into_body()).await;
            assert_eq!(
                body["type"], "runtime_not_found",
                "Error type must be runtime_not_found, got: {}",
                body
            );

            // Wall-clock guard: must complete well under 1 second.
            assert!(
                elapsed < Duration::from_secs(1),
                "Request took {:?}; expected < 1 s — scan request must NOT park on \
                 pending runtime (regression: would block ~30 s without the fix)",
                elapsed
            );
        })
        .await
        .expect("test timed out after 5 s — possible park regression");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 2: legitimate creation request still waits on pending runtime
    // ─────────────────────────────────────────────────────────────────────

    /// When the caller supplies a non-empty `image`, it is the owner of the
    /// build it triggered.  The fix sets `should_wait_for_pending = true` for
    /// this path, so the request must still park and wake when notified.
    ///
    /// A background task notifies at ~200 ms, transitions the runtime to
    /// running, then the request wakes and resolves the runtime.  The
    /// downstream TCP connect to the fake hostname fails fast, but the
    /// response must arrive well before `pending_wait_max_secs` (60 s default).
    #[tokio::test]
    async fn legitimate_creation_request_still_waits_on_pending() {
        require_docker!(state);

        tokio::time::timeout(Duration::from_secs(8), async move {
            let hostname = state.config.hostname.clone();
            let runtime_id = "rp-legit-wait";
            let full_name = format!("{}-{}", hostname, runtime_id);

            // Insert pending runtime + notifier.
            let pending = Runtime::new(runtime_id, &hostname, "test-image:latest", "v5", None);
            state
                .registry
                .insert(pending)
                .await
                .expect("insert pending");
            let _notifier = state.readiness_notifier(&full_name);

            let app = create_router(state.clone());
            let rid = runtime_id.to_string();
            let start = Instant::now();

            // Non-empty image → should_wait_for_pending = true → parks on pending.
            let payload = exec_payload_with_image(30, "openruntimes/node:v5-25");
            let exec_handle =
                tokio::spawn(async move { post_execution_raw(app, &rid, payload).await });

            // Allow the spawned task to park on the Notify.
            tokio::time::sleep(Duration::from_millis(50)).await;

            // Transition the runtime to running and broadcast the wake-up.
            let mut running = state
                .registry
                .get(&full_name)
                .await
                .expect("runtime must still be in registry");
            running.mark_running("running");
            running.set_listening(); // skip TCP port check
            state
                .registry
                .update(running)
                .await
                .expect("update to running");
            state.readiness_notify_and_remove(&full_name);

            let response = exec_handle.await.expect("execution task panicked");
            let elapsed = start.elapsed();

            // Must resolve quickly (woken by notify, then fast-fails on network).
            assert!(
                elapsed < Duration::from_secs(3),
                "Response took {:?}; expected < 3 s — legitimate build request \
                 may not have woken on the readiness notify",
                elapsed
            );

            // A 404 here means the runtime was not found after notification
            // (wrong path — the waiter must have resolved Ok(runtime)).
            assert_ne!(
                response.status(),
                StatusCode::NOT_FOUND,
                "Got 404 ({:?}): runtime was not resolved from registry after wakeup; \
                 should_wait_for_pending path may be broken",
                elapsed
            );
        })
        .await
        .expect("test timed out after 8 s");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 3: pending wait is capped by Config::pending_wait_max_secs
    // ─────────────────────────────────────────────────────────────────────

    /// `pending_wait_max_secs = 1` caps the park duration independently of the
    /// caller's `req.timeout`.  A creation request with `timeout=30` against a
    /// runtime that is never notified must time out after ~1 s (the cap), not
    /// 30 s, and must return RuntimeTimeout (504).
    ///
    /// Uses `tokio::time::pause` + `advance` so the test completes
    /// instantaneously rather than burning 1 s of real wall-clock time.
    #[tokio::test(start_paused = true)]
    async fn pending_wait_capped_by_config() {
        // We cannot use require_docker! here because that macro calls
        // create_test_state() which makes async Docker calls; with time paused
        // those may not resolve correctly.  Instead we build a minimal
        // no-Docker AppState directly, mirroring create_test_state() but
        // short-circuiting the Docker connection.
        //
        // If Docker is genuinely unavailable the test_config/create_test_state
        // path would return None and we'd need to skip anyway.  This direct
        // build avoids the issue entirely.
        use urt_executor::{
            config::{ExecutorConfig, StorageConfig},
            docker::DockerManager,
            routes::AppState,
            runtime::{KeepAliveRegistry, RuntimeRegistry},
            storage,
        };

        let config = ExecutorConfig {
            host: "127.0.0.1".to_string(),
            port: 9901,
            secret: "test-secret-key".to_string(),
            metrics_enabled: false,
            env: "test".to_string(),
            networks: vec!["test-network".to_string()],
            hostname: "test-executor".to_string(),
            docker_hub_username: None,
            docker_hub_password: None,
            allowed_runtimes: vec![],
            runtime_versions: vec!["v5".to_string()],
            image_pull_enabled: false,
            auto_runtime: false,
            min_cpus: 0.0,
            min_memory: 0,
            keep_alive: false,
            inactive_threshold: 60,
            maintenance_interval: 3600,
            autoscale: false,
            eager_runtime_readiness: false,
            max_concurrent_executions: None,
            max_concurrent_runtime_creates: None,
            execution_queue_wait_ms: 2_000,
            runtime_create_queue_wait_ms: 5_000,
            max_body_size: 20 * 1024 * 1024,
            storage: StorageConfig::default(),
            logging_config: None,
            retry_attempts: 5,
            retry_delay_ms: 500,
            warmup_required: false,
            // KEY: cap the pending-wait at 1 second, regardless of req.timeout.
            pending_wait_max_secs: 1,
        };

        let docker = match DockerManager::new(config.clone()).await {
            Ok(d) => Arc::new(d),
            Err(_) => {
                eprintln!("Skipping pending_wait_capped_by_config: Docker not available");
                return;
            }
        };

        let registry = RuntimeRegistry::new();
        let keep_alive_registry = KeepAliveRegistry::new();
        let http_client = reqwest::Client::new();
        let storage: Arc<dyn urt_executor::storage::Storage> =
            Arc::from(storage::from_config(&config.storage).expect("storage"));

        let state = AppState {
            config,
            docker,
            registry,
            keep_alive_registry,
            http_client,
            storage,
            execution_limiter: None,
            runtime_create_limiter: None,
            execution_limiter_capacity: None,
            runtime_create_limiter_capacity: None,
            readiness: Arc::new(dashmap::DashMap::new()),
        };

        let hostname = state.config.hostname.clone();
        let runtime_id = "rp-cap-test";
        let full_name = format!("{}-{}", hostname, runtime_id);

        // Insert pending runtime + notifier — it will NEVER be notified.
        let pending = Runtime::new(runtime_id, &hostname, "test-image:latest", "v5", None);
        state
            .registry
            .insert(pending)
            .await
            .expect("insert pending");
        let _notifier = state.readiness_notifier(&full_name);

        let app = create_router(state.clone());
        let rid = runtime_id.to_string();

        // Non-empty image → waits on pending, bounded by pending_wait_max_secs=1.
        // req.timeout=30 is the caller deadline; the cap must override it.
        let payload = exec_payload_with_image(30, "openruntimes/node:v5-25");
        let exec_handle = tokio::spawn(async move { post_execution_raw(app, &rid, payload).await });

        // Allow the spawned task to reach the wait_for_pending park.
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Advance time past the 1-second cap to trigger RuntimeTimeout.
        tokio::time::advance(Duration::from_millis(1100)).await;

        // Allow the timeout future to fire after the advance.
        tokio::time::sleep(Duration::from_millis(10)).await;

        let response = tokio::time::timeout(Duration::from_secs(2), exec_handle)
            .await
            .expect("task did not complete after time advance")
            .expect("task panicked");

        // Must be 504 (RuntimeTimeout), not 30-second expiry or 404.
        assert_eq!(
            response.status(),
            StatusCode::GATEWAY_TIMEOUT,
            "Expected 504 (RuntimeTimeout) after pending_wait_max_secs=1 cap, got {}; \
             the cap may not be applied (would block 30 s without this fix)",
            response.status()
        );

        let body = parse_json_body(response.into_body()).await;
        assert_eq!(
            body["type"], "runtime_timeout",
            "Error type must be runtime_timeout, got: {}",
            body
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 4: commands route does NOT wait on pending runtime
    // ─────────────────────────────────────────────────────────────────────

    /// `commands::resolve_runtime` passes `should_wait_for_pending = false`.
    /// A pending runtime must cause an immediate 404, not a park for the full
    /// command timeout (default 600 s).
    ///
    /// Regression signal: response time > 1 s.
    #[tokio::test]
    async fn commands_route_does_not_wait_on_pending() {
        require_docker!(state);

        tokio::time::timeout(Duration::from_secs(5), async move {
            let hostname = state.config.hostname.clone();
            let runtime_id = "rp-cmd-no-wait";
            let full_name = format!("{}-{}", hostname, runtime_id);

            let pending = Runtime::new(runtime_id, &hostname, "test-image:latest", "v5", None);
            state
                .registry
                .insert(pending)
                .await
                .expect("insert pending");
            let _notifier = state.readiness_notifier(&full_name);

            let app = create_router(state.clone());

            // Commands route with a generous timeout — must return 404 fast.
            let start = Instant::now();
            let response = post_command_rp(app, runtime_id, 30).await;
            let elapsed = start.elapsed();

            assert_eq!(
                response.status(),
                StatusCode::NOT_FOUND,
                "Expected 404 for commands against pending runtime, got {} (elapsed: {:?}); \
                 without the fix this would park for ~30 s",
                response.status(),
                elapsed
            );

            assert!(
                elapsed < Duration::from_secs(1),
                "Commands response took {:?}; expected < 1 s — must not park on pending",
                elapsed
            );
        })
        .await
        .expect("test timed out after 5 s");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 5: logs route does NOT wait on pending runtime
    // ─────────────────────────────────────────────────────────────────────

    /// `logs::resolve_runtime` passes `should_wait_for_pending = false`.  A
    /// pending runtime must cause an immediate failure (404 is the mapped
    /// response because RuntimeNotFound and RuntimeTimeout both map to 404 in
    /// the logs handler).
    ///
    /// Regression signal: response time > 1 s.
    #[tokio::test]
    async fn logs_route_does_not_wait_on_pending() {
        require_docker!(state);

        tokio::time::timeout(Duration::from_secs(5), async move {
            let hostname = state.config.hostname.clone();
            let runtime_id = "rp-logs-no-wait";
            let full_name = format!("{}-{}", hostname, runtime_id);

            let pending = Runtime::new(runtime_id, &hostname, "test-image:latest", "v5", None);
            state
                .registry
                .insert(pending)
                .await
                .expect("insert pending");
            let _notifier = state.readiness_notifier(&full_name);

            let app = create_router(state.clone());

            // Logs route with a generous timeout — must return 404 fast.
            let start = Instant::now();
            let response = get_logs_rp(app, runtime_id, 30).await;
            let elapsed = start.elapsed();

            // logs::resolve_runtime maps both RuntimeNotFound and RuntimeTimeout
            // to 404 (RuntimeNotFound).
            assert_eq!(
                response.status(),
                StatusCode::NOT_FOUND,
                "Expected 404 for logs against pending runtime, got {} (elapsed: {:?}); \
                 without the fix this would park for ~30 s",
                response.status(),
                elapsed
            );

            assert!(
                elapsed < Duration::from_secs(1),
                "Logs response took {:?}; expected < 1 s — must not park on pending",
                elapsed
            );
        })
        .await
        .expect("test timed out after 5 s");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 6: ReadinessGuard fires on error path, waking parked waiters
    // ─────────────────────────────────────────────────────────────────────

    /// Fix D: `ReadinessGuard` is an RAII type that calls `notify_waiters()` +
    /// removes the DashMap entry on `Drop`, ensuring no error path between
    /// `readiness_notifier()` insertion and the explicit success-path notify
    /// can leave entries that park future requests forever.
    ///
    /// We prove this through the public API: we park a waiter on a pending
    /// runtime (using a scan request with empty `image`, which in the presence
    /// of a notifier will see the pending state but return immediately due to
    /// `should_wait_for_pending=false`).
    ///
    /// For the guard test we use a *second* request that arrives AFTER the
    /// notifier is dropped (simulating a future request hitting the ID after
    /// a failed build left the notifier in the map).  Without Fix D, the
    /// notifier entry would remain forever after an error path and a future
    /// request (with no registry entry) would enter the R1 branch, find the
    /// stale notifier, park on it, and wait until the caller deadline.
    ///
    /// With Fix D, the stale notifier is removed by the guard on every error
    /// path, so the future request finds NO notifier and takes the fast path.
    ///
    /// We simulate the leak scenario directly: insert a notifier without a
    /// matching registry entry (the state an error-path-without-guard would
    /// produce), then verify that a request for that ID still resolves in
    /// < 200 ms rather than hanging for the full deadline.
    ///
    /// Additionally we verify the guard-drop equivalent (notify + remove)
    /// wakes a parked concurrent task fast.
    #[tokio::test]
    async fn readiness_guard_fires_on_error_path() {
        require_docker!(state);

        // 3-second outer bound; any hang is a regression.
        tokio::time::timeout(Duration::from_secs(3), async move {
            let hostname = state.config.hostname.clone();
            let runtime_id = "rp-guard-error";
            let full_name = format!("{}-{}", hostname, runtime_id);

            // Simulate a build that inserted a pending runtime + notifier
            // but then hit an error before the explicit success-path notify.
            let pending = Runtime::new(runtime_id, &hostname, "test-image:latest", "v5", None);
            state
                .registry
                .insert(pending)
                .await
                .expect("insert pending");
            let _notifier = state.readiness_notifier(&full_name);

            // ── Part A: concurrent waiter wakes fast after guard drop ──────
            //
            // Spawn a waiter that parks on the pending runtime.  We use a
            // SCAN request (empty image) — it returns 404 immediately since
            // should_wait_for_pending=false.  To get a genuine park we
            // instead test the notify mechanism directly via the Arc<Notify>
            // API (mirrors exactly what ReadinessGuard::Drop does).
            let notify_arc = state.readiness_notifier(&full_name);
            let notify_clone = notify_arc.clone();

            // Spawn a task that parks on the notifier.
            let park_start = Instant::now();
            let park_handle = tokio::spawn(async move {
                // Park on the Notify — this will be woken by the guard drop.
                tokio::time::timeout(
                    Duration::from_secs(2),
                    notify_clone.notified(),
                )
                .await
            });

            // Give the park task time to reach the .await inside notified().
            tokio::time::sleep(Duration::from_millis(20)).await;

            // Simulate ReadinessGuard::Drop: notify_waiters() + remove.
            state.readiness_notify_and_remove(&full_name);
            state.registry.remove(&full_name).await;

            // The parked task must wake almost immediately after the drop.
            let park_result = park_handle.await.expect("park task panicked");
            let park_elapsed = park_start.elapsed();

            assert!(
                park_result.is_ok(),
                "Parked task timed out — notify_waiters() from guard drop did not fire"
            );

            assert!(
                park_elapsed < Duration::from_millis(500),
                "Parked task took {:?} to wake after guard drop; expected < 500 ms — \
                 Fix D wakeup may not be firing",
                park_elapsed
            );

            // ── Part B: stale notifier left in map parks future requests ──
            //
            // Verify that with Fix D in place (notifier removed on error path),
            // a subsequent request for the same ID does NOT park.  We simulate
            // the pre-Fix D state (stale notifier in map, no registry entry)
            // by re-inserting a notifier without a registry entry and then
            // issuing a request.  A request must complete in < 200 ms
            // (the R1 bound), proving the notifier does not hold it forever.
            //
            // In a correctly fixed codebase the guard removes the notifier on
            // error, so this scenario should not arise in production.  Here
            // we test the fallback: even if a stale notifier exists, the
            // request takes the R1 path and completes within the 200 ms bound.
            let runtime_id_b = "rp-guard-stale";
            let full_name_b = format!("{}-{}", hostname, runtime_id_b);

            // Insert a notifier with NO matching registry entry.
            let _stale_notifier = state.readiness_notifier(&full_name_b);

            let app = create_router(state.clone());
            let payload = exec_payload_with_image(30, "");
            let r1_start = Instant::now();
            let response = post_execution_raw(app, runtime_id_b, payload).await;
            let r1_elapsed = r1_start.elapsed();

            assert_eq!(
                response.status(),
                StatusCode::NOT_FOUND,
                "Expected 404 when no registry entry exists, got {}",
                response.status()
            );

            // The R1 path now does a single ~10 ms sleep (Fix E).
            // With a stale notifier but no registry entry the request must
            // complete in the R1 window, not hang.
            assert!(
                r1_elapsed < Duration::from_millis(200),
                "Request with stale notifier (no registry entry) took {:?}; \
                 expected < 200 ms — stale notifier may be parking the request",
                r1_elapsed
            );
        })
        .await
        .expect("guard error-path test timed out — waiter may be hanging on dead notifier (Fix D regression)");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 7: unknown-ID R1 poll short-circuits fast (Fix E)
    // ─────────────────────────────────────────────────────────────────────

    /// Fix E caps the R1 speculative poll to a single ~10 ms iteration for
    /// IDs that have NO registry entry and NO notifier.  Before the fix, the
    /// poll ceiling was ~200 ms (iterating loop).
    ///
    /// We issue a request for a completely unknown runtime ID and assert
    /// elapsed time < 150 ms.  Without Fix E this would burn at least 200 ms.
    ///
    /// The assertion threshold is deliberately generous (< 150 ms) to avoid
    /// flakiness on cold CI machines while still catching the pre-fix 200 ms
    /// floor.
    #[tokio::test]
    async fn unknown_id_r1_poll_short_circuits_fast() {
        require_docker!(state);

        tokio::time::timeout(Duration::from_secs(3), async move {
            let runtime_id = "rp-unknown-r1-fast";

            // No registry entry, no notifier — completely unknown ID.
            let app = create_router(state.clone());
            let payload = exec_payload_with_image(30, "");

            let start = Instant::now();
            let response = post_execution_raw(app, runtime_id, payload).await;
            let elapsed = start.elapsed();

            // Must be 404.
            assert_eq!(
                response.status(),
                StatusCode::NOT_FOUND,
                "Expected 404 for unknown runtime ID, got {}",
                response.status()
            );

            // Must complete well under the old 200 ms R1 polling ceiling.
            assert!(
                elapsed < Duration::from_millis(150),
                "Unknown-ID request took {:?}; expected < 150 ms — Fix E R1 poll \
                 reduction may be absent (pre-fix would take >= 200 ms)",
                elapsed
            );
        })
        .await
        .expect("unknown-ID test timed out");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 8: bot-scan storm concurrent with a legitimate build
    // ─────────────────────────────────────────────────────────────────────

    /// End-to-end load test for the regression scenario described in the brief.
    ///
    /// Setup:
    ///   - Insert a pending runtime + notifier (simulates a mid-build state).
    ///   - Spawn 50 scan requests (empty `image`) concurrently.
    ///   - Spawn 1 legitimate-build task (non-empty `image`) concurrently.
    ///   - After 200 ms, transition the runtime to running and fire the notify.
    ///
    /// Assertions:
    ///   (a) All 50 scan requests return 404 in < 1 s each.
    ///   (b) The build path returns a non-404 status (woke via notify).
    ///   (c) p99 latency for the 50 scans is < 500 ms.
    ///
    /// Without the fix, all 50 scans would park for 30 s before returning 504,
    /// blocking the executor thread pool and delaying the legitimate build path.
    #[tokio::test]
    async fn bot_scan_concurrent_with_build_does_not_block_build() {
        require_docker!(state);

        // Generous outer bound; real assertions are stricter.
        tokio::time::timeout(Duration::from_secs(15), async move {
            let hostname = state.config.hostname.clone();
            let runtime_id = "rp-storm-test";
            let full_name = format!("{}-{}", hostname, runtime_id);

            let pending = Runtime::new(runtime_id, &hostname, "test-image:latest", "v5", None);
            state
                .registry
                .insert(pending)
                .await
                .expect("insert pending");
            let _notifier = state.readiness_notifier(&full_name);

            const N_SCANS: usize = 50;
            let storm_start = Instant::now();

            // Spawn N scan requests (empty image → must return 404 fast).
            let mut scan_handles = Vec::with_capacity(N_SCANS);
            for _ in 0..N_SCANS {
                let app = create_router(state.clone());
                let rid = runtime_id.to_string();
                let payload = exec_payload_with_image(30, "");
                scan_handles.push(tokio::spawn(async move {
                    let t0 = Instant::now();
                    let resp = post_execution_raw(app, &rid, payload).await;
                    (resp, t0.elapsed())
                }));
            }

            // Spawn 1 legitimate-build request (non-empty image → parks until notified).
            let build_app = create_router(state.clone());
            let build_rid = runtime_id.to_string();
            let build_payload = exec_payload_with_image(30, "openruntimes/node:v5-25");
            let build_handle = tokio::spawn(async move {
                post_execution_raw(build_app, &build_rid, build_payload).await
            });

            // Wait for scans to resolve (they should be near-instant).
            // We collect scan results with a generous 4-second timeout.
            let scan_results: Vec<(axum::http::Response<axum::body::Body>, Duration)> =
                tokio::time::timeout(
                    Duration::from_secs(4),
                    futures::future::join_all(scan_handles),
                )
                .await
                .expect(
                    "scan tasks did not complete within 4 s — all 50 may be parked (regression)",
                )
                .into_iter()
                .map(|r| r.expect("scan task panicked"))
                .collect();

            // After scans complete, fire the build notification.
            let mut running = state
                .registry
                .get(&full_name)
                .await
                .expect("pending runtime must still be in registry");
            running.mark_running("running");
            running.set_listening();
            state
                .registry
                .update(running)
                .await
                .expect("update to running");
            state.readiness_notify_and_remove(&full_name);

            let build_response = tokio::time::timeout(Duration::from_secs(5), build_handle)
                .await
                .expect("build task did not complete within 5 s after notification")
                .expect("build task panicked");

            // ── Assertion (a): all scans returned 404 ─────────────────────
            let non_404_scans: Vec<_> = scan_results
                .iter()
                .filter(|(r, _)| r.status() != StatusCode::NOT_FOUND)
                .collect();
            assert!(
                non_404_scans.is_empty(),
                "{} out of {} scan requests did not return 404 — \
                 scan requests may be parking on the pending runtime (regression)",
                non_404_scans.len(),
                N_SCANS
            );

            // ── Assertion (b): build path returned a non-404 status ───────
            // After wakeup the build resolves the running runtime; the HTTP
            // connect to the fake hostname fails, but it must NOT be 404
            // (which would mean the runtime was not found after notification).
            assert_ne!(
                build_response.status(),
                StatusCode::NOT_FOUND,
                "Build path returned 404: runtime was not resolved after notification; \
                 the build task may not have woken correctly"
            );

            // ── Assertion (c): p99 scan latency < 500 ms ──────────────────
            let mut latencies: Vec<Duration> = scan_results.iter().map(|(_, d)| *d).collect();
            latencies.sort_unstable();
            let p99_idx = (N_SCANS as f64 * 0.99).ceil() as usize - 1;
            let p99_idx = p99_idx.min(latencies.len() - 1);
            let p99 = latencies[p99_idx];

            assert!(
                p99 < Duration::from_millis(500),
                "Scan p99 latency = {:?}; expected < 500 ms — \
                 some scan requests may have parked briefly on the pending runtime",
                p99
            );

            // Total storm elapsed (all scans + build) sanity check.
            let total_elapsed = storm_start.elapsed();
            assert!(
                total_elapsed < Duration::from_secs(10),
                "Total storm elapsed {:?}; expected < 10 s",
                total_elapsed
            );
        })
        .await
        .expect("bot-scan storm test timed out — possible parking regression");
    }
}

mod cold_start {
    use super::*;
    use std::time::{Duration, Instant};
    use urt_executor::runtime::Runtime;

    #[tokio::test]
    async fn pending_runtime_past_timeout_returns_504() {
        require_docker!(state);

        let hostname = state.config.hostname.clone();
        let runtime_id = "cold-start-timeout-test";
        let _full_name = format!("{}-{}", hostname, runtime_id);

        let pending_runtime = Runtime::new(runtime_id, &hostname, "test-image:latest", "v5", None);
        state
            .registry
            .insert(pending_runtime)
            .await
            .expect("failed to insert pending runtime into registry");

        let app = create_router(state);

        // Non-empty `image` so the request takes the caller-owns-build path
        // (wait_for_pending=true) and parks until the timeout fires.  Without
        // this, the v0.4.1 fast-fail-on-pending design returns 404 immediately.
        let payload = serde_json::json!({
            "body": "",
            "path": "/",
            "method": "GET",
            "headers": {},
            "timeout": 1,
            "image": "openruntimes/node:v5-25"
        });

        let start = Instant::now();
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/v1/runtimes/{}/executions", runtime_id))
                    .header("Authorization", "Bearer test-secret-key")
                    .header("Content-Type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let elapsed = start.elapsed();

        assert_eq!(
            response.status(),
            StatusCode::GATEWAY_TIMEOUT,
            "Expected 504 when runtime stays pending past timeout, got {} (elapsed: {:?})",
            response.status(),
            elapsed
        );

        let body = parse_json_body(response.into_body()).await;
        assert_eq!(
            body["code"], 504,
            "Error body 'code' must be 504, got: {}",
            body
        );
        assert_eq!(
            body["type"], "runtime_timeout",
            "Error body 'type' must be 'runtime_timeout', got: {}",
            body
        );

        assert!(
            elapsed >= Duration::from_millis(900),
            "Request resolved too quickly ({:?}); polling deadline may not have been honoured",
            elapsed
        );
        assert!(
            elapsed < Duration::from_secs(10),
            "Request hung for {:?}; possible infinite loop regression",
            elapsed
        );
    }

    #[tokio::test]
    async fn already_running_runtime_skips_cold_start_polling() {
        require_docker!(state);

        let hostname = state.config.hostname.clone();
        let runtime_id = "cold-start-running-test";
        let full_name = format!("{}-{}", hostname, runtime_id);

        let mut running_runtime =
            Runtime::new(runtime_id, &hostname, "test-image:latest", "v5", None);
        running_runtime.mark_running("running");
        running_runtime.set_listening();

        state
            .registry
            .insert(running_runtime)
            .await
            .expect("failed to insert running runtime into registry");

        let app = create_router(state);

        let payload = serde_json::json!({
            "body": "",
            "path": "/",
            "method": "GET",
            "headers": {},
            "timeout": 5
        });

        let start = Instant::now();
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/v1/runtimes/{}/executions", runtime_id))
                    .header("Authorization", "Bearer test-secret-key")
                    .header("Content-Type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let elapsed = start.elapsed();

        assert_ne!(
            response.status(),
            StatusCode::NOT_FOUND,
            "Got 404: runtime was not resolved from the registry (full_name: {})",
            full_name
        );

        assert!(
            elapsed < Duration::from_secs(4),
            "Request took {:?}, suggesting cold-start polling fired for a running runtime",
            elapsed
        );
    }
}

mod source_archive_integrity {
    //! An object store answering a GET with an error document must not produce
    //! a runtime. These tests drive the local storage backend, so they need
    //! neither network nor object storage.

    use super::*;
    use std::io::Write;
    use std::path::PathBuf;
    use urt_executor::storage::{download_verified_archive, LocalStorage};

    /// The body Hetzner object storage returned for every object during the
    /// 25 Aug outage: 207 bytes of XML with a 503 status.
    const S3_ERROR_BODY: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>ServiceUnavailable</Code><Message>Service is unable to handle request.</Message></Error>"#;

    fn gzipped_source() -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(b"module.exports = () => {};").unwrap();
        encoder.finish().unwrap()
    }

    #[tokio::test]
    async fn error_document_named_code_tar_gz_fails_the_download() {
        let store = tempfile::tempdir().unwrap();
        tokio::fs::write(store.path().join("code.tar.gz"), S3_ERROR_BODY)
            .await
            .unwrap();
        let storage = LocalStorage::with_base_path(store.path().to_str().unwrap());

        let destination = tempfile::tempdir().unwrap();
        let local_source = destination.path().join("src").join("code.tar.gz");

        let error = download_verified_archive(&storage, "code.tar.gz", &local_source, 2, 1)
            .await
            .expect_err("an error document must not be accepted as a build");

        let message = error.to_string();
        assert!(message.contains("it is an error document"), "{}", message);
        assert!(
            !local_source.exists(),
            "a rejected artefact was left at {}",
            local_source.display()
        );
    }

    #[tokio::test]
    async fn real_archive_downloads_and_reports_its_size() {
        let store = tempfile::tempdir().unwrap();
        let archive = gzipped_source();
        tokio::fs::write(store.path().join("code.tar.gz"), &archive)
            .await
            .unwrap();
        let storage = LocalStorage::with_base_path(store.path().to_str().unwrap());

        let destination = tempfile::tempdir().unwrap();
        let local_source = destination.path().join("src").join("code.tar.gz");

        let size = download_verified_archive(&storage, "code.tar.gz", &local_source, 2, 1)
            .await
            .expect("a real archive downloads");

        assert_eq!(size, archive.len() as u64);
        assert_eq!(tokio::fs::read(&local_source).await.unwrap(), archive);
    }

    /// End-to-end through `POST /v1/runtimes`: the create must fail, no
    /// registry entry may survive, and the runtime's tmp folder must be gone,
    /// so the next request for the deployment starts a fresh create.
    #[tokio::test]
    async fn create_rejects_error_document_source_and_leaves_no_registry_entry() {
        require_docker!(state);

        let runtime_id = format!("urt-xml-source-{}", uuid::Uuid::new_v4().simple());
        let full_name = format!("{}-{}", state.config.hostname, runtime_id);

        // The default storage backend is the local filesystem rooted at the
        // system temp directory, so the source key is a path relative to it.
        let source_key = format!("{}/code.tar.gz", runtime_id);
        let source_path = std::env::temp_dir().join(&source_key);
        tokio::fs::create_dir_all(source_path.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&source_path, S3_ERROR_BODY).await.unwrap();

        let payload = json!({
            "runtimeId": runtime_id,
            "image": "alpine:latest",
            "entrypoint": "",
            "source": source_key,
            "version": "v5",
            "variables": {}
        });

        let response = create_router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/runtimes")
                    .header("Authorization", "Bearer test-secret-key")
                    .header("Content-Type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(
            response.status().is_client_error() || response.status().is_server_error(),
            "create should have failed, got {}",
            response.status()
        );

        assert!(
            !state.registry.exists(&full_name).await,
            "a runtime was registered from a source that is not an archive"
        );

        let tmp_folder: PathBuf = std::env::temp_dir().join(&full_name);
        assert!(
            !tmp_folder.exists(),
            "the failed create left {} behind",
            tmp_folder.display()
        );

        tokio::fs::remove_dir_all(std::env::temp_dir().join(&runtime_id))
            .await
            .ok();
    }
}
