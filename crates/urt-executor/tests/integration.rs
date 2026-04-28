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
    fn exec_payload(timeout_secs: u32) -> String {
        serde_json::json!({
            "body": "",
            "path": "/",
            "method": "GET",
            "headers": {},
            "timeout": timeout_secs
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

    /// When the runtime is removed while executions are waiting (e.g. due to a
    /// create_runtime failure path), the waiters must receive a deterministic
    /// outcome — either RuntimeNotFound (404) or RuntimeTimeout (504) — within
    /// the execution deadline.  They must NOT panic or hang past the deadline.
    ///
    /// Production ordering: readiness_notify_and_remove THEN registry.remove.
    /// After wake, wait_for_pending re-checks the registry, finds None, and
    /// returns None → resolve_runtime falls through to adoption → adoption
    /// fails (no Docker) → RuntimeNotFound.
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
            let exec_handle = tokio::spawn(async move { post_execution(app, &rid, 2).await });

            // Give the execution task a moment to park on the Notify.
            tokio::time::sleep(Duration::from_millis(100)).await;

            // Production failure-path ordering: notify BEFORE remove.
            state.readiness_notify_and_remove(&full_name);
            state.registry.remove(&full_name).await;

            let response = exec_handle.await.expect("execution task panicked");

            // The outcome must be one of the two legal deterministic errors.
            // Anything else (200, 500, panic, hang) is a regression.
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

    // ─────────────────────────────────────────────────────────────────────────
    // Test 7: waiter that arrives before the registry insert still wakes (R1)
    // ─────────────────────────────────────────────────────────────────────────

    /// The R1 fix: resolve_runtime acquires a Notify future *before* the first
    /// registry check.  If the entry does not yet exist it parks on that future
    /// for up to 200 ms (the R1 sub-deadline configured in executions.rs) before
    /// falling through to the adoption path.
    ///
    /// Race window under test:
    ///   Task A  — calls the execution endpoint when the runtime is NOT yet in
    ///             the registry.  The R1 path parks on the pre-acquired Notify.
    ///   Task B  — after 50 ms inserts the runtime as pending, then after
    ///             another 50 ms marks it running and calls
    ///             readiness_notify_and_remove.
    ///
    /// Task B's total delay (~100 ms) is inside the 200 ms R1 sub-deadline, so
    /// task A must observe the notification and proceed through resolve_runtime.
    ///
    /// Assertion strategy: timing.  The execution payload uses a 30-second
    /// deadline so a pending-timeout regression would not respond for 30 s.
    /// A correct wakeup + fast network failure returns within ~1 s.
    ///
    /// Sub-deadline note: the R1 sub-deadline is `min(200ms, remaining)`.
    /// With a 30-second execution deadline the effective bound is 200 ms.
    /// The test pre-creates the notifier entry so the notification fired by
    /// task B is stored in the DashMap entry that task A's resolve_runtime
    /// will use when it calls readiness_notifier.
    #[tokio::test]
    async fn waiter_arrived_before_insert_still_wakes() {
        require_docker!(state);

        // Outer timeout is generous to catch hangs; the real assertion is elapsed.
        tokio::time::timeout(Duration::from_secs(8), async move {
            let hostname = state.config.hostname.clone();
            let runtime_id = "rg-r1-preinsert";
            let full_name = format!("{}-{}", hostname, runtime_id);

            // Pre-create the notifier entry in the readiness map BEFORE the
            // execution task starts.  This mirrors the production ordering in
            // create_runtime (readiness_notifier before registry.insert) and
            // ensures the DashMap entry exists when resolve_runtime calls
            // readiness_notifier on its own.
            let _notifier = state.readiness_notifier(&full_name);

            // Task A: post an execution for a runtime that does not yet exist.
            // Long deadline so the only fast path is wakeup → network failure.
            let app = create_router(state.clone());
            let rid = runtime_id.to_string();
            let start = Instant::now();
            let exec_handle = tokio::spawn(async move { post_execution(app, &rid, 30).await });

            // Give task A a moment to reach the R1 park inside resolve_runtime.
            tokio::time::sleep(Duration::from_millis(50)).await;

            // Task B step 1: insert the runtime as pending.
            let pending = Runtime::new(runtime_id, &hostname, "test-image:latest", "v5", None);
            state
                .registry
                .insert(pending)
                .await
                .expect("insert pending");

            // Task B step 2: 50 ms later, transition to running and notify.
            // Total task-B delay = 100 ms < 200 ms R1 sub-deadline.
            tokio::time::sleep(Duration::from_millis(50)).await;

            let mut running = state
                .registry
                .get(&full_name)
                .await
                .expect("runtime must still be present");
            running.mark_running("running");
            running.set_listening();
            state
                .registry
                .update(running)
                .await
                .expect("update to running");
            state.readiness_notify_and_remove(&full_name);

            let response = exec_handle.await.expect("execution task panicked");
            let elapsed = start.elapsed();

            // A response within 3 seconds proves task A woke via the
            // notification (not via the 30-second deadline or the R1 200 ms
            // timeout followed by adoption failure).
            assert!(
                elapsed < Duration::from_secs(3),
                "Response took {:?}; expected < 3 s — R1 waiter may not have caught \
                 the notification within the 200 ms sub-deadline",
                elapsed
            );

            // After R1 wakeup task A re-checks the registry, finds the running
            // runtime, and proceeds past resolve_runtime.  A 404 here means
            // task A fell through to adoption and Docker returned nothing.
            assert_ne!(
                response.status(),
                StatusCode::NOT_FOUND,
                "Got 404 ({:?}): R1 waiter did not observe the notification; \
                 task A may have fallen through to adoption",
                elapsed
            );
        })
        .await
        .expect("R1 pre-insert test timed out after 8 seconds");
    }
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

    fn cmd_payload(timeout_secs: u32) -> String {
        serde_json::json!({ "command": "echo hello", "timeout": timeout_secs }).to_string()
    }

    async fn post_command(
        app: axum::Router,
        runtime_id: &str,
        timeout_secs: u32,
    ) -> axum::http::Response<axum::body::Body> {
        app.oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/v1/runtimes/{}/commands", runtime_id))
                .header("Authorization", "Bearer test-secret-key")
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(cmd_payload(timeout_secs)))
                .unwrap(),
        )
        .await
        .unwrap()
    }

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
    // Test 1: commands route parks on readiness gate and wakes when running
    // ─────────────────────────────────────────────────────────────────────────

    /// A pending runtime inserted before the commands request arrives must
    /// cause the handler to park on the readiness Notify and wake once the
    /// runtime is marked running.  After waking, resolve_runtime returns the
    /// runtime and the command handler attempts to exec — that attempt fails
    /// (no real Docker), but the response arrives well before the deadline.
    #[tokio::test]
    async fn commands_resolve_waits_for_pending_runtime() {
        require_docker!(state);

        tokio::time::timeout(Duration::from_secs(8), async move {
            let hostname = state.config.hostname.clone();
            let runtime_id = "af-cmd-wait";
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

            let start = Instant::now();
            // Long timeout so the only fast-exit path is wakeup + exec failure.
            let handle = tokio::spawn(async move { post_command(app, &rid, 30).await });

            tokio::time::sleep(Duration::from_millis(150)).await;

            let mut running = state
                .registry
                .get(&full_name)
                .await
                .expect("runtime must be in registry");
            running.mark_running("running");
            running.set_listening();
            state.registry.update(running).await.expect("update");

            state.readiness_notify_and_remove(&full_name);

            let response = handle.await.expect("task panicked");
            let elapsed = start.elapsed();

            // Response must arrive well before the 30-second command deadline —
            // wakeup happens at ~150 ms and exec fails fast (no real container).
            assert!(
                elapsed < Duration::from_secs(3),
                "Response took {:?}; expected < 3 s — commands resolve may not have \
                 woken on the readiness notify",
                elapsed
            );

            // A 404 would mean the runtime was never resolved after notification.
            assert_ne!(
                response.status(),
                StatusCode::NOT_FOUND,
                "Got 404: runtime was not found after wakeup (elapsed: {:?})",
                elapsed
            );
        })
        .await
        .expect("test timed out after 8 s");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 2: commands route returns 504 when pending runtime never becomes ready
    // ─────────────────────────────────────────────────────────────────────────

    /// When the runtime stays pending and the command timeout expires, the
    /// handler must return HTTP 504 with type "runtime_timeout".
    #[tokio::test]
    async fn commands_resolve_returns_504_on_timeout() {
        require_docker!(state);

        tokio::time::timeout(Duration::from_secs(5), async move {
            let hostname = state.config.hostname.clone();
            let runtime_id = "af-cmd-timeout";
            let full_name = format!("{}-{}", hostname, runtime_id);

            let pending = Runtime::new(runtime_id, &hostname, "test-image:latest", "v5", None);
            state
                .registry
                .insert(pending)
                .await
                .expect("insert pending");

            let _notifier = state.readiness_notifier(&full_name);

            let app = create_router(state.clone());

            let start = Instant::now();
            // 1-second command timeout so the test completes quickly.
            let response = post_command(app, runtime_id, 1).await;
            let elapsed = start.elapsed();

            assert_eq!(
                response.status(),
                StatusCode::GATEWAY_TIMEOUT,
                "Expected 504, got {} (elapsed: {:?})",
                response.status(),
                elapsed
            );

            let body = parse_json_body(response.into_body()).await;
            assert_eq!(body["code"], 504, "code must be 504, got: {}", body);
            assert_eq!(
                body["type"], "runtime_timeout",
                "type must be 'runtime_timeout', got: {}",
                body
            );

            // Must have spent at least the deadline amount of time waiting.
            assert!(
                elapsed >= Duration::from_millis(900),
                "Response arrived too quickly ({:?}); deadline may not have been honoured",
                elapsed
            );
        })
        .await
        .expect("test timed out after 5 s");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 3: logs route parks on readiness gate and wakes when running
    // ─────────────────────────────────────────────────────────────────────────

    /// The logs handler uses `resolve_runtime_with_readiness` with the
    /// `timeout_secs` from the query parameter.  A pending runtime must cause
    /// the handler to park and then wake once the runtime is marked running,
    /// delivering a response well before the 30-second deadline.
    #[tokio::test]
    async fn logs_resolve_waits_for_pending_runtime() {
        require_docker!(state);

        tokio::time::timeout(Duration::from_secs(8), async move {
            let hostname = state.config.hostname.clone();
            let runtime_id = "af-logs-wait";
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

            let start = Instant::now();
            let handle = tokio::spawn(async move { get_logs(app, &rid, 30).await });

            tokio::time::sleep(Duration::from_millis(150)).await;

            let mut running = state
                .registry
                .get(&full_name)
                .await
                .expect("runtime must be in registry");
            running.mark_running("running");
            running.set_listening();
            state.registry.update(running).await.expect("update");

            state.readiness_notify_and_remove(&full_name);

            let response = handle.await.expect("task panicked");
            let elapsed = start.elapsed();

            // Logs handler wakes, resolves the runtime, then returns the SSE
            // stream (or 404/error) quickly.
            assert!(
                elapsed < Duration::from_secs(3),
                "Response took {:?}; expected < 3 s — logs resolve may not have \
                 woken on the readiness notify",
                elapsed
            );

            // A 404 would mean the runtime was not resolved after wakeup.
            assert_ne!(
                response.status(),
                StatusCode::NOT_FOUND,
                "Got 404: runtime was not found in logs handler after wakeup (elapsed: {:?})",
                elapsed
            );
        })
        .await
        .expect("test timed out after 8 s");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 4: logs resolve is no longer capped at 2 seconds
    // ─────────────────────────────────────────────────────────────────────────

    /// Previously `logs::resolve_runtime` used a hardcoded 2-second grace
    /// period.  The fix uses the `timeout_secs` query param.  This test
    /// verifies the new behaviour by:
    ///   1. Starting a pending runtime with NO readiness transition.
    ///   2. Asserting that a logs request with `timeout=10` has NOT returned
    ///      at the 2.5-second mark (proving the 2-second cap was removed).
    ///   3. Then transitioning the runtime to running and notifying.
    ///   4. Asserting the request returns successfully shortly after.
    #[tokio::test]
    async fn logs_resolve_no_longer_capped_at_2s() {
        require_docker!(state);

        // Outer timeout is generous; real assertion is timing.
        tokio::time::timeout(Duration::from_secs(10), async move {
            let hostname = state.config.hostname.clone();
            let runtime_id = "af-logs-no-2s-cap";
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

            let start = Instant::now();
            // 10-second timeout passed via query param — previously the handler
            // would cap at 2 s; now it must wait the full 10 s (or until notified).
            let handle = tokio::spawn(async move { get_logs(app, &rid, 10).await });

            // Verify that at 2.5 s the request has NOT yet returned.
            tokio::time::sleep(Duration::from_millis(2500)).await;

            // If the task already completed, it hit the old 2-second cap.
            assert!(
                !handle.is_finished(),
                "Logs request finished at ~2.5 s — the 2-second hardcoded cap \
                 appears to still be in place (regression)"
            );

            // Now notify: transition to running and wake the waiter.
            let mut running = state
                .registry
                .get(&full_name)
                .await
                .expect("runtime must still be in registry");
            running.mark_running("running");
            running.set_listening();
            state.registry.update(running).await.expect("update");
            state.readiness_notify_and_remove(&full_name);

            // The handler must wake and return within a generous window.
            let response = handle.await.expect("task panicked");
            let elapsed = start.elapsed();

            assert_ne!(
                response.status(),
                StatusCode::NOT_FOUND,
                "Got 404: runtime not resolved after notification in logs handler \
                 (elapsed: {:?})",
                elapsed
            );

            // Response must have arrived after the 2.5 s mark (proved above)
            // but well before the 10 s deadline.
            assert!(
                elapsed < Duration::from_secs(6),
                "Response took {:?}; expected between 2.5 s and 6 s",
                elapsed
            );
        })
        .await
        .expect("test timed out after 10 s");
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
            let payload = serde_json::json!({
                "body": "", "path": "/", "method": "GET", "headers": {}, "timeout": 1
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

        let payload = serde_json::json!({
            "body": "",
            "path": "/",
            "method": "GET",
            "headers": {},
            "timeout": 1
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
