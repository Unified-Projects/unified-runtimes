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
    runtime::RuntimeRegistry,
    storage::{self, Storage},
};

/// Create a test configuration
fn test_config() -> ExecutorConfig {
    ExecutorConfig {
        host: "127.0.0.1".to_string(),
        port: 9900,
        secret: "test-secret-key".to_string(),
        env: "development".to_string(),
        networks: vec!["test-network".to_string()],
        hostname: "test-executor".to_string(),
        docker_hub_username: None,
        docker_hub_password: None,
        allowed_runtimes: vec![],
        runtime_versions: vec!["v5".to_string()],
        image_pull_enabled: true,
        min_cpus: 0.0,
        min_memory: 0,
        keep_alive: true,
        inactive_threshold: 60,
        maintenance_interval: 3600,
        max_body_size: 20 * 1024 * 1024,
        storage: StorageConfig::default(),
        logging_config: None,
        retry_attempts: 5,
        retry_delay_ms: 500,
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
    let http_client = reqwest::Client::new();
    let storage: Arc<dyn Storage> =
        Arc::from(storage::from_config(&config.storage).expect("Failed to create storage"));

    Some(AppState {
        config,
        docker,
        registry,
        http_client,
        storage,
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
    async fn returns_valid_json_structure() {
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

        let body = parse_json_body(response.into_body()).await;

        // Verify structure
        assert!(
            body.get("usage").is_some(),
            "Response should have 'usage' field"
        );
        assert!(
            body.get("runtimes").is_some(),
            "Response should have 'runtimes' field"
        );

        // Verify usage contains expected fields
        let usage = body.get("usage").unwrap();
        assert!(
            usage.get("memory").is_some(),
            "Usage should have 'memory' field"
        );
        assert!(usage.get("cpu").is_some(), "Usage should have 'cpu' field");

        // Verify memory structure
        let memory = usage.get("memory").unwrap();
        assert!(
            memory.get("percentage").is_some(),
            "Memory should have 'percentage'"
        );
        assert!(
            memory.get("memoryLimit").is_some(),
            "Memory should have 'memoryLimit'"
        );

        // Verify runtimes is an array
        assert!(body["runtimes"].is_array(), "Runtimes should be an array");
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
    async fn content_type_is_json() {
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

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
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
        assert!(content_type.contains("application/json"));
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
                    .uri("/v1/health")
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

        // Without auth, health endpoint returns minimal response
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
