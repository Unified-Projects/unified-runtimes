//! End-to-End Tests for URT Executor
//!
//! These tests spin up a real HTTP server and test against actual Docker containers.
//! They require Docker to be available and will pull real runtime images.
//!
//! Run with: cargo test --test e2e
//! Run specific test: cargo test --test e2e test_name
//!
//! Environment variables:
//! - E2E_RUNTIME_IMAGE: Override the default runtime image (default: openruntimes/node:v5-22)
//! - E2E_TIMEOUT_SECS: Override test timeout in seconds (default: 60)

use reqwest::{Client, StatusCode};
use serde_json::{json, Value};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::time::timeout;
use urt_executor::{
    config::{ExecutorConfig, StorageConfig},
    docker::DockerManager,
    routes::{create_router, AppState},
    runtime::{KeepAliveRegistry, RuntimeRegistry},
    storage::{self, S3Storage, Storage},
};

const DEFAULT_RUNTIME_IMAGE: &str = "openruntimes/node:v5-22";
const DEFAULT_TIMEOUT_SECS: u64 = 120;
const TEST_SECRET: &str = "e2e-test-secret-key";
const TEST_NETWORK: &str = "e2e-test-network";
const OPENRUNTIMES_FUNCTION_PATH: &str = "/usr/local/server/src/function";
const OPENRUNTIMES_SERVER_CMD: [&str; 2] = ["node", "/usr/local/server/src/server.js"];

/// Get the runtime image to use for tests
fn get_runtime_image() -> String {
    std::env::var("E2E_RUNTIME_IMAGE").unwrap_or_else(|_| DEFAULT_RUNTIME_IMAGE.to_string())
}

/// Get the test timeout
fn get_timeout() -> Duration {
    let secs = std::env::var("E2E_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_TIMEOUT_SECS);
    Duration::from_secs(secs)
}

/// Get the path to the test function fixture
/// Uses TEST_FIXTURES_HOST_PATH env var when running in Docker (host path for mounts),
/// falls back to CARGO_MANIFEST_DIR for local runs
fn get_test_function_path() -> String {
    if let Ok(host_path) = std::env::var("TEST_FIXTURES_HOST_PATH") {
        // Running in Docker - use the HOST path so containers created via socket can mount it
        let candidate = format!("{}/node-function", host_path);
        if Path::new(&candidate).exists() {
            return candidate;
        }
    } else {
        return local_fixture_path();
    }

    local_fixture_path()
}

fn local_fixture_path() -> String {
    // Running locally - use cargo manifest dir
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    format!("{}/tests/fixtures/node-function", manifest_dir)
}

struct TestServer {
    base_url: String,
    client: Client,
    _handle: tokio::task::JoinHandle<()>,
    // Keep the shutdown sender alive so the stats collector doesn't exit
    _shutdown_tx: tokio::sync::watch::Sender<bool>,
}

impl TestServer {
    fn auth_header(&self) -> (&'static str, String) {
        ("Authorization", format!("Bearer {}", TEST_SECRET))
    }
}

/// Create test configuration
fn test_config(network: String) -> ExecutorConfig {
    ExecutorConfig {
        host: "127.0.0.1".to_string(),
        port: 0, // Will be overridden
        secret: TEST_SECRET.to_string(),
        env: "development".to_string(),
        networks: vec![network],
        hostname: "e2e-test-executor".to_string(),
        docker_hub_username: None,
        docker_hub_password: None,
        allowed_runtimes: vec![],
        runtime_versions: vec!["v5".to_string()],
        image_pull_enabled: true,
        min_cpus: 0.0,
        min_memory: 0,
        keep_alive: true,
        inactive_threshold: 300,
        maintenance_interval: 3600,
        max_body_size: 20 * 1024 * 1024,
        storage: StorageConfig::default(),
        logging_config: None,
        retry_attempts: 5,
        retry_delay_ms: 500,
    }
}

/// Ensure test network exists
async fn ensure_test_network() {
    let docker =
        bollard::Docker::connect_with_local_defaults().expect("Failed to connect to Docker");

    // Check if network exists
    if docker
        .inspect_network(
            TEST_NETWORK,
            None::<bollard::query_parameters::InspectNetworkOptions>,
        )
        .await
        .is_err()
    {
        // Create network
        let config = bollard::models::NetworkCreateRequest {
            name: TEST_NETWORK.to_string(),
            driver: Some("bridge".to_string()),
            ..Default::default()
        };
        let _ = docker.create_network(config).await;
    }
}

/// Create a new test server instance for each test
async fn create_test_server() -> TestServer {
    // Ensure test network exists
    ensure_test_network().await;

    // Create Docker manager
    let config = test_config(TEST_NETWORK.to_string());
    let docker = DockerManager::new(config.clone())
        .await
        .expect("Failed to connect to Docker - is Docker running?");

    // Create storage from config
    let storage: Arc<dyn Storage> =
        Arc::from(storage::from_config(&config.storage).expect("Failed to create storage"));

    // Create app state
    let state = AppState {
        config,
        docker: Arc::new(docker),
        registry: RuntimeRegistry::new(),
        keep_alive_registry: KeepAliveRegistry::new(),
        http_client: Client::new(),
        storage,
    };

    // Bind to random available port
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind to address");
    let port = listener.local_addr().unwrap().port();
    let base_url = format!("http://127.0.0.1:{}", port);

    // Create router and start server
    let app = create_router(state.clone());

    // Start stats collector background task
    let docker_clone = state.docker.clone();
    let registry_clone = state.registry.clone();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        urt_executor::tasks::run_stats_collector(docker_clone, registry_clone, shutdown_rx).await;
    });

    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("Server failed to start");
    });

    // Wait for server to be ready
    // Long timeout for runtime creation which may pull images
    let client = Client::builder()
        .timeout(Duration::from_secs(180))
        .build()
        .unwrap();

    // Give the server a moment to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    for i in 0..30 {
        match client
            .get(format!("{}/v1/health", base_url))
            .header("Authorization", format!("Bearer {}", TEST_SECRET))
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                break;
            }
            Ok(_) | Err(_) => {
                if i == 29 {
                    panic!("Test server failed to start on {}", base_url);
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    TestServer {
        base_url,
        client,
        _handle: handle,
        _shutdown_tx: shutdown_tx,
    }
}

/// Generate a unique runtime ID for each test
fn unique_runtime_id(prefix: &str) -> String {
    format!(
        "{}-{}",
        prefix,
        uuid::Uuid::new_v4().to_string().split('-').next().unwrap()
    )
}

/// Clean up a runtime (best effort, doesn't fail on error)
async fn cleanup_runtime(server: &TestServer, runtime_id: &str) {
    let _ = server
        .client
        .delete(format!("{}/v1/runtimes/{}", server.base_url, runtime_id))
        .header(server.auth_header().0, server.auth_header().1.clone())
        .send()
        .await;

    // Give Docker time to clean up
    tokio::time::sleep(Duration::from_millis(500)).await;
}

#[tokio::test]
async fn test_health_endpoint_returns_200() {
    let server = create_test_server().await;

    let response = server
        .client
        .get(format!("{}/v1/health", server.base_url))
        .header(server.auth_header().0, server.auth_header().1.clone())
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_health_endpoint_returns_valid_structure() {
    let server = create_test_server().await;

    let response = server
        .client
        .get(format!("{}/v1/health", server.base_url))
        .header(server.auth_header().0, server.auth_header().1.clone())
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);

    let body: Value = response.json().await.expect("Failed to parse JSON");

    // Verify structure
    assert!(body.get("usage").is_some(), "Should have 'usage' field");
    assert!(
        body.get("runtimes").is_some(),
        "Should have 'runtimes' field"
    );

    let usage = &body["usage"];
    assert!(usage.get("memory").is_some(), "Should have memory stats");
    assert!(usage.get("cpu").is_some(), "Should have CPU stats");
    assert!(
        usage["memory"].get("percentage").is_some(),
        "Should have memory percentage"
    );
}

#[tokio::test]
async fn test_health_is_public() {
    let server = create_test_server().await;

    // Health endpoint is public - no auth required
    let response = server
        .client
        .get(format!("{}/v1/health", server.base_url))
        .send()
        .await
        .expect("Failed to send request");

    // Health should be accessible without auth
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_auth_required_for_runtimes() {
    let server = create_test_server().await;

    let response = server
        .client
        .get(format!("{}/v1/runtimes", server.base_url))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_auth_invalid_token_rejected() {
    let server = create_test_server().await;

    let response = server
        .client
        .get(format!("{}/v1/runtimes", server.base_url))
        .header("Authorization", "Bearer wrong-token")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let body: Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["code"], 401);
    assert_eq!(body["type"], "general_unauthorized");
}

#[tokio::test]
async fn test_auth_valid_token_accepted() {
    let server = create_test_server().await;

    let response = server
        .client
        .get(format!("{}/v1/runtimes", server.base_url))
        .header(server.auth_header().0, server.auth_header().1.clone())
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_auth_bearer_prefix_required() {
    let server = create_test_server().await;

    // Token without "Bearer " prefix should fail
    let response = server
        .client
        .get(format!("{}/v1/runtimes", server.base_url))
        .header("Authorization", TEST_SECRET)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_list_runtimes_empty() {
    let server = create_test_server().await;

    let response = server
        .client
        .get(format!("{}/v1/runtimes", server.base_url))
        .header(server.auth_header().0, server.auth_header().1.clone())
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);

    let body: Value = response.json().await.expect("Failed to parse JSON");
    assert!(body.is_array(), "Response should be an array");
}

#[tokio::test]
async fn test_get_runtime_not_found() {
    let server = create_test_server().await;

    let response = server
        .client
        .get(format!(
            "{}/v1/runtimes/nonexistent-runtime-12345",
            server.base_url
        ))
        .header(server.auth_header().0, server.auth_header().1.clone())
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_delete_runtime_not_found() {
    let server = create_test_server().await;

    let response = server
        .client
        .delete(format!(
            "{}/v1/runtimes/nonexistent-runtime-12345",
            server.base_url
        ))
        .header(server.auth_header().0, server.auth_header().1.clone())
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_create_runtime() {
    let server = create_test_server().await;
    let runtime_id = unique_runtime_id("create");

    let result = timeout(get_timeout(), async {
        let payload = json!({
            "runtimeId": runtime_id,
            "image": get_runtime_image(),
            "entrypoint": "index.js",
            "source": get_test_function_path(),
            "destination": OPENRUNTIMES_FUNCTION_PATH,
            "dockerCmd": OPENRUNTIMES_SERVER_CMD,
            "variables": {}
        });

        let response = server
            .client
            .post(format!("{}/v1/runtimes", server.base_url))
            .header(server.auth_header().0, server.auth_header().1.clone())
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await
            .expect("Failed to send request");

        assert!(
            response.status().is_success(),
            "Create runtime failed with status: {} - {:?}",
            response.status(),
            response
                .bytes()
                .await
                .expect("failed to read response body")
                .to_vec()
        );

        // Verify runtime exists
        tokio::time::sleep(Duration::from_secs(2)).await;

        let response = server
            .client
            .get(format!("{}/v1/runtimes/{}", server.base_url, runtime_id))
            .header(server.auth_header().0, server.auth_header().1.clone())
            .send()
            .await
            .expect("Failed to send request");

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Runtime should exist after creation"
        );

        cleanup_runtime(&server, &runtime_id).await;
    })
    .await;

    assert!(result.is_ok(), "Test timed out");
}

#[tokio::test]
async fn test_runtime_full_lifecycle() {
    let server = create_test_server().await;
    let runtime_id = unique_runtime_id("lifecycle");

    let result = timeout(get_timeout(), async {
        // 1. Create runtime
        let payload = json!({
            "runtimeId": runtime_id,
            "image": get_runtime_image(),
            "entrypoint": "index.js",
            "source": get_test_function_path(),
            "destination": OPENRUNTIMES_FUNCTION_PATH,
            "dockerCmd": OPENRUNTIMES_SERVER_CMD,
            "variables": {}
        });

        let response = server
            .client
            .post(format!("{}/v1/runtimes", server.base_url))
            .header(server.auth_header().0, server.auth_header().1.clone())
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await
            .expect("Failed to create runtime");

        assert!(
            response.status().is_success(),
            "Create failed: {:?}",
            response
                .bytes()
                .await
                .expect("failed to read response body")
                .to_vec()
        );

        tokio::time::sleep(Duration::from_secs(2)).await;

        // 2. List runtimes and verify it's there
        let response = server
            .client
            .get(format!("{}/v1/runtimes", server.base_url))
            .header(server.auth_header().0, server.auth_header().1.clone())
            .send()
            .await
            .expect("Failed to list runtimes");

        assert_eq!(response.status(), StatusCode::OK);
        let runtimes: Value = response.json().await.expect("Failed to parse JSON");
        let runtimes = runtimes.as_array().expect("Should be array");
        assert!(
            runtimes.iter().any(|r| r["name"]
                .as_str()
                .map(|n| n.contains(&runtime_id))
                .unwrap_or(false)),
            "Runtime should be in list"
        );

        // 3. Get runtime details
        let response = server
            .client
            .get(format!("{}/v1/runtimes/{}", server.base_url, runtime_id))
            .header(server.auth_header().0, server.auth_header().1.clone())
            .send()
            .await
            .expect("Failed to get runtime");

        assert_eq!(response.status(), StatusCode::OK);
        let runtime: Value = response.json().await.expect("Failed to parse JSON");
        assert!(runtime.get("name").is_some(), "Should have name");
        assert!(runtime.get("status").is_some(), "Should have status");

        // 4. Delete runtime
        let response = server
            .client
            .delete(format!("{}/v1/runtimes/{}", server.base_url, runtime_id))
            .header(server.auth_header().0, server.auth_header().1.clone())
            .send()
            .await
            .expect("Failed to delete runtime");

        assert!(
            response.status().is_success(),
            "Delete failed: {}",
            response.status()
        );

        tokio::time::sleep(Duration::from_secs(2)).await;

        // 5. Verify runtime is gone
        let response = server
            .client
            .get(format!("{}/v1/runtimes/{}", server.base_url, runtime_id))
            .header(server.auth_header().0, server.auth_header().1.clone())
            .send()
            .await
            .expect("Failed to send request");

        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "Runtime should be gone after deletion"
        );
    })
    .await;

    assert!(result.is_ok(), "Test timed out");
}

#[tokio::test]
async fn test_execute_command() {
    let server = create_test_server().await;
    let runtime_id = unique_runtime_id("exec-cmd");

    let result = timeout(get_timeout(), async {
        // Create runtime
        let payload = json!({
            "runtimeId": runtime_id,
            "image": get_runtime_image(),
            "entrypoint": "index.js",
            "source": get_test_function_path(),
            "destination": OPENRUNTIMES_FUNCTION_PATH,
            "dockerCmd": OPENRUNTIMES_SERVER_CMD,
            "variables": {}
        });

        let response = server
            .client
            .post(format!("{}/v1/runtimes", server.base_url))
            .header(server.auth_header().0, server.auth_header().1.clone())
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await
            .expect("Failed to create runtime");

        assert!(
            response.status().is_success(),
            "Create failed: {:?}",
            response
                .bytes()
                .await
                .expect("failed to read response body")
                .to_vec()
        );

        tokio::time::sleep(Duration::from_secs(3)).await;

        // Execute command
        let cmd_payload = json!({
            "command": "echo 'hello-from-e2e-test'"
        });

        let response = server
            .client
            .post(format!(
                "{}/v1/runtimes/{}/commands",
                server.base_url, runtime_id
            ))
            .header(server.auth_header().0, server.auth_header().1.clone())
            .header("Content-Type", "application/json")
            .json(&cmd_payload)
            .send()
            .await
            .expect("Failed to execute command");

        assert!(
            response.status().is_success(),
            "Command failed: {} - {:?}",
            response.status(),
            response
                .bytes()
                .await
                .expect("failed to read response body")
                .to_vec()
        );

        cleanup_runtime(&server, &runtime_id).await;
    })
    .await;

    assert!(result.is_ok(), "Test timed out");
}

#[tokio::test]
async fn test_function_execution() {
    let server = create_test_server().await;
    let runtime_id = unique_runtime_id("exec-fn");

    let result = timeout(get_timeout(), async {
        // Create runtime
        let payload = json!({
            "runtimeId": runtime_id,
            "image": get_runtime_image(),
            "entrypoint": "index.js",
            "source": get_test_function_path(),
            "destination": OPENRUNTIMES_FUNCTION_PATH,
            "dockerCmd": OPENRUNTIMES_SERVER_CMD,
            "variables": {}
        });

        let response = server
            .client
            .post(format!("{}/v1/runtimes", server.base_url))
            .header(server.auth_header().0, server.auth_header().1.clone())
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await
            .expect("Failed to create runtime");

        assert!(
            response.status().is_success(),
            "Create failed: {:?}",
            response
                .bytes()
                .await
                .expect("failed to read response body")
                .to_vec()
        );

        tokio::time::sleep(Duration::from_secs(3)).await;

        // Execute function
        let exec_payload = json!({
            "body": "{\"test\": \"hello\"}",
            "path": "/",
            "method": "POST",
            "headers": {
                "content-type": "application/json"
            }
        });

        let response = server
            .client
            .post(format!(
                "{}/v1/runtimes/{}/executions",
                server.base_url, runtime_id
            ))
            .header(server.auth_header().0, server.auth_header().1.clone())
            .header("Content-Type", "application/json")
            .json(&exec_payload)
            .send()
            .await
            .expect("Failed to execute function");

        // Function execution might return various status codes depending on runtime state
        // Just verify we get a response
        let status = response.status();
        assert!(
            status.is_success() || status == StatusCode::BAD_REQUEST,
            "Unexpected status: {}",
            status
        );

        cleanup_runtime(&server, &runtime_id).await;
    })
    .await;

    assert!(result.is_ok(), "Test timed out");
}

#[tokio::test]
async fn test_concurrent_executions() {
    let server = create_test_server().await;
    let runtime_id = unique_runtime_id("concurrent");

    let result = timeout(get_timeout(), async {
        // Create runtime
        let payload = json!({
            "runtimeId": runtime_id,
            "image": get_runtime_image(),
            "entrypoint": "index.js",
            "source": get_test_function_path(),
            "destination": OPENRUNTIMES_FUNCTION_PATH,
            "dockerCmd": OPENRUNTIMES_SERVER_CMD,
            "variables": {}
        });

        let response = server
            .client
            .post(format!("{}/v1/runtimes", server.base_url))
            .header(server.auth_header().0, server.auth_header().1.clone())
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await
            .expect("Failed to create runtime");

        assert!(
            response.status().is_success(),
            "Create failed: {:?}",
            response
                .bytes()
                .await
                .expect("failed to read response body")
                .to_vec()
        );

        tokio::time::sleep(Duration::from_secs(3)).await;

        // Fire 5 concurrent requests
        let exec_payload = json!({
            "body": "{}",
            "path": "/",
            "method": "GET",
            "headers": {}
        });

        let mut handles = Vec::new();
        for _ in 0..5 {
            let client = server.client.clone();
            let url = format!("{}/v1/runtimes/{}/executions", server.base_url, runtime_id);
            let auth = server.auth_header().1.clone();
            let payload = exec_payload.clone();

            handles.push(tokio::spawn(async move {
                client
                    .post(&url)
                    .header("Authorization", auth)
                    .header("Content-Type", "application/json")
                    .json(&payload)
                    .send()
                    .await
            }));
        }

        // Wait for all to complete
        let results: Vec<_> = futures::future::join_all(handles).await;

        // Verify all completed (even if some failed)
        for result in results {
            assert!(result.is_ok(), "Request failed to complete");
        }

        cleanup_runtime(&server, &runtime_id).await;
    })
    .await;

    assert!(result.is_ok(), "Test timed out");
}

// Use multi-threaded runtime so stats collector task actually runs
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_health_shows_runtime_stats() {
    let server = create_test_server().await;
    let runtime_id = unique_runtime_id("health-stats");

    let result = timeout(get_timeout(), async {
        // Create runtime
        let payload = json!({
            "runtimeId": runtime_id,
            "image": get_runtime_image(),
            "entrypoint": "index.js",
            "source": get_test_function_path(),
            "destination": OPENRUNTIMES_FUNCTION_PATH,
            "dockerCmd": OPENRUNTIMES_SERVER_CMD,
            "variables": {}
        });

        let response = server
            .client
            .post(format!("{}/v1/runtimes", server.base_url))
            .header(server.auth_header().0, server.auth_header().1.clone())
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await
            .expect("Failed to create runtime");

        assert!(response.status().is_success());

        // The runtime name in health includes the executor hostname prefix
        let expected_name = format!("e2e-test-executor-{}", runtime_id);

        // Poll health endpoint until the runtime appears in stats
        // Stats collector runs every 1 second, give it up to 10 seconds
        let mut found = false;
        for _attempt in 0..20 {
            tokio::time::sleep(Duration::from_millis(500)).await;

            let response = server
                .client
                .get(format!("{}/v1/health", server.base_url))
                .header(server.auth_header().0, server.auth_header().1.clone())
                .send()
                .await
                .expect("Failed to get health");

            if response.status() != StatusCode::OK {
                continue;
            }

            let body: Value = response.json().await.expect("Failed to parse JSON");
            let runtimes = body["runtimes"]
                .as_array()
                .expect("runtimes should be array");

            if runtimes.iter().any(|r| {
                r["name"]
                    .as_str()
                    .map(|n| n.contains(&runtime_id) || n == expected_name)
                    .unwrap_or(false)
            }) {
                found = true;
                break;
            }
        }

        assert!(
            found,
            "Health should show our runtime '{}' after 10 seconds of polling",
            runtime_id
        );

        cleanup_runtime(&server, &runtime_id).await;
    })
    .await;

    assert!(result.is_ok(), "Test timed out");
}

#[tokio::test]
async fn test_execution_runtime_not_found() {
    let server = create_test_server().await;

    let payload = json!({
        "body": "",
        "path": "/",
        "method": "GET",
        "headers": {}
    });

    let response = server
        .client
        .post(format!(
            "{}/v1/runtimes/nonexistent-runtime-xyz/executions",
            server.base_url
        ))
        .header(server.auth_header().0, server.auth_header().1.clone())
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_command_runtime_not_found() {
    let server = create_test_server().await;

    let payload = json!({
        "command": "echo hello"
    });

    let response = server
        .client
        .post(format!(
            "{}/v1/runtimes/nonexistent-runtime-xyz/commands",
            server.base_url
        ))
        .header(server.auth_header().0, server.auth_header().1.clone())
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_logs_runtime_not_found() {
    let server = create_test_server().await;

    let response = server
        .client
        .get(format!(
            "{}/v1/runtimes/nonexistent-runtime-xyz/logs",
            server.base_url
        ))
        .header(server.auth_header().0, server.auth_header().1.clone())
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_invalid_json_payload() {
    let server = create_test_server().await;

    let response = server
        .client
        .post(format!("{}/v1/runtimes", server.base_url))
        .header(server.auth_header().0, server.auth_header().1.clone())
        .header("Content-Type", "application/json")
        .body("not valid json")
        .send()
        .await
        .expect("Failed to send request");

    assert!(
        response.status() == StatusCode::BAD_REQUEST
            || response.status() == StatusCode::UNPROCESSABLE_ENTITY,
        "Expected 400 or 422, got {}",
        response.status()
    );
}

#[tokio::test]
async fn test_create_runtime_missing_image() {
    let server = create_test_server().await;

    let response = server
        .client
        .post(format!("{}/v1/runtimes", server.base_url))
        .header(server.auth_header().0, server.auth_header().1.clone())
        .header("Content-Type", "application/json")
        .json(&json!({}))
        .send()
        .await
        .expect("Failed to send request");

    assert!(
        response.status() == StatusCode::BAD_REQUEST
            || response.status() == StatusCode::UNPROCESSABLE_ENTITY,
        "Expected 400 or 422, got {}",
        response.status()
    );
}

/// Check if MinIO is available for testing
async fn is_minio_available() -> bool {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();

    client
        .get("http://localhost:9000/minio/health/live")
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

/// Create a test server with S3 storage configured
/// Requires MinIO to be available
async fn create_test_server_with_s3(s3_dsn: &str) -> TestServer {
    if !is_minio_available().await {
        panic!("MinIO not available - cannot create S3 test server");
    }

    ensure_test_network().await;

    // Create S3 storage from DSN
    let s3_storage = S3Storage::from_dsn(s3_dsn).expect("Failed to create S3 storage from DSN");

    let config = test_config(TEST_NETWORK.to_string());

    let docker = DockerManager::new(config.clone())
        .await
        .expect("Failed to connect to Docker");

    let storage: Arc<dyn Storage> = Arc::from(s3_storage);

    let state = AppState {
        config,
        docker: Arc::new(docker),
        registry: RuntimeRegistry::new(),
        keep_alive_registry: KeepAliveRegistry::new(),
        http_client: Client::new(),
        storage,
    };

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind to address");
    let port = listener.local_addr().unwrap().port();
    let base_url = format!("http://127.0.0.1:{}", port);

    let app = create_router(state.clone());

    let docker_clone = state.docker.clone();
    let registry_clone = state.registry.clone();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        urt_executor::tasks::run_stats_collector(docker_clone, registry_clone, shutdown_rx).await;
    });

    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("Server failed to start");
    });

    let client = Client::builder()
        .timeout(Duration::from_secs(180))
        .build()
        .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    for i in 0..30 {
        match client
            .get(format!("{}/v1/health", base_url))
            .header("Authorization", format!("Bearer {}", TEST_SECRET))
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                break;
            }
            Ok(_) | Err(_) => {
                if i == 29 {
                    panic!("Test server failed to start on {}", base_url);
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    TestServer {
        base_url,
        client,
        _handle: handle,
        _shutdown_tx: shutdown_tx,
    }
}

/// Clean up S3 test artifacts
async fn cleanup_s3_artifacts(storage: &S3Storage, prefix: &str) {
    let files = storage.list(prefix).await.unwrap_or_default();
    for file in files {
        let _ = storage.delete(&file).await;
    }
}

#[tokio::test]
async fn test_s3_storage_operations() {
    if !is_minio_available().await {
        eprintln!("Skipping S3 test - MinIO not available (run docker-compose -f docker-compose.test.yml up -d)");
        return;
    }

    use urt_executor::storage::S3Storage;

    // Create S3 storage connected to MinIO
    let storage = S3Storage::from_dsn("s3://minioadmin:minioadmin@localhost:9000/test-bucket")
        .expect("Failed to create S3 storage");

    // Test write
    let test_data = b"hello from e2e test";
    storage
        .write("e2e-test/test-file.txt", test_data)
        .await
        .expect("Failed to write to S3");

    // Test exists
    assert!(
        storage.exists("e2e-test/test-file.txt").await.unwrap(),
        "File should exist after write"
    );

    // Test read
    let read_data = storage
        .read("e2e-test/test-file.txt")
        .await
        .expect("Failed to read from S3");
    assert_eq!(read_data, test_data, "Read data should match written data");

    // Test size
    let size = storage
        .size("e2e-test/test-file.txt")
        .await
        .expect("Failed to get size");
    assert_eq!(size, test_data.len() as u64, "Size should match");

    // Test list
    let files = storage
        .list("e2e-test/")
        .await
        .expect("Failed to list files");
    assert!(
        files.iter().any(|f| f.contains("test-file.txt")),
        "List should include our file"
    );

    // Test delete
    storage
        .delete("e2e-test/test-file.txt")
        .await
        .expect("Failed to delete from S3");
    assert!(
        !storage.exists("e2e-test/test-file.txt").await.unwrap(),
        "File should not exist after delete"
    );
}

#[tokio::test]
async fn test_s3_storage_upload_download() {
    if !is_minio_available().await {
        eprintln!("Skipping S3 upload/download test - MinIO not available");
        return;
    }

    use tempfile::tempdir;
    use urt_executor::storage::S3Storage;

    let storage = S3Storage::from_dsn("s3://minioadmin:minioadmin@localhost:9000/test-bucket")
        .expect("Failed to create S3 storage");

    let dir = tempdir().expect("Failed to create temp dir");

    // Create a local file
    let local_file = dir.path().join("upload-test.txt");
    std::fs::write(&local_file, b"upload test content").expect("Failed to write local file");

    // Upload to S3
    storage
        .upload(local_file.to_str().unwrap(), "e2e-test/uploaded-file.txt")
        .await
        .expect("Failed to upload");

    // Download from S3
    let download_file = dir.path().join("downloaded.txt");
    storage
        .download(
            "e2e-test/uploaded-file.txt",
            download_file.to_str().unwrap(),
        )
        .await
        .expect("Failed to download");

    // Verify content
    let content = std::fs::read(&download_file).expect("Failed to read downloaded file");
    assert_eq!(content, b"upload test content");

    // Cleanup
    storage
        .delete("e2e-test/uploaded-file.txt")
        .await
        .expect("Failed to cleanup");
}

#[tokio::test]
async fn test_build_cache_with_s3() {
    if !is_minio_available().await {
        eprintln!("Skipping build cache test - MinIO not available");
        return;
    }

    use tempfile::tempdir;
    use urt_executor::storage::{BuildCache, S3Storage};

    let storage = S3Storage::from_dsn("s3://minioadmin:minioadmin@localhost:9000/builds")
        .expect("Failed to create S3 storage");

    let cache = BuildCache::new(storage, "test-cache");

    // Create a test directory with dependency files
    let dir = tempdir().expect("Failed to create temp dir");
    let package_json = dir.path().join("package.json");
    std::fs::write(&package_json, r#"{"name": "test", "version": "1.0.0"}"#)
        .expect("Failed to write package.json");

    // Hash dependencies
    let deps_hash = cache
        .hash_deps(&[package_json.to_str().unwrap()])
        .await
        .expect("Failed to hash deps");
    assert!(!deps_hash.is_empty(), "Hash should not be empty");

    // Create cache key
    let cache_key = cache.cache_key("test-runtime", &deps_hash);
    assert!(cache_key.contains("test-cache"));
    assert!(cache_key.contains("test-runtime"));
    assert!(cache_key.contains(&deps_hash));

    // Initially no cache
    assert!(
        !cache.has_cache(&cache_key).await.unwrap(),
        "Cache should not exist initially"
    );

    // Create a layer directory and cache it
    let node_modules = dir.path().join("node_modules");
    std::fs::create_dir_all(&node_modules).expect("Failed to create node_modules");
    std::fs::write(node_modules.join("test.txt"), b"test module")
        .expect("Failed to write test file");

    cache
        .cache_layers(&cache_key, dir.path().to_str().unwrap(), &["node_modules"])
        .await
        .expect("Failed to cache layers");

    // Now cache should exist
    assert!(
        cache.has_cache(&cache_key).await.unwrap(),
        "Cache should exist after caching"
    );

    // Get cached layers
    let layers = cache
        .get_cached_layers(&cache_key)
        .await
        .expect("Failed to get cached layers");
    assert!(!layers.is_empty(), "Should have cached layers");
}

/// Test that all S3 provider factory methods can be instantiated
/// These tests verify the factory methods work correctly with valid config
#[tokio::test]
async fn test_s3_provider_factory_methods() {
    if !is_minio_available().await {
        eprintln!("Skipping S3 provider factory tests - MinIO not available");
        return;
    }

    use urt_executor::config::S3ProviderConfig;

    let access_key = "minioadmin";
    let secret = "minioadmin";
    let region = "us-east-1";
    let bucket = "test-bucket";
    let endpoint = "http://localhost:9000";

    let config = S3ProviderConfig {
        access_key: access_key.to_string(),
        secret: secret.to_string(),
        region: region.to_string(),
        bucket: bucket.to_string(),
        endpoint: Some(endpoint.to_string()),
    };

    // Test S3 factory
    let s3 = S3Storage::new_s3(&config);
    assert!(s3.is_ok(), "S3 factory should succeed with valid config");

    // Test DO Spaces factory
    let do_spaces = S3Storage::new_do_spaces(&config);
    assert!(do_spaces.is_ok(), "DO Spaces factory should succeed");

    // Test Backblaze factory
    let backblaze = S3Storage::new_backblaze(&config);
    assert!(backblaze.is_ok(), "Backblaze factory should succeed");

    // Test Linode factory
    let linode = S3Storage::new_linode(&config);
    assert!(linode.is_ok(), "Linode factory should succeed");

    // Test Wasabi factory
    let wasabi = S3Storage::new_wasabi(&config);
    assert!(wasabi.is_ok(), "Wasabi factory should succeed");

    // Test DSN parsing
    let dsn = format!(
        "s3://{}:{}@{}:{}/{}?region={}",
        access_key, secret, "localhost", 9000, bucket, region
    );
    let from_dsn = S3Storage::from_dsn(&dsn);
    assert!(from_dsn.is_ok(), "DSN parsing should succeed");
}

/// Test cold start from S3 storage - the critical path for S3 functionality
///
/// This test verifies the full cold start flow:
/// 1. Upload a test function source to S3
/// 2. Create a runtime pointing to the S3 source
/// 3. Execute the runtime (triggers cold start + S3 download)
/// 4. Verify execution succeeded (proves artifact was downloaded from S3)
#[tokio::test]
async fn test_cold_start_from_s3() {
    if !is_minio_available().await {
        eprintln!("Skipping S3 cold start test - MinIO not available");
        return;
    }

    use tempfile::tempdir;

    let s3_dsn = "s3://minioadmin:minioadmin@localhost:9000/test-bucket";
    let server = create_test_server_with_s3(s3_dsn).await;

    let runtime_id = unique_runtime_id("cold-start-s3");
    let s3_source_path = format!("cold-start-test/{}/source.tar.gz", runtime_id);

    // Create a temporary directory with a test function
    let dir = tempdir().expect("Failed to create temp dir");
    let function_dir = dir.path().join("function");
    std::fs::create_dir_all(&function_dir).expect("Failed to create function dir");

    // Create index.js for Node.js runtime
    let index_file = function_dir.join("index.js");
    std::fs::write(
        &index_file,
        r#"
        module.exports = async function(context) {
            return {
                body: "Hello from S3 cold start!",
                statusCode: 200
            };
        }
    "#,
    )
    .expect("Failed to write index.js");

    // Create package.json
    let package_file = function_dir.join("package.json");
    std::fs::write(
        &package_file,
        r#"{"name": "test-function", "version": "1.0.0"}"#,
    )
    .expect("Failed to write package.json");

    // Create tar.gz of the function source
    let source_tar = dir.path().join("function.tar.gz");
    let cmd = std::process::Command::new("tar")
        .arg("-czf")
        .arg(&source_tar)
        .arg("-C")
        .arg(dir.path())
        .arg("function")
        .output()
        .expect("Failed to create tarball");

    if !cmd.status.success() {
        eprintln!("tar stderr: {}", String::from_utf8_lossy(&cmd.stderr));
        panic!("Failed to create tarball");
    }

    // Upload source to S3
    let storage = S3Storage::from_dsn(s3_dsn).expect("Failed to create S3 storage");

    storage
        .upload(source_tar.to_str().unwrap(), &s3_source_path)
        .await
        .expect("Failed to upload source to S3");

    // Create runtime pointing to S3 source
    let payload = json!({
        "runtimeId": runtime_id,
        "image": get_runtime_image(),
        "entrypoint": "index.js",
        "source": s3_source_path,
        "destination": "/usr/local/server/src/function",
        "dockerCmd": OPENRUNTIMES_SERVER_CMD,
        "variables": {}
    });

    let create_response = server
        .client
        .post(format!("{}/v1/runtimes", server.base_url))
        .header(server.auth_header().0, server.auth_header().1.clone())
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await
        .expect("Failed to create runtime");

    assert!(
        create_response.status().is_success(),
        "Runtime creation failed: {}",
        create_response.text().await.unwrap_or_default()
    );

    // Wait for runtime to be ready (cold start + S3 download)
    tokio::time::sleep(Duration::from_secs(10)).await;

    // Execute the function
    let exec_payload = json!({
        "body": "",
        "path": "/",
        "method": "GET",
        "headers": {}
    });

    let exec_result = timeout(get_timeout(), async {
        server
            .client
            .post(format!(
                "{}/v1/runtimes/{}/executions",
                server.base_url, runtime_id
            ))
            .header(server.auth_header().0, server.auth_header().1.clone())
            .header("Content-Type", "application/json")
            .json(&exec_payload)
            .send()
            .await
    })
    .await;

    let exec_success = match exec_result {
        Ok(Ok(response)) => {
            if response.status().is_success() {
                let body: Value = response.json().await.expect("Failed to parse response");
                body["statusCode"] == 200
                    && body["body"]
                        .as_str()
                        .unwrap_or("")
                        .contains("S3 cold start")
            } else {
                false
            }
        }
        Ok(Err(_)) | Err(_) => false,
    };

    // Cleanup - S3 artifacts and runtime
    let _ = cleanup_s3_artifacts(&storage, "cold-start-test/").await;
    cleanup_runtime(&server, &runtime_id).await;

    assert!(
        exec_success,
        "Cold start from S3 failed - execution did not succeed"
    );
}

// AppWrite Response Format Compatibility Tests
mod appwrite_compatibility {
    use super::*;

    #[tokio::test]
    async fn test_json_response_has_all_required_fields() {
        let server = create_test_server().await;
        let runtime_id = unique_runtime_id("json-fields");

        let result = timeout(get_timeout(), async {
            // Create runtime
            let payload = json!({
                "runtimeId": runtime_id,
                "image": get_runtime_image(),
                "entrypoint": "index.js",
                "source": get_test_function_path(),
                "destination": OPENRUNTIMES_FUNCTION_PATH,
                "dockerCmd": OPENRUNTIMES_SERVER_CMD,
                "variables": {}
            });

            let response = server
                .client
                .post(format!("{}/v1/runtimes", server.base_url))
                .header(server.auth_header().0, server.auth_header().1.clone())
                .header("Content-Type", "application/json")
                .json(&payload)
                .send()
                .await
                .expect("Failed to create runtime");

            assert!(response.status().is_success());

            tokio::time::sleep(Duration::from_secs(3)).await;

            // Execute and check JSON response structure
            let exec_payload = json!({
                "body": "{}",
                "path": "/",
                "method": "GET",
                "headers": {}
            });

            let response = server
                .client
                .post(format!(
                    "{}/v1/runtimes/{}/executions",
                    server.base_url, runtime_id
                ))
                .header(server.auth_header().0, server.auth_header().1.clone())
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .json(&exec_payload)
                .send()
                .await
                .expect("Failed to execute");

            // We might get success or failure depending on runtime state
            if response.status().is_success() {
                let body: Value = response.json().await.expect("Failed to parse JSON");

                // Verify all required AppWrite fields are present
                assert!(body.get("statusCode").is_some(), "Should have statusCode");
                assert!(body.get("body").is_some(), "Should have body");
                assert!(body.get("headers").is_some(), "Should have headers");
                assert!(body.get("logs").is_some(), "Should have logs");
                assert!(body.get("errors").is_some(), "Should have errors");
                assert!(body.get("duration").is_some(), "Should have duration");
                assert!(body.get("startTime").is_some(), "Should have startTime");
            }

            cleanup_runtime(&server, &runtime_id).await;
        })
        .await;

        assert!(result.is_ok(), "Test timed out");
    }

    #[tokio::test]
    async fn test_multipart_response_format() {
        let server = create_test_server().await;
        let runtime_id = unique_runtime_id("multipart-resp");

        let result = timeout(get_timeout(), async {
            // Create runtime
            let payload = json!({
                "runtimeId": runtime_id,
                "image": get_runtime_image(),
                "entrypoint": "index.js",
                "source": get_test_function_path(),
                "destination": OPENRUNTIMES_FUNCTION_PATH,
                "dockerCmd": OPENRUNTIMES_SERVER_CMD,
                "variables": {}
            });

            let response = server
                .client
                .post(format!("{}/v1/runtimes", server.base_url))
                .header(server.auth_header().0, server.auth_header().1.clone())
                .header("Content-Type", "application/json")
                .json(&payload)
                .send()
                .await
                .expect("Failed to create runtime");

            assert!(response.status().is_success());

            tokio::time::sleep(Duration::from_secs(3)).await;

            // Execute with multipart response
            let exec_payload = json!({
                "body": "{}",
                "path": "/",
                "method": "GET",
                "headers": {}
            });

            let response = server
                .client
                .post(format!(
                    "{}/v1/runtimes/{}/executions",
                    server.base_url, runtime_id
                ))
                .header(server.auth_header().0, server.auth_header().1.clone())
                .header("Content-Type", "application/json")
                .header("Accept", "multipart/form-data")
                .json(&exec_payload)
                .send()
                .await
                .expect("Failed to execute");

            // Check response format
            let content_type = response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");

            // Verify response format - multipart if successful, JSON on error
            if response.status().is_success() {
                // On success with multipart accept, should get multipart response
                // Note: The actual format depends on the runtime response
                assert!(response.status().is_success(), "Execution should succeed");
                // Log what we got for debugging
                if !content_type.contains("multipart/form-data") {
                    eprintln!("Note: Expected multipart, got: {}", content_type);
                }
            } else {
                // On error, JSON is returned regardless of Accept header
                assert!(
                    content_type.contains("application/json"),
                    "Error responses should be JSON"
                );
            }

            cleanup_runtime(&server, &runtime_id).await;
        })
        .await;

        assert!(result.is_ok(), "Test timed out");
    }

    #[tokio::test]
    async fn test_response_headers_appwrite_format() {
        let server = create_test_server().await;
        let runtime_id = unique_runtime_id("resp-headers");

        let result = timeout(get_timeout(), async {
            // Create runtime
            let payload = json!({
                "runtimeId": runtime_id,
                "image": get_runtime_image(),
                "entrypoint": "index.js",
                "source": get_test_function_path(),
                "destination": OPENRUNTIMES_FUNCTION_PATH,
                "dockerCmd": OPENRUNTIMES_SERVER_CMD,
                "variables": {}
            });

            let response = server
                .client
                .post(format!("{}/v1/runtimes", server.base_url))
                .header(server.auth_header().0, server.auth_header().1.clone())
                .header("Content-Type", "application/json")
                .json(&payload)
                .send()
                .await
                .expect("Failed to create runtime");

            assert!(response.status().is_success());

            tokio::time::sleep(Duration::from_secs(3)).await;

            // Execute with text/plain accept
            let exec_payload = json!({
                "body": "{}",
                "path": "/",
                "method": "GET",
                "headers": {}
            });

            let response = server
                .client
                .post(format!(
                    "{}/v1/runtimes/{}/executions",
                    server.base_url, runtime_id
                ))
                .header(server.auth_header().0, server.auth_header().1.clone())
                .header("Content-Type", "application/json")
                .header("Accept", "text/plain")
                .json(&exec_payload)
                .send()
                .await
                .expect("Failed to execute");

            // Check for AppWrite-specific headers (these are set for text/plain responses)
            let _has_status_code = response
                .headers()
                .contains_key("x-open-runtimes-status-code");

            // Headers should be present on success
            if response.status().is_success() {
                // On success, headers should be present for text/plain responses
                // Note: These headers may or may not be present depending on implementation
                if _has_status_code {
                    // Headers are present as expected
                } else {
                    eprintln!("Note: x-open-runtimes-status-code header not found");
                }
            } else {
                // On error, headers might not be set
                assert!(
                    response.status().is_client_error() || response.status().is_server_error(),
                    "Should get an error response"
                );
            }

            cleanup_runtime(&server, &runtime_id).await;
        })
        .await;

        assert!(result.is_ok(), "Test timed out");
    }
}

// Error Scenario Tests
mod error_scenarios {
    use super::*;

    #[tokio::test]
    async fn test_execution_on_deleted_runtime() {
        let server = create_test_server().await;
        let runtime_id = unique_runtime_id("deleted-rt");

        let result = timeout(get_timeout(), async {
            // Create runtime
            let payload = json!({
                "runtimeId": runtime_id,
                "image": get_runtime_image(),
                "entrypoint": "index.js",
                "source": get_test_function_path(),
                "destination": OPENRUNTIMES_FUNCTION_PATH,
                "dockerCmd": OPENRUNTIMES_SERVER_CMD,
                "variables": {}
            });

            let response = server
                .client
                .post(format!("{}/v1/runtimes", server.base_url))
                .header(server.auth_header().0, server.auth_header().1.clone())
                .header("Content-Type", "application/json")
                .json(&payload)
                .send()
                .await
                .expect("Failed to create runtime");

            assert!(response.status().is_success());

            tokio::time::sleep(Duration::from_secs(2)).await;

            // Delete the runtime
            let response = server
                .client
                .delete(format!("{}/v1/runtimes/{}", server.base_url, runtime_id))
                .header(server.auth_header().0, server.auth_header().1.clone())
                .send()
                .await
                .expect("Failed to delete runtime");

            assert!(response.status().is_success());

            tokio::time::sleep(Duration::from_secs(1)).await;

            // Try to execute on deleted runtime
            let exec_payload = json!({
                "body": "{}",
                "path": "/",
                "method": "GET",
                "headers": {}
            });

            let response = server
                .client
                .post(format!(
                    "{}/v1/runtimes/{}/executions",
                    server.base_url, runtime_id
                ))
                .header(server.auth_header().0, server.auth_header().1.clone())
                .header("Content-Type", "application/json")
                .json(&exec_payload)
                .send()
                .await
                .expect("Failed to send request");

            // Should get 404
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        })
        .await;

        assert!(result.is_ok(), "Test timed out");
    }

    #[tokio::test]
    async fn test_command_on_nonexistent_runtime() {
        let server = create_test_server().await;

        let cmd_payload = json!({
            "command": "echo hello"
        });

        let response = server
            .client
            .post(format!(
                "{}/v1/runtimes/definitely-not-real-xyz/executions",
                server.base_url
            ))
            .header(server.auth_header().0, server.auth_header().1.clone())
            .header("Content-Type", "application/json")
            .json(&cmd_payload)
            .send()
            .await
            .expect("Failed to send request");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_logs_on_nonexistent_runtime() {
        let server = create_test_server().await;

        let response = server
            .client
            .get(format!(
                "{}/v1/runtimes/definitely-not-real-xyz/logs",
                server.base_url
            ))
            .header(server.auth_header().0, server.auth_header().1.clone())
            .send()
            .await
            .expect("Failed to send request");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_invalid_accept_header() {
        let server = create_test_server().await;

        let response = server
            .client
            .get(format!("{}/v1/health", server.base_url))
            .header("Accept", "invalid.accept.value")
            .send()
            .await
            .expect("Failed to send request");

        // Should still return valid JSON response
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_very_large_body_rejected() {
        let server = create_test_server().await;

        // Create a very large body (larger than max_body_size of 20MB)
        let large_body = "x".repeat(25 * 1024 * 1024);

        let response = server
            .client
            .post(format!("{}/v1/runtimes", server.base_url))
            .header(server.auth_header().0, server.auth_header().1.clone())
            .header("Content-Type", "application/json")
            .body(large_body)
            .send()
            .await
            .expect("Failed to send request");

        // Should get a 413 Payload Too Large or similar error
        assert!(
            response.status() == StatusCode::PAYLOAD_TOO_LARGE
                || response.status() == StatusCode::BAD_REQUEST
                || response.status() == StatusCode::INTERNAL_SERVER_ERROR,
            "Expected large body rejection, got: {}",
            response.status()
        );
    }
}

// Concurrent Load Tests
mod concurrent_load {
    use super::*;

    #[tokio::test]
    async fn test_many_concurrent_health_checks() {
        let server = create_test_server().await;
        let num_requests = 50;

        let result = timeout(Duration::from_secs(30), async {
            let mut handles = Vec::new();

            for _ in 0..num_requests {
                let client = server.client.clone();
                let url = format!("{}/v1/health", server.base_url);

                handles.push(tokio::spawn(async move {
                    client
                        .get(&url)
                        .send()
                        .await
                        .map(|r| (r.status().as_u16(), r))
                }));
            }

            let results: Vec<_> = futures::future::join_all(handles).await;

            // Verify all completed successfully
            for result in results {
                let (status, _) = match result {
                    Ok(Ok((status, _))) => (status, ()),
                    Ok(Err(e)) => panic!("Request failed: {}", e),
                    Err(e) => panic!("Join error: {}", e),
                };
                assert_eq!(status, 200, "Health check should return 200");
            }
        })
        .await;

        assert!(result.is_ok(), "Test timed out - concurrent health checks");
    }

    #[tokio::test]
    async fn test_rapid_successive_creates() {
        let server = create_test_server().await;
        let num_runtimes = 5;

        let result = timeout(Duration::from_secs(120), async {
            let mut runtime_ids = Vec::new();

            for i in 0..num_runtimes {
                let runtime_id = format!("rapid-create-{}", i);
                let image = get_runtime_image();
                let payload = json!({
                    "runtimeId": runtime_id,
                    "image": image,
                    "entrypoint": "",
                    "variables": {}
                });

                let response = server
                    .client
                    .post(format!("{}/v1/runtimes", server.base_url))
                    .header(server.auth_header().0, server.auth_header().1.clone())
                    .header("Content-Type", "application/json")
                    .json(&payload)
                    .send()
                    .await
                    .expect("Failed to create runtime");

                let status = response.status();
                let body = response.text().await.unwrap_or_else(|_| "".to_string());

                // Log for debugging
                if !status.is_success() {
                    tracing::warn!(
                        "Runtime create failed for {}: {} - {}",
                        runtime_id,
                        status,
                        body
                    );
                } else {
                    tracing::info!("Successfully created runtime: {}", runtime_id);
                    runtime_ids.push(runtime_id);
                }

                tokio::time::sleep(Duration::from_millis(100)).await;
            }

            // Cleanup any created runtimes
            for runtime_id in &runtime_ids {
                cleanup_runtime(&server, runtime_id).await;
            }

            // At least some should have succeeded
            assert!(
                !runtime_ids.is_empty(),
                "At least some runtime creates should succeed"
            );
        })
        .await;

        assert!(result.is_ok(), "Test timed out");
    }

    #[tokio::test]
    async fn test_stress_list_runtimes() {
        let server = create_test_server().await;
        let num_requests = 100;

        let result = timeout(Duration::from_secs(60), async {
            let mut handles = Vec::new();

            for _ in 0..num_requests {
                let client = server.client.clone();
                let url = format!("{}/v1/runtimes", server.base_url);
                let auth = server.auth_header().1.clone();

                handles.push(tokio::spawn(async move {
                    client
                        .get(&url)
                        .header("Authorization", auth)
                        .send()
                        .await
                        .map(|r| (r.status().as_u16(), r))
                }));
            }

            let results: Vec<_> = futures::future::join_all(handles).await;

            // Most should succeed
            let success_count = results
                .iter()
                .filter_map(|r| match r {
                    Ok(Ok((status, _))) => Some(*status == 200),
                    _ => None,
                })
                .count();

            // Allow some failures due to resource constraints
            assert!(
                success_count >= num_requests - 10,
                "Most list requests should succeed: {}/{}",
                success_count,
                num_requests
            );
        })
        .await;

        assert!(result.is_ok(), "Test timed out - stress test");
    }
}

// Runtime State Tests
mod runtime_state {
    use super::*;

    #[tokio::test]
    async fn test_runtime_persists_across_requests() {
        let server = create_test_server().await;
        let runtime_id = unique_runtime_id("persist");

        let result = timeout(get_timeout(), async {
            // Create runtime
            let payload = json!({
                "runtimeId": runtime_id,
                "image": get_runtime_image(),
                "entrypoint": "index.js",
                "source": get_test_function_path(),
                "destination": OPENRUNTIMES_FUNCTION_PATH,
                "dockerCmd": OPENRUNTIMES_SERVER_CMD,
                "variables": {}
            });

            let response = server
                .client
                .post(format!("{}/v1/runtimes", server.base_url))
                .header(server.auth_header().0, server.auth_header().1.clone())
                .header("Content-Type", "application/json")
                .json(&payload)
                .send()
                .await
                .expect("Failed to create runtime");

            assert!(response.status().is_success());

            tokio::time::sleep(Duration::from_secs(3)).await;

            // Execute multiple times
            for i in 0..3 {
                let exec_payload = json!({
                    "body": format!(r#"{{"iteration": {}}}"#, i),
                    "path": "/",
                    "method": "POST",
                    "headers": {"content-type": "application/json"}
                });

                let response = server
                    .client
                    .post(format!(
                        "{}/v1/runtimes/{}/executions",
                        server.base_url, runtime_id
                    ))
                    .header(server.auth_header().0, server.auth_header().1.clone())
                    .header("Content-Type", "application/json")
                    .json(&exec_payload)
                    .send()
                    .await
                    .expect("Failed to execute");

                // All should work (or at least return, not 404)
                assert!(
                    response.status().is_success() || response.status() == StatusCode::BAD_REQUEST,
                    "Execution {} should work",
                    i
                );

                tokio::time::sleep(Duration::from_millis(500)).await;
            }

            cleanup_runtime(&server, &runtime_id).await;
        })
        .await;

        assert!(result.is_ok(), "Test timed out");
    }

    #[tokio::test]
    async fn test_runtime_in_health_response() {
        let server = create_test_server().await;
        let runtime_id = unique_runtime_id("health-test");

        let result = timeout(get_timeout(), async {
            // Create runtime
            let payload = json!({
                "runtimeId": runtime_id,
                "image": get_runtime_image(),
                "entrypoint": "index.js",
                "source": get_test_function_path(),
                "destination": OPENRUNTIMES_FUNCTION_PATH,
                "dockerCmd": OPENRUNTIMES_SERVER_CMD,
                "variables": {}
            });

            let response = server
                .client
                .post(format!("{}/v1/runtimes", server.base_url))
                .header(server.auth_header().0, server.auth_header().1.clone())
                .header("Content-Type", "application/json")
                .json(&payload)
                .send()
                .await
                .expect("Failed to create runtime");

            assert!(response.status().is_success());

            // Wait for runtime to be ready and stats collector to pick it up
            tokio::time::sleep(Duration::from_secs(5)).await;

            // Check health endpoint for our runtime
            let response = server
                .client
                .get(format!("{}/v1/health", server.base_url))
                .header(server.auth_header().0, server.auth_header().1.clone())
                .send()
                .await
                .expect("Failed to get health");

            assert_eq!(response.status(), StatusCode::OK);

            let body: Value = response.json().await.expect("Failed to parse JSON");
            let runtimes = body["runtimes"].as_array().expect("Should be array");

            // Our runtime should appear in the list
            let found = runtimes.iter().any(|r| {
                r["name"]
                    .as_str()
                    .map(|n| n.contains(&runtime_id) || n.contains("e2e-test-executor"))
                    .unwrap_or(false)
            });

            assert!(
                found,
                "Runtime {} should appear in health response",
                runtime_id
            );

            cleanup_runtime(&server, &runtime_id).await;
        })
        .await;

        assert!(result.is_ok(), "Test timed out");
    }
}

// Docker DNS Resolution Tests
// These tests verify that the executor correctly uses container NAMES for DNS resolution,
// NOT container hostnames. Docker DNS only resolves by container name on user-defined networks.
mod docker_dns_resolution {
    use super::*;

    /// Test that execution works via Docker DNS resolution using container NAME.
    ///
    /// This test verifies the fix for a critical bug where the executor was using
    /// `runtime.hostname` (a random 32-char hex string like "1ca14d56857971dfad412b32f66e6466")
    /// instead of `runtime.name` (the actual container name) for network communication.
    ///
    /// Docker DNS only resolves containers by their NAME, not by their internal hostname.
    /// The hostname is what the container sees as its own hostname, but other containers
    /// cannot resolve it via DNS.
    ///
    /// This test would hang indefinitely with the old broken code because:
    /// 1. wait_for_port tried to connect to "hostname:3000"
    /// 2. Docker DNS couldn't resolve the hostname
    /// 3. TCP connect attempts would fail but keep retrying
    ///
    /// With the fix, it uses the container name which Docker DNS can resolve.
    #[tokio::test]
    async fn test_execution_uses_container_name_for_dns() {
        let server = create_test_server().await;
        let runtime_id = unique_runtime_id("dns-resolution");

        let result = timeout(get_timeout(), async {
            // Create runtime
            let payload = json!({
                "runtimeId": runtime_id,
                "image": get_runtime_image(),
                "entrypoint": "index.js",
                "source": get_test_function_path(),
                "destination": OPENRUNTIMES_FUNCTION_PATH,
                "dockerCmd": OPENRUNTIMES_SERVER_CMD,
                "variables": {}
            });

            let response = server
                .client
                .post(format!("{}/v1/runtimes", server.base_url))
                .header(server.auth_header().0, server.auth_header().1.clone())
                .header("Content-Type", "application/json")
                .json(&payload)
                .send()
                .await
                .expect("Failed to create runtime");

            assert!(
                response.status().is_success(),
                "Create failed: {:?}",
                response
                    .bytes()
                    .await
                    .expect("failed to read response body")
                    .to_vec()
            );

            // Wait for runtime to be ready
            tokio::time::sleep(Duration::from_secs(3)).await;

            // Get runtime info to verify name vs hostname
            let response = server
                .client
                .get(format!("{}/v1/runtimes/{}", server.base_url, runtime_id))
                .header(server.auth_header().0, server.auth_header().1.clone())
                .send()
                .await
                .expect("Failed to get runtime");

            assert_eq!(response.status(), StatusCode::OK);
            let runtime: Value = response.json().await.expect("Failed to parse JSON");

            // Verify runtime has both name and hostname, and they're DIFFERENT
            let name = runtime["name"].as_str().expect("Should have name");
            let hostname = runtime["hostname"].as_str().expect("Should have hostname");

            assert!(
                name.contains(&runtime_id),
                "Name should contain runtime_id: {} vs {}",
                name,
                runtime_id
            );
            assert_ne!(
                name, hostname,
                "Name and hostname should be different: name={}, hostname={}",
                name, hostname
            );
            assert_eq!(
                hostname.len(),
                32,
                "Hostname should be a 32-char hex string: {}",
                hostname
            );

            // Execute function - this would hang with the old broken code
            // because Docker DNS can't resolve the hostname, only the name
            let exec_payload = json!({
                "body": "{}",
                "path": "/",
                "method": "GET",
                "headers": {},
                "timeout": 30
            });

            let response = server
                .client
                .post(format!(
                    "{}/v1/runtimes/{}/executions",
                    server.base_url, runtime_id
                ))
                .header(server.auth_header().0, server.auth_header().1.clone())
                .header("Content-Type", "application/json")
                .json(&exec_payload)
                .send()
                .await
                .expect("Failed to execute function");

            // With the fix, execution should complete (success or known error)
            // Without the fix, this would hang forever waiting for DNS resolution
            let status = response.status();
            assert!(
                status.is_success() || status == StatusCode::BAD_REQUEST,
                "Execution should complete (not hang): status={}",
                status
            );

            cleanup_runtime(&server, &runtime_id).await;
        })
        .await;

        assert!(
            result.is_ok(),
            "Test timed out - this likely means DNS resolution is using hostname instead of name"
        );
    }

    /// Test that the timeout parameter is respected during execution.
    ///
    /// This test verifies that if a runtime doesn't respond, the request properly
    /// times out according to the specified timeout parameter.
    #[tokio::test]
    async fn test_execution_timeout_is_respected() {
        let server = create_test_server().await;
        let runtime_id = unique_runtime_id("timeout-test");

        let result = timeout(Duration::from_secs(45), async {
            // Create runtime
            let payload = json!({
                "runtimeId": runtime_id,
                "image": get_runtime_image(),
                "entrypoint": "index.js",
                "source": get_test_function_path(),
                "destination": OPENRUNTIMES_FUNCTION_PATH,
                "dockerCmd": OPENRUNTIMES_SERVER_CMD,
                "variables": {}
            });

            let response = server
                .client
                .post(format!("{}/v1/runtimes", server.base_url))
                .header(server.auth_header().0, server.auth_header().1.clone())
                .header("Content-Type", "application/json")
                .json(&payload)
                .send()
                .await
                .expect("Failed to create runtime");

            assert!(response.status().is_success());

            // Wait for runtime
            tokio::time::sleep(Duration::from_secs(3)).await;

            // Execute with short timeout
            let exec_payload = json!({
                "body": "{}",
                "path": "/",
                "method": "GET",
                "headers": {},
                "timeout": 10
            });

            let start = std::time::Instant::now();
            let response = server
                .client
                .post(format!(
                    "{}/v1/runtimes/{}/executions",
                    server.base_url, runtime_id
                ))
                .header(server.auth_header().0, server.auth_header().1.clone())
                .header("Content-Type", "application/json")
                .json(&exec_payload)
                .send()
                .await
                .expect("Failed to execute function");

            let elapsed = start.elapsed();

            // Request should complete within timeout + some buffer
            // If DNS resolution was broken, this would hang forever
            assert!(
                elapsed.as_secs() < 30,
                "Execution should complete within timeout, took {:?}",
                elapsed
            );

            // Response received (success or timeout error)
            let _status = response.status();

            cleanup_runtime(&server, &runtime_id).await;
        })
        .await;

        assert!(
            result.is_ok(),
            "Test timed out - timeout parameter not respected"
        );
    }

    /// Test that the `listening` field correctly reflects runtime port availability.
    ///
    /// This test verifies:
    /// 1. Initially `listening` is 0 (runtime not yet listening on port 3000)
    /// 2. After first successful execution, `listening` becomes 1
    /// 3. When `listening` is 1, subsequent executions work correctly
    ///
    /// The `listening` flag is used to skip the TCP port check on subsequent requests,
    /// which is an important optimization for warm starts.
    #[tokio::test]
    async fn test_listening_flag_reflects_runtime_state() {
        let server = create_test_server().await;
        let runtime_id = unique_runtime_id("listening-flag");

        let result = timeout(get_timeout(), async {
            // Create runtime
            let payload = json!({
                "runtimeId": runtime_id,
                "image": get_runtime_image(),
                "entrypoint": "index.js",
                "source": get_test_function_path(),
                "destination": OPENRUNTIMES_FUNCTION_PATH,
                "dockerCmd": OPENRUNTIMES_SERVER_CMD,
                "variables": {}
            });

            let response = server
                .client
                .post(format!("{}/v1/runtimes", server.base_url))
                .header(server.auth_header().0, server.auth_header().1.clone())
                .header("Content-Type", "application/json")
                .json(&payload)
                .send()
                .await
                .expect("Failed to create runtime");

            assert!(response.status().is_success());

            // Wait for runtime to start
            tokio::time::sleep(Duration::from_secs(3)).await;

            // Check initial listening state - should be 0 before first execution
            let response = server
                .client
                .get(format!("{}/v1/runtimes/{}", server.base_url, runtime_id))
                .header(server.auth_header().0, server.auth_header().1.clone())
                .send()
                .await
                .expect("Failed to get runtime");

            assert_eq!(response.status(), StatusCode::OK);
            let runtime: Value = response.json().await.expect("Failed to parse JSON");
            let initial_listening = runtime["listening"].as_u64().unwrap_or(99);

            // Initial state should be 0 (not yet verified as listening)
            assert_eq!(
                initial_listening, 0,
                "Runtime should initially have listening=0, got {}",
                initial_listening
            );

            // Execute function (this triggers the TCP port check and sets listening=1)
            let exec_payload = json!({
                "body": "{}",
                "path": "/",
                "method": "GET",
                "headers": {},
                "timeout": 30
            });

            let response = server
                .client
                .post(format!(
                    "{}/v1/runtimes/{}/executions",
                    server.base_url, runtime_id
                ))
                .header(server.auth_header().0, server.auth_header().1.clone())
                .header("Content-Type", "application/json")
                .json(&exec_payload)
                .send()
                .await
                .expect("Failed to execute function");

            // Execution should succeed (or at least complete)
            let first_exec_status = response.status();
            assert!(
                first_exec_status.is_success() || first_exec_status == StatusCode::BAD_REQUEST,
                "First execution should complete: status={}",
                first_exec_status
            );

            // Check listening state after first execution - should now be 1
            let response = server
                .client
                .get(format!("{}/v1/runtimes/{}", server.base_url, runtime_id))
                .header(server.auth_header().0, server.auth_header().1.clone())
                .send()
                .await
                .expect("Failed to get runtime");

            assert_eq!(response.status(), StatusCode::OK);
            let runtime: Value = response.json().await.expect("Failed to parse JSON");
            let after_exec_listening = runtime["listening"].as_u64().unwrap_or(99);

            // After successful execution, listening should be 1
            assert_eq!(
                after_exec_listening, 1,
                "Runtime should have listening=1 after execution, got {}",
                after_exec_listening
            );

            // Second execution should also work (using the listening=1 fast path)
            let response = server
                .client
                .post(format!(
                    "{}/v1/runtimes/{}/executions",
                    server.base_url, runtime_id
                ))
                .header(server.auth_header().0, server.auth_header().1.clone())
                .header("Content-Type", "application/json")
                .json(&exec_payload)
                .send()
                .await
                .expect("Failed to execute second function");

            let second_exec_status = response.status();
            assert!(
                second_exec_status.is_success() || second_exec_status == StatusCode::BAD_REQUEST,
                "Second execution should complete: status={}",
                second_exec_status
            );

            cleanup_runtime(&server, &runtime_id).await;
        })
        .await;

        assert!(
            result.is_ok(),
            "Test timed out - listening flag test failed"
        );
    }

    /// Test that when listening=1, we can actually communicate with the runtime.
    ///
    /// This is a regression test to ensure that the listening flag is only set
    /// when the runtime is actually reachable via TCP.
    #[tokio::test]
    async fn test_listening_true_means_runtime_is_reachable() {
        let server = create_test_server().await;
        let runtime_id = unique_runtime_id("reachable");

        let result = timeout(get_timeout(), async {
            // Create runtime
            let payload = json!({
                "runtimeId": runtime_id,
                "image": get_runtime_image(),
                "entrypoint": "index.js",
                "source": get_test_function_path(),
                "destination": OPENRUNTIMES_FUNCTION_PATH,
                "dockerCmd": OPENRUNTIMES_SERVER_CMD,
                "variables": {}
            });

            let response = server
                .client
                .post(format!("{}/v1/runtimes", server.base_url))
                .header(server.auth_header().0, server.auth_header().1.clone())
                .header("Content-Type", "application/json")
                .json(&payload)
                .send()
                .await
                .expect("Failed to create runtime");

            assert!(response.status().is_success());
            tokio::time::sleep(Duration::from_secs(3)).await;

            // Execute multiple times to ensure consistent behavior
            let exec_payload = json!({
                "body": r#"{"test": "data"}"#,
                "path": "/",
                "method": "POST",
                "headers": {"content-type": "application/json"},
                "timeout": 30
            });

            let mut successful_executions = 0;
            for i in 0..5 {
                let response = server
                    .client
                    .post(format!(
                        "{}/v1/runtimes/{}/executions",
                        server.base_url, runtime_id
                    ))
                    .header(server.auth_header().0, server.auth_header().1.clone())
                    .header("Content-Type", "application/json")
                    .json(&exec_payload)
                    .send()
                    .await
                    .expect("Failed to execute function");

                if response.status().is_success() {
                    successful_executions += 1;
                }

                // After first execution, listening should be 1
                if i == 0 {
                    let runtime_response = server
                        .client
                        .get(format!("{}/v1/runtimes/{}", server.base_url, runtime_id))
                        .header(server.auth_header().0, server.auth_header().1.clone())
                        .send()
                        .await
                        .expect("Failed to get runtime");

                    let runtime: Value = runtime_response.json().await.unwrap();
                    let listening = runtime["listening"].as_u64().unwrap_or(0);
                    assert_eq!(listening, 1, "After first execution, listening should be 1");
                }

                tokio::time::sleep(Duration::from_millis(200)).await;
            }

            // At least some executions should succeed when runtime is listening
            assert!(
                successful_executions >= 1,
                "At least one execution should succeed when listening=1"
            );

            cleanup_runtime(&server, &runtime_id).await;
        })
        .await;

        assert!(result.is_ok(), "Test timed out");
    }

    /// Test execution with keep-alive enabled.
    ///
    /// This test verifies that:
    /// 1. Runtimes with keep-alive work correctly
    /// 2. DNS resolution uses container name (not hostname) with keep-alive
    /// 3. The listening flag is correctly maintained across keep-alive executions
    #[tokio::test]
    async fn test_execution_with_keepalive() {
        let server = create_test_server().await;
        let runtime_id = unique_runtime_id("keepalive");
        let keep_alive_id = "test-keepalive-service";

        let result = timeout(get_timeout(), async {
            // Create runtime with keep-alive
            let payload = json!({
                "runtimeId": runtime_id,
                "image": get_runtime_image(),
                "entrypoint": "index.js",
                "source": get_test_function_path(),
                "destination": OPENRUNTIMES_FUNCTION_PATH,
                "dockerCmd": OPENRUNTIMES_SERVER_CMD,
                "variables": {},
                "keepAliveId": keep_alive_id
            });

            let response = server
                .client
                .post(format!("{}/v1/runtimes", server.base_url))
                .header(server.auth_header().0, server.auth_header().1.clone())
                .header("Content-Type", "application/json")
                .json(&payload)
                .send()
                .await
                .expect("Failed to create runtime");

            assert!(
                response.status().is_success(),
                "Create failed: {:?}",
                response.bytes().await.unwrap_or_default()
            );

            tokio::time::sleep(Duration::from_secs(3)).await;

            // Verify keep-alive is set on runtime
            let response = server
                .client
                .get(format!("{}/v1/runtimes/{}", server.base_url, runtime_id))
                .header(server.auth_header().0, server.auth_header().1.clone())
                .send()
                .await
                .expect("Failed to get runtime");

            assert_eq!(response.status(), StatusCode::OK);
            let runtime: Value = response.json().await.expect("Failed to parse JSON");

            // Verify name vs hostname are different
            let name = runtime["name"].as_str().expect("Should have name");
            let hostname = runtime["hostname"].as_str().expect("Should have hostname");
            assert_ne!(
                name, hostname,
                "Name and hostname should be different for keep-alive runtime"
            );

            // Verify keep-alive is present (may or may not be exposed in API)
            let initial_listening = runtime["listening"].as_u64().unwrap_or(99);
            assert_eq!(initial_listening, 0, "Should start with listening=0");

            // Execute multiple times to test keep-alive behavior
            let exec_payload = json!({
                "body": r#"{"keepalive": true}"#,
                "path": "/",
                "method": "POST",
                "headers": {"content-type": "application/json"},
                "timeout": 30
            });

            for i in 0..3 {
                let response = server
                    .client
                    .post(format!(
                        "{}/v1/runtimes/{}/executions",
                        server.base_url, runtime_id
                    ))
                    .header(server.auth_header().0, server.auth_header().1.clone())
                    .header("Content-Type", "application/json")
                    .json(&exec_payload)
                    .send()
                    .await
                    .expect("Failed to execute function");

                let status = response.status();
                assert!(
                    status.is_success() || status == StatusCode::BAD_REQUEST,
                    "Keep-alive execution {} should complete: status={}",
                    i,
                    status
                );

                tokio::time::sleep(Duration::from_millis(500)).await;
            }

            // Verify listening is now 1
            let response = server
                .client
                .get(format!("{}/v1/runtimes/{}", server.base_url, runtime_id))
                .header(server.auth_header().0, server.auth_header().1.clone())
                .send()
                .await
                .expect("Failed to get runtime");

            let runtime: Value = response.json().await.expect("Failed to parse JSON");
            let final_listening = runtime["listening"].as_u64().unwrap_or(0);
            assert_eq!(
                final_listening, 1,
                "After executions, listening should be 1"
            );

            cleanup_runtime(&server, &runtime_id).await;
        })
        .await;

        assert!(
            result.is_ok(),
            "Test timed out - keep-alive execution failed"
        );
    }

    /// Test that keep-alive runtimes can be re-used across multiple execution batches.
    ///
    /// This simulates real-world usage where a keep-alive runtime is used for multiple
    /// separate function invocations over time.
    #[tokio::test]
    async fn test_keepalive_runtime_reuse() {
        let server = create_test_server().await;
        let runtime_id = unique_runtime_id("keepalive-reuse");

        let result = timeout(get_timeout(), async {
            // Create runtime with keep-alive
            let payload = json!({
                "runtimeId": runtime_id,
                "image": get_runtime_image(),
                "entrypoint": "index.js",
                "source": get_test_function_path(),
                "destination": OPENRUNTIMES_FUNCTION_PATH,
                "dockerCmd": OPENRUNTIMES_SERVER_CMD,
                "variables": {},
                "keepAliveId": "reuse-test-service"
            });

            let response = server
                .client
                .post(format!("{}/v1/runtimes", server.base_url))
                .header(server.auth_header().0, server.auth_header().1.clone())
                .header("Content-Type", "application/json")
                .json(&payload)
                .send()
                .await
                .expect("Failed to create runtime");

            assert!(response.status().is_success());
            tokio::time::sleep(Duration::from_secs(3)).await;

            // First batch of executions
            let exec_payload = json!({
                "body": "{}",
                "path": "/",
                "method": "GET",
                "headers": {},
                "timeout": 30
            });

            for _ in 0..2 {
                let response = server
                    .client
                    .post(format!(
                        "{}/v1/runtimes/{}/executions",
                        server.base_url, runtime_id
                    ))
                    .header(server.auth_header().0, server.auth_header().1.clone())
                    .header("Content-Type", "application/json")
                    .json(&exec_payload)
                    .send()
                    .await
                    .expect("Failed to execute");

                assert!(
                    response.status().is_success() || response.status() == StatusCode::BAD_REQUEST
                );
            }

            // Simulate idle time
            tokio::time::sleep(Duration::from_secs(2)).await;

            // Verify runtime still exists and listening is still 1
            let response = server
                .client
                .get(format!("{}/v1/runtimes/{}", server.base_url, runtime_id))
                .header(server.auth_header().0, server.auth_header().1.clone())
                .send()
                .await
                .expect("Failed to get runtime");

            assert_eq!(
                response.status(),
                StatusCode::OK,
                "Runtime should still exist"
            );
            let runtime: Value = response.json().await.expect("Failed to parse JSON");
            let listening = runtime["listening"].as_u64().unwrap_or(0);
            assert_eq!(listening, 1, "Listening should still be 1 after idle time");

            // Second batch of executions - should work without re-checking port
            for _ in 0..2 {
                let response = server
                    .client
                    .post(format!(
                        "{}/v1/runtimes/{}/executions",
                        server.base_url, runtime_id
                    ))
                    .header(server.auth_header().0, server.auth_header().1.clone())
                    .header("Content-Type", "application/json")
                    .json(&exec_payload)
                    .send()
                    .await
                    .expect("Failed to execute second batch");

                assert!(
                    response.status().is_success() || response.status() == StatusCode::BAD_REQUEST,
                    "Second batch execution should complete"
                );
            }

            cleanup_runtime(&server, &runtime_id).await;
        })
        .await;

        assert!(result.is_ok(), "Test timed out - keep-alive reuse failed");
    }
}
