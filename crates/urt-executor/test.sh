#!/usr/bin/env bash
#
# Test script for urt-executor (Rust AppWrite-compatible runtime executor)
# Compatible with macOS and Linux
#

set -euo pipefail

# Colors for output (disable if not a terminal)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    NC='\033[0m' # No Color
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

# Detect OS
detect_os() {
    case "$(uname -s)" in
        Darwin*) echo "macos" ;;
        Linux*) echo "linux" ;;
        *) echo "unknown" ;;
    esac
}

OS=$(detect_os)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
EXECUTOR_CRATE="$PROJECT_ROOT/crates/urt-executor"

# Docker compose file path
DOCKER_COMPOSE_FILE="$EXECUTOR_CRATE/docker-compose.test.yml"

# Test results tracking
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TESTS_FAILED++))
}

log_skip() {
    echo -e "${YELLOW}[SKIP]${NC} $1"
    ((TESTS_SKIPPED++))
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

header() {
    echo ""
    echo "========================================"
    echo " $1"
    echo "========================================"
}

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check Docker availability
check_docker() {
    log_info "Checking Docker..."

    if ! command_exists docker; then
        log_warn "Docker not found. E2E tests requiring Docker will be skipped."
        return 1
    fi

    if ! docker info >/dev/null 2>&1; then
        log_warn "Docker is not running. E2E tests requiring Docker will be skipped."
        return 1
    fi

    log_success "Docker is available"
    return 0
}

# Check Docker Compose availability
check_docker_compose() {
    if command_exists docker-compose; then
        COMPOSE_CMD="docker-compose"
        return 0
    elif docker compose version >/dev/null 2>&1; then
        COMPOSE_CMD="docker compose"
        return 0
    else
        log_warn "docker-compose not found. S3/MinIO tests will be skipped."
        return 1
    fi
}

# Start test services (MinIO for S3 tests)
start_test_services() {
    header "Starting Test Services"

    if [ ! -f "$DOCKER_COMPOSE_FILE" ]; then
        log_warn "Docker compose file not found at $DOCKER_COMPOSE_FILE"
        return 1
    fi

    if ! check_docker; then
        log_skip "Skipping test services (Docker not available)"
        return 1
    fi

    check_docker_compose || return 1

    log_info "Starting MinIO and other test services..."
    $COMPOSE_CMD -f "$DOCKER_COMPOSE_FILE" up -d

    # Wait for MinIO to be ready
    local max_attempts=30
    local attempt=0

    while [ $attempt -lt $max_attempts ]; do
        if curl -s "http://localhost:9000/minio/health/live" >/dev/null 2>&1; then
            log_success "MinIO is ready"
            return 0
        fi
        ((attempt++))
        log_info "Waiting for MinIO... ($attempt/$max_attempts)"
        sleep 1
    done

    log_warn "MinIO did not become ready in time"
    return 1
}

# Stop test services
stop_test_services() {
    if [ -f "$DOCKER_COMPOSE_FILE" ] && check_docker 2>/dev/null; then
        check_docker_compose 2>/dev/null || return 0
        log_info "Stopping test services..."
        $COMPOSE_CMD -f "$DOCKER_COMPOSE_FILE" down >/dev/null 2>&1 || true
    fi
}

# Run unit tests (no Docker required)
run_unit_tests() {
    header "Running Unit Tests"

    cd "$PROJECT_ROOT"

    if cargo test -p urt-executor --lib -- --test-threads=1 2>&1; then
        log_success "All unit tests passed"
    else
        log_fail "Some unit tests failed"
        return 1
    fi
}

# Run integration tests (requires Docker)
run_integration_tests() {
    header "Running Integration Tests"

    if ! check_docker; then
        log_skip "Skipping integration tests (Docker not available)"
        return 0
    fi

    cd "$PROJECT_ROOT"

    if cargo test -p urt-executor --test integration -- --test-threads=1 2>&1; then
        log_success "All integration tests passed"
    else
        log_fail "Some integration tests failed"
        return 1
    fi
}

# Run E2E tests (requires Docker + MinIO)
run_e2e_tests() {
    header "Running E2E Tests"

    if ! check_docker; then
        log_skip "Skipping E2E tests (Docker not available)"
        return 0
    fi

    cd "$PROJECT_ROOT"

    if cargo test -p urt-executor --test e2e -- --test-threads=1 2>&1; then
        log_success "All E2E tests passed"
    else
        log_fail "Some E2E tests failed"
        return 1
    fi
}

# Run all tests
run_all_tests() {
    header "All Tests"

    run_unit_tests || true
    run_integration_tests || true
    run_e2e_tests || true

    header "Test Summary"
    echo -e "Passed:  ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Failed:  ${RED}$TESTS_FAILED${NC}"
    echo -e "Skipped: ${YELLOW}$TESTS_SKIPPED${NC}"
    echo ""

    if [ $TESTS_FAILED -gt 0 ]; then
        echo -e "${RED}Some tests failed!${NC}"
        exit 1
    else
        echo -e "${GREEN}All tests passed!${NC}"
        exit 0
    fi
}

# Print usage
usage() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  unit          Run unit tests only (no Docker required)"
    echo "  integration   Run integration tests (requires Docker)"
    echo "  e2e           Run E2E tests (requires Docker + MinIO)"
    echo "  services      Start test services (MinIO) and keep running"
    echo "  up            Start test services in background"
    echo "  down          Stop test services"
    echo "  all           Run all tests (default)"
    echo "  help          Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  URT_SKIP_DOCKER   Skip tests requiring Docker (set to 'true')"
    echo "  URT_SKIP_E2E      Skip E2E tests (set to 'true')"
}

# Main entry point
main() {
    cd "$PROJECT_ROOT"

    echo ""
    echo "============================================"
    echo " urt-executor Test Runner"
    echo " OS: $OS"
    echo " Project: $PROJECT_ROOT"
    echo "============================================"
    echo ""

    # Check for cargo
    if ! command_exists cargo; then
        echo -e "${RED}Error: cargo not found. Please install Rust.${NC}"
        exit 1
    fi

    # Parse arguments
    case "${1:-all}" in
        unit)
            run_unit_tests
            ;;
        integration)
            run_integration_tests
            ;;
        e2e)
            run_e2e_tests
            ;;
        services|up)
            start_test_services
            ;;
        down)
            stop_test_services
            ;;
        all)
            # Set up trap to clean up services on exit
            trap 'stop_test_services' EXIT INT TERM
            run_all_tests
            ;;
        help|--help|-h)
            usage
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown command: $1${NC}"
            usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
