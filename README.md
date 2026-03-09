# Unified Runtimes (URT) Executor

A high-performance drop-in replacement for the [OpenRuntimes Executor](https://github.com/open-runtimes/executor), rebuilt from the ground up in Rust.

## Overview

URT Executor provides full API compatibility with the PHP OpenRuntimes Executor while delivering improved performance through compiled Rust, with graceful shutdown, background maintenance tasks, and container health monitoring.

### Key Features

- Full API compatibility with OpenRuntimes Executor
- Backwards-compatible configuration (supports both `URT_*` and `OPR_EXECUTOR_*` environment variables)
- Support for v2, v4, and v5 runtime protocols
- Configurable resource minimums (CPU/memory overrides)
- Configurable request body size limits
- S3/MinIO storage support for build artifacts
- Graceful shutdown with active execution draining
- Container stats collection and caching
- Optional Prometheus `/metrics` exporter for Grafana/Prometheus
- Automatic inactive container cleanup

## Project Structure

```
unified-runtimes/
├── crates/
│   ├── urt-core/       # Shared types and configuration
│   └── urt-executor/   # Main executor binary
└── docker/
    └── Dockerfile      # Production container image
```

## Quick Start

### Docker Compose (Recommended)

```bash
# Clone the repository
git clone https://github.com/Unified-Projects/unified-runtimes.git
cd unified-runtimes

# Copy environment template
cp .env.example .env

# Edit .env and set URT_SECRET to a secure value
vim .env

# Start the executor
docker compose up -d

# Check health
curl http://localhost:9900/v1/health
```

### Build from Source

```bash
# Build release binary
cargo build --release --package urt-executor

# Run
URT_SECRET=your-secret ./target/release/urt-executor
```

### Docker Build

```bash
docker build -f docker/Dockerfile -t urt-executor .
docker run -d \
  -p 9900:80 \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -e URT_SECRET=your-secret \
  urt-executor
```

## Configuration

All configuration is via environment variables. URT variables take priority over legacy OPR_EXECUTOR variables.

| Variable | Default | Description |
|----------|---------|-------------|
| `URT_HOST` | `0.0.0.0` | Server bind address |
| `URT_PORT` | `80` | Server port |
| `URT_SECRET` | `` | API authentication secret (required for production) |
| `URT_METRICS` | `false` | Enable Prometheus metrics endpoint at `/metrics` |
| `URT_NETWORK` | `openruntimes-runtimes` | Docker network for containers |
| `URT_KEEP_ALIVE` | `false` | Disable idle timeout (containers only removed via DELETE) |
| `URT_INACTIVE_THRESHOLD` | `60` | Seconds before marking runtime inactive |
| `URT_MAINTENANCE_INTERVAL` | `3600` | Seconds between cleanup tasks |
| `URT_AUTOSCALE` | `false` | Enable autoscale mode with adaptive concurrency limiting |
| `URT_MAX_CONCURRENT_EXECUTIONS` | `` | Optional max concurrent executions (autoscale mode) |
| `URT_MAX_CONCURRENT_RUNTIME_CREATES` | `` | Optional max concurrent runtime creations (autoscale mode) |
| `URT_EXECUTION_QUEUE_WAIT_MS` | `2000` | Max queue wait before execution fast-fails with overload |
| `URT_RUNTIME_CREATE_QUEUE_WAIT_MS` | `5000` | Max queue wait before runtime create fast-fails with overload |
| `URT_MIN_CPUS` | `0` | Minimum CPU allocation override |
| `URT_MIN_MEMORY` | `0` | Minimum memory (MB) override |
| `URT_MAX_BODY_SIZE` | `20MB` | Maximum request body size |
| `URT_RUNTIMES` | `` | Comma-separated allowlist of runtime images (falls back to `OPR_EXECUTOR_IMAGES`) |
| `URT_AUTO_RUNTIME` | `true` | Auto-resolve official OpenRuntimes shorthands and command mismatches to the newest verified runtime family, bypassing runtime allowlist pinning for official images |
| `URT_CONNECTION_STORAGE` | `local://localhost` | Storage DSN for builds |
| `URT_CACHE_CLEANUP_ON_SHUTDOWN` | `false` | If true, purge local download cache during shutdown |

See `.env.example` for the complete list with descriptions.

## API Endpoints

### Health
- `GET /v1/health` - OpenRuntimes-compatible text health check (`OK`)
- `GET /v1/health/stats` - Enhanced JSON health stats (optional)
- `GET /v1/ping` - Lightweight ping check

### Metrics
- `GET /metrics` - Prometheus metrics (enabled only when `URT_METRICS=true`)
  - When `URT_SECRET` is set, provide `Authorization: Bearer <secret>`

### Runtimes
- `POST /v1/runtimes` - Create a new runtime
- `GET /v1/runtimes` - List all runtimes
- `GET /v1/runtimes/{id}` - Get runtime details
- `DELETE /v1/runtimes/{id}` - Delete a runtime

### Executions
- `POST /v1/runtimes/{id}/executions` - Execute a function
- `POST /v1/runtimes/{id}/execution` - Execute a function (alias)

### Logs & Commands
- `GET /v1/runtimes/{id}/logs` - Stream container logs
- `POST /v1/runtimes/{id}/commands` - Execute shell command in container

## Development

```bash
# Run tests
cargo test

# Run with debug logging
RUST_LOG=debug cargo run --package urt-executor

# Run benchmarks
cargo bench --package urt-executor
```

## Security

For security issues, kindly email us at security@unifiedprojects.co.uk instead of posting a public issue on GitHub.

## License

AGPL-3.0 - See [LICENSE](LICENSE) for details.
