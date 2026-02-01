# Unified Runtimes (URT) Executor

A high-performance drop-in replacement for the [OpenRuntimes Executor](https://github.com/open-runtimes/open-runtimes), rebuilt from the ground up in Rust.

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
| `URT_NETWORK` | `executor_runtimes` | Docker network for containers |
| `URT_KEEP_ALIVE` | `false` | Disable idle timeout (containers only removed via DELETE) |
| `URT_INACTIVE_THRESHOLD` | `60` | Seconds before marking runtime inactive |
| `URT_MAINTENANCE_INTERVAL` | `3600` | Seconds between cleanup tasks |
| `URT_MIN_CPUS` | `0` | Minimum CPU allocation override |
| `URT_MIN_MEMORY` | `0` | Minimum memory (MB) override |
| `URT_MAX_BODY_SIZE` | `20MB` | Maximum request body size |
| `URT_RUNTIMES` | `` | Comma-separated allowlist of runtime images |
| `URT_CONNECTION_STORAGE` | `local://localhost` | Storage DSN for builds |

See `.env.example` for the complete list with descriptions.

## API Endpoints

### Health
- `GET /v1/health` - Health check

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
