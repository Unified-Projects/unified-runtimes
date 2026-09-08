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
| `URT_INACTIVE_THRESHOLD` | `60` | Default seconds before an idle runtime is reclaimed (per-runtime `inactiveThreshold` overrides it) |
| `URT_STARTUP_TIMEOUT_SECS` | `60` | Default seconds a runtime has to start listening on port 3000 before it is marked failed (per-runtime `startupTimeout` overrides it) |
| `URT_RUNTIME_MAX_CONCURRENCY` | `` | Default cap on executions in flight against a single runtime; unlimited when unset (per-runtime `maxConcurrency` overrides it) |
| `URT_MAINTENANCE_INTERVAL` | `3600` | Seconds between cleanup tasks |
| `URT_ADOPTION_NEGATIVE_CACHE_MS` | `2000` | How long a failed container adoption is remembered, so repeated requests for an unknown runtime ID do not each cost a Docker inspect (`0` disables) |
| `URT_AUTOSCALE` | `false` | Enable autoscale mode with adaptive concurrency limiting |
| `URT_MAX_CONCURRENT_EXECUTIONS` | `` | Optional max concurrent executions (autoscale mode) |
| `URT_MAX_CONCURRENT_RUNTIME_CREATES` | `` | Optional max concurrent serve-style runtime creations |
| `URT_MAX_CONCURRENT_BUILDS` | `max(2, cores / 2)` | Max concurrent build-style creates (build command, or `remove: true`) |
| `URT_EXECUTION_QUEUE_WAIT_MS` | `2000` | Max queue wait before execution fast-fails with overload |
| `URT_RUNTIME_CREATE_QUEUE_WAIT_MS` | `5000` | Max queue wait before runtime create fast-fails with overload |
| `URT_MIN_CPUS` | `0` | Minimum CPU allocation override |
| `URT_MIN_MEMORY` | `0` | Minimum memory (MB) override |
| `URT_MAX_BODY_SIZE` | `20MB` | Maximum request body size |
| `URT_RUNTIMES` | `` | Comma-separated allowlist of runtime images (falls back to `OPR_EXECUTOR_IMAGES`) |
| `URT_AUTO_RUNTIME` | `true` | Auto-resolve official OpenRuntimes shorthands and command mismatches to the newest verified runtime family, bypassing runtime allowlist pinning for official images |
| `URT_DOCKER_EVENTS` | `true` | Subscribe to Docker container events so runtime deaths are handled as they happen |
| `URT_RESTART_BACKOFF_MAX_SECS` | `30` | Cap on the 1s, 2s, 4s ... backoff between executor-initiated recreates of a runtime that keeps dying |
| `URT_CRASH_LOOP_THRESHOLD` | `3` | Deaths inside the crash-loop window that quarantine a runtime |
| `URT_CRASH_LOOP_WINDOW_SECS` | `60` | Window over which runtime deaths are counted |
| `URT_QUARANTINE_SECS` | `300` | How long a crash-looping runtime answers 503 on execute and 409 on create |
| `URT_RUNTIME_NAMESPACE` | `openruntimes` | Namespace auto-resolution prefers for official runtime families |
| `URT_RUNTIME_REGISTRY` | `` | Registry host for the preferred namespace (empty means Docker Hub), e.g. `ghcr.io` |
| `URT_RUNTIME_NAMESPACE_FAMILIES` | `` | Comma-separated families served from the preferred namespace; empty means all of them |
| `URT_CONNECTION_STORAGE` | `local://localhost` | Storage DSN for builds |
| `URT_CACHE_CLEANUP_ON_SHUTDOWN` | `false` | If true, purge local download cache during shutdown |

See `.env.example` for the complete list with descriptions.

### Runtime resolution

The executor ships a table of the official OpenRuntimes families and their
published `v5` tags: `bun`, `cpp`, `dart`, `deno`, `dotnet`, `flutter`, `go`,
`java`, `kotlin`, `node`, `php`, `python`, `python-ml`, `ruby`, `rust`,
`static` and `swift`.

Shorthands in `URT_RUNTIMES` and in `image` on `POST /v1/runtimes` expand
against that table:

- `node-22` becomes `openruntimes/node:v5-22`
- `node-20` becomes `openruntimes/node:v5-20.0`, the tag that is actually
  published for that line
- `go` (no version) becomes the newest published tag for the family
- a version the table does not know, such as `node-99`, is passed through as
  `openruntimes/node:v5-99` so a deployment can pin a tag published after the
  last table refresh

With `URT_AUTO_RUNTIME=true` (the default) a request whose entrypoint or build
command reveals a different family, for example `main.go` or `cargo build`, is
resolved to the newest tag of the family it really needs.

Set `URT_RUNTIME_NAMESPACE` and `URT_RUNTIME_REGISTRY` to serve those families
from your own mirror. With `URT_RUNTIME_REGISTRY=ghcr.io` and
`URT_RUNTIME_NAMESPACE=unified-runtimes`, `node-22` resolves to
`ghcr.io/unified-runtimes/node:v5-22`. `URT_RUNTIME_NAMESPACE_FAMILIES` narrows
that to a subset, for example `node,python,go`; every other family keeps
falling back to `openruntimes/<family>`. Image references that are not an
official family are never rewritten, whichever namespace is configured.

The table is static data, verified against Docker Hub on the date recorded in
`crates/urt-executor/src/config.rs`. Regenerate it with:

```bash
python scripts/refresh-runtime-table.py
```

The script prints the `OFFICIAL_RUNTIMES` constant, refreshed comment included,
ready to paste over the existing one. `--json` prints the raw tag data instead.

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

#### Per-runtime lifecycle fields

`POST /v1/runtimes` and the on-the-fly create inside `POST /v1/runtimes/{id}/executions`
accept three optional fields. Each falls back to the environment default above, and
each is echoed back on the runtime in `GET /v1/runtimes`. Unknown fields are ignored,
so OpenRuntimes clients that know nothing about them are unaffected.

| Field | Type | Description |
|-------|------|-------------|
| `startupTimeout` | seconds | How long the runtime has to start listening on port 3000. A runtime still silent at the end of its window is marked `failed` and removed, so the next request builds a fresh one. |
| `inactiveThreshold` | seconds | How long the runtime may sit idle before maintenance reclaims it. |
| `maxConcurrency` | integer | Executions admitted at once. Requests beyond the cap wait up to `URT_EXECUTION_QUEUE_WAIT_MS` and are then refused with `503 runtime_at_capacity`. |

The values are stored as container labels, so a runtime adopted after an executor
restart keeps the settings it was created with.

#### Runtime state

`status` is `pending` while a runtime is being built, then the Docker container
state, or `failed` once the executor has given up on a runtime that never listened.
`listening` is 1 once the runtime has answered on port 3000, and `initialised` is
set at the same moment and never before: a runtime reporting `initialised: 1` has
proved it can serve.

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
