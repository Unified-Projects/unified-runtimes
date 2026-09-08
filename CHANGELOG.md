# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Fixed
- **`OPEN_RUNTIMES_CODE_PATH` not set on created runtimes**: openruntimes runtime images from September 2026 read `OPEN_RUNTIMES_CODE_PATH` in `/usr/local/server/helpers/lifecycle/extract.sh` to locate the code archive, falling back to scanning `/mnt/code` only when the variable is unset. URT mounted the downloaded source under the runtime's `/tmp` but never advertised its path, so serve-mode runtimes created with a source archive failed with "Code archive not found" unless the caller passed the variable by hand. `apply_runtime_env_vars` now sets `OPEN_RUNTIMES_CODE_PATH` to `/tmp/<mount file name>` whenever `source` is non-empty and the version is not legacy `v2`, matching executor-main 0.29 `Docker.php::createRuntime`. A value supplied in the request `variables` is left untouched. On-the-fly runtime creation from `routes/executions.rs` inherits the fix because it delegates to `create_runtime`.
- **Next.js standalone runtimes bound to their container address and were unreachable**: Next's standalone `server.js` reads `process.env.HOSTNAME || '0.0.0.0'` as its bind address, and Docker seeds `HOSTNAME` with the container identity, which resolves to a single bridge address. The runtime bound there and nowhere else, so the executor on the runtimes network got an immediate connection refusal on every request while the registry reported `status=running, initialised=1, listening=0` indefinitely. `routes/runtimes.rs::apply_runtime_env_vars` now seeds `HOSTNAME=0.0.0.0` into the environment of every runtime container on the modern (non-v2) layout. A caller-supplied `HOSTNAME` still wins, so the per-site variable remains the escape hatch; a blank value is treated as unset. Legacy v2 containers keep the Docker-provided identity. `OPEN_RUNTIMES_HOSTNAME` is a different variable (it carries the executor's hostname to the runtime) and is unchanged, as are the container's own hostname, `/etc/hostname` and the `urt.*` labels.
- **Unix-only permission tests broke the whole test binary on Windows**: `platform.rs`'s test module imports `std::os::unix::fs::PermissionsExt` under a plain `#[cfg(test)]`, so `cargo test -p urt-executor` failed to compile on Windows hosts. Gated on `#[cfg(all(test, unix))]`.

### Added
- **Non-listening runtime watchdog** (`tasks::listening_watch`, spawned from `main.rs`): scans the registry every 30s and logs a warning naming any runtime that has been running and initialised for at least 120s without ever having been observed listening on port 3000, pointing at a container-address bind as the likely cause. Each runtime is reported once; names that leave the registry are forgotten, so a runtime recreated under the same name is reported again. This fault class was previously only visible by reading `listening` out of the registry by hand.

### Changed
- **Source archives keep their real extension in the `/tmp` mount**: the mount name is now derived by a single `source_mount_file_name` helper shared by the download path and the `OPEN_RUNTIMES_CODE_PATH` value, so the two cannot drift. `.tar.gz`, `.tgz`, `.tar`, `.sqfs` and `.gz` sources map to `code.tar.gz`, `code.tgz`, `code.tar`, `code.sqfs` and `code.gz` respectively; anything else keeps the previous `code.tar.gz` default. Previously only `.tar` was special-cased and every other source, squashfs included, was mounted as `code.tar.gz`. Build commands that hardcode `/tmp/code.tar.gz` (including the built-in Next.js build command) therefore only work with gzipped-tar sources, which matches executor-main.

## [0.4.1] - 2026-05-04

### Fixed
- **Bot-scan-induced 30s 504 storm against pending runtimes**: `runtime::readiness::resolve_runtime_with_readiness` previously parked every caller on the runtime's `Arc<Notify>` for the full caller-supplied `req.timeout` whenever the registry entry was in pending state. Bot scanners targeting nonexistent paths (`/.env`, `/.git/config`, `/api`, `/graphql`, `/.DS_Store`, `/ecp/...`) that Appwrite forwards as function executions on a runtime ID currently being built would each block 30s and return `RuntimeTimeout` -> 504. The full caller deadline is no longer the wait bound for callers who did not initiate the build.
- **Readiness map leak on `create_runtime` error paths**: `routes/runtimes.rs::create_runtime` inserted into the `AppState.readiness` notifier map at the start and only removed on the explicit success-path call to `readiness_notify_and_remove`. Any error branch between those two points (registry insert race, container start failure, network attach error, build extraction failure, registry update failure) left the entry in the map; subsequent requests for that runtime ID would park on a `Notify` that nothing would ever wake, blocking until their own deadlines. Every error path now drops the new `ReadinessGuard` which calls `notify_waiters()` and removes the map entry.
- **R1 unknown-ID poll burned 200ms per scan**: the pre-insert race fallback in `resolve_runtime_with_readiness` polled with exponential backoff (10ms -> 20ms -> 40ms) up to a 200ms ceiling for every request whose runtime ID was neither in the registry nor in the readiness map. Reduced to a single ~10ms poll iteration; the legitimate notifier-creation race (notifier appears within ~10ms of request entry) is still covered by the post-sleep branch, with up to 200ms of additional wait once the notifier is observed.
- **`commands` and `logs` routes no longer block on someone else's build**: both routes previously called `resolve_runtime_with_readiness` with the wait path enabled. They now pass `should_wait_for_pending = false` and `adopt = false`, returning `RuntimeNotFound` immediately when the registry entry is pending. Neither route can legitimately wait for a build it did not initiate.

### Added
- **`ReadinessGuard` RAII type** in `runtime::readiness`: wraps the `AppState.readiness` insertion site so any error path between insertion and the explicit success-path notify automatically calls `notify_waiters()` and removes the DashMap entry on drop. Provides `disarm()` for the success path so the explicit removal call remains the single load-bearing operation. Panic-safe; relies only on infallible DashMap and Notify operations.
- **`Config::pending_wait_max_secs`** (env `URT_PENDING_WAIT_MAX_SECS`, default 60s): caps the pending-runtime wait duration independently of the caller's `req.timeout`. Applied as `min(cap, deadline_remaining)` so the caller's deadline still shortens when smaller than the cap; the cap only ever bounds the wait, never extends it.
- **`should_wait_for_pending: bool` parameter** on `resolve_runtime_with_readiness`: routes opt in to waiting only when the caller legitimately owns the build. `routes/executions.rs` passes `!req.image.is_empty()` (creation-style requests wait for their own build); `routes/commands.rs` and `routes/logs.rs` pass `false`. The notify-based wait, R1 race fallback, and adoption path are all preserved for callers that opt in.
- **8 new integration tests** under `tests/integration.rs` `mod regression_pending_wait`: `scan_request_does_not_park_on_pending_runtime`, `legitimate_creation_request_still_waits_on_pending`, `pending_wait_capped_by_config` (uses `tokio::time::pause`), `commands_route_does_not_wait_on_pending`, `logs_route_does_not_wait_on_pending`, `readiness_guard_fires_on_error_path`, `unknown_id_r1_poll_short_circuits_fast`, `bot_scan_concurrent_with_build_does_not_block_build` (50 concurrent scans + live build, asserts all scans 404 in <1s, build completes, scan p99 <500ms).

## [0.4.0] - 2026-04-28

### Fixed
- **Notify-based readiness gate (replaces poll-based fix from 0.3.1)**: `resolve_runtime` now parks waiters on a per-runtime `tokio::sync::Notify` keyed in a new `AppState.readiness` map and wakes them when `create_runtime` transitions the registry entry out of pending. Eliminates per-request Docker `inspect_container` polling on the hot path. Concurrent first-execution storms (50+ waiters) wake from a single `notify_waiters()` call, no fan-out to the Docker daemon. Pre-insert (R1) waiters are handled by a bounded sub-deadline plain-poll fallback.
- **Readiness gate applied to commands and logs routes**: `routes/commands.rs::resolve_runtime` previously returned `RuntimeTimeout` immediately when the registry entry was pending; now waits up to the request `timeout`. `routes/logs.rs::resolve_runtime` previously had a hardcoded 2-second grace window; now uses the validated `timeout_secs` query parameter and the shared readiness helper. Both routes now route through `runtime::readiness::resolve_runtime_with_readiness`.
- **DashMap shard locks no longer held across `await`**: `runtime::registry::sync_status` previously held a `get_mut` shard guard across `docker.inspect_container().await`, serialising every key on the same shard for the duration of the Docker RPC. Restructured to release the guard before the await and re-acquire only for the synchronous mutation.
- **Pending runtimes never removed by maintenance**: `cleanup_idle`, `cleanup_orphaned_keepalive`, and `sync_status` now skip entries with `is_pending() == true`, preventing parked execution waiters from observing a spurious `RuntimeNotFound` while `create_runtime` is still in flight. `sync_status` uses an atomic `DashMap::remove_if` to close the prior TOCTOU window.
- **`registry.update` errors no longer swallowed**: `routes/runtimes.rs::create_runtime` previously called `.ok()` on the success-path `registry.update`, which silently orphaned the Docker container if the registry entry had been concurrently removed. Errors now propagate; the failure path tears down the container, removes the tmp folder, and fires `readiness_notify_and_remove` so any parked waiters get a deterministic 404 instead of waiting to deadline.
- **Atomic check-and-insert in `create_runtime`**: `registry.insert` now runs before `readiness_notifier(name)`, so a duplicate concurrent create returns `RuntimeConflict` (409) before any notifier or container resource is allocated. The R1 fallback in the readiness helper continues to handle waiters that arrive in the narrow window between `insert` and `notifier`.
- **`tmp_folder` path canonicalisation**: moved to the top of the volume-mount setup in `routes/runtimes.rs` so cleanup paths derive from the canonical base on hosts where `/var` is symlinked to `/private/var` (macOS), preventing stray temp directories on extraction failure.

### Changed
- **Parallel container adoption on startup**: `tasks::maintenance::adopt_existing_containers` previously issued `docker.inspect_container` calls for every managed container in series; now fans out via `futures::stream::buffer_unordered(min(16, num_cpus*2).max(4))`. Restart adoption time scales O(n / concurrency) instead of O(n).
- **Parallel runtime stats collection**: `tasks::stats::collect_stats` parallelises `get_container_stats` calls via `buffer_unordered(20)`.
- **Concurrency-bounded warmup**: `tasks::warmup::run_warmup` no longer spawns one task per image; uses `buffer_unordered(4)` with `resilience::retry_with_backoff` (3 attempts) per pull, matching the existing `pull_semaphore` capacity.
- **Single `list_containers` per maintenance cycle**: `run_maintenance` now calls `docker.list_containers(Some("urt.managed=true"))` once and threads `&[ContainerInfo]` to both `cleanup_orphaned_keepalive` and `cleanup_untracked_managed_containers`, halving the cycle's Docker RPC count.
- **Lower-cadence `sync_status` in log streaming**: `routes/logs.rs` log-buffer polling continues at 100ms but `sync_status` is only called every 3s (`LOG_SYNC_STATUS_INTERVAL`), eliminating the 2 RPC/100ms hot path under many concurrent streams.
- **`runtime_create_limiter` is always `Some`**: when `autoscale=false`, the create-runtime semaphore now holds `max(4, num_cpus)` permits instead of being unset, providing default backpressure against Docker daemon overload from create bursts.
- **Connect timeout on the runtime HTTP client**: `reqwest::Client::builder()` in `main.rs` now sets `.connect_timeout(Duration::from_secs(5))` so dead containers cannot hold connection slots open up to the full request deadline.
- **Per-request build timeout**: `routes/build.rs` accepts an optional `timeout` multipart field (1-900s, default 300s) and wraps `docker.build_image` in `tokio::time::timeout`. New `ExecutorError::BuildTimeout` variant maps to HTTP 504; existing build response schema preserved.
- **Retry-wrapped maintenance container removal**: `remove_container_for_cleanup` wraps `docker.remove_container` in `resilience::retry_with_backoff` (3 attempts, 100ms base). `RuntimeNotFound` is treated as terminal-success and not retried.

### Added
- **Optional blocking warmup**: `URT_WARMUP_REQUIRED` (default `false`). When `true`, the executor awaits image pre-pulls before binding the listener, eliminating cold-pull latency from the first wave of requests after startup. When `false`, warmup remains a background task as before.
- **Readiness-gate observability**: new histogram `urt_executor_readiness_wait_seconds` (label `outcome`=`ready`|`timeout`|`absent`), counter `urt_executor_readiness_timeout_total`, counter `urt_executor_network_attach_failures_total`. `wait_for_pending` records on every exit path so wait-time distribution and 504-from-readiness can be alerted on independently of network-side 504s.
- **Network-attach failure metric**: `docker::manager::connect_container_to_networks` increments `urt_executor_network_attach_failures_total{network, container}` on secondary network attach failure (existing best-effort behaviour preserved, now observable).
- **Shared readiness helper module**: new `crates/urt-executor/src/runtime/readiness.rs` exposing `pub(crate) wait_for_pending` and `pub(crate) async fn resolve_runtime_with_readiness`. Used by `executions.rs`, `commands.rs`, and `logs.rs` to deduplicate the readiness-gate logic.
- **18 new integration tests** under `tests/integration.rs` (`mod readiness_gate` and `mod audit_fixes`) covering: cold-start readiness, 504 timeout, 50-waiter storm, removal-while-waiting, pending-not-cleaned, notifier consistency, R1 pre-insert wake, commands/logs readiness wait, build-timeout error mapping, parallel adoption fan-out primitive, atomic create-runtime insert, readiness metric increment, `URT_WARMUP_REQUIRED` config parsing, retry-wrap transient handling.

## [0.3.1] - 2026-04-16

### Fixed
- **Cold-start request handling**: `resolve_runtime` now polls runtime status with exponential backoff (50ms to 500ms) bounded by `req.timeout`, waiting for pending runtimes to become ready instead of returning immediately on the first sync check. Applies to both the registry-hit and post-adoption pending branches.
- **Runtime timeout status code**: `ExecutorError::RuntimeTimeout` now maps to HTTP `504 Gateway Timeout` instead of `400 Bad Request`, matching the semantics of `LogsTimeout` and correctly signalling upstream readiness failures.

### Security
- **Advisory-driven dependency bumps**: `quinn-proto` 0.11.13 to 0.11.14 (RUSTSEC-2026-0037 DoS), `rustls-webpki` 0.103.9 to 0.103.12 (RUSTSEC-2026-0049 CRL matching), `tar` 0.4.44 to 0.4.45 (RUSTSEC-2026-0067 / RUSTSEC-2026-0068 symlink chmod and PAX size header handling), and `rand` 0.9.2 to 0.9.4 (RUSTSEC-2026-0097 unsoundness).

## [0.3.0] - 2026-03-09

### Changed
- **Automatic official runtime resolution**: Added `URT_AUTO_RUNTIME` (default `true`) to normalize official OpenRuntimes shorthands and resolve empty or mismatched official runtime requests to the newest verified runtime family based on the requested image, entrypoint, and build command.
- **Runtime lifecycle reconciliation**: Runtime create, command, and log paths now re-adopt managed containers, clean stale runtime IDs before recreation, and tolerate brief create/log races instead of failing immediately with conflicts or missing-runtime errors.
- **Network and protocol routing**: Runtime startup now advertises the executor hostname consistently for legacy and modern images, attaches containers to all configured networks, and routes protocol traffic through the runtime network host with a fallback to the container name.
- **Build cache and storage handling**: Build cache scopes now include Dockerfiles and build args, cache cleanup prefers the oldest manifest `created` timestamp, and local/S3 storage listing now walks nested cache entries so cleanup sees full cache trees.
- **Build and response log handling**: Modern runtime log streaming now follows generated `logging/logs.txt` and `timings.txt` output, waits for asynchronous log flushes, truncates oversized build logs to executor limits, and preserves legacy execution header formatting for clients older than `0.11.0`.

### Fixed
- **Portable tar extraction**: Replaced GNU-only tar extraction flags with BusyBox-compatible `--no-same-permissions -o` handling.
- **Build source hardening**: Build context packaging is now deterministic, skips symlinks, and rejects tarballs that attempt path traversal or link-based escapes during extraction.
- **Docker startup resilience**: Container creation now retries after pulling missing images and treats duplicate network-attach responses as non-fatal.
- **Shutdown and maintenance cleanup**: Shutdown now removes per-runtime temp directories, keep-alive mode still cleans idle runtimes without a keep-alive ID, and maintenance removes untracked managed containers.

## [0.2.0] - 2026-02-25

### Changed
- **Autoscale controls**: Added `URT_AUTOSCALE`, `URT_MAX_CONCURRENT_EXECUTIONS`, and `URT_MAX_CONCURRENT_RUNTIME_CREATES` to enable adaptive runtime/execution concurrency limiting without API schema changes.
- **Load shedding and queue control**: Added bounded queue wait controls via `URT_EXECUTION_QUEUE_WAIT_MS` and `URT_RUNTIME_CREATE_QUEUE_WAIT_MS`, returning fast overload responses (`429`/`503`) under sustained saturation.
- **Transient retry hardening**: Added jittered exponential backoff with transient/non-transient error classification for runtime source downloads, runtime container creation, build artifact uploads, and runtime execution protocol calls.
- **Metrics expansion**: `/metrics` now exports persistent counters/histograms for queue wait/depth, execution/runtime-create latency, retries, keep-alive transfer and cleanup outcomes, active executions, and error classes.
- **Keep-alive replacement serialization**: Added per-`keepAliveId` async locking to serialize ownership transfer, replacement cleanup, deletion, and maintenance reconciliation paths.
- **Keep-alive generation labels**: New runtime containers include `urt.keep_alive_generation` and cleanup uses owner/generation guards to avoid removing the active replacement.
- **Prometheus exporter support**: Added optional `/metrics` endpoint for Prometheus/Grafana, toggled by `URT_METRICS` (with `OPR_EXECUTOR_METRICS` fallback), and protected by bearer auth when `URT_SECRET` is configured.
- **Request log correlation**: Added structured request logging with propagated/generated `x-request-id` response headers.
- **Startup/warmup noise reduction**: Runtime/network allowlists are deduplicated and startup network attach now skips unresolved executor container names instead of emitting repeated missing-container warnings.
- **Cache lifecycle behavior**: Added `URT_CACHE_CLEANUP_ON_SHUTDOWN` (default `false`) so warm cache can persist across restarts for lower cold-start latency.
- **Drop-in startup compatibility**: `URT_NETWORK` now defaults to `openruntimes-runtimes` and runtime warmup/allowlist accepts legacy `OPR_EXECUTOR_IMAGES` when `*_RUNTIMES` is not set.
- **Drop-in server compatibility**: `/v1/health` now returns plain-text `OK` (reference behavior), while enhanced JSON stats moved to `/v1/health/stats`.
- **API response parity**: Runtime delete now responds `200 OK` (instead of `204`) to match executor-main semantics.
- **Response header parity**: All responses now include `Server: Executor`, matching executor-main startup request handling.
- **Storage startup compatibility**: When `*_STORAGE_DEVICE` is unset, executor now honors `URT_CONNECTION_STORAGE` / `OPR_EXECUTOR_CONNECTION_STORAGE` DSN during storage initialization.

## [0.1.5] - 2026-02-25

### Fixed
- **Lifecycle cleanup safety**: Cleanup workers no longer drop runtime metadata when Docker container removal fails. Registry entries are preserved for retry, preventing unmanaged live container drift.
- **Targeted re-adoption on runtime misses**: `GET /v1/runtimes/:id` and execution runtime-miss paths now attempt adoption for the specific container name instead of scanning all managed containers, reducing Docker load under repeated bad IDs/misses.
- **Clippy CI regression**: Restored `-D warnings` compatibility by handling the newly-unused registry helper without failing lint.

### Changed
- **Container state detection hardening**: Runtime lifecycle reconciliation now uses richer container metadata (canonical state, labels, env, hostname) and more resilient startup/readiness behavior.
- **Keep-alive orphan reconciliation**: Maintenance cleanup better reconciles keep-alive ownership and stale/orphaned containers after replacements and restarts.
- **Coverage expansion**: Added lifecycle resilience E2E scenarios for restart re-adoption, keep-alive orphan cleanup, chaos deletion detection, and mass cleanup behavior.

## [0.1.4] - 2026-02-20

### Fixed
- **Tar permission/ACL/xattr failures**: Inject `--no-same-permissions --no-same-owner --no-acls --no-xattrs` into tar extraction commands via `sanitize_tar_flags`, preventing exit code 2 failures when tar tries to restore ownership, permission bits, POSIX ACLs, or extended attributes (including macOS `com.apple.*`) on host-mounted Docker volumes where the container user lacks those privileges. Flags are injected idempotently and only for extract (`x`) invocations; create commands are left unchanged.
- **Source file permission normalization**: After downloading source archives, recursively normalize permissions on all files (`0o644`) and directories (`0o755`) under the source directory before handing off to the runtime container.
- **Container startup detection**: Replace the single 100ms sleep + one-shot `inspect_container` check with a 30-second retry loop (200ms poll interval). Terminal states (`exited`, `dead`, `removing`) fail fast; transient states (`created`, `restarting`) continue polling. Fixes runtimes such as Next.js SSR (which log `✓ Ready in 124ms`) never being marked as running due to the race between container startup and the old one-shot check.

### Dependencies
- Bumped `bollard` 0.19 → 0.20 (major API reorganisation: all `*Options` types moved to `bollard::query_parameters`, `Config` replaced by `ContainerCreateBody`, `BuildInfo.error` replaced by `error_detail`, network types moved to `bollard::models`)
- Bumped `time` 0.3.44 → 0.3.47 (resolves RUSTSEC-2026-0009)
- Bumped `uuid` 1.19 → 1.21, `arc-swap` 1.7 → 1.8, `memchr` 2.7 → 2.8
- Updated transitive dependencies: `tower`, `serde_json`, `thiserror`, `anyhow`, `flate2`, `chrono`, `bytes`, `url`, `futures-util`, `tempfile`, `criterion`
- Pinned all GitHub Actions to full commit SHAs: `actions/checkout` v6.0.2, `docker/build-push-action` v6.19.2, `docker/login-action` v3.7.0, `docker/setup-qemu-action` v3, `docker/setup-buildx-action` v3, `github/codeql-action` v4.32.3, `dtolnay/rust-toolchain` stable, `Swatinem/rust-cache` v2, `actions/upload-artifact` v4

## [0.1.3]

### Fixed
- Default execution response now matches OpenRuntimes (multipart unless JSON is explicitly requested)
- JSON responses now fail fast for binary bodies, matching reference behavior
- Static runtime images are always allowed, even when runtime allowlist is set
- Build artifact naming respects `OPEN_RUNTIMES_BUILD_COMPRESSION=none` (tar vs tar.gz)
- Ignore tar permission-setting errors during build source extraction to avoid failures on restricted mounts
- Prevent maintenance from deleting temp directories for active runtimes
- Ensure executor container joins runtime networks and resolve container name via Docker
- Normalize v5 execution paths to always start with `/`
- Disable ownership and permission restoration when extracting cached tar layers

## [0.1.2]

### Fixed
- Clean up the previous keep-alive runtime when a new runtime claims the same keep-alive ID

### Changed
- Default executor keep-alive mode to false so idle cleanup runs unless explicitly enabled

## [0.1.1]

### Fixed
- Fixed tar extraction permission errors during fresh builds by setting mount directories to 0777

### Added
- Added cross-platform (Linux/Windows) support for host-side paths and APIs

### Changed
- Optimised CI pipeline: removed redundant build job, merged Docker build and test jobs, switched PR checks to single-arch (amd64)
- Added cargo-chef dependency caching to production and test Dockerfiles
- Pinned test Dockerfile base image to `rust:1.93`

## [0.1.0]

Initial release.

- Full API compatibility with OpenRuntimes Executor
- Support for v2, and v5 runtime protocols
- Backwards-compatible configuration (`URT_*` and `OPR_EXECUTOR_*` variables)
- Runtime management (create, list, get, delete)
- Function execution with JSON, multipart, and plain text responses
- Shell command execution and log streaming
- Local and S3/MinIO storage backends
- Container security hardening
- Graceful shutdown with execution draining
- Background maintenance and stats collection
- Docker multi-architecture support (amd64, arm64)
