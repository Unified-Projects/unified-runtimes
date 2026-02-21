# Changelog

All notable changes to this project will be documented in this file.

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
