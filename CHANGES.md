# Changelog

All notable changes to this project will be documented in this file.

## [0.1.1]

### Fixed
- Fixed tar extraction permission errors during fresh builds by setting mount directories to 0777

### Added
- Added cross-platform (Linux/Windows) support for host-side paths and APIs

### Changed
- Optimised CI pipeline: removed redundant build job, merged Docker build and test jobs, switched PR checks to single-arch (amd64)
- Added cargo-chef dependency caching to production and test Dockerfiles
- Pinned test Dockerfile base image to `rust:1.93`

## [0.1.2]

### Fixed
- Clean up the previous keep-alive runtime when a new runtime claims the same keep-alive ID

### Changed
- Default executor keep-alive mode to false so idle cleanup runs unless explicitly enabled


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
