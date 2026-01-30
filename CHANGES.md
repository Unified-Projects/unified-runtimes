# Changelog

All notable changes to this project will be documented in this file.

## [0.1.1]

### Fixed
- Fixed tar extraction permission errors during fresh builds by setting mount directories to 0777
- Added cross-platform (Linux/Windows) support for host-side paths and APIs


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
