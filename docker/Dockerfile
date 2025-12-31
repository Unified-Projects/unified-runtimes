# =============================================================================
# URT Executor Dockerfile
# Multi-stage build for optimized production image
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Build the Rust binary
# -----------------------------------------------------------------------------
FROM rust:1.92-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    musl-dev \
    openssl-dev \
    openssl-libs-static \
    pkgconfig \
    git

# Set up workspace
WORKDIR /app

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Build only urt-executor in release mode with optimizations.
# Disable -crt-static explicitly so the binary links dynamically against the
# Alpine base image's musl libc at runtime instead of producing a fully static
# binary. This keeps the binary compatible with the container's C runtime and
# allows us to rely on the system-provided OpenSSL and other shared libraries.
ENV RUSTFLAGS="-C target-feature=-crt-static"
RUN cargo build --release --package urt-executor

# Strip binary for smaller size
RUN strip /app/target/release/urt-executor

# -----------------------------------------------------------------------------
# Stage 2: Production image
# -----------------------------------------------------------------------------
FROM alpine:3.23

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    curl \
    libgcc \
    openssl \
    tini \
    tzdata

# Create directories
RUN mkdir -p \
    /usr/local/bin \
    /mnt/builds \
    /mnt/functions \
    /mnt/code \
    /mnt/logs \
    /mnt/telemetry \
    /tmp

# Copy binary from builder
COPY --from=builder /app/target/release/urt-executor /usr/local/bin/

# Make binary executable
RUN chmod +x /usr/local/bin/urt-executor

# Environment defaults
ENV URT_HOST=0.0.0.0
ENV URT_PORT=80
ENV RUST_LOG=info
ENV OPR_EXECUTOR_NETWORK=executor_runtimes
ENV URT_KEEP_ALIVE=true

# Expose port
EXPOSE 80

# Allow graceful shutdown (executor listens for SIGTERM)
STOPSIGNAL SIGTERM

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD sh -c 'curl -sf "http://${URT_HOST}:${URT_PORT}/v1/health" || exit 1'

# Use tini as init system for proper signal handling
ENTRYPOINT ["/sbin/tini", "--"]

# Run the executor (as root to access Docker socket)
CMD ["urt-executor"]
