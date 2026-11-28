# ==============================================================================
# Multi-Stage Production Dockerfile for Skybouncer
# Sovereign Auto-Moderation & Bouncer Service for AT Protocol & Bluesky
# ==============================================================================

# Stage 0: Normalize package version in manifests so version bumps (e.g. 0.3.1 -> 0.3.2)
# produce identical manifest checksums and preserve the compiled dependency layer cache.
FROM debian:bookworm-slim AS manifest-prep
WORKDIR /manifests
COPY Cargo.toml Cargo.lock ./
RUN sed -i '0,/^version = ".*"/s//version = "0.0.1"/' Cargo.toml && \
    sed -i '/^name = "skybouncer"$/{n;s/^version = ".*"/version = "0.0.1"/;}' Cargo.lock

# ------------------------------------------------------------------------------
# Stage 1: Build Release Binary
# ------------------------------------------------------------------------------
FROM rust:1-bookworm AS builder

WORKDIR /build

# Copy version-normalized manifests; sibling crates (skybase, skyauth) are fetched from crates.io.
COPY --from=manifest-prep /manifests/Cargo.toml /manifests/Cargo.lock ./

# Pre-build third-party dependencies using dummy sources so app edits & version bumps reuse this layer.
RUN mkdir -p src && \
    echo "pub fn main() {}" > src/main.rs && \
    echo "" > src/lib.rs && \
    cargo build --release --locked --bin skybouncer && \
    rm -rf src

# Copy real manifests, application source, and embedded assets
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY assets ./assets

# Build optimized production binary (clean dummy crate artifacts so real code is compiled) and strip debug symbols
RUN rm -rf target/release/deps/skybouncer* target/release/deps/libskybouncer* \
           target/release/skybouncer* target/release/.fingerprint/skybouncer-* && \
    cargo build --release --locked --bin skybouncer && \
    strip /build/target/release/skybouncer

# ------------------------------------------------------------------------------
# Stage 2: Minimal Hardened Runtime Image
# ------------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# Install CA certificates for TLS/WSS connections and curl for container healthchecks,
# and explicitly distrust the October 2026 compromised eMudhra / Comodo AAA roots in the OS store.
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl sqlite3 && \
    sed -i \
      -e 's|^mozilla/emSign_ECC_Root_CA_-_G3.crt|!&|' \
      -e 's|^mozilla/Comodo_AAA_Services_root.crt|!&|' \
      /etc/ca-certificates.conf && \
    update-ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Dedicated non-root application user and group (UID/GID 10001)
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /sbin/nologin -d /app appuser

# Create application directory and persistent SQLite volume directory
RUN mkdir -p /app /data && \
    chown -R appuser:appgroup /app /data

WORKDIR /app

# Copy stripped binary from builder
COPY --from=builder /build/target/release/skybouncer /usr/local/bin/skybouncer

# Run as non-root user
USER appuser:appgroup

# Production environment defaults
ENV HOST=0.0.0.0 \
    PORT=3000 \
    WEB_ENABLED=true \
    SKYBOUNCER_DATABASE_PATH=/data/skybouncer.db \
    RUST_LOG=info,skybouncer=info,skybase=info

# Expose web dashboard and API port
EXPOSE 3000

# Container healthcheck: verify web dashboard and SQLite readiness probe
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://localhost:3000/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/skybouncer"]
