# ─────────────────────────────────────────────────────────────────────────────
# OpenSSL minimum version pin and cache-bust key.
# Bump this ARG or pass --no-cache / a new --build-arg OPENSSL_VERSION to invalidate
# the package-install layer when security patches land in Debian bookworm
# (fixes CVE-2026-63076, CVE-2026-63072). Do not rely on --pull alone since
# cached layers will otherwise be reused.
# ─────────────────────────────────────────────────────────────────────────────
ARG OPENSSL_VERSION="3.0.22"

# ─────────────────────────────────────────────────────────────────────────────
# Stage 0 — Chef Planner
#   Computes the exact dependency recipe from Cargo manifests.
#   Rebuilds ONLY when Cargo.toml / Cargo.lock change, not when src/ changes.
#
# NOTE: fully-qualified image names are required for Podman compatibility.
# ─────────────────────────────────────────────────────────────────────────────
FROM docker.io/rust:bookworm AS chef
RUN cargo install cargo-chef
WORKDIR /build

# ─────────────────────────────────────────────────────────────────────────────
# Stage 1 — Planner
# ─────────────────────────────────────────────────────────────────────────────
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ─────────────────────────────────────────────────────────────────────────────
# Stage 2 — Cacher
#   Fetches and pre-compiles ALL dependencies from the recipe.
#   This layer is invalidated only when Cargo dependencies change.
# ─────────────────────────────────────────────────────────────────────────────
FROM chef AS cacher
COPY --from=planner /build/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# ─────────────────────────────────────────────────────────────────────────────
# Stage 3 — Builder
#   Compiles only the application source. Re-runs only on src/ changes.
# ─────────────────────────────────────────────────────────────────────────────
FROM chef AS builder
# Restore pre-built dependency artifacts
COPY --from=cacher /build/target target
COPY --from=cacher /usr/local/cargo /usr/local/cargo
# Copy full workspace source
COPY . .
# Build the release binaries — CLI and Daemon
RUN cargo build --release --bin satspath --bin satspathd

# ─────────────────────────────────────────────────────────────────────────────
# Stage 4 — Runtime
#   Minimal Debian Bookworm Slim: glibc for OpenSSL, zero build tools.
#   Runs as a non-root user with a read-only root filesystem.
# ─────────────────────────────────────────────────────────────────────────────
FROM docker.io/debian:bookworm-slim AS runtime

# OCI image labels — provenance and registry cataloging.
LABEL org.opencontainers.image.title="satspath-cli" \
      org.opencontainers.image.description="SatsPath — universal Bitcoin payment resolver and router" \
      org.opencontainers.image.vendor="SatsPath" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/satspath/satspath" \
      org.opencontainers.image.documentation="https://github.com/satspath/satspath/blob/main/README.md"

# Security: install CA certs and assert OpenSSL and libssl3 meet or exceed the patched version.
# Fixes: CVE-2026-63076, CVE-2026-63072, and related OpenSSL advisories.
ARG OPENSSL_VERSION
RUN apt-get update -qq \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        openssl \
        libssl3 \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' openssl)" ge "${OPENSSL_VERSION}" \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' libssl3)" ge "${OPENSSL_VERSION}" \
    && rm -rf /var/lib/apt/lists/*

# Security: create a dedicated non-root user for running the binary.
RUN groupadd --system --gid 10001 satspath \
    && useradd  --system --uid 10001 --gid satspath \
                --no-create-home --shell /sbin/nologin satspath

# Copy the compiled binary (the only artifact we need from the builder stage).
COPY --from=builder /build/target/release/satspath /usr/local/bin/satspath
RUN chmod 755 /usr/local/bin/satspath

# Create a writable data directory for .satspath/ state (mounted as a volume).
RUN mkdir -p /data && chown satspath:satspath /data

# Drop to non-root
USER satspath
WORKDIR /data

# Default environment (overridable at runtime via -e or docker-compose env file).
ENV SATSPATH_DATA_DIR=/data

# satspath is a CLI tool; the default command shows help.
ENTRYPOINT ["/usr/local/bin/satspath"]
CMD ["--help"]

# ─────────────────────────────────────────────────────────────────────────────
# Stage 5 — Runtime Daemon (satspathd)
#   Runs the local receiver-profile daemon with strict security.
# ─────────────────────────────────────────────────────────────────────────────
FROM docker.io/debian:bookworm-slim AS runtime-daemon

LABEL org.opencontainers.image.title="satspathd" \
      org.opencontainers.image.description="SatsPath Daemon — receiver-profile registry and API" \
      org.opencontainers.image.vendor="SatsPath" \
      org.opencontainers.image.licenses="MIT"

# Security: install CA certs, curl, and assert OpenSSL and libssl3 meet or exceed the patched version.
# Fixes: CVE-2026-63076, CVE-2026-63072, and related OpenSSL advisories.
ARG OPENSSL_VERSION
RUN apt-get update -qq \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl \
        openssl \
        libssl3 \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' openssl)" ge "${OPENSSL_VERSION}" \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' libssl3)" ge "${OPENSSL_VERSION}" \
    && rm -rf /var/lib/apt/lists/*

# Security: create a dedicated non-root user.
RUN groupadd --system --gid 10002 satspathd \
    && useradd  --system --uid 10002 --gid satspathd \
                --no-create-home --shell /sbin/nologin satspathd

# Copy the daemon binary.
COPY --from=builder /build/target/release/satspathd /usr/local/bin/satspathd
RUN chmod 755 /usr/local/bin/satspathd

# Writable data directory.
RUN mkdir -p /data && chown satspathd:satspathd /data

USER satspathd
WORKDIR /data

ENV SATSPATH_DATA_DIR=/data \
    SATSPATHD_BIND="0.0.0.0:9737"

EXPOSE 9737

ENTRYPOINT ["/usr/local/bin/satspathd"]
CMD ["--home", "/data", "--no-open"]

