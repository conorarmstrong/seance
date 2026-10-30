# syntax=docker/dockerfile:1

# Séance digital-forensics platform — production image.
#
# Three stages:
#   1. frontend  — build the React SPA (frontend/dist)
#   2. backend   — build the release `seance_api` server binary (links libewf)
#   3. runtime   — slim Debian image with the binary, the SPA bundle, libewf
#
# The `seance_api` binary serves the JSON API only (it does not serve the SPA
# itself). The built SPA is shipped at /app/frontend/dist so a reverse proxy
# can serve it and proxy /api/* to this container. See documentation/DEPLOYMENT.md.

# ---------------------------------------------------------------------------
# Stage 1: build the React frontend
# ---------------------------------------------------------------------------
FROM node:20-trixie-slim AS frontend

WORKDIR /build/frontend

# Install dependencies first for better layer caching (only re-runs when the
# lockfile changes).
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

# Build the SPA. `npm run build` runs `tsc -b && vite build`, emitting to
# frontend/dist (vite.config.ts: build.outDir = "dist").
COPY frontend/ ./
RUN npm run build

# ---------------------------------------------------------------------------
# Stage 2: build the Rust release binary
# ---------------------------------------------------------------------------
FROM rust:1-trixie AS backend

# libewf-dev + pkg-config: the seance_container_e01 crate links libewf.
# clang + libclang-dev: its build.rs uses bindgen, which needs libclang to
# parse <libewf.h> and generate FFI bindings.
# libssl-dev: seance_reporting builds openssl-sys (report signing) against the
# system OpenSSL. (The rust:1-trixie base already ships it; installed here so
# the build does not depend on that base detail.)
# libheif-dev: seance_api's default features include heic, which links libheif
# (via libheif-rs) for HEIC/HEIF thumbnails. The build below takes those
# defaults, so omitting this fails the same way a bare host does.
#
# These stages are on trixie, not bookworm, for libheif alone: bookworm ships
# 1.15.1 and libheif-rs needs >= 1.19 (see the v1_19 pin in seance_api).
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        libewf-dev \
        libssl-dev \
        libheif-dev \
        clang \
        libclang-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy the whole workspace. The build context is trimmed by .dockerignore
# (no target/, node_modules, reference/, test_data/, .git).
COPY . .

# Build the API server plus the isolated E01 read helper (seance-ewf-helper),
# which the server spawns so a libewf crash on a hostile image can't take down
# the process. The helper must sit next to the server binary at runtime.
RUN cargo build --release --locked --bin seance_api --bin seance-ewf-helper

# ---------------------------------------------------------------------------
# Stage 3: slim runtime
# ---------------------------------------------------------------------------
FROM debian:trixie-slim AS runtime

# Runtime shared libraries the binary is dynamically linked against:
#   libewf2  — the libewf RUNTIME library (E01 container support)
#   libssl3  — OpenSSL 3 runtime (report signing via seance_reporting)
#   libheif1 — libheif runtime (HEIC/HEIF thumbnails); the binary is linked
#              against it by the heic feature, so without it the server fails
#              at process start on a missing shared object, not at build time.
# (SQLite is statically bundled by sqlx, so no system SQLite is needed.)
# ca-certificates for outbound TLS; curl for the container HEALTHCHECK.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libewf2 \
        libssl3 \
        libheif1 \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root service account (fixed UID/GID for predictable volume ownership).
RUN groupadd --system --gid 10001 seance \
    && useradd --system --uid 10001 --gid seance --home-dir /home/seance --create-home seance

# /data holds the SQLite DB (+ WAL/SHM) and the search_index/ directory. The
# server writes these relative to its working directory, so WORKDIR is /data.
RUN mkdir -p /data && chown seance:seance /data

# The API server binary.
COPY --from=backend /build/target/release/seance_api /usr/local/bin/seance_api
# Ship the E01 isolation helper beside the server so it is auto-discovered.
COPY --from=backend /build/target/release/seance-ewf-helper /usr/local/bin/seance-ewf-helper

# The built SPA bundle, for a reverse proxy to serve (see DEPLOYMENT.md).
COPY --from=frontend /build/frontend/dist /app/frontend/dist

USER seance
WORKDIR /data

# Bind to all interfaces inside the container; publish/reverse-proxy as needed.
ENV SEANCE_BIND=0.0.0.0:8080
EXPOSE 8080

# /api/v1/auth/me returns 200 without a token, so it works as a liveness probe
# whether or not authentication is enabled.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/api/v1/auth/me || exit 1

ENTRYPOINT ["/usr/local/bin/seance_api"]
