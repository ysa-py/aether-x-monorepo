# Multi-stage build for the Rust data plane (aether-core-supervisor).
#
# Build context: the MONOREPO ROOT.
#   docker build -f deploy/docker/core-supervisor.Dockerfile .
#
# The crate is a member of the root Cargo workspace and has a path dependency
# on `routing/`, so the workspace manifest, the lockfile and every member
# referenced by that manifest must be present — building from the crate
# directory alone cannot resolve `aether-routing` and fails.
#
# Produces a minimal glibc image. For armv7/musl, build with the matching
# toolchain target and switch the runtime base to an arm-compatible image.

FROM rust:1-bookworm AS builder
WORKDIR /build
# protoc is required by tonic_build when the pure-Rust fallback is unavailable.
RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Workspace root manifest + lockfile: pinned, reproducible dependency graph.
COPY Cargo.toml Cargo.lock /build/
# The gRPC contracts consumed by build.rs.
COPY api/proto /build/api/proto
# Every workspace member (the root manifest lists all four; a missing one is a
# hard resolve error even when it is not in this binary's dependency tree).
COPY core-supervisor /build/core-supervisor
COPY routing /build/routing
COPY antiforgery /build/antiforgery
COPY antiforgery-server /build/antiforgery-server

# Build only this binary out of the workspace.
RUN cargo build --release --locked --package aether-core-supervisor --bin aether-supervisor

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tini \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 aether
COPY --from=builder /build/target/release/aether-supervisor /usr/local/bin/aether-supervisor
USER aether
EXPOSE 7070
ENTRYPOINT ["/usr/bin/tini", "--", "aether-supervisor"]
