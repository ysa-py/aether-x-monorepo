# Multi-stage build for the Rust anti-forgery gRPC service (aether-antiforgery).
#
# Build context: the MONOREPO ROOT.
#   docker build -f deploy/docker/antiforgery-server.Dockerfile .
#
# This service is what makes `/v1/subscriptions` work: the Go control plane
# delegates every Ed25519 token operation to it over gRPC rather than
# reimplementing the crypto (see README, "Anti-Forgery Service"). Without it
# deployed, that endpoint stays disabled.
#
# Like the supervisor, this crate is a workspace member with a path dependency
# (`antiforgery/`), so the workspace manifest and all members must be present.

FROM rust:1-bookworm AS builder
WORKDIR /build
# protoc is required by tonic_build when the pure-Rust fallback is unavailable.
RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock /build/
COPY api/proto /build/api/proto
COPY antiforgery-server /build/antiforgery-server
COPY antiforgery /build/antiforgery
COPY core-supervisor /build/core-supervisor
COPY routing /build/routing

RUN cargo build --release --locked --package aether-antiforgery-server --bin aether-antiforgery

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tini \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10002 aether
COPY --from=builder /build/target/release/aether-antiforgery /usr/local/bin/aether-antiforgery
USER aether
EXPOSE 7071
ENTRYPOINT ["/usr/bin/tini", "--", "aether-antiforgery"]