# Development quickstart

This repo currently has **no working toolchain in the authoring sandbox** (no
Rust/Go/protoc). The code is written to compile on a standard dev machine.

## Prerequisites

```bash
rustup default stable          # and add targets you need (aarch64, armv7)
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
curl -sSL https://buf.build/install | sh   # for proto lint/generate
docker                              # for the local data layer
```

## Generate proto stubs

```bash
make buf          # writes api/gen/{go,rust}/
```

## Run the local data layer

```bash
make compose-up   # postgres :5432, clickhouse :9000/:8123, redis :6379
```

## Build & test

```bash
make rust-test    # cargo test + clippy (-D warnings)
make go-test      # go test -race + golangci-lint
```

## Run locally (dev, loopback only)

```bash
# Terminal 1 — data plane
cd core-supervisor
AETHER_SUPERVISOR_ADDR=127.0.0.1:7070 cargo run

# Terminal 2 — anti-forgery service (ephemeral signer is development-only)
cd antiforgery-server
AETHER_DEV=true cargo run

# Terminal 3 — control plane
cd control-plane
AETHER_DEV=true AETHER_JWT_SECRET=dev-dev-dev-dev-dev-dev-dev-dev-32 \
  go run ./cmd/aether-control
```

The control plane connects to the supervisor at `127.0.0.1:7070` over plaintext
(allowed only on loopback; see `SECURITY.md`).

## CI gates (all must pass before merge)

- `proto` — buf lint + "generated stubs are up to date" check.
- `rust-core` — fmt, `clippy -D warnings`, `cargo test`, `cargo audit`,
  cross-compile matrix (amd64 / arm64 / armv7-musl).
- `go-control` — `go vet`, golangci-lint, `go test -race`, `govulncheck`.

See `ARCHITECTURE.md` for the plane split and `THREAT_MODEL.md` for the
adversary assumptions.
