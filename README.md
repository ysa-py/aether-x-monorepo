# Aether-X

**Autonomous multi-core proxy orchestration for adversarial networks.**

Aether-X is a two-plane system for running, supervising, and intelligently
switching between multiple proxy cores (Xray-core, sing-box, AmneziaWG, …)
under nation-state-grade DPI / active censorship — optimized first for the
Iranian telecommunications infrastructure.

| Plane | Language | Responsibility |
|-------|----------|----------------|
| **Data Plane** — `core-supervisor/` | Rust | Process isolation, cgroup limits, protocol hot-swap, live telemetry, fragmentation, cover traffic, **local adaptive decider** |
| **Routing** — `routing/` | Rust | Iran-aware Direct/Proxy/Block engine (domain + CIDR), JSON rule sets, auto-update trait |
| **Anti-Forgery Core** — `antiforgery/` | Rust | PASETO v4.public subscription tokens signed with Ed25519, tamper-evident audit log (chain + Merkle inclusion/consistency proofs), replay protection, device limiting |
| **Anti-Forgery Service** — `antiforgery-server/` | Rust | gRPC bridge exposing the anti-forgery core to the control plane (no crypto reimplementation in Go) |
| **Control Plane** — `control-plane/` | Go | User/quota/expiry, cluster orchestration, REST+gRPC API, **embedded MCP server**, telemetry aggregation, **per-ISP feature store** |
| **Dashboard** — `aether-x-dashboard/` | Next.js 15 / React 19 / TS | Enterprise NOC UI: Bento-grid, SVG topology + particle stream, Merkle viewer, RTL/LTR i18n |
| **AI layer** | Rust (ONNX in prod) + Python **only** in isolated offline training | Censorship classification, protocol-fitness prediction, fallback policy |

> **Hard constraint:** *No Python in any production runtime path.* Python is
> permitted **only** inside `ai-training/` (offline, sandboxed) to produce ONNX
> artifacts that the Rust inference engine loads. See `ARCHITECTURE.md` §6.

## Repository layout

```
aether-x-monorepo/
├── api/proto/                  # gRPC contracts (single source of truth, buf-managed)
│   └── aether/{supervisor,telemetry}/v1/*.proto
├── core-supervisor/            # Rust data plane (tonic gRPC server)
│   └── src/{supervisor,protocol,grpc,policy,decider,fragmentation,telemetry,core/*}.rs
├── antiforgery/                # Rust anti-forgery core (tokens, audit, replay, device)
│   └── src/{token,audit,merkle,replay,device}.rs
├── antiforgery-server/         # Rust gRPC bridge exposing antiforgery to Go
│   └── src/{main,server}.rs
├── control-plane/              # Go management plane (tonic-grpc client + REST + MCP)
│   ├── cmd/aether-control/
│   └── internal/{api,auth,antiforgeryclient,config,grpcclient,mcp,model,telemetry,featurizer}/
├── aether-x-dashboard/         # Next.js NOC dashboard (App Router, TS strict)
├── deploy/{docker,compose,examples,helm}/   # incl. production Helm chart

├── .github/workflows/          # CI: proto-lint, rust (workspace), go
├── Cargo.toml                  # Rust workspace root
└── docs/
```

## Status

Phase 0 — **foundation scaffold, verified with real compilers**. Compiles on a
standard Rust+Go+buf toolchain. No production deployment yet. Read the
[production-readiness audit](docs/PRODUCTION_READINESS_AUDIT_2026-07-26.md),
[external-core operation contract](docs/EXTERNAL_CORE_OPERATIONS.md), and
[verified node-catalog contract](docs/NODE_CATALOG_OPERATIONS.md) before
treating a simulated transport, capability request, or timing target as an
operational guarantee.

**Test coverage** (all green; incl. **k6 load/stress** via `make load-test`): Rust (unit + property/fuzz + integration), Go (unit + E2E), and **Playwright E2E** for the dashboard (Chromium + Firefox). Property tests (`proptest`) fuzz the Merkle, token, audit-chain,
and fragmentation-decision paths — satisfying spec §11's fuzz mandate at the
library level (cargo-fuzz/libfuzzer targets are the deeper follow-up layer).

## Build prerequisites (outside this repo)

```bash
rustup default stable
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
# buf for proto lint/generation:
curl -sSL https://buf.build/install | sh
```

## License

Proprietary. See `LICENSE`.
