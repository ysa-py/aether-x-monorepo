# Aether-X — Architecture

> Status: Phase 0 (foundation). This document is the source of truth for the
> data-plane / control-plane split and the gRPC contract between them.

## 1. Executive summary

Aether-X is a **two-plane** proxy orchestration system. We deliberately do
**not** rewrite Xray-core or sing-box — they are mature, years-hardened cores.
Instead we wrap them under a Rust **Core Supervisor** (the data plane) that
owns process lifecycle, resource isolation, telemetry, and protocol hot-swap.
A Go **Control Plane** handles everything user-facing and orchestration-facing,
and talks to the supervisor exclusively over one versioned gRPC contract.

An autonomous AI layer sits *above* the control plane: it consumes anonymized
telemetry, classifies censorship events, and pushes **Policies** down to the
supervisor. The supervisor is the thing that actually mutates config. This
keeps the blast radius of any AI mistake bounded — a bad policy can be reverted
in one RPC, and the supervisor always has a deterministic fallback heuristic.

### Design principles

1. **Data plane is dumb and fast.** It executes; it does not decide strategy.
   Strategy is decided in the control plane / AI layer and *pushed* as policy.
2. **One contract.** All cross-plane communication is `aether.supervisor.v1`
   gRPC. No shared memory, no shared DB between planes. This is what lets us
   version, test, and replace either side independently.
3. **ISP-first telemetry.** Every observation is tagged by Iranian carrier
   (MCI / Irancell / Rightel / Shatel / TCI / …) because each implements DPI
   differently. Per-ISP learning is non-negotiable.
4. **Fail open to a heuristic, not to silence.** If the ONNX inference engine
   is unavailable, the supervisor applies a deterministic state machine. The
   system never fails "closed" with zero fallback logic.

## 2. Plane responsibilities

```
            ┌─────────────────────────── CONTROL PLANE (Go) ───────────────────────────┐
            │  REST/gRPC API · MCP server · users/quota/expiry · cluster orchestration  │
            │  auth (JWT+mTLS, RBAC) · telemetry aggregation → ClickHouse · AI ingest    │
            └─────────────────────────────────────┬──────────────────────────────────────┘
                                                  │  gRPC (mTLS)
                                                  │  aether.supervisor.v1
            ┌─────────────────────────────────────▼──────────────────────────────────────┐
            │                       DATA PLANE (Rust Core Supervisor)                     │
            │  process lifecycle · cgroups · protocol hot-swap · fragmentation            │
            │  cover traffic · live telemetry emission · deterministic fallback policy    │
            │  ┌──────────┐ ┌──────────┐ ┌───────────┐ ┌────────┐ ┌───────────────────┐  │
            │  │ xray-core│ │ sing-box │ │ AmneziaWG │ │ Naive  │ │ persis-core (Rust)│  │
            │  └──────────┘ └──────────┘ └───────────┘ └────────┘ └───────────────────┘  │
            └────────────────────────────────────────────────────────────────────────────┘
```

## 3. Inter-plane IPC — gRPC

The control plane is **always the client**; the supervisor is **always the
server**. Communication is bidirectional in effect via:

- **unary RPCs** for lifecycle: `StartCore`, `StopCore`, `RestartCore`,
  `ListCores`, `HotSwapProtocol`, `HealthCheck`, `ApplyPolicy`
- **server-streaming** for telemetry: `StreamTelemetry` → `stream TelemetryBatch`

Transport security is **mTLS mandatory** on the control port. The supervisor
rejects any plaintext / certificate-mismatched connection (see `SECURITY.md`).

Telemetry is **pushed** from supervisor → control plane → ClickHouse, never
polled, so detection latency is bounded by the supervisor's flush interval
(target: detection of a new block pattern and protocol switch **< 5 s** from
first failure signal).

## 4. Repository structure (CI/CD-optimized)

The monorepo is structured for independent cross-compilation and matrix testing
in GitHub Actions — including `armv7-unknown-linux-musleabihf` for embedded
routers.

```
aether-x-monorepo/
├── .github/workflows/
│   ├── proto-ci.yml
│   ├── rust-core-ci.yml        # cross-compile matrix + cargo test + clippy -D warnings
│   └── go-control-ci.yml       # go test + golangci-lint + govulncheck
├── api/
│   ├── proto/                  # source of truth
│   └── gen/                    # generated (go/, rust/) — committed for reproducible builds
├── core-supervisor/            # Rust crate (data plane)
│   ├── Cargo.toml
│   ├── build.rs                # tonic_build from ../api/gen or local protos
│   └── src/
│       ├── main.rs
│       ├── lib.rs
│       ├── supervisor.rs       # CoreSupervisor: lifecycle, restart loop, registry
│       ├── protocol.rs         # ProtocolCore trait + CoreKind dispatch
│       ├── grpc.rs             # tonic service impl of CoreSupervisorService
│       ├── policy.rs           # deterministic fallback heuristic state machine
│       ├── fragmentation.rs    # adaptive ClientHello fragmentation
│       ├── telemetry.rs        # collector + flusher
│       └── core/{xray.rs,singbox.rs,amnezia.rs,naive.rs,persis.rs}
├── control-plane/              # Go module (management plane)
│   ├── go.mod
│   ├── cmd/aether-control/main.go
│   └── internal/
│       ├── api/                # REST + MCP server
│       ├── auth/               # JWT + mTLS + RBAC
│       ├── config/
│       ├── grpcclient/         # supervisor gRPC client + mTLS dial
│       ├── model/              # users, subscriptions, nodes
│       └── telemetry/          # ingest supervisor stream → ClickHouse
├── deploy/{docker,compose,examples}/
└── docs/
```

## 5. Detection → reaction loop (target < 5 s)

```
 core probe fails ─▶ supervisor emits TelemetryEvent(CONNECT_FAIL/…)
                         │  (push, flush interval 100–250 ms)
                         ▼
                 control-plane ingest ─▶ ClickHouse feature store
                         │
                         ▼
                 AI/heuristic classifier (Rust ONNX, or fallback FSM)
                         │  emits Policy(revision=N)
                         ▼
                 ApplyPolicy RPC ─▶ supervisor applies (idempotent, monotonic revision)
                         │  if hot-swap-capable: drain + migrate; else restart
                         ▼
                 TelemetryEvent(PROTOCOL_SWITCH)
```

## 6. The "no Python in production" rule

| Where | Python allowed? |
|-------|-----------------|
| `core-supervisor/` (Rust data plane) | **No** |
| `control-plane/` (Go management plane) | **No** |
| Production inference runtime | **No** — Rust + `ort` (ONNX) only |
| `ai-training/` (offline, sandboxed, not on the prod path) | **Yes** — training pipeline |

The `ai-training/` directory is intentionally **outside** any deployed image.
It reads from the anonymized ClickHouse feature store and writes ONNX model
artifacts to a Model Registry; the Rust inference engine pulls those artifacts
at runtime. CI rejects any `Dockerfile` in a production service that installs
a Python runtime.

## 7. Why we wrap instead of rewrite

Xray-core and sing-box each represent years of protocol hardening. A from-scratch
Rust reimplementation would be a multi-year research project and would start
behind on every security fix. Our value is the **control/telemetry/decision
layer around them**, plus a single proprietary differentiator core
(`persis-core`) for Iran-specific adaptive fragmentation and cover traffic. That
core starts as a layer over existing transports and only graduates to a
hand-built Rust TLS path once its value is proven on real traffic.

## 8. Advanced subsystems (phase 0+)

### 8.1 Anti-forgery core (`antiforgery/`, Rust)

The user-facing panel must never trust client-reported expiry/quota. Four
composable primitives enforce this, each unit- and integration-tested:

- **Ed25519 subscription tokens** (`token`): the authoritative `bytes_total`,
  `bytes_used`, `expires_unix` are signed by the server key. A client altering
  any field invalidates the signature — verified by `scenario.rs` ("forged
  quota is rejected").
- **Hash-chained audit log** (`audit`): every subscription mutation appends a
  record whose hash chains to the previous (`SHA-256(seq||prev||payload)`).
  Any retroactive edit or deletion is cryptographically detectable. The log
  also exposes [`AuditLog::merkle_root`] and, via the [`merkle`] module, O(log n)
  inclusion proofs (RFC 6962-style, domain-separated leaves/nodes) so a third
  party can verify a specific record is part of the log without the whole log.
- **Merkle tree** (`merkle`): append-style tree with `from_leaves`, `root`,
  `proof`, `verify_proof` (inclusion, O(log n)). Also `forest_root` (RFC 6962
  forest) and **consistency proofs** — `consistency_proof(m)` +
  `verify_consistency` prove the log is append-only (the m-tree is a prefix of
  the n-tree), the other half of RFC 6962. Verified by round-trip + property
  fuzz tests.
- **Replay protection** (`replay`): `ReplayGuard` rejects reused nonces within
  a TTL; `RefreshVerifier` accepts rotating HMAC refresh tokens (current +
  previous key) with a timestamp-skew bound.
- **Device limiting** (`device`): per-subscription concurrent-fingerprint cap
  to defeat subscription-link sharing/resale.

This crate ships **no** network/DB code — it is a pure, deterministic core
the (Go) control plane calls (via the gRPC bridge below) to issue and verify.

#### 8.1.1 Anti-forgery gRPC bridge (`antiforgery-server/`, Rust)

Because the core is Rust and the control plane is Go, the crypto is **not**
reimplemented in Go. `antiforgery-server/` is a tonic gRPC service
(`aether.antiforgery.v1.AntiForgeryService`: `IssueToken`, `VerifyToken`,
`AuditRoot`) wrapping the core. The Go control plane dials it via
`internal/antiforgeryclient/` and exposes `/v1/subscriptions/{issue,verify}`
plus `/v1/subscriptions/audit-root`, mirroring the control-plane<->supervisor
gRPC pattern.

### 8.2 Local adaptive decider (`core-supervisor/src/decider.rs`, Rust)

Makes the fallback FSM **live** on the data plane. It folds a stream of probe
outcomes (success / RST / TLS-truncation / DNS-anomaly) into windowed signal
rates, builds a [`policy::FailureSignature`], and asks the existing
[`policy::FallbackEngine`] for a `Keep` / `Switch` / `Escalate` decision.

Crucially it is **non-duplicative**: it owns zero decision logic — every rule
lives in `FallbackEngine`, the single source of truth shared with the AI path.

### 8.3 Per-ISP feature store (`control-plane/internal/featurizer/`, Go)

Aggregates the telemetry stream into windowed `(ISP, protocol)` feature points
(sample count, success/RST/trunc/DNS rates, median RTT) — the rows the **AI
training** pipeline consumes. This is distinct from (and does not duplicate)
the per-node realtime decision in §8.2: that decides *now*; this records
*history* for learning.

The ingester feeds it in parallel with persistence via a `MultiWriter`, so
adding sinks requires no change to the ingestion path.

### 8.4 Embedded MCP server (`control-plane/internal/mcp/`, Go)

An AI assistant (Claude, Cursor, …) operates the control plane in natural
language over the Model Context Protocol (JSON-RPC 2.0 at `/mcp`), mounted by
the API layer — **not a sidecar**. It exposes:

- **Tools** backed by real components: `list_cores`, `get_node_health`,
  `switch_protocol` (→ supervisor HotSwap), `analyze_traffic` (→ featurizer
  snapshot, with optional protocol filter), `apply_ai_recommendation` (→
  supervisor ApplyPolicy with a fallback chain). Missing/invalid arguments
  return structured `isError` results, not crashes.
- **Resources**: `aether://node/status`, `aether://traffic/features`.
- **Prompts**: `diagnose_isp_failures`, `protocol_switch_recommendation`.

The server depends only on two small interfaces (`SupervisorClient`,
`FeatureClient`), which `main.go` adapts from the live gRPC client and
featurizer. This makes the MCP layer fully unit-testable with fakes (12 tests)
and keeps it decoupled from transport details.

## 9. Open questions (tracked, not blocking Phase 0)

- Q1: deterministic-fallback FSM spec per ISP (needs real baseline data).
- Q2: model registry storage + signing (Sigstore?) for ONNX artifacts.
- Q3: session migration semantics per protocol during hot-swap (which cores
  can truly drain vs. must hard-cut).
