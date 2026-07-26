# MASTER_EXECUTION_DIRECTIVE — Autonomous Integrated Phase 2 Implementation

**Target Executor:** External Senior Engineering Team / Autonomous Coding Agent (Claude Code, Cursor, Codex)

**Context:** `aether-x-monorepo` (Rust `core-supervisor` data plane, Go `control-plane`, Rust `antiforgery` core, Next.js dashboard).

**Execution Mode:** FULLY AUTONOMOUS, CONCURRENT, ZERO-ERROR MULTI-SUBSYSTEM IMPLEMENTATION.

**Strict Scope:** Implement Subsystems A, B, C, and D concurrently as additive, production-grade layers on top of the existing repo. **DO NOT rewrite, refactor, or break any existing code or state machine.**

---

## 0. MANDATORY GLOBAL INVARIANTS (NON-NEGOTIABLE)

1. **Additive Architecture:** Extend existing modules (`featurizer`, `antiforgery`, `policy::FallbackEngine`, `decider::LocalDecider`, `mcp`). Do not fork or duplicate core logic.
2. **Deterministic FSM Floor:** The deterministic FSM MUST remain the primary operational floor. System MUST boot, route, and recover with **ZERO** active ML models.
3. **No Python at Runtime:** Python is restricted strictly to offline jobs in `ai-training/`.
4. **Privacy-by-Construction:** Differential privacy (DP) and k-anonymity (K ≥ 20) are applied **on-device before network egress**. No raw destination data or user identity vectors may ever touch a server log.
5. **Zero Memory Unsafety:** All new Rust crates MUST enforce `#![forbid(unsafe_code)]`. All Go additions MUST pass `go test -race ./...` and `govulncheck`.
6. **Strict Error Isolation:** Subsystem failures MUST be non-fatal to core proxy routing. If Subsystems A, B, C, or D crash, the data plane immediately degrades gracefully to the FSM.

---

## 1. SUBSYSTEM EXECUTION SPECIFICATIONS

### Subsystem A: Real AI Training Pipeline (`ai-training/` + `ort` Loader)

- **Goal:** Implement the 5 lightweight ONNX models (Censorship Classifier, Protocol Fitness Predictor, Fingerprint Drift Detector, Adaptive Fallback, and Artifact Signer).
- **Shadow Mode Gate:** Models run in shadow mode for ≥ 7 days or ≥ 10,000 decisions. `TelemetryEvent(SHADOW_DECISION)` logs predictions without calling `ApplyPolicy`.
- **Rollback Requirement:** If a promoted model regresses, `ApplyPolicy` MUST revert to FSM-only in < 5s.
- **Signatures:** All ONNX artifacts MUST be signed via `antiforgery` Ed25519 keys. Unsigned artifacts MUST be rejected at load time.

### Subsystem B: Consented Measurement Network & DP Telemetry

- **Goal:** Collect anonymized transport reachability metrics over operator-curated canary domains (NEVER raw user traffic).
- **Consent Control:** Opt-in (default `off`). Toggle state MUST immediately halt outbound telemetry deltas within 1 probe cycle.
- **On-Device Aggregation:** Aggregate metrics locally into (ISP, protocol, transport, time_window) buckets. Apply Laplace DP noise.
- **K-Anonymity Enforcement:** Drop (do not zero-redact) any bucket fed by < K distinct device attestations (K = 20).

### Subsystem C: Anti-Enumeration Node & Bridge Distribution (`control-plane/internal/distribution/`)

- **Goal:** Prevent censor enumeration of egress pools using a two-tier pool architecture.
- **Public Tier:** Unchanged `/v1/transports` catalog.
- **Rationed Tier:** Allocate max N nodes (N=2) per identity per rolling 30-day window. Dampen allocations for accounts younger than threshold T.
- **Burned IP Rotation:** Wire `ReportBurned` signals directly into the proactive rotation scheduler.

### Subsystem D: Public Transparency Log & Device OpSec

- **Goal:** Public cryptographic auditing and physical device seizure safety.
- **Merkle Log Service:** Expose `GetSignedTreeHead`, `GetInclusionProof`, and `GetConsistencyProof` over gRPC via `antiforgery/src/merkle.rs`. Gossip signed tree heads to ≥ 2 independent external endpoints.
- **Panic-Wipe Engine:** Triggering the panic PIN MUST erase local subscriptions, memory buffers, and persistent logs within a strict execution budget (< 500ms).
- **UI Camouflage:** Implement alternate app presentation. MUST NOT alter network-layer wire signatures (wire-traffic invariant).

---

## 2. EXTENDED MCP PROTOCOL TOOLS (`control-plane/internal/mcp/`)

Expose control interfaces for all 4 subsystems via the embedded MCP server:

- `get_training_pipeline_status`
- `promote_model_canary` / `rollback_model`
- `get_measurement_coverage`
- `get_distribution_pool_health`
- `get_transparency_log_head`

---

## 3. ACCEPTANCE & QUALITY GATE MANDATES

The build is considered **COMPLETE** if and only if all gates return exit code 0:

1. `cargo test --workspace` passes with **zero ONNX files present**.
2. `cargo clippy --all-targets -- -D warnings` returns zero issues.
3. `go test -race ./...` and `golangci-lint` pass without warnings.
4. Property tests (`proptest`) confirm:
   - K − 1 telemetry buckets are dropped.
   - Panic-wipe leaves zero subscription remnants on disk.
   - Merkle consistency proofs verify append-only integrity.
   - N-per-identity rate limits hold across sliding time windows.
5. `Dockerfile` linters assert zero runtime Python in production service manifests.

**Execute all four subsystems concurrently, maintain absolute structural integrity, and deliver a zero-error build.**
