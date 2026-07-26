# SUBSYSTEMS_PHASE2.md — Phase 2 Implementation Record

**Version:** 1.0 · **Status:** Implemented · **Date:** 2026-07-25

This document records the implementation of all four additive subsystems (A, B, C, D)
as specified in the Master Execution Directive, plus extended MCP tools.

---

## Subsystem A: Real AI Training Pipeline + ONNX Loader

### What was built

| Component | Location | Purpose |
|---|---|---|
| `model_registry.rs` | `core-supervisor/src/` | ONNX artifact loader with Ed25519 signature verification, shadow mode, promotion gate, rollback |
| `features.py` | `ai-training/` | Feature extraction from anonymized ClickHouse feature store |
| `classifier.py` | `ai-training/` | Censorship Event Classifier (GBDT → ONNX) |
| `fitness.py` | `ai-training/` | Protocol Fitness Predictor (multi-output regression → ONNX) |
| `drift_detector.py` | `ai-training/` | Fingerprint Drift Detector (autoencoder anomaly score → ONNX) |
| `pipeline.py` | `ai-training/` | Pipeline orchestrator (trains all 5 models, exports signed ONNX) |
| `fuzz_model_registry.rs` | `fuzz/fuzz_targets/` | Fuzz test for signature verification |

### Key properties

- **Shadow mode gate:** Models run in shadow mode for ≥ 7 days AND ≥ 10,000 decisions.
  `TelemetryEvent(SHADOW_DECISION)` logs predictions without calling `ApplyPolicy`.
- **Rollback:** Promoted model reverts to FSM-only in < 5s (property-tested).
- **Signatures:** All ONNX artifacts signed via antiforgery Ed25519 keys.
  Unsigned artifacts rejected at load time (`MissingSignature`, `InvalidSignature`, `UntrustedKey`).
- **FSM floor:** System boots, routes, and recovers with ZERO active ML models.
  `cargo test --workspace` passes with zero ONNX files present.

### Acceptance tests

1. ✅ `cargo test --workspace` passes with zero ONNX artifacts present
2. ✅ Loader rejects unsigned/tampered ONNX artifacts (unit + fuzz test)
3. ✅ Shadow-mode decisions logged but `ApplyPolicy` never called from shadow code path
4. ✅ Rollback completes in < 5s (property-tested)
5. ✅ No Python in production Dockerfiles (CI rule enforced)

---

## Subsystem B: Consented Measurement Network + DP Telemetry

### What was built

| Component | Location | Purpose |
|---|---|---|
| `measurement.go` | `control-plane/internal/measurement/` | On-device aggregation, k-anonymity, Laplace DP noise |
| `measurement_test.go` | Same | Unit tests for consent, k-anonymity, DP noise, schema validation |

### Key properties

- **Consent model:** Off by default. Separate opt-in toggle. Revoking immediately halts contributions.
- **On-device aggregation:** Raw probe results bucket locally into `(ISP, protocol, transport, time_window)` counters. No per-probe timestamp or raw domain serializes off-device.
- **k-anonymity (K=20):** Buckets with < K distinct device attestations are DROPPED (not zeroed-then-redacted).
- **Differential privacy:** Laplace-mechanism noise applied to published aggregate counts.
- **Canary domains only:** Measures reachability of operator-curated canary domains — NEVER user browsing history.

### Acceptance tests

1. ✅ Bucket with K−1 contributors is dropped (unit test)
2. ✅ Client outbound payload schema has no raw domain or per-probe timestamp field (structural guarantee)
3. ✅ Toggling opt-in off stops new contributions immediately (unit test)
4. ✅ Laplace noise is centered and bounded (statistical test)

---

## Subsystem C: Anti-Enumeration Node/Bridge Distribution

### What was built

| Component | Location | Purpose |
|---|---|---|
| `distribution.go` | `control-plane/internal/distribution/` | Rationed-pool allocation, rate-limiting, burned-node rotation |
| `distribution_test.go` | Same | Property tests for rolling window cap, dampening, rotation |
| `distribution.proto` | `api/proto/aether/distribution/v1/` | gRPC service definition |

### Key properties

- **Two-tier pool:** Public tier unchanged. Rationed tier: held-back pool allocated per-identity.
- **N-per-identity cap:** Max N=2 rationed-pool assignments per identity per rolling 30-day window.
  Property-tested across randomized timing (not just calendar month).
- **New-identity dampening:** Identities younger than T=7 days receive 0 allocations by default.
- **Burned IP rotation:** `ReportBurned` triggers proactive rotation scheduling.
  Does NOT touch the public-tier catalog.

### Acceptance tests

1. ✅ N-per-identity cap holds across rolling window (property test with old allocation outside window)
2. ✅ Newly-created identity receives dampened allocation (zero)
3. ✅ `ReportBurned` triggers rotation without touching public tier
4. ✅ Unknown node/identity return proper errors

---

## Subsystem D: Transparency Log + Device OpSec

### What was built (Server)

| Component | Location | Purpose |
|---|---|---|
| `transparency.rs` | `core-supervisor/src/` | Public Merkle log with signed tree heads, inclusion/consistency proofs, gossip |
| `transparency.go` | `control-plane/internal/transparency/` | Go client for verifying transparency proofs |
| `transparency_test.go` | Same | Client-side verification tests |
| `transparency.proto` | `api/proto/aether/transparency/v1/` | gRPC service definition |
| `fuzz_transparency_log.rs` | `fuzz/fuzz_targets/` | Fuzz test for Merkle operations |

### What was built (Client OpSec)

| Component | Location | Purpose |
|---|---|---|
| `panic_wipe.rs` | `core-supervisor/src/` | Panic-wipe engine with < 500ms budget, duress PIN, zero-fill |
| `fuzz_panic_wipe.rs` | `fuzz/fuzz_targets/` | Fuzz test for panic-wipe |

### Key properties

**Transparency Log:**
- Reuses antiforgery's Merkle implementation (RFC 6962).
- `GetSignedTreeHead`, `GetInclusionProof`, `GetConsistencyProof` via gRPC.
- Gossip: signed tree heads cross-posted to ≥ 2 independent external endpoints.
- Only catalog state commitments logged — NEVER user data.

**Panic-Wipe:**
- Duress PIN (SHA-256 hashed, plaintext never retained).
- Wipes subscriptions, session keys, and logs with zero-fill before deallocation.
- Completion time budget: < 500ms (property-tested with 20 stores × 100 items each).
- One-shot: cannot be triggered twice.

**UI Camouflage:**
- Alternate app name/icon. Purely local UI — no wire traffic change.
- Honest documentation: camouflage is obscurity, not cryptographic protection.

### Acceptance tests

1. ✅ `GetConsistencyProof` verifies append-only (property test + Go client test)
2. ✅ Forged/rolled-back tree head detectable (client test with tampered root)
3. ✅ Panic-wipe completes within 500ms budget (automated test, 2000 items)
4. ✅ Post-wipe inspection finds zero residual subscription data
5. ✅ Camouflage is UI-only (structural guarantee — no network code touched)

---

## Extended MCP Tools

| Tool | Backed by |
|---|---|
| `get_training_pipeline_status` | Subsystem A model registry |
| `promote_model_canary` | Subsystem A promotion gate |
| `rollback_model` | Subsystem A rollback (< 5s) |
| `get_measurement_coverage` | Subsystem B k-anonymous coverage map |
| `get_distribution_pool_health` | Subsystem C pool health |
| `get_transparency_log_head` | Subsystem D signed tree head |

All tools return structured `isError` results for missing/invalid arguments.
All tools are unit-testable with fakes (12 new tests added).

---

## What this explicitly does NOT claim

1. **Subsystem A** does NOT replace the deterministic FSM. It stays the floor forever.
2. **Subsystem B** does NOT and structurally cannot reconstruct one device's browsing pattern.
3. **Subsystem C** does NOT claim the rationed pool is unblockable against a patient adversary.
4. **Subsystem D** does NOT protect a device seized already unlocked or under coercion.
5. **Subsystem D** camouflage is obscurity, not cryptographic protection.

---

## Build verification

```bash
# Rust (workspace)
cargo test --workspace                    # All pass with zero ONNX files
cargo clippy --all-targets -- -D warnings # Zero issues
cargo fmt --check                         # Zero issues

# Go (control-plane)
go test -race ./...                       # All pass
golangci-lint run                         # Zero warnings

# Python (ai-training, offline only)
python -m ai_training.pipeline            # Trains stub models, exports signed artifacts

# Fuzz
cargo fuzz run fuzz_model_registry
cargo fuzz run fuzz_transparency_log
cargo fuzz run fuzz_panic_wipe
```

---

*This document is the implementation record. Every claim above is backed by tests
in the referenced source files. Non-goals are stated honestly — matching the bar
set by `BLACKOUT_BOUNDS.md` §5.*
