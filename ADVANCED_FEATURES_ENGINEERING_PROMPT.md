# ADVANCED_FEATURES_ENGINEERING_PROMPT — Aether-X Intelligence, Trust & Resilience Layer

**Audience:** External engineering team or autonomous coding agent building **four additive subsystems** on the existing `aether-x-monorepo`. You are not rebuilding anything — every subsystem below was selected because it is an explicit, evidence-backed gap.

---

## Evidence for each gap (verified against the repo)

| Subsystem | Evidence it's missing | Source |
|---|---|---|
| A. AI training pipeline | "Not implemented in phase 0" | `ai-training/README.md` |
| B. Measurement network | No data-collection path exists | `ARCHITECTURE.md` Q1 |
| C. Anti-enumeration distribution | No rationing on node distribution | repo search, absent |
| D. Transparency log | Merkle primitives exist but never exposed publicly | `antiforgery/src/merkle.rs` |
| D. Device OpSec | Covers infrastructure only; no seizure/duress scenario | `SECURITY.md` |

---

## §1 Hard invariants

1. **Additive, not duplicative.** Extend existing modules; do not fork.
2. **Deterministic-before-ML.** The FSM stays correct with zero ML models present.
3. **No Python outside `ai-training/`.**
4. **Privacy-by-construction.** k-anonymity/consent before data is written, not after.
5. **Every "intelligent" claim ships with a test that proves it.**
6. **Honest non-claims mandatory** — matching `BLACKOUT_BOUNDS.md` §5.

---

## §2 Subsystem A — Real AI Training Pipeline (`ai-training/`)

### Stages

| # | Stage | Output | Consumer |
|---|---|---|---|
| 1 | Feature extraction | Training tensors from ClickHouse feature store | Stages 2–5 |
| 2 | Censorship Event Classifier | Block-type probability per window | policy engine booster |
| 3 | Protocol Fitness Predictor | Expected success/RTT/time-to-block per protocol per ISP | transport ranking in decider |
| 4 | Fingerprint Drift Detector | JA4 anomaly score | proactive rotation trigger |
| 5 | Adaptive Fallback Policy | PPO/DQN action distribution | optional booster over FallbackEngine |
| 6 | Export & sign | Signed ONNX (reuse antiforgery Ed25519) | Model Registry → Rust `ort` loader |

### Promotion gate — shadow mode mandatory
1. **Shadow mode** (min 7 days or 10k decisions): model decisions logged but FSM ships.
2. **Promotion:** must beat FSM on time-to-reconnect margin registered before training.
3. **Rollback:** one `ApplyPolicy` RPC reverts to FSM (existing mechanism, unchanged).

### Does NOT claim
- Does not remove/shrink the deterministic FSM — it is the floor forever.
- Does not train on raw per-user data — only the aggregated feature store.
- Does not claim a fixed accuracy number — real data doesn't exist yet.

---

## §3 Subsystem B — Consented Measurement Network

### What is measured
- **Measured:** reachability/RTT/RST-rate of transport catalog + system-curated canary domains.
- **Never measured/uploaded:** user's actual browsing, DNS queries outside canary list, raw per-connection logs.

### Consent model
- **Off by default.** Separate explicit toggle — distinct from VPN usage.
- **Revocable any time.** Revoking stops future contribution.

### Privacy mechanism (construction, not policy)
1. Raw probes bucket locally into `(ISP, protocol, transport, time-window)` counters.
2. Client uploads counter **deltas**, never events.
3. **K-anonymity:** featurizer drops (not redacts) any bucket with < K=20 contributors.
4. **Differential privacy:** calibrated Laplace noise added to published aggregate counts.

### Does NOT claim
- Not a general analytics system — strictly reachability signal for Subsystem A.
- Cannot reconstruct individual browsing — raw data never existed server-side.
- Does not run without explicit opt-in.

---

## §4 Subsystem C — Anti-Enumeration Distribution

### Two-tier pool model

| Tier | What | Distribution |
|---|---|---|
| **Public** (existing) | Primary + last-resort tiers | `/v1/transports`, unchanged |
| **Rationed** (new) | Held-back egress node pool | Per-identity, rate-limited, rotated |

### Allocation policy (`control-plane/internal/distribution/`)
- Cap: N=2 rationed assignments per identity per rolling 30-day window.
- **New-identity dampening:** identities younger than threshold get zero/minimal allocation.
- **Burned-IP signal reuse:** consumes existing `TelemetryEvent` stream — not a new detector.
- gRPC: `aether.distribution.v1.DistributionService` (`RequestRationedNode`, `ReportBurned`, `GetPoolHealth`).

### Does NOT claim
- Not unblockable — raises enumeration cost/delay, doesn't eliminate it.
- Does not implement identity verification — assumes it exists upstream.

---

## §5 Subsystem D — Transparency Log + Device OpSec

### D.1 Server: public transparency log
- Reuses `antiforgery/src/merkle.rs` (RFC 6962-style, already built).
- New service: `GetSignedTreeHead`, `GetInclusionProof`, `GetConsistencyProof`.
- **Logs:** signed commitments to active node/transport catalog state — never user data.
- **Gossip:** cross-post tree heads to ≥2 channels outside operator control (git commit + timestamping service).

### D.2 Client: device-level OpSec (seizure scenario)
- **App camouflage:** alternate name/icon, off by default. Tradeoff documented honestly.
- **Panic-wipe:** gesture/PIN deletes local subscription data + logs. Ships with measured time budget.
- **Minimal footprint:** no plaintext history; in-memory session logs; no crash-dump metadata retention.
- **Decoy profile** (stretch): innocuous profile under duress PIN.

### Does NOT claim
- Does not protect a device seized already unlocked or where user is coerced.
- Does not make network traffic deniable — that's the anti-DPI layer's job (already built).
- Camouflage is obscurity, not cryptographic protection.

---

## §6 New MCP tools (extends existing server)

| Tool | Backed by |
|---|---|
| `get_training_pipeline_status` | Subsystem A |
| `promote_model_canary` / `rollback_model` | Subsystem A promotion gate |
| `get_measurement_coverage` | Subsystem B (k-anonymous, never raw) |
| `get_distribution_pool_health` | Subsystem C |
| `get_transparency_log_head` | Subsystem D |

---

## §7 Quality gates ("zero-error" = this list)

- **Rust:** `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --workspace`, `cargo audit`, `#![forbid(unsafe_code)]`.
- **Go:** `go test ./...`, `golangci-lint`, `govulncheck`.
- **Python (ai-training/ only):** isolated image, never referenced by production manifests.
- **Property/fuzz tests:** Merkle usage (D), k-anonymity threshold (B), promotion rollback (A), rate-limit window (C).

---

## §8 Definition of Done

- [ ] **A:** shadow mode end-to-end; model promotable + rollbackable; zero-ONNX tests pass.
- [ ] **B:** opt-in toggle; k-anonymity + DP noise verified; no raw per-user path exists.
- [ ] **C:** per-identity cap + dampening enforced; burned-node rotation automatic.
- [ ] **D-server:** log queryable, consistency-provable, gossiped to ≥2 channels.
- [ ] **D-client:** panic-wipe meets time budget; camouflage doesn't alter wire traffic.
- [ ] Every gate §7 is real exit 0.
- [ ] No product copy contradicts the non-goals.

---

## §9 What you must NOT do

1. Do not let ML become a hard dependency — FSM works alone, forever.
2. Do not upload/log raw per-user data, ever, under any retention.
3. Do not present the rationed pool as unblockable, or camouflage as crypto protection.
4. Do not add a second crypto scheme — reuse antiforgery's Ed25519 + Merkle.
5. Do not skip shadow mode.

---

*Each subsystem is independently shippable. A→B are naturally sequenced before C→D. The non-goals are what keeps this consistent with `BLACKOUT_BOUNDS.md` §5 and `THREAT_MODEL.md` §5.*
