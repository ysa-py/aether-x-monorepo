# `ai-training/` — Offline ML training pipeline

> **This directory is the ONLY place Python may live.** It is never deployed,
> never packaged into a production image, and never reachable from the data or
> control planes at runtime. It reads the *anonymized* telemetry feature store
> and writes ONNX artifacts to a Model Registry; the Rust inference engine
> (`core-supervisor`) loads those artifacts via `ort` at runtime.

## Boundary (enforced in CI)

```
                    ┌────────── production (Rust + Go) ──────────┐
   telemetry ─────▶ │ ClickHouse feature store (anonymized)       │
                    └───────────────────────┬────────────────────┘
                                            │ read-only
                    ┌───────────────────────▼────────────────────┐
                    │  ai-training/  (Python, PyTorch)            │
                    │   - feature extraction                      │
                    │   - model training (classifier, fitness,    │
                    │     fingerprint-drift autoencoder, RL)      │
                    │   - ONNX export                             │
                    └───────────────────────┬────────────────────┘
                                            │ push artifacts (signed)
                    ┌───────────────────────▼────────────────────┐
                    │  Model Registry  ─────▶ Rust ort runtime     │
                    └─────────────────────────────────────────────┘
```

CI rule (to be wired in `.github/workflows/`): any `Dockerfile` under
`core-supervisor/` or `control-plane/` that installs Python or `pip` fails the
build. `ai-training/` ships its own sandboxed image and is never referenced by
a production service manifest.

## Status

Not implemented in phase 0. Planned scope (matches `ARCHITECTURE.md` §3):

1. **Feature extraction** from the ClickHouse feature store (per-ISP windowed
   success/failure, RTT drift, RST/TLS-truncation rates, DNS anomalies).
2. **Censorship Event Classifier** — gradient-boosted trees → ONNX.
3. **Protocol Fitness Predictor** — multi-output regression → ONNX.
4. **Fingerprint Drift Detector** — autoencoder anomaly score → ONNX.
5. **Adaptive Fallback Policy** — PPO/DQN policy network → ONNX (retrained
   periodically from aggregated telemetry).
6. **ONNX export + signature** before registry push.

> Until real labeled telemetry exists, the production system runs on the
> deterministic fallback FSM in `core-supervisor/src/policy.rs`. Do not ship
> "AI" that is actually a decorated `if/else` — that is explicitly out of scope
> until the data exists.
