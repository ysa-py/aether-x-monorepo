# Aether-X — Threat Model

Adversary profile, asset inventory, and mitigations. Written for a **nation-
state-level DPI** operator as the adversary, tuned to the Iranian
telecommunications context.

## 1. Adversary capabilities (assumed, conservative)

- **Deep packet inspection** on all international gateways, updated frequently.
- **Active probing**: the censor connects to a suspected proxy endpoint to
  confirm it is a proxy (not merely a "looks-suspicious" heuristic).
- **TLS fingerprinting** (JA3/JA4) to classify handshakes against known proxy
  client profiles.
- **SNI / ESNI / ECH inspection and blocking**, including by partial match.
- **ML-based traffic classification**: statistical analysis of flow
  size/timing/entropy to distinguish proxy traffic from benign HTTPS.
- **DNS poisoning / hijack** of resolved records.
- **IP reputation blacklisting** of known proxy egress, including by ASN.
- **RST injection** and connection throttling during sensitive windows.
- **Coordinated, time-correlated** filtering (rolling blackouts tied to events
  and working hours).

We design as if the adversary **updates weekly**, so static defenses are
insufficient — the value of this platform is *adaptive* defense.

## 2. Assets

| Asset | Why it matters |
|-------|----------------|
| Per-user subscription links | Direct leakage defeats the whole system for that user. |
| Node egress IPs | Once burned, that node's IPs are useless. |
| Protocol/fragmentation strategies | If fully known, they are fingerprinted and blocked. |
| Telemetry feature store | Aggregate failure patterns reveal what the censor is doing. |
| Signing keys (Ed25519) | Compromise ⇒ forged expiry/quota. |

## 3. Mapping: threat → control

| Threat | Control |
|--------|---------|
| Active probing confirms a proxy | Run proxy behind "look-alike" fronting (Reality, ShadowTLS v3); the endpoint must respond to a probe *as if* it were the fronted service. |
| TLS fingerprint (JA3/JA4) classification | Randomized, statistically valid fingerprint rotation per connection; uTLS-equivalent ClientHello construction (persis-core, phased). |
| SNI blocking | ECH/ESNI where available; SNI/ESNI rotation driven by the AI engine; domain fronting via CDN fallback. |
| ML traffic classification | Cover-traffic generator mimicking HTTPS/video statistical signatures; adaptive fragmentation breaks signature thresholds. |
| DNS poisoning | Compare resolved IP against known-good anchors; emit `DNS_HIJACK` telemetry; prefer DoH/DoT to anchors. |
| IP blacklisting | Multi-ASN, multi-region egress diversity; the AI engine deprioritizes recently-burned IPs. |
| Rolling blackout windows | Time-series block-pattern detection (autoencoder anomaly model) → proactive protocol pre-switch before peak windows. |
| RST injection | Detect RST patterns, switch protocol via `ApplyPolicy`; fallback FSM guarantees < 5 s reaction. |
| Forgery of expiry/quota | Ed25519-signed tokens + hash-chained audit log; client can never assert remaining time/quota. |
| Insider DB tampering | Tamper-evident Merkle audit log; any edit is cryptographically detectable. |
| Subscription link sharing/resale | Device fingerprinting + concurrent-connection limits. |
| Replay of token refresh | Rotating HMAC tokens with nonce + timestamp + short TTL. |

## 4. Reaction-time budget (target < 5 s)

```
T0    core probe fails
T0+ε  supervisor emits TelemetryEvent (push, flush ≤ 250 ms)
T0+1s control-plane ingest → ClickHouse feature store
T0+2s classifier (ONNX or fallback FSM) emits Policy
T0+3s ApplyPolicy RPC; supervisor hot-swaps / restarts
T0+4s TelemetryEvent(PROTOCOL_SWITCH) confirms
```

The deterministic fallback FSM (`core-supervisor/src/policy.rs`) guarantees a
*useful* decision even when the ONNX engine is unavailable, so the system
never fails "closed."

## 5. What this platform does NOT claim

- It does not make traffic **invisible**; it makes correct classification
  **expensive and non-deterministic**, raising the censor's cost continuously.
- It does not defeat an adversary with **full on-path global passive**
  capabilities targeting a single identified user with sustained effort; that
  requires endpoint hardening out of scope here.
- The ML models are only as good as the **real labeled telemetry** they are
  trained on (see ARCHITECTURE.md open question Q1). Until that data exists,
  the fallback FSM is the operative intelligence.
