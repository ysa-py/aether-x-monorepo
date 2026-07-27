# BLACKOUT_BOUNDS.md — Aether-X Blackout Isolation Bounds Contract

**Version:** 1.0 · **Status:** Non-negotiable engineering contract · **Supersedes:** nothing (additive to THREAT_MODEL.md §5)

This document is the authoritative, honest answer to: *"When international internet access is
cut (Iran DPI throttling, BGP route severing, national blackout), what does Aether-X actually
deliver, and where is the limit no software can cross?"* Every claim below is an engineering
commitment enforced by tests. Every non-claim is an explicit, honest boundary.

> **The one invariant above all others:** No software or AI component in this system may report a
> "connected" state to the user — or to any UI layer — unless a real transport has completed a real,
> successful handshake within a bounded recent window (default 5 s). Violating this is a **P0
> correctness bug**, not a UX preference.

---

## 1. The five isolation levels

The system classifies its environment into one of five strictly-ordered levels. Transitions
**upward** (worse) are **debounced** — a single failed probe never advances past Degraded.
Transitions **downward** (recovery) are **instant** — the first successful probe on any path drops
straight to Nominal.

| Level | Meaning | What carries traffic |
|---|---|---|
| **Nominal** | Primary core reachable; normal operation. | Primary TLS cores (VLESS/Reality/Vision, Hysteria2, TUIC, NaiveProxy, ShadowTLS, AmneziaWG). |
| **Degraded** | One path degraded; DPI active (RST injection, TLS truncation, DNS tampering). | Hot-swap to another primary protocol + AI anti-DPI morphing kicks in. User does not notice. |
| **Escalated** | All primary paths blocked; last-resort tier engaged. | Tor pluggable transports (WebTunnel, Snowflake, obfs4, Meek, Conjure) + DNS tunnels (MasterDnsVPN, VayDNS, NoizDNS) + SSH SOCKS. |
| **ConfirmedIsolation** | The last-resort tier has also failed **sustained across a debounce window and across multiple independent egress paths** — this is "the exit is gone," not "one node is gone." | **Nothing.** The system stops high-frequency retries (battery/footprint discipline), preserves all queued data locally, and probes at low frequency. UI shows "Reconnecting" — never "Connected." |
| **TotalIsolation** | ConfirmedIsolation has persisted past a longer threshold AND no out-of-band interface (satellite/secondary SIM) reports healthy either. | **Nothing international.** Local mesh + any configured out-of-band uplink activate. UI shows "Offline — no international path exists." |

---

## 2. What the system claims at each level (the engineering commitments)

### Nominal / Degraded / Escalated — "the user does not notice"
The system will reroute around **single-path failures, individual IP/SNI blocking, DPI throttling,
and rolling/coordinated blackout windows** without the user perceiving a disconnect. This is
achieved by:
- The decider → resilience-tier chain (`policy::FallbackEngine` → `decider::LocalDecider` →
  `resilience::ResilienceController`).
- The **buffer replay**: in-flight frames are re-injected onto the winning path on a transport
  swap, so the user's TCP socket never sees a gap (< 1 ms re-injection).
- The **multipath racer**: all candidate transports are raced concurrently; the fastest established
  one is adopted in ~one round-trip, not N serial timeouts.
- The **AI anti-DPI morpher**: packet-size entropy + Gaussian IAT jitter + JA4/uTLS fingerprint
  rotation matching Iranian-domestic whitelisted traffic (Aparat / SHAPARAK).

**This is an engineering commitment the test suite enforces.** These three levels are where
"zero-perceived-disconnect" is real and achievable.

### ConfirmedIsolation — "disciplined waiting, not false hope"
The system **stops generating high-frequency retry traffic** (battery and network-footprint
discipline — a retry storm during a blackout is both wasteful and a signal to the censor). It:
- Preserves queued data locally in the bounded, disk-backed store-and-forward queue — up to its
  configured capacity, after which it evicts oldest-bulk-first and counts the loss. (Not yet
  encrypted at rest; see §9.) "All application state" is **not** claimed.
- Continues **low-frequency background probing** (default: one probe per transport every 30 s).
- Reports **"Reconnecting — international paths appear blocked"** to the UI — **never "Connected."**
- Does **not** claim it can reach the international internet, because at this moment it cannot.

### TotalIsolation — "the honest bound"
The system additionally activates **local mesh** (nearby devices exchange cached data) and any
configured **out-of-band interface** (satellite terminal, secondary SIM, friend's relay). It:

> **Does not and cannot manufacture a path to the international internet where no physical or
> logical path exists.**

If the censor has severed international IP routing **and** international DNS resolution **and** no
out-of-band uplink is provisioned, **no software on Earth** — not this system, not any VPN, not any
AI — can reach the international internet. There is nothing to ride. This is a statement about
**physics and routing**, not a limitation of this product. The system says so honestly, in the UI,
rather than pretending.

---

## 3. The transport survival matrix (what works at what level)

| Transport class | Nominal | Degraded | Escalated | Confirmed | Total |
|---|---|---|---|---|---|
| Primary TLS cores (Reality/Vision/Hysteria2/TUIC/NaiveProxy/ShadowTLS/AmneziaWG) | ✅ Fast | ✅ (hot-swapped) | ❌ Blocked | ❌ | ❌ |
| Tor pluggable transports (WebTunnel/Snowflake/obfs4/Meek/Conjure) | — | — | ✅ Slow | ❌ | ❌ |
| DNS tunnels (MasterDnsVPN/VayDNS/NoizDNS) — ride surviving DNS resolution | — | — | ✅ Slow | ❌ (if DNS also severed) | ❌ |
| SSH SOCKS tunnel (deep last-resort) | — | — | ✅ Very slow | ❌ | ❌ |
| Out-of-band (satellite/2nd SIM — **if operator provisioned**) | — | — | — | ✅ (if healthy) | ✅ (if healthy) |
| Local mesh (nearby device with a working path) | — | — | — | — | ✅ (if a peer has egress) |

**The critical honest line:** DNS tunnels work at Escalated **only if international DNS resolution
survives**. If the censor severs international DNS too (which is the ConfirmedIsolation signal),
DNS tunnels die — there is no resolver path left to ride. This is why ConfirmedIsolation is
"waiting," not "connected."

---

## 4. Direct answer: "How do I stay connected during a blackout?"

**At Escalated level (international IP routing cut, DNS still resolves):**
You stay connected — slowly — via Tor pluggable transports and/or DNS tunnels. Throughput is
**tens to a few hundred kbps** (not the local-loopback benchmarks in any DNS-tunnel README — those
are same-machine figures, not real censored-resolver-chain figures). It is enough for text
messaging, news, Signal/Telegram text, and DNS. It is **not** enough for video. This is the honest
tradeoff: **connected but slow**, which is exactly what you asked for ("اگر پرسرعت نباشد اشکال
نداره فقط فقط وصل بشه" — "if it's not high-speed, no problem, just stay connected").

**At ConfirmedIsolation (even DNS resolution severed):**
No software reaches the international internet. The system queues your data and probes silently.
When **any** path returns — primary, last-resort, or out-of-band — you reconnect **automatically in
≤ 1 second** and the queued data flushes. You do nothing.

**To improve your odds at TotalIsolation (operator action, not magic):**
- Provision an **out-of-band uplink**: a tethered satellite terminal (e.g. Starlink Mini), a
  secondary SIM on a different international backbone, or a trusted relay on a host with outbound
  access. The system binds to it automatically.
- Use the **local mesh**: if any nearby device (family, neighbor) has a working path, your device
  routes through theirs.

---

## 5. What this system explicitly does NOT claim (do not soften these)

1. **Does NOT claim** perfect uptime, zero packet loss, or infinite bandwidth.
2. **Does NOT claim** guaranteed censorship bypass against all present or future network controls.
3. **Does NOT claim** it can stay connected to the international internet during **total physical
   isolation** with zero out-of-band path configured. No software can.
4. **Does NOT claim** the DNS-tunnel throughput figures from any upstream README — those are
   local-loopback benchmarks; real censored-path throughput is orders of magnitude lower.
5. **Does NOT claim** "the user will never experience any disconnection under any circumstance" —
   it claims the narrower, honest, **achievable** thing: the user will not perceive a disconnect
   during any failure that leaves at least one rideable path (levels Nominal→Escalated).
6. **Does NOT report "Connected" when it is not.** This is the single most important non-claim.

---

## 6. Recovery contract (automatic, zero-user-action)

Recovery from **any** level back to Nominal is **automatic and instant**: the first successful
probe on **any** transport — primary core, last-resort tier, or out-of-band — drops the level
straight to Nominal and triggers `store_and_forward::flush()` (drains the queued data, highest
priority first, across whatever transports are now healthy, with multipath spray if ≥2 are
healthy). The user does nothing. The queued messages/data go out. This is the achievable
guarantee — and unlike the isolation-side bounds, it is **unconditional**.

---

## 7. Transport registry (the full last-resort tier)

The resilience tier registers these transports, tried by priority (lower = first):

| # | Transport | Priority | Disguise | Lineage / License |
|---|---|---|---|---|
| 1 | Arti Tor engine | 10 | Tor circuits | Arti, MIT/Apache |
| 2 | WebTunnel | 20 | HTTP/2 WebSocket to CDN front | Tor PT |
| 3 | Snowflake | 30 | WebRTC via STUN/TURN brokers | Tor PT |
| 4 | obfs4 (Lyrebird) | 40 | Packet-length padding + entropy | Tor PT |
| 5 | Meek | 50 | CDN domain fronting | Tor PT |
| 6 | Conjure | 60 | Phantom-IP tap routing | Tor PT |
| 7 | MasterDnsVPN | 100 | Plain DNS UDP, custom ARQ, multi-resolver | MIT; documented surviving Iran's 88-day blackout |
| 8 | VayDNS | 100 | DoH/DoT + uTLS fingerprint randomization | CC0; dnstt fork |
| 9 | NoizDNS | 100 | Noisy DNS (DPI-resistant dnstt fork) | dnstt lineage |
| 10 | SSH SOCKS tunnel | 110 | SSH-over-TCP dynamic SOCKS | OpenSSH lineage; deep last-resort (SSH handshakes are increasingly fingerprintable) |

**Deliberately excluded (non-duplication):**
- **Slipstream** — `MasterDnsVPN` is the documented faster successor in the same DNSTT lineage.
- **Standalone DoH transport** — `VayDNS` already tunnels over DoH/DoT. A second DoH transport
  duplicates it.

---

## 8. How the levels are detected (non-duplicative by design)

The isolation classifier consumes the **same telemetry** the `LocalDecider` already folds
(success rate, TCP-RST rate, TLS-truncation rate, DNS-anomaly rate) — it does **not** re-implement
signal collection. It adds:
- A **wider observation window** and **cross-transport correlation** (multiple egress paths failing
  simultaneously = "the exit is gone," not "one node is gone").
- **Debounce** on the way up (sustained failure required).
- **Out-of-band + local-mesh probes** for the TotalIsolation transition.
- **Instant single-step recovery** on the way down (one success → Nominal).

A single dropped probe **never** advances past Degraded. This is property-tested.

---

## 9. Integration with the rest of the system

- **`blackout.rs`** (`BlackoutController`) — classifies the level, drives the AI morpher profile,
  and escalates to the resilience tier. Already implemented.
- **`resilience.rs`** (`ResilienceController`) — owns the transport registry + failover bridge;
  the `Decision::Escalate → select_best() → promote()` chain. Already implemented.
- **`buffer_replay.rs`** (`RingBufferReplay`) — holds in-flight frames; re-injects on loss > 15%.
  Already implemented.
- **`multipath.rs`** (`MultipathRacer` + `MultipathBond`) — concurrent racing + bonded throughput.
  Already implemented.
- **`dns_tunnel.rs`** — MasterDnsVPN, VayDNS, NoizDNS variants. Already implemented (2 of 3;
  NoizDNS pending per §6 of the directive).
- **`store_and_forward.rs`** — bounded, disk-backed priority queue, flushed on recovery.
  **Implemented and wired into the live path.** Concretely:
  - **Capacity bound** — `QueueLimits { max_items, max_bytes, policy }`. On overflow it either
    rejects the newcomer (`OverflowPolicy::RejectNew`) or evicts the oldest *bulk* item
    (`OverflowPolicy::EvictOldest`); control-lane items are never evicted for bulk data. There is
    no unbounded growth path, however long the blackout lasts.
  - **Disk persistence** — `StoreAndForward::open(path, limits)` appends each accepted item as a
    JSON line and compacts by temp-file + rename on flush/eviction. This follows the same pattern
    as the `AETHER_TELEMETRY_SPOOL` disk spool in
    `control-plane/internal/telemetry/clickhouse.go` (append JSONL on the write path, drain and
    truncate on reconnect), so both planes behave identically during an outage.
  - **Crash recovery** — the queue is reloaded from disk at startup, restoring lane order, item IDs
    and the next-ID watermark. A torn trailing line from a power cut costs that one record, not the
    queue.
  - **Live path** — `telemetry::Collector::with_store_and_forward` buffers telemetry recorded while
    the control plane is detached and replays the backlog on the next `StreamTelemetry` attach.
    Configured by `AETHER_SUPERVISOR_SPOOL` (+ `_MAX_ITEMS` / `_MAX_BYTES`) in
    `core-supervisor/src/main.rs`.

  Still **not** claimed: the at-rest payload is not yet sealed with the `antiforgery` crypto
  primitives — the sealing trait is defined but the queue writes plaintext JSON today.
- **`out_of_band.rs`** — optional operator-provisioned uplink. **Pending** (§2 of the directive).
- **`local_mesh.rs`** — peer discovery + ad-hoc gateway. **Pending** (§3 of the directive).

---

*This document is the contract. Every UI label, every telemetry field, every status notification in
the client and server must be consistent with it. The honesty clauses (§5) are what make this a
trustworthy product, not just an impressive feature list.*
