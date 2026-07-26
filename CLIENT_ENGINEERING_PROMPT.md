# ENGINEERING PROMPT — Aether-X Client (Multi-Tunnel, Zero-Disconnection, AI Anti-DPI)

**Audience:** An external engineering team or autonomous coding agent commissioned to build the
**Aether-X client application** — the cross-platform VPN/tunnel client that end users in Iran
install. The server side (Rust `core-supervisor` data plane + Go `control-plane`) already exists in
the `aether-x-monorepo` repository. **You are building the client only.** This prompt is a complete,
self-contained specification. It is intentionally honest about what software can and cannot do; the
honesty clauses are non-negotiable and are correctness requirements, not soft preferences.

**Owner's note (Farsi):** «این سند را به یک تیم یا هوش مصنوعی خارجی بدهید تا کلاینت Aether-X را
بسازد — بدون اینکه خودتان کلاینت بنویسید. همهٔ قابلیت‌ها داخل این سند است.»

---

## 0. TL;DR for the builder

Build a **free, open-source, cross-platform** (Android, iOS, Windows, macOS, Linux) tunnel client that:

1. Imports an Aether-X **subscription URL** and auto-generates working configs for **every** protocol
   and transport the server advertises (see §6 matrix).
2. Runs a **multi-tunnel cascade** with **zero-perceived-disconnect**: an in-flight frame replay
   buffer plus mid-stream transport hopping, so a transport swap never tears down the user's socket.
3. Embeds a **local AI anti-DPI engine** that pads packets and perturbs inter-arrival timing to match
   Iranian-domestic whitelisted traffic (Aparat / SHAPARAK), with **JA4/uTLS fingerprint rotation**.
4. Implements the **Blackout Isolation Bounds** contract (§9) — and **never reports "connected" unless
   a real transport has completed a real, recent successful handshake.**
5. Is **fully automatic** (transport selection, healing, recovery) with a **deterministic fallback**
   that works even when the optional ML booster is absent.

---

## 1. Hard invariants (non-negotiable, correctness-grade)

1. **Never lie about connectivity.** No UI element, notification, status flag, or telemetry field may
   assert a "connected"/"online" state unless at least one transport has completed a real handshake
   within a bounded recent window (configurable, default 5 s). Violating this is a **P0 bug**, not a
   UX nit. This single rule governs every other requirement.
2. **Free & open-source only.** Every runtime dependency must be FOSS-licensed (MIT/Apache-2.0/CC0/BSD).
   No paid SDKs, no proprietary DPI-evasion services, no metered APIs in the data path. Subscription
   *billing* is server-side; the client is free for the user.
3. **Zero-error quality bar.** Every PR ships green on the gates in §12. No `unwrap`/`panic` in data
   paths on mobile (crash = the user is offline in a blackout — unacceptable).
4. **Additive & non-duplicative.** The client must consume the server's decisions where the server
   owns the logic (transport catalog, subscription parsing, anti-forgery token verification). The
   client is the *consumer* of `GET /v1/transports`, `GET /sub/{token}`, `GET /v1/me/subscription`,
   etc. — do not re-implement server-side rule engines on the client.
5. **Deterministic-before-ML.** Every "AI"/scoring feature must have a deterministic, non-ML fallback
   that produces a *correct* (even if conservative) decision when the ONNX model is absent or fails to
   load. The deterministic path is the one that ships; ML is a confidence booster on top, never a
   dependency.
6. **Privacy baseline.** No crash analytics, no fingerprinting, no third-party DNS in the data path.
   The only network the client speaks to is the user's configured Aether-X server (and the upstream
   internet through the tunnel). Optional, opt-in, anonymized telemetry only.

---

## 2. Platform targets (all five required)

| Platform | Min version | Notes |
|---|---|---|
| Android | 9 (API 28) | VpnService; foreground notification; battery-aware background probing. |
| iOS / iPadOS | 15 | NetworkExtension (PacketTunnelProvider); survives background limits. |
| Windows | 10 1809+ | TUN via wintun; per-app split tunnelling. |
| macOS | 11 | TUN via utun/System Extension. |
| Linux | kernel 5.6+ (TUN), or namespaces | Desktop + server/headless mode. |

One **shared Rust core** (the tunnel engine, AI morpher, replay buffer, transport adapters) compiled
to each platform; **thin native shells** (Kotlin/Swift/Flutter or Tauri for desktop) provide UI +
platform VPN APIs. Recommend a **Flutter** UI on top of a shared Rust core via FFI (matches the
project's history and gives one UI for all five platforms); Tauri is acceptable for desktop-only.

---

## 3. Reference architecture (client)

```
┌──────────────────────────────────────────────────────────────────┐
│  Native Shell (Flutter/Kotlin/Swift/Tauri) — UI, VPN service     │
│   • Subscriber Portal (RGB glass, RTL/LTR) • One-tap import • QR │
└────────────────────────────┬─────────────────────────────────────┘
                             │ FFI
┌────────────────────────────┴─────────────────────────────────────┐
│  Aether-X Client Core  (Rust, the part you build)                │
│                                                                  │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────────┐  │
│  │ Subscription│  │ Multi-Tunnel │  │ AI Anti-DPI Engine     │  │
│  │ Manager     │  │ Cascade      │  │  • Entropy/IAT morpher │  │
│  │ (parses     │  │  + Buffer    │  │  • JA4/uTLS rotation   │  │
│  │  /sub/{t})  │  │  Replay      │  │  • Domestic profiles   │  │
│  └─────────────┘  └──────────────┘  └────────────────────────┘  │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────────┐  │
│  │ Multipath   │  │ Blackout     │  │ Engine Pool (FOSS)     │  │
│  │ Racer+Bond  │  │ Sentinel     │  │ xray-core / sing-box / │  │
│  │             │  │ (isolation   │  │ amneziawg / naive /    │  │
│  │             │  │  classifier) │  │ arti(tor) / dnstt-forks│  │
│  └─────────────┘  └──────────────┘  └────────────────────────┘  │
└────────────────────────────┬─────────────────────────────────────┘
                             │ tunnel
                        [ censored network ]
```

**Reuse existing FOSS engines; do not re-implement protocols.** Bind `xray-core` (XHTTP/Reality/Vision),
`sing-box` (Hysteria2/TUIC/ShadowTLS/AnyTLS), `amneziawg-go`, `naiveproxy` (`naive`/NaiveProxy),
`arti` (Tor), and the DNS-tunnel binaries (`MasterDnsVPN`, `VayDNS`, `NoizDNS`) as managed
subprocesses (mobile) or in-process libraries where a Rust binding exists. Your value-add is the
**orchestration layer**: cascade, replay, morph, select, heal.

---

## 4. Server integration contract (consume, do not duplicate)

The client talks to one Aether-X server. Implement these consumers exactly:

| Endpoint | Method | Purpose |
|---|---|---|
| `/sub/{subToken}` | GET | Subscription. Content-negotiate on `User-Agent` + `?format=`: returns base64 (v2rayNG/Hiddify), Clash YAML (Clash/Mihomo), or sing-box JSON. **Parse `Subscription-Userinfo` header** (`upload=;download=;total=;expire=`) for live quota/expiry. |
| `/sub/{subToken}/qr.png` | GET | Server-rendered QR PNG of the subscription URL (token never leaves backend). |
| `/v1/me/subscription` | GET | Authenticated live status: `bytes_used/total`, `expires_at`, `plan_type`, `is_live`. Auth via `Authorization: Bearer <jwt>` **or** `?token=<subToken>`. |
| `/v1/transports` | GET | Transport catalog (tcp, kcp, ws, h2, grpc, httpupgrade, xhttp/splithttp, quic, mkcp, …). The client's config builder consumes this — adding a server-side transport = zero client recompile. |
| `/v1/transport-profiles` | GET | Schema-driven profiles (core × network × security) for the admin builder. |
| `/v1/sub/clients?platform=` | GET | One-tap deep-link scheme list (`sing-box://`, `v2rayng://`, `shadowrocket://`, `clash://`, …). Only `confirmed` entries are served; `ai-drafted-pending-review` never reach the user. |

**Client config generation:** prefer handing the raw `/sub/{token}` body to the embedded engine
(sing-box/xray consume Clash/sing-box/base64 natively). Only build client-native config objects when
the engine requires it, and always derive the transport parameters from `/v1/transports`.

---

## 5. Subscription & one-tap onboarding

- **Import methods:** paste subscription URL, scan QR (`/sub/{t}/qr.png` rendered server-side — never
  a third-party QR API), or deep-link (`aetherx://add/<url-encoded-sub>`).
- **Auto-format detection** from `User-Agent` / response `Content-Type` / `?format=`.
- **One-tap "open in app":** for every `confirmed` scheme in `/v1/sub/clients`, render a button that
  fires the deep link with `{{SUB_URL_ENCODED}}`, `{{SUB_URL_BASE64}}`, `{{REMARK}}` substituted.
- **Subscription-Userinfo** drives the live usage ring + expiry countdown in the portal (§10).

---

## 6. Transport & protocol matrix (the "is there still…?" answer — YES to these)

The client must be able to **connect to** every protocol/transport below. Group A = primary (fast);
Group B = last-resort (slow but rides censorship). Honest throughput notes included.

### Group A — Primary protocols × transports (TLS-class, high throughput)

| Protocol | Transports (`streamSettings.network`) | Security | Notes |
|---|---|---|---|
| **VLESS** | tcp, ws, grpc, httpupgrade, **xhttp/splithttp**, h2, mkcp | none / tls / **reality** / **vision** | Default. XHTTP preferred (no `ALPN:http/1.1` fingerprint). |
| **VMess** | tcp, ws, grpc, h2, httpupgrade | tls / none | Legacy compatibility. |
| **Trojan** | tcp, ws, grpc, httpupgrade, xhttp | tls / reality | |
| **Shadowsocks** (2022) | tcp, ws | — | AEAD-2022. |
| **NaiveProxy** (`naive`) | http/2 + quic (HTTP/3) over Chromium network stack | tls | Looks like Chrome traffic; strong DPI evasion. **Required.** |
| **Hysteria2** | quic | tls | High-speed UDP/QUIC; great on lossy links. |
| **TUIC v5** | quic | tls/uuid | |
| **ShadowTLS (v3)** | tcp | tls (wraps another protocol behind a real TLS handshake) | |
| **AmneziaWG / WireGuard** | udp | — | AmneziaWG adds junk-packet obfuscation to defeat WG DPI signatures. |

### Group B — Last-resort tier (carries traffic when Group A is blocked)

| Transport | Wire disguise | Honest throughput |
|---|---|---|
| **Tor PTs**: WebTunnel, Snowflake, obfs4, Meek, Conjure (+ Arti engine) | HTTP/2/WebRTC/various | Low; circuit-bound. |
| **MasterDnsVPN** (MIT) | Plain DNS UDP queries, custom ARQ, multi-resolver | Tens–hundreds kbps through real resolvers. Documented surviving Iran's 88-day blackout. |
| **VayDNS** (CC0, dnstt fork) | **DoH/DoT** + uTLS fingerprint randomization | Same class; better disguise than plain DNS. |
| **NoizDNS** (dnstt-lineage DPI-resistant fork) | Noisy DNS | Distinct from VayDNS; add as a separate registry entry. |
| **SSH SOCKS tunnel** | SSH-over-TCP (dynamic SOCKS) | Deep last-resort only; SSH handshakes are increasingly DPI-fingerprintable. |
| **DoH / DoT (resolver disguise)** | DNS-over-HTTPS / TLS to a resolver | Used as the **carrier** for VayDNS/NoizDNS — **not a separate standalone transport**. |

### Explicitly EXCLUDED (do not add — duplication, per project non-negotiable #2)

- **Slipstream** — `MasterDnsVPN` is the documented faster successor in the same DNSTT lineage. Do not
  add Slipstream alongside it.
- **A standalone DoH/DoT transport variant** — `VayDNS` already tunnels over DoH/DoT. A second DoH
  transport duplicates it. DoH/DoT is a *carrier*, not a peer transport.

So, to the owner's question — *"is there still Multi-Tunneling, DNSTT, NoizDNS, Slipstream, SSH, DoH,
NaiveProxy?"* — **answer: yes to Multi-Tunneling, DNSTT-lineage (MasterDnsVPN/VayDNS/NoizDNS), SSH,
DoH-as-carrier, and NaiveProxy. No to Slipstream and no to standalone-DoH (both deliberately excluded
to avoid duplication).**

---

## 7. Multi-tunnel cascade + zero-disconnection (the core differentiator)

This is what makes a transport swap **invisible** to the user.

### 7.1 Nested encapsulation (cascade)
- **Outer transport** (Intranet mTLS / xhttp) wraps an **inner protocol** (AmneziaWG / ShadowTLS),
  which wraps the payload (onion framing). The censor sees the outer layer; the tunnel rides the inner.
- The cascade is an ordered layer stack; `encapsulate`/`decapsulate` round-trip losslessly.

### 7.2 Mid-stream transport hopping (no socket teardown)
- `hop(new_transport)` swaps which transport carries subsequent frames **without closing the user's
  TCP/QUIC socket** above the cascade. The socket sees continuous data.

### 7.3 Zero-disconnection buffer replay
- An in-memory **ring buffer** holds every **unacknowledged in-flight frame** handed to a transport.
- On a **transport drop** or a **loss spike > 15 %**, immediately **re-inject** all buffered frames
  onto the **winning path** from the Multipath Racer (§8) **within sub-millisecond bounds**.
- `ack(upto_seq)` retires acknowledged frames; bounded capacity with an observable `dropped` counter
  (never unbounded memory). Per-frame `max_hops` caps infinite replay.

### 7.4 User-visible effect
The peer never observes a gap, because re-injection completes before the upper-layer retransmit timer
fires. This is the honest meaning of "zero-perceived-disconnect" — it is **achievable** and is the
primary resilience commitment. (It does **not** mean "stays connected during total physical
isolation" — see §9.)

---

## 8. Multipath racing + bonded aggregation

- **Race:** fire connects across **every** available transport concurrently; adopt the fastest
  established one. Cuts connect latency from O(N serial timeouts) to ~1 round-trip.
- **Bond:** once ≥2 transports are established, spray traffic across all of them (weighted
  round-robin by inverse RTT) → N parallel slow streams ≈ N× throughput on last-resort paths.
- **Collapse property (required):** with exactly one healthy transport, multipath must behave
  byte-for-byte like plain failover (it is a generalization, not a parallel system that can disagree).
- `PathScore { rtt_ms, jitter_ms, loss_rate, handshake_success_rate }` — reuse the server's metric
  shape; do not invent a second metrics format.

---

## 9. Blackout Isolation Bounds (the client-side contract — honesty layer)

The client classifies its own isolation level and **adjusts behavior and UI claims accordingly**.
Transitions are **debounced** (a single failed probe never advances past Degraded).

| Level | What the client claims / does |
|---|---|
| **Nominal** | Primary core reachable. UI: "Connected". |
| **Degraded** | Single-path degradation; hot-swap in progress. UI stays "Connected" if a real handshake is recent. |
| **Escalated** | Last-resort tier (PTs / DNS tunnels) is carrying traffic. UI: "Connected (resilient path)". |
| **ConfirmedIsolation** | All paths failing across a debounce window + multiple egresses. Stop high-frequency retries (battery/footprint), keep low-frequency probing, **queue data locally** (store-and-forward). UI: **"Reconnecting — international paths appear blocked"** (never "Connected"). |
| **TotalIsolation** | Above + no out-of-band interface healthy + no local-mesh peer with egress. UI: **"Offline — no path to the international internet exists right now."** Activate local mesh + any configured out-of-band uplink. |

**The contract the client must enforce (copy this into the UI logic verbatim):**
> No software or AI component in this client may report a "connected" state to the user unless a real
> transport has completed a real successful handshake within a bounded recent window. Reporting
> "connected" when no path exists is a correctness bug, not a UX choice.
>
> **Recovery is automatic and instant:** the first successful probe on *any* transport (primary,
> last-resort, or out-of-band) drops the level straight to Nominal and flushes the queued data —
> zero user action.

**Out-of-band egress** (optional, if the operator provisioned it): a satellite terminal, secondary
SIM, or a friend's relay. The client binds to it automatically when configured. The client must **not**
assume such an interface exists — it is an extension point, not a guarantee.

**Local mesh** (mDNS/BLE): nearby devices exchange cached/queued data, and one device with a working
path acts as an ad-hoc gateway for peers. This provides **no international path by itself** — if zero
peers have egress, the mesh cannot reach the outside world. That is physics, not a bug.

---

## 10. UX & subscriber portal

- **RGB glassmorphism** aesthetic (animated gradient borders, glass-blur panels, neon glow).
- **Bilingual:** Persian (RTL, default) + English (LTR), runtime toggle, persisted.
- **Subscriber portal screen:** circular RGB usage ring (from `Subscription-Userinfo` /
  `/v1/me/subscription`), live expiry countdown (days/hours/min/sec), plan badge (incl. **Enterprise**
  tier), live device list with revoke, **one-tap import** grid, copy-link with toast, **inline + modal
  QR** (server-rendered PNG — never third-party).
- **One-tap import:** one button → modal listing all `confirmed` client schemes; tapping fires the
  deep link. The user must never configure a transport manually.
- **Status truthfulness:** the connection indicator reflects §9 exactly. Never green unless really
  connected.
- **Zero-friction:** auto-start on boot (opt-in), auto-reconnect, no manual "select server" unless
  advanced mode.

---

## 11. Automation & internal AI

- **Auto transport selection:** on connect, race all candidate transports (§8) and adopt the fastest
  healthy one. Re-evaluate on failure signals (RST, TLS truncation, DNS anomaly, loss spike).
- **Auto-heal:** on a detected block, hot-swap protocol/transport, then escalate to the last-resort
  tier, then to out-of-band — all automatic, all behind the buffer-replay so the user feels nothing.
- **AI anti-DPI engine (local, on-device):**
  - **Entropy & packet-size padding** to match Aparat (VOD streaming) / SHAPARAK (banking TLS) /
    generic HTTPS distributions.
  - **Inter-arrival-time (IAT) perturbation** — **Gaussian microsecond jitter** (not uniform) to
    defeat ML-DPI classifiers that fit the IAT *distribution shape*; deterministic per-connection
    seed (reproducible, no `rand` dependency required).
  - **JA4 / TLS fingerprint rotation** via uTLS (Chrome/Firefox/iOS profiles, GREASE injection),
    rotated per handshake.
- **Deterministic fallback:** every AI choice has a rule-based fallback (e.g., if the ONNX traffic
  classifier is missing, fall back to the highest-priority whitelisted domestic profile). The
  deterministic path must ship and be correct; the ONNX booster is layered on top.

---

## 12. Quality gates (zero-error, enforced in CI — all must be real exit 0)

- **Rust core:** `cargo fmt --check`; `cargo clippy --all-targets -- -D warnings`; `cargo test
  --workspace`; `cargo audit`; cross-compile `x86_64/aarch64/armv7` (+ musl). Enforce
  `#![forbid(unsafe_code)]` in the core.
- **Native shells:** platform build + unit tests (Android Gradle, iOS xcodebuild, etc.).
- **UI:** `tsc --noEmit` / `dart analyze` clean; production build succeeds.
- **E2E:** instrumentation/UI tests on at least Android + desktop; a hermetic Playwright-style suite
  for the portal across Chromium/Firefox/WebKit (the project already uses Playwright on the server
  side — match it).
- **Connectivity-truthfulness test (mandatory):** an automated test asserts the UI **cannot** show
  "Connected" when every transport probe is failing. This is the single most important test in the
  suite.

---

## 13. Recommended FOSS stack

- **Core:** Rust. `#![forbid(unsafe_code)]`.
- **Engines (bind, don't rewrite):** `xray-core`, `sing-box`, `amneziawg-go`, `naiveproxy`, `arti`
  (Tor), DNS-tunnel binaries (`MasterDnsVPN`/`VayDNS`/`NoizDNS`) as managed subprocesses.
- **Crypto:** reuse the project's existing `antiforgery` Ed25519 primitives for queue-at-rest signing;
  `ring`/`rustls` for TLS. No second crypto dependency.
- **FEC (optional, evaluate):** `reed-solomon-erasure` crate (run through `cargo audit`).
- **UI:** Flutter (one UI for all 5 platforms) over the Rust core via FFI; or Tauri for desktop.
- **QR:** render server-side (`/sub/{t}/qr.png`) or, if client-side is unavoidable, a pure-Rust QR
  encoder (`qrcode` crate) — **never a third-party QR API**.

---

## 14. Definition of Done

- [ ] All five platforms build and launch; subscription import works on each.
- [ ] Full §6 matrix is connectable; Group A fast, Group B connects under simulated censorship.
- [ ] Multi-tunnel cascade + buffer replay demonstrably avoid socket gaps on transport swap (measured
      < 1 ms re-injection in a test harness).
- [ ] Multipath racing + bonding implemented; collapses to failover with one healthy path.
- [ ] AI anti-DPI: entropy/IAT/JA4 morphing active; deterministic fallback proven when ML absent.
- [ ] Blackout Isolation Bounds: all five levels implemented with debounced transitions; the
      connectivity-truthfulness test passes; recovery-to-Nominal is automatic + flushes queue.
- [ ] UI: RGB glass portal, RTL/LTR, live usage/expiry, one-tap import, QR (no third-party).
- [ ] Every gate in §12 is real exit 0; `cargo audit` and `govulncheck`-equivalent clean.
- [ ] No claim of a guarantee that §9 does not also state.

---

## 15. What you must NOT do

1. **Never report "connected" when no real handshake succeeded** (see §1, §9, §12).
2. **Do not add Slipstream** (duplicates MasterDnsVPN) or a **standalone DoH transport** (duplicates
   VayDNS).
3. **Do not re-implement server-owned logic** on the client — consume the endpoints in §4.
4. **Do not use any third-party QR API, metered DPI service, or proprietary SDK** in the data path.
5. **Do not ship an ML model as a hard dependency** — the deterministic path must work alone.
6. **Do not claim** perfect uptime, zero packet loss, infinite bandwidth, guaranteed bypass of all
   future censorship, or operation during total physical isolation with no out-of-band path. Design
   for *maximum achievable resilience under real constraints* — and for *never lying about
   connectivity*. That is the actual goal.

---

## 16. Acceptance tests (minimum set)

1. Import subscription via URL and via server QR → portal shows live usage + expiry.
2. Under normal network → "Connected" (Nominal); kill the primary transport → user's socket stays up
   (buffer replay), status transitions Degraded→Escalated, never shows a disconnect.
3. Simulate full egress failure (all probes fail) → status becomes "Offline / Reconnecting", **never**
   "Connected"; queue accepts data.
4. Restore one path → status returns to "Connected" automatically within ≤1 s; queued data flushes.
5. Connectivity-truthfulness test: with all probes failing, assert UI status ≠ "Connected" (P0).
6. AI morpher on: outbound packets' size/IAT distribution matches the active domestic profile within
   tolerance; JA4 rotates across handshakes.
7. Multi-tunnel cascade round-trip is lossless; mid-stream hop keeps the socket alive.
8. One-tap import fires the correct deep link for ≥4 client schemes.
9. Gate §12: all green, real exit 0, including `cargo audit` clean.

---

*End of prompt. Hand this entire document to the external builder. Every clause is intentional; the
honesty clauses (§1, §9, §12-test-5) are the ones that make this a trustworthy product rather than a
collection of impressive-sounding features.*
