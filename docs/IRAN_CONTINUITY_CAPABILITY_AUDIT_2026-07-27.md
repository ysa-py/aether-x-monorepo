# Iran anti-DPI and blackout-continuity capability audit — 2026-07-27

**Scope.** This is a source-and-test-path audit of the checkout at
`8d7f18b13c0bd1b7a5cb15ed19d69bbf7d929876`, plus the honesty-only corrections in
this change. It covers `ai_dpi.rs`, `blackout.rs`, `domestic_intel.rs`,
`dpi_forecast.rs`, `local_mesh.rs`, `out_of_band.rs`, the Go transport registry,
and the standard-client subscription publisher.

It does **not** assert that an Iranian network, a censor, a proxy endpoint, or a
third-party client was tested. A green repository CI run proves the checked code
and its hermetic tests, not reachability through a real network.

## Reading this audit

| Label | Meaning |
| --- | --- |
| **Implemented model** | Deterministic library logic whose behaviour is covered by repository tests. It may still have no I/O or production call path. |
| **Runtime-wired** | The production executable constructs and invokes it under a documented configuration. This is still not an operational connectivity claim. |
| **Mock/simulation** | Inputs, health, handshakes, timing, or transport state are represented in memory rather than obtained from an external system. |
| **Not proven** | No pinned external binary/client test and no authorized live-network test exists in this repository. Do not advertise it as working. |

## Executive result

1. The six requested Rust modules are compiled because `core-supervisor/src/lib.rs:41,46,56-57,72,79` exports them. That is **not** runtime wiring.
2. **Follow-up update — live signals:** when an operator supplies
   `AETHER_LIVE_SIGNAL_CONFIG`, the supervisor now constructs and spawns
   `LiveSignalSource`, which uses actual configured TCP/TLS/UDP DNS probes and
   calls `blackout::classify`. See
   `docs/LIVE_CENSORSHIP_SIGNAL_OPERATIONS.md`. It still does not construct
   `TrafficMorpher`, `BlackoutController`, `DpiForecaster`, `DomesticIntel`,
   `LocalMesh`, or `EgressRegistry`, and the new classifier output has no
   transport-actuation side effect.
3. `store_and_forward` is genuinely wired for **supervisor telemetry**: the queue
   is created from the environment and passed to `Collector` at
   `core-supervisor/src/main.rs:95-100`. It is not a store-and-forward path for
   arbitrary subscriber traffic.
4. The subscription publisher is a real Go HTTP/catalog-rendering path when an
   operator enables it and supplies a valid catalog. It is disabled in the
   shipped Northflank manifest (`deploy/northflank/northflank.yaml:306-312`).
   A later CI fixture validates one generated VLESS-over-WebSocket config with
   pinned sing-box and Mihomo parser binaries; app import and connection remain
   separate, unproven layers.
5. **Two pinned parser binaries are now CI-proven for one generated fixture:**
   sing-box `v1.13.14` accepts the emitted JSON and Mihomo `v1.19.29` accepts
   the emitted YAML in CI run `30266875057`. This is parser acceptance only;
   it does not prove an app import, a proxy connection, or censorship
   resistance. Xray-family VLESS remains structural URI validation because
   xray-core has no CLI subscription-URI importer.
6. At full international isolation, software cannot create a missing external
   route. The only honest service level is local/domestic exchange or queued
   work *if* a separately deployed local/OOB transport exists; it is not
   international Internet continuity.

## Requested continuity modules: real code vs. missing execution

| Area | Implemented model | Runtime wiring | Mock/simulation / missing operational component | Verdict |
| --- | --- | --- | --- | --- |
| `ai_dpi.rs` | Profile selection, target-length calculation, deterministic jitter, and a candidate extension/cipher ordering (`core-supervisor/src/ai_dpi.rs:78-202,255-272`). | Used by `BlackoutController` and `AdvancedIntegration` as in-process state (`blackout.rs:167-225`, `advanced_integration.rs:129-160`); neither is created in `main.rs`. | No packet writer, scheduler, TLS ClientHello builder, Xray/sing-box config mutation, or packet capture. Unit tests only test numbers/order (`ai_dpi.rs:274-362`). | **Implemented model; not a traffic morpher.** |
| `blackout.rs` | Pure classification from rates/booleans (`blackout.rs:75-121`) and an in-memory escalation decision (`blackout.rs:204-260`). The full-isolation output correctly lists no international paths (`blackout.rs:127-139`). | `LiveSignalSource` is conditionally started by `main.rs` from `AETHER_LIVE_SIGNAL_CONFIG` and calls `blackout::classify` after a bounded window. `BlackoutController`/`EnterpriseEngine` still are not constructed by `main.rs`. | The source measures actual configured TCP/TLS/UDP DNS outcomes, but a socket error cannot attribute a censor; deployment anchors, packet capture, and an authorized carrier drill remain required. The “fast” race/bond still operates on the mock `Transport` abstraction. | **Classifier now has an optional real probe input; no real transport protection/actuation.** |
| `domestic_intel.rs` | TTL-based local ranking, per-peer caps, and permutation-only ordering (`domestic_intel.rs:62-79,200-310,362-408`). The tests cover stale/rejected observations and preserve candidates (`domestic_intel.rs:523-542,598-735`). | Only held by `AdvancedIntegration` (`advanced_integration.rs:49-53,79-82`), which is not constructed in `main.rs`. | No peer discovery, serialization, signature/authentication, replay protection, network send/receive, or binding to `MeshTransport`. `Observation` contains `Instant`, not a wire protocol. | **Implemented in-memory ranker; not gossip or a domestic network.** |
| `dpi_forecast.rs` | Bounded EWMA/trend/hazard calculation (`dpi_forecast.rs:202-380`) with synthetic-sequence tests (`dpi_forecast.rs:415-635`). | `SeamlessController` consumes the `Transport` model (`seamless.rs:169-220`), but neither controller is constructed by the executable. | No telemetry-to-`HealthSample` bridge, no trained/ONNX model, no standby socket creation outside the simulated `Transport::connect`, and no real pre-warm test. | **Implemented deterministic forecast model; not a deployed predictive system.** |
| `local_mesh.rs` | Thread-safe peer list, gateway filter, and a `MeshTransport` *trait* (`local_mesh.rs:23-99`). | No non-test `LocalMesh::new` use in the crate. | No BLE, Wi-Fi Direct, mDNS, WebRTC, WireGuard, routing, peer authentication, relay data plane, or implementation of `MeshTransport`. | **Registry/trait only; orphaned.** |
| `out_of_band.rs` | `ExternalEgressInterface` trait and registry iteration (`out_of_band.rs:16-23,76-118`). | No `EgressRegistry::new` or `ProxyEgress::new` use outside tests. | `ProxyEgress::probe` reads an `AtomicBool`; the source explicitly says a real `TcpStream::connect` is only a future production implementation (`out_of_band.rs:28-34,65-73`). No satellite/SIM/relay binding or configuration path exists. | **Mock health model; not OOB egress.** |

### Why the blackout path is simulated even though it has tests

`BlackoutController::react_fast` calls `MultipathRacer::race` and
`MultipathBond::from_available` (`core-supervisor/src/blackout.rs:233-250`).
Those functions only see `TransportConnection` records. The default
`Transport::connect` returns `established: self.is_available()` and a fixed
50 ms RTT (`core-supervisor/src/tor.rs:18-44`). The five built-in pluggable
transport structs are constructed with `available: true` without a network
probe (`tor.rs:51-80,82-109,111-138,140-167,169-196`). The DNS and SSH models
are explicit `AtomicBool` state models (`dns_tunnel.rs:55-88,109-138` and
`ssh_tunnel.rs:12-75`).

Therefore the tests prove selection logic, not Tor/WebTunnel/Snowflake/obfs4,
DNS tunnelling, SSH, multipath throughput, or a blackout escape. In particular,
`throughput_multiplier` is a weighted scheduling estimate
(`multipath.rs:138-219`), not measured aggregate throughput and not a packet
bonding implementation.

`AdvancedIntegration` does not close that gap. At the hard bound it enqueues the
literal marker `b"queue-reserved"` (`advanced_integration.rs:165-175`), not
subscriber frames. Its “connected” helper consults an in-memory
`FailoverBridge` handle (`advanced_integration.rs:318-338`; `resilience.rs:118-130`),
not a subscriber data-plane round trip.

## Transport registry: what it is and is not

### Real and wired

The Go catalog is an actual data registry:

- `control-plane/internal/transport/transport.go:41-77` returns/looks up the
  11 declared transport IDs; `transport.go:87-97` declares six protocol IDs.
- `GET /v1/transports` exposes the registry through
  `control-plane/internal/api/admin_config.go:13-28` and is mounted as an
  admin route at `admin_config.go:159-164`.
- `ValidateNodeConfig` rejects unsupported IDs and malformed catalog material
  (`control-plane/internal/subendpoint/config_builder.go:59-105`).
- The registry has unit tests for catalog membership and sorting
  (`control-plane/internal/transport/transport_test.go:7-85`).

That establishes an **admin/config vocabulary**, not a transport implementation.

### Not an implementation or compatibility contract

- `transport.Profiles()` is an admin form schema only
  (`control-plane/internal/transport/profiles.go:20-111`). It does not configure
  a core process.
- The supervisor accepts `ProtocolSpec.opaque_config` as opaque data
  (`core-supervisor/src/protocol.rs:96-115`). Its managed adapter requires an
  already-mounted native config file, rather than translating registry fields
  into Xray/sing-box config (`core-supervisor/src/core_adapters.rs:236-349`).
- The real-core adapter is opt-in: default adapters are `MockCore` for all
  kinds (`core_adapters.rs:48-73`), `real_cores` is off by default
  (`core-supervisor/Cargo.toml:58-62`), and the published supervisor Dockerfile
  neither enables that feature nor includes Xray or sing-box
  (`deploy/docker/core-supervisor.Dockerfile:31-41`).
- Even when opt-in, health is only an executable-process check plus a loopback
  TCP listener probe (`core_adapters.rs:448-495`). It does not prove a client
  handshake, forwarding, DPI resistance, a remote path, drain, or migration.

The catalog also has a concrete renderer mismatch that prevents a broad support
claim: `singboxTransport` emits a `kcp` map while its own source states
“sing-box has no mkcp transport for vless”
(`config_builder.go:556-587`, especially `581-583`). `ValidateNodeConfig` does
not reject that VLESS+kcp+sing-box combination. This is a catalog/UI generation
path, not evidence of a valid sing-box config.

## Standard subscription output and the “no client of my own” answer

### What is actually emitted

With `AETHER_ENABLE_DYNAMIC_SUBS=true` plus a validated
`AETHER_NODE_CATALOG_FILE`, the control-plane main creates a reloading verified
catalog service (`control-plane/cmd/aether-control/main.go:135-189`) and passes
it as `DynamicSubs` to the HTTP server (`main.go:264-285`). The config parser
requires a catalog path and rejects telemetry scoring without delivery
(`control-plane/internal/config/config.go:143-159`). The public route is
`GET /sub/{subToken}` (`control-plane/internal/api/sub_onboarding.go:14-19`),
and it fails with `503` if the store/catalog is absent
(`sub_onboarding.go:31-42,58-81`). This is correct fail-closed behaviour.

The renderer chooses exactly three body forms:

| Requested/negotiated form | Repository output | Source proof |
| --- | --- | --- |
| `base64` (also default fallback) | Base64-encoded newline-separated `vless://`, `vmess://`, `trojan://`, `ss://`, `hysteria2://`, or `tuic://` links, depending on catalog protocol. | `config_builder.go:108-130,329-351`; UA fallback at `endpoint.go:53-67`. |
| `clash` | Hand-built YAML with `proxies`, proxy-groups, and rules. | `config_builder.go:329-393,396-492`. |
| `singbox` | Hand-built JSON with an `outbounds` array. | `config_builder.go:494-610`. |

The service validates its own serialization, not a third-party parser: catalog
admission only decodes the generated YAML with `yaml.v3` and the generated JSON
with Go's `encoding/json` (`control-plane/internal/subendpoint/catalog.go:255-293`).
The HTTP E2E test uses `httptest`, `MemStore`, and a TEST-NET endpoint
(`control-plane/internal/api/e2e_integration_test.go:20-27,42-71`); it checks
that base64 decodes, YAML contains `proxies:`, and JSON contains `outbounds`
(`e2e_integration_test.go:137-235`). None of those tests launches a standard
client or establishes a proxy session.

### Exact compatibility status today

CI run [30266875057](https://github.com/ysa-py/aether-x-monorepo/actions/runs/30266875057)
executes `TestExternalClientParsersAcceptGeneratedSubscriptionConfigs` inside
the existing Go CI gate. The test downloads pinned upstream release assets,
verifies their GitHub-published SHA-256 values, writes bytes generated directly
by `BuildSubscriptionBodyEx` / `BuildProxyLink`, and invokes each native parser.
The narrow result is documented in `docs/CLIENT_COMPATIBILITY_CI.md`.

| Product/core | Current proof | Precise boundary |
| --- | --- | --- |
| **sing-box `v1.13.14`** | **CI parser-proven**: `sing-box check -c` accepted generated VLESS-over-WebSocket JSON. | Does not prove a connection, an app import, server compatibility, or other protocols/transports. |
| **Mihomo `v1.19.29`** | **CI parser-proven**: `mihomo -t -f` accepted generated VLESS-over-WebSocket YAML. | This is Mihomo/Clash Meta parser acceptance only—not FlClash, ClashX, or a live proxy session. |
| **Xray-family VLESS URI** | **Structurally serialized**: CI validates the generated URI scheme, UUID, endpoint, TLS, WebSocket, SNI, host, ALPN, path, and remark fields. | Xray-core has no CLI which imports a subscription URI. `xray run -test` validates native JSON, not this URI, so it is not parser- or connection-proven. |
| **NekoBox, Shadowrocket, v2rayNG, Hiddify, Karing, FlClash/ClashX, v2RayTun, Streisand** | **Structurally serialized / launcher metadata only.** | No pinned application import or connection test exists. |

The client manifest records sing-box as `ci-parser-validated`; the combined
Clash/Mihomo/FlClash entry remains `verify-before-ship` because this CI proof
covers Mihomo only. A standard client becomes supported for a published profile
only after the pinned client/version and exact profile pass the appropriate
parser and authorized connection tests.

## Blackout Isolation Bounds: operational answer

`blackout::classify` has four deterministic labels: Normal, DPI blocking,
routing severed, and full isolation (`core-supervisor/src/blackout.rs:34-113`).
Those labels are useful state-machine vocabulary, but their inputs are supplied
by the caller; they are not measured by the running supervisor.

| Observed condition | What can honestly be said now | What Aether-X currently executes |
| --- | --- | --- |
| International route available, censorship symptoms supplied | A model can recommend a profile name/ordering. | No live morphing or core hot-swap from `main.rs`. |
| International IP route lost but DNS allegedly remains | A real, independently deployed tunnel *might* be a candidate; it must prove its own handshake. | Only selection among in-memory transport states; DNS-tunnel/SSH subprocesses and probes are absent. |
| International route and international DNS unavailable | No software-only international path is available. Domestic exchange, OOB equipment, or buffering may still be useful, but none is Internet continuity. | The model reports an empty surviving-path list. No local mesh/OOB data plane is started. |
| A separate satellite/secondary SIM/trusted relay exists | That equipment can be an independent path only after a concrete adapter and end-to-end test exist. | `ExternalEgressInterface` is available as an extension point; `ProxyEgress` is an `AtomicBool` test model. |

There is no honest “zero error”, “guaranteed high speed”, or “users never notice”
claim under a national/global blackout. Reliability engineering can reduce
outage probability and preserve queued local work, but cannot overcome a
physical absence of a permitted external path.

## Required proof gates before enabling or advertising a capability

No new continuity path should be wired merely because a model exists. The
minimum merge/release evidence should be:

1. **Pinned core/profile matrix.** Build an image containing pinned Xray,
   sing-box, and Mihomo versions; render each advertised catalog entry; invoke
   the native parser/config check; and reject unsupported combinations (for
   example VLESS+mKCP for sing-box) before a catalog can publish them.
2. **Pinned external-client matrix.** For every named application and version,
   fetch the exact subscription form over HTTPS in an authorized lab, import it,
   and assert both parser acceptance and a controlled egress request. Store the
   client version, artifact digest, profile fixture, logs, and result as CI
   artifacts. A serializer unit test is not a substitute.
3. **Real data-plane actuation.** Attach shaping only at a reviewed packet/core
   boundary. Verify by packet capture that padding/timing/TLS configuration is
   actually applied, and prove that a failed policy reverts safely. Do not
   pretend that `TrafficMorpher` output mutated a flow before this exists.
4. **Measured failover semantics.** Use controlled endpoints and fault injection
   to measure reconnect duration, request semantics, loss/duplication, and
   p50/p95/p99—not a universal “seamless” promise. Test real transport
   handshakes, not `AtomicBool` availability.
5. **Domestic mesh security/data plane.** Implement an authenticated peer
   identity, replay-resistant signed wire messages, discovery/transport
   implementations, relay authorization, and quota/abuse controls. Test
   poisoning and partition recovery with real peers.
6. **OOB deployment contract.** Make the interface explicit for operator-owned
   equipment, perform a bounded real health/egress test, and make the system
   fail closed when it is absent. Do not infer OOB health from a mutable flag.
7. **Authorized blackout drill.** In a lawful isolated test environment,
   independently remove international IP and DNS paths and record exactly what
   still works. The full-isolation result must remain “no international path”.
8. **AI safety and privacy.** Use consented, aggregate telemetry; make learned
   models advisory/shadowed first; compare against deterministic fallback; set a
   rollback condition; and never train on raw browsing histories or use an
   “AI” label as a connectivity guarantee.

Only a change set with the relevant test harness, a green CI run, and a
reviewable staging result may move a row in this audit from “not proven” to a
narrowly stated, versioned capability. This audit itself intentionally adds no
new networking, bypass, or client-support claim.

## فارسی — پاسخ عملیاتی کوتاه

- به‌روزرسانی بعدی: با `AETHER_LIVE_SIGNAL_CONFIG`، منبع `LiveSignalSource`
  واقعاً TCP/TLS/UDP DNS را به anchorهای کنترل‌شده probe می‌کند و خروجی را به
  `blackout::classify` می‌دهد؛ اما فقط اندازه‌گیری/log است و هنوز مسیر انتقال
  یا تضمین اتصال نیست. سایر قابلیت‌های نام‌برده عمدتاً **مدل و شبیه‌سازی
  تستی** هستند و نباید ضد-DPI عملیاتی یا تضمین‌کنندهٔ اتصال معرفی شوند.
- خروجی subscription سه قالب دارد: لینک‌های Base64، YAML برای خانوادهٔ
  Clash/Mihomo و JSON برای sing-box. اما در مخزن هیچ تست CI که خودِ sing-box،
  Xray/Mihomo یا اپ‌های v2rayNG/Hiddify/NekoBox/Shadowrocket را اجرا و اتصال
  واقعی را تأیید کند وجود ندارد. بنابراین امروز **هیچ نام کلاینتی تأییدشده
  نیست**؛ ساخت کلاینت اختصاصی لازم نیست، ولی هر کلاینت باید با نسخهٔ مشخص در
  آزمایش مجاز import و اتصال واقعی را پاس کند.
- در قطع کامل مسیر بین‌المللی و DNS بین‌المللی، نرم‌افزار نمی‌تواند اینترنت
  خارجی ایجاد کند. راهِ درست: ذخیره/ارسال بعدیِ دادهٔ محلی، ارتباط داخلی، یا
  تجهیز مستقل واقعی مانند مسیر دوم/SIM دوم/ماهواره—همراه با تست واقعی و مجاز.
  قول «صفر خطا»، «کاربر هرگز قطعی حس نمی‌کند» یا «اتصال تضمینی در blackout
  کامل» از نظر فنی صادقانه نیست.
- اولویت مهندسی پیشنهادی: (۱) ماتریس parser واقعی core/client، (۲) مسیر
  واقعی اعمال shaping و اندازه‌گیری packet capture، (۳) failover اندازه‌گیری
  شده، (۴) mesh امن واقعی، و (۵) OOB واقعی. هر مورد فقط پس از PR با CI سبز و
  آزمایش staging مجاز باید قابل عرضه نامیده شود.
