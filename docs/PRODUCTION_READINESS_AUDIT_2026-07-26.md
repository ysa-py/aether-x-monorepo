# Production-readiness audit — 2026-07-26

This is an engineering audit, not marketing material. It distinguishes what
Aether-X currently executes from designs, simulations, and planned work so an
operator does not risk users on an unverified claim.

## Findings addressed in this change

### 1. Internal gRPC had a security/deployment contradiction — **remediated**

Before this change, the supervisor refused a plaintext non-loopback listener,
while the Northflank template configured exactly that. The mTLS flag only
logged a warning and did not configure tonic. The anti-forgery service and its
client were also plaintext on named service addresses.

The current implementation now:

- requires certificate, key, and client-CA PEM files before a non-loopback
  supervisor or anti-forgery listener starts;
- configures tonic `ServerTlsConfig` with an identity and `client_ca_root`, so
  a client certificate is required and verified before RPC dispatch;
- rejects a remote plaintext dial in both Go gRPC clients before it creates a
  connection;
- validates all required client PEM paths in `config.FromEnv`;
- uses a stable `AETHER_ANTIFORGERY_SIGNING_KEY` seed for subscription
  signatures outside explicit `AETHER_DEV=true` mode; and
- makes the Northflank template mTLS-first and documents the key/certificate
  provisioning prerequisite.

This is covered by unit tests for path/material validation and plaintext
non-loopback rejection. A live TLS handshake test still requires a compiler
and test certificates in CI/staging.

### 2. CNI/eBPF capability loss was only a mock — **partially remediated**

`runtime_preflight.rs` now inspects the running container's `CapEff`, actual
`/proc/self/mountinfo`, and actual network-interface directory. It makes a
side-effect-free strategy decision at supervisor startup:

| Observation | Result |
|---|---|
| veth + bpffs + `CAP_BPF` and `CAP_NET_ADMIN` | existing TC-oriented strategy |
| non-veth + kernel requirements | existing CNI policy strategy |
| no bpffs, denied capability, unavailable `/proc`, or no interface | existing userspace fallback policy |

The decision is logged along with reasons. Restriction is a non-fatal state;
there is no capability escalation, mount attempt, panic, or pretend XDP driver
claim for a veth.

**Important:** this is accurate capability detection and safe degradation. The
repository still needs a real, audited AF_PACKET/TC/eBPF execution backend
before any operational claim that packets are being transformed in the
selected path. A timing simulator is not evidence of kernel attachment.

### 3. AI promotion lacked a measurable safety gate — **remediated**

`ModelRegistry` already required signed artifacts and a seven-day / 10,000
prediction shadow period, but it did not require evidence that a model improved
on the deterministic FSM. It also let any model kind acquire routing authority
and retained an unbounded prediction log.

The registry now keeps a bounded shadow audit ring and accepts only aggregate,
paired canary/replay outcomes—never user identifiers, destinations, or raw
traffic. Promotion additionally requires all of the following:

- a signed adaptive-fallback artifact in shadow mode for at least seven days;
- 10,000 shadow predictions;
- 1,000 paired outcomes using the same declared success criterion;
- at least a 1 percentage-point success advantage over the FSM; and
- no net paired regression (`model-only successes >= fsm-only successes`).

Classifiers and fingerprint-drift models stay advisory even when their shadow
evidence is good. A model that does not pass every gate cannot change routing;
rollback remains FSM-first and returns an error for an unknown model.

### 4. The deployment advertised ports no process owned — **remediated**

The previous Northflank template published UDP/TCP proxy and metrics ports
that the current binaries do not bind. That guarantees failed probes and is
not a real client capability. The template now exposes only the implemented
internal gRPC listeners and the control plane's actual HTTP listener.

No source module was deleted. The proxy-ingress entries are deliberately absent
until a real supervised core binds them, has an authenticated readiness check,
and passes an authorized staging test. Publishing an unbound port would make a
claim of client compatibility that the code cannot meet.

### 5. Standard-client subscriptions used fabricated endpoints — **remediated**

The old fallback renderer could emit a syntactically valid subscription using
an `aether-x.example` address or fabricate a hostname from a telemetry node ID.
That does not help sing-box, Xray, Clash Meta, Shadowrocket, or Nekobox: it
only moves the failure to the client.

A strict, operator-managed `NodeCatalog` now validates real endpoint material
before rendering standard base64 links, Clash/Mihomo YAML, or sing-box JSON.
Production delivery stays disabled without a catalog or with no node compatible
with the requesting client. The test-only placeholder renderer is explicitly
blocked in a normal `api.Server`. Once enabled, a content-fingerprinted reload
loop validates a complete replacement before atomically swapping it; invalid or
partial updates retain the last known-good catalog. A separate opt-in production
ClickHouse reader can reorder only verified catalog entries from aggregate
per-node RTT, loss, RST, and throughput evidence; reader failure returns to the
deterministic catalog order. It does not fabricate an ISP/region label when no
trusted edge resolver exists; an allow-listed ingress CIDR is required before
ISP/region headers are accepted. See `docs/NODE_CATALOG_OPERATIONS.md`.

### 6. Session mutation could race migration state — **remediated in the manager layer**

Heartbeat, close, and migration paths now share bounded lock striping per
session. This prevents a concurrent heartbeat from overwriting a new node ID
with stale cached state during a migration. Byte counters are monotonic,
failover selection is stable and excludes the current node, and the in-memory
store used by tests/dev is protected by an RWMutex for `go test -race`. The
control-plane now initializes a migrated PostgreSQL session store in production
and exposes its aggregate state through an admin-only endpoint; development may
explicitly fall back to memory when the local data layer is absent.

This does **not** claim transparent TCP migration across independent endpoints;
the existing Blackout Bounds remain authoritative. It makes state bookkeeping
truthful and concurrency-safe for transports that actually support migration.

### 7. External core ownership was a stub — **partially remediated**

The `real_cores` feature previously spawned an Xray command without retaining
its child, passing the supplied configuration, checking a listener, or stopping
it. A managed subprocess adapter now exists for Xray and sing-box. It is
explicitly opt-in at build and runtime, accepts only an absolute reviewed config
path, retains the child for restart/termination, and reports `Degraded` when
its declared loopback listener cannot be reached.

The default image still intentionally contains no external core binary and the
generic adapter cannot implement a core-native drain or transparent TCP session
migration. Those remain explicit prerequisites for publishing proxy ingress.
See `docs/EXTERNAL_CORE_OPERATIONS.md`.

## Material limits that remain

The repository is a Phase-0 foundation, not a system that can honestly promise
“zero error”, “invisibility”, or continuous international connectivity:

1. Several high-risk modules explicitly identify themselves as mocks or
   simulators, including XDP, ML-KEM/HPKE behavior, ZKP proofs, edge deployment
   providers, and some transport handshakes. They must not be described as
   production cryptography or live network defense until replaced with audited
   implementations.
2. A full international network isolation or physical upstream outage is a hard
   connectivity bound. Software can preserve local session state, buffer
   allowed data, expose truthful status, and retry conservatively; it cannot
   create a route where no reachable international path exists.
3. TCP streams cannot generally be moved transparently between independent
   endpoints by an external supervisor after a path failure. QUIC supports
   connection migration when both peers and path validation support it; existing
   TCP applications require application/proxy protocol support or reconnect
   semantics. Treat “zero perceived disconnect” as an SLO to measure, not a
   guarantee.
4. No packet-size/IAT classifier score is valid without a consented, labeled,
   versioned dataset and a held-out evaluation procedure. A claim such as
   99.9% indistinguishability requires a defined threat model, a reproducible
   benchmark, and independent review.
5. Northflank capability/mount availability is platform- and plan-dependent.
   The requested capability in a YAML file is not proof that the runtime grants
   it. Use the startup preflight and a canary deployment as the source of truth.

## Highest-value next increments (additive, non-duplicative)

1. **Real core adapters and readiness contracts.** Replace mock core adapters
   with supervised, version-pinned sing-box/xray processes; expose readiness
   only after an authenticated local health check. Do not expose UDP/TCP ports
   until the process that owns them actually binds them.
2. **Authenticated telemetry control loop.** Wire a typed health/telemetry
   event to a policy proposal queue with a deterministic fallback, shadow-mode
   promotion, rate limits, rollback, and audit events. Keep model decisions
   advisory until they meet a predeclared statistical gate.
3. **Capability canary.** Run a privileged and intentionally restricted
   staging job; assert the exact selected CNI mode, check that no privileged
   attach is attempted in fallback, and retain only non-sensitive metrics.
4. **Real mTLS integration test.** Generate an ephemeral test CA in CI,
   exercise accepted trusted client, rejected anonymous client, rejected
   untrusted client, and SNI mismatch for both Rust services.
5. **Session-continuity SLO test.** Use only transports that actually support
   migration, inject loss/rebinding in an authorized lab, measure success rate,
   reconnect time, and data semantics. Publish p50/p95/p99 rather than a
   universal no-disconnect promise.
6. **Privacy review.** Maintain opt-in measurement, k-anonymity, and
   differential privacy. Do not collect raw traffic, destination history, or
   personal identifiers to tune an anti-DPI model.

## Verification record for this workspace

The authoring environment used for this audit has no executable Rust, Go,
Docker, Helm, buf, or protoc toolchain on `PATH`. Therefore no build, race,
container, kernel, packet, or external-network test is claimed as run here.
Static syntax/structure checks that do not require those toolchains are the
only local verification that can be reported. The required full gate remains:

```bash
cd aether-x-monorepo
make ci
```

Run it in a controlled CI/staging environment with Rust, Go, protoc, Docker,
Helm, and test certificates available. Treat a green unit suite as necessary
but not sufficient for a live-network deployment.
