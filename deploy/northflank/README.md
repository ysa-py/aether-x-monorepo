# Northflank deployment prerequisites

This directory is a **deployment template**, not a proof that a managed
runtime grants every requested Linux capability. The supervisor now performs a
startup preflight and will choose its restricted-container policy when bpffs or
`CAP_BPF`/`CAP_NET_ADMIN` is unavailable. It does not attempt privilege
escalation and it does not report kernel acceleration merely because a manifest
requested it.

## Required mTLS material

The internal control plane is not allowed to run over plaintext outside
loopback. Provision a private CA and the following **read-only** PEM files in
each relevant workload before applying `northflank.yaml`:

| Workload | Files | Certificate requirements |
|---|---|---|
| `core-supervisor` | `core-supervisor.crt`, `core-supervisor.key`, `interservice-ca.crt` | Server certificate SAN contains `core-supervisor`; CA issues the control-plane client certificate. |
| `antiforgery-server` | `antiforgery-server.crt`, `antiforgery-server.key`, `interservice-ca.crt` | Server certificate SAN contains `antiforgery-server`; CA issues the control-plane client certificate. |
| `control-plane` | `control-plane-client.crt`, `control-plane-client.key`, `interservice-ca.crt` | Client certificate chains to the CA trusted by both Rust services. |

The template refers to `/var/run/aether-tls`. Map that directory with the
platform's secret-file facility, owned by the non-root service user and not
writable by the workload. Do **not** commit a CA, private key, generated
certificate, or a base64-encoded private key to this repository.

`antiforgery-server` also requires `AETHER_ANTIFORGERY_SIGNING_KEY`: exactly
32 random bytes represented as 64 hexadecimal characters. It is an Ed25519
seed and must be stable across restarts; rotating it invalidates signatures
issued by the old key unless a verifying-key migration has been planned.

The named server identities must match the SNI settings in the template:

```text
AETHER_SUPERVISOR_SERVER_NAME=core-supervisor
AETHER_ANTIFORGERY_SERVER_NAME=antiforgery-server
```

The processes intentionally fail at startup if a path is missing, empty, or a
non-loopback listener has `AETHER_MTLS_ENABLED=false`. That is a security
control, not a transient condition to bypass.

## Verified standard-client subscriptions

The control plane publishes sing-box, Xray, Clash/Mihomo, Shadowrocket, and
NekoBox-compatible subscriptions only when both of these environment settings
are present:

```text
AETHER_ENABLE_DYNAMIC_SUBS=true
AETHER_NODE_CATALOG_FILE=/read-only/path/to/catalog.json
AETHER_NODE_CATALOG_RELOAD_INTERVAL=30s
```

Mount the catalog through the platform's secret/config-file facility. The
catalog must contain real operator endpoints and is rejected for placeholder
addresses, insecure TLS, unknown JSON fields, missing required credentials,
unsupported transports, or incompatible client allow-lists. Without it, the subscription
endpoint returns `503` rather than handing a user a non-routable configuration.
See `docs/NODE_CATALOG_OPERATIONS.md` for the document contract and rollout
sequence. If per-ISP scoring is required, set `AETHER_TRUSTED_PROXY_CIDRS` only
to operator-controlled ingress ranges; only those peers may supply the
`X-Aether-ISP`, `X-Aether-Region`, and `X-Aether-Country` headers.

## Capability-aware CNI behavior

At every supervisor boot, `RuntimePreflight` reads the current process's
`CapEff`, `/proc/self/mountinfo`, and `/sys/class/net`:

- a veth gets the existing TC-oriented strategy instead of claiming XDP driver
  support;
- missing `CAP_BPF`, `CAP_NET_ADMIN`, or a bpffs mount selects the existing
  userspace-fallback policy without a panic;
- a selected interface can be pinned with `AETHER_CNI_INTERFACE`;
- the selected strategy and all downgrade reasons are emitted in structured
  startup logs.

This detects a capability restriction; it is not evidence that a real eBPF,
AF_PACKET, XDP, or TC program has been attached. Keep the accelerated path in
shadow/canary validation until the actual packet-processing backend and its
privileges have been verified in the target Northflank runtime.

## Minimum pre-production verification

1. Verify each service starts only with its required certificate files mounted.
2. Verify a non-mTLS gRPC connection to `core-supervisor:7070` and
   `antiforgery-server:7071` is rejected.
3. Verify a control-plane certificate issued by any other CA is rejected.
4. Deploy one canary with BPF-related capabilities deliberately removed and
   confirm the supervisor logs `userspace fallback selected` rather than
   crashing or claiming XDP attachment.
5. Run the repository unit/race/static gates, then run a separately authorized
   staging-network test for any live protocol core. Do not treat simulated
   latency or unit-test timing as a production failover SLO.
