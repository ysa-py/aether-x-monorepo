# Verified node catalog contract

Standard clients must receive connection details for a real operator-managed
endpoint, never a hostname synthesized from telemetry or an `*.example`
placeholder. Aether-X therefore supports an optional, strict JSON node catalog
loaded from `AETHER_NODE_CATALOG_FILE`.

When no verified catalog is configured, production subscription delivery stays
disabled and returns a truthful `503`. If an operator explicitly enables
`AETHER_ENABLE_DYNAMIC_SUBS=true` but supplies an invalid/unreadable catalog,
the control plane fails startup rather than silently serving stale or invented
configuration. It does **not** fall back to a syntactic but non-routable link.
There is no production placeholder renderer. Unit and E2E tests construct a
verified test catalog with documentation-range endpoint material so the same
catalog renderer is exercised without publishing a real operator endpoint.

## Required document shape

```json
{
  "version": "operator-change-id",
  "nodes": [
    {
      "id": "stable-operator-node-id",
      "address": "operator-controlled-fqdn-or-ip",
      "port": 443,
      "protocol": "vless",
      "uuid": "operator-provisioned-credential",
      "transport": "ws",
      "path": "/operator-reviewed-path",
      "host": "operator-controlled-sni-name",
      "sni": "operator-controlled-sni-name",
      "enabled": true,
      "client_cores": ["sing-box", "nekobox"]
    }
  ]
}
```

The values above are schema labels, **not usable endpoint values**. Supply
real, reviewed credentials through the operator's secret/config mechanism; do
not put private keys in this catalog or commit the catalog to Git.

### Native QUIC node shape

Hysteria2 and TUIC are represented as native protocol outbounds, rather than
being falsely converted into VLESS-over-QUIC. They must be targeted only to
client cores that can import their native schema.

```json
{
  "id": "native-quic-node-id",
  "address": "operator-controlled-fqdn-or-ip",
  "port": 443,
  "protocol": "hysteria2",
  "password": "operator-provisioned-password",
  "transport": "quic",
  "sni": "operator-controlled-sni-name",
  "up_mbps": 100,
  "down_mbps": 200,
  "enabled": true,
  "client_cores": ["sing-box", "clash-meta", "nekobox"]
}
```

For TUIC, use `"protocol": "tuic"`, plus `uuid` and `password`. Optional
`congestion_control` and `udp_relay_mode` default to `bbr` and `native` only
when the node uses those server-side settings. Do not omit an actual required
server-side setting merely to make a client profile look simpler.

## Validation performed before publication

- exactly one JSON document; unknown fields are rejected;
- a non-empty version and at least one uniquely identified node;
- IP or DNS address, non-zero port, supported protocol and transport;
- no `localhost`, `.example`, whitespace, URL/userinfo, or insecure-TLS node;
- credential presence for VLESS/VMess, Trojan/Shadowsocks, Hysteria2, and TUIC;
- protocol-correct rendering: a VLESS `flow` is emitted only when explicitly
  supplied, and Shadowsocks emits its configured cipher in URI, Clash/Mihomo,
  and sing-box forms;
- native QUIC protocols: Hysteria2 requires `transport: "quic"`, a password,
  and positive `up_mbps` / `down_mbps`; TUIC requires `transport: "quic"`, a
  UUID, and a password. Both require an explicit allow-list limited to
  `sing-box`, `clash-meta`, and/or `nekobox`; they are never advertised to
  Xray-core or a client with no compatible native schema;
- pre-publication render gate: each accepted node must generate one non-empty
  share link, one parseable Clash/Mihomo YAML proxy with the expected protocol
  type, and one parseable sing-box JSON outbound with the expected protocol
  type before it can replace the active catalog;
- Shadowsocks is limited to `tcp`/`raw` in this catalog because no plugin
  transport schema is published. A node requiring a plugin is rejected rather
  than silently receiving a configuration with its transport discarded;
- optional allow-list restricted to supported standard clients:
  `sing-box`, `xray-core`, `clash-meta`, `shadowrocket`, and `nekobox`.

The catalog service orders validated nodes deterministically. It intentionally
does not use the repository's simulated ClickHouse score reader to reorder
production clients. A real telemetry score reader must be wired and evaluated
in shadow mode before it is allowed to influence this baseline.

`DynamicOptimizerService` is retained only as an advisory compatibility seam:
it can evaluate aggregate score availability but intentionally fails closed when
asked to publish a subscription. It has no verified endpoint material and must
not synthesize an address from a telemetry node ID. Production publication uses
`TelemetryCatalogSubscriptionService`, which can reorder only entries already
present in the verified catalog.

## Rollout sequence

1. Create the catalog outside Git with real endpoint values.
2. Mount it read-only into the control-plane workload.
3. Set `AETHER_NODE_CATALOG_FILE` to that absolute path, set
   `AETHER_ENABLE_DYNAMIC_SUBS=true`, and choose an
   `AETHER_NODE_CATALOG_RELOAD_INTERVAL` of at least one second (30 seconds is
   the default).
4. Verify each target client receives only allow-listed nodes and can parse its
   chosen subscription format in an authorized staging environment. For a
   Shadowsocks entry, verify the configured cipher (or the documented default
   `chacha20-ietf-poly1305`) is accepted by that client.
5. Rotate catalog version/change ID through the controlled deployment path.

## Atomic hot reload

The control plane fingerprints the catalog content and polls at the configured
interval. A complete replacement is parsed and validated before it replaces the
in-memory catalog. During a malformed, partial, deleted, or unreadable update,
the last known-good catalog continues serving existing standard clients; the
rejection counter and last error are retained in reload status. This avoids
turning a bad operator edit into an immediate mass subscription outage.

## Optional aggregate telemetry ordering

The deterministic catalog order is the default. Only after ClickHouse receives
real, per-node aggregates may an operator enable:

```text
AETHER_ENABLE_TELEMETRY_SCORING=true
```

This requires both subscription delivery and `AETHER_CLICKHOUSE_DSN`. The
reader queries a bounded ten-minute window, requires at least 20 observations
per `(node_id, protocol)`, and uses only aggregate RTT, loss, RST count, and
throughput to reorder nodes already present in the verified catalog. It never
creates an endpoint from telemetry.

The server does not guess a client's ISP or region from an address. To provide
per-ISP ordering, configure `AETHER_TRUSTED_PROXY_CIDRS` with only
operator-controlled ingress networks. Only a request received from those CIDRs
may supply normalized `X-Aether-ISP`, `X-Aether-Region`, and
`X-Aether-Country` headers; identical headers from a client are ignored. Without
this boundary the reader queries all aggregate evidence rather than fabricating
a carrier cohort. Aggregate scores are cached for 30 seconds; during a short
ClickHouse outage, a circuit breaker permits a bounded stale snapshot for up to
five minutes and then falls back to deterministic catalog order rather than
blocking subscription delivery. The fallback is reported in the reason field.

This path requires no custom client: it emits standard base64 share links,
Clash/Mihomo YAML, and sing-box JSON using the existing renderer.
