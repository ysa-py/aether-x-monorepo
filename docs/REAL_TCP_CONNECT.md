# Real TCP connection path

## Scope

`core-supervisor/src/tor.rs` now has a real TCP endpoint transport. It measures
monotonic elapsed time around an actual `tokio::net::TcpStream::connect` and
returns a typed result instead of a fabricated `rtt_ms` value.

The production binary reaches this path only when an operator explicitly
configures both variables:

```text
AETHER_TRANSPORT_PROBE_TARGET=host-or-ip:port
AETHER_TRANSPORT_PROBE_TIMEOUT_MS=1500
```

There is intentionally no default target and no default timeout. If the target
is absent, no connection is attempted. If the target is present but the timeout
is absent/invalid, startup fails rather than selecting a fake or default
connection path.

## Error contract

`ConnectError` distinguishes at least:

- `ConnectionRefused`, retaining the real `std::io::Error`;
- `Timeout { after }` from `tokio::time::timeout`;
- `DnsResolutionFailed { hostname, source }` from explicit `lookup_host`;
- `IoError { target, source }` for other socket errors; and
- `TlsHandshakeFailed` is reserved for a future TLS endpoint transport.

The TCP connector does not claim a TLS or application-protocol handshake. A
TCP connect only proves that the TCP peer accepted a socket at the measured
endpoint.

## CI evidence

[Run 30294993835](https://github.com/ysa-py/aether-x-monorepo/actions/runs/30294993835)
passed the Rust and deploy gates with `core-supervisor/tests/real_tcp_connect.rs`.
That integration suite exercises real I/O:

1. an OS-assigned loopback listener and two real TCP connections;
2. a closed loopback port returning `ConnectionRefused`;
3. `192.0.2.1:443` with a short bounded timeout returning `Timeout` on the
   GitHub Actions runner; and
4. a `.invalid` hostname returning `DnsResolutionFailed` with the hostname
   preserved.

The test also reads `src/tor.rs` and fails if the historical static
`rtt_ms: 50` assignment returns.

## Remaining limits

The legacy conceptual WebTunnel, Snowflake, obfs4, Meek, Conjure, Arti, DNS
and SSH registry entries do not yet have real configured protocol endpoints.
Their `Transport::connect` result is explicitly `NotConfigured`; they do not
fabricate success, RTT, or a connection. A future protocol-specific transport
must provide a real endpoint and handshake before it can be promoted.
