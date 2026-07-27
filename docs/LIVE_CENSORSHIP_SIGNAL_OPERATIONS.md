# Live censorship-signal measurement operations

## Scope and non-claim

`core-supervisor/src/live_signals.rs` is the first runtime-wired source of
inputs for `blackout::classify`. It makes small, configured network probes and
reports aggregate observations; it **does not** start a transport, change a
proxy configuration, bypass a network control, or promise continued
connectivity.

The monitor starts only when `AETHER_LIVE_SIGNAL_CONFIG` names a readable JSON
file. With that variable absent, it sends no probes. A malformed config or an
unreadable pinned TLS CA prevents supervisor startup rather than silently
falling back to invented results.

The code has no public endpoint/default resolver list. Use only operator-owned
or expressly authorized test anchors. Do not commit real endpoint addresses,
subscription credentials, or private keys to this repository.

## Configuration shape

```json
{
  "interval_ms": 10000,
  "timeout_ms": 3000,
  "window_cycles": 3,
  "tcp_targets": [
    {
      "address": "192.0.2.10:443",
      "scope": "international"
    },
    {
      "address": "192.0.2.11:443",
      "scope": "international"
    },
    {
      "address": "198.51.100.10:443",
      "scope": "domestic"
    }
  ],
  "tls_targets": [
    {
      "address": "203.0.113.10:443",
      "server_name": "tls-anchor.operator.invalid",
      "ca_certificate_pem": "/run/aether/probe-ca.pem"
    }
  ],
  "dns_targets": [
    {
      "resolver": "192.0.2.53:53",
      "name": "dns-anchor.operator.invalid",
      "expected_addresses": ["192.0.2.10"]
    },
    {
      "resolver": "192.0.2.54:53",
      "name": "dns-anchor.operator.invalid",
      "expected_addresses": ["192.0.2.10"]
    }
  ]
}
```

The hostnames and TEST-NET address above are **schema labels only** and cannot
be deployed. `SocketAddr` fields must be concrete IP-address-and-port values in
the deployed JSON; DNS names are used only for SNI/DNS questions.

The strict validator requires:

- at least two TCP targets labelled `international` and one labelled `domestic`;
- at least one TLS target with a CA PEM that validates the target's SNI name;
- at least two DNS targets with explicit expected A/AAAA answer sets;
- `interval_ms` in 1–300 seconds, timeout in 250 ms–30 seconds, and a 2–60
  cycle window.

The TLS source refuses to disable certificate verification. For an authorized
private anchor, mount the anchor's CA PEM read-only at the configured path.

## Exact measurements

| Signal field | Source behaviour | It does **not** prove |
| --- | --- | --- |
| `tcp_rst_rate` | Fraction of TCP/TLS attempts that returned local `ConnectionReset` over the rolling window. | That an ISP/censor injected an RST rather than the endpoint/path resetting a connection. |
| `tls_trunc_rate` | Fraction of certificate-verified TLS probes interrupted by EOF or reset after the ClientHello was sent. | Which actor closed the connection, or a general property of all TLS paths. |
| `dns_anomaly_rate` | Fraction of direct UDP DNS responses whose response code or A/AAAA answers disagree with the pinned anchor. | Poisoning when a resolver merely timed out; timeouts are counted separately as DNS failures. |
| `international_ip_severed` | True only when every configured international TCP anchor had zero successes across a full window. | Nationwide international routing state. |
| `dns_resolves_international` | True when at least one configured direct DNS anchor returns an expected answer in a full window. | General international DNS availability. |
| `domestic_intranet_up` | True when at least one operator-designated domestic TCP anchor accepts a connection. | National intranet availability or user Internet reachability. |

Only after the window is full does `LiveSignalSource` call
`blackout::classify`; this avoids escalating from one packet loss event. The
supervisor logs aggregate counts/rates and classification only—no destinations,
hostnames, resolver addresses, or subscriber information.

## CI evidence versus deployment evidence

The repository test suite uses actual loopback sockets:

- a local TCP listener for connection-success measurement;
- a local rustls server and pinned test CA for verified TLS success;
- a local TCP listener which reads a ClientHello and closes, exercising the
  observed TLS-EOF/truncation path; and
- a local UDP DNS responder for matching and mismatched pinned answers.

Those tests prove that this code sends/receives real local TCP, TLS, and UDP DNS
traffic and that its resulting `BlackoutSignal` reaches the existing
classifier. They do **not** prove censorship detection on an Iranian carrier or
on any public network.

Before enabling the monitor in a real deployment, perform an authorized
staging drill:

1. Deploy independent controlled international, domestic, TLS, and DNS anchors.
2. Verify TLS CA/SNI validation succeeds without an insecure verifier.
3. Confirm normal-window metrics and classification against packet captures and
   anchor-side logs.
4. Introduce controlled endpoint resets, TLS close-before-handshake, wrong DNS
   answers, DNS timeouts, and route withdrawal one at a time. Record expected
   versus observed rates/classification.
5. If RST **injection attribution** is required, capture packets at a reviewed
   boundary (AF_PACKET/eBPF/pcap) and correlate sequence numbers with the probe
   flow. A userspace `ConnectionReset` alone cannot establish injection.
6. Keep the monitor advisory until the policy/actuation path has its own
   independently measured fail-safe and rollback review.

A full international blackout remains a physical boundary: this monitor can
report a supported observation, but cannot create an external route where none
exists.
