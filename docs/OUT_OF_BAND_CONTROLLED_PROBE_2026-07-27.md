# Controlled out-of-band probe evidence — 2026-07-27

**Scope:** a controlled loopback HTTPS DNS-JSON target only. No probe was sent
to Iranian ISP infrastructure or a production third-party endpoint.

## Reproducible command

```bash
tests/oob/run_controlled_doh_probe.sh
```

The script generates a one-day local test certificate, starts
`tests/oob/controlled_doh_target.py` on an OS-assigned loopback port, makes a
real TCP/TLS/HTTPS `GET /dns-query` request with `curl --cacert`, validates the
DNS-JSON answer, records observer-side request metadata, prints the client
HTTPS trace, and removes the temporary key/certificate/logs.

## Actual output

```text
controlled_doh_response=PASS
{"accept":"application/dns-json","content_length":"","method":"GET","name":"example.test","path":"/dns-query","query_keys":["name","type"],"type":"A","user_agent":"curl/7.88.1"}
controlled_doh_probe=PASS
```

## Observer / fingerprinting assessment

The controlled endpoint observed a clearly distinguishable DNS-over-HTTPS
pattern: TLS followed by `GET /dns-query`, query keys `name` and `type`,
`Accept: application/dns-json`, a DNS name, query type, and a curl user-agent.
A network observer cannot see those HTTP fields through TLS without
interception, but can still observe TLS endpoint/IP, SNI when ECH is absent,
request timing, packet sizes, connection reuse, and periodic cadence. A TLS
interceptor or the resolver itself can observe the full request metadata.

**Risk: yes, a naive periodic probe can be fingerprintable.** Mitigations that
must be configured and evaluated per authorized deployment are: bounded random
cadence, connection reuse, probe coalescing with legitimate resolver traffic,
operator-controlled endpoint rotation, and strict rate limits. These reduce
but do not eliminate observability; they are not bypass guarantees.

## Capture limitation

The agent has no `CAP_NET_RAW`; both raw IP and AF_PACKET socket creation return
`EPERM`, and `tcpdump` is absent. The evidence above is therefore a controlled
server observer record plus the client’s application-visible HTTPS trace, **not
a packet capture**. A privileged capture run using `tcpdump`/pcap on the test
interface remains required before any DPI-wire signature claim.

## Production limitation

`core-supervisor/src/out_of_band.rs` still contains a flag-backed placeholder
interface and is not eligible for a production-complete claim. A real shipped
probe must use explicit operator-provided DoH/TCP targets, report structured
latency/failure results, and preserve the fingerprinting assessment above.
