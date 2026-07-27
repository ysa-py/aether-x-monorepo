# Privileged capture CI blocker — 2026-07-27

The controlled loopback probe has real TCP/TLS/HTTPS evidence, but cannot
produce a PCAP in the current execution environment:

```text
AF_PACKET blocked: EPERM
raw IP blocked: EPERM
tcpdump: unavailable
dumpcap: unavailable
```

The requested scoped CI job cannot be added by the current authenticated GitHub
App credential. This credential has repository contents access but cannot create
or modify `.github/workflows/*`; previous workflow update attempts are rejected
by GitHub for missing `workflows` permission.

A privileged capture job must be provisioned by a repository administrator with
workflow administration rights. It must be isolated to one job only, use the
controlled loopback target in `tests/oob/`, grant only `CAP_NET_RAW` (or use a
self-hosted test runner with that capability), install `tcpdump`, write the
PCAP as a restricted artifact, and never target Iranian ISP or production user
traffic. The current broad CI pipeline must not be made privileged.

Until that job exists, a PCAP and wire-level timing/size analysis are 🟡 blocked;
the application-level controlled observer record is not represented as a PCAP.
