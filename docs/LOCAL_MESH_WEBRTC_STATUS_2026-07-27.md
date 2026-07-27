# local_mesh WebRTC transport status — 2026-07-27

**Status: 🟡 Not configured.**

No WebRTC peer connection, ICE session, TURN relay allocation, NAT traversal,
packet-loss/jitter drill, or data-channel throughput result is claimed.

## Environment evidence

The verification environment was checked for the minimum real-transport tools:

```text
turnserver: not installed
coturn: not installed
docker/podman: not installed
webrtc-rs dependency: not present
traffic-control (tc): not installed
```

A local loopback-only WebRTC test would not satisfy the requirement: it does
not exercise NAT traversal or TURN fallback. It is intentionally not presented
as a substitute.

## Isolated TURN provisioning

`infra/turn/` now contains a loopback-only coturn Docker/Compose provisioner.
`provision.sh` generates fresh credentials at startup and writes them with mode
`0600`; no TURN username or password is committed. It binds relay signaling and
UDP relay ports only to `127.0.0.1`.

It was not executed here because Docker/Compose is absent from this environment.
The provisioner is ready for a container-capable isolated runner, but that is
not evidence of a relay allocation.

## Exact blocker

**No Docker/container runtime or TURN infrastructure is provisioned in the
current execution environment.** A symmetric-NAT or relay-fallback scenario
cannot be established without running the isolated coturn service and supplying
its generated credentials to a real `webrtc-rs` peer pair. The current
environment also lacks `tc`, so packet-loss/jitter impairment cannot be applied
to a real WebRTC path here.

## Required evidence for a future ✅

1. A pinned `webrtc-rs` implementation in the production binary.
2. Two real processes gather ICE candidates and exchange SDP through an
   authenticated signaling channel.
3. A controlled coturn service accepts a relay allocation and logs that the
   selected ICE candidate pair is relay-backed.
4. A real data channel exchanges application bytes through the relay.
5. A privileged network namespace or `tc netem` drill applies documented loss
   and jitter, with connection logs, received-byte count, throughput, and
   latency statistics.
6. A failure-mode report covers unreachable STUN/TURN, expired credentials,
   UDP-blocked networks, relay quota exhaustion, and no-peer/no-egress cases.

BLE and Wi-Fi Direct remain 🟡 deferred: they require platform-specific Android,
iOS, Windows, macOS, and Linux radio/permission work and are not represented by
this WebRTC status.
