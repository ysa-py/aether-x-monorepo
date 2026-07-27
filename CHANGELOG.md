# Changelog

## Unreleased

### Real TCP transport connection path

Commits [`51c1e03`](https://github.com/ysa-py/aether-x-monorepo/commit/51c1e03f1ee59a59e304ed29b822e85ca02fb660), [`50fb71e`](https://github.com/ysa-py/aether-x-monorepo/commit/50fb71e0d98f212229f83c4e86f9e71630701045), and [`49cabe5`](https://github.com/ysa-py/aether-x-monorepo/commit/49cabe5d0bfc57bc3fe2d896d7dfbefcac1aed7e) replace the historical fabricated transport RTT path with a real configurable TCP connector.

Verified by [CI run 30294993835](https://github.com/ysa-py/aether-x-monorepo/actions/runs/30294993835):

- real loopback TCP connect and monotonic RTT measurement;
- real closed-port `ConnectionRefused` classification;
- real RFC 5737 TEST-NET timeout on the GitHub Actions runner;
- real `.invalid` DNS-resolution failure retaining the hostname;
- static regression guard rejecting the historical `rtt_ms: 50` assignment; and
- Rust, deploy, and final CI gates all exited successfully.

Remaining gap: this change measures TCP connection establishment only. TLS and
application/proxy handshakes are not yet measured, and conceptual transport
entries without a configured real protocol endpoint return `NotConfigured`
rather than fabricating a connection.
