# Changelog

## Unreleased

### Cryptographic core: PASETO v4 and real X25519

Commits [`1aa5b4c`](https://github.com/ysa-py/aether-x-monorepo/commit/1aa5b4cd32c84fc86a6fe25d42a865547022ac22), [`e412a7f`](https://github.com/ysa-py/aether-x-monorepo/commit/e412a7f591945799212f716ef2404a3e4a15b6e2), [`338631a`](https://github.com/ysa-py/aether-x-monorepo/commit/338631a82789ff300a45c3466ca0bf98e50a4b0d), [`b9240b0`](https://github.com/ysa-py/aether-x-monorepo/commit/b9240b0add7b0455b069d71d3e49311cd0688a3d), and [`df1f430`](https://github.com/ysa-py/aether-x-monorepo/commit/df1f430a20eacb2ea4fdd616f8d94e04d6c86a18) replace the former fabricated X25519/ML-KEM/XOR construction and ad-hoc subscription-token envelope.

Verified by [CI run 30299237077](https://github.com/ysa-py/aether-x-monorepo/actions/runs/30299237077) on [PR #5](https://github.com/ysa-py/aether-x-monorepo/pull/5):

- the production anti-forgery binary issues and verifies `v4.public` PASETO subscription tokens using `ed25519-dalek` over real loopback gRPC/TCP process I/O; a tampered token is rejected;
- the complete official PASETO v4 corpus pinned from `paseto-standard/test-vectors` is checked: all valid `v4.public` vectors are verified and reproduced, valid `v4.local` vectors decrypt, and the negative vectors reject;
- PASETO `v4.local` issue/verify helpers use the pinned `pasetors 0.8.0` implementation and reject a modified ciphertext;
- RFC 7748 X25519 and RFC 5869 HKDF-SHA-256 vectors pass; generated peers derive the same real X25519/HKDF session key and an all-zero shared secret is rejected with a constant-time comparison;
- deployment-decoded signing material and X25519 shared secret buffers are zeroized; and
- Rust format, clippy with warnings denied, workspace tests, fuzz build, deployment-image builds, and all final CI gates exited successfully.

Remaining honest limits: `v4.local` is a server-only library API, intentionally not the subscriber-facing gRPC token format because that would require distributing its symmetric key. The real executable subscription path is `v4.public`. ML-KEM-768 and ECH are `NotConfigured`, not simulated: the maintained RustCrypto ML-KEM implementation currently declares no independent audit, so no hybrid secret/ciphertext is claimed. X25519 here is a key-agreement primitive, not a completed TLS, ECH, proxy, or censorship-bypass protocol. This does not establish Iranian-carrier, mobile-client, DPI-evasion, blackout-continuity, or full international-isolation capability.

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
