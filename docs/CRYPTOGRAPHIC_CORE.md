# Cryptographic core — verified scope and non-claims

**Status date:** 2026-07-27

This document records what the deployed Rust binaries actually do. It is not a
claim that cryptography alone bypasses filtering, DPI, loss, or an international
routing blackout.

## Subscription tokens: PASETO v4

`aether-antiforgery` now issues its subscription claims as **PASETO
`v4.public`** tokens. The production issuance/verification path is:

1. `antiforgery-server/src/main.rs` loads a stable 32-byte Ed25519 seed from
   `AETHER_ANTIFORGERY_SIGNING_KEY` (or permits an ephemeral development key
   only with `AETHER_DEV=true`). The temporary decoded environment buffer is a
   `zeroize::Zeroizing<[u8; 32]>`.
2. `antiforgery/src/token.rs` signs PASETO pre-authentication encoding (PAE) of
   the `v4.public.` header, JSON claims, footer, and implicit assertion using
   **`ed25519-dalek`**.
3. The gRPC `IssueToken` and `VerifyToken` operations in the real production
   binary use that implementation. They do not retain the former ad-hoc
   `base64(payload).base64(signature)` token envelope.
4. Signature verification is performed by `ed25519-dalek`; it rejects altered
   payload/signature bytes before JSON claims are trusted.

`v4.local` is implemented through the pinned `pasetors = 0.8.0` dependency for
server-only confidential claims (`issue_local` / `verify_local`). It requires a
separate 32-byte symmetric key. It is deliberately **not** exposed as the
subscriber-facing gRPC token: distributing a symmetric local-token key to
clients would destroy the confidentiality/integrity boundary. It must never
reuse the Ed25519 signing seed.

### Vector and tamper coverage

`antiforgery/src/token.rs` includes the official
[`paseto-standard/test-vectors` v4 corpus](https://github.com/paseto-standard/test-vectors/tree/32d7406591eb022f9eff88abb84106dd9d42c0f2):

- the official `v4.public` signing vector is both verified and reproduced with
  `ed25519-dalek`;
- the official `v4.local` decryption vector is authenticated/decrypted through
  `pasetors`;
- one altered public signature byte and one altered local ciphertext byte are
  rejected;
- a real-process integration test starts `aether-antiforgery` on an OS-assigned
  loopback TCP port, calls gRPC `IssueToken`, calls `VerifyToken`, and confirms
  a tampered token is rejected.

The process test is real local TCP I/O and executable entrypoint coverage; it
is not a remote deployment, carrier, or mobile-client test.

## Key agreement: real X25519, no fabricated hybrid

`core-supervisor/src/pqc_handshake.rs` now uses:

- **`x25519-dalek` 2.0.1** for RFC 7748 X25519 scalar multiplication;
- operating-system CSPRNG material for generated agreement identities;
- a constant-time all-zero shared-secret rejection using `subtle`;
- **HKDF-SHA-256** for a 32-byte session key;
- zeroizing key/secret buffers (`x25519-dalek` and `zeroize`).

The module has the RFC 7748 X25519 test vector, the RFC 5869 HKDF-SHA-256
vector, and a two-party agreement test. It is a key-agreement primitive only:
it is not yet a TLS, proxy, or ECH protocol integration, so it must not be
described as a completed transport handshake.

### ML-KEM-768 and ECH status: `NotConfigured`

ML-KEM is intentionally **not configured**. The maintained RustCrypto
`ml-kem` crate was reviewed on 2026-07-27, but its own documentation states
that it has **never been independently audited**. That fails the project’s
stated audited-primitive bar. The old generated SHA-256 data and synthetic
ciphertext were removed; non-empty ML-KEM input is rejected with
`PostQuantumNotConfigured` rather than being mixed into a claimed hybrid key.

ECH is also `NotConfigured` in this userspace key-agreement module. The old
XOR operation did not implement HPKE, an ECHConfigList, TLS transcript binding,
or peer authentication and has been removed. Complete ECH must be provided by
a TLS stack and verified against a real endpoint before any production claim.

## Constant-time comparisons and secret lifecycle

- Ed25519 signature verification comes from `ed25519-dalek`.
- PASETO `v4.local` key/tag handling comes from `pasetors`, which uses constant
  time operations and zeroizes secret-key containers.
- X25519 low-order shared-secret rejection uses `subtle::ConstantTimeEq`.
- Environment-decoded signing material and X25519 shared material are
  zeroized after copying/derivation.

No code here makes a claim about hiding traffic metadata, defeating an active
network adversary, bypassing a carrier, or retaining Internet access during a
true international isolation event. Those require independently deployed
paths and protocol-specific end-to-end evidence.
