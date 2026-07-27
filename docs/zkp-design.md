# ZKP design: registered PASETO expiry credential

**Status:** design locked before proof implementation

**Date:** 2026-07-27

## Why the initially suggested statement is not implemented directly

A literal statement such as:

> “I know a PASETO v4.public token that is Ed25519-valid and unexpired, without
> revealing its bytes.”

requires an arithmetic circuit for PASETO v4 pre-authentication encoding,
Ed25519 signature verification, JSON claim parsing, and expiry comparison. A
range-proof system alone cannot prove that statement. This repository must not
make a hash-based “challenge response” look like that proof.

A Groth16/Halo2 implementation for that full circuit would add a large trusted
setup/circuit/dependency surface. No independently audited, version-pinned Rust
implementation and audit evidence for *that exact PASETO/Ed25519 circuit* has
been established in this repository. Therefore the full direct-token statement
is **not configured** rather than being approximated by a mock circuit.

## Exact statement implemented in this scope

The production issuer already possesses the PASETO v4.public verification key.
It verifies a presented token with the real Item A `aether_antiforgery::token`
implementation before issuing a ZK registration record.

For a registered, non-revoked credential commitment `C_exp`, a prover proves:

> I know an expiration timestamp `exp` and Pedersen blinding scalar `r` such
> that `C_exp = PedersenCommit(exp, r)` is an entry in the verifier’s issuer
> registry, **and** `delta = exp - (now_unix + 1)` lies in `[0, 2^64)`. The
> registry entry was created only after the issuer verified the real PASETO
> v4.public token from which `exp` was read.

The verifier receives the registered `C_exp`, computes the public shifted
commitment `C_delta = C_exp - (now_unix + 1) * G`, and verifies a 64-bit
Bulletproof range proof for `C_delta`. The proof contains neither the PASETO
string nor its JSON claims.

This proves **issuer-attested PASETO eligibility at registration plus current
unexpiredness**, not a zero-knowledge Ed25519-signature verification. The
issuer/registry is therefore an explicit trust boundary.

## Security properties and bounds

- The issuer calls the Item A PASETO verifier before registration. A forged,
  altered, malformed, expired, or quota-exhausted token is never registered.
- The verifier rejects an unknown or revoked commitment before accepting a
  range proof.
- The verifier checks the real current time supplied by its production entry
  point; a client-supplied `now` is not trusted.
- The transcript binds protocol domain, registry commitment, and `now_unix` to
  prevent proof replay across identities or times.
- A verifier sees `C_exp`, so repeated use is linkable at the credential
  commitment level. This design does **not** claim unlinkable anonymous
  credentials.
- Revocation is registry based. A proof cannot override a revoked registry
  entry.
- The `u64` range bounds Unix seconds. Values outside the supported range are
  rejected instead of silently wrapping.

## Library choice and audit qualification

The implementation will use the pinned `bulletproofs` crate only for a
standard Pedersen commitment and 64-bit range proof, which is precisely the
shape it implements. The dalek Bulletproofs lineage received a public
Quarkslab assessment in 2019. The report is useful evidence for the underlying
protocol implementation, but it predates the currently pinned release; it is
not represented as a fresh audit of every later release or of this
application’s registry policy.

The code must pin its version, retain the documented transcript labels, and
cover a real forged-proof rejection. Application review remains required before
using it as an authorization gate.

## Required implementation evidence

1. A real PASETO v4.public token is issued by Item A code and verified before
   ZK credential registration.
2. A real Bulletproof prover creates a proof; the verifier validates it against
   its registered actual Pedersen commitment.
3. A changed proof byte, changed commitment, expired credential, and revoked
   credential each reject.
4. A production-binary path invokes registration/verification only through
   explicit operator configuration; there is no synthetic success default.
   `aether-antiforgery` reads `AETHER_ANTIFORGERY_ZKP_VERIFY_TOKEN` only when
   an operator supplies a non-empty token. It verifies that supplied PASETO,
   registers it, proves eligibility, and verifies the proof before opening the
   loopback gRPC listener. An invalid proof or token terminates startup.
5. The integration test must use real loopback process I/O for the production
   entrypoint, not call an in-memory test-only verifier.

## Deliberate non-claims

This is not a proof of PASETO signature validity inside the ZK proof, a
privacy-preserving rate limiter, a mobile-client protocol, a DPI bypass, or a
network continuity mechanism. It does not make Internet access available under
an international routing blackout.
