# Aether-X — Security Policy

## Threat model (summary)

The adversary is a **nation-state-level DPI / censorship system** with active
probing, TLS fingerprinting, ML-based traffic classification, and IP-reputation
blacklisting, assumed to update weekly. See `THREAT_MODEL.md` for the full
analysis. This document covers the **operational** security posture of the
platform itself.

## Transport security

| Path | Requirement |
|------|-------------|
| Control plane ↔ Core Supervisor (gRPC) | **mTLS mandatory.** Supervisor rejects non-mTLS on its control port. |
| Control plane ↔ Client (REST/MCP) | TLS 1.3; mTLS for admin/reseller surfaces. |
| Inter-service internal traffic | **Zero plaintext.** All internal calls are mTLS. |
| Data at rest (Postgres, ClickHouse, Redis) | AES-256-GCM. Redis TLS enabled. |

Both Rust gRPC binaries additionally **refuse to bind plaintext on a
non-loopback address**. Their tonic listeners load a server identity and
`client_ca_root`, so an unauthenticated TLS connection cannot dispatch an RPC.
Both Go clients refuse a remote plaintext dial before connecting. This is a
hard guardrail, not a recommendation. Certificate provisioning and the exact
Northflank variables are documented in `deploy/northflank/README.md`.

## Hard constraint: no Python in production

Python is permitted **only** inside `ai-training/` (offline, sandboxed, never
deployed). CI must reject any production `Dockerfile` that installs a Python
runtime, and any production service that imports a Python process. The
production inference path is Rust + ONNX (`ort`) only.

## Authentication & authorization

- Access tokens: HS256 JWT today; **Ed25519** in phase 1 (aligns with the
  anti-forgery core). The parser pins HS256, validates issuer/expiry, subject,
  identity consistency, and known roles before a request reaches a handler.
  Tokens carry a `kid`; `AETHER_JWT_KEY_ID` selects the active signer while
  `AETHER_JWT_PREVIOUS_KEYS=kid:secret,...` verifies short-lived old tokens
  during a planned rotation without a control-plane session cliff.
- `/v1` and `/mcp` require `Authorization: Bearer <JWT>` whenever an issuer is
  configured. Privileged core visibility, transport/config generation, client
  draft/confirm operations, and MCP tools require `admin`.
- RBAC roles: `admin > reseller > user`. Unknown roles deny access.
- `AETHER_DEV=true` is the only explicit local-development bypass. It must
  remain false in every public deployment.
- Rate limiting per-token (Redis counters).

## Anti-forgery (expiry / quota) — phase 1

User-facing expiry and quota values are **cryptographically signed** (Ed25519)
server-side. The client may never spoof remaining time/quota. Every
subscription mutation is written to a **tamper-evident, hash-chained audit
log** (Merkle-style), so an unauthorized DB edit is cryptographically
detectable. Subscription token refresh uses rotating HMAC tokens with
nonce + timestamp and short TTL to defeat replay.

## Reporting a vulnerability

Do **not** open a public issue. Email security@aether-x.local with a
reproduction. We acknowledge within 72 hours.
