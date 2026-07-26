# TRANSPORT_REGISTRY.md — Aether-X Transport & Protocol Decision Record

**Version:** 1.0 · **Authority:** non-negotiable §6 of the engineering directive · **Answers:** *"Is there still Multi Tunneling, DNSTT, NoizDNS, Slipstream, SSH, DoH, NaiveProxy?"*

---

## Direct answer to the owner's question

| Asked about | Included? | Why |
|---|---|---|
| **Multi Tunneling** (nested cascade + mid-stream hop) | ✅ YES | Core differentiator. `multi_tunnel.rs` (outer wraps inner, hop without socket teardown) + `buffer_replay.rs` (in-flight re-injection). |
| **DNSTT** (DNS-tunnel lineage) | ✅ YES | Three forks registered: MasterDnsVPN, VayDNS, NoizDNS. Each distinct. |
| **NoizDNS** | ✅ YES (new) | DPI-resistant dnstt fork; distinct from VayDNS. Transport #9. |
| **Slipstream** | ❌ NO (by design) | `MasterDnsVpn` is the documented faster successor in the same DNSTT lineage. Adding Slipstream = forbidden duplication. |
| **SSH** (SOCKS via SSH) | ✅ YES (new) | Deep last-resort transport #10 (priority 110). Honest caveat: SSH handshakes are increasingly DPI-fingerprintable. |
| **DoH / DoT** | ✅ YES — as a CARRIER, not a standalone transport | VayDNS already tunnels over DoH/DoT. A second standalone DoH transport = forbidden duplication. DoH is how VayDNS/NoizDNS disguise themselves, not a peer transport. |
| **NaiveProxy** | ✅ YES | Primary-tier protocol. Looks like Chrome traffic (HTTP/2 + QUIC over Chromium network stack). Strong DPI evasion. |
| **Tor PTs** (WebTunnel, Snowflake, obfs4, Meek, Conjure) | ✅ YES | Last-resort tier, priorities 20–60. |
| **Reality / Vision** | ✅ YES | Primary security layer for VLESS. |
| **Hysteria2 / TUIC** | ✅ YES | High-speed QUIC protocols. |
| **ShadowTLS / AmneziaWG** | ✅ YES | ShadowTLS v3 (wraps behind real TLS); AmneziaWG (WireGuard + junk-packet obfuscation). |

---

## The full 10-transport last-resort tier

Registered in `ResilienceController::with_full_resilience_tier()`, tried by priority (lower = first):

| # | Transport ID | Priority | Disguise | Upstream / License |
|---|---|---|---|---|
| 1 | `arti-tor` | 10 | Tor circuits (Arti engine) | Arti, MIT/Apache |
| 2 | `webtunnel` | 20 | HTTP/2 WebSocket to CDN front | Tor PT |
| 3 | `snowflake` | 30 | WebRTC via STUN/TURN brokers | Tor PT |
| 4 | `obfs4` | 40 | Packet-length padding + entropy | Tor PT (Lyrebird) |
| 5 | `meek` | 50 | CDN domain fronting (Cloudflare/Azure) | Tor PT |
| 6 | `conjure` | 60 | Phantom-IP space tap routing | Tor PT |
| 7 | `dns-tunnel-masterdns` | 100 | Plain DNS UDP, custom ARQ, multi-resolver + duplication | MasterDnsVPN, MIT |
| 8 | `dns-tunnel-vaydns-doh` | 100 | **DoH/DoT** + uTLS fingerprint randomization | VayDNS, CC0 (dnstt fork) |
| 9 | `dns-tunnel-noizdns` | 100 | Noisy DNS (DPI-resistant dnstt fork) | NoizDNS, dnstt lineage |
| 10 | `ssh-socks-tunnel` | 110 | SSH-over-TCP dynamic SOCKS | OpenSSH lineage; deep last-resort |

**Test assertion (§7):** `registry.len() == 10`; names include all 10; `slipstream` and standalone `doh-transport` are **absent** (negative test documents this so a future contributor doesn't re-add the duplicate).

---

## The full primary-tier protocol × transport matrix

These are the fast, high-throughput protocols the client connects to under normal conditions (Group A in BLACKOUT_BOUNDS.md §3). The last-resort tier above is Group B (slow, rides censorship).

| Protocol | Transports | Security | Engine | Use case |
|---|---|---|---|---|
| **VLESS** | tcp, ws, grpc, httpupgrade, **xhttp/splithttp**, h2, mkcp | none / tls / **reality** / **vision** | xray-core | Default; XHTTP preferred (no ALPN fingerprint) |
| **VMess** | tcp, ws, grpc, h2, httpupgrade | tls / none | xray-core / sing-box | Legacy compat |
| **Trojan** | tcp, ws, grpc, httpupgrade, xhttp | tls / reality | xray-core / sing-box | |
| **Shadowsocks** (2022) | tcp, ws | — | sing-box | AEAD-2022 |
| **NaiveProxy** | http/2 + quic (HTTP/3) | tls (Chromium stack) | naive | Looks like Chrome; strong DPI evasion |
| **Hysteria2** | quic | tls | sing-box | High-speed UDP/QUIC; lossy links |
| **TUIC v5** | quic | tls / uuid | sing-box | |
| **ShadowTLS v3** | tcp | tls (wraps protocol behind real TLS handshake) | sing-box | |
| **AmneziaWG** | udp | — (junk-packet obfuscation) | amneziawg-go | WireGuard variant; defeats WG DPI signatures |
| **WireGuard** | udp | — | wireguard-go | Baseline (AmneziaWG preferred in censored zones) |

---

## Deliberate exclusions (non-duplication record)

Per non-negotiable #2 (decision logic has one owner; do not duplicate), these are **excluded by design**:

| Excluded | Reason | Already covered by |
|---|---|---|
| **Slipstream** | Same DNSTT lineage; `MasterDnsVPN` is the documented faster successor | `dns-tunnel-masterdns` (#7) |
| **Standalone DoH transport** | `VayDNS` already tunnels over DoH/DoT | `dns-tunnel-vaydns-doh` (#8) |
| **dnstt (original)** | All three registered DNS-tunnel variants (MasterDnsVPN/VayDNS/NoizDNS) are dnstt-lineage forks that supersede it | #7, #8, #9 |

**A future contributor who "helpfully" re-adds any of these is creating the exact duplication the architecture forbids. The negative test in §7 enforces this.**

---

## How these map to the isolation levels (BLACKOUT_BOUNDS.md §1)

| Level | Which tier carries traffic |
|---|---|
| **Nominal** | Primary-tier protocols (table above) |
| **Degraded** | Primary-tier, hot-swapped + AI morphed |
| **Escalated** | The 10-transport last-resort tier (this document) |
| **ConfirmedIsolation** | Nothing — disciplined waiting |
| **TotalIsolation** | Out-of-band (if provisioned) + local mesh only |

---

*This document is the single source of truth for "which transports does Aether-X support and why." It is consistent with `BLACKOUT_BOUNDS.md`, `CLIENT_ENGINEERING_PROMPT.md` §6, and the `transport::Catalog()` / `transport::Profiles()` Go functions in `control-plane/internal/transport/`.*
