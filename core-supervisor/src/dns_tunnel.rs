//! DNS-tunnel last-resort transport (MasterDnsVPN / VayDNS) — spec §3.
//!
//! Both projects expose a local SOCKS5 endpoint once their client binary is
//! running. A DNS tunnel is emphatically *not* a primary transport peer to
//! Xray/sing-box (its real-world throughput through a censored resolver chain
//! is orders of magnitude lower — see `THREAT_MODEL.md`), so it belongs in the
//! [`crate::tor`] last-resort registry, not in [`crate::protocol`]`::CoreKind`.
//! That keeps this addition off the `protocol.rs` / proto surface entirely.
//!
//! Priority 100 places it dead last — after Arti (10) and every Tor pluggable
//! transport (20–60). It is only selected by [`crate::tor::TransportRegistry`]
//! when nothing above it is available, i.e. an actual connectivity blackout
//! where DNS queries still ride a surviving path.

use crate::tor::Transport;
use std::sync::atomic::{AtomicBool, Ordering};

/// Which upstream DNS-tunnel project a [`DnsTunnelTransport`] wraps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsTunnelVariant {
    /// `github.com/masterking32/MasterDnsVPN` (MIT) — custom ARQ + resolver
    /// health design; documented surviving Iran's 88-day total blackout.
    MasterDnsVpn,
    /// `github.com/net2share/vaydns` (CC0-1.0, `dnstt` lineage) — adds DoH/DoT
    /// disguise + uTLS fingerprint randomization over the same spawn→SOCKS5
    /// integration shape.
    VayDns,
    /// `github.com/anonvector/noiz-dns` — DPI-resistant fork of dnstt with
    /// noise injection; distinct from VayDNS's DoH/DoT approach.
    NoizDns,
}

impl DnsTunnelVariant {
    /// Human-readable upstream project label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::MasterDnsVpn => "MasterDnsVPN",
            Self::VayDns => "VayDNS",
            Self::NoizDns => "NoizDNS",
        }
    }
}

/// Wraps a DNS-tunnel client (MasterDnsVPN or VayDNS) as a last-resort
/// [`Transport`]. The adapter owns process lifecycle + health, *not* protocol
/// logic: in production it spawns the variant's client binary once (e.g.
/// `MasterDnsVPN_Client ... -listen 127.0.0.1:18000`) and a background Tokio
/// task probes the local SOCKS5 port to flip [`DnsTunnelTransport::healthy`].
///
/// This model mirrors how [`crate::tor::ArtiEngine`] simulates its real
/// bootstrap: the trait surface is real, the heavy subprocess work is a
/// deterministic stand-in so the registry, failover wiring, and tests exercise
/// the *selection* logic without requiring the external binaries.
#[derive(Debug)]
pub struct DnsTunnelTransport {
    variant: DnsTunnelVariant,
    local_socks_addr: String,
    spawned: AtomicBool,
    healthy: AtomicBool,
}

impl DnsTunnelTransport {
    /// Spawn-equivalent constructor. In production this launches the variant's
    /// client binary bound to `local_socks_addr`; here the process is modelled
    /// as `spawned` (lifecycle) + `healthy` (probe result), both initially
    /// false until [`DnsTunnelTransport::mark_spawned`] /
    /// [`DnsTunnelTransport::mark_healthy`] reflect a real probe.
    #[must_use]
    pub fn spawn(variant: DnsTunnelVariant, local_socks_addr: &str) -> Self {
        Self {
            variant,
            local_socks_addr: local_socks_addr.into(),
            spawned: AtomicBool::new(false),
            healthy: AtomicBool::new(false),
        }
    }

    /// Mark the underlying client process as launched (lifecycle tracking).
    pub fn mark_spawned(&self, spawned: bool) {
        self.spawned.store(spawned, Ordering::SeqCst);
    }

    /// Mark the tunnel healthy/unhealthy. A production health probe calls this
    /// after a successful (or failed) SOCKS5 round-trip to `local_socks_addr`.
    pub fn mark_healthy(&self, ok: bool) {
        self.healthy.store(ok, Ordering::SeqCst);
    }

    /// Whether the client process has been launched.
    #[must_use]
    pub fn is_spawned(&self) -> bool {
        self.spawned.load(Ordering::SeqCst)
    }

    /// Local SOCKS5 address the tunnel exposes once healthy.
    #[must_use]
    pub fn local_socks_addr(&self) -> &str {
        &self.local_socks_addr
    }

    /// Which upstream DNS-tunnel project this wraps.
    #[must_use]
    pub fn variant(&self) -> DnsTunnelVariant {
        self.variant
    }
}

impl Transport for DnsTunnelTransport {
    fn name(&self) -> &str {
        match self.variant {
            DnsTunnelVariant::MasterDnsVpn => "dns-tunnel-masterdns",
            DnsTunnelVariant::VayDns => "dns-tunnel-vaydns-doh",
            DnsTunnelVariant::NoizDns => "dns-tunnel-noizdns",
        }
    }

    // Lower priority (= tried later) than every existing entry — this is the
    // option of last resort, after Arti and all five pluggable transports, not
    // a peer to them. See spec §3.1 for the throughput rationale.
    fn priority(&self) -> u8 {
        100
    }

    fn is_available(&self) -> bool {
        self.healthy.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_priorities_match_spec() {
        let m = DnsTunnelTransport::spawn(DnsTunnelVariant::MasterDnsVpn, "127.0.0.1:18000");
        let v = DnsTunnelTransport::spawn(DnsTunnelVariant::VayDns, "127.0.0.1:18001");
        assert_eq!(m.name(), "dns-tunnel-masterdns");
        assert_eq!(v.name(), "dns-tunnel-vaydns-doh");
        assert_eq!(m.variant().label(), "MasterDnsVPN");
        assert_eq!(v.variant().label(), "VayDNS");
        // Dead last — after Arti (10) and the five PTs (20–60).
        assert_eq!(m.priority(), 100);
        assert_eq!(v.priority(), 100);
    }

    #[test]
    fn health_state_is_not_fabricated_into_a_connection() {
        let t = DnsTunnelTransport::spawn(DnsTunnelVariant::MasterDnsVpn, "127.0.0.1:18000");
        assert!(!t.is_available());
        assert!(!t.is_spawned());
        assert!(matches!(
            t.connect(),
            Err(crate::tor::ConnectError::NotConfigured { .. })
        ));

        t.mark_spawned(true);
        t.mark_healthy(true);
        assert!(t.is_spawned());
        assert!(t.is_available());
        // The lifecycle state alone cannot claim a socket handshake or static RTT.
        assert!(matches!(
            t.connect(),
            Err(crate::tor::ConnectError::NotConfigured { .. })
        ));

        t.mark_healthy(false);
        assert!(!t.is_available());
    }

    #[test]
    fn dns_tunnels_sort_after_every_pt() {
        use crate::tor::TransportRegistry;
        let reg = TransportRegistry::with_all_transports();
        reg.register(std::sync::Arc::new(DnsTunnelTransport::spawn(
            DnsTunnelVariant::MasterDnsVpn,
            "127.0.0.1:18000",
        )));
        reg.register(std::sync::Arc::new(DnsTunnelTransport::spawn(
            DnsTunnelVariant::VayDns,
            "127.0.0.1:18001",
        )));
        let names = reg.transport_names();
        // Lowest priority sorts last; both DNS tunnels must be the final two.
        let last_two = &names[names.len().saturating_sub(2)..];
        assert!(last_two.contains(&"dns-tunnel-masterdns".to_string()));
        assert!(last_two.contains(&"dns-tunnel-vaydns-doh".to_string()));
        assert_eq!(reg.len(), 8);
    }
}
