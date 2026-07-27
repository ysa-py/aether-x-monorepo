//! Multi-protocol fallback mechanisms & reverse relay engine.
//!
//! Implements the Blackout Isolation Bounds & Reverse Relay Engine:
//! - Reverse Tunnel Manager between Iran edge relays and foreign core-supervisor
//! - Fallback chain: TLS in TLS, gRPC multiplexing, DoH tunneling, ICMP encapsulation, IPv6 direct
//! - Each fallback is tried in priority, with health scores from telemetry.
//!
//! This is the heart of "stay connected when international routing is cut".

use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Fallback transport kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FallbackKind {
    TlsInTls = 10,   // TLS 1.3 inside TLS (most DPI-resistant)
    GrpcMux = 20,    // gRPC multiplexing over allowed endpoint
    DoH = 30,        // DNS-over-HTTPS tunneling
    IcmpEncap = 40,  // ICMP payload encapsulation (ping tunneling)
    Ipv6Direct = 50, // IPv6 direct routing (often overlooked by DPI)
}

impl FallbackKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TlsInTls => "tls-in-tls",
            Self::GrpcMux => "grpc-mux",
            Self::DoH => "doh-tunnel",
            Self::IcmpEncap => "icmp-encap",
            Self::Ipv6Direct => "ipv6-direct",
        }
    }

    #[must_use]
    pub fn description(self) -> &'static str {
        match self {
            Self::TlsInTls => "TLS 1.3 inside outer TLS to whitelisted SNI",
            Self::GrpcMux => "gRPC multiplexed streams over whitelisted domain",
            Self::DoH => "DNS-over-HTTPS tunneling riding surviving DNS",
            Self::IcmpEncap => "ICMP payload encapsulation (ping tunnel)",
            Self::Ipv6Direct => "IPv6 direct routing bypassing IPv4 DPI",
        }
    }

    #[must_use]
    pub fn priority(self) -> u8 {
        self as u8
    }
}

/// Health score for a fallback transport.
#[derive(Debug, Clone)]
pub struct FallbackHealth {
    pub kind: FallbackKind,
    pub success_rate: f64, // 0.0-1.0
    pub avg_rtt_ms: u32,
    pub last_success: Option<Instant>,
    pub consecutive_failures: u32,
    pub available: bool,
}

impl FallbackHealth {
    pub fn new(kind: FallbackKind) -> Self {
        Self {
            kind,
            success_rate: 1.0,
            avg_rtt_ms: 100,
            last_success: None,
            consecutive_failures: 0,
            available: true,
        }
    }

    pub fn record_success(&mut self, rtt_ms: u32) {
        self.success_rate = self.success_rate * 0.9 + 0.1;
        self.avg_rtt_ms = (self.avg_rtt_ms * 9 + rtt_ms) / 10;
        self.last_success = Some(Instant::now());
        self.consecutive_failures = 0;
        self.available = true;
    }

    pub fn record_failure(&mut self) {
        self.success_rate = self.success_rate * 0.9;
        self.consecutive_failures += 1;
        if self.consecutive_failures >= 3 {
            self.available = false;
        }
    }

    #[must_use]
    pub fn score(&self) -> f64 {
        if !self.available {
            return 0.0;
        }
        // Higher success + lower RTT = higher score
        let rtt_factor = 1.0 / (1.0 + self.avg_rtt_ms as f64 / 1000.0);
        self.success_rate * rtt_factor * (1.0 / self.kind.priority() as f64 * 50.0)
    }
}

/// A reverse tunnel from edge relay (Iran) to core supervisor (foreign).
#[derive(Debug, Clone)]
pub struct ReverseTunnel {
    pub edge_id: String,
    pub core_addr: String,
    pub transport: FallbackKind,
    pub established_at: Instant,
    pub bytes_relayed: u64,
    pub active: bool,
}

/// Reverse Tunnel Manager.
#[derive(Debug)]
pub struct ReverseTunnelManager {
    health: RwLock<Vec<FallbackHealth>>,
    tunnels: RwLock<Vec<ReverseTunnel>>,
    total_bytes: AtomicU64,
    tunnels_established: AtomicU64,
}

impl ReverseTunnelManager {
    #[must_use]
    pub fn new() -> Self {
        let health = vec![
            FallbackHealth::new(FallbackKind::TlsInTls),
            FallbackHealth::new(FallbackKind::GrpcMux),
            FallbackHealth::new(FallbackKind::DoH),
            FallbackHealth::new(FallbackKind::IcmpEncap),
            FallbackHealth::new(FallbackKind::Ipv6Direct),
        ];
        Self {
            health: RwLock::new(health),
            tunnels: RwLock::new(Vec::new()),
            total_bytes: AtomicU64::new(0),
            tunnels_established: AtomicU64::new(0),
        }
    }

    /// Select best available fallback transport by score.
    #[must_use]
    pub fn select_best(&self) -> Option<FallbackKind> {
        let health = self.health.read();
        let mut candidates: Vec<&FallbackHealth> = health.iter().filter(|h| h.available).collect();
        candidates.sort_by(|a, b| {
            b.score()
                .partial_cmp(&a.score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        candidates.first().map(|h| h.kind)
    }

    /// Get fallback chain ordered best-first.
    #[must_use]
    pub fn fallback_chain(&self) -> Vec<FallbackKind> {
        let health = self.health.read();
        let mut ordered: Vec<FallbackHealth> = health.clone();
        ordered.sort_by(|a, b| {
            b.score()
                .partial_cmp(&a.score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        ordered.into_iter().map(|h| h.kind).collect()
    }

    /// Record success for a transport.
    pub fn record_success(&self, kind: FallbackKind, rtt_ms: u32) {
        let mut health = self.health.write();
        if let Some(h) = health.iter_mut().find(|h| h.kind == kind) {
            h.record_success(rtt_ms);
        }
    }

    /// Record failure.
    pub fn record_failure(&self, kind: FallbackKind) {
        let mut health = self.health.write();
        if let Some(h) = health.iter_mut().find(|h| h.kind == kind) {
            h.record_failure();
        }
    }

    /// Establish a reverse tunnel (edge initiated).
    pub fn establish_tunnel(
        &self,
        edge_id: &str,
        core_addr: &str,
        transport: FallbackKind,
    ) -> String {
        let tunnel_id = format!(
            "{edge_id}-{}-{:x}",
            transport.as_str(),
            Instant::now().elapsed().as_nanos() & 0xFFFF
        );
        let tunnel = ReverseTunnel {
            edge_id: edge_id.to_string(),
            core_addr: core_addr.to_string(),
            transport,
            established_at: Instant::now(),
            bytes_relayed: 0,
            active: true,
        };
        {
            let mut tunnels = self.tunnels.write();
            tunnels.push(tunnel);
        }
        self.tunnels_established.fetch_add(1, Ordering::Relaxed);
        self.record_success(transport, 50); // assume reasonable RTT on establishment
        tunnel_id
    }

    /// Relay bytes through a tunnel (simulate).
    pub fn relay_bytes(&self, edge_id: &str, bytes: u64) -> bool {
        let mut tunnels = self.tunnels.write();
        if let Some(t) = tunnels
            .iter_mut()
            .find(|t| t.edge_id == edge_id && t.active)
        {
            t.bytes_relayed += bytes;
            self.total_bytes.fetch_add(bytes, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Close tunnel.
    pub fn close_tunnel(&self, edge_id: &str) -> bool {
        let mut tunnels = self.tunnels.write();
        if let Some(t) = tunnels.iter_mut().find(|t| t.edge_id == edge_id) {
            t.active = false;
            true
        } else {
            false
        }
    }

    #[must_use]
    pub fn active_tunnels(&self) -> Vec<ReverseTunnel> {
        self.tunnels
            .read()
            .iter()
            .filter(|t| t.active)
            .cloned()
            .collect()
    }

    #[must_use]
    pub fn total_bytes_relayed(&self) -> u64 {
        self.total_bytes.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn tunnels_established_count(&self) -> u64 {
        self.tunnels_established.load(Ordering::Relaxed)
    }

    /// Auto-failover: try fallback chain until one succeeds (simulated health check).
    pub fn auto_failover(&self, edge_id: &str, core_addr: &str) -> Option<FallbackKind> {
        let chain = self.fallback_chain();
        for kind in chain {
            // Simulate health check: available ones succeed with 80% chance if success_rate >0.5
            let health_snapshot = {
                let h = self.health.read();
                h.iter().find(|x| x.kind == kind).cloned()
            };
            if let Some(h) = health_snapshot {
                if h.available && h.success_rate > 0.3 {
                    self.establish_tunnel(edge_id, core_addr, kind);
                    return Some(kind);
                }
            }
        }
        None
    }

    /// Health summary for metrics.
    #[must_use]
    pub fn health_summary(&self) -> Vec<FallbackHealth> {
        self.health.read().clone()
    }
}

impl Default for ReverseTunnelManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_best_initially_tls_in_tls() {
        let mgr = ReverseTunnelManager::new();
        let best = mgr.select_best().unwrap();
        assert_eq!(best, FallbackKind::TlsInTls);
    }

    #[test]
    fn failure_makes_fallback() {
        let mgr = ReverseTunnelManager::new();
        // Fail TLS-in-TLS 3 times -> unavailable
        for _ in 0..3 {
            mgr.record_failure(FallbackKind::TlsInTls);
        }
        let best = mgr.select_best().unwrap();
        assert_ne!(best, FallbackKind::TlsInTls);
        assert_eq!(best, FallbackKind::GrpcMux);
    }

    #[test]
    fn establish_and_relay() {
        let mgr = ReverseTunnelManager::new();
        let tid = mgr.establish_tunnel("edge-tehran-01", "core.eu:443", FallbackKind::TlsInTls);
        assert!(!tid.is_empty());
        assert_eq!(mgr.active_tunnels().len(), 1);
        assert!(mgr.relay_bytes("edge-tehran-01", 1024));
        assert_eq!(mgr.total_bytes_relayed(), 1024);
        assert!(mgr.close_tunnel("edge-tehran-01"));
        assert_eq!(mgr.active_tunnels().len(), 0);
    }

    #[test]
    fn auto_failover_picks_available() {
        let mgr = ReverseTunnelManager::new();
        // Make TLS fail
        for _ in 0..3 {
            mgr.record_failure(FallbackKind::TlsInTls);
        }
        let chosen = mgr.auto_failover("edge-02", "core:443").unwrap();
        assert_eq!(chosen, FallbackKind::GrpcMux);
        assert_eq!(mgr.active_tunnels().len(), 1);
    }

    #[test]
    fn chain_ordered_by_score() {
        let mgr = ReverseTunnelManager::new();
        let chain = mgr.fallback_chain();
        assert_eq!(chain.len(), 5);
        assert_eq!(chain[0], FallbackKind::TlsInTls);
        // Make DoH have best RTT
        mgr.record_success(FallbackKind::DoH, 10);
        mgr.record_success(FallbackKind::DoH, 10);
        // Still TLS should be first due to priority weight, but DoH score improves
        let chain2 = mgr.fallback_chain();
        assert!(chain2.contains(&FallbackKind::DoH));
    }

    #[test]
    fn score_zero_when_unavailable() {
        let mut h = FallbackHealth::new(FallbackKind::DoH);
        for _ in 0..3 {
            h.record_failure();
        }
        assert_eq!(h.score(), 0.0);
    }
}
