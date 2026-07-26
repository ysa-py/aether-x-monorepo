//! Reverse Relay Engine — Iran edge relays ↔ foreign core-supervisor
//!
//! Under Blackout Isolation Bounds, edge relays inside Iran initiate
//! *reverse* tunnels to the foreign core-supervisor, because inbound
//! connections are blocked but outbound to whitelisted SNIs may survive.
//!
//! This module owns:
//! - Edge relay registry (Iran-based)
//! - Reverse tunnel lifecycle (auto-reconnect, exponential backoff)
//! - Integration with fallback transports (TLS-in-TLS, gRPC, DoH, ICMP, IPv6)
//! - SNI whitelisting & domain fronting for the outer layer
//!
//! Production would use real TCP/TLS dials; here deterministic mock.

use crate::domain_fronting::{DomainFrontingEngine, FrontingConfig};
use crate::fallback_transport::{FallbackKind, ReverseTunnelManager};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Edge relay located in Iran (or other censored region).
#[derive(Debug, Clone)]
pub struct EdgeRelay {
    pub id: String,
    pub region: String, // e.g. "tehran", "isfahan"
    pub isp: String,    // MCI, Irancell, etc
    pub last_seen: Instant,
    pub healthy: bool,
    pub active_transport: Option<FallbackKind>,
}

impl EdgeRelay {
    pub fn new(id: &str, region: &str, isp: &str) -> Self {
        Self {
            id: id.to_string(),
            region: region.to_string(),
            isp: isp.to_string(),
            last_seen: Instant::now(),
            healthy: true,
            active_transport: None,
        }
    }
}

/// Reverse relay controller.
#[derive(Debug)]
pub struct ReverseRelayEngine {
    edges: RwLock<HashMap<String, EdgeRelay>>,
    tunnel_mgr: ReverseTunnelManager,
    fronting: DomainFrontingEngine,
    reconnect_attempts: RwLock<HashMap<String, u32>>,
    total_reconnects: AtomicU64,
}

impl ReverseRelayEngine {
    #[must_use]
    pub fn new() -> Self {
        Self {
            edges: RwLock::new(HashMap::new()),
            tunnel_mgr: ReverseTunnelManager::new(),
            fronting: DomainFrontingEngine::with_iran_defaults(),
            reconnect_attempts: RwLock::new(HashMap::new()),
            total_reconnects: AtomicU64::new(0),
        }
    }

    /// Register an edge relay.
    pub fn register_edge(&self, relay: EdgeRelay) {
        let mut edges = self.edges.write();
        edges.insert(relay.id.clone(), relay);
    }

    /// Edge heartbeat (keeps alive).
    pub fn heartbeat(&self, edge_id: &str, healthy: bool) {
        let mut edges = self.edges.write();
        if let Some(e) = edges.get_mut(edge_id) {
            e.last_seen = Instant::now();
            e.healthy = healthy;
        }
    }

    /// Attempt to establish reverse tunnel from edge to core.
    /// Uses domain fronting for outer SNI and fallback chain.
    pub fn connect_edge(&self, edge_id: &str, core_addr: &str) -> ConnectResult {
        // Ensure edge exists
        let edge_exists = { self.edges.read().contains_key(edge_id) };
        if !edge_exists {
            return ConnectResult::EdgeNotFound;
        }

        // Pick front SNI via domain fronting engine
        let fronted = self.fronting.fronted_handshake(core_addr);
        let front_sni = fronted
            .as_ref()
            .map(|f| f.outer_sni.clone())
            .unwrap_or_else(|| "www.digikala.com".to_string());

        // Try auto-failover chain
        let chosen = self.tunnel_mgr.auto_failover(edge_id, core_addr);

        match chosen {
            Some(kind) => {
                {
                    let mut edges = self.edges.write();
                    if let Some(e) = edges.get_mut(edge_id) {
                        e.active_transport = Some(kind);
                        e.healthy = true;
                        e.last_seen = Instant::now();
                    }
                }
                {
                    let mut attempts = self.reconnect_attempts.write();
                    attempts.remove(edge_id);
                }
                ConnectResult::Connected {
                    transport: kind,
                    front_sni,
                }
            }
            None => {
                // All transports exhausted -> schedule reconnect with backoff
                let backoff = self.record_failed_attempt(edge_id);
                ConnectResult::FailedRetry { backoff, front_sni }
            }
        }
    }

    fn record_failed_attempt(&self, edge_id: &str) -> Duration {
        let mut attempts = self.reconnect_attempts.write();
        let count = attempts.entry(edge_id.to_string()).or_insert(0);
        *count += 1;
        self.total_reconnects.fetch_add(1, Ordering::Relaxed);
        // Exponential backoff: 1s, 2s, 4s, 8s, capped at 60s + jitter
        let base = 2u64.pow((*count).min(6) as u32);
        let jitter = (*count as u64 * 137) % 500; // deterministic jitter
        Duration::from_millis(base * 1000 + jitter)
    }

    /// Handle edge disconnect (e.g. DPI kill).
    pub fn handle_disconnect(&self, edge_id: &str) {
        self.tunnel_mgr.close_tunnel(edge_id);
        {
            let mut edges = self.edges.write();
            if let Some(e) = edges.get_mut(edge_id) {
                e.healthy = false;
                e.active_transport = None;
            }
        }
        // Record failure for current transport to drive fallback
        let chain = self.tunnel_mgr.fallback_chain();
        if let Some(best) = chain.first() {
            self.tunnel_mgr.record_failure(*best);
        }
    }

    /// Periodic maintenance: prune stale edges, auto-reconnect unhealthy.
    pub fn tick(&self, core_addr: &str) -> Vec<ConnectResult> {
        let mut results = Vec::new();
        let now = Instant::now();
        let stale_threshold = Duration::from_secs(120);

        let unhealthy: Vec<String> = {
            let edges = self.edges.read();
            edges
                .iter()
                .filter(|(_, e)| !e.healthy || now.duration_since(e.last_seen) > stale_threshold)
                .map(|(id, _)| id.clone())
                .collect()
        };

        for edge_id in unhealthy {
            let res = self.connect_edge(&edge_id, core_addr);
            results.push(res);
        }

        results
    }

    #[must_use]
    pub fn active_edges(&self) -> Vec<EdgeRelay> {
        self.edges
            .read()
            .values()
            .filter(|e| e.healthy)
            .cloned()
            .collect()
    }

    #[must_use]
    pub fn all_edges(&self) -> Vec<EdgeRelay> {
        self.edges.read().values().cloned().collect()
    }

    #[must_use]
    pub fn total_reconnects(&self) -> u64 {
        self.total_reconnects.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn tunnel_manager(&self) -> &ReverseTunnelManager {
        &self.tunnel_mgr
    }

    #[must_use]
    pub fn fronting_engine(&self) -> &DomainFrontingEngine {
        &self.fronting
    }

    /// Add custom fronting config (operator).
    pub fn add_fronting(&self, cfg: FrontingConfig) {
        self.fronting.add_config(cfg);
    }
}

#[derive(Debug, Clone)]
pub enum ConnectResult {
    Connected {
        transport: FallbackKind,
        front_sni: String,
    },
    FailedRetry {
        backoff: Duration,
        front_sni: String,
    },
    EdgeNotFound,
}

impl Default for ReverseRelayEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_and_connect() {
        let engine = ReverseRelayEngine::new();
        engine.register_edge(EdgeRelay::new("tehran-01", "tehran", "MCI"));
        let res = engine.connect_edge("tehran-01", "core.example:443");
        match res {
            ConnectResult::Connected {
                transport,
                front_sni,
            } => {
                assert!(matches!(
                    transport,
                    FallbackKind::TlsInTls
                        | FallbackKind::GrpcMux
                        | FallbackKind::DoH
                        | FallbackKind::IcmpEncap
                        | FallbackKind::Ipv6Direct
                ));
                assert!(!front_sni.is_empty());
            }
            _ => panic!("should connect"),
        }
        assert_eq!(engine.active_edges().len(), 1);
    }

    #[test]
    fn disconnect_and_reconnect_with_backoff() {
        let engine = ReverseRelayEngine::new();
        engine.register_edge(EdgeRelay::new("tehran-02", "tehran", "Irancell"));
        engine.connect_edge("tehran-02", "core:443");

        engine.handle_disconnect("tehran-02");
        assert_eq!(engine.active_edges().len(), 0);

        // Tick should attempt reconnect
        let results = engine.tick("core:443");
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0], ConnectResult::Connected { .. }));
    }

    #[test]
    fn backoff_grows() {
        let engine = ReverseRelayEngine::new();
        engine.register_edge(EdgeRelay::new("edge-backoff", "tehran", "MCI"));

        // Exhaust all transports by failing them
        for kind in [
            FallbackKind::TlsInTls,
            FallbackKind::GrpcMux,
            FallbackKind::DoH,
            FallbackKind::IcmpEncap,
            FallbackKind::Ipv6Direct,
        ] {
            for _ in 0..4 {
                engine.tunnel_manager().record_failure(kind);
            }
        }

        let res = engine.connect_edge("edge-backoff", "core:443");
        match res {
            ConnectResult::FailedRetry { backoff, .. } => {
                assert!(backoff >= Duration::from_secs(1));
            }
            _ => panic!("expected failed retry"),
        }

        // second attempt larger backoff
        let res2 = engine.connect_edge("edge-backoff", "core:443");
        match (res, res2) {
            (
                ConnectResult::FailedRetry { backoff: b1, .. },
                ConnectResult::FailedRetry { backoff: b2, .. },
            ) => {
                assert!(b2 >= b1);
            }
            _ => panic!("both should be failed"),
        }
    }

    #[test]
    fn fronting_config_used() {
        let engine = ReverseRelayEngine::new();
        engine.add_fronting(FrontingConfig::new("www.shaparak.ir", "core.example:443"));
        engine.register_edge(EdgeRelay::new("edge-front", "tehran", "MCI"));
        let res = engine.connect_edge("edge-front", "core.example:443");
        assert!(matches!(res, ConnectResult::Connected { .. }));
    }

    #[test]
    fn edge_not_found() {
        let engine = ReverseRelayEngine::new();
        let res = engine.connect_edge("nonexistent", "core:443");
        assert!(matches!(res, ConnectResult::EdgeNotFound));
    }
}
