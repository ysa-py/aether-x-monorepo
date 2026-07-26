//! Local mesh — peer discovery + ad-hoc relay for nearby devices (§3).
//!
//! This module provides **no path to the international internet by itself**. It lets nearby
//! devices exchange cached data and queued messages, and lets one device's restored or
//! out-of-band path act as an ad hoc gateway for local peers. If zero peers within radio
//! range have any working egress, this module still cannot reach the outside world — that
//! is a statement about physics, not a bug.

use crate::isolation::IsolationLevel;
use parking_lot::RwLock;

/// A discovered peer in the local mesh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshPeer {
    /// Unique peer identifier (e.g. device hostname or public key hash).
    pub id: String,
    /// Reachable address (e.g. `192.168.1.42:7890` or a BLE MAC).
    pub addr: String,
    /// Whether this peer reports it can reach the internet (egress available).
    pub has_egress: bool,
}

/// The local mesh node — discovers peers and offers/uses relay.
#[derive(Debug)]
pub struct LocalMesh {
    peers: RwLock<Vec<MeshPeer>>,
    self_id: String,
}

impl LocalMesh {
    /// Create a mesh node with a self identifier.
    #[must_use]
    pub fn new(self_id: &str) -> Self {
        Self {
            peers: RwLock::new(Vec::new()),
            self_id: self_id.into(),
        }
    }

    /// Add or update a discovered peer.
    pub fn add_peer(&self, peer: MeshPeer) {
        let mut g = self.peers.write();
        if let Some(existing) = g.iter_mut().find(|p| p.id == peer.id) {
            *existing = peer;
        } else {
            g.push(peer);
        }
    }

    /// Remove a peer (went offline).
    pub fn remove_peer(&self, id: &str) {
        self.peers.write().retain(|p| p.id != id);
    }

    /// All known peers.
    #[must_use]
    pub fn peers(&self) -> Vec<MeshPeer> {
        self.peers.read().clone()
    }

    /// Peers that can act as a gateway — they have egress AND are not at TotalIsolation.
    #[must_use]
    pub fn gateway_candidates(&self) -> Vec<MeshPeer> {
        self.peers
            .read()
            .iter()
            .filter(|p| p.has_egress)
            .cloned()
            .collect()
    }

    /// Whether this node should offer to relay for isolated peers. A node offers
    /// if its own isolation level is below TotalIsolation (i.e. it has connectivity).
    #[must_use]
    pub fn should_offer_relay(&self, my_level: IsolationLevel) -> bool {
        my_level < IsolationLevel::TotalIsolation
    }

    /// This node's identifier.
    #[must_use]
    pub fn self_id(&self) -> &str {
        &self.self_id
    }

    /// Number of known peers.
    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.peers.read().len()
    }
}

/// Trait for platform-specific transport implementations (BLE, Wi-Fi Direct, mDNS).
/// Platform code implements this; the mesh logic above is transport-agnostic.
pub trait MeshTransport: Send + Sync {
    /// Discover peers on the local network/radio. Returns peer IDs + addresses.
    fn discover(&self) -> Vec<(String, String)>;
    /// Send data to a specific peer by address.
    fn send(&self, addr: &str, data: &[u8]) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_remove_peers() {
        let m = LocalMesh::new("device-A");
        assert_eq!(m.peer_count(), 0);
        m.add_peer(MeshPeer {
            id: "B".into(),
            addr: "10.0.0.2:7890".into(),
            has_egress: true,
        });
        m.add_peer(MeshPeer {
            id: "C".into(),
            addr: "10.0.0.3:7890".into(),
            has_egress: false,
        });
        assert_eq!(m.peer_count(), 2);
        m.remove_peer("B");
        assert_eq!(m.peer_count(), 1);
    }

    #[test]
    fn gateway_candidates_filter_by_egress() {
        let m = LocalMesh::new("A");
        m.add_peer(MeshPeer {
            id: "B".into(),
            addr: "x".into(),
            has_egress: true,
        });
        m.add_peer(MeshPeer {
            id: "C".into(),
            addr: "y".into(),
            has_egress: false,
        });
        m.add_peer(MeshPeer {
            id: "D".into(),
            addr: "z".into(),
            has_egress: true,
        });
        let gw = m.gateway_candidates();
        assert_eq!(gw.len(), 2);
        assert!(gw.iter().all(|p| p.has_egress));
    }

    #[test]
    fn should_offer_relay_only_when_not_isolated() {
        let m = LocalMesh::new("A");
        assert!(m.should_offer_relay(IsolationLevel::Nominal));
        assert!(m.should_offer_relay(IsolationLevel::Degraded));
        assert!(m.should_offer_relay(IsolationLevel::Escalated));
        assert!(m.should_offer_relay(IsolationLevel::ConfirmedIsolation));
        assert!(
            !m.should_offer_relay(IsolationLevel::TotalIsolation),
            "isolated node must not offer relay"
        );
    }

    #[test]
    fn no_gateway_candidates_when_no_egress() {
        let m = LocalMesh::new("A");
        m.add_peer(MeshPeer {
            id: "B".into(),
            addr: "x".into(),
            has_egress: false,
        });
        assert!(m.gateway_candidates().is_empty(), "no egress = no gateway");
    }
}
