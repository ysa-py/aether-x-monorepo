//! Multipath QUIC — dual-interface bonding (Cellular + WiFi)
//!
//! Supports concurrent dual-interface stream bonding with unified Session ID
//! preservation across NAT rebinding and ISP switching.
//! TUIC v5 / Hysteria2 already support QUIC CID migration; MPQUIC extends to
//! bond multiple paths simultaneously.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Network interface (e.g. cellular, wifi)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Interface {
    pub name: String, // e.g. "wlan0", "rmnet_data0"
    pub kind: InterfaceKind,
    pub ip: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InterfaceKind {
    Wifi,
    Cellular,
    Ethernet,
}

#[derive(Debug, Clone)]
pub struct MpQuicPath {
    pub interface: Interface,
    pub rtt_ms: u32,
    pub loss_rate: f64,
    pub cwnd: u32,
    pub last_used: Instant,
    pub bytes_sent: u64,
}

/// Multipath QUIC session with unified Session ID
#[derive(Debug)]
pub struct MpQuicSession {
    pub session_id: String,
    pub paths: RwLock<HashMap<String, MpQuicPath>>, // keyed by interface name
    pub active_interfaces: RwLock<Vec<String>>,
    pub total_bytes: AtomicU64,
    pub migrations: AtomicU64,
    pub created_at: Instant,
}

impl MpQuicSession {
    #[must_use]
    pub fn new(session_id: &str) -> Self {
        Self {
            session_id: session_id.to_string(),
            paths: RwLock::new(HashMap::new()),
            active_interfaces: RwLock::new(Vec::new()),
            total_bytes: AtomicU64::new(0),
            migrations: AtomicU64::new(0),
            created_at: Instant::now(),
        }
    }

    /// Add path for interface
    pub fn add_path(&self, interface: Interface, rtt_ms: u32) {
        let path = MpQuicPath {
            interface: interface.clone(),
            rtt_ms,
            loss_rate: 0.0,
            cwnd: 10,
            last_used: Instant::now(),
            bytes_sent: 0,
        };
        self.paths.write().insert(interface.name.clone(), path);
        let mut active = self.active_interfaces.write();
        if !active.contains(&interface.name) {
            active.push(interface.name);
        }
    }

    /// Remove path (e.g. interface down)
    pub fn remove_path(&self, iface_name: &str) -> bool {
        let removed = self.paths.write().remove(iface_name).is_some();
        if removed {
            self.active_interfaces
                .write()
                .retain(|n| n != iface_name);
        }
        removed
    }

    /// Send data – bonding logic: pick best path(s), or split across both for throughput
    /// Returns (chosen interface, latency)
    pub fn send(&self, data_len: usize) -> Result<(String, Duration), MpQuicError> {
        let paths = self.paths.read();
        if paths.is_empty() {
            return Err(MpQuicError::NoPath);
        }

        // Pick lowest RTT path for latency-sensitive, or both for throughput
        // Simplified: choose lowest RTT
        let best = paths
            .values()
            .min_by_key(|p| p.rtt_ms)
            .ok_or(MpQuicError::NoPath)?;

        let iface_name = best.interface.name.clone();
        drop(paths);

        // Update stats
        {
            let mut map = self.paths.write();
            if let Some(p) = map.get_mut(&iface_name) {
                p.bytes_sent += data_len as u64;
                p.last_used = Instant::now();
            }
        }
        self.total_bytes
            .fetch_add(data_len as u64, Ordering::Relaxed);

        // Simulate latency = RTT/2 + processing
        let latency = Duration::from_millis((best.rtt_ms / 2) as u64 + 5);
        Ok((iface_name, latency))
    }

    /// Send bonded – split data across all active paths for N× throughput
    pub fn send_bonded(&self, data_len: usize) -> Result<Vec<(String, usize, Duration)>, MpQuicError> {
        let active_names = self.active_interfaces.read().clone();
        if active_names.is_empty() {
            return Err(MpQuicError::NoPath);
        }

        let paths = self.paths.read();
        let mut distribution = Vec::new();
        let per_path = data_len / active_names.len();
        let remainder = data_len % active_names.len();

        for (i, iface_name) in active_names.iter().enumerate() {
            if let Some(path) = paths.get(iface_name) {
                let mut chunk = per_path;
                if i == 0 {
                    chunk += remainder;
                }
                let latency = Duration::from_millis((path.rtt_ms / 2) as u64 + 5);
                distribution.push((iface_name.clone(), chunk, latency));
            }
        }
        drop(paths);

        // Update total
        self.total_bytes
            .fetch_add(data_len as u64, Ordering::Relaxed);

        Ok(distribution)
    }

    /// Handle NAT rebinding / ISP switching – preserve session ID, update IP for interface
    pub fn handle_rebinding(&self, iface_name: &str, new_ip: &str) -> Result<(), MpQuicError> {
        let mut paths = self.paths.write();
        let Some(path) = paths.get_mut(iface_name) else {
            return Err(MpQuicError::InterfaceNotFound);
        };
        path.interface.ip = new_ip.to_string();
        path.last_used = Instant::now();
        drop(paths);
        self.migrations.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub fn path_count(&self) -> usize {
        self.paths.read().len()
    }

    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn migration_count(&self) -> u64 {
        self.migrations.load(Ordering::Relaxed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MpQuicError {
    NoPath,
    InterfaceNotFound,
    SessionClosed,
}

impl std::fmt::Display for MpQuicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoPath => write!(f, "no mpquic path available"),
            Self::InterfaceNotFound => write!(f, "interface not found"),
            Self::SessionClosed => write!(f, "session closed"),
        }
    }
}

impl std::error::Error for MpQuicError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dual_interface_bonding() {
        let sess = MpQuicSession::new("session-123");
        sess.add_path(
            Interface {
                name: "wlan0".into(),
                kind: InterfaceKind::Wifi,
                ip: "192.168.1.100".into(),
            },
            20,
        );
        sess.add_path(
            Interface {
                name: "rmnet_data0".into(),
                kind: InterfaceKind::Cellular,
                ip: "10.0.0.5".into(),
            },
            60,
        );
        assert_eq!(sess.path_count(), 2);

        // Single send picks lowest RTT (wifi)
        let (iface, _) = sess.send(1400).unwrap();
        assert_eq!(iface, "wlan0");

        // Bonded send splits across both
        let bonded = sess.send_bonded(2800).unwrap();
        assert_eq!(bonded.len(), 2);
        let total: usize = bonded.iter().map(|(_, len, _)| len).sum();
        assert_eq!(total, 2800);
        assert_eq!(sess.total_bytes(), 4200);
    }

    #[test]
    fn nat_rebinding_preserves_session_id() {
        let sess = MpQuicSession::new("persistent-session-id");
        sess.add_path(
            Interface {
                name: "wlan0".into(),
                kind: InterfaceKind::Wifi,
                ip: "192.168.1.100".into(),
            },
            20,
        );

        // NAT rebinding changes IP but session ID preserved
        sess.handle_rebinding("wlan0", "192.168.1.101").unwrap();
        assert_eq!(sess.session_id(), "persistent-session-id");
        assert_eq!(sess.migration_count(), 1);
        assert_eq!(sess.path_count(), 1);

        // Still can send
        let (iface, _) = sess.send(100).unwrap();
        assert_eq!(iface, "wlan0");
    }

    #[test]
    fn remove_path() {
        let sess = MpQuicSession::new("s1");
        sess.add_path(
            Interface {
                name: "wlan0".into(),
                kind: InterfaceKind::Wifi,
                ip: "1.1.1.1".into(),
            },
            20,
        );
        assert!(sess.remove_path("wlan0"));
        assert_eq!(sess.path_count(), 0);
        let err = sess.send(100).unwrap_err();
        assert_eq!(err, MpQuicError::NoPath);
    }
}
