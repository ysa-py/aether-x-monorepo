//! QUIC Connection ID migration — TUIC v5 / Hysteria2 zero-disconnection
//!
//! QUIC allows connection migration without breaking the session by using
//! a stable Connection ID that survives IP changes (e.g. NAT rebinding,
//! ISP throttling, moving from WiFi to mobile). TUIC v5 and Hysteria2 both
//! exploit this for zero-disconnection transport under censorship.
//!
//! This module models the migration state machine, path validation, and
//! seamless socket migration so active TCP streams inside the QUIC tunnel
//! never drop when the underlying UDP socket moves.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Uniquely identifies a QUIC connection (independent of 4-tuple).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionId(pub String);

impl ConnectionId {
    pub fn new_random(seed: u64) -> Self {
        // Deterministic for tests; real impl uses rand
        Self(format!("{:016x}{:016x}", seed, seed.wrapping_mul(0x9E3779B97F4A7C15)))
    }
}

/// A network path (IP:port pair) that a QUIC connection may use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPath {
    pub local_addr: String,
    pub remote_addr: String,
    pub rtt_ms: u32,
    pub validated: bool,
}

impl NetworkPath {
    pub fn new(local: &str, remote: &str) -> Self {
        Self {
            local_addr: local.to_string(),
            remote_addr: remote.to_string(),
            rtt_ms: 0,
            validated: false,
        }
    }
}

/// Migration state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationState {
    /// Stable on one path.
    Stable,
    /// Probing a new path (path validation in progress).
    PathValidation,
    /// Migrated to new path, draining old.
    Migrated,
    /// Failed to migrate, staying on old.
    Failed,
}

/// A QUIC connection capable of migration.
#[derive(Debug)]
pub struct QuicConnection {
    pub conn_id: ConnectionId,
    pub protocol: QuicProtocol,
    pub current_path: NetworkPath,
    pub state: MigrationState,
    pub last_migration: Option<Instant>,
    pub migration_count: u64,
    pub bytes_before_migration: u64,
    pub bytes_after_migration: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicProtocol {
    TuicV5,
    Hysteria2,
}

impl QuicConnection {
    pub fn new(conn_id: ConnectionId, protocol: QuicProtocol, initial_path: NetworkPath) -> Self {
        Self {
            conn_id,
            protocol,
            current_path: initial_path,
            state: MigrationState::Stable,
            last_migration: None,
            migration_count: 0,
            bytes_before_migration: 0,
            bytes_after_migration: 0,
        }
    }

    /// Start path validation to `new_path`. Returns true if validation started.
    pub fn start_path_validation(&mut self, new_path: NetworkPath) -> bool {
        if self.state == MigrationState::PathValidation {
            return false; // already validating
        }
        self.state = MigrationState::PathValidation;
        self.current_path = new_path;
        true
    }

    /// Complete path validation (e.g. PATH_CHALLENGE / PATH_RESPONSE succeeded).
    pub fn complete_validation(&mut self, success: bool, rtt_ms: u32) {
        if success {
            self.current_path.validated = true;
            self.current_path.rtt_ms = rtt_ms;
            self.state = MigrationState::Migrated;
            self.last_migration = Some(Instant::now());
            self.migration_count += 1;
        } else {
            self.state = MigrationState::Failed;
        }
    }

    /// After migration, mark as stable again (drain complete).
    pub fn stabilize(&mut self) {
        if self.state == MigrationState::Migrated {
            self.state = MigrationState::Stable;
        } else if self.state == MigrationState::Failed {
            self.state = MigrationState::Stable;
        }
    }

    #[must_use]
    pub fn can_migrate(&self) -> bool {
        self.state == MigrationState::Stable
    }

    #[must_use]
    pub fn migration_age(&self) -> Option<Duration> {
        self.last_migration.map(|t| t.elapsed())
    }
}

/// Migration manager — tracks many QUIC connections and orchestrates zero-downtime migration.
#[derive(Debug, Default)]
pub struct QuicMigrationManager {
    connections: RwLock<HashMap<String, QuicConnection>>,
}

impl QuicMigrationManager {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new QUIC connection.
    pub fn register(&self, conn: QuicConnection) {
        let mut map = self.connections.write();
        map.insert(conn.conn_id.0.clone(), conn);
    }

    /// Migrate a connection identified by conn_id to new_path.
    /// Returns outcome.
    pub fn migrate(&self, conn_id: &str, new_path: NetworkPath) -> MigrationOutcome {
        let mut map = self.connections.write();
        let Some(conn) = map.get_mut(conn_id) else {
            return MigrationOutcome::NotFound;
        };
        if !conn.can_migrate() {
            return MigrationOutcome::AlreadyMigrating;
        }
        let started = conn.start_path_validation(new_path);
        if started {
            MigrationOutcome::ValidationStarted
        } else {
            MigrationOutcome::Failed
        }
    }

    /// Complete validation for a connection.
    pub fn complete_validation(&self, conn_id: &str, success: bool, rtt_ms: u32) -> bool {
        let mut map = self.connections.write();
        if let Some(conn) = map.get_mut(conn_id) {
            conn.complete_validation(success, rtt_ms);
            true
        } else {
            false
        }
    }

    /// Stabilize after migration.
    pub fn stabilize(&self, conn_id: &str) -> bool {
        let mut map = self.connections.write();
        if let Some(conn) = map.get_mut(conn_id) {
            conn.stabilize();
            true
        } else {
            false
        }
    }

    #[must_use]
    pub fn get(&self, conn_id: &str) -> Option<QuicConnectionSnapshot> {
        let map = self.connections.read();
        map.get(conn_id).map(|c| QuicConnectionSnapshot {
            conn_id: c.conn_id.0.clone(),
            protocol: c.protocol,
            state: c.state,
            current_path: c.current_path.clone(),
            migration_count: c.migration_count,
        })
    }

    #[must_use]
    pub fn total_migrations(&self) -> u64 {
        self.connections.read().values().map(|c| c.migration_count).sum()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.connections.read().len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.connections.read().is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct QuicConnectionSnapshot {
    pub conn_id: String,
    pub protocol: QuicProtocol,
    pub state: MigrationState,
    pub current_path: NetworkPath,
    pub migration_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationOutcome {
    ValidationStarted,
    AlreadyMigrating,
    NotFound,
    Failed,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> QuicConnection {
        QuicConnection::new(
            ConnectionId::new_random(1),
            QuicProtocol::Hysteria2,
            NetworkPath::new("192.168.1.1:1234", "1.2.3.4:443"),
        )
    }

    #[test]
    fn migration_lifecycle() {
        let mut c = conn();
        assert_eq!(c.state, MigrationState::Stable);
        assert!(c.can_migrate());

        let new_path = NetworkPath::new("10.0.0.2:5678", "1.2.3.4:443");
        assert!(c.start_path_validation(new_path.clone()));
        assert_eq!(c.state, MigrationState::PathValidation);
        assert!(!c.can_migrate());

        c.complete_validation(true, 42);
        assert_eq!(c.state, MigrationState::Migrated);
        assert_eq!(c.migration_count, 1);
        assert!(c.current_path.validated);
        assert_eq!(c.current_path.rtt_ms, 42);

        c.stabilize();
        assert_eq!(c.state, MigrationState::Stable);
        assert!(c.can_migrate());
    }

    #[test]
    fn failed_validation() {
        let mut c = conn();
        c.start_path_validation(NetworkPath::new("10.0.0.2:0", "1.2.3.4:443"));
        c.complete_validation(false, 0);
        assert_eq!(c.state, MigrationState::Failed);
        c.stabilize();
        assert_eq!(c.state, MigrationState::Stable);
    }

    #[test]
    fn manager_register_and_migrate() {
        let mgr = QuicMigrationManager::new();
        let cid = ConnectionId::new_random(42);
        let id_str = cid.0.clone();
        mgr.register(QuicConnection::new(
            cid,
            QuicProtocol::TuicV5,
            NetworkPath::new("192.168.1.1:0", "5.6.7.8:443"),
        ));
        assert_eq!(mgr.len(), 1);

        let outcome = mgr.migrate(&id_str, NetworkPath::new("192.168.1.2:0", "5.6.7.8:443"));
        assert_eq!(outcome, MigrationOutcome::ValidationStarted);

        let dup = mgr.migrate(&id_str, NetworkPath::new("192.168.1.3:0", "5.6.7.8:443"));
        assert_eq!(dup, MigrationOutcome::AlreadyMigrating);

        assert!(mgr.complete_validation(&id_str, true, 30));
        let snap = mgr.get(&id_str).unwrap();
        assert_eq!(snap.state, MigrationState::Migrated);
        assert_eq!(snap.migration_count, 1);

        assert!(mgr.stabilize(&id_str));
        let snap2 = mgr.get(&id_str).unwrap();
        assert_eq!(snap2.state, MigrationState::Stable);
        assert_eq!(mgr.total_migrations(), 1);
    }

    #[test]
    fn zero_disconnection_semantic() {
        // Simulate: during migration, bytes continue flowing — no TCP drop.
        let mgr = QuicMigrationManager::new();
        let cid = ConnectionId::new_random(100);
        let id = cid.0.clone();
        let mut c = QuicConnection::new(
            cid,
            QuicProtocol::Hysteria2,
            NetworkPath::new("10.0.0.1:1000", "8.8.8.8:443"),
        );
        c.bytes_before_migration = 5000;
        mgr.register(c);

        // Start migration (e.g. ISP throttles, NAT rebinding)
        mgr.migrate(&id, NetworkPath::new("10.0.0.2:2000", "8.8.8.8:443"));
        // During PathValidation, data still flows on old path (modeled as no drop)
        // Complete
        mgr.complete_validation(&id, true, 25);
        mgr.stabilize(&id);
        let snap = mgr.get(&id).unwrap();
        assert_eq!(snap.state, MigrationState::Stable);
        // Connection ID preserved across migration — session continuity
        assert_eq!(snap.conn_id, id);
    }

    #[test]
    fn not_found() {
        let mgr = QuicMigrationManager::new();
        let out = mgr.migrate("nonexistent", NetworkPath::new("a", "b"));
        assert_eq!(out, MigrationOutcome::NotFound);
    }
}
