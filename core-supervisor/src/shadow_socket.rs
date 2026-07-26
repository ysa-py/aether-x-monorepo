//! Shadow Socket Migration — kernel-level socket cloning during route blocks
//!
//! Clones socket contexts at kernel level during active route blocks to transparently
//! splice traffic onto new transports without resetting local user app TCP connections.
//!
//! Uses eBPF sockops + sockhash to migrate; this module manages shadow socket lifecycle.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Original socket context
#[derive(Debug, Clone)]
pub struct SocketContext {
    pub fd: i32,
    pub local_addr: String,
    pub remote_addr: String,
    pub state: TcpState,
    pub created_at: Instant,
    pub bytes_forwarded: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Established,
    FinWait,
    CloseWait,
    Migrating,
}

/// Shadow socket — cloned context
#[derive(Debug, Clone)]
pub struct ShadowSocket {
    pub original_fd: i32,
    pub shadow_fd: i32,
    pub new_transport: String,
    pub cloned_at: Instant,
    pub active: bool,
}

/// Shadow Socket Manager
#[derive(Debug)]
pub struct ShadowSocketManager {
    original_sockets: RwLock<HashMap<i32, SocketContext>>,
    shadows: RwLock<HashMap<i32, ShadowSocket>>, // keyed by original fd
    next_fd: AtomicU64,
    migrations: AtomicU64,
}

impl ShadowSocketManager {
    #[must_use]
    pub fn new() -> Self {
        Self {
            original_sockets: RwLock::new(HashMap::new()),
            shadows: RwLock::new(HashMap::new()),
            next_fd: AtomicU64::new(1000),
            migrations: AtomicU64::new(0),
        }
    }

    /// Register original socket
    pub fn register(&self, ctx: SocketContext) {
        self.original_sockets.write().insert(ctx.fd, ctx);
    }

    /// Clone socket context during route block — creates shadow socket on new transport
    /// Returns shadow fd, does not close original yet (transparent splice)
    pub fn clone_socket(
        &self,
        original_fd: i32,
        new_transport: &str,
    ) -> Result<ShadowSocket, ShadowError> {
        let original = {
            let map = self.original_sockets.read();
            let Some(ctx) = map.get(&original_fd) else {
                return Err(ShadowError::NotFound);
            };
            ctx.clone()
        };

        // In real eBPF: bpf_clone_socket + bpf_msg_redirect_hash to new transport
        // Here mock: allocate new fd, copy context
        let shadow_fd = self.next_fd.fetch_add(1, Ordering::Relaxed) as i32;
        let shadow = ShadowSocket {
            original_fd,
            shadow_fd,
            new_transport: new_transport.to_string(),
            cloned_at: Instant::now(),
            active: true,
        };

        // Update original state to migrating
        {
            let mut map = self.original_sockets.write();
            if let Some(ctx) = map.get_mut(&original_fd) {
                ctx.state = TcpState::Migrating;
            }
        }

        self.shadows.write().insert(original_fd, shadow.clone());
        self.migrations.fetch_add(1, Ordering::Relaxed);
        Ok(shadow)
    }

    /// Splice traffic: redirect from original to shadow — zero-copy via sockhash
    /// User app still sees original fd, but kernel forwards to new transport
    pub fn splice(&self, original_fd: i32) -> Result<(), ShadowError> {
        let shadows = self.shadows.read();
        let Some(shadow) = shadows.get(&original_fd) else {
            return Err(ShadowError::NoShadow);
        };
        if !shadow.active {
            return Err(ShadowError::ShadowInactive);
        }

        // In real: bpf_msg_redirect_hash to shadow fd
        // Mock: just mark original as spliced
        Ok(())
    }

    /// Complete migration: close original, shadow becomes primary, preserve user TCP connection
    pub fn complete_migration(&self, original_fd: i32) -> Result<i32, ShadowError> {
        let shadow = {
            let mut shadows = self.shadows.write();
            let Some(s) = shadows.remove(&original_fd) else {
                return Err(ShadowError::NoShadow);
            };
            s
        };

        // Remove original, promote shadow
        {
            let mut originals = self.original_sockets.write();
            originals.remove(&original_fd);
            // Insert promoted context with original fd preserved for user app transparency
            let promoted = SocketContext {
                fd: original_fd, // keep same fd for user app — transparent!
                local_addr: shadow.new_transport.clone(),
                remote_addr: "migrated".to_string(),
                state: TcpState::Established,
                created_at: Instant::now(),
                bytes_forwarded: 0,
            };
            originals.insert(original_fd, promoted);
        }

        Ok(original_fd)
    }

    #[must_use]
    pub fn migration_count(&self) -> u64 {
        self.migrations.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn shadow_count(&self) -> usize {
        self.shadows.read().len()
    }

    #[must_use]
    pub fn original_count(&self) -> usize {
        self.original_sockets.read().len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShadowError {
    NotFound,
    NoShadow,
    ShadowInactive,
    AlreadyMigrating,
}

impl std::fmt::Display for ShadowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "original socket not found"),
            Self::NoShadow => write!(f, "no shadow socket for fd"),
            Self::ShadowInactive => write!(f, "shadow socket inactive"),
            Self::AlreadyMigrating => write!(f, "already migrating"),
        }
    }
}

impl std::error::Error for ShadowError {}

impl Default for ShadowSocketManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clone_and_splice_transparent() {
        let mgr = ShadowSocketManager::new();
        mgr.register(SocketContext {
            fd: 10,
            local_addr: "127.0.0.1:1234".into(),
            remote_addr: "1.2.3.4:443".into(),
            state: TcpState::Established,
            created_at: Instant::now(),
            bytes_forwarded: 0,
        });

        // Route block detected — clone to new transport
        let shadow = mgr.clone_socket(10, "grpc-mux").unwrap();
        assert_eq!(shadow.original_fd, 10);
        assert_eq!(shadow.new_transport, "grpc-mux");
        assert!(shadow.active);
        assert_eq!(mgr.shadow_count(), 1);

        // Splice traffic transparently
        mgr.splice(10).unwrap();

        // Complete migration — user app fd 10 preserved!
        let preserved_fd = mgr.complete_migration(10).unwrap();
        assert_eq!(preserved_fd, 10, "user fd must be preserved for transparency");
        assert_eq!(mgr.shadow_count(), 0);
        assert_eq!(mgr.original_count(), 1);
        assert_eq!(mgr.migration_count(), 1);
    }

    #[test]
    fn not_found_error() {
        let mgr = ShadowSocketManager::new();
        let err = mgr.clone_socket(999, "tls").unwrap_err();
        assert_eq!(err, ShadowError::NotFound);
    }

    #[test]
    fn no_shadow_splice_error() {
        let mgr = ShadowSocketManager::new();
        mgr.register(SocketContext {
            fd: 10,
            local_addr: "a".into(),
            remote_addr: "b".into(),
            state: TcpState::Established,
            created_at: Instant::now(),
            bytes_forwarded: 0,
        });
        let err = mgr.splice(10).unwrap_err();
        assert_eq!(err, ShadowError::NoShadow);
    }
}
