//! SSH SOCKS tunnel — deep last-resort transport (#10, priority 110).
//!
//! Wraps an SSH dynamic SOCKS proxy (`ssh -D`) as a [`Transport`]. Registered
//! at the **lowest** priority of the entire tier: SSH handshakes are
//! increasingly fingerprintable by modern DPI, so this exists as one more
//! option, not because it outperforms the DNS tunnels or pluggable transports
//! above it.

use crate::tor::Transport;
use std::sync::atomic::{AtomicBool, Ordering};

/// SSH SOCKS tunnel transport. In production, spawns `ssh -D <addr>` and probes
/// the SOCKS port for health. Here: lifecycle model matching [`DnsTunnelTransport`].
#[derive(Debug)]
pub struct SshTunnelTransport {
    local_socks_addr: String,
    spawned: AtomicBool,
    healthy: AtomicBool,
}

impl SshTunnelTransport {
    /// Create with a local SOCKS5 address.
    #[must_use]
    pub fn new(local_socks_addr: &str) -> Self {
        Self {
            local_socks_addr: local_socks_addr.into(),
            spawned: AtomicBool::new(false),
            healthy: AtomicBool::new(false),
        }
    }

    /// Mark the SSH process as spawned.
    pub fn mark_spawned(&self, ok: bool) {
        self.spawned.store(ok, Ordering::SeqCst);
    }

    /// Mark the SOCKS port healthy/unhealthy (from a probe).
    pub fn mark_healthy(&self, ok: bool) {
        self.healthy.store(ok, Ordering::SeqCst);
    }

    /// Whether the SSH process has been spawned.
    #[must_use]
    pub fn is_spawned(&self) -> bool {
        self.spawned.load(Ordering::SeqCst)
    }

    /// Local SOCKS5 address.
    #[must_use]
    pub fn local_socks_addr(&self) -> &str {
        &self.local_socks_addr
    }
}

impl Transport for SshTunnelTransport {
    fn name(&self) -> &str {
        "ssh-socks-tunnel"
    }

    /// Lowest priority in the entire tier — tried after everything else.
    fn priority(&self) -> u8 {
        110
    }

    fn is_available(&self) -> bool {
        self.healthy.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_and_priority() {
        let t = SshTunnelTransport::new("127.0.0.1:18003");
        assert_eq!(t.name(), "ssh-socks-tunnel");
        assert_eq!(t.priority(), 110); // lowest in the tier
    }

    #[test]
    fn health_state_is_not_fabricated_into_a_connection() {
        let t = SshTunnelTransport::new("127.0.0.1:18003");
        assert!(!t.is_available());
        assert!(!t.is_spawned());
        t.mark_spawned(true);
        t.mark_healthy(true);
        assert!(t.is_spawned());
        assert!(t.is_available());
        // A lifecycle flag is not proof that a SOCKS handshake completed.
        assert!(matches!(
            t.connect(),
            Err(crate::tor::ConnectError::NotConfigured { .. })
        ));
    }
}
