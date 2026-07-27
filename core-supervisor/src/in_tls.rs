//! TLS in TLS (in-TLS) tunneling — TLS 1.3 inside outer TLS.
//!
//! One of the multi-protocol fallback mechanisms. Inner TLS is camouflaged
//! inside outer TLS to whitelisted SNI. DPI sees only outer SNI (domestic),
//! inner SNI (real dest) is encrypted.

use crate::domain_fronting::{DomainFrontingEngine, FrontingConfig};
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

/// In-TLS session.
#[derive(Debug)]
pub struct InTlsSession {
    pub outer_sni: String,
    pub inner_sni: String,
    pub session_id: String,
    pub established: bool,
    pub bytes_inner: AtomicU64,
    pub bytes_outer: AtomicU64,
}

impl InTlsSession {
    pub fn new(outer_sni: &str, inner_sni: &str, session_id: &str) -> Self {
        Self {
            outer_sni: outer_sni.to_string(),
            inner_sni: inner_sni.to_string(),
            session_id: session_id.to_string(),
            established: false,
            bytes_inner: AtomicU64::new(0),
            bytes_outer: AtomicU64::new(0),
        }
    }

    pub fn mark_established(&mut self) {
        self.established = true;
    }

    pub fn add_bytes(&self, inner: u64, outer: u64) {
        self.bytes_inner.fetch_add(inner, Ordering::Relaxed);
        self.bytes_outer.fetch_add(outer, Ordering::Relaxed);
    }

    #[must_use]
    pub fn overhead_ratio(&self) -> f64 {
        let inner = self.bytes_inner.load(Ordering::Relaxed) as f64;
        let outer = self.bytes_outer.load(Ordering::Relaxed) as f64;
        if inner == 0.0 {
            return 0.0;
        }
        outer / inner
    }
}

/// In-TLS tunnel manager.
#[derive(Debug)]
pub struct InTlsTunnel {
    fronting: DomainFrontingEngine,
    sessions: RwLock<Vec<InTlsSession>>,
    total_sessions: AtomicU64,
}

impl InTlsTunnel {
    #[must_use]
    pub fn new() -> Self {
        Self {
            fronting: DomainFrontingEngine::with_iran_defaults(),
            sessions: RwLock::new(Vec::new()),
            total_sessions: AtomicU64::new(0),
        }
    }

    /// Establish in-TLS tunnel: outer to whitelisted SNI, inner to real dest.
    pub fn establish(&self, real_dest: &str) -> Option<String> {
        let fronted = self.fronting.fronted_handshake(real_dest)?;
        if !fronted.valid {
            return None;
        }
        // Wall clocks can be adjusted before the Unix epoch. That must be an
        // ordinary degraded condition, never a process panic; a zero timestamp
        // still combines with the monotonic session counter below.
        let epoch_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        // Allocate the sequence before constructing the ID so concurrent
        // successful handshakes cannot reuse one even within the same clock tick.
        let sequence = self.total_sessions.fetch_add(1, Ordering::Relaxed);
        let session_id = format!("intls-{:x}-{:x}", epoch_nanos & 0xFFFF_FFFF_FFFF, sequence,);
        let mut session = InTlsSession::new(&fronted.outer_sni, real_dest, &session_id);
        session.mark_established();
        {
            let mut sessions = self.sessions.write();
            sessions.push(session);
        }
        Some(session_id)
    }

    #[must_use]
    pub fn get_session(&self, session_id: &str) -> Option<InTlsSessionSnapshot> {
        let sessions = self.sessions.read();
        sessions
            .iter()
            .find(|s| s.session_id == session_id)
            .map(|s| InTlsSessionSnapshot {
                session_id: s.session_id.clone(),
                outer_sni: s.outer_sni.clone(),
                inner_sni: s.inner_sni.clone(),
                established: s.established,
                bytes_inner: s.bytes_inner.load(Ordering::Relaxed),
                bytes_outer: s.bytes_outer.load(Ordering::Relaxed),
            })
    }

    #[must_use]
    pub fn active_count(&self) -> usize {
        self.sessions
            .read()
            .iter()
            .filter(|s| s.established)
            .count()
    }

    #[must_use]
    pub fn total_sessions(&self) -> u64 {
        self.total_sessions.load(Ordering::Relaxed)
    }

    pub fn add_fronting(&self, cfg: FrontingConfig) {
        self.fronting.add_config(cfg);
    }
}

#[derive(Debug, Clone)]
pub struct InTlsSessionSnapshot {
    pub session_id: String,
    pub outer_sni: String,
    pub inner_sni: String,
    pub established: bool,
    pub bytes_inner: u64,
    pub bytes_outer: u64,
}

impl Default for InTlsTunnel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn establish_intls() {
        let tunnel = InTlsTunnel::new();
        let sid = tunnel.establish("core.example:443").unwrap();
        assert!(!sid.is_empty());
        assert_eq!(tunnel.active_count(), 1);
        let snap = tunnel.get_session(&sid).unwrap();
        assert!(snap.established);
        assert_ne!(snap.outer_sni, snap.inner_sni);
    }

    #[test]
    fn outer_is_whitelisted() {
        let tunnel = InTlsTunnel::new();
        let sid = tunnel.establish("any.real.host").unwrap();
        let snap = tunnel.get_session(&sid).unwrap();
        // Outer SNI must be from whitelist
        let wl = tunnel.fronting.whitelist();
        assert!(wl.is_whitelisted(&snap.outer_sni));
    }

    #[test]
    fn multiple_sessions() {
        let tunnel = InTlsTunnel::new();
        for i in 0..3 {
            tunnel.establish(&format!("host-{i}.example"));
        }
        assert_eq!(tunnel.active_count(), 3);
        assert_eq!(tunnel.total_sessions(), 3);
    }
}

#[cfg(test)]
mod resilience_tests {
    use super::*;

    #[test]
    fn generated_session_ids_remain_distinct_within_one_clock_tick() {
        let tunnel = InTlsTunnel::new();
        let first = tunnel.establish("first.example");
        let second = tunnel.establish("second.example");

        assert!(first.is_some(), "first fronted session must be created");
        assert!(second.is_some(), "second fronted session must be created");
        if let (Some(first), Some(second)) = (first, second) {
            assert_ne!(first, second, "the monotonic sequence prevents ID reuse");
            assert_eq!(tunnel.total_sessions(), 2);
        }
    }
}
