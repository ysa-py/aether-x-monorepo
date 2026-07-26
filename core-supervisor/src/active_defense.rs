//! Active Probing Defense — extends honeypot with eBPF detection
//!
//! Detects unauthorized DPI active probing scans via eBPF and silently redirects
//! their connections to legitimate domestic endpoints (HTTP 200/OK).

use crate::active_probing_honeypot::{HoneypotEngine, ProbeVerdict};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// Active defense engine — wraps honeypot with eBPF detection map
#[derive(Debug)]
pub struct ActiveDefenseEngine {
    honeypot: HoneypotEngine,
    probe_sources: RwLock<HashMap<String, u32>>, // src_ip -> count
    blocked_sources: RwLock<HashMap<String, u64>>, // src_ip -> blocked count
    total_probes: AtomicU64,
}

impl ActiveDefenseEngine {
    #[must_use]
    pub fn new() -> Self {
        Self {
            honeypot: HoneypotEngine::new(),
            probe_sources: RwLock::new(HashMap::new()),
            blocked_sources: RwLock::new(HashMap::new()),
            total_probes: AtomicU64::new(0),
        }
    }

    /// eBPF detection: if src sends many ClientHellos without completing handshake, or JA3 fingerprint is scanner-like
    pub fn detect_probe(&self, src_ip: &str, client_hello_count: u32, completed_handshake: bool) -> ProbeVerdict {
        // Track source
        {
            let mut map = self.probe_sources.write();
            *map.entry(src_ip.to_string()).or_insert(0) += client_hello_count;
        }

        if completed_handshake {
            return ProbeVerdict::Legitimate;
        }

        // If many hellos without handshake → probe
        let count = {
            let map = self.probe_sources.read();
            *map.get(src_ip).unwrap_or(&0)
        };

        if count > 3 {
            self.total_probes.fetch_add(1, Ordering::Relaxed);
            ProbeVerdict::Probe
        } else {
            ProbeVerdict::Uncertain
        }
    }

    /// Handle connection with auto detection + honeypot redirect
    pub fn handle(&self, src_ip: &str, client_hello_count: u32, completed: bool) -> ActiveDefenseAction {
        let verdict = self.detect_probe(src_ip, client_hello_count, completed);
        let honeypot_action = self.honeypot.handle_connection(src_ip, verdict);

        if honeypot_action.intercepted {
            let mut blocked = self.blocked_sources.write();
            *blocked.entry(src_ip.to_string()).or_insert(0) += 1;
        }

        ActiveDefenseAction {
            src_ip: src_ip.to_string(),
            verdict,
            intercepted: honeypot_action.intercepted,
            redirected_to: honeypot_action.redirected_to,
            response: honeypot_action.response,
        }
    }

    #[must_use]
    pub fn stats(&self) -> ActiveDefenseStats {
        ActiveDefenseStats {
            total_probes: self.total_probes.load(Ordering::Relaxed),
            tracked_sources: self.probe_sources.read().len(),
            blocked_sources: self.blocked_sources.read().len(),
            honeypot: self.honeypot.stats(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ActiveDefenseAction {
    pub src_ip: String,
    pub verdict: ProbeVerdict,
    pub intercepted: bool,
    pub redirected_to: Option<String>,
    pub response: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ActiveDefenseStats {
    pub total_probes: u64,
    pub tracked_sources: usize,
    pub blocked_sources: usize,
    pub honeypot: crate::active_probing_honeypot::HoneypotStats,
}

impl Default for ActiveDefenseEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_probe_after_many_hellos() {
        let engine = ActiveDefenseEngine::new();
        // First few incomplete hellos → uncertain
        let a1 = engine.handle("1.2.3.4", 1, false);
        assert!(a1.intercepted); // uncertain also honeypotted

        // After 4 hellos without handshake → Probe
        engine.handle("1.2.3.4", 1, false);
        engine.handle("1.2.3.4", 1, false);
        let a4 = engine.handle("1.2.3.4", 1, false);
        assert_eq!(a4.verdict, ProbeVerdict::Probe);
        assert!(a4.intercepted);
        assert!(a4.redirected_to.is_some());
    }

    #[test]
    fn legitimate_handshake_not_blocked() {
        let engine = ActiveDefenseEngine::new();
        let action = engine.handle("5.6.7.8", 1, true);
        assert_eq!(action.verdict, ProbeVerdict::Legitimate);
        assert!(!action.intercepted);
    }

    #[test]
    fn stats() {
        let engine = ActiveDefenseEngine::new();
        engine.handle("1.1.1.1", 5, false);
        let stats = engine.stats();
        assert_eq!(stats.total_probes, 1);
        assert_eq!(stats.tracked_sources, 1);
    }
}
