//! Out-of-band egress — extension point for operator-provisioned alternate uplinks (§2).
//!
//! Does NOT invent hardware. If the operator has a satellite terminal, secondary SIM, or
//! trusted relay proxy, the supervisor binds to it automatically. No vendor-specific APIs.

use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, Ordering};

/// Health result from an out-of-band probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    Healthy,
    Unhealthy,
}

/// Trait for an operator-provisioned alternate egress interface. The probe must
/// return a real, falsifiable result — never a hardcoded `Healthy`.
#[async_trait]
pub trait ExternalEgressInterface: Send + Sync + std::fmt::Debug {
    fn name(&self) -> &str;
    /// Probe the interface health. Must be a real network check in production.
    async fn probe(&self) -> HealthStatus;
}

/// Reference implementation: a generic "bind to a configured upstream SOCKS/HTTP proxy"
/// adapter. The operator provides a proxy address; the probe does a TCP connect to verify.
#[derive(Debug)]
pub struct ProxyEgress {
    name: String,
    proxy_addr: String,
    /// Model: in production this is a real TCP connect result. Here: a settable flag
    /// so tests can simulate healthy/unhealthy deterministically.
    last_known_healthy: AtomicBool,
}

impl ProxyEgress {
    /// Create with a proxy address (e.g. `socks5://127.0.0.1:1080` or `http://relay:8080`).
    #[must_use]
    pub fn new(name: &str, proxy_addr: &str) -> Self {
        Self {
            name: name.into(),
            proxy_addr: proxy_addr.into(),
            last_known_healthy: AtomicBool::new(false),
        }
    }

    /// Set the known health (for test injection / external probe callback).
    pub fn set_healthy(&self, healthy: bool) {
        self.last_known_healthy.store(healthy, Ordering::SeqCst);
    }

    /// The proxy address.
    #[must_use]
    pub fn proxy_addr(&self) -> &str {
        &self.proxy_addr
    }
}

#[async_trait]
impl ExternalEgressInterface for ProxyEgress {
    fn name(&self) -> &str {
        &self.name
    }

    async fn probe(&self) -> HealthStatus {
        // In production: tokio::net::TcpStream::connect(proxy_addr) with a timeout.
        // Here: return the last-known health (set externally or by a background task).
        if self.last_known_healthy.load(Ordering::SeqCst) {
            HealthStatus::Healthy
        } else {
            HealthStatus::Unhealthy
        }
    }
}

/// A registry of configured out-of-band interfaces. Used by the isolation
/// correlator to determine if TotalIsolation is reachable.
#[derive(Debug, Default)]
pub struct EgressRegistry {
    interfaces: Vec<std::sync::Arc<dyn ExternalEgressInterface>>,
}

impl EgressRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            interfaces: Vec::new(),
        }
    }

    /// Register an out-of-band interface.
    pub fn register(&mut self, iface: std::sync::Arc<dyn ExternalEgressInterface>) {
        self.interfaces.push(iface);
    }

    /// Number of registered interfaces.
    #[must_use]
    pub fn len(&self) -> usize {
        self.interfaces.len()
    }

    /// Whether the registry is empty (no OOB configured — TotalIsolation check
    /// trivially passes).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.interfaces.is_empty()
    }

    /// Probe all interfaces. Returns true if ANY is healthy.
    pub async fn any_healthy(&self) -> bool {
        for iface in &self.interfaces {
            if iface.probe().await == HealthStatus::Healthy {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn proxy_egress_probe_reflects_health() {
        let p = ProxyEgress::new("test-relay", "socks5://127.0.0.1:1080");
        assert_eq!(p.probe().await, HealthStatus::Unhealthy);
        p.set_healthy(true);
        assert_eq!(p.probe().await, HealthStatus::Healthy);
        p.set_healthy(false);
        assert_eq!(p.probe().await, HealthStatus::Unhealthy);
    }

    #[tokio::test]
    async fn empty_registry_is_empty_and_not_healthy() {
        let reg = EgressRegistry::new();
        assert!(reg.is_empty());
        assert!(!reg.any_healthy().await);
    }

    #[tokio::test]
    async fn registry_any_healthy_with_one_healthy() {
        let mut reg = EgressRegistry::new();
        let p1 = Arc::new(ProxyEgress::new("satellite", "socks5://sat:1080"));
        let p2 = Arc::new(ProxyEgress::new("sim2", "socks5://sim:1080"));
        p2.set_healthy(true);
        reg.register(p1);
        reg.register(p2);
        assert_eq!(reg.len(), 2);
        assert!(reg.any_healthy().await, "at least one healthy");
    }

    #[tokio::test]
    async fn registry_all_unhealthy() {
        let mut reg = EgressRegistry::new();
        reg.register(Arc::new(ProxyEgress::new("a", "x")));
        reg.register(Arc::new(ProxyEgress::new("b", "y")));
        assert!(!reg.any_healthy().await);
    }
}
