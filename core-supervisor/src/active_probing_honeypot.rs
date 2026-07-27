//! Active Probing Honeypot — eBPF interception of unauthorized probes
//!
//! Intercepts unauthorized active probing packets via eBPF and redirects them
//! to legitimate domestic endpoints, returning valid HTTP 200/OK web server responses.
//!
//! DPI active probing: censor sends probes to suspected proxy IPs to confirm if they are proxies.
//! If server responds with proxy handshake, it's blocked. REALITY and ShadowTLS defend by
//! forwarding probes to real dest (e.g. digikala) and returning that site's content.
//!
//! This module generalizes: any probe that fails TLS mimicry check gets redirected to honeypot
//! domestic endpoint with valid HTTP 200.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// A domestic endpoint that can serve as honeypot destination
#[derive(Debug, Clone)]
pub struct HoneypotEndpoint {
    pub id: String,
    pub address: String, // e.g. www.digikala.com
    pub sni: String,
    pub http_response: String, // valid HTTP 200 response to return
    pub priority: u8,
    pub healthy: bool,
}

impl HoneypotEndpoint {
    pub fn new(id: &str, address: &str, response: &str) -> Self {
        Self {
            id: id.to_string(),
            address: address.to_string(),
            sni: address.to_string(),
            http_response: response.to_string(),
            priority: 10,
            healthy: true,
        }
    }

    pub fn digikala() -> Self {
        Self {
            id: "digikala".into(),
            address: "www.digikala.com".into(),
            sni: "www.digikala.com".into(),
            http_response: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 15\r\n\r\nDigikala Shop".into(),
            priority: 10,
            healthy: true,
        }
    }

    pub fn aparat() -> Self {
        Self {
            id: "aparat".into(),
            address: "www.aparat.com".into(),
            sni: "www.aparat.com".into(),
            http_response: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nAparat Video".into(),
            priority: 20,
            healthy: true,
        }
    }

    pub fn shaparak() -> Self {
        Self {
            id: "shaparak".into(),
            address: "www.shaparak.ir".into(),
            sni: "www.shaparak.ir".into(),
            http_response:
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"ok\"}"
                    .into(),
            priority: 10,
            healthy: true,
        }
    }
}

/// Probe detection verdict (from TLS mimicry engine)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeVerdict {
    Legitimate,
    Probe,
    Uncertain,
}

/// Honeypot redirect action
#[derive(Debug, Clone)]
pub struct HoneypotAction {
    pub intercepted: bool,
    pub redirected_to: Option<String>,
    pub response: Option<String>,
    pub probe_src: String,
}

/// Active Probing Honeypot Engine
#[derive(Debug)]
pub struct HoneypotEngine {
    endpoints: RwLock<HashMap<String, HoneypotEndpoint>>,
    intercepted_count: AtomicU64,
    legitimate_count: AtomicU64,
}

impl HoneypotEngine {
    #[must_use]
    pub fn new() -> Self {
        let mut map = HashMap::new();
        map.insert("digikala".into(), HoneypotEndpoint::digikala());
        map.insert("aparat".into(), HoneypotEndpoint::aparat());
        map.insert("shaparak".into(), HoneypotEndpoint::shaparak());
        Self {
            endpoints: RwLock::new(map),
            intercepted_count: AtomicU64::new(0),
            legitimate_count: AtomicU64::new(0),
        }
    }

    pub fn add_endpoint(&self, ep: HoneypotEndpoint) {
        self.endpoints.write().insert(ep.id.clone(), ep);
    }

    pub fn set_healthy(&self, id: &str, healthy: bool) {
        if let Some(ep) = self.endpoints.write().get_mut(id) {
            ep.healthy = healthy;
        }
    }

    #[must_use]
    pub fn best_endpoint(&self) -> Option<HoneypotEndpoint> {
        let endpoints = self.endpoints.read();
        let mut candidates: Vec<&HoneypotEndpoint> =
            endpoints.values().filter(|e| e.healthy).collect();
        candidates.sort_by_key(|e| e.priority);
        candidates.first().map(|e| (*e).clone())
    }

    /// Handle incoming connection: verdict from TLS mimicry decides if probe
    pub fn handle_connection(&self, src_ip: &str, verdict: ProbeVerdict) -> HoneypotAction {
        match verdict {
            ProbeVerdict::Legitimate => {
                self.legitimate_count.fetch_add(1, Ordering::Relaxed);
                HoneypotAction {
                    intercepted: false,
                    redirected_to: None,
                    response: None,
                    probe_src: src_ip.to_string(),
                }
            }
            ProbeVerdict::Probe | ProbeVerdict::Uncertain => {
                self.intercepted_count.fetch_add(1, Ordering::Relaxed);
                let ep = self.best_endpoint();
                if let Some(endpoint) = ep {
                    // In real eBPF: bpf_redirect to endpoint's socket, and reply with HTTP 200
                    HoneypotAction {
                        intercepted: true,
                        redirected_to: Some(endpoint.address.clone()),
                        response: Some(endpoint.http_response.clone()),
                        probe_src: src_ip.to_string(),
                    }
                } else {
                    // No healthy endpoint – still intercept but no redirect (drop)
                    HoneypotAction {
                        intercepted: true,
                        redirected_to: None,
                        response: None,
                        probe_src: src_ip.to_string(),
                    }
                }
            }
        }
    }

    #[must_use]
    pub fn stats(&self) -> HoneypotStats {
        HoneypotStats {
            intercepted: self.intercepted_count.load(Ordering::Relaxed),
            legitimate: self.legitimate_count.load(Ordering::Relaxed),
            endpoints: self.endpoints.read().len(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HoneypotStats {
    pub intercepted: u64,
    pub legitimate: u64,
    pub endpoints: usize,
}

impl Default for HoneypotEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legitimate_not_intercepted() {
        let engine = HoneypotEngine::new();
        let action = engine.handle_connection("5.6.7.8", ProbeVerdict::Legitimate);
        assert!(!action.intercepted);
        assert_eq!(action.redirected_to, None);
        assert_eq!(engine.stats().legitimate, 1);
        assert_eq!(engine.stats().intercepted, 0);
    }

    #[test]
    fn probe_intercepted_and_redirected() {
        let engine = HoneypotEngine::new();
        let action = engine.handle_connection("1.2.3.4", ProbeVerdict::Probe);
        assert!(action.intercepted);
        assert!(action.redirected_to.is_some());
        assert!(action.response.is_some());
        assert!(action.response.unwrap().contains("200 OK"));
        assert_eq!(engine.stats().intercepted, 1);
    }

    #[test]
    fn uncertain_also_honeypotted() {
        let engine = HoneypotEngine::new();
        let action = engine.handle_connection("9.9.9.9", ProbeVerdict::Uncertain);
        assert!(action.intercepted);
    }

    #[test]
    fn best_endpoint_priority() {
        let engine = HoneypotEngine::new();
        let best = engine.best_endpoint().unwrap();
        // digikala and shaparak priority 10, aparat 20 -> best should be 10
        assert_eq!(best.priority, 10);
    }

    #[test]
    fn unhealthy_endpoint_not_selected() {
        let engine = HoneypotEngine::new();
        engine.set_healthy("digikala", false);
        engine.set_healthy("shaparak", false);
        let best = engine.best_endpoint().unwrap();
        assert_eq!(best.id, "aparat");
    }

    #[test]
    fn no_healthy_endpoint() {
        let engine = HoneypotEngine::new();
        for id in ["digikala", "aparat", "shaparak"] {
            engine.set_healthy(id, false);
        }
        assert!(engine.best_endpoint().is_none());
        let action = engine.handle_connection("1.2.3.4", ProbeVerdict::Probe);
        assert!(action.intercepted);
        assert!(action.redirected_to.is_none());
    }
}
