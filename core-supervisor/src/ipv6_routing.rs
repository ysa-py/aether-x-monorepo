//! IPv6 direct routing — bypass via IPv6 when DPI focuses on IPv4.
//!
//! Many DPI deployments in Iran primarily filter IPv4. IPv6 routing
//! often has different rules, less filtering, or no DPI at all.
//! This module provides IPv6 direct routing as fallback.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// IPv6 route entry.
#[derive(Debug, Clone)]
pub struct Ipv6Route {
    pub dest: String,
    pub next_hop: String,
    pub via_interface: String,
    pub latency_ms: u32,
    pub success_rate: f64,
    pub last_checked: Instant,
}

impl Ipv6Route {
    pub fn new(dest: &str, next_hop: &str, iface: &str) -> Self {
        Self {
            dest: dest.to_string(),
            next_hop: next_hop.to_string(),
            via_interface: iface.to_string(),
            latency_ms: 50,
            success_rate: 1.0,
            last_checked: Instant::now(),
        }
    }

    pub fn record_success(&mut self, rtt_ms: u32) {
        self.success_rate = self.success_rate * 0.9 + 0.1;
        self.latency_ms = (self.latency_ms * 9 + rtt_ms) / 10;
        self.last_checked = Instant::now();
    }

    pub fn record_failure(&mut self) {
        self.success_rate *= 0.8;
        self.last_checked = Instant::now();
    }

    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.success_rate > 0.3 && self.last_checked.elapsed() < Duration::from_secs(300)
    }
}

/// IPv6 routing manager.
#[derive(Debug, Default)]
pub struct Ipv6Routing {
    routes: RwLock<HashMap<String, Ipv6Route>>,
}

impl Ipv6Routing {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_route(&self, route: Ipv6Route) {
        let mut routes = self.routes.write();
        routes.insert(route.dest.clone(), route);
    }

    #[must_use]
    pub fn best_route_for(&self, dest: &str) -> Option<Ipv6Route> {
        let routes = self.routes.read();
        // Exact match
        if let Some(r) = routes.get(dest) {
            if r.is_healthy() {
                return Some(r.clone());
            }
        }
        // Prefix match heuristic
        let mut candidates: Vec<&Ipv6Route> = routes.values().filter(|r| r.is_healthy()).collect();
        candidates.sort_by(|a, b| {
            b.success_rate
                .partial_cmp(&a.success_rate)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        candidates.first().map(|r| (*r).clone())
    }

    #[must_use]
    pub fn all_routes(&self) -> Vec<Ipv6Route> {
        self.routes.read().values().cloned().collect()
    }

    pub fn record_success(&self, dest: &str, rtt_ms: u32) {
        if let Some(r) = self.routes.write().get_mut(dest) {
            r.record_success(rtt_ms);
        }
    }

    pub fn record_failure(&self, dest: &str) {
        if let Some(r) = self.routes.write().get_mut(dest) {
            r.record_failure();
        }
    }

    #[must_use]
    pub fn has_ipv6_connectivity(&self) -> bool {
        self.routes.read().values().any(|r| r.is_healthy())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_get_route() {
        let routing = Ipv6Routing::new();
        routing.add_route(Ipv6Route::new("core.example:443", "2001:db8::1", "eth0"));
        let best = routing.best_route_for("core.example:443").unwrap();
        assert_eq!(best.next_hop, "2001:db8::1");
        assert!(best.is_healthy());
    }

    #[test]
    fn failure_makes_unhealthy() {
        let routing = Ipv6Routing::new();
        routing.add_route(Ipv6Route::new("dest", "::1", "lo"));
        for _ in 0..10 {
            routing.record_failure("dest");
        }
        assert!(!routing.has_ipv6_connectivity());
    }

    #[test]
    fn fallback_to_any_healthy() {
        let routing = Ipv6Routing::new();
        routing.add_route(Ipv6Route::new("a", "::1", "eth0"));
        routing.add_route(Ipv6Route::new("b", "::2", "eth0"));
        let best = routing.best_route_for("nonexistent");
        assert!(best.is_some());
    }

    #[test]
    fn success_improves_rate() {
        let mut route = Ipv6Route::new("d", "::1", "eth0");
        route.record_failure();
        let before = route.success_rate;
        route.record_success(20);
        assert!(route.success_rate > before);
    }
}
