//! Data-plane routing integration.
//!
//! This wires the [`aether_routing`] engine into the supervisor: before a core
//! connects a destination, the supervisor asks the [`RouteResolver`] whether the
//! traffic should go [`Action::Direct`] (domestic — bypass the tunnel),
//! [`Action::Proxy`] (foreign — through the tunnel), or [`Action::Block`]
//! (dropped).
//!
//! The resolver is hot-reloadable (an atomic-ish swap under a `RwLock`), so the
//! rule set can be refreshed at runtime without restarting cores — the
//! file-loading and reload capability live HERE (the data plane), not in the
//! routing library, which keeps this non-duplicative.

use std::net::IpAddr;
use std::path::Path;

use parking_lot::RwLock;

use aether_routing::{preset, Action, Engine, Request, RuleSet};

/// A hot-reloadable routing resolver bound to the data plane.
#[derive(Debug)]
pub struct RouteResolver {
    engine: RwLock<Engine>,
}

impl RouteResolver {
    /// Build a resolver from the embedded Iran preset.
    #[must_use]
    pub fn from_preset() -> Self {
        Self::from_ruleset(preset())
    }

    /// Build a resolver from an explicit rule set.
    #[must_use]
    pub fn from_ruleset(rules: RuleSet) -> Self {
        Self {
            engine: RwLock::new(Engine::new(rules)),
        }
    }

    /// Load a resolver from a JSON rule-set file.
    pub fn from_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let rules = RuleSet::from_json(&text)
            .map_err(|e| anyhow::anyhow!("parse routing rule set: {e}"))?;
        Ok(Self::from_ruleset(rules))
    }

    /// Resolve the action for one destination.
    pub fn route(&self, domain: Option<&str>, ip: Option<IpAddr>) -> Action {
        let engine = self.engine.read();
        engine.decide(&Request { domain, ip })
    }

    /// Swap in a fresh rule set at runtime (no restart). Concurrent `route`
    /// callers finish on the old engine; new callers see the new one.
    pub fn reload(&self, rules: RuleSet) {
        let mut engine = self.engine.write();
        *engine = Engine::new(rules);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preset_decisions() {
        let r = RouteResolver::from_preset();
        assert_eq!(r.route(Some("bank.mellat.ir"), None), Action::Direct);
        assert_eq!(r.route(Some("www.youtube.com"), None), Action::Proxy);
        assert_eq!(r.route(Some("stats.doubleclick.net"), None), Action::Block);
        // An Iranian IP with no domain is domestic.
        assert_eq!(
            r.route(None, Some("78.38.5.5".parse().unwrap())),
            Action::Direct
        );
    }

    #[test]
    fn reload_changes_behavior() {
        let r = RouteResolver::from_preset();
        assert_eq!(r.route(Some("www.youtube.com"), None), Action::Proxy);
        // Reload with a rule set that forces youtube.com to Direct.
        let mut rs = preset();
        rs.categories.insert(
            0,
            aether_routing::Category {
                name: "override".into(),
                action: Action::Direct,
                priority: 1000,
                domains: vec![aether_routing::DomainRule {
                    ty: aether_routing::DomainType::Suffix,
                    value: "youtube.com".into(),
                }],
                cidrs: vec![],
            },
        );
        let rs = rs.sorted();
        r.reload(rs);
        assert_eq!(r.route(Some("www.youtube.com"), None), Action::Direct);
    }

    #[test]
    fn from_file_round_trip() {
        let dir = std::env::temp_dir().join("aether_route_resolver_test.json");
        std::fs::write(&dir, serde_json::to_string(&preset()).unwrap()).unwrap();
        let r = RouteResolver::from_file(&dir).unwrap();
        assert_eq!(r.route(Some("service.irancell.ir"), None), Action::Direct);
        std::fs::remove_file(&dir).ok();
    }
}
