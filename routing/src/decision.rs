//! The routing engine: turns a (domain, IP) request into an [`Action`].

use std::net::IpAddr;

use crate::matcher;
use crate::rules::{Action, RuleSet};

/// The routing engine. Immutable after construction; cheap to clone/share.
#[derive(Debug, Clone)]
pub struct Engine {
    rules: RuleSet,
}

/// A routing request: the destination domain and/or IP. Either may be `None`
/// (e.g. a raw-IP connection has no domain).
#[derive(Debug, Clone, Default)]
pub struct Request<'a> {
    pub domain: Option<&'a str>,
    pub ip: Option<IpAddr>,
}

impl Engine {
    /// Build an engine from a rule set. The set MUST already be sorted by
    /// priority ([`RuleSet::sorted`] / [`RuleSet::from_json`] do this).
    pub fn new(rules: RuleSet) -> Self {
        Self { rules }
    }

    /// Decide the action for a request. Categories are scanned in priority
    /// order; the first whose domain OR CIDR rules match wins. If none match,
    /// the rule set's `default_action` is returned.
    pub fn decide(&self, req: &Request<'_>) -> Action {
        for cat in &self.rules.categories {
            let dom_ok = req
                .domain
                .is_some_and(|d| matcher::domain_matches(d, &cat.domains));
            let ip_ok = req.ip.is_some_and(|ip| matcher::ip_matches(ip, &cat.cidrs));
            if dom_ok || ip_ok {
                return cat.action;
            }
        }
        self.rules.default_action
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Category, DomainRule, DomainType};

    fn rs() -> RuleSet {
        RuleSet {
            version: 1,
            default_action: Action::Proxy,
            categories: vec![
                Category {
                    name: "ads".into(),
                    action: Action::Block,
                    priority: 100,
                    domains: vec![DomainRule {
                        ty: DomainType::Keyword,
                        value: "doubleclick".into(),
                    }],
                    cidrs: vec![],
                },
                Category {
                    name: "ir".into(),
                    action: Action::Direct,
                    priority: 50,
                    domains: vec![DomainRule {
                        ty: DomainType::Suffix,
                        value: "ir".into(),
                    }],
                    cidrs: vec!["5.160.0.0/15".parse().unwrap()],
                },
            ],
        }
        .sorted()
    }

    #[test]
    fn ads_block_wins_over_direct_via_priority() {
        let e = Engine::new(rs());
        // Higher-priority ads category beats the ir category.
        assert_eq!(
            e.decide(&Request {
                domain: Some("stats.doubleclick.ir"),
                ip: None
            }),
            Action::Block
        );
    }

    #[test]
    fn ir_domain_is_direct() {
        let e = Engine::new(rs());
        assert_eq!(
            e.decide(&Request {
                domain: Some("service.irancell.ir"),
                ip: None
            }),
            Action::Direct
        );
    }

    #[test]
    fn ir_ip_is_direct_without_domain() {
        let e = Engine::new(rs());
        assert_eq!(
            e.decide(&Request {
                domain: None,
                ip: Some("5.160.1.1".parse().unwrap())
            }),
            Action::Direct
        );
    }

    #[test]
    fn unknown_foreign_is_proxy_by_default() {
        let e = Engine::new(rs());
        assert_eq!(
            e.decide(&Request {
                domain: Some("youtube.com"),
                ip: Some("142.250.0.1".parse().unwrap())
            }),
            Action::Proxy
        );
    }
}
