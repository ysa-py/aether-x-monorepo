//! Rule-set types: actions, domain rules, categories, and the rule set.

use std::cmp::Ordering;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::error::{Result, RoutingError};

/// Routing action for a matched destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Domestic / trusted: bypass the tunnel.
    Direct,
    /// Foreign / blocked: send through the tunnel.
    #[default]
    Proxy,
    /// Ads / malware: drop entirely.
    Block,
}

/// How a domain rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DomainType {
    /// Exact, case-insensitive match.
    Full,
    /// Suffix match: the domain equals `value` or ends with `.value`.
    Suffix,
    /// Substring match.
    Keyword,
}

/// One domain rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainRule {
    #[serde(rename = "type")]
    pub ty: DomainType,
    pub value: String,
}

/// A named category of rules that resolve to a single [`Action`]. Categories are
/// evaluated in `priority` order (higher first); first match wins.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Category {
    pub name: String,
    pub action: Action,
    /// Higher = evaluated first.
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub domains: Vec<DomainRule>,
    #[serde(default)]
    pub cidrs: Vec<IpNet>,
}

/// A versioned, JSON-serializable rule set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSet {
    pub version: u32,
    #[serde(default)]
    pub default_action: Action,
    pub categories: Vec<Category>,
}

impl RuleSet {
    /// Sort categories by descending priority (stable) so the engine can scan
    /// them in evaluation order.
    #[must_use]
    pub fn sorted(mut self) -> Self {
        self.categories.sort_by(|a, b| {
            // Higher priority first; ties keep declaration order (sort_by is stable).
            match b.priority.cmp(&a.priority) {
                Ordering::Equal => Ordering::Equal,
                ord => ord,
            }
        });
        self
    }

    /// Parse a rule set from JSON, sorted and validated.
    pub fn from_json(json: &str) -> Result<Self> {
        let rs: RuleSet = serde_json::from_str(json)?;
        if rs.version == 0 {
            return Err(RoutingError::InvalidRuleSet("version must be > 0".into()));
        }
        Ok(rs.sorted())
    }
}
