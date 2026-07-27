//! Rule-set loading, the [`Updater`] abstraction (auto-update from upstream),
//! and an embedded Iran preset.

use std::fs;
use std::path::Path;

use ipnet::IpNet;

use crate::error::{Result, RoutingError};
use crate::rules::{Action, Category, DomainRule, DomainType, RuleSet};

/// An updater fetches the latest rule set. The production implementation
/// downloads `chocolate4u/Iran-v2ray-rules` (geosite/geoip) and converts it
/// into our [`RuleSet`] JSON; here it is a documented stub so the trait and
/// reload path are wired and testable.
pub trait Updater: Send + Sync {
    /// Fetch the freshest rule set available.
    fn fetch_latest(&self) -> Result<RuleSet>;
}

/// Loads a rule set from a local JSON file (the dev / cached path).
pub struct LocalLoader;

impl LocalLoader {
    /// Read and parse a rule set from `path`.
    pub fn load_path(path: impl AsRef<Path>) -> Result<RuleSet> {
        let text = fs::read_to_string(path)?;
        RuleSet::from_json(&text)
    }
}

/// HTTP-based upstream updater. Not yet implemented (network lives outside the
/// library); returns [`RoutingError::NotImplemented`].
pub struct HttpUpdater {
    upstream_url: String,
}

impl HttpUpdater {
    /// `upstream_url` is the base URL of the Iran-v2ray-rules source.
    #[must_use]
    pub fn new(upstream_url: impl Into<String>) -> Self {
        Self {
            upstream_url: upstream_url.into(),
        }
    }
}

impl Updater for HttpUpdater {
    fn fetch_latest(&self) -> Result<RuleSet> {
        Err(RoutingError::NotImplemented(format!(
            "HTTP fetch + convert from {} (chocolate4u/Iran-v2ray-rules)",
            self.upstream_url
        )))
    }
}

/// An embedded, minimal-but-real Iran-aware rule set. In production this is
/// replaced by the converted upstream data; it is enough to exercise the engine
/// and to ship a sane default policy.
///
/// NOTE: the CIDRs below are a small *sample* of Iranian ranges for the demo;
/// the live data comes from the upstream geoip list.
#[must_use]
pub fn preset() -> RuleSet {
    let parse_cidrs = |list: &[&str]| -> Vec<IpNet> {
        // The preset is static source data, but it must still remain total if
        // somebody edits it incorrectly. Invalid entries are omitted; the
        // matching unit tests pin the expected set so CI catches a bad edit.
        list.iter()
            .filter_map(|value| value.parse::<IpNet>().ok())
            .collect()
    };

    RuleSet {
        version: 1,
        default_action: Action::Proxy,
        categories: vec![
            Category {
                name: "ads".into(),
                action: Action::Block,
                priority: 100,
                domains: vec![
                    d(DomainType::Keyword, "doubleclick"),
                    d(DomainType::Suffix, "adservice"),
                ],
                cidrs: vec![],
            },
            Category {
                name: "ir".into(),
                action: Action::Direct,
                priority: 50,
                domains: vec![
                    d(DomainType::Suffix, "ir"),
                    d(DomainType::Suffix, "i.ir"),
                    d(DomainType::Full, "irancell.ir"),
                ],
                cidrs: parse_cidrs(&[
                    "2.144.0.0/13",
                    "5.160.0.0/15",
                    "31.7.24.0/21",
                    "77.36.0.0/13",
                    "78.38.0.0/15",
                    "91.92.0.0/14",
                    "178.131.0.0/16",
                    "188.159.0.0/16",
                ]),
            },
            Category {
                name: "foreign-media".into(),
                action: Action::Proxy,
                priority: 10,
                domains: vec![
                    d(DomainType::Suffix, "youtube.com"),
                    d(DomainType::Suffix, "googlevideo.com"),
                    d(DomainType::Suffix, "twitter.com"),
                ],
                cidrs: vec![],
            },
        ],
    }
    .sorted()
}

fn d(ty: DomainType, value: &str) -> DomainRule {
    DomainRule {
        ty,
        value: value.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::{Engine, Request};

    #[test]
    fn preset_routes_iran_direct() {
        let e = Engine::new(preset());
        assert_eq!(
            e.decide(&Request {
                domain: Some("bank.mellat.ir"),
                ip: None
            }),
            Action::Direct
        );
        assert_eq!(
            e.decide(&Request {
                domain: None,
                ip: Some("78.38.5.5".parse().unwrap())
            }),
            Action::Direct
        );
    }

    #[test]
    fn preset_keeps_every_declared_iran_cidr() {
        let ir_cidr_count = preset()
            .categories
            .iter()
            .find(|category| category.name == "ir")
            .map_or(0, |category| category.cidrs.len());
        assert_eq!(
            ir_cidr_count, 8,
            "a malformed static CIDR must not silently shrink the preset"
        );
    }

    #[test]
    fn preset_routes_foreign_media_proxy() {
        let e = Engine::new(preset());
        assert_eq!(
            e.decide(&Request {
                domain: Some("www.youtube.com"),
                ip: None
            }),
            Action::Proxy
        );
    }

    #[test]
    fn preset_blocks_ads() {
        let e = Engine::new(preset());
        assert_eq!(
            e.decide(&Request {
                domain: Some("stats.doubleclick.net"),
                ip: None
            }),
            Action::Block
        );
    }

    #[test]
    fn json_round_trip_preserves_decisions() {
        let rs = preset();
        let json = serde_json::to_string(&rs).unwrap();
        let back = RuleSet::from_json(&json).unwrap();
        let e1 = Engine::new(rs);
        let e2 = Engine::new(back);
        for dom in ["bank.mellat.ir", "www.youtube.com", "stats.doubleclick.net"] {
            assert_eq!(
                e1.decide(&Request {
                    domain: Some(dom),
                    ip: None
                }),
                e2.decide(&Request {
                    domain: Some(dom),
                    ip: None
                }),
                "decision diverged after round-trip for {dom}"
            );
        }
    }

    #[test]
    fn local_loader_reads_file() {
        let dir = std::env::temp_dir().join("aether_routing_test.json");
        std::fs::write(&dir, serde_json::to_string(&preset()).unwrap()).unwrap();
        let rs = LocalLoader::load_path(&dir).unwrap();
        assert_eq!(rs.version, 1);
        std::fs::remove_file(&dir).ok();
    }

    #[test]
    fn http_updater_is_documented_stub() {
        let u = HttpUpdater::new("https://example/iran-rules");
        match u.fetch_latest() {
            Err(RoutingError::NotImplemented(_)) => {}
            other => panic!("expected NotImplemented, got {other:?}"),
        }
    }
}
