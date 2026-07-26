//! Domain Fronting & SNI whitelisting engine.
//!
//! Implements SNI fronting where the TLS ClientHello SNI is a whitelisted
//! domestic endpoint (e.g. digikala.com) but the HTTP Host header or inner
//! routing points to the real destination. Also supports CDN fronting with
//! front domain ≠ real SNI.
//!
//! This is critical under Blackout Isolation Bounds: domestic SNI values
//! survive DPI, while direct foreign SNI values are blocked.

use crate::sni_whitelist::{SniWhitelist, SniCategory};
use parking_lot::RwLock;
use std::sync::Arc;

/// Domain fronting configuration.
#[derive(Debug, Clone)]
pub struct FrontingConfig {
    /// Front domain visible to DPI (must be whitelisted).
    pub front_sni: String,
    /// Real destination hidden inside encrypted Host header / HTTP/2 :authority
    pub real_host: String,
    /// Optional real SNI for inner TLS (when using in-TLS).
    pub real_sni: Option<String>,
    /// Whether to use HTTP Host header difference method.
    pub use_host_header: bool,
    /// Whether to use CDN-style fronting (Cloudflare, ArvanCloud).
    pub cdn_fronting: bool,
}

impl FrontingConfig {
    pub fn new(front_sni: &str, real_host: &str) -> Self {
        Self {
            front_sni: front_sni.to_string(),
            real_host: real_host.to_string(),
            real_sni: None,
            use_host_header: true,
            cdn_fronting: false,
        }
    }

    pub fn with_real_sni(mut self, real_sni: &str) -> Self {
        self.real_sni = Some(real_sni.to_string());
        self
    }

    pub fn with_cdn(mut self, cdn: bool) -> Self {
        self.cdn_fronting = cdn;
        self
    }
}

/// Result of applying domain fronting to a TLS handshake.
#[derive(Debug, Clone)]
pub struct FrontedHandshake {
    /// Outer SNI to send in ClientHello (whitelisted).
    pub outer_sni: String,
    /// HTTP Host / :authority to send inside encrypted channel.
    pub inner_host: String,
    /// Whether this is considered valid (outer is whitelisted).
    pub valid: bool,
}

/// Domain fronting engine.
#[derive(Debug)]
pub struct DomainFrontingEngine {
    whitelist: Arc<SniWhitelist>,
    active_configs: RwLock<Vec<FrontingConfig>>,
}

impl DomainFrontingEngine {
    #[must_use]
    pub fn new(whitelist: Arc<SniWhitelist>) -> Self {
        Self {
            whitelist,
            active_configs: RwLock::new(Vec::new()),
        }
    }

    #[must_use]
    pub fn with_iran_defaults() -> Self {
        let wl = Arc::new(SniWhitelist::with_iran_defaults());
        let engine = Self::new(wl);
        // Pre-populate with common fronting pairs
        engine.add_config(FrontingConfig::new("www.digikala.com", "aether-x.core.example").with_cdn(false));
        engine.add_config(FrontingConfig::new("www.aparat.com", "aether-x.core.example"));
        engine.add_config(FrontingConfig::new("arvancloud.ir", "aether-x.core.example").with_cdn(true));
        engine.add_config(FrontingConfig::new("www.shaparak.ir", "aether-x.core.example"));
        engine
    }

    pub fn add_config(&self, cfg: FrontingConfig) {
        let mut guard = self.active_configs.write();
        // deduplicate by front_sni
        if let Some(pos) = guard.iter().position(|c| c.front_sni == cfg.front_sni) {
            guard[pos] = cfg;
        } else {
            guard.push(cfg);
        }
    }

    #[must_use]
    pub fn fronted_handshake(&self, desired_real_host: &str) -> Option<FrontedHandshake> {
        let configs = self.active_configs.read();
        // Find config whose real_host matches desired, or pick best reachable whitelist
        let matched = configs.iter().find(|c| c.real_host == desired_real_host);
        let front_sni = if let Some(m) = matched {
            m.front_sni.clone()
        } else {
            // auto-pick best banking or ecommerce SNI
            self.whitelist.best_for_category(Some(SniCategory::Banking))
                .or_else(|| self.whitelist.best_for_category(Some(SniCategory::ECommerce)))
                .or_else(|| self.whitelist.best_for_category(None))?
                .sni
        };

        if !self.whitelist.is_whitelisted(&front_sni) {
            return Some(FrontedHandshake {
                outer_sni: front_sni,
                inner_host: desired_real_host.to_string(),
                valid: false,
            });
        }

        Some(FrontedHandshake {
            outer_sni: front_sni,
            inner_host: desired_real_host.to_string(),
            valid: true,
        })
    }

    /// Validate that a fronting config uses only whitelisted SNIs.
    #[must_use]
    pub fn validate_config(&self, cfg: &FrontingConfig) -> bool {
        self.whitelist.is_whitelisted(&cfg.front_sni)
    }

    /// Rotate to next best front SNI when current is blocked.
    #[must_use]
    pub fn rotate_front(&self, blocked_front: &str) -> Option<FrontingConfig> {
        self.whitelist.set_reachable(blocked_front, false);
        let best = self.whitelist.best_for_category(None)?;
        Some(FrontingConfig::new(&best.sni, "aether-x.core.example"))
    }

    #[must_use]
    pub fn whitelist(&self) -> Arc<SniWhitelist> {
        Arc::clone(&self.whitelist)
    }
}

impl Default for DomainFrontingEngine {
    fn default() -> Self {
        Self::with_iran_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fronting_validates_whitelist() {
        let engine = DomainFrontingEngine::with_iran_defaults();
        let cfg = FrontingConfig::new("www.digikala.com", "real.example");
        assert!(engine.validate_config(&cfg));

        let bad = FrontingConfig::new("google.com", "real.example");
        assert!(!engine.validate_config(&bad));
    }

    #[test]
    fn handshake_uses_whitelisted_sni() {
        let engine = DomainFrontingEngine::with_iran_defaults();
        let hs = engine.fronted_handshake("aether-x.core.example").unwrap();
        assert!(hs.valid);
        assert!(engine.whitelist().is_whitelisted(&hs.outer_sni));
        assert_eq!(hs.inner_host, "aether-x.core.example");
    }

    #[test]
    fn rotate_on_block() {
        let engine = DomainFrontingEngine::with_iran_defaults();
        let first = engine.fronted_handshake("aether-x.core.example").unwrap().outer_sni.clone();
        let rotated = engine.rotate_front(&first).unwrap();
        assert_ne!(rotated.front_sni, first);
        assert!(engine.whitelist().is_whitelisted(&rotated.front_sni));
    }

    #[test]
    fn unknown_host_auto_picks_whitelisted() {
        let engine = DomainFrontingEngine::with_iran_defaults();
        let hs = engine.fronted_handshake("unknown.internal.example").unwrap();
        assert!(hs.valid);
        assert_ne!(hs.outer_sni, "unknown.internal.example");
    }
}
