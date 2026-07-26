//! SNI Whitelisting — approved domestic endpoints for domain fronting
//! and collateral freedom.
//!
//! Under national blackout, Iranian DPI whitelists a small set of domestic
//! SNI values (banks, gov, aparat, digikala, etc). This module stores that
//! whitelist, rotates preferred SNI based on telemetry, and validates that a
//! requested SNI is whitelisted before tunneling.
//!
//! All lists are explicit — no wildcard magic that would accidentally expose
//! non-whitelisted domains.

use parking_lot::RwLock;
use std::collections::HashSet;

/// A whitelisted SNI entry with metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhitelistedSni {
    /// The SNI hostname, e.g. "www.aparat.com"
    pub sni: String,
    /// Category for routing preferences.
    pub category: SniCategory,
    /// Priority: lower = more preferred (more whitelisted / less DPI).
    pub priority: u8,
    /// Whether currently observed as reachable.
    pub reachable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SniCategory {
    Banking,      // SHAPARAK, banking — most whitelisted
    Government,   // gov.ir
    VideoStreaming, // Aparat
    ECommerce,    // Digikala, Torob
    Cdn,          // ArvanCloud, etc
    Edu,
    Other,
}

/// Store of whitelisted SNIs, thread-safe, hot-swappable.
#[derive(Debug)]
pub struct SniWhitelist {
    entries: RwLock<Vec<WhitelistedSni>>,
    domain_set: RwLock<HashSet<String>>,
}

impl SniWhitelist {
    /// Create with Iran's commonly-whitelisted domestic endpoints.
    #[must_use]
    pub fn with_iran_defaults() -> Self {
        let defaults = vec![
            WhitelistedSni { sni: "www.shaparak.ir".into(), category: SniCategory::Banking, priority: 10, reachable: true },
            WhitelistedSni { sni: "cbi.ir".into(), category: SniCategory::Banking, priority: 10, reachable: true },
            WhitelistedSni { sni: "www.aparat.com".into(), category: SniCategory::VideoStreaming, priority: 20, reachable: true },
            WhitelistedSni { sni: "www.digikala.com".into(), category: SniCategory::ECommerce, priority: 20, reachable: true },
            WhitelistedSni { sni: "www.torob.com".into(), category: SniCategory::ECommerce, priority: 25, reachable: true },
            WhitelistedSni { sni: "www.irib.ir".into(), category: SniCategory::Government, priority: 15, reachable: true },
            WhitelistedSni { sni: "www.dolat.ir".into(), category: SniCategory::Government, priority: 15, reachable: true },
            WhitelistedSni { sni: "arvancloud.ir".into(), category: SniCategory::Cdn, priority: 30, reachable: true },
            WhitelistedSni { sni: "www.sharif.edu".into(), category: SniCategory::Edu, priority: 35, reachable: true },
            WhitelistedSni { sni: "cdn.digikala.com".into(), category: SniCategory::Cdn, priority: 30, reachable: true },
        ];
        let set: HashSet<String> = defaults.iter().map(|e| e.sni.clone()).collect();
        Self {
            entries: RwLock::new(defaults),
            domain_set: RwLock::new(set),
        }
    }

    /// Whether SNI is whitelisted.
    #[must_use]
    pub fn is_whitelisted(&self, sni: &str) -> bool {
        self.domain_set.read().contains(sni)
    }

    /// Get best reachable whitelisted SNI for a category, or overall best.
    #[must_use]
    pub fn best_for_category(&self, cat: Option<SniCategory>) -> Option<WhitelistedSni> {
        let entries = self.entries.read();
        let mut candidates: Vec<&WhitelistedSni> = entries.iter().filter(|e| e.reachable).collect();
        if let Some(c) = cat {
            candidates.retain(|e| e.category == c);
            if candidates.is_empty() {
                // fallback to any
                candidates = entries.iter().filter(|e| e.reachable).collect();
            }
        }
        candidates.sort_by_key(|e| e.priority);
        candidates.first().map(|e| (*e).clone())
    }

    /// Mark SNI reachable/unreachable based on probe result.
    pub fn set_reachable(&self, sni: &str, reachable: bool) {
        let mut entries = self.entries.write();
        if let Some(e) = entries.iter_mut().find(|e| e.sni == sni) {
            e.reachable = reachable;
        }
    }

    /// Add custom whitelisted SNI (operator override).
    pub fn add(&self, entry: WhitelistedSni) {
        {
            let mut set = self.domain_set.write();
            set.insert(entry.sni.clone());
        }
        let mut entries = self.entries.write();
        // dedup
        if let Some(pos) = entries.iter().position(|e| e.sni == entry.sni) {
            entries[pos] = entry;
        } else {
            entries.push(entry);
        }
    }

    /// Remove SNI from whitelist.
    pub fn remove(&self, sni: &str) -> bool {
        let mut set = self.domain_set.write();
        let removed_set = set.remove(sni);
        let mut entries = self.entries.write();
        let before = entries.len();
        entries.retain(|e| e.sni != sni);
        removed_set || entries.len() < before
    }

    /// List all whitelisted SNIs, sorted by priority.
    #[must_use]
    pub fn list(&self) -> Vec<WhitelistedSni> {
        let mut v = self.entries.read().clone();
        v.sort_by_key(|e| e.priority);
        v
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }
}

impl Default for SniWhitelist {
    fn default() -> Self {
        Self::with_iran_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_whitelisted() {
        let wl = SniWhitelist::with_iran_defaults();
        assert!(wl.is_whitelisted("www.aparat.com"));
        assert!(wl.is_whitelisted("www.shaparak.ir"));
        assert!(!wl.is_whitelisted("google.com"));
    }

    #[test]
    fn best_sni_selection() {
        let wl = SniWhitelist::with_iran_defaults();
        let banking = wl.best_for_category(Some(SniCategory::Banking)).unwrap();
        assert_eq!(banking.category, SniCategory::Banking);
        assert!(banking.priority <= 15);

        // Mark banking unreachable, should fallback?
        wl.set_reachable("www.shaparak.ir", false);
        wl.set_reachable("cbi.ir", false);
        // best_for_category Banking will fallback to any reachable
        let fallback = wl.best_for_category(Some(SniCategory::Banking)).unwrap();
        assert!(fallback.reachable);
    }

    #[test]
    fn add_remove() {
        let wl = SniWhitelist::with_iran_defaults();
        let before = wl.len();
        wl.add(WhitelistedSni {
            sni: "custom.ir".into(),
            category: SniCategory::Other,
            priority: 50,
            reachable: true,
        });
        assert_eq!(wl.len(), before + 1);
        assert!(wl.is_whitelisted("custom.ir"));
        assert!(wl.remove("custom.ir"));
        assert!(!wl.is_whitelisted("custom.ir"));
    }

    #[test]
    fn reachable_updates() {
        let wl = SniWhitelist::with_iran_defaults();
        wl.set_reachable("www.aparat.com", false);
        let list = wl.list();
        let aparat = list.iter().find(|e| e.sni == "www.aparat.com").unwrap();
        assert!(!aparat.reachable);
    }
}
