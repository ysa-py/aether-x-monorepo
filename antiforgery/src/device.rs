//! Device-fingerprint registry with concurrent-connection limiting.
//!
//! Defeats subscription-link sharing/resale: a subscription may be used from at
//! most `max_concurrent` distinct device fingerprints simultaneously. A
//! fingerprint is an opaque, server-computed blob (e.g. hash of UA + keypair +
//! platform) — the client cannot meaningfully rotate it fast enough to evade
//! the limit without also breaking the session.

use std::collections::{HashMap, HashSet};

use crate::error::{AntiForgeryError, Result};

/// Tracks the set of currently-active device fingerprints per subscription.
#[derive(Debug, Default, Clone)]
pub struct DeviceRegistry {
    active: HashMap<String, HashSet<String>>,
}

impl DeviceRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an active device for `subscription_id` if the per-subscription
    /// limit `max_concurrent` is not exceeded. Re-registering an already-active
    /// fingerprint is a no-op success.
    pub fn register(
        &mut self,
        subscription_id: &str,
        fingerprint: &str,
        max_concurrent: usize,
    ) -> Result<()> {
        let set = self.active.entry(subscription_id.to_string()).or_default();
        if set.contains(fingerprint) {
            return Ok(());
        }
        if set.len() >= max_concurrent {
            return Err(AntiForgeryError::DeviceLimit);
        }
        set.insert(fingerprint.to_string());
        Ok(())
    }

    /// Release a device fingerprint (e.g. on clean disconnect). Idempotent.
    pub fn release(&mut self, subscription_id: &str, fingerprint: &str) {
        if let Some(set) = self.active.get_mut(subscription_id) {
            set.remove(fingerprint);
            if set.is_empty() {
                self.active.remove(subscription_id);
            }
        }
    }

    /// Number of currently-active devices for a subscription.
    pub fn active_count(&self, subscription_id: &str) -> usize {
        self.active.get(subscription_id).map_or(0, HashSet::len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_concurrent_limit() {
        let mut r = DeviceRegistry::new();
        assert!(r.register("s1", "fp-a", 2).is_ok());
        assert!(r.register("s1", "fp-b", 2).is_ok());
        assert!(matches!(
            r.register("s1", "fp-c", 2),
            Err(AntiForgeryError::DeviceLimit)
        ));
        assert_eq!(r.active_count("s1"), 2);
    }

    #[test]
    fn re_register_same_device_is_ok() {
        let mut r = DeviceRegistry::new();
        assert!(r.register("s1", "fp-a", 1).is_ok());
        assert!(r.register("s1", "fp-a", 1).is_ok()); // idempotent
        assert_eq!(r.active_count("s1"), 1);
    }

    #[test]
    fn release_frees_a_slot() {
        let mut r = DeviceRegistry::new();
        r.register("s1", "fp-a", 1).unwrap();
        assert!(matches!(
            r.register("s1", "fp-b", 1),
            Err(AntiForgeryError::DeviceLimit)
        ));
        r.release("s1", "fp-a");
        assert!(r.register("s1", "fp-b", 1).is_ok());
    }

    #[test]
    fn subscriptions_are_isolated() {
        let mut r = DeviceRegistry::new();
        r.register("s1", "fp", 1).unwrap();
        // Same fingerprint on a different subscription is independent.
        assert!(r.register("s2", "fp", 1).is_ok());
    }
}
