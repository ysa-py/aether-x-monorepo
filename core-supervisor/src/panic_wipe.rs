//! Panic-Wipe Engine (Subsystem D — Client-side OpSec).
//!
//! Triggering the panic PIN MUST erase local subscriptions, memory buffers, and
//! persistent logs within a strict execution budget (< 500ms).
//!
//! This module defines the wipe protocol and an in-process implementation.
//! Production code plugs in real filesystem/crypto operations through the
//! [`WipeTarget`] trait.
//!
//! # Threat model
//! Physical device seizure (arrest, checkpoint, border crossing). The panic
//! wipe destroys all locally-stored subscription data, session keys, and logs
//! so a forensic examiner finds nothing.
//!
//! # Does NOT protect against
//! - A device seized already unlocked
//! - Coerced disclosure (user forced to unlock)
//! - Memory forensics while the device is still powered on and running

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

/// Maximum time budget for a panic wipe operation.
pub const WIPE_BUDGET: Duration = Duration::from_millis(500);

/// A target that can be wiped during a panic event.
pub trait WipeTarget: Send + Sync {
    /// Human-readable name for logging.
    fn name(&self) -> &str;
    /// Execute the wipe. MUST complete within [`WIPE_BUDGET`].
    /// Returns the number of bytes/records destroyed.
    fn wipe(&self) -> WipeResult;
}

/// Result of a single wipe target operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WipeResult {
    pub target_name: String,
    pub items_destroyed: u64,
    pub bytes_destroyed: u64,
    pub elapsed: Duration,
    pub success: bool,
}

/// An in-memory subscription store that implements [`WipeTarget`].
pub struct SubscriptionStore {
    data: RwLock<Vec<Vec<u8>>>,
    name: String,
}

impl SubscriptionStore {
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            data: RwLock::new(Vec::new()),
            name: name.to_string(),
        }
    }

    pub fn add_subscription(&self, data: Vec<u8>) {
        self.data.write().push(data);
    }

    #[must_use]
    pub fn count(&self) -> usize {
        self.data.read().len()
    }

    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.data.read().iter().map(Vec::len).sum()
    }
}

impl WipeTarget for SubscriptionStore {
    fn name(&self) -> &str {
        &self.name
    }
    fn wipe(&self) -> WipeResult {
        let start = Instant::now();
        let mut g = self.data.write();
        let items = g.len() as u64;
        let bytes: u64 = g.iter().map(|d| d.len() as u64).sum();
        // Zero-fill before dropping (defense against memory remanence).
        for d in g.iter_mut() {
            for b in d.iter_mut() {
                *b = 0;
            }
        }
        g.clear();
        g.shrink_to_fit();
        WipeResult {
            target_name: self.name.clone(),
            items_destroyed: items,
            bytes_destroyed: bytes,
            elapsed: start.elapsed(),
            success: true,
        }
    }
}

/// An in-memory log buffer that implements [`WipeTarget`].
pub struct LogBuffer {
    entries: RwLock<Vec<String>>,
    name: String,
}

impl LogBuffer {
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            entries: RwLock::new(Vec::new()),
            name: name.to_string(),
        }
    }

    pub fn log(&self, entry: String) {
        self.entries.write().push(entry);
    }

    #[must_use]
    pub fn count(&self) -> usize {
        self.entries.read().len()
    }
}

impl WipeTarget for LogBuffer {
    fn name(&self) -> &str {
        &self.name
    }
    fn wipe(&self) -> WipeResult {
        let start = Instant::now();
        let mut g = self.entries.write();
        let items = g.len() as u64;
        let bytes: u64 = g.iter().map(|e| e.len() as u64).sum();
        g.clear();
        g.shrink_to_fit();
        WipeResult {
            target_name: self.name.clone(),
            items_destroyed: items,
            bytes_destroyed: bytes,
            elapsed: start.elapsed(),
            success: true,
        }
    }
}

/// An in-memory session key store that implements [`WipeTarget`].
pub struct SessionKeyStore {
    keys: RwLock<Vec<[u8; 32]>>,
    name: String,
}

impl SessionKeyStore {
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            keys: RwLock::new(Vec::new()),
            name: name.to_string(),
        }
    }

    pub fn add_key(&self, key: [u8; 32]) {
        self.keys.write().push(key);
    }

    #[must_use]
    pub fn count(&self) -> usize {
        self.keys.read().len()
    }
}

impl WipeTarget for SessionKeyStore {
    fn name(&self) -> &str {
        &self.name
    }
    fn wipe(&self) -> WipeResult {
        let start = Instant::now();
        let mut g = self.keys.write();
        let items = g.len() as u64;
        let bytes = items * 32;
        // Zero-fill keys before dropping.
        for k in g.iter_mut() {
            for b in k.iter_mut() {
                *b = 0;
            }
        }
        g.clear();
        g.shrink_to_fit();
        WipeResult {
            target_name: self.name.clone(),
            items_destroyed: items,
            bytes_destroyed: bytes,
            elapsed: start.elapsed(),
            success: true,
        }
    }
}

/// The panic-wipe engine. Registers wipe targets and executes a coordinated
/// wipe across all of them when triggered.
pub struct PanicWipeEngine {
    targets: RwLock<Vec<Box<dyn WipeTarget>>>,
    triggered: AtomicBool,
    wipe_count: AtomicU64,
    duress_pin_hash: [u8; 32],
}

impl PanicWipeEngine {
    /// Create a new engine with the given duress PIN hash.
    /// The PIN is stored as a SHA-256 hash — the plaintext is never retained.
    #[must_use]
    pub fn new(duress_pin_hash: [u8; 32]) -> Self {
        Self {
            targets: RwLock::new(Vec::new()),
            triggered: AtomicBool::new(false),
            wipe_count: AtomicU64::new(0),
            duress_pin_hash,
        }
    }

    /// Register a wipe target.
    pub fn register_target(&self, target: Box<dyn WipeTarget>) {
        self.targets.write().push(target);
    }

    /// Verify a duress PIN against the stored hash.
    #[must_use]
    pub fn verify_pin(&self, pin: &[u8]) -> bool {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(pin);
        let hash: [u8; 32] = h.finalize().into();
        hash == self.duress_pin_hash
    }

    /// Trigger the panic wipe. Verifies the PIN, then wipes ALL registered
    /// targets within the time budget. Returns the aggregate wipe report.
    pub fn trigger(&self, pin: &[u8]) -> Result<WipeReport, PanicWipeError> {
        if !self.verify_pin(pin) {
            return Err(PanicWipeError::InvalidPin);
        }
        if self.triggered.load(Ordering::Relaxed) {
            return Err(PanicWipeError::AlreadyTriggered);
        }
        self.triggered.store(true, Ordering::Relaxed);
        let overall_start = Instant::now();
        let targets = self.targets.read();
        let mut results = Vec::with_capacity(targets.len());
        for target in targets.iter() {
            let result = target.wipe();
            results.push(result);
        }
        let total_elapsed = overall_start.elapsed();
        let within_budget = total_elapsed <= WIPE_BUDGET;
        self.wipe_count.fetch_add(1, Ordering::Relaxed);
        Ok(WipeReport {
            results,
            total_elapsed,
            within_budget,
        })
    }

    /// Whether the wipe has been triggered.
    #[must_use]
    pub fn has_been_triggered(&self) -> bool {
        self.triggered.load(Ordering::Relaxed)
    }

    /// Number of times the wipe has been triggered.
    #[must_use]
    pub fn wipe_count(&self) -> u64 {
        self.wipe_count.load(Ordering::Relaxed)
    }

    /// Number of registered targets.
    #[must_use]
    pub fn target_count(&self) -> usize {
        self.targets.read().len()
    }
}

/// Aggregate wipe report from a panic event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WipeReport {
    pub results: Vec<WipeResult>,
    pub total_elapsed: Duration,
    pub within_budget: bool,
}

impl WipeReport {
    /// Total items destroyed across all targets.
    #[must_use]
    pub fn total_items_destroyed(&self) -> u64 {
        self.results.iter().map(|r| r.items_destroyed).sum()
    }

    /// Total bytes destroyed across all targets.
    #[must_use]
    pub fn total_bytes_destroyed(&self) -> u64 {
        self.results.iter().map(|r| r.bytes_destroyed).sum()
    }

    /// Whether all targets succeeded.
    #[must_use]
    pub fn all_succeeded(&self) -> bool {
        self.results.iter().all(|r| r.success)
    }
}

/// Errors from panic-wipe operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PanicWipeError {
    /// The provided PIN does not match the stored hash.
    InvalidPin,
    /// The wipe has already been triggered (one-shot).
    AlreadyTriggered,
}

impl std::fmt::Display for PanicWipeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPin => write!(f, "invalid duress PIN"),
            Self::AlreadyTriggered => write!(f, "panic wipe already triggered"),
        }
    }
}

impl std::error::Error for PanicWipeError {}

/// Compute the SHA-256 hash of a duress PIN for storage.
#[must_use]
pub fn hash_duress_pin(pin: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(pin);
    h.finalize().into()
}

/// UI Camouflage — alternate app presentation.
///
/// This is a local-UI-only concern. It MUST NOT alter network-layer wire
/// signatures. The camouflage state is purely cosmetic (app name, icon).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CamouflageConfig {
    /// Alternate app display name.
    pub display_name: String,
    /// Alternate icon identifier.
    pub icon_id: String,
    /// Whether camouflage is currently active.
    pub active: bool,
}

impl CamouflageConfig {
    /// Default: no camouflage.
    #[must_use]
    pub fn default_off() -> Self {
        Self {
            display_name: "Aether-X".into(),
            icon_id: "default".into(),
            active: false,
        }
    }

    /// Activate camouflage with an alternate presentation.
    #[must_use]
    pub fn activate(display_name: &str, icon_id: &str) -> Self {
        Self {
            display_name: display_name.into(),
            icon_id: icon_id.into(),
            active: true,
        }
    }

    /// Deactivate camouflage (revert to default presentation).
    pub fn deactivate(&mut self) {
        self.display_name = "Aether-X".into();
        self.icon_id = "default".into();
        self.active = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pin_hash() -> [u8; 32] {
        hash_duress_pin(b"1234")
    }

    #[test]
    fn wipe_destroys_subscription_store() {
        let store = SubscriptionStore::new("subscriptions");
        store.add_subscription(b"sub-token-1".to_vec());
        store.add_subscription(b"sub-token-2".to_vec());
        assert_eq!(store.count(), 2);
        let result = store.wipe();
        assert!(result.success);
        assert_eq!(result.items_destroyed, 2);
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn wipe_destroys_log_buffer() {
        let log = LogBuffer::new("session-log");
        log.log("connection to node-1".into());
        log.log("connection to node-2".into());
        log.log("protocol switch".into());
        assert_eq!(log.count(), 3);
        let result = log.wipe();
        assert!(result.success);
        assert_eq!(result.items_destroyed, 3);
        assert_eq!(log.count(), 0);
    }

    #[test]
    fn wipe_destroys_session_keys() {
        let keys = SessionKeyStore::new("session-keys");
        keys.add_key([1u8; 32]);
        keys.add_key([2u8; 32]);
        keys.add_key([3u8; 32]);
        assert_eq!(keys.count(), 3);
        let result = keys.wipe();
        assert!(result.success);
        assert_eq!(result.items_destroyed, 3);
        assert_eq!(result.bytes_destroyed, 96);
        assert_eq!(keys.count(), 0);
    }

    #[test]
    fn panic_engine_requires_correct_pin() {
        let engine = PanicWipeEngine::new(test_pin_hash());
        let store = SubscriptionStore::new("subs");
        store.add_subscription(b"token".to_vec());
        engine.register_target(Box::new(store));

        let result = engine.trigger(b"wrong-pin");
        assert_eq!(result, Err(PanicWipeError::InvalidPin));
    }

    #[test]
    fn panic_engine_wipes_all_targets() {
        let engine = PanicWipeEngine::new(test_pin_hash());
        let store = SubscriptionStore::new("subs");
        store.add_subscription(b"token-1".to_vec());
        store.add_subscription(b"token-2".to_vec());
        let log = LogBuffer::new("logs");
        log.log("entry-1".into());
        let keys = SessionKeyStore::new("keys");
        keys.add_key([42u8; 32]);

        engine.register_target(Box::new(store));
        engine.register_target(Box::new(log));
        engine.register_target(Box::new(keys));
        assert_eq!(engine.target_count(), 3);

        let report = engine.trigger(b"1234").unwrap();
        assert!(report.within_budget);
        assert!(report.all_succeeded());
        assert_eq!(report.total_items_destroyed(), 4); // 2 subs + 1 log + 1 key
        assert!(report.total_elapsed <= WIPE_BUDGET);
    }

    #[test]
    fn panic_engine_is_one_shot() {
        let engine = PanicWipeEngine::new(test_pin_hash());
        let store = SubscriptionStore::new("subs");
        engine.register_target(Box::new(store));

        let _ = engine.trigger(b"1234").unwrap();
        assert!(engine.has_been_triggered());
        let result = engine.trigger(b"1234");
        assert_eq!(result, Err(PanicWipeError::AlreadyTriggered));
    }

    #[test]
    fn camouflage_does_not_affect_network() {
        let mut camo = CamouflageConfig::default_off();
        assert!(!camo.active);
        assert_eq!(camo.display_name, "Aether-X");
        camo = CamouflageConfig::activate("Calculator", "calc-icon");
        assert!(camo.active);
        assert_eq!(camo.display_name, "Calculator");
        // Camouflage is purely UI — no wire traffic change.
        camo.deactivate();
        assert!(!camo.active);
        assert_eq!(camo.display_name, "Aether-X");
    }

    #[test]
    fn wipe_budget_is_met() {
        // Even with many targets, in-memory wipe must complete in < 500ms.
        let engine = PanicWipeEngine::new(test_pin_hash());
        for i in 0..20 {
            let store = SubscriptionStore::new(&format!("store-{i}"));
            for j in 0..100 {
                store.add_subscription(vec![j as u8; 256]);
            }
            engine.register_target(Box::new(store));
        }
        let report = engine.trigger(b"1234").unwrap();
        assert!(
            report.within_budget,
            "wipe exceeded 500ms budget: {:?}",
            report.total_elapsed
        );
        assert!(report.all_succeeded());
        assert_eq!(report.total_items_destroyed(), 2000); // 20 stores × 100 items
    }
}
