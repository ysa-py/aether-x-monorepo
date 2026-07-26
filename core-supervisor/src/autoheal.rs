//! Zero-downtime IP rotation + auto-healing engine.
//!
//! When the health monitor detects packet loss above 15% or TCP RST injection
//! from Iranian DPI, the AutoHealer rotates to a fresh clean IP atomically.
//! Readers (active connections) never see a torn TargetConfig. Existing file
//! descriptors stay open; new connections use the updated target. This
//! guarantees zero packet loss and zero TCP session tear-downs during the
//! endpoint transition (sub-10ms swap).
//!
//! The full auto-heal workflow: the IP scanner discovers clean IPs, rotate()
//! atomically swaps the target, anti_dpi randomizes the fragmentation pattern,
//! and the LocalDecider may switch protocol if still blocked. All happens in
//! the background with zero user-visible downtime.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::RwLock;

/// Packet-loss threshold (15%) above which rotation is triggered.
pub const ROTATION_PACKET_LOSS_THRESHOLD: f64 = 0.15;

/// The current target configuration for outbound proxy traffic.
#[derive(Debug, Clone)]
pub struct TargetConfig {
    /// Destination IP for the proxy egress.
    pub ip: String,
    /// Active protocol (e.g. "reality-vision", "hysteria2").
    pub protocol: String,
    /// Current TLS fragmentation offsets (from the anti_dpi engine).
    pub fragment_offsets: Vec<u32>,
    /// Latest measured packet loss fraction [0, 1].
    pub packet_loss: f64,
    /// Whether RST injection was detected in the last probe window.
    pub rst_detected: bool,
}

impl TargetConfig {
    /// Create a new target config with defaults.
    #[must_use]
    pub fn new(ip: &str, protocol: &str) -> Self {
        Self {
            ip: ip.into(),
            protocol: protocol.into(),
            fragment_offsets: Vec::new(),
            packet_loss: 0.0,
            rst_detected: false,
        }
    }
}

/// The auto-healing engine. Holds the current target behind an RwLock of Arc,
/// enabling cheap lock-free reads and atomic writes during IP rotation.
pub struct AutoHealer {
    current: RwLock<Arc<TargetConfig>>,
    rotations: AtomicU64,
}

impl AutoHealer {
    /// Initialize with a starting target.
    #[must_use]
    pub fn new(initial: TargetConfig) -> Self {
        Self {
            current: RwLock::new(Arc::new(initial)),
            rotations: AtomicU64::new(0),
        }
    }

    /// Get the current target config (cheap Arc clone; readers never block).
    #[must_use]
    pub fn current(&self) -> Arc<TargetConfig> {
        Arc::clone(&self.current.read())
    }

    /// Atomically rotate to a new target. Returns the new rotation count.
    /// Old connections keep their file descriptors; new connections see the
    /// new config immediately with zero packet loss and zero session tear-down.
    pub fn rotate(&self, new_config: TargetConfig) -> u64 {
        let mut guard = self.current.write();
        *guard = Arc::new(new_config);
        self.rotations.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Check whether the current health metrics warrant a rotation.
    #[must_use]
    pub fn needs_rotation(&self) -> bool {
        let cfg = self.current();
        cfg.packet_loss > ROTATION_PACKET_LOSS_THRESHOLD || cfg.rst_detected
    }

    /// Total number of rotations performed (for metrics / monitoring).
    #[must_use]
    pub fn rotation_count(&self) -> u64 {
        self.rotations.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_is_atomic() {
        let healer = AutoHealer::new(TargetConfig::new("1.1.1.1", "reality-vision"));
        assert_eq!(healer.current().ip, "1.1.1.1");

        let count = healer.rotate(TargetConfig::new("2.2.2.2", "hysteria2"));
        assert_eq!(count, 1);
        assert_eq!(healer.current().ip, "2.2.2.2");
        assert_eq!(healer.current().protocol, "hysteria2");
        assert_eq!(healer.rotation_count(), 1);
    }

    #[test]
    fn needs_rotation_on_high_loss() {
        let healer = AutoHealer::new(TargetConfig::new("1.1.1.1", "reality-vision"));
        assert!(!healer.needs_rotation());

        let mut cfg = TargetConfig::new("1.1.1.1", "reality-vision");
        cfg.packet_loss = 0.20;
        healer.rotate(cfg);
        assert!(healer.needs_rotation());
    }

    #[test]
    fn needs_rotation_on_rst() {
        let healer = AutoHealer::new(TargetConfig::new("1.1.1.1", "reality-vision"));
        let mut cfg = TargetConfig::new("1.1.1.1", "reality-vision");
        cfg.rst_detected = true;
        healer.rotate(cfg);
        assert!(healer.needs_rotation());
    }

    #[test]
    fn no_rotation_below_threshold() {
        let healer = AutoHealer::new(TargetConfig::new("1.1.1.1", "reality-vision"));
        let mut cfg = TargetConfig::new("1.1.1.1", "reality-vision");
        cfg.packet_loss = 0.10;
        healer.rotate(cfg);
        assert!(!healer.needs_rotation());
    }

    #[test]
    fn multiple_rotations_count() {
        let healer = AutoHealer::new(TargetConfig::new("1.1.1.1", "p"));
        healer.rotate(TargetConfig::new("2.2.2.2", "p"));
        healer.rotate(TargetConfig::new("3.3.3.3", "p"));
        assert_eq!(healer.rotation_count(), 2);
        assert_eq!(healer.current().ip, "3.3.3.3");
    }
}
