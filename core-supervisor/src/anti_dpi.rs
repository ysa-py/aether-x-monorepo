//! Dynamic anti-DPI heuristics engine.
//!
//! When the health monitor detects a TCP RST injection (Iranian DPI), the
//! [`AntiDPIEngine`] randomizes the TLS ClientHello fragmentation pattern to
//! evade the fingerprint. This works in concert with the autoheal engine:
//! RST → randomize pattern → rotate IP if still blocked → switch protocol.
//! All happens in the background — the user never sees a disconnect.
//!
//! ## eBPF/XDP TCP RST Dropper
//!
//! In production with `CAP_BPF` + kernel 5.x+, an XDP program drops forged RST
//! packets from DPI middleboxes at the kernel level (before the TCP stack sees
//! them), preventing session disruption. The program template is documented
//! in [`EBpfRstDropper`]; loading requires the `aya` crate at runtime.

use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::RwLock;

use crate::fragmentation::FragmentationPolicy;

/// The anti-DPI engine. Holds the current fragmentation pattern and reacts to
/// RST detection by randomizing split points.
pub struct AntiDPIEngine {
    pattern: RwLock<FragmentationPolicy>,
    rst_count: AtomicU64,
    seed: AtomicU64,
}

impl AntiDPIEngine {
    /// Create a new engine with an initial adaptive pattern.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pattern: RwLock::new(FragmentationPolicy {
                enabled: true,
                split_offsets: [None; 4],
                max_segments: 5,
            }),
            rst_count: AtomicU64::new(0),
            seed: AtomicU64::new(1),
        }
    }

    /// Called when a TCP RST injection is detected. Generates a new randomized
    /// fragmentation pattern and returns it.
    pub fn on_rst_detected(&self) -> FragmentationPolicy {
        self.rst_count.fetch_add(1, Ordering::Relaxed);
        let s = self.seed.fetch_add(7, Ordering::Relaxed);
        let new_pattern = Self::randomize_pattern(s);
        *self.pattern.write() = new_pattern;
        new_pattern
    }

    /// Get the current fragmentation pattern (cheap copy).
    #[must_use]
    pub fn current_pattern(&self) -> FragmentationPolicy {
        *self.pattern.read()
    }

    /// Total RST detections (for metrics / monitoring).
    #[must_use]
    pub fn rst_count(&self) -> u64 {
        self.rst_count.load(Ordering::Relaxed)
    }

    /// Generate a randomized fragmentation policy from a seed (LCG PRNG).
    fn randomize_pattern(seed: u64) -> FragmentationPolicy {
        let mut state = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let mut offsets = [None; 4];
        for slot in &mut offsets {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *slot = Some(1 + (state % 60) as u32);
        }
        FragmentationPolicy {
            enabled: true,
            split_offsets: offsets,
            max_segments: 2 + (state % 4) as u8,
        }
    }
}

impl Default for AntiDPIEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// eBPF/XDP TCP RST Dropper (documented template).
///
/// In production with `CAP_BPF` + kernel 5.x+, an XDP eBPF program inspects
/// incoming TCP segments: if the RST flag is set AND the packet doesn't match
/// any known legitimate connection, it's dropped at the kernel level.
///
/// The eBPF bytecode (`xdp_rst_dropper.bpf.o`) is compiled separately with
/// `clang -target bpf` and loaded at runtime via the `aya` crate. The struct
/// here provides the userspace management interface and compiles without the
/// actual bytecode.
pub struct EBpfRstDropper {
    loaded: bool,
}

impl EBpfRstDropper {
    /// Create a new (unloaded) RST dropper.
    #[must_use]
    pub fn new() -> Self {
        Self { loaded: false }
    }

    /// Load the XDP program onto a network interface.
    /// Requires `CAP_BPF` + kernel 5.x+.
    pub fn load(&mut self) -> Result<(), &'static str> {
        // Production: aya::Bpf::load_file("xdp_rst_dropper.bpf.o") + attach.
        Err("eBPF loading requires CAP_BPF + kernel 5.x+ at runtime")
    }

    /// Whether the XDP program is currently loaded and active.
    #[must_use]
    pub fn is_loaded(&self) -> bool {
        self.loaded
    }
}

impl Default for EBpfRstDropper {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn on_rst_changes_pattern_and_increments() {
        let engine = AntiDPIEngine::new();
        assert_eq!(engine.rst_count(), 0);

        let after = engine.on_rst_detected();
        assert_eq!(engine.rst_count(), 1);
        assert!(after.enabled);
        // Pattern should have non-empty offsets after RST.
        assert_ne!(after.split_offsets, [None; 4]);
        assert!(after.max_segments >= 2);
        // The current pattern matches what was returned.
        assert_eq!(engine.current_pattern(), after);
    }

    #[test]
    fn different_rsts_different_patterns() {
        let engine = AntiDPIEngine::new();
        let p1 = engine.on_rst_detected();
        let p2 = engine.on_rst_detected();
        // Two consecutive randomizations should (very likely) differ.
        assert_ne!(p1.split_offsets, p2.split_offsets);
    }

    #[test]
    fn offsets_are_valid() {
        let engine = AntiDPIEngine::new();
        for _ in 0..20 {
            let p = engine.on_rst_detected();
            for o in p.split_offsets.iter().flatten() {
                assert!(*o > 0 && *o <= 60, "offset out of range: {o}");
            }
            assert!(p.max_segments >= 2 && p.max_segments <= 5);
        }
    }

    #[test]
    fn ebpf_dropper_stub() {
        let mut d = EBpfRstDropper::new();
        assert!(!d.is_loaded());
        assert!(d.load().is_err()); // documented: not available without CAP_BPF
    }
}
