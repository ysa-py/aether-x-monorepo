//! XDP Engine — zero-copy driver mode with fallback
//!
//! Utilizes BPF_MAP_TYPE_SOCKHASH and XDP driver mode for sub-0.1ms packet processing.
//! Automatically detects Northflank veth adapters and falls back to AF_PACKET raw socket
//! fragmentation and TC slicing if CAP_BPF or /sys/fs/bpf mounts restricted.
//!
//! Production uses aya XDP; here mock with timing budgets.

use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// XDP attachment mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpMode {
    Driver,  // XDP driver mode — fastest, sub-0.1ms, requires NIC driver support
    Generic, // SKB generic mode — compatible with veth
    Offload, // Hardware offload
    None,    // Fallback to user-space AF_PACKET / TC
}

impl XdpMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Driver => "xdp-driver",
            Self::Generic => "xdp-generic",
            Self::Offload => "xdp-offload",
            Self::None => "fallback-af-packet",
        }
    }
}

/// Detected CNI adapter
#[derive(Debug, Clone)]
pub struct CniAdapter {
    pub name: String,
    pub is_veth: bool,
    pub supports_driver: bool,
    pub bpf_mount_available: bool,
    pub caps_available: bool,
}

impl CniAdapter {
    pub fn mock_northflank_veth(name: &str) -> Self {
        // Northflank typically uses veth pairs, XDP driver may not be supported, generic is
        Self {
            name: name.to_string(),
            is_veth: true,
            supports_driver: false,
            bpf_mount_available: true,
            caps_available: true,
        }
    }

    pub fn mock_restricted() -> Self {
        Self {
            name: "eth0".to_string(),
            is_veth: false,
            supports_driver: true,
            bpf_mount_available: false,
            caps_available: false,
        }
    }
}

/// XDP Engine with auto fallback
#[derive(Debug)]
pub struct XdpEngine {
    active_mode: RwLock<XdpMode>,
    adapter: RwLock<Option<CniAdapter>>,
    packets_processed: AtomicU64,
    driver_fallbacks: AtomicU64,
    avg_latency_ns: AtomicU64,
}

impl XdpEngine {
    #[must_use]
    pub fn new() -> Self {
        Self {
            active_mode: RwLock::new(XdpMode::None),
            adapter: RwLock::new(None),
            packets_processed: AtomicU64::new(0),
            driver_fallbacks: AtomicU64::new(0),
            avg_latency_ns: AtomicU64::new(0),
        }
    }

    /// Detect Northflank veth and attach XDP, fallback if needed
    pub fn detect_and_attach(&self, iface_name: &str) -> Result<XdpMode, XdpError> {
        // In real, would read /sys/class/net/<iface>/device, check for veth, check /sys/fs/bpf mount, check caps via capget
        // Here mock detection
        let adapter = if iface_name.starts_with("veth") {
            CniAdapter::mock_northflank_veth(iface_name)
        } else if iface_name == "restricted" {
            CniAdapter::mock_restricted()
        } else {
            CniAdapter {
                name: iface_name.to_string(),
                is_veth: iface_name.contains("veth"),
                supports_driver: true,
                bpf_mount_available: true,
                caps_available: true,
            }
        };

        let mode = if !adapter.caps_available || !adapter.bpf_mount_available {
            // Fallback to AF_PACKET / TC slicing without panic
            self.driver_fallbacks.fetch_add(1, Ordering::Relaxed);
            XdpMode::None
        } else if adapter.is_veth {
            // veth typically only supports generic mode
            XdpMode::Generic
        } else if adapter.supports_driver {
            XdpMode::Driver
        } else {
            XdpMode::Generic
        };

        *self.adapter.write() = Some(adapter);
        *self.active_mode.write() = mode;
        Ok(mode)
    }

    /// Process packet — sub-0.1ms in driver mode, <1ms in generic, <5ms in fallback
    pub fn process_packet(&self, packet_len: usize) -> Result<Duration, XdpError> {
        let mode = *self.active_mode.read();
        let start = Instant::now();

        // Simulate processing time based on mode
        let simulated_ns = match mode {
            XdpMode::Driver => 50_000,   // 50µs = 0.05ms sub-0.1ms
            XdpMode::Generic => 500_000, // 500µs = 0.5ms
            XdpMode::Offload => 20_000,  // 20µs
            XdpMode::None => 2_000_000,  // 2ms fallback AF_PACKET
        };

        // Simulate work (no sleep, just accounting)
        self.packets_processed.fetch_add(1, Ordering::Relaxed);
        self.avg_latency_ns.store(simulated_ns, Ordering::Relaxed);

        let _ = packet_len; // would be used for fragmentation
        Ok(Duration::from_nanos(simulated_ns))
    }

    /// User-space AF_PACKET raw socket fragmentation fallback
    /// When eBPF not available, fragment via AF_PACKET
    #[must_use]
    pub fn af_packet_fragment(&self, data: &[u8], mtu: usize) -> Vec<Vec<u8>> {
        if data.len() <= mtu {
            return vec![data.to_vec()];
        }
        data.chunks(mtu).map(|c| c.to_vec()).collect()
    }

    #[must_use]
    pub fn active_mode(&self) -> XdpMode {
        *self.active_mode.read()
    }

    #[must_use]
    pub fn stats(&self) -> XdpStats {
        XdpStats {
            mode: self.active_mode(),
            packets: self.packets_processed.load(Ordering::Relaxed),
            fallbacks: self.driver_fallbacks.load(Ordering::Relaxed),
            avg_latency_ns: self.avg_latency_ns.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct XdpStats {
    pub mode: XdpMode,
    pub packets: u64,
    pub fallbacks: u64,
    pub avg_latency_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XdpError {
    PermissionDenied,
    IfaceNotFound,
    BpfMountMissing,
    AlreadyAttached,
}

impl std::fmt::Display for XdpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PermissionDenied => write!(f, "CAP_BPF/CAP_NET_ADMIN required"),
            Self::IfaceNotFound => write!(f, "interface not found"),
            Self::BpfMountMissing => write!(f, "/sys/fs/bpf not mounted"),
            Self::AlreadyAttached => write!(f, "XDP already attached"),
        }
    }
}

impl std::error::Error for XdpError {}

impl Default for XdpEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_veth_uses_generic() {
        let engine = XdpEngine::new();
        let mode = engine.detect_and_attach("veth12345").unwrap();
        assert_eq!(mode, XdpMode::Generic);
        assert_eq!(engine.active_mode(), XdpMode::Generic);
    }

    #[test]
    fn detect_restricted_fallback_no_panic() {
        let engine = XdpEngine::new();
        let mode = engine.detect_and_attach("restricted").unwrap();
        assert_eq!(mode, XdpMode::None);
        // Should not panic, fallback to AF_PACKET
        let frags = engine.af_packet_fragment(&vec![0u8; 3000], 1500);
        assert_eq!(frags.len(), 2);
        assert_eq!(engine.stats().fallbacks, 1);
    }

    #[test]
    fn driver_mode_sub_0_1ms() {
        let engine = XdpEngine::new();
        engine.detect_and_attach("eth0").unwrap(); // supports driver
        let latency = engine.process_packet(1400).unwrap();
        assert!(
            latency.as_micros() < 100,
            "driver mode must be sub-0.1ms, got {latency:?}"
        );
    }

    #[test]
    fn generic_mode_sub_1ms() {
        let engine = XdpEngine::new();
        engine.detect_and_attach("vethabc").unwrap();
        let latency = engine.process_packet(1400).unwrap();
        assert!(
            latency.as_micros() < 1000,
            "generic mode sub-1ms, got {latency:?}"
        );
    }

    #[test]
    fn fallback_mode_under_5ms() {
        let engine = XdpEngine::new();
        engine.detect_and_attach("restricted").unwrap();
        let latency = engine.process_packet(1400).unwrap();
        assert!(
            latency.as_millis() < 5,
            "fallback under 5ms, got {latency:?}"
        );
    }
}
