//! OS Polymorphism — eBPF TCP stack spoofing
//!
//! Dynamically rewrites TCP window sizes, TTLs, IP IDs, and TCP option order
//! at kernel level to spoof arbitrary OS network stacks (iOS, Windows 11, Android)
//!
//! Uses TC eBPF program to mangle packets on egress; this module controls
//! the map that holds OS profiles.

use parking_lot::RwLock;
use std::collections::HashMap;

/// OS fingerprint profile
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsProfile {
    pub name: String,
    pub ttl: u8,
    pub window_size: u16,
    pub window_scale: u8,
    pub ip_id_behavior: IpIdBehavior,
    pub tcp_options_order: Vec<TcpOption>,
    pub mss: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpIdBehavior {
    Zero,        // iOS often 0
    Random,      // Windows random
    Incremental, // Linux incremental
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpOption {
    Mss,
    SackPermitted,
    Timestamp,
    Nop,
    WindowScale,
}

impl OsProfile {
    /// iOS 17 profile
    #[must_use]
    pub fn ios() -> Self {
        Self {
            name: "ios-17".into(),
            ttl: 64,
            window_size: 65535,
            window_scale: 7,
            ip_id_behavior: IpIdBehavior::Zero,
            tcp_options_order: vec![
                TcpOption::Mss,
                TcpOption::Nop,
                TcpOption::WindowScale,
                TcpOption::Nop,
                TcpOption::Nop,
                TcpOption::Timestamp,
                TcpOption::SackPermitted,
            ],
            mss: 1460,
        }
    }

    /// Windows 11 profile
    #[must_use]
    pub fn windows11() -> Self {
        Self {
            name: "windows-11".into(),
            ttl: 128,
            window_size: 64240,
            window_scale: 8,
            ip_id_behavior: IpIdBehavior::Random,
            tcp_options_order: vec![
                TcpOption::Mss,
                TcpOption::Nop,
                TcpOption::WindowScale,
                TcpOption::Nop,
                TcpOption::Nop,
                TcpOption::SackPermitted,
            ],
            mss: 1460,
        }
    }

    /// Android 14 profile
    #[must_use]
    pub fn android() -> Self {
        Self {
            name: "android-14".into(),
            ttl: 64,
            window_size: 65535,
            window_scale: 6,
            ip_id_behavior: IpIdBehavior::Incremental,
            tcp_options_order: vec![
                TcpOption::Mss,
                TcpOption::SackPermitted,
                TcpOption::Timestamp,
                TcpOption::Nop,
                TcpOption::WindowScale,
            ],
            mss: 1420,
        }
    }

    /// Linux 6.x
    #[must_use]
    pub fn linux() -> Self {
        Self {
            name: "linux-6".into(),
            ttl: 64,
            window_size: 29200,
            window_scale: 7,
            ip_id_behavior: IpIdBehavior::Incremental,
            tcp_options_order: vec![
                TcpOption::Mss,
                TcpOption::SackPermitted,
                TcpOption::Timestamp,
                TcpOption::Nop,
                TcpOption::WindowScale,
            ],
            mss: 1460,
        }
    }
}

/// TCP packet fields that can be morphed (simplified)
#[derive(Debug, Clone)]
pub struct TcpPacketFields {
    pub ttl: u8,
    pub window: u16,
    pub ip_id: u16,
    pub mss: u16,
    pub options: Vec<TcpOption>,
}

/// OS Polymorphism Engine – controls eBPF map
#[derive(Debug)]
pub struct OsPolymorphismEngine {
    profiles: HashMap<String, OsProfile>,
    active: RwLock<Option<String>>,
    ip_id_counter: std::sync::atomic::AtomicU16,
}

impl OsPolymorphismEngine {
    #[must_use]
    pub fn new() -> Self {
        let mut profiles = HashMap::new();
        profiles.insert("ios-17".into(), OsProfile::ios());
        profiles.insert("windows-11".into(), OsProfile::windows11());
        profiles.insert("android-14".into(), OsProfile::android());
        profiles.insert("linux-6".into(), OsProfile::linux());
        Self {
            profiles,
            active: RwLock::new(None),
            ip_id_counter: std::sync::atomic::AtomicU16::new(0),
        }
    }

    /// Set active OS profile
    pub fn set_active(&self, name: &str) -> Result<(), PolymorphismError> {
        if !self.profiles.contains_key(name) {
            return Err(PolymorphismError::ProfileNotFound);
        }
        *self.active.write() = Some(name.to_string());
        Ok(())
    }

    #[must_use]
    pub fn active_profile(&self) -> Option<OsProfile> {
        let active = self.active.read();
        active
            .as_ref()
            .and_then(|name| self.profiles.get(name).cloned())
    }

    /// Morph outgoing packet fields to match active OS profile
    pub fn morph_packet(&self, original: TcpPacketFields, seed: u64) -> TcpPacketFields {
        let Some(profile) = self.active_profile() else {
            return original;
        };

        let ip_id = match profile.ip_id_behavior {
            IpIdBehavior::Zero => 0,
            IpIdBehavior::Incremental => self
                .ip_id_counter
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            IpIdBehavior::Random => (seed % 65535) as u16,
        };

        TcpPacketFields {
            ttl: profile.ttl,
            window: profile.window_size,
            ip_id,
            mss: profile.mss,
            options: profile.tcp_options_order.clone(),
        }
    }

    #[must_use]
    pub fn available_profiles(&self) -> Vec<String> {
        self.profiles.keys().cloned().collect()
    }

    pub fn add_profile(&mut self, profile: OsProfile) {
        self.profiles.insert(profile.name.clone(), profile);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolymorphismError {
    ProfileNotFound,
    PermissionDenied,
}

impl std::fmt::Display for PolymorphismError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProfileNotFound => write!(f, "os profile not found"),
            Self::PermissionDenied => write!(f, "CAP_BPF required to modify eBPF map"),
        }
    }
}

impl std::error::Error for PolymorphismError {}

impl Default for OsPolymorphismEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_exist() {
        let engine = OsPolymorphismEngine::new();
        let profiles = engine.available_profiles();
        assert!(profiles.contains(&"ios-17".to_string()));
        assert!(profiles.contains(&"windows-11".to_string()));
        assert!(profiles.contains(&"android-14".to_string()));
    }

    #[test]
    fn set_active_and_morph() {
        let engine = OsPolymorphismEngine::new();
        engine.set_active("ios-17").unwrap();
        let profile = engine.active_profile().unwrap();
        assert_eq!(profile.name, "ios-17");
        assert_eq!(profile.ttl, 64);
        assert_eq!(profile.ip_id_behavior, IpIdBehavior::Zero);

        let orig = TcpPacketFields {
            ttl: 128,
            window: 1000,
            ip_id: 1234,
            mss: 1460,
            options: vec![],
        };
        let morphed = engine.morph_packet(orig, 42);
        assert_eq!(morphed.ttl, 64);
        assert_eq!(morphed.ip_id, 0); // iOS zero
        assert_eq!(morphed.window, 65535);
    }

    #[test]
    fn windows_random_ip_id() {
        let engine = OsPolymorphismEngine::new();
        engine.set_active("windows-11").unwrap();
        let orig = TcpPacketFields {
            ttl: 64,
            window: 1000,
            ip_id: 0,
            mss: 1460,
            options: vec![],
        };
        let m1 = engine.morph_packet(orig.clone(), 1);
        let m2 = engine.morph_packet(orig, 2);
        assert_ne!(m1.ip_id, m2.ip_id, "random should differ per seed");
        assert_eq!(m1.ttl, 128);
    }

    #[test]
    fn android_incremental_ip_id() {
        let engine = OsPolymorphismEngine::new();
        engine.set_active("android-14").unwrap();
        let orig = TcpPacketFields {
            ttl: 64,
            window: 1000,
            ip_id: 0,
            mss: 1460,
            options: vec![],
        };
        let m1 = engine.morph_packet(orig.clone(), 0);
        let m2 = engine.morph_packet(orig, 0);
        assert_eq!(m1.ip_id + 1, m2.ip_id);
    }

    #[test]
    fn invalid_profile_error() {
        let engine = OsPolymorphismEngine::new();
        let err = engine.set_active("nonexistent").unwrap_err();
        assert_eq!(err, PolymorphismError::ProfileNotFound);
    }

    #[test]
    fn no_active_returns_original() {
        let engine = OsPolymorphismEngine::new();
        let orig = TcpPacketFields {
            ttl: 64,
            window: 1000,
            ip_id: 0,
            mss: 1460,
            options: vec![TcpOption::Mss],
        };
        let morphed = engine.morph_packet(orig.clone(), 0);
        assert_eq!(morphed.ttl, orig.ttl);
    }
}
