//! Runtime preflight for the container-facing data plane.
//!
//! A managed Kubernetes runtime may deliberately deny eBPF capabilities or
//! mounting `/sys/fs/bpf`.  That must be a normal operating condition, not a
//! startup failure.  This module observes the *actual* container namespace,
//! chooses the existing CNI attachment strategy, and returns an explicit
//! userspace-fallback decision when kernel acceleration is unavailable.
//!
//! It does not attempt to grant capabilities, mount filesystems, or attach a
//! program by itself. Those operations are platform policy decisions. Keeping
//! the detection and decision side-effect free makes a restricted Northflank
//! workload safe to boot and makes the chosen mode auditable in logs.

use std::fs;
use std::path::Path;

use crate::cni_detector::{AttachStrategy, CapsInfo, CniDetector, CniType};

const CAP_NET_ADMIN: u8 = 12;
const CAP_NET_RAW: u8 = 13;
const CAP_SYS_PTRACE: u8 = 19;
const CAP_SYS_ADMIN: u8 = 21;
const CAP_BPF: u8 = 39;

/// Kernel capabilities effective in the current container namespace.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RuntimeCapabilities {
    /// Required together with `CAP_NET_ADMIN` for eBPF program/map operations.
    pub bpf: bool,
    /// Required for TC/XDP attachment and network configuration.
    pub net_admin: bool,
    /// Required by raw-packet fallback implementations.
    pub net_raw: bool,
    /// Optional; useful for selected observability integrations.
    pub sys_ptrace: bool,
    /// Optional in the data plane; never assumed to be available.
    pub sys_admin: bool,
}

impl RuntimeCapabilities {
    /// Decode Linux `CapEff` from `/proc/self/status`.
    #[must_use]
    pub fn from_effective_mask(mask: u64) -> Self {
        Self {
            bpf: is_set(mask, CAP_BPF),
            net_admin: is_set(mask, CAP_NET_ADMIN),
            net_raw: is_set(mask, CAP_NET_RAW),
            sys_ptrace: is_set(mask, CAP_SYS_PTRACE),
            sys_admin: is_set(mask, CAP_SYS_ADMIN),
        }
    }

    /// Capabilities consumed by the existing CNI strategy selector.
    #[must_use]
    pub fn cni_caps(self) -> CapsInfo {
        CapsInfo {
            cap_bpf: self.bpf,
            cap_net_admin: self.net_admin,
            cap_net_raw: self.net_raw,
            cap_sys_ptrace: self.sys_ptrace,
        }
    }

    /// Whether the kernel-side eBPF attach path is permitted.
    #[must_use]
    pub fn kernel_attach_allowed(self) -> bool {
        self.bpf && self.net_admin
    }
}

/// A truthful, startup-time description of the active data-plane mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePreflight {
    /// Selected interface, if the network namespace exposed one.
    pub interface: Option<String>,
    /// Detected CNI kind for the selected interface.
    pub cni_type: Option<CniType>,
    /// Whether `/sys/fs/bpf` is an actual bpffs mount in this namespace.
    pub bpf_mounted: bool,
    /// Effective capabilities observed from the current process.
    pub capabilities: RuntimeCapabilities,
    /// Strategy selected by the existing CNI policy.
    pub strategy: AttachStrategy,
    /// Non-fatal diagnostics explaining a fallback or a degraded observation.
    pub diagnostics: Vec<String>,
}

impl RuntimePreflight {
    /// Inspect the current Linux container namespace.
    ///
    /// Every inspection error becomes a diagnostic and selects the conservative
    /// userspace strategy. A missing `/proc` or `/sys` therefore cannot panic
    /// or prevent the supervisor from serving its control API.
    #[must_use]
    pub fn inspect() -> Self {
        let mut diagnostics = Vec::new();
        let capabilities = match read_effective_capabilities(Path::new("/proc/self/status")) {
            Ok(caps) => caps,
            Err(error) => {
                diagnostics.push(format!("unable to read effective Linux capabilities: {error}"));
                RuntimeCapabilities::default()
            }
        };
        let bpf_mounted = match read_bpffs_mounted(Path::new("/proc/self/mountinfo")) {
            Ok(mounted) => mounted,
            Err(error) => {
                diagnostics.push(format!("unable to inspect bpffs mount: {error}"));
                false
            }
        };
        let configured = std::env::var("AETHER_CNI_INTERFACE").ok();
        let interface = match discover_interface(
            Path::new("/sys/class/net"),
            configured.as_deref(),
        ) {
            Ok(interface) => interface,
            Err(error) => {
                diagnostics.push(format!("unable to discover CNI interface: {error}"));
                None
            }
        };

        Self::evaluate(interface, capabilities, bpf_mounted, diagnostics)
    }

    /// Determine a strategy from already-observed inputs.
    ///
    /// This seam is intentionally public so an integration test can exercise a
    /// capability-drop scenario without modifying host capabilities.
    #[must_use]
    pub fn evaluate(
        interface: Option<String>,
        capabilities: RuntimeCapabilities,
        bpf_mounted: bool,
        mut diagnostics: Vec<String>,
    ) -> Self {
        let detector = CniDetector::new();
        let (cni_type, strategy) = match interface.as_deref() {
            Some(name) => {
                let info = crate::cni_detector::CniInfo {
                    iface: name.to_string(),
                    cni_type: detector.detect_cni(name),
                    bpf_mount: bpf_mounted,
                    caps: capabilities.cni_caps(),
                };
                let cni_type = info.cni_type.clone();
                let strategy = detector.strategy(&info);
                (Some(cni_type), strategy)
            }
            None => {
                diagnostics.push(
                    "no non-loopback CNI interface found; selecting userspace fallback".to_string(),
                );
                (None, AttachStrategy::FallbackAfPacket)
            }
        };

        if !capabilities.kernel_attach_allowed() {
            diagnostics.push(
                "CAP_BPF and/or CAP_NET_ADMIN is unavailable; kernel acceleration is disabled"
                    .to_string(),
            );
        }
        if !bpf_mounted {
            diagnostics.push(
                "/sys/fs/bpf is not a bpffs mount; kernel acceleration is disabled".to_string(),
            );
        }
        if strategy.is_fallback() {
            diagnostics.push(
                "userspace AF_PACKET/TC fallback selected; no privileged attach will be attempted"
                    .to_string(),
            );
        }

        Self {
            interface,
            cni_type,
            bpf_mounted,
            capabilities,
            strategy,
            diagnostics,
        }
    }

    /// True when the supervisor selected the restricted-container path.
    #[must_use]
    pub fn is_userspace_fallback(&self) -> bool {
        self.strategy.is_fallback()
    }
}

fn is_set(mask: u64, capability: u8) -> bool {
    mask & (1_u64 << u32::from(capability)) != 0
}

fn read_effective_capabilities(status_path: &Path) -> Result<RuntimeCapabilities, std::io::Error> {
    let status = fs::read_to_string(status_path)?;
    let Some(line) = status.lines().find(|line| line.starts_with("CapEff:")) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "CapEff is absent from proc status",
        ));
    };
    let Some(value) = line.split_once(':').map(|(_, value)| value.trim()) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "CapEff has no value",
        ));
    };
    let mask = u64::from_str_radix(value, 16).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid CapEff value: {error}"),
        )
    })?;
    Ok(RuntimeCapabilities::from_effective_mask(mask))
}

fn read_bpffs_mounted(mountinfo_path: &Path) -> Result<bool, std::io::Error> {
    let mountinfo = fs::read_to_string(mountinfo_path)?;
    Ok(bpffs_is_mounted(&mountinfo))
}

fn bpffs_is_mounted(mountinfo: &str) -> bool {
    mountinfo.lines().any(|line| {
        let Some((before_separator, after_separator)) = line.split_once(" - ") else {
            return false;
        };
        let mountpoint = before_separator.split_whitespace().nth(4);
        let fs_type = after_separator.split_whitespace().next();
        mountpoint == Some("/sys/fs/bpf") && fs_type == Some("bpf")
    })
}

fn discover_interface(
    network_dir: &Path,
    configured: Option<&str>,
) -> Result<Option<String>, std::io::Error> {
    if let Some(name) = configured.filter(|name| !name.is_empty()) {
        return Ok(Some(name.to_string()));
    }

    let mut interfaces = Vec::new();
    for entry in fs::read_dir(network_dir)? {
        let entry = entry?;
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if name != "lo" {
            interfaces.push(name);
        }
    }
    interfaces.sort_unstable();

    if let Some(veth) = interfaces.iter().find(|name| name.starts_with("veth")) {
        return Ok(Some(veth.clone()));
    }
    Ok(interfaces.into_iter().next())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_kernel_capabilities_from_effective_mask() {
        let mask = (1_u64 << CAP_BPF)
            | (1_u64 << CAP_NET_ADMIN)
            | (1_u64 << CAP_NET_RAW)
            | (1_u64 << CAP_SYS_PTRACE)
            | (1_u64 << CAP_SYS_ADMIN);
        let caps = RuntimeCapabilities::from_effective_mask(mask);

        assert!(caps.bpf);
        assert!(caps.net_admin);
        assert!(caps.net_raw);
        assert!(caps.sys_ptrace);
        assert!(caps.sys_admin);
        assert!(caps.kernel_attach_allowed());
    }

    #[test]
    fn detects_a_real_bpffs_mount_from_mountinfo() {
        let mountinfo = "36 25 0:31 / /sys/fs/bpf rw,nosuid,nodev,noexec,relatime - bpf bpf rw\n";
        assert!(bpffs_is_mounted(mountinfo));
        assert!(!bpffs_is_mounted("36 25 0:31 / /sys/fs/bpf rw - tmpfs tmpfs rw\n"));
        assert!(!bpffs_is_mounted("malformed mountinfo"));
    }

    #[test]
    fn revoked_bpf_and_net_admin_selects_fallback_without_a_panic() {
        let report = RuntimePreflight::evaluate(
            Some("veth0".to_string()),
            RuntimeCapabilities {
                net_raw: true,
                ..RuntimeCapabilities::default()
            },
            false,
            Vec::new(),
        );

        assert_eq!(report.strategy, AttachStrategy::FallbackAfPacket);
        assert!(report.is_userspace_fallback());
        assert!(report
            .diagnostics
            .iter()
            .any(|message| message.contains("CAP_BPF")));
    }

    #[test]
    fn veth_with_capabilities_uses_tc_instead_of_claiming_xdp_driver() {
        let report = RuntimePreflight::evaluate(
            Some("veth-aether".to_string()),
            RuntimeCapabilities {
                bpf: true,
                net_admin: true,
                ..RuntimeCapabilities::default()
            },
            true,
            Vec::new(),
        );

        assert_eq!(report.cni_type, Some(CniType::Veth));
        assert_eq!(report.strategy, AttachStrategy::TcEgress);
        assert!(!report.is_userspace_fallback());
    }

    #[test]
    fn configured_interface_wins_and_discovery_is_deterministic(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        for name in ["eth0", "veth9", "veth1", "lo"] {
            fs::create_dir(dir.path().join(name))?;
        }

        let automatic = discover_interface(dir.path(), None)?;
        let configured = discover_interface(dir.path(), Some("bond0"))?;
        assert_eq!(automatic.as_deref(), Some("veth1"));
        assert_eq!(configured.as_deref(), Some("bond0"));
        Ok(())
    }
}
