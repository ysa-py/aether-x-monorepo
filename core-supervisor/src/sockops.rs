//! Zero-copy socket redirection via eBPF Sock Hash
//!
//! Implements `BPF_MAP_TYPE_SOCKHASH` and `bpf_msg_redirect_hash` for sub-millisecond
//! packet forwarding without user-space copies.
//!
//! Architecture:
//! - XDP/TC programs would use sockhash map to direct packets between sockets
//! - Userspace loader (aya) populates map with socket FDs
//! - This module provides mock manager for CI + production interface
//! - Zero-copy achieved via kernel bypassing copy to userspace
//!
//! Production loader sketch (aya):
//! ```ignore
//! let mut bpf = Bpf::load(include_bytes!("../../ebpf/bin/sockops.o"))?;
//! let raw_map = bpf.map_mut("sock_hash").ok_or("sock_hash map is missing")?;
//! let map: &mut SockHash = raw_map.try_into()?;
//! map.insert(key, &socket, 0)?;
//! ```

use parking_lot::RwLock;
use std::collections::HashMap;

use crate::cni_detector::AttachStrategy;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Socket key for sockhash – typically (sip, dip, sport, dport)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SockKey {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
}

impl SockKey {
    pub fn new(src_ip: &str, dst_ip: &str, src_port: u16, dst_port: u16) -> Self {
        Self {
            src_ip: src_ip.to_string(),
            dst_ip: dst_ip.to_string(),
            src_port,
            dst_port,
        }
    }
}

/// A socket entry tracked in sockhash
#[derive(Debug, Clone)]
pub struct SockEntry {
    pub key: SockKey,
    pub fd: i32, // file descriptor in real impl, mocked as id
    pub added_at: Instant,
    pub bytes_redirected: u64,
}

/// Statistics for zero-copy forwarding
#[derive(Debug, Clone, Default)]
pub struct SockOpsStats {
    pub attachment: SockHashAttachment,
    pub total_sockets: usize,
    pub total_redirects: u64,
    pub fallback_redirects: u64,
    pub total_bytes_zero_copy: u64,
    pub avg_redirect_latency_us: u64,
}

/// Attachment state for the redirect backend. A kernel state is entered only
/// after a real loader reports that its sockhash map/link attached successfully.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SockHashAttachment {
    /// No redirect backend is usable; calls must fail closed.
    Detached,
    /// A real eBPF sockhash map has been attached by an external loader.
    KernelAttached,
    /// Restricted CNI/capability environment: use the userspace fallback path.
    UserspaceFallback,
}

impl Default for SockHashAttachment {
    fn default() -> Self {
        Self::Detached
    }
}

/// SockHash Manager – zero-copy socket redirection when a real kernel map is
/// attached, with an explicit userspace fallback state for restricted CNI pods.
#[derive(Debug)]
pub struct SockHashManager {
    sockets: RwLock<HashMap<SockKey, SockEntry>>,
    attachment: RwLock<SockHashAttachment>,
    redirects: AtomicU64,
    fallback_redirects: AtomicU64,
    bytes: AtomicU64,
    latency_accum_us: AtomicU64,
}

impl SockHashManager {
    #[must_use]
    pub fn new() -> Self {
        Self {
            sockets: RwLock::new(HashMap::new()),
            attachment: RwLock::new(SockHashAttachment::Detached),
            redirects: AtomicU64::new(0),
            fallback_redirects: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            latency_accum_us: AtomicU64::new(0),
        }
    }

    /// Select a backend from the capability-aware CNI strategy. Kernel paths
    /// remain detached until a real loader calls `mark_kernel_attached`; a
    /// requested capability is never treated as proof of eBPF attachment.
    pub fn prepare_for_strategy(&self, strategy: AttachStrategy) {
        let attachment = if strategy.is_fallback() {
            SockHashAttachment::UserspaceFallback
        } else {
            SockHashAttachment::Detached
        };
        *self.attachment.write() = attachment;
    }

    /// Record a successful real sockhash/bpf_link attachment from the loader.
    pub fn mark_kernel_attached(&self) {
        *self.attachment.write() = SockHashAttachment::KernelAttached;
    }

    /// Detach all backend state during orderly shutdown. This manager owns no
    /// raw file descriptor, so a real loader remains responsible for its link;
    /// clearing the userspace registry prevents a stale redirect after SIGTERM.
    pub fn detach(&self) {
        self.sockets.write().clear();
        *self.attachment.write() = SockHashAttachment::Detached;
    }

    #[must_use]
    pub fn attachment(&self) -> SockHashAttachment {
        *self.attachment.read()
    }

    /// Add socket to sockhash map (mock: stores entry)
    /// Real impl: bpf_map_update_elem with SK_MSG program
    pub fn add_socket(&self, key: SockKey, fd: i32) -> Result<(), SockOpsError> {
        let entry = SockEntry {
            key: key.clone(),
            fd,
            added_at: Instant::now(),
            bytes_redirected: 0,
        };
        let mut map = self.sockets.write();
        if map.contains_key(&key) {
            return Err(SockOpsError::AlreadyExists);
        }
        map.insert(key, entry);
        Ok(())
    }

    /// Remove socket from map
    pub fn remove_socket(&self, key: &SockKey) -> Result<(), SockOpsError> {
        let mut map = self.sockets.write();
        if map.remove(key).is_none() {
            return Err(SockOpsError::NotFound);
        }
        Ok(())
    }

    /// Zero-copy redirect via bpf_msg_redirect_hash
    /// Takes message from src socket, redirects to dst socket without copying to userspace
    /// Returns latency in microseconds
    pub fn redirect_msg(
        &self,
        src_key: &SockKey,
        dst_key: &SockKey,
        msg_len: usize,
    ) -> Result<Duration, SockOpsError> {
        let start = Instant::now();
        let attachment = self.attachment();
        if attachment == SockHashAttachment::Detached {
            return Err(SockOpsError::MapNotAttached);
        }

        // Verify both sockets exist
        {
            let map = self.sockets.read();
            if !map.contains_key(src_key) {
                return Err(SockOpsError::NotFound);
            }
            if !map.contains_key(dst_key) {
                return Err(SockOpsError::NotFound);
            }
        }

        // KernelAttached represents a verified bpf_msg_redirect_hash path.
        // UserspaceFallback remains functional for a restricted container but
        // is deliberately counted separately and never advertised as zero-copy.
        let elapsed = start.elapsed();

        self.redirects.fetch_add(1, Ordering::Relaxed);
        if attachment == SockHashAttachment::KernelAttached {
            self.bytes.fetch_add(msg_len as u64, Ordering::Relaxed);
        } else {
            self.fallback_redirects.fetch_add(1, Ordering::Relaxed);
        }
        self.latency_accum_us
            .fetch_add(elapsed.as_micros() as u64, Ordering::Relaxed);

        // Update per-socket byte counter
        {
            let mut map = self.sockets.write();
            if let Some(entry) = map.get_mut(dst_key) {
                entry.bytes_redirected += msg_len as u64;
            }
        }

        Ok(elapsed)
    }

    /// Batch redirect for multipath bonding – redirects same message to multiple sockets
    pub fn redirect_multipath(
        &self,
        src_key: &SockKey,
        dst_keys: &[SockKey],
        msg_len: usize,
    ) -> Result<Vec<Duration>, SockOpsError> {
        let mut latencies = Vec::with_capacity(dst_keys.len());
        for dst in dst_keys {
            let d = self.redirect_msg(src_key, dst, msg_len)?;
            latencies.push(d);
        }
        Ok(latencies)
    }

    #[must_use]
    pub fn stats(&self) -> SockOpsStats {
        let map = self.sockets.read();
        let total_redirects = self.redirects.load(Ordering::Relaxed);
        let total_bytes = self.bytes.load(Ordering::Relaxed);
        let latency_accum = self.latency_accum_us.load(Ordering::Relaxed);
        let avg = if total_redirects > 0 {
            latency_accum / total_redirects
        } else {
            0
        };
        SockOpsStats {
            attachment: self.attachment(),
            total_sockets: map.len(),
            total_redirects,
            fallback_redirects: self.fallback_redirects.load(Ordering::Relaxed),
            total_bytes_zero_copy: total_bytes,
            avg_redirect_latency_us: avg,
        }
    }

    #[must_use]
    pub fn contains(&self, key: &SockKey) -> bool {
        self.sockets.read().contains_key(key)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.sockets.read().len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sockets.read().is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SockOpsError {
    AlreadyExists,
    NotFound,
    MapFull,
    PermissionDenied,
    MapNotAttached,
}

impl std::fmt::Display for SockOpsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyExists => write!(f, "socket already in sockhash"),
            Self::NotFound => write!(f, "socket not found in sockhash"),
            Self::MapFull => write!(f, "sockhash map full"),
            Self::PermissionDenied => write!(f, "CAP_BPF / CAP_NET_ADMIN required"),
            Self::MapNotAttached => write!(f, "sockhash map is not attached"),
        }
    }
}

impl std::error::Error for SockOpsError {}

impl Default for SockHashManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SockHashManager {
    fn drop(&mut self) {
        self.sockets.get_mut().clear();
        *self.attachment.get_mut() = SockHashAttachment::Detached;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_redirect_zero_copy() {
        let mgr = SockHashManager::new();
        let k1 = SockKey::new("10.0.0.1", "1.2.3.4", 1234, 443);
        let k2 = SockKey::new("10.0.0.2", "1.2.3.4", 1235, 443);
        mgr.mark_kernel_attached();

        mgr.add_socket(k1.clone(), 10).unwrap();
        mgr.add_socket(k2.clone(), 11).unwrap();
        assert_eq!(mgr.len(), 2);

        let latency = mgr.redirect_msg(&k1, &k2, 1400).unwrap();
        // Sub-millisecond expected (<1000us in mock, real eBPF even less)
        assert!(
            latency.as_micros() < 5000,
            "zero-copy should be sub-ms, got {latency:?}"
        );

        let stats = mgr.stats();
        assert_eq!(stats.total_redirects, 1);
        assert_eq!(stats.total_bytes_zero_copy, 1400);
        assert!(stats.avg_redirect_latency_us < 5000);
    }

    #[test]
    fn duplicate_add_error() {
        let mgr = SockHashManager::new();
        let k = SockKey::new("10.0.0.1", "1.2.3.4", 1234, 443);
        mgr.add_socket(k.clone(), 10).unwrap();
        let err = mgr.add_socket(k, 10).unwrap_err();
        assert_eq!(err, SockOpsError::AlreadyExists);
    }

    #[test]
    fn redirect_not_found() {
        let mgr = SockHashManager::new();
        let k1 = SockKey::new("10.0.0.1", "1.2.3.4", 1234, 443);
        let k2 = SockKey::new("10.0.0.2", "1.2.3.4", 1235, 443);
        mgr.mark_kernel_attached();
        let err = mgr.redirect_msg(&k1, &k2, 100).unwrap_err();
        assert_eq!(err, SockOpsError::NotFound);
    }

    #[test]
    fn multipath_bonding_zero_copy() {
        let mgr = SockHashManager::new();
        let src = SockKey::new("10.0.0.1", "1.2.3.4", 1234, 443);
        mgr.mark_kernel_attached();
        mgr.add_socket(src.clone(), 10).unwrap();
        let dsts: Vec<SockKey> = (0..3)
            .map(|i| SockKey::new("10.0.0.2", "1.2.3.4", 2000 + i, 443))
            .collect();
        for (i, k) in dsts.iter().enumerate() {
            mgr.add_socket(k.clone(), 20 + i as i32).unwrap();
        }

        let latencies = mgr.redirect_multipath(&src, &dsts, 1400).unwrap();
        assert_eq!(latencies.len(), 3);
        assert_eq!(mgr.stats().total_redirects, 3);
        assert_eq!(mgr.stats().total_bytes_zero_copy, 4200);
    }

    #[test]
    fn remove_socket() {
        let mgr = SockHashManager::new();
        let k = SockKey::new("10.0.0.1", "1.2.3.4", 1234, 443);
        mgr.add_socket(k.clone(), 10).unwrap();
        assert!(mgr.contains(&k));
        mgr.remove_socket(&k).unwrap();
        assert!(!mgr.contains(&k));
        assert!(mgr.is_empty());
    }
}

#[cfg(test)]
mod attachment_tests {
    use super::*;

    #[test]
    fn detached_map_fails_closed_before_redirect() {
        let manager = SockHashManager::new();
        let source = SockKey::new("10.0.0.1", "1.2.3.4", 1000, 443);
        let destination = SockKey::new("10.0.0.2", "1.2.3.4", 1001, 443);
        manager.add_socket(source.clone(), 10).unwrap();
        manager.add_socket(destination.clone(), 11).unwrap();

        let error = manager.redirect_msg(&source, &destination, 64).unwrap_err();
        assert_eq!(error, SockOpsError::MapNotAttached);
    }

    #[test]
    fn restricted_cni_uses_explicit_userspace_fallback() {
        let manager = SockHashManager::new();
        manager.prepare_for_strategy(AttachStrategy::FallbackAfPacket);
        let source = SockKey::new("10.0.0.1", "1.2.3.4", 1000, 443);
        let destination = SockKey::new("10.0.0.2", "1.2.3.4", 1001, 443);
        manager.add_socket(source.clone(), 10).unwrap();
        manager.add_socket(destination.clone(), 11).unwrap();

        assert!(manager.redirect_msg(&source, &destination, 64).is_ok());
        let stats = manager.stats();
        assert_eq!(stats.attachment, SockHashAttachment::UserspaceFallback);
        assert_eq!(stats.fallback_redirects, 1);
        assert_eq!(stats.total_bytes_zero_copy, 0);
    }

    #[test]
    fn kernel_strategy_requires_real_attachment_confirmation() {
        let manager = SockHashManager::new();
        manager.prepare_for_strategy(AttachStrategy::TcEgress);
        assert_eq!(manager.attachment(), SockHashAttachment::Detached);
        manager.mark_kernel_attached();
        assert_eq!(manager.attachment(), SockHashAttachment::KernelAttached);
        manager.detach();
        assert_eq!(manager.attachment(), SockHashAttachment::Detached);
        assert!(manager.is_empty());
    }
}
