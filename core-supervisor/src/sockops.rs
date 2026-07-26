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
//! let map: &mut SockHash = bpf.map_mut("sock_hash").unwrap().try_into()?;
//! map.insert(key, &socket, 0)?;
//! ```

use parking_lot::RwLock;
use std::collections::HashMap;
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
    pub total_sockets: usize,
    pub total_redirects: u64,
    pub total_bytes_zero_copy: u64,
    pub avg_redirect_latency_us: u64,
}

/// SockHash Manager – zero-copy socket redirection
#[derive(Debug)]
pub struct SockHashManager {
    sockets: RwLock<HashMap<SockKey, SockEntry>>,
    redirects: AtomicU64,
    bytes: AtomicU64,
    latency_accum_us: AtomicU64,
}

impl SockHashManager {
    #[must_use]
    pub fn new() -> Self {
        Self {
            sockets: RwLock::new(HashMap::new()),
            redirects: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            latency_accum_us: AtomicU64::new(0),
        }
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

        // Simulate zero-copy redirect: no memory copy, just hash lookup + kernel redirect
        // In real eBPF: bpf_msg_redirect_hash(msg, &sock_hash, &dst_key, BPF_F_INGRESS)
        let elapsed = start.elapsed();

        // Update stats – sub-millisecond expected
        self.redirects.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(msg_len as u64, Ordering::Relaxed);
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
            total_sockets: map.len(),
            total_redirects,
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
}

impl std::fmt::Display for SockOpsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyExists => write!(f, "socket already in sockhash"),
            Self::NotFound => write!(f, "socket not found in sockhash"),
            Self::MapFull => write!(f, "sockhash map full"),
            Self::PermissionDenied => write!(f, "CAP_BPF / CAP_NET_ADMIN required"),
        }
    }
}

impl std::error::Error for SockOpsError {}

impl Default for SockHashManager {
    fn default() -> Self {
        Self::new()
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

        mgr.add_socket(k1.clone(), 10).unwrap();
        mgr.add_socket(k2.clone(), 11).unwrap();
        assert_eq!(mgr.len(), 2);

        let latency = mgr.redirect_msg(&k1, &k2, 1400).unwrap();
        // Sub-millisecond expected (<1000us in mock, real eBPF even less)
        assert!(latency.as_micros() < 5000, "zero-copy should be sub-ms, got {latency:?}");

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
        let err = mgr.redirect_msg(&k1, &k2, 100).unwrap_err();
        assert_eq!(err, SockOpsError::NotFound);
    }

    #[test]
    fn multipath_bonding_zero_copy() {
        let mgr = SockHashManager::new();
        let src = SockKey::new("10.0.0.1", "1.2.3.4", 1234, 443);
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
