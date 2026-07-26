//! DNS-over-HTTPS (DoH) tunneling — last-resort transport riding surviving DNS.
//!
//! Under Escalated blackout where international IP routing is cut but DNS
//! still resolves internationally, DoH tunneling encapsulates data inside
//! DNS queries over HTTPS. VayDNS/NoizDNS already implement DoH,
//! this module provides the generic DoH transport abstraction and
//! optimized heuristics.
//!
//! Survives when DPI blocks direct TLS SNI but allows DoH to known resolvers.

use parking_lot::RwLock;
use std::time::{Duration, Instant};

/// DoH resolver (whitelisted, known to survive Iranian DPI).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DohResolver {
    pub url: String, // e.g. https://dns.google/dns-query
    pub ips: Vec<String>,
    pub priority: u8,
    pub reachable: bool,
}

impl DohResolver {
    pub fn new(url: &str, ips: Vec<&str>, priority: u8) -> Self {
        Self {
            url: url.to_string(),
            ips: ips.into_iter().map(|s| s.to_string()).collect(),
            priority,
            reachable: true,
        }
    }
}

/// DoH tunnel endpoint.
#[derive(Debug)]
pub struct DoHTunnel {
    resolvers: RwLock<Vec<DohResolver>>,
    active_resolver: RwLock<Option<String>>,
    bytes_tunneled: std::sync::atomic::AtomicU64,
    query_count: std::sync::atomic::AtomicU64,
}

impl DoHTunnel {
    #[must_use]
    pub fn with_iran_resilient_resolvers() -> Self {
        let resolvers = vec![
            DohResolver::new("https://dns.google/dns-query", vec!["8.8.8.8", "8.8.4.4"], 10),
            DohResolver::new("https://cloudflare-dns.com/dns-query", vec!["1.1.1.1", "1.0.0.1"], 15),
            DohResolver::new("https://dns.quad9.net/dns-query", vec!["9.9.9.9"], 20),
            DohResolver::new("https://doh.opendns.com/dns-query", vec!["208.67.222.222"], 25),
            // Domestic resolvers that may survive intranet-only
            DohResolver::new("https://dns.arvancloud.ir/dns-query", vec!["185.143.232.0"], 30),
        ];
        Self {
            resolvers: RwLock::new(resolvers),
            active_resolver: RwLock::new(None),
            bytes_tunneled: std::sync::atomic::AtomicU64::new(0),
            query_count: std::sync::atomic::AtomicU64::new(0),
        }
    }

    #[must_use]
    pub fn best_resolver(&self) -> Option<DohResolver> {
        let resolvers = self.resolvers.read();
        let mut candidates: Vec<&DohResolver> = resolvers.iter().filter(|r| r.reachable).collect();
        candidates.sort_by_key(|r| r.priority);
        candidates.first().map(|r| (*r).clone())
    }

    pub fn mark_reachable(&self, url: &str, reachable: bool) {
        let mut resolvers = self.resolvers.write();
        if let Some(r) = resolvers.iter_mut().find(|r| r.url == url) {
            r.reachable = reachable;
            if !reachable {
                let mut active = self.active_resolver.write();
                if active.as_deref() == Some(url) {
                    *active = None;
                }
            }
        }
    }

    /// Simulate tunneling data via DoH: encode as base32 DNS label, chunk.
    #[must_use]
    pub fn tunnel_data(&self, data: &[u8]) -> Vec<String> {
        // Each DNS query can carry ~63 chars label * ~4 labels ~ 200 bytes after base32
        // Chunk data into 150-byte pieces, base32 encode
        let resolver = self.best_resolver();
        let resolver_url = resolver.map(|r| r.url).unwrap_or_else(|| "https://dns.google/dns-query".to_string());
        {
            let mut active = self.active_resolver.write();
            *active = Some(resolver_url.clone());
        }

        self.bytes_tunneled.fetch_add(data.len() as u64, std::sync::atomic::Ordering::Relaxed);
        self.query_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        data.chunks(150)
            .enumerate()
            .map(|(i, chunk)| {
                let b32 = base32_encode(chunk);
                format!("{i}-{b32}.tunnel.aether-x.example")
            })
            .collect()
    }

    #[must_use]
    pub fn bytes_tunneled(&self) -> u64 {
        self.bytes_tunneled.load(std::sync::atomic::Ordering::Relaxed)
    }

    #[must_use]
    pub fn query_count(&self) -> u64 {
        self.query_count.load(std::sync::atomic::Ordering::Relaxed)
    }

    #[must_use]
    pub fn active_resolver_url(&self) -> Option<String> {
        self.active_resolver.read().clone()
    }
}

impl Default for DoHTunnel {
    fn default() -> Self {
        Self::with_iran_resilient_resolvers()
    }
}

/// Simple base32 encode (RFC 4648) without padding for DNS labels.
fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::new();
    let mut buffer: u32 = 0;
    let mut bits_left: u8 = 0;

    for &b in data {
        buffer = (buffer << 8) | b as u32;
        bits_left += 8;
        while bits_left >= 5 {
            bits_left -= 5;
            let idx = ((buffer >> bits_left) & 0x1F) as usize;
            out.push(ALPHABET[idx] as char);
        }
    }
    if bits_left > 0 {
        let idx = ((buffer << (5 - bits_left)) & 0x1F) as usize;
        out.push(ALPHABET[idx] as char);
    }
    out
}

/// Estimate throughput of DoH tunnel (conservative, real censored path).
#[must_use]
pub fn estimate_doh_throughput_kbps(rtt_ms: u32, loss_rate: f64) -> f64 {
    // Each DNS query ~200 bytes payload + overhead ~ 500 bytes wire
    // QPS limited by RTT: 1000/rtt * (1-loss)
    let qps = (1000.0 / rtt_ms.max(1) as f64) * (1.0 - loss_rate).max(0.0);
    let bytes_per_query = 150.0; // usable
    (qps * bytes_per_query * 8.0) / 1000.0 // kbps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolvers_sorted() {
        let tun = DoHTunnel::with_iran_resilient_resolvers();
        let best = tun.best_resolver().unwrap();
        assert_eq!(best.priority, 10);
        assert!(best.url.contains("google"));
    }

    #[test]
    fn mark_unreachable_fallback() {
        let tun = DoHTunnel::with_iran_resilient_resolvers();
        tun.mark_reachable("https://dns.google/dns-query", false);
        let best = tun.best_resolver().unwrap();
        assert_ne!(best.url, "https://dns.google/dns-query");
    }

    #[test]
    fn tunnel_data_chunks() {
        let tun = DoHTunnel::with_iran_resilient_resolvers();
        let data = vec![0u8; 400]; // 400 bytes -> 3 chunks of 150
        let queries = tun.tunnel_data(&data);
        assert_eq!(queries.len(), 3);
        for q in &queries {
            assert!(q.ends_with(".tunnel.aether-x.example"));
        }
        assert_eq!(tun.bytes_tunneled(), 400);
        assert_eq!(tun.query_count(), 1);
    }

    #[test]
    fn base32_roundtrip_len() {
        let data = b"hello";
        let encoded = base32_encode(data);
        assert!(!encoded.is_empty());
        // all chars are valid base32 lower
        for c in encoded.chars() {
            assert!(c.is_ascii_lowercase() || c.is_ascii_digit());
        }
    }

    #[test]
    fn throughput_estimate() {
        let kbps = estimate_doh_throughput_kbps(100, 0.0);
        assert!(kbps > 1.0 && kbps < 100.0, "kbps {kbps} unrealistic");
        let high_loss = estimate_doh_throughput_kbps(100, 0.9);
        assert!(high_loss < kbps);
    }

    #[test]
    fn active_resolver_tracking() {
        let tun = DoHTunnel::with_iran_resilient_resolvers();
        assert!(tun.active_resolver_url().is_none());
        tun.tunnel_data(b"test");
        assert!(tun.active_resolver_url().is_some());
    }
}
