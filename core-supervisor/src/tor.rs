//! Tor (Arti) + Pluggable Transports suite + transport registry.
//!
//! Provides a unified Transport trait implemented by five anti-censorship
//! pluggable transports (WebTunnel, Snowflake, obfs4, Meek, Conjure) plus an
//! Arti engine abstraction for pre-warmed Tor circuits. The registry selects
//! the best available transport by priority for automatic, zero-downtime
//! failover when DPI blocking is detected.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::RwLock;

// ---------------------------------------------------------------------------
// Transport trait + connection handle
// ---------------------------------------------------------------------------

/// A live or simulated transport connection.
#[derive(Debug, Clone)]
pub struct TransportConnection {
    pub transport_name: String,
    pub established: bool,
    pub rtt_ms: u32,
}

/// Unified transport abstraction. Every pluggable transport and the Arti Tor
/// engine implements this trait so the registry can select and fail over
/// transparently.
#[allow(clippy::needless_lifetimes)]
pub trait Transport: Send + Sync + std::fmt::Debug {
    /// Human-readable name (e.g. "webtunnel", "snowflake").
    fn name(&self) -> &'static str;
    /// Priority (lower = preferred). Used by the registry for selection.
    fn priority(&self) -> u8;
    /// Whether the transport is currently reachable.
    fn is_available(&self) -> bool;
    /// Establish a connection (real handshake in production; fast mock here).
    fn connect(&self) -> TransportConnection {
        TransportConnection {
            transport_name: self.name().to_string(),
            established: self.is_available(),
            rtt_ms: 50,
        }
    }
}

// ---------------------------------------------------------------------------
// Pluggable Transports
// ---------------------------------------------------------------------------

/// WebTunnel: encapsulates Tor handshakes as HTTP/2 WebSocket upgrades
/// targeting whitelisted CDN fronting domains.
#[derive(Debug)]
pub struct WebTunnel {
    _front_domain: String,
    available: bool,
}

impl WebTunnel {
    /// Create with a CDN fronting domain (e.g. "cdn.cloudflare.com").
    #[must_use]
    pub fn new(front_domain: &str) -> Self {
        Self {
            _front_domain: front_domain.into(),
            available: true,
        }
    }
}

impl Transport for WebTunnel {
    fn name(&self) -> &'static str {
        "webtunnel"
    }
    fn priority(&self) -> u8 {
        20
    }
    fn is_available(&self) -> bool {
        self.available
    }
}

/// Snowflake: WebRTC peer connection via dynamic STUN/TURN signaling brokers.
#[derive(Debug)]
pub struct Snowflake {
    _stun_servers: Vec<String>,
    available: bool,
}

impl Snowflake {
    #[must_use]
    pub fn new(stun_servers: Vec<String>) -> Self {
        Self {
            _stun_servers: stun_servers,
            available: true,
        }
    }
}

impl Transport for Snowflake {
    fn name(&self) -> &'static str {
        "snowflake"
    }
    fn priority(&self) -> u8 {
        30
    }
    fn is_available(&self) -> bool {
        self.available
    }
}

/// obfs4 / Lyrebird: packet length padding + dynamic payload entropy.
#[derive(Debug)]
pub struct Obfs4 {
    _node_id: String,
    available: bool,
}

impl Obfs4 {
    #[must_use]
    pub fn new(node_id: &str) -> Self {
        Self {
            _node_id: node_id.into(),
            available: true,
        }
    }
}

impl Transport for Obfs4 {
    fn name(&self) -> &'static str {
        "obfs4"
    }
    fn priority(&self) -> u8 {
        40
    }
    fn is_available(&self) -> bool {
        self.available
    }
}

/// Meek: CDN domain fronting over Cloudflare/Azure edge nodes.
#[derive(Debug)]
pub struct Meek {
    _cdn_front: String,
    available: bool,
}

impl Meek {
    #[must_use]
    pub fn new(cdn_front: &str) -> Self {
        Self {
            _cdn_front: cdn_front.into(),
            available: true,
        }
    }
}

impl Transport for Meek {
    fn name(&self) -> &'static str {
        "meek"
    }
    fn priority(&self) -> u8 {
        50
    }
    fn is_available(&self) -> bool {
        self.available
    }
}

/// Conjure: phantom IP space tap routing for unreachable ranges.
#[derive(Debug)]
pub struct Conjure {
    _phantom_cidr: String,
    available: bool,
}

impl Conjure {
    #[must_use]
    pub fn new(phantom_cidr: &str) -> Self {
        Self {
            _phantom_cidr: phantom_cidr.into(),
            available: true,
        }
    }
}

impl Transport for Conjure {
    fn name(&self) -> &'static str {
        "conjure"
    }
    fn priority(&self) -> u8 {
        60
    }
    fn is_available(&self) -> bool {
        self.available
    }
}

// ---------------------------------------------------------------------------
// Arti Tor engine (pre-warmed circuit abstraction)
// ---------------------------------------------------------------------------

/// Bootstrap status of the embedded Arti Tor client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapStatus {
    Idle,
    Bootstrapping,
    Ready,
    Failed,
}

/// Arti engine abstraction. In production this wraps `arti_client::TorClient`
/// and maintains pre-warmed circuits in background Tokio tasks. Here it tracks
/// bootstrap state and circuit count.
#[derive(Debug)]
pub struct ArtiEngine {
    status: RwLock<BootstrapStatus>,
    pre_warmed: AtomicU32,
    bootstrap_count: AtomicU64,
}

impl ArtiEngine {
    /// Create a new Arti engine in Idle state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            status: RwLock::new(BootstrapStatus::Idle),
            pre_warmed: AtomicU32::new(0),
            bootstrap_count: AtomicU64::new(0),
        }
    }

    /// Trigger a bootstrap (non-blocking; sets status to Bootstrapping).
    pub fn bootstrap(&self) {
        *self.status.write() = BootstrapStatus::Bootstrapping;
        self.bootstrap_count.fetch_add(1, Ordering::SeqCst);
        // In production: arti_client::TorClient::bootstrap() in a background task.
        // Here we simulate completion.
        *self.status.write() = BootstrapStatus::Ready;
        self.pre_warmed.store(3, Ordering::SeqCst);
    }

    /// Current bootstrap status.
    #[must_use]
    pub fn status(&self) -> BootstrapStatus {
        *self.status.read()
    }

    /// Number of pre-warmed circuits available.
    #[must_use]
    pub fn pre_warmed_circuits(&self) -> u32 {
        self.pre_warmed.load(Ordering::SeqCst)
    }

    /// Consume one pre-warmed circuit (returns true if one was available).
    pub fn take_circuit(&self) -> bool {
        loop {
            let current = self.pre_warmed.load(Ordering::SeqCst);
            if current == 0 {
                return false;
            }
            if self
                .pre_warmed
                .compare_exchange(current, current - 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return true;
            }
        }
    }

    /// Total bootstrap attempts (for metrics).
    #[must_use]
    pub fn bootstrap_count(&self) -> u64 {
        self.bootstrap_count.load(Ordering::SeqCst)
    }
}

impl Default for ArtiEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for ArtiEngine {
    fn name(&self) -> &'static str {
        "arti-tor"
    }
    fn priority(&self) -> u8 {
        10
    }
    fn is_available(&self) -> bool {
        self.status() == BootstrapStatus::Ready
    }
}

// ---------------------------------------------------------------------------
// Transport registry (selection + failover ordering)
// ---------------------------------------------------------------------------

/// Registry of available transports, sorted by priority. The registry selects
/// the best available transport and can re-order for failover.
#[derive(Debug)]
pub struct TransportRegistry {
    transports: RwLock<Vec<Arc<dyn Transport>>>,
}

impl TransportRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            transports: RwLock::new(Vec::new()),
        }
    }

    /// Create a registry pre-loaded with all five PTs + Arti.
    #[must_use]
    pub fn with_all_transports() -> Self {
        let reg = Self::new();
        reg.register(Arc::new(ArtiEngine::new()));
        reg.register(Arc::new(WebTunnel::new("cdn.aether-x.dev")));
        reg.register(Arc::new(Snowflake::new(vec![
            "stun:stun.l.google.com:19302".into(),
        ])));
        reg.register(Arc::new(Obfs4::new("bridge-001")));
        reg.register(Arc::new(Meek::new("azureedge.net")));
        reg.register(Arc::new(Conjure::new("192.0.2.0/24")));
        reg
    }

    /// Register a transport (sorted by priority after insert).
    pub fn register(&self, t: Arc<dyn Transport>) {
        let mut guard = self.transports.write();
        guard.push(t);
        guard.sort_by_key(|t| t.priority());
    }

    /// Select the best (lowest-priority) available transport.
    #[must_use]
    pub fn select_best(&self) -> Option<Arc<dyn Transport>> {
        self.transports
            .read()
            .iter()
            .find(|t| t.is_available())
            .cloned()
    }

    /// Get all transport names in priority order.
    #[must_use]
    pub fn transport_names(&self) -> Vec<String> {
        self.transports
            .read()
            .iter()
            .map(|t| t.name().to_string())
            .collect()
    }

    /// Snapshot every registered transport as cheap `Arc` clones. Used by the
    /// multipath racer / bond to fire across the whole tier concurrently.
    #[must_use]
    pub fn snapshot(&self) -> Vec<Arc<dyn Transport>> {
        self.transports.read().iter().cloned().collect()
    }

    /// Count of registered transports.
    #[must_use]
    pub fn len(&self) -> usize {
        self.transports.read().len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for TransportRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_selects_by_priority() {
        let reg = TransportRegistry::with_all_transports();
        // Arti (priority 10) is NOT available (Idle status), so WebTunnel (20) wins.
        let best = reg.select_best().expect("at least one available");
        assert_eq!(best.name(), "webtunnel");
        assert_eq!(reg.len(), 6);
    }

    #[test]
    fn arti_bootstrap_and_circuit() {
        let engine = ArtiEngine::new();
        assert_eq!(engine.status(), BootstrapStatus::Idle);
        assert!(!engine.is_available());
        engine.bootstrap();
        assert_eq!(engine.status(), BootstrapStatus::Ready);
        assert!(engine.is_available());
        assert_eq!(engine.pre_warmed_circuits(), 3);
        assert!(engine.take_circuit());
        assert_eq!(engine.pre_warmed_circuits(), 2);
    }

    #[test]
    fn each_transport_has_unique_name_and_priority() {
        let reg = TransportRegistry::with_all_transports();
        let names = reg.transport_names();
        let unique: std::collections::HashSet<_> = names.iter().collect();
        assert_eq!(unique.len(), names.len(), "duplicate transport names");
        assert!(names.contains(&"arti-tor".to_string()));
        assert!(names.contains(&"webtunnel".to_string()));
        assert!(names.contains(&"snowflake".to_string()));
        assert!(names.contains(&"obfs4".to_string()));
        assert!(names.contains(&"meek".to_string()));
        assert!(names.contains(&"conjure".to_string()));
    }

    #[test]
    fn connect_returns_established() {
        let wt = WebTunnel::new("cdn.example.com");
        let conn = wt.connect();
        assert!(conn.established);
        assert_eq!(conn.transport_name, "webtunnel");
    }
}
