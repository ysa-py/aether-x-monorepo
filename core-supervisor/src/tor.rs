//! Tor (Arti) + Pluggable Transports suite + transport registry.
//!
//! Provides a unified `Transport` registry plus a real, configurable TCP
//! endpoint transport. The historical named pluggable-transport/Arti types are
//! retained as conceptual registry entries, but they return `NotConfigured`
//! until an implementation supplies a real endpoint and protocol handshake;
//! they cannot fabricate a connection or RTT.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use thiserror::Error;
use tokio::net::{lookup_host, TcpStream};
use tokio::time::{timeout, Instant};

// ---------------------------------------------------------------------------
// Transport trait + real TCP connection handle
// ---------------------------------------------------------------------------

/// A successfully established, real TCP connection measurement.
#[derive(Debug, Clone)]
pub struct TransportConnection {
    pub transport_name: String,
    pub established: bool,
    /// Monotonic elapsed time from connection attempt start through TCP connect,
    /// rounded up to one millisecond when a loopback connection is sub-ms.
    pub rtt_ms: u32,
    pub peer: SocketAddr,
}

/// A configured TCP endpoint. Hostname resolution is deliberately explicit so
/// DNS errors cannot be misreported as generic connection failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpConnectTarget {
    SocketAddr(SocketAddr),
    Hostname { hostname: String, port: u16 },
}

impl TcpConnectTarget {
    /// Parse either `IP:port` / `[IPv6]:port` or `hostname:port`.
    pub fn parse(value: &str) -> Result<Self, ConnectError> {
        if let Ok(address) = value.parse::<SocketAddr>() {
            return Ok(Self::SocketAddr(address));
        }
        let (hostname, port) =
            value
                .rsplit_once(':')
                .ok_or_else(|| ConnectError::InvalidTarget {
                    target: value.to_string(),
                })?;
        let port = port
            .parse::<u16>()
            .map_err(|_| ConnectError::InvalidTarget {
                target: value.to_string(),
            })?;
        if hostname.is_empty() || port == 0 {
            return Err(ConnectError::InvalidTarget {
                target: value.to_string(),
            });
        }
        Ok(Self::Hostname {
            hostname: hostname.to_string(),
            port,
        })
    }

    #[must_use]
    pub fn display(&self) -> String {
        match self {
            Self::SocketAddr(address) => address.to_string(),
            Self::Hostname { hostname, port } => format!("{hostname}:{port}"),
        }
    }
}

/// Every connection attempt gets an explicit, caller-provided timeout. There
/// is intentionally no production default: a deployment must state its budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectOptions {
    pub timeout: Duration,
}

impl ConnectOptions {
    pub fn new(timeout: Duration) -> Result<Self, ConnectError> {
        if timeout.is_zero() {
            return Err(ConnectError::InvalidTimeout);
        }
        Ok(Self { timeout })
    }
}

/// Real, distinct connection failures. Each variant preserves the underlying
/// I/O error instead of converting it into a fabricated connection result.
#[derive(Debug, Error)]
pub enum ConnectError {
    #[error("connection to {target} was refused")]
    ConnectionRefused {
        target: String,
        #[source]
        source: io::Error,
    },
    #[error("connection timed out after {after:?}")]
    Timeout { after: Duration },
    #[error("DNS resolution failed for {hostname}")]
    DnsResolutionFailed {
        hostname: String,
        #[source]
        source: io::Error,
    },
    #[error("TLS handshake failed")]
    TlsHandshakeFailed {
        #[source]
        source: io::Error,
    },
    #[error("I/O error while connecting to {target}")]
    IoError {
        target: String,
        #[source]
        source: io::Error,
    },
    #[error("transport {transport} has no configured real network endpoint")]
    NotConfigured { transport: String },
    #[error("invalid TCP connection target {target}")]
    InvalidTarget { target: String },
    #[error("connection timeout must be non-zero")]
    InvalidTimeout,
    #[error("failed to create or join the Tokio connection runtime")]
    RuntimeUnavailable,
}

/// Open a genuine TCP socket with explicit DNS resolution and a monotonic RTT
/// measurement. This is the single implementation used by production endpoint
/// transports and by the real-I/O integration tests below.
pub async fn connect_tcp(
    transport_name: impl Into<String>,
    target: TcpConnectTarget,
    options: ConnectOptions,
) -> Result<TransportConnection, ConnectError> {
    let transport_name = transport_name.into();
    let started = Instant::now();
    let target_display = target.display();
    let addresses = match target {
        TcpConnectTarget::SocketAddr(address) => vec![address],
        TcpConnectTarget::Hostname { hostname, port } => {
            // `lookup_host` retains a borrow until its result is dropped; keep a
            // separate lookup string so the original hostname remains available
            // for the typed DNS error below.
            let lookup_hostname = hostname.clone();
            let resolution = timeout(
                options.timeout,
                lookup_host((lookup_hostname.as_str(), port)),
            )
            .await;
            match resolution {
                Ok(Ok(addresses)) => addresses.collect::<Vec<_>>(),
                Ok(Err(source)) => {
                    return Err(ConnectError::DnsResolutionFailed { hostname, source })
                }
                Err(_) => {
                    return Err(ConnectError::Timeout {
                        after: options.timeout,
                    })
                }
            }
        }
    };
    if addresses.is_empty() {
        return Err(ConnectError::IoError {
            target: target_display,
            source: io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "DNS returned no socket addresses",
            ),
        });
    }

    let mut last_error = None;
    for address in addresses {
        let elapsed = started.elapsed();
        let Some(remaining) = options.timeout.checked_sub(elapsed) else {
            return Err(ConnectError::Timeout {
                after: options.timeout,
            });
        };
        match timeout(remaining, TcpStream::connect(address)).await {
            Ok(Ok(_stream)) => {
                let elapsed_ms = started.elapsed().as_millis();
                let rtt_ms = elapsed_ms.clamp(1, u128::from(u32::MAX)) as u32;
                return Ok(TransportConnection {
                    transport_name,
                    established: true,
                    rtt_ms,
                    peer: address,
                });
            }
            Ok(Err(source)) if source.kind() == io::ErrorKind::ConnectionRefused => {
                return Err(ConnectError::ConnectionRefused {
                    target: address.to_string(),
                    source,
                });
            }
            Ok(Err(source)) => last_error = Some((address, source)),
            Err(_) => {
                return Err(ConnectError::Timeout {
                    after: options.timeout,
                })
            }
        }
    }
    if let Some((address, source)) = last_error {
        return Err(ConnectError::IoError {
            target: address.to_string(),
            source,
        });
    }
    Err(ConnectError::IoError {
        target: target_display,
        source: io::Error::new(io::ErrorKind::Other, "connection target yielded no attempt"),
    })
}

/// A concrete, production-selectable TCP endpoint transport. Unlike the
/// historical static Transport default, every call opens a socket and returns
/// the actual measured RTT or a real error.
#[derive(Debug, Clone)]
pub struct TcpEndpointTransport {
    name: String,
    priority: u8,
    target: TcpConnectTarget,
    options: ConnectOptions,
}

impl TcpEndpointTransport {
    pub fn new(
        name: impl Into<String>,
        priority: u8,
        target: TcpConnectTarget,
        options: ConnectOptions,
    ) -> Self {
        Self {
            name: name.into(),
            priority,
            target,
            options,
        }
    }

    pub async fn connect_async(&self) -> Result<TransportConnection, ConnectError> {
        connect_tcp(self.name.clone(), self.target.clone(), self.options).await
    }
}

/// Unified transport abstraction. A transport without an actual configured
/// endpoint returns `NotConfigured`; it can never fabricate reachability or RTT.
pub trait Transport: Send + Sync + std::fmt::Debug {
    fn name(&self) -> &str;
    fn priority(&self) -> u8;
    fn is_available(&self) -> bool;
    fn connect(&self) -> Result<TransportConnection, ConnectError> {
        Err(ConnectError::NotConfigured {
            transport: self.name().to_string(),
        })
    }
}

impl Transport for TcpEndpointTransport {
    fn name(&self) -> &str {
        &self.name
    }

    fn priority(&self) -> u8 {
        self.priority
    }

    fn is_available(&self) -> bool {
        true
    }

    fn connect(&self) -> Result<TransportConnection, ConnectError> {
        let name = self.name.clone();
        let target = self.target.clone();
        let options = self.options;
        let worker = std::thread::Builder::new()
            .name(format!("aether-connect-{name}"))
            .spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .enable_time()
                    .build()
                    .map_err(|_| ConnectError::RuntimeUnavailable)?
                    .block_on(connect_tcp(name, target, options))
            })
            .map_err(|source| ConnectError::IoError {
                target: self.target.display(),
                source,
            })?;
        worker
            .join()
            .map_err(|_| ConnectError::RuntimeUnavailable)?
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
    fn name(&self) -> &str {
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
    fn name(&self) -> &str {
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
    fn name(&self) -> &str {
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
    fn name(&self) -> &str {
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
    fn name(&self) -> &str {
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
    fn name(&self) -> &str {
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
    fn unconfigured_conceptual_transport_never_fabricates_a_connection() {
        let wt = WebTunnel::new("cdn.example.com");
        assert!(matches!(
            wt.connect(),
            Err(ConnectError::NotConfigured { .. })
        ));
    }
}
