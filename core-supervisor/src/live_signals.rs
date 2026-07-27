//! Live censorship-signal measurement for the blackout classifier.
//!
//! This module performs small, operator-configured network probes and turns
//! their **locally observed** outcomes into a [`crate::blackout::BlackoutSignal`].
//! It deliberately does not include public probe endpoints, domain fronts, or
//! bypass transports: an operator must provide controlled, consented anchors in
//! a read-only JSON configuration file.
//!
//! Measurements have deliberately narrow meanings:
//!
//! * a TCP `ConnectionReset` is an observed reset candidate, **not proof** that
//!   an on-path censor injected an RST;
//! * an EOF or TCP reset during a TLS handshake after a ClientHello is an
//!   observed TLS truncation, **not proof** of who closed the connection; and
//! * DNS poisoning is reported only when a direct UDP response for an
//!   operator-pinned hostname contains an unexpected address or response code.
//!
//! Raw packet capture (AF_PACKET/eBPF/pcap), an independently controlled
//! receiver, and an authorized deployment drill are required to attribute any
//! of these events to a censor. The source remains useful without those
//! privileges because it records falsifiable socket/DNS outcomes rather than
//! accepting manually set health flags.

use std::collections::{BTreeSet, VecDeque};
use std::fs::File;
use std::io::BufReader;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures::future::join_all;
use parking_lot::Mutex;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use serde::Deserialize;
use thiserror::Error;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::blackout::{self, BlackoutSignal, IsolationLevel};

const MIN_INTERVAL_MS: u64 = 1_000;
const MAX_INTERVAL_MS: u64 = 300_000;
const MIN_TIMEOUT_MS: u64 = 250;
const MAX_TIMEOUT_MS: u64 = 30_000;
const MIN_WINDOW_CYCLES: usize = 2;
const MAX_WINDOW_CYCLES: usize = 60;
const MAX_TARGETS_PER_KIND: usize = 16;
const MIN_INTERNATIONAL_TCP_TARGETS: usize = 2;
const MIN_DNS_TARGETS: usize = 2;
const DNS_HEADER_LEN: usize = 12;
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_CLASS_IN: u16 = 1;

fn default_interval_ms() -> u64 {
    10_000
}

fn default_timeout_ms() -> u64 {
    3_000
}

fn default_window_cycles() -> usize {
    3
}

/// Whether a TCP anchor is expected to be reachable through an international or
/// domestic path. The monitor trusts this as operator configuration; it does
/// not attempt to infer geography from an IP address.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TcpProbeScope {
    International,
    Domestic,
}

/// A TCP endpoint that is safe for the operator to probe by connecting only.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcpProbeTarget {
    /// A controlled endpoint. It is never logged by this module.
    pub address: SocketAddr,
    pub scope: TcpProbeScope,
}

/// A TLS endpoint with a pinned CA bundle. The source refuses an unverified TLS
/// handshake rather than disabling certificate validation to obtain a signal.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsProbeTarget {
    /// Socket address to connect to; the hostname remains independently pinned.
    pub address: SocketAddr,
    /// DNS name used for SNI and certificate verification.
    pub server_name: String,
    /// PEM file containing the root/intermediate CA required by this anchor.
    pub ca_certificate_pem: PathBuf,
}

/// A direct DNS query against an operator-selected resolver and an
/// operator-pinned answer set. This is an anchor check, not a general-purpose
/// DNS resolver.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsProbeTarget {
    /// UDP resolver address. Use an operator-authorized resolver only.
    pub resolver: SocketAddr,
    /// FQDN whose expected answers are controlled by the operator.
    pub name: String,
    /// Every returned A/AAAA answer must be in this set for a match.
    pub expected_addresses: Vec<IpAddr>,
}

/// File-backed configuration for live measurement. No defaults name a network
/// target: enabling the monitor always requires explicit operator anchors.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveSignalConfig {
    /// Delay between complete probe cycles.
    #[serde(default = "default_interval_ms")]
    pub interval_ms: u64,
    /// Per-socket/UDP deadline. A timeout is recorded as failed reachability,
    /// not as injected RST or DNS poisoning.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Number of cycles over which rates and reachability are aggregated before
    /// an isolation classification is emitted.
    #[serde(default = "default_window_cycles")]
    pub window_cycles: usize,
    pub tcp_targets: Vec<TcpProbeTarget>,
    pub tls_targets: Vec<TlsProbeTarget>,
    pub dns_targets: Vec<DnsProbeTarget>,
}

/// A configuration/load failure prevents the monitor from starting. Silently
/// running with malformed anchors would produce misleading censorship signals.
#[derive(Debug, Error)]
pub enum LiveSignalConfigError {
    #[error("read live-signal configuration: {0}")]
    Read(#[from] std::io::Error),
    #[error("decode live-signal configuration: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("invalid live-signal configuration: {0}")]
    Invalid(String),
}

impl LiveSignalConfig {
    /// Load one strict JSON document and validate it before any probe is sent.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, LiveSignalConfigError> {
        let bytes = std::fs::read(path)?;
        let config = serde_json::from_slice::<Self>(&bytes)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate structural safety and make sure every classifier input has at
    /// least one independently configured measurement source.
    pub fn validate(&self) -> Result<(), LiveSignalConfigError> {
        if !(MIN_INTERVAL_MS..=MAX_INTERVAL_MS).contains(&self.interval_ms) {
            return Err(LiveSignalConfigError::Invalid(format!(
                "interval_ms must be in {MIN_INTERVAL_MS}..={MAX_INTERVAL_MS}"
            )));
        }
        if !(MIN_TIMEOUT_MS..=MAX_TIMEOUT_MS).contains(&self.timeout_ms) {
            return Err(LiveSignalConfigError::Invalid(format!(
                "timeout_ms must be in {MIN_TIMEOUT_MS}..={MAX_TIMEOUT_MS}"
            )));
        }
        if !(MIN_WINDOW_CYCLES..=MAX_WINDOW_CYCLES).contains(&self.window_cycles) {
            return Err(LiveSignalConfigError::Invalid(format!(
                "window_cycles must be in {MIN_WINDOW_CYCLES}..={MAX_WINDOW_CYCLES}"
            )));
        }
        for (kind, count) in [
            ("tcp_targets", self.tcp_targets.len()),
            ("tls_targets", self.tls_targets.len()),
            ("dns_targets", self.dns_targets.len()),
        ] {
            if count == 0 {
                return Err(LiveSignalConfigError::Invalid(format!(
                    "{kind} must not be empty"
                )));
            }
            if count > MAX_TARGETS_PER_KIND {
                return Err(LiveSignalConfigError::Invalid(format!(
                    "{kind} must contain at most {MAX_TARGETS_PER_KIND} entries"
                )));
            }
        }
        let international_targets = self
            .tcp_targets
            .iter()
            .filter(|target| target.scope == TcpProbeScope::International)
            .count();
        if international_targets < MIN_INTERNATIONAL_TCP_TARGETS {
            return Err(LiveSignalConfigError::Invalid(format!(
                "tcp_targets requires at least {MIN_INTERNATIONAL_TCP_TARGETS} international anchors"
            )));
        }
        if !self
            .tcp_targets
            .iter()
            .any(|target| target.scope == TcpProbeScope::Domestic)
        {
            return Err(LiveSignalConfigError::Invalid(
                "tcp_targets requires at least one domestic anchor".into(),
            ));
        }
        for target in &self.tcp_targets {
            if target.address.port() == 0 {
                return Err(LiveSignalConfigError::Invalid(
                    "TCP probe address must use a non-zero port".into(),
                ));
            }
        }
        for target in &self.tls_targets {
            if target.address.port() == 0 {
                return Err(LiveSignalConfigError::Invalid(
                    "TLS probe address must use a non-zero port".into(),
                ));
            }
            if target.ca_certificate_pem.as_os_str().is_empty() {
                return Err(LiveSignalConfigError::Invalid(
                    "TLS probe CA path must not be empty".into(),
                ));
            }
            ServerName::try_from(target.server_name.clone()).map_err(|error| {
                LiveSignalConfigError::Invalid(format!("TLS probe server_name is invalid: {error}"))
            })?;
        }
        if self.dns_targets.len() < MIN_DNS_TARGETS {
            return Err(LiveSignalConfigError::Invalid(format!(
                "dns_targets requires at least {MIN_DNS_TARGETS} independent anchors"
            )));
        }
        for target in &self.dns_targets {
            if target.resolver.port() == 0 {
                return Err(LiveSignalConfigError::Invalid(
                    "DNS resolver must use a non-zero port".into(),
                ));
            }
            if target.expected_addresses.is_empty() {
                return Err(LiveSignalConfigError::Invalid(
                    "DNS probe expected_addresses must not be empty".into(),
                ));
            }
            dns_question(0, &target.name, dns_query_type(target))?;
        }
        Ok(())
    }

    /// Configured sampling interval.
    #[must_use]
    pub fn interval(&self) -> Duration {
        Duration::from_millis(self.interval_ms)
    }

    fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }
}

struct PreparedTlsProbe {
    address: SocketAddr,
    connector: TlsConnector,
    server_name: ServerName<'static>,
}

/// The bounded aggregate counts behind one classifier input. These counts are
/// safe for logs/metrics: they contain no destination, hostname, resolver, or
/// subscriber identity.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LiveSignalTotals {
    pub tcp_attempts: u64,
    pub tcp_successes: u64,
    /// Locally observed `ConnectionReset` errors from TCP or TLS probes.
    pub reset_candidates: u64,
    pub tls_attempts: u64,
    pub tls_successes: u64,
    /// EOF while a TLS handshake was in progress after ClientHello transmission.
    pub tls_truncations: u64,
    pub dns_attempts: u64,
    pub dns_valid_answers: u64,
    /// Direct DNS responses whose code/answers disagree with the pinned anchor.
    pub dns_mismatches: u64,
    pub dns_failures: u64,
    pub international_attempts: u64,
    pub international_successes: u64,
    pub domestic_attempts: u64,
    pub domestic_successes: u64,
}

impl LiveSignalTotals {
    fn add_cycle(&mut self, cycle: &Self) {
        self.tcp_attempts += cycle.tcp_attempts;
        self.tcp_successes += cycle.tcp_successes;
        self.reset_candidates += cycle.reset_candidates;
        self.tls_attempts += cycle.tls_attempts;
        self.tls_successes += cycle.tls_successes;
        self.tls_truncations += cycle.tls_truncations;
        self.dns_attempts += cycle.dns_attempts;
        self.dns_valid_answers += cycle.dns_valid_answers;
        self.dns_mismatches += cycle.dns_mismatches;
        self.dns_failures += cycle.dns_failures;
        self.international_attempts += cycle.international_attempts;
        self.international_successes += cycle.international_successes;
        self.domestic_attempts += cycle.domestic_attempts;
        self.domestic_successes += cycle.domestic_successes;
    }

    fn ratio(numerator: u64, denominator: u64) -> f64 {
        if denominator == 0 {
            0.0
        } else {
            numerator as f64 / denominator as f64
        }
    }

    fn signal(&self) -> BlackoutSignal {
        BlackoutSignal {
            tcp_rst_rate: Self::ratio(self.reset_candidates, self.tcp_attempts + self.tls_attempts),
            tls_trunc_rate: Self::ratio(self.tls_truncations, self.tls_attempts),
            dns_anomaly_rate: Self::ratio(self.dns_mismatches, self.dns_attempts),
            // A conservative windowed indication only: every configured
            // international TCP anchor failed throughout the whole window.
            international_ip_severed: self.international_attempts > 0
                && self.international_successes == 0,
            // One verified expected answer proves that at least one configured
            // DNS anchor is still usable. A timeout is not mislabeled poisoning.
            dns_resolves_international: self.dns_valid_answers > 0,
            // This means an operator-designated domestic TCP anchor accepted a
            // connection; it does not establish nationwide intranet health.
            domestic_intranet_up: self.domestic_successes > 0,
        }
    }
}

/// One output from a real probe cycle. `classification` remains `None` until
/// the configured window is full, so a single failed packet cannot escalate a
/// network state.
#[derive(Debug, Clone)]
pub struct LiveSignalReport {
    pub signal: BlackoutSignal,
    pub totals: LiveSignalTotals,
    pub samples: usize,
    pub ready: bool,
    pub classification: Option<IsolationLevel>,
}

/// Live source of classifier inputs. It has no automatic transport actuation:
/// callers may log/export the report or hand it to a separately reviewed policy
/// layer, but a measurement alone never claims connectivity or starts a bypass.
pub struct LiveSignalSource {
    config: LiveSignalConfig,
    tls_targets: Vec<PreparedTlsProbe>,
    window: Mutex<VecDeque<LiveSignalTotals>>,
}

impl std::fmt::Debug for LiveSignalSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LiveSignalSource")
            .field("tcp_targets", &self.config.tcp_targets.len())
            .field("tls_targets", &self.tls_targets.len())
            .field("dns_targets", &self.config.dns_targets.len())
            .field("window_cycles", &self.config.window_cycles)
            .finish_non_exhaustive()
    }
}

impl LiveSignalSource {
    /// Create a source from validated configuration and load the pinned TLS CAs
    /// before the first probe. A missing/malformed CA prevents startup instead
    /// of silently switching to an insecure handshake.
    pub fn new(config: LiveSignalConfig) -> Result<Self, LiveSignalConfigError> {
        config.validate()?;
        let tls_targets = config
            .tls_targets
            .iter()
            .map(prepare_tls_target)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            config,
            tls_targets,
            window: Mutex::new(VecDeque::new()),
        })
    }

    /// Load strict configuration and construct a live source.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, LiveSignalConfigError> {
        Self::new(LiveSignalConfig::from_path(path)?)
    }

    /// Sampling interval selected by the operator.
    #[must_use]
    pub fn interval(&self) -> Duration {
        self.config.interval()
    }

    /// Run one cycle of actual TCP, TLS, and UDP DNS probes, update the bounded
    /// window, and call [`blackout::classify`] once enough real cycles exist.
    pub async fn sample(&self) -> LiveSignalReport {
        let probe_timeout = self.config.timeout();
        let tcp_futures = self
            .config
            .tcp_targets
            .iter()
            .map(|target| probe_tcp(target.address, probe_timeout));
        let tls_futures = self
            .tls_targets
            .iter()
            .map(|target| probe_tls(target, probe_timeout));
        let dns_futures = self
            .config
            .dns_targets
            .iter()
            .map(|target| probe_dns(target, probe_timeout));
        let (tcp, tls, dns) = tokio::join!(
            join_all(tcp_futures),
            join_all(tls_futures),
            join_all(dns_futures)
        );

        let cycle = self.measure_cycle(tcp, tls, dns);
        let (totals, samples) = {
            let mut window = self.window.lock();
            if window.len() == self.config.window_cycles {
                window.pop_front();
            }
            window.push_back(cycle);
            let totals = window
                .iter()
                .fold(LiveSignalTotals::default(), |mut all, item| {
                    all.add_cycle(item);
                    all
                });
            (totals, window.len())
        };
        let signal = totals.signal();
        let ready = samples >= self.config.window_cycles;
        let classification = ready.then(|| blackout::classify(&signal));
        LiveSignalReport {
            signal,
            totals,
            samples,
            ready,
            classification,
        }
    }

    fn measure_cycle(
        &self,
        tcp: Vec<TcpProbeOutcome>,
        tls: Vec<TlsProbeOutcome>,
        dns: Vec<DnsProbeOutcome>,
    ) -> LiveSignalTotals {
        let mut totals = LiveSignalTotals::default();
        for (target, outcome) in self.config.tcp_targets.iter().zip(tcp) {
            totals.tcp_attempts += 1;
            match target.scope {
                TcpProbeScope::International => totals.international_attempts += 1,
                TcpProbeScope::Domestic => totals.domestic_attempts += 1,
            }
            match outcome {
                TcpProbeOutcome::Success => {
                    totals.tcp_successes += 1;
                    match target.scope {
                        TcpProbeScope::International => totals.international_successes += 1,
                        TcpProbeScope::Domestic => totals.domestic_successes += 1,
                    }
                }
                TcpProbeOutcome::Reset => totals.reset_candidates += 1,
                TcpProbeOutcome::Failed | TcpProbeOutcome::Timeout => {}
            }
        }
        for outcome in tls {
            totals.tls_attempts += 1;
            match outcome {
                TlsProbeOutcome::Success => totals.tls_successes += 1,
                TlsProbeOutcome::TcpReset => totals.reset_candidates += 1,
                TlsProbeOutcome::HandshakeReset => {
                    totals.reset_candidates += 1;
                    totals.tls_truncations += 1;
                }
                TlsProbeOutcome::Truncated => totals.tls_truncations += 1,
                TlsProbeOutcome::Failed | TlsProbeOutcome::Timeout => {}
            }
        }
        for outcome in dns {
            totals.dns_attempts += 1;
            match outcome {
                DnsProbeOutcome::Match => totals.dns_valid_answers += 1,
                DnsProbeOutcome::Mismatch => totals.dns_mismatches += 1,
                DnsProbeOutcome::Failure | DnsProbeOutcome::Timeout => totals.dns_failures += 1,
            }
        }
        totals
    }
}

/// Run a monitor indefinitely. The supervisor starts this only when an
/// operator supplies `AETHER_LIVE_SIGNAL_CONFIG`; it emits aggregate evidence
/// and classifier output but intentionally has no transport-actuation side
/// effect.
pub async fn run_live_signal_monitor(source: Arc<LiveSignalSource>) {
    loop {
        let report = source.sample().await;
        if let Some(level) = report.classification {
            tracing::info!(
                ?level,
                samples = report.samples,
                tcp_rst_rate = report.signal.tcp_rst_rate,
                tls_trunc_rate = report.signal.tls_trunc_rate,
                dns_anomaly_rate = report.signal.dns_anomaly_rate,
                international_ip_severed = report.signal.international_ip_severed,
                dns_resolves_international = report.signal.dns_resolves_international,
                domestic_intranet_up = report.signal.domestic_intranet_up,
                "live censorship-signal window classified; no transport actuation is attached"
            );
        } else {
            tracing::debug!(
                samples = report.samples,
                required_samples = source.config.window_cycles,
                "live censorship-signal window warming"
            );
        }
        tokio::time::sleep(source.interval()).await;
    }
}

#[derive(Debug, Clone, Copy)]
enum TcpProbeOutcome {
    Success,
    Reset,
    Failed,
    Timeout,
}

#[derive(Debug, Clone, Copy)]
enum TlsProbeOutcome {
    Success,
    /// TCP reset before a TLS ClientHello can be sent.
    TcpReset,
    /// TCP reset after a TLS ClientHello was sent; this is also a truncated TLS
    /// handshake, while remaining separately visible as a reset candidate.
    HandshakeReset,
    /// EOF after a TLS ClientHello without a TLS close-notify record.
    Truncated,
    Failed,
    Timeout,
}

#[derive(Debug, Clone, Copy)]
enum DnsProbeOutcome {
    Match,
    Mismatch,
    Failure,
    Timeout,
}

async fn probe_tcp(address: SocketAddr, probe_timeout: Duration) -> TcpProbeOutcome {
    match timeout(probe_timeout, TcpStream::connect(address)).await {
        Ok(Ok(_stream)) => TcpProbeOutcome::Success,
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionReset => {
            TcpProbeOutcome::Reset
        }
        Ok(Err(_)) => TcpProbeOutcome::Failed,
        Err(_) => TcpProbeOutcome::Timeout,
    }
}

async fn probe_tls(target: &PreparedTlsProbe, probe_timeout: Duration) -> TlsProbeOutcome {
    let stream = match timeout(probe_timeout, TcpStream::connect(target.address)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionReset => {
            return TlsProbeOutcome::TcpReset;
        }
        Ok(Err(_)) => return TlsProbeOutcome::Failed,
        Err(_) => return TlsProbeOutcome::Timeout,
    };
    match timeout(
        probe_timeout,
        target.connector.connect(target.server_name.clone(), stream),
    )
    .await
    {
        Ok(Ok(_stream)) => TlsProbeOutcome::Success,
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionReset => {
            TlsProbeOutcome::HandshakeReset
        }
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
            TlsProbeOutcome::Truncated
        }
        Ok(Err(_)) => TlsProbeOutcome::Failed,
        Err(_) => TlsProbeOutcome::Timeout,
    }
}

async fn probe_dns(target: &DnsProbeTarget, probe_timeout: Duration) -> DnsProbeOutcome {
    let query_type = dns_query_type(target);
    let id = rand::random::<u16>();
    let query = match dns_question(id, &target.name, query_type) {
        Ok(query) => query,
        Err(_) => return DnsProbeOutcome::Failure,
    };
    let bind_address = match target.resolver {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };
    let socket = match timeout(probe_timeout, UdpSocket::bind(bind_address)).await {
        Ok(Ok(socket)) => socket,
        Ok(Err(_)) => return DnsProbeOutcome::Failure,
        Err(_) => return DnsProbeOutcome::Timeout,
    };
    if socket.connect(target.resolver).await.is_err() {
        return DnsProbeOutcome::Failure;
    }
    match timeout(probe_timeout, socket.send(&query)).await {
        Ok(Ok(_)) => {}
        Ok(Err(_)) => return DnsProbeOutcome::Failure,
        Err(_) => return DnsProbeOutcome::Timeout,
    }
    let mut response = [0_u8; 1_500];
    let size = match timeout(probe_timeout, socket.recv(&mut response)).await {
        Ok(Ok(size)) => size,
        Ok(Err(_)) => return DnsProbeOutcome::Failure,
        Err(_) => return DnsProbeOutcome::Timeout,
    };
    let answers = match parse_dns_answers(&response[..size], id, query_type) {
        Ok(answers) => answers,
        Err(()) => return DnsProbeOutcome::Mismatch,
    };
    let expected: BTreeSet<IpAddr> = target.expected_addresses.iter().copied().collect();
    if !answers.is_empty() && answers.iter().all(|answer| expected.contains(answer)) {
        DnsProbeOutcome::Match
    } else {
        DnsProbeOutcome::Mismatch
    }
}

fn prepare_tls_target(target: &TlsProbeTarget) -> Result<PreparedTlsProbe, LiveSignalConfigError> {
    let file = File::open(&target.ca_certificate_pem)?;
    let mut reader = BufReader::new(file);
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(LiveSignalConfigError::Read)?;
    if certificates.is_empty() {
        return Err(LiveSignalConfigError::Invalid(
            "TLS probe CA PEM contains no certificates".into(),
        ));
    }
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots.add(certificate).map_err(|error| {
            LiveSignalConfigError::Invalid(format!(
                "TLS probe CA PEM contains an unusable certificate: {error}"
            ))
        })?;
    }
    let server_name = ServerName::try_from(target.server_name.clone()).map_err(|error| {
        LiveSignalConfigError::Invalid(format!("TLS probe server_name is invalid: {error}"))
    })?;
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(PreparedTlsProbe {
        address: target.address,
        connector: TlsConnector::from(Arc::new(config)),
        server_name,
    })
}

fn dns_query_type(target: &DnsProbeTarget) -> u16 {
    if target
        .expected_addresses
        .iter()
        .any(|address| matches!(address, IpAddr::V4(_)))
    {
        DNS_TYPE_A
    } else {
        DNS_TYPE_AAAA
    }
}

fn dns_question(id: u16, name: &str, query_type: u16) -> Result<Vec<u8>, LiveSignalConfigError> {
    let mut query = Vec::with_capacity(256);
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&0x0100_u16.to_be_bytes()); // recursion desired
    query.extend_from_slice(&1_u16.to_be_bytes()); // QDCOUNT
    query.extend_from_slice(&0_u16.to_be_bytes()); // ANCOUNT
    query.extend_from_slice(&0_u16.to_be_bytes()); // NSCOUNT
    query.extend_from_slice(&0_u16.to_be_bytes()); // ARCOUNT
    encode_dns_name(name, &mut query)?;
    query.extend_from_slice(&query_type.to_be_bytes());
    query.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    Ok(query)
}

fn encode_dns_name(name: &str, output: &mut Vec<u8>) -> Result<(), LiveSignalConfigError> {
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() || trimmed.len() > 253 {
        return Err(LiveSignalConfigError::Invalid(
            "DNS probe name must be a non-empty FQDN".into(),
        ));
    }
    for label in trimmed.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty()
            || bytes.len() > 63
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b'_')
        {
            return Err(LiveSignalConfigError::Invalid(
                "DNS probe name contains an invalid label".into(),
            ));
        }
        output.push(bytes.len() as u8);
        output.extend_from_slice(bytes);
    }
    output.push(0);
    Ok(())
}

fn parse_dns_answers(
    response: &[u8],
    expected_id: u16,
    query_type: u16,
) -> Result<Vec<IpAddr>, ()> {
    if response.len() < DNS_HEADER_LEN || read_u16(response, 0)? != expected_id {
        return Err(());
    }
    let flags = read_u16(response, 2)?;
    let is_response = flags & 0x8000 != 0;
    let truncated = flags & 0x0200 != 0;
    let response_code = flags & 0x000f;
    if !is_response || truncated || response_code != 0 {
        return Err(());
    }
    let questions = usize::from(read_u16(response, 4)?);
    let answers = usize::from(read_u16(response, 6)?);
    let mut cursor = DNS_HEADER_LEN;
    for _ in 0..questions {
        cursor = skip_dns_name(response, cursor)?;
        cursor = cursor
            .checked_add(4)
            .filter(|next| *next <= response.len())
            .ok_or(())?;
    }
    let mut addresses = Vec::new();
    for _ in 0..answers {
        cursor = skip_dns_name(response, cursor)?;
        let record_type = read_u16(response, cursor)?;
        let record_class = read_u16(response, cursor + 2)?;
        let data_length = usize::from(read_u16(response, cursor + 8)?);
        let data_start = cursor.checked_add(10).ok_or(())?;
        let data_end = data_start
            .checked_add(data_length)
            .filter(|end| *end <= response.len())
            .ok_or(())?;
        if record_class == DNS_CLASS_IN && record_type == query_type {
            match (record_type, data_length) {
                (DNS_TYPE_A, 4) => {
                    addresses.push(IpAddr::from([
                        response[data_start],
                        response[data_start + 1],
                        response[data_start + 2],
                        response[data_start + 3],
                    ]));
                }
                (DNS_TYPE_AAAA, 16) => {
                    let mut bytes = [0_u8; 16];
                    bytes.copy_from_slice(&response[data_start..data_end]);
                    addresses.push(IpAddr::from(bytes));
                }
                _ => return Err(()),
            }
        }
        cursor = data_end;
    }
    Ok(addresses)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, ()> {
    let end = offset
        .checked_add(2)
        .filter(|end| *end <= bytes.len())
        .ok_or(())?;
    Ok(u16::from_be_bytes([bytes[offset], bytes[end - 1]]))
}

fn skip_dns_name(bytes: &[u8], mut cursor: usize) -> Result<usize, ()> {
    loop {
        let length = *bytes.get(cursor).ok_or(())?;
        if length == 0 {
            return cursor.checked_add(1).ok_or(());
        }
        if length & 0xc0 == 0xc0 {
            return cursor
                .checked_add(2)
                .filter(|end| *end <= bytes.len())
                .ok_or(());
        }
        if length & 0xc0 != 0 {
            return Err(());
        }
        cursor = cursor.checked_add(1 + usize::from(length)).ok_or(())?;
        if cursor > bytes.len() {
            return Err(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    use tokio::net::TcpListener;

    fn fixture_ca_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/live_signals/probe-ca.pem")
    }

    async fn start_tcp_acceptor() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        address
    }

    async fn start_dns_responder(answer: Ipv4Addr) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut request = [0_u8; 512];
            if let Ok((size, peer)) = socket.recv_from(&mut request).await {
                let response = dns_a_response(&request[..size], answer);
                let _ = socket.send_to(&response, peer).await;
            }
        });
        address
    }

    fn dns_a_response(request: &[u8], answer: Ipv4Addr) -> Vec<u8> {
        let question_end = skip_dns_name(request, DNS_HEADER_LEN).unwrap() + 4;
        let mut response = Vec::new();
        response.extend_from_slice(&request[..2]);
        response.extend_from_slice(&0x8180_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&request[DNS_HEADER_LEN..question_end]);
        response.extend_from_slice(&0xc00c_u16.to_be_bytes());
        response.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        response.extend_from_slice(&60_u32.to_be_bytes());
        response.extend_from_slice(&4_u16.to_be_bytes());
        response.extend_from_slice(&answer.octets());
        response
    }

    #[test]
    fn configuration_requires_independent_anchors_for_every_signal() {
        let config = LiveSignalConfig {
            interval_ms: 100,
            timeout_ms: 1_000,
            window_cycles: 1,
            tcp_targets: Vec::new(),
            tls_targets: Vec::new(),
            dns_targets: Vec::new(),
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn pinned_tls_ca_is_loaded_without_an_insecure_verifier() {
        let target = TlsProbeTarget {
            address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443)),
            server_name: "probe.test".into(),
            ca_certificate_pem: fixture_ca_path(),
        };
        assert!(prepare_tls_target(&target).is_ok());
    }

    #[tokio::test]
    async fn loopback_tcp_and_udp_dns_probes_execute_against_real_anchors() {
        let tcp_address = start_tcp_acceptor().await;
        let _tcp_outcome = probe_tcp(tcp_address, Duration::from_secs(1)).await;

        let dns_address = start_dns_responder(Ipv4Addr::new(192, 0, 2, 10)).await;
        let dns_target = DnsProbeTarget {
            resolver: dns_address,
            name: "anchor.probe.test".into(),
            expected_addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))],
        };
        let _dns_outcome = probe_dns(&dns_target, Duration::from_secs(1)).await;
    }
}
