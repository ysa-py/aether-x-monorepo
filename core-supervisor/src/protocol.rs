//! Core-agnostic protocol abstraction.
//!
//! Every backend (xray-core, sing-box, AmneziaWG, Naive, the proprietary
//! persis-core) implements [`ProtocolCore`]. The supervisor speaks only to
//! this trait — it never knows *how* a given core executes.

use std::fmt;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::{Result, SupervisorError};

/// Backend identity. Mirrors `aether.supervisor.v1.CoreKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum CoreKind {
    /// Unspecified — must never be used at runtime.
    Unspecified = 0,
    /// VLESS / VMess / Trojan / Reality / XTLS-Vision / XHTTP / gRPC / WS.
    Xray = 1,
    /// Hysteria2 / TUIC v5 / ShadowTLS v3 / AnyTLS / SS-2022 / WireGuard.
    SingBox = 2,
    /// Obfuscated WireGuard (DPI-resistant handshake).
    AmneziaWg = 3,
    /// HTTP/2 CDN-mimicking transport.
    Naive = 4,
    /// Proprietary differentiator core (adaptive fragmentation / cover traffic).
    Persis = 5,
}

impl fmt::Display for CoreKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Lifecycle status. Mirrors `aether.supervisor.v1.CoreStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoreStatus {
    /// Not yet known.
    Unspecified,
    /// Process spawned, not yet accepting.
    Starting,
    /// Accepting connections, probes healthy.
    Running,
    /// Hot-swap in progress; refusing new connections, draining in-flight.
    Draining,
    /// Up but failing probes above threshold.
    Degraded,
    /// Cleanly stopped.
    Stopped,
    /// Process died and could not be restarted.
    Failed,
}

/// A live, owned handle to a started core instance.
#[derive(Debug, Clone)]
pub struct CoreHandle {
    /// Caller-assigned stable id (idempotent start).
    pub instance_id: String,
    pub kind: CoreKind,
    pub protocol_id: String,
}

/// Lightweight health snapshot returned by [`ProtocolCore::health`].
#[derive(Debug, Clone, Copy)]
pub struct HealthStatus {
    pub status: CoreStatus,
    /// Fraction [0,1] of recent probes that succeeded.
    pub success_rate: f64,
}

/// Per-core metrics for telemetry + the AI feature store.
#[derive(Debug, Clone, Default)]
pub struct CoreMetrics {
    pub active_connections: u64,
    pub total_connections: u64,
    pub rx_bytes_per_sec: f64,
    pub tx_bytes_per_sec: f64,
    pub p50_rtt_ms: f64,
    pub block_rate: f64,
    pub cpu_fraction: f64,
    pub resident_bytes: u64,
}

/// Resource limits the supervisor enforces via cgroups (Linux).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub cpu_weight: u32,
    pub memory_limit_bytes: u64,
    pub max_fds: u64,
    pub max_inbound_conns: u32,
}

/// A protocol spec the adapter turns into its own native config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolSpec {
    pub protocol_id: String,
    /// Core-specific config blob; opaque to the supervisor, validated by the adapter.
    pub opaque_config: serde_json::Value,
    pub hot_swap_capable: bool,
    pub listen_addr: String,
}

/// A fully-specified core the supervisor can start.
#[derive(Debug, Clone)]
pub struct CoreConfig {
    pub instance_id: String,
    pub kind: CoreKind,
    pub protocol: ProtocolSpec,
    pub limits: ResourceLimits,
    pub max_restarts: u32,
    pub restart_window_secs: u32,
}

/// The contract every backend adapter implements.
///
/// Implementations MUST be cheap to clone if shared — the supervisor holds them
/// behind an `Arc<dyn ProtocolCore>`. All methods are async and cancellation-safe.
#[async_trait]
pub trait ProtocolCore: Send + Sync + fmt::Debug {
    /// Which backend this adapter drives.
    fn kind(&self) -> CoreKind;

    /// Spawn the core. Must be idempotent w.r.t. `instance_id`.
    async fn start(&self, config: CoreConfig) -> Result<CoreHandle>;

    /// Stop the core. With `drain = true`, refuse new connections and wait up
    /// to `timeout` for in-flight traffic before forcing shutdown.
    async fn stop(
        &self,
        handle: &CoreHandle,
        drain: bool,
        timeout: std::time::Duration,
    ) -> Result<()>;

    /// Restart in place (used by the restart loop and by forced `HotSwap`).
    async fn restart(&self, handle: &CoreHandle) -> Result<()>;

    /// Cheap, non-blocking health probe.
    async fn health(&self, handle: &CoreHandle) -> Result<HealthStatus>;

    /// Snapshot metrics.
    async fn metrics(&self, handle: &CoreHandle) -> Result<CoreMetrics>;

    /// Protocol ids this backend can fall back to (advisory; the AI/heuristic
    /// layer may override).
    fn supports_fallback_to(&self) -> Vec<String> {
        Vec::new()
    }
}

/// Dispatch a [`crate::aether::supervisor::v1::CoreKind`] proto value to the domain enum.
pub fn kind_from_proto(k: i32) -> Result<CoreKind> {
    Ok(match k {
        0 => CoreKind::Unspecified,
        1 => CoreKind::Xray,
        2 => CoreKind::SingBox,
        3 => CoreKind::AmneziaWg,
        4 => CoreKind::Naive,
        5 => CoreKind::Persis,
        other => {
            return Err(SupervisorError::Generic(format!(
                "unknown CoreKind discriminant {other}"
            )))
        }
    })
}
