//! Core adapters.
//!
//! Each adapter implements [`ProtocolCore`] for one backend. In production an
//! adapter owns a child process (xray-core / sing-box / …) over its native
//! control surface (gRPC / Clash API). This crate ships:
//!
//!   - [`MockCore`] — a fully in-process, deterministic adapter used for tests
//!     and local development so the supervisor is exercisable with zero
//!     external dependencies.
//!   - [`ManagedProcessAdapter`] — a capability-gated subprocess owner for
//!     Xray and sing-box. It validates an operator-mounted config path, tracks
//!     its child, probes the declared loopback listener, and never reports a
//!     running core merely because spawn succeeded.
//!
//! External cores are opt-in (`real_cores` build feature **and**
//! `AETHER_EXTERNAL_CORE_MODE=true`). This prevents a minimal container from
//! pretending it has proxy binaries that were never installed.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use dashmap::DashMap;

#[cfg(feature = "real_cores")]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
#[cfg(feature = "real_cores")]
use std::path::PathBuf;
#[cfg(feature = "real_cores")]
use tokio::net::TcpStream;
#[cfg(feature = "real_cores")]
use tokio::process::{Child, Command};
#[cfg(feature = "real_cores")]
use tokio::sync::Mutex as AsyncMutex;

use crate::error::{Result, SupervisorError};
use crate::protocol::{
    CoreConfig, CoreHandle, CoreKind, CoreMetrics, CoreStatus, HealthStatus, ProtocolCore,
};

/// Build the adapter set the supervisor should start with.
///
/// The external process path requires both a build-time feature and an explicit
/// runtime opt-in. This makes a missing core binary an actionable start error,
/// not a fabricated healthy instance. All other kinds retain the deterministic
/// in-process adapter until an equivalent managed implementation exists.
pub fn default_adapters() -> HashMap<CoreKind, Arc<dyn ProtocolCore>> {
    let mut adapters = HashMap::new();
    let mock: Arc<dyn ProtocolCore> = Arc::new(MockCore::default());
    for kind in [
        CoreKind::Xray,
        CoreKind::SingBox,
        CoreKind::AmneziaWg,
        CoreKind::Naive,
        CoreKind::Persis,
    ] {
        adapters.insert(kind, mock.clone());
    }

    #[cfg(feature = "real_cores")]
    if external_core_mode_requested() {
        adapters.insert(
            CoreKind::Xray,
            Arc::new(ManagedProcessAdapter::xray()) as Arc<dyn ProtocolCore>,
        );
        adapters.insert(
            CoreKind::SingBox,
            Arc::new(ManagedProcessAdapter::sing_box()) as Arc<dyn ProtocolCore>,
        );
    }

    adapters
}

fn external_core_mode_requested() -> bool {
    match std::env::var("AETHER_EXTERNAL_CORE_MODE") {
        Ok(value) => matches!(value.trim().to_ascii_lowercase().as_str(), "1" | "true"),
        Err(_) => false,
    }
}

/// Reject a deployment that requested process supervision from a binary built
/// without the feature implementing it. Falling back to MockCore in that case
/// would look healthy while forwarding no user traffic.
pub fn validate_external_core_mode() -> Result<()> {
    #[cfg(not(feature = "real_cores"))]
    if external_core_mode_requested() {
        return Err(SupervisorError::Generic(
            "AETHER_EXTERNAL_CORE_MODE=true requires a supervisor built with the real_cores feature"
                .to_string(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// MockCore — in-process, deterministic, zero-dependency.
// ---------------------------------------------------------------------------

/// In-memory state for one mock instance. DashMap shards already serialize
/// access per-key, so plain fields suffice.
#[derive(Debug)]
struct MockState {
    status: CoreStatus,
    started_at: Option<Instant>,
    active: u64,
    total: u64,
    restarts: u64,
}

impl Default for MockState {
    fn default() -> Self {
        Self {
            status: CoreStatus::Stopped,
            started_at: None,
            active: 0,
            total: 0,
            restarts: 0,
        }
    }
}

/// In-process adapter. Behaves like a real core but performs no I/O.
#[derive(Default)]
pub struct MockCore {
    instances: DashMap<String, MockState>,
}

impl std::fmt::Debug for MockCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockCore")
            .field("instances", &self.instances.len())
            .finish()
    }
}

#[async_trait]
impl ProtocolCore for MockCore {
    fn kind(&self) -> CoreKind {
        CoreKind::Unspecified
    }

    async fn start(&self, config: CoreConfig) -> Result<CoreHandle> {
        let handle = CoreHandle {
            instance_id: config.instance_id.clone(),
            kind: config.kind,
            protocol_id: config.protocol.protocol_id.clone(),
        };
        match self.instances.entry(config.instance_id.clone()) {
            dashmap::mapref::entry::Entry::Occupied(_) => {
                Err(SupervisorError::InstanceExists(config.instance_id))
            }
            dashmap::mapref::entry::Entry::Vacant(v) => {
                let st = MockState {
                    status: CoreStatus::Running,
                    started_at: Some(Instant::now()),
                    ..MockState::default()
                };
                v.insert(st);
                Ok(handle)
            }
        }
    }

    async fn stop(&self, handle: &CoreHandle, drain: bool, _timeout: Duration) -> Result<()> {
        let mut entry = self
            .instances
            .get_mut(&handle.instance_id)
            .ok_or_else(|| SupervisorError::InstanceNotFound(handle.instance_id.clone()))?;
        if drain {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        entry.status = CoreStatus::Stopped;
        Ok(())
    }

    async fn restart(&self, handle: &CoreHandle) -> Result<()> {
        let mut entry = self
            .instances
            .get_mut(&handle.instance_id)
            .ok_or_else(|| SupervisorError::InstanceNotFound(handle.instance_id.clone()))?;
        entry.restarts += 1;
        entry.status = CoreStatus::Running;
        entry.started_at = Some(Instant::now());
        Ok(())
    }

    async fn health(&self, handle: &CoreHandle) -> Result<HealthStatus> {
        let entry = self
            .instances
            .get(&handle.instance_id)
            .ok_or_else(|| SupervisorError::InstanceNotFound(handle.instance_id.clone()))?;
        Ok(HealthStatus {
            status: entry.status,
            success_rate: if entry.status == CoreStatus::Running {
                1.0
            } else {
                0.0
            },
        })
    }

    async fn metrics(&self, handle: &CoreHandle) -> Result<CoreMetrics> {
        let entry = self
            .instances
            .get(&handle.instance_id)
            .ok_or_else(|| SupervisorError::InstanceNotFound(handle.instance_id.clone()))?;
        Ok(CoreMetrics {
            active_connections: entry.active,
            total_connections: entry.total,
            ..Default::default()
        })
    }
}

// ---------------------------------------------------------------------------
// ManagedProcessAdapter — opt-in real subprocess ownership.
// ---------------------------------------------------------------------------

/// Health probing has a hard, bounded timeout. A live PID is not sufficient
/// evidence that a proxy core is accepting traffic.
#[cfg(feature = "real_cores")]
const LISTENER_PROBE_TIMEOUT: Duration = Duration::from_secs(1);

/// A spawned process plus the immutable launch contract needed for a safe
/// restart. The child is behind an async mutex because `try_wait`, `wait`, and
/// `start_kill` require mutable access.
#[cfg(feature = "real_cores")]
struct ManagedProcessInstance {
    child: AsyncMutex<Child>,
    config: CoreConfig,
    probe_address: SocketAddr,
}

/// Generic supervisor for an operator-provided Xray or sing-box executable.
///
/// The adapter does not accept config bytes through stdin and does not interpolate
/// opaque user strings into command arguments. A production operator mounts a
/// reviewed JSON config at an absolute path and exposes that path as
/// `opaque_config.config_path`; the only command form emitted is
/// `<binary> run -c <config_path>`.
#[cfg(feature = "real_cores")]
pub struct ManagedProcessAdapter {
    kind: CoreKind,
    binary_env: &'static str,
    default_binary: &'static str,
    instances: DashMap<String, Arc<ManagedProcessInstance>>,
    lifecycle: AsyncMutex<()>,
}

#[cfg(feature = "real_cores")]
impl ManagedProcessAdapter {
    /// Build the Xray process adapter. Set `AETHER_XRAY_BIN` when `xray` is
    /// not on `PATH` in the workload image.
    #[must_use]
    pub fn xray() -> Self {
        Self::new(CoreKind::Xray, "AETHER_XRAY_BIN", "xray")
    }

    /// Build the sing-box process adapter. Set `AETHER_SING_BOX_BIN` when
    /// `sing-box` is not on `PATH` in the workload image.
    #[must_use]
    pub fn sing_box() -> Self {
        Self::new(CoreKind::SingBox, "AETHER_SING_BOX_BIN", "sing-box")
    }

    fn new(kind: CoreKind, binary_env: &'static str, default_binary: &'static str) -> Self {
        Self {
            kind,
            binary_env,
            default_binary,
            instances: DashMap::new(),
            lifecycle: AsyncMutex::new(()),
        }
    }

    fn binary(&self) -> String {
        match std::env::var(self.binary_env) {
            Ok(value) if !value.trim().is_empty() => value,
            _ => self.default_binary.to_string(),
        }
    }

    fn launch_contract(&self, config: &CoreConfig) -> Result<(PathBuf, SocketAddr)> {
        if config.kind != self.kind {
            return Err(SupervisorError::InvalidConfig {
                kind: self.kind,
                reason: format!("adapter received config for {}", config.kind),
            });
        }
        let Some(object) = config.protocol.opaque_config.as_object() else {
            return Err(SupervisorError::InvalidConfig {
                kind: self.kind,
                reason: "opaque_config must be an object containing config_path".to_string(),
            });
        };
        let Some(config_path) = object.get("config_path").and_then(serde_json::Value::as_str)
        else {
            return Err(SupervisorError::InvalidConfig {
                kind: self.kind,
                reason: "opaque_config.config_path is required".to_string(),
            });
        };
        let config_path = PathBuf::from(config_path);
        if !config_path.is_absolute() {
            return Err(SupervisorError::InvalidConfig {
                kind: self.kind,
                reason: "opaque_config.config_path must be absolute".to_string(),
            });
        }
        let metadata = std::fs::metadata(&config_path).map_err(|error| {
            SupervisorError::InvalidConfig {
                kind: self.kind,
                reason: format!("cannot read config_path {}: {error}", config_path.display()),
            }
        })?;
        if !metadata.is_file() {
            return Err(SupervisorError::InvalidConfig {
                kind: self.kind,
                reason: "opaque_config.config_path must name a regular file".to_string(),
            });
        }
        let probe_address = loopback_probe_address(&config.protocol.listen_addr, self.kind)?;
        Ok((config_path, probe_address))
    }

    fn spawn_process(
        &self,
        config: &CoreConfig,
        config_path: PathBuf,
        probe_address: SocketAddr,
    ) -> Result<Arc<ManagedProcessInstance>> {
        let child = Command::new(self.binary())
            .arg("run")
            .arg("-c")
            .arg(config_path)
            .kill_on_drop(true)
            .spawn()
            .map_err(|source| SupervisorError::CoreExited {
                instance: config.instance_id.clone(),
                source,
            })?;
        Ok(Arc::new(ManagedProcessInstance {
            child: AsyncMutex::new(child),
            config: config.clone(),
            probe_address,
        }))
    }

    async fn terminate(
        &self,
        instance_id: &str,
        process: Arc<ManagedProcessInstance>,
        timeout: Duration,
    ) -> Result<()> {
        let mut child = process.child.lock().await;
        child
            .start_kill()
            .map_err(|source| SupervisorError::CoreExited {
                instance: instance_id.to_string(),
                source,
            })?;
        match tokio::time::timeout(timeout.max(Duration::from_millis(1)), child.wait()).await {
            Ok(Ok(_status)) => Ok(()),
            Ok(Err(source)) => Err(SupervisorError::CoreExited {
                instance: instance_id.to_string(),
                source,
            }),
            Err(_) => Err(SupervisorError::Generic(format!(
                "core {instance_id} did not exit within {timeout:?} after forced termination"
            ))),
        }
    }
}

#[cfg(feature = "real_cores")]
impl std::fmt::Debug for ManagedProcessAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagedProcessAdapter")
            .field("kind", &self.kind)
            .field("binary_env", &self.binary_env)
            .field("instances", &self.instances.len())
            .finish()
    }
}

#[cfg(feature = "real_cores")]
#[async_trait]
impl ProtocolCore for ManagedProcessAdapter {
    fn kind(&self) -> CoreKind {
        self.kind
    }

    async fn start(&self, config: CoreConfig) -> Result<CoreHandle> {
        let _lifecycle = self.lifecycle.lock().await;
        if self.instances.contains_key(&config.instance_id) {
            return Err(SupervisorError::InstanceExists(config.instance_id));
        }
        let (config_path, probe_address) = self.launch_contract(&config)?;
        let process = self.spawn_process(&config, config_path, probe_address)?;
        let handle = CoreHandle {
            instance_id: config.instance_id.clone(),
            kind: self.kind,
            protocol_id: config.protocol.protocol_id.clone(),
        };
        self.instances.insert(config.instance_id, process);
        Ok(handle)
    }

    async fn stop(&self, handle: &CoreHandle, drain: bool, timeout: Duration) -> Result<()> {
        if drain {
            return Err(SupervisorError::NotHotSwapCapable(handle.instance_id.clone()));
        }
        let _lifecycle = self.lifecycle.lock().await;
        let (_, process) = self
            .instances
            .remove(&handle.instance_id)
            .ok_or_else(|| SupervisorError::InstanceNotFound(handle.instance_id.clone()))?;
        self.terminate(&handle.instance_id, process, timeout).await
    }

    async fn restart(&self, handle: &CoreHandle) -> Result<()> {
        let _lifecycle = self.lifecycle.lock().await;
        let process = self
            .instances
            .get(&handle.instance_id)
            .map(|entry| entry.clone())
            .ok_or_else(|| SupervisorError::InstanceNotFound(handle.instance_id.clone()))?;
        let config = process.config.clone();
        let (_, previous) = self
            .instances
            .remove(&handle.instance_id)
            .ok_or_else(|| SupervisorError::InstanceNotFound(handle.instance_id.clone()))?;
        self.terminate(&handle.instance_id, previous, Duration::from_secs(2))
            .await?;
        let (config_path, probe_address) = self.launch_contract(&config)?;
        let replacement = self.spawn_process(&config, config_path, probe_address)?;
        self.instances.insert(handle.instance_id.clone(), replacement);
        Ok(())
    }

    async fn health(&self, handle: &CoreHandle) -> Result<HealthStatus> {
        let process = self
            .instances
            .get(&handle.instance_id)
            .map(|entry| entry.clone())
            .ok_or_else(|| SupervisorError::InstanceNotFound(handle.instance_id.clone()))?;
        let exit_status = {
            let mut child = process.child.lock().await;
            child
                .try_wait()
                .map_err(|source| SupervisorError::CoreExited {
                    instance: handle.instance_id.clone(),
                    source,
                })?
        };
        if exit_status.is_some() {
            self.instances.remove(&handle.instance_id);
            return Ok(HealthStatus {
                status: CoreStatus::Failed,
                success_rate: 0.0,
            });
        }
        let probe = tokio::time::timeout(
            LISTENER_PROBE_TIMEOUT,
            TcpStream::connect(process.probe_address),
        )
        .await;
        match probe {
            Ok(Ok(_stream)) => Ok(HealthStatus {
                status: CoreStatus::Running,
                success_rate: 1.0,
            }),
            Ok(Err(_)) | Err(_) => Ok(HealthStatus {
                status: CoreStatus::Degraded,
                success_rate: 0.0,
            }),
        }
    }

    async fn metrics(&self, handle: &CoreHandle) -> Result<CoreMetrics> {
        if !self.instances.contains_key(&handle.instance_id) {
            return Err(SupervisorError::InstanceNotFound(handle.instance_id.clone()));
        }
        // Do not fabricate connection counts or memory usage. The native core
        // statistics API remains the authority for those metrics.
        Ok(CoreMetrics::default())
    }

    fn supports_fallback_to(&self) -> Vec<String> {
        match self.kind {
            CoreKind::Xray => vec!["grpc".to_string(), "ws".to_string(), "xhttp".to_string()],
            CoreKind::SingBox => vec!["hysteria2".to_string(), "tuic-v5".to_string()],
            _ => Vec::new(),
        }
    }
}

#[cfg(feature = "real_cores")]
fn loopback_probe_address(listen_addr: &str, kind: CoreKind) -> Result<SocketAddr> {
    let address = listen_addr
        .parse::<SocketAddr>()
        .map_err(|error| SupervisorError::InvalidConfig {
            kind,
            reason: format!("protocol.listen_addr must be an explicit socket address: {error}"),
        })?;
    if address.port() == 0 {
        return Err(SupervisorError::InvalidConfig {
            kind,
            reason: "protocol.listen_addr must use a non-zero listener port".to_string(),
        });
    }
    let loopback_ip = match address.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    Ok(SocketAddr::new(loopback_ip, address.port()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{ProtocolSpec, ResourceLimits};

    fn cfg(id: &str) -> CoreConfig {
        CoreConfig {
            instance_id: id.into(),
            kind: CoreKind::Xray,
            protocol: ProtocolSpec {
                protocol_id: "mock".into(),
                opaque_config: serde_json::json!({}),
                hot_swap_capable: true,
                listen_addr: "127.0.0.1:0".into(),
            },
            limits: ResourceLimits::default(),
            max_restarts: 3,
            restart_window_secs: 60,
        }
    }

    #[tokio::test]
    async fn mock_start_then_health() -> Result<()> {
        let core = MockCore::default();
        let handle = core.start(cfg("a1")).await?;
        let status = core.health(&handle).await?;
        assert_eq!(status.status, CoreStatus::Running);
        Ok(())
    }

    #[tokio::test]
    async fn mock_duplicate_start_errors() -> Result<()> {
        let core = MockCore::default();
        let _handle = core.start(cfg("dup")).await?;
        let error = core.start(cfg("dup")).await.err();
        assert!(matches!(error, Some(SupervisorError::InstanceExists(_))));
        Ok(())
    }

    #[cfg(feature = "real_cores")]
    #[test]
    fn managed_core_requires_an_absolute_reviewed_config_path(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let adapter = ManagedProcessAdapter::xray();
        let mut config = cfg("managed-xray");
        config.protocol.opaque_config = serde_json::json!({"config_path": "relative.json"});
        assert!(matches!(
            adapter.launch_contract(&config),
            Err(SupervisorError::InvalidConfig { .. })
        ));

        let file = tempfile::NamedTempFile::new()?;
        let path = file.path().to_string_lossy().to_string();
        config.protocol.opaque_config = serde_json::json!({"config_path": path});
        config.protocol.listen_addr = "0.0.0.0:14443".to_string();
        let (_path, probe) = adapter.launch_contract(&config)?;
        assert_eq!(probe, "127.0.0.1:14443".parse()?);
        Ok(())
    }
}
