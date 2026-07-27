//! The [`CoreSupervisor`] — owns the lifecycle of every supervised core.
//!
//! The supervisor is the *only* component that touches core adapters. It is
//! concurrency-safe (DashMap + adapter `Arc`s) and deliberately stateful: it
//! tracks the effective policy revision per instance so stale AI pushes are
//! rejected, and it runs a bounded restart loop so a flapping core cannot
//! consume the node.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::sync::Mutex;

use crate::error::{Result, SupervisorError};
use crate::policy::Policy;
use crate::protocol::{CoreConfig, CoreHandle, CoreKind, CoreMetrics, CoreStatus, ProtocolCore};

/// Maximum time a spawned adapter may take to prove its listener is ready.
const CORE_STARTUP_READY_TIMEOUT: Duration = Duration::from_secs(5);
/// Backoff between readiness probes. Bounded to avoid a retry storm at boot.
const CORE_STARTUP_PROBE_INTERVAL: Duration = Duration::from_millis(100);

/// A record the supervisor keeps per running instance.
pub(super) struct InstanceRecord {
    pub handle: CoreHandle,
    pub kind: CoreKind,
    pub protocol_id: String,
    pub started_at: Instant,
    pub restarts: u32,
    pub max_restarts: u32,
    pub restart_window: Duration,
    /// Monotonic effective policy revision; guards against stale AI pushes.
    pub effective_revision: u64,
}

/// The data-plane supervisor.
pub struct CoreSupervisor {
    adapters: HashMap<CoreKind, Arc<dyn ProtocolCore>>,
    instances: DashMap<String, Arc<Mutex<InstanceRecord>>>,
}

impl CoreSupervisor {
    /// Construct with an explicit adapter set (see [`crate::core_adapters::default_adapters`]).
    pub fn new(adapters: HashMap<CoreKind, Arc<dyn ProtocolCore>>) -> Self {
        Self {
            adapters,
            instances: DashMap::new(),
        }
    }

    /// Construct with the default in-process adapters.
    pub fn with_default_adapters() -> Self {
        Self::new(crate::core_adapters::default_adapters())
    }

    fn adapter(&self, kind: CoreKind) -> Result<Arc<dyn ProtocolCore>> {
        self.adapters
            .get(&kind)
            .cloned()
            .ok_or_else(|| SupervisorError::Generic(format!("no adapter for {kind:?}")))
    }

    /// Start a core. Idempotent on `instance_id`.
    pub async fn start_core(&self, config: CoreConfig) -> Result<CoreStatus> {
        if self.instances.contains_key(&config.instance_id) {
            return Err(SupervisorError::InstanceExists(config.instance_id));
        }
        let adapter = self.adapter(config.kind)?;
        let handle = adapter.start(config.clone()).await?;
        if let Err(error) = wait_for_startup_readiness(adapter.clone(), &handle).await {
            // A spawned PID with no listener is not a running core. Best-effort
            // cleanup prevents a failed start from leaking a child process;
            // the readiness error remains the caller-visible root cause.
            if let Err(cleanup_error) = adapter.stop(&handle, false, Duration::from_secs(2)).await {
                tracing::error!(
                    instance = %handle.instance_id,
                    error = %cleanup_error,
                    "failed to clean up an unready core"
                );
            }
            return Err(error);
        }
        let rec = Arc::new(Mutex::new(InstanceRecord {
            handle,
            kind: config.kind,
            protocol_id: config.protocol.protocol_id.clone(),
            started_at: Instant::now(),
            restarts: 0,
            max_restarts: config.max_restarts,
            restart_window: Duration::from_secs(u64::from(config.restart_window_secs.max(1))),
            effective_revision: 0,
        }));
        self.instances
            .insert(config.instance_id.clone(), rec.clone());

        // Spawn a lightweight health watcher. A real impl would also enforce
        // cgroups here; the adapter owns process spawn.
        let adapters = self.adapters.clone();
        let id = config.instance_id;
        tokio::spawn(async move {
            if let Err(e) = watch_and_restart(id, rec, adapters).await {
                tracing::error!(error = %e, "health watcher exited");
            }
        });

        Ok(CoreStatus::Running)
    }

    /// Stop a core, optionally draining first.
    pub async fn stop_core(
        &self,
        instance_id: &str,
        drain: bool,
        timeout: Duration,
    ) -> Result<CoreStatus> {
        let rec = self
            .instances
            .get(instance_id)
            .map(|r| r.clone())
            .ok_or_else(|| SupervisorError::InstanceNotFound(instance_id.to_string()))?;
        let adapter = {
            let g = rec.lock().await;
            self.adapter(g.kind)?
        };
        let handle = {
            let g = rec.lock().await;
            g.handle.clone()
        };
        adapter.stop(&handle, drain, timeout).await?;
        self.instances.remove(instance_id);
        Ok(CoreStatus::Stopped)
    }

    /// Restart a core in place.
    pub async fn restart_core(&self, instance_id: &str) -> Result<CoreStatus> {
        let rec = self
            .instances
            .get(instance_id)
            .map(|r| r.clone())
            .ok_or_else(|| SupervisorError::InstanceNotFound(instance_id.to_string()))?;
        let (adapter, handle) = {
            let g = rec.lock().await;
            (self.adapter(g.kind)?, g.handle.clone())
        };
        adapter.restart(&handle).await?;
        wait_for_startup_readiness(adapter.clone(), &handle).await?;
        let mut g = rec.lock().await;
        g.restarts += 1;
        g.started_at = Instant::now();
        Ok(CoreStatus::Running)
    }

    /// Hot-swap the protocol of an instance, draining where supported.
    pub async fn hot_swap(
        &self,
        instance_id: &str,
        new_protocol_id: String,
        drain_timeout: Duration,
    ) -> Result<bool> {
        let rec = self
            .instances
            .get(instance_id)
            .map(|r| r.clone())
            .ok_or_else(|| SupervisorError::InstanceNotFound(instance_id.to_string()))?;
        // Only adapters that advertise hot-swap may drain+migrate; others are
        // hard-cut (migrated = false). A real impl calls adapter.start(new) +
        // adapter.stop(old, drain); for Phase 0 we mutate the recorded protocol.
        let migrated = drain_timeout != Duration::ZERO;
        let mut g = rec.lock().await;
        g.protocol_id = new_protocol_id;
        g.started_at = Instant::now();
        Ok(migrated)
    }

    /// Apply a (monotonically revisioned) policy. Stale revisions are rejected.
    pub async fn apply_policy(&self, instance_id: &str, policy: &Policy) -> Result<u64> {
        let rec = self
            .instances
            .get(instance_id)
            .map(|r| r.clone())
            .ok_or_else(|| SupervisorError::InstanceNotFound(instance_id.to_string()))?;
        let mut g = rec.lock().await;
        if policy.revision <= g.effective_revision {
            return Err(SupervisorError::StalePolicy {
                provided: policy.revision,
                effective: g.effective_revision,
            });
        }
        // Apply fragmentation immediately; the fallback chain is advisory and
        // consumed by [`crate::policy::FallbackEngine`].
        g.effective_revision = policy.revision;
        Ok(g.effective_revision)
    }

    /// List all instances with a cheap metrics snapshot.
    pub async fn list_cores(&self) -> Vec<ListedCore> {
        let mut out = Vec::with_capacity(self.instances.len());
        for entry in &self.instances {
            let rec = entry.value().clone();
            let (adapter, handle, protocol_id, restarts) = {
                let g = rec.lock().await;
                (
                    self.adapters.get(&g.kind).cloned(),
                    g.handle.clone(),
                    g.protocol_id.clone(),
                    g.restarts,
                )
            };
            let metrics = match adapter {
                Some(adapter) => match adapter.metrics(&handle).await {
                    Ok(metrics) => metrics,
                    Err(error) => {
                        tracing::debug!(
                            instance = %handle.instance_id,
                            error = %error,
                            "core metrics unavailable"
                        );
                        CoreMetrics::default()
                    }
                },
                None => CoreMetrics::default(),
            };
            out.push(ListedCore {
                instance_id: entry.key().clone(),
                protocol_id,
                restart_count: restarts,
                metrics,
            });
        }
        out
    }

    /// Aggregate health for the orchestrator's readiness probe.
    pub async fn healthy(&self) -> bool {
        if self.instances.is_empty() {
            return true;
        }
        for entry in &self.instances {
            let rec = entry.value().clone();
            let (adapter, handle) = {
                let g = rec.lock().await;
                (self.adapters.get(&g.kind).cloned(), g.handle.clone())
            };
            if let Some(a) = adapter {
                match a.health(&handle).await {
                    Ok(h) if h.status == CoreStatus::Running => {}
                    _ => return false,
                }
            }
        }
        true
    }
}

/// A flattened instance view returned by [`CoreSupervisor::list_cores`].
#[derive(Debug, Clone)]
pub struct ListedCore {
    pub instance_id: String,
    pub protocol_id: String,
    pub restart_count: u32,
    pub metrics: CoreMetrics,
}

/// Wait until an adapter proves it has a healthy listener. The adapter owns
/// the protocol-specific probe; the supervisor only enforces a bounded retry
/// policy and never turns a successful spawn into a false readiness claim.
async fn wait_for_startup_readiness(
    adapter: Arc<dyn ProtocolCore>,
    handle: &CoreHandle,
) -> Result<()> {
    let deadline = Instant::now() + CORE_STARTUP_READY_TIMEOUT;
    loop {
        match adapter.health(handle).await {
            Ok(health) if health.status == CoreStatus::Running => return Ok(()),
            Ok(health) => {
                tracing::debug!(
                    instance = %handle.instance_id,
                    status = ?health.status,
                    "core spawned but listener is not ready yet"
                );
            }
            Err(error) => {
                tracing::debug!(
                    instance = %handle.instance_id,
                    error = %error,
                    "core readiness probe failed"
                );
            }
        }
        if Instant::now() >= deadline {
            return Err(SupervisorError::Generic(format!(
                "core {} did not become ready within {CORE_STARTUP_READY_TIMEOUT:?}",
                handle.instance_id
            )));
        }
        tokio::time::sleep(CORE_STARTUP_PROBE_INTERVAL).await;
    }
}

/// Bounded restart watcher. Restarts a core within `max_restarts` per
/// `restart_window`; beyond that marks it FAILED and stops trying.
async fn watch_and_restart(
    instance_id: String,
    rec: Arc<Mutex<InstanceRecord>>,
    adapters: HashMap<CoreKind, Arc<dyn ProtocolCore>>,
) -> Result<()> {
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;

        let (adapter, handle, max_restarts, window) = {
            let g = rec.lock().await;
            let adapter = adapters.get(&g.kind).cloned();
            (adapter, g.handle.clone(), g.max_restarts, g.restart_window)
        };
        let Some(adapter) = adapter else { continue };

        let status = match adapter.health(&handle).await {
            Ok(h) => h.status,
            Err(_) => CoreStatus::Failed,
        };

        if status == CoreStatus::Failed {
            // Enforce the restart budget.
            let now_within_window = {
                let g = rec.lock().await;
                g.restarts < max_restarts && g.started_at.elapsed() < window
            };
            if now_within_window {
                tracing::warn!(%instance_id, "core unhealthy; restarting");
                if let Err(e) = adapter.restart(&handle).await {
                    tracing::error!(%instance_id, error = %e, "restart failed");
                }
                let mut g = rec.lock().await;
                g.restarts += 1;
                g.started_at = Instant::now();
            } else {
                tracing::error!(%instance_id, "restart budget exhausted");
                // The control plane sees the core as FAILED via health probes
                // and can act (e.g., spin a replacement node).
                return Err(SupervisorError::RestartBudgetExhausted(instance_id));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{ProtocolSpec, ResourceLimits};

    fn cfg(id: &str) -> CoreConfig {
        CoreConfig {
            instance_id: id.into(),
            // The test constructor does not request AETHER_EXTERNAL_CORE_MODE,
            // so SingBox resolves to MockCore even when real_cores is compiled.
            // This keeps lifecycle tests deterministic across feature flags.
            kind: CoreKind::SingBox,
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
    async fn start_list_stop() {
        let sv = CoreSupervisor::with_default_adapters();
        let st = sv.start_core(cfg("svc-1")).await.unwrap();
        assert_eq!(st, CoreStatus::Running);
        let listed = sv.list_cores().await;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].instance_id, "svc-1");
        let st = sv.stop_core("svc-1", false, Duration::ZERO).await.unwrap();
        assert_eq!(st, CoreStatus::Stopped);
        assert!(sv.list_cores().await.is_empty());
    }

    #[tokio::test]
    async fn policy_must_be_monotonic() {
        let sv = CoreSupervisor::with_default_adapters();
        sv.start_core(cfg("svc-2")).await.unwrap();
        let p1 = Policy {
            revision: 5,
            ..Policy::default_for("mock")
        };
        assert_eq!(sv.apply_policy("svc-2", &p1).await.unwrap(), 5);
        let p_stale = Policy {
            revision: 4,
            ..Policy::default_for("mock")
        };
        assert!(sv.apply_policy("svc-2", &p_stale).await.is_err());
        let p2 = Policy {
            revision: 6,
            ..Policy::default_for("mock")
        };
        assert_eq!(sv.apply_policy("svc-2", &p2).await.unwrap(), 6);
    }
}
