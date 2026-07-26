//! tonic implementation of `aether.supervisor.v1.CoreSupervisorService`.
//!
//! This is the *only* network boundary the control plane sees. Every incoming
//! RPC is translated to a domain call on [`crate::CoreSupervisor`] and the
//! result is translated back to proto. All errors map to a `tonic::Status`
//! with a stable, parseable code so the control plane can react programmatically.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use thiserror::Error;
use tonic::{
    transport::{Certificate, Identity, Server, ServerTlsConfig},
    Request, Response, Status,
};
use tracing::info;

use crate::aether::supervisor::v1 as pb;
use crate::aether::telemetry::v1::{TelemetryBatch, TelemetryEvent};
use crate::routing::RouteResolver;
use crate::telemetry::{Collector, FLUSH_INTERVAL};
use crate::{fragmentation, policy, protocol, CoreSupervisor};
use aether_routing::Action;

/// The running server handle.
pub struct SupervisorServer {
    supervisor: Arc<CoreSupervisor>,
    collector: Collector,
    resolver: Arc<RouteResolver>,
    build_version: &'static str,
}

impl SupervisorServer {
    pub fn new(
        supervisor: Arc<CoreSupervisor>,
        collector: Collector,
        resolver: Arc<RouteResolver>,
    ) -> Self {
        Self {
            supervisor,
            collector,
            resolver,
            build_version: env!("CARGO_PKG_VERSION"),
        }
    }
}

#[tonic::async_trait]
impl pb::core_supervisor_service_server::CoreSupervisorService for SupervisorServer {
    async fn start_core(
        &self,
        req: Request<pb::StartCoreRequest>,
    ) -> Result<Response<pb::StartCoreResponse>, Status> {
        let cfg = req
            .into_inner()
            .config
            .ok_or_else(|| Status::invalid_argument("StartCoreRequest.config is required"))?;
        let domain = core_config_from_proto(cfg)?;
        let status = self
            .supervisor
            .start_core(domain)
            .await
            .map_err(|e| status_from(&e))?;
        Ok(Response::new(pb::StartCoreResponse {
            instance_id: String::new(), // caller already knows; left empty
            status: core_status_to_proto(status) as i32,
        }))
    }

    async fn stop_core(
        &self,
        req: Request<pb::StopCoreRequest>,
    ) -> Result<Response<pb::StopCoreResponse>, Status> {
        let inner = req.into_inner();
        let timeout = Duration::from_millis(u64::from(inner.drain_timeout_ms.max(1)));
        let status = self
            .supervisor
            .stop_core(&inner.instance_id, inner.drain, timeout)
            .await
            .map_err(|e| status_from(&e))?;
        Ok(Response::new(pb::StopCoreResponse {
            status: core_status_to_proto(status) as i32,
        }))
    }

    async fn restart_core(
        &self,
        req: Request<pb::RestartCoreRequest>,
    ) -> Result<Response<pb::RestartCoreResponse>, Status> {
        let inner = req.into_inner();
        let status = self
            .supervisor
            .restart_core(&inner.instance_id)
            .await
            .map_err(|e| status_from(&e))?;
        Ok(Response::new(pb::RestartCoreResponse {
            status: core_status_to_proto(status) as i32,
        }))
    }

    async fn list_cores(
        &self,
        _req: Request<pb::ListCoresRequest>,
    ) -> Result<Response<pb::ListCoresResponse>, Status> {
        let cores = self.supervisor.list_cores().await;
        let instances = cores
            .into_iter()
            .map(|c| pb::CoreInstance {
                instance_id: c.instance_id,
                kind: pb::CoreKind::Unspecified as i32, // supervisor doesn't persist kind in ListedCore
                protocol_id: c.protocol_id,
                status: pb::CoreStatus::Running as i32,
                started_at_unix_millis: 0,
                restart_count: c.restart_count,
                metrics: Some(pb::CoreMetrics {
                    active_connections: c.metrics.active_connections,
                    total_connections: c.metrics.total_connections,
                    rx_bytes_per_sec: c.metrics.rx_bytes_per_sec,
                    tx_bytes_per_sec: c.metrics.tx_bytes_per_sec,
                    p50_rtt_ms: c.metrics.p50_rtt_ms,
                    block_rate: c.metrics.block_rate,
                    cpu_fraction: c.metrics.cpu_fraction,
                    resident_bytes: c.metrics.resident_bytes,
                    collected_at_unix_millis: now_unix_millis(),
                }),
            })
            .collect();
        Ok(Response::new(pb::ListCoresResponse { instances }))
    }

    async fn hot_swap_protocol(
        &self,
        req: Request<pb::HotSwapProtocolRequest>,
    ) -> Result<Response<pb::HotSwapProtocolResponse>, Status> {
        let inner = req.into_inner();
        let new_proto = inner
            .new_protocol
            .ok_or_else(|| Status::invalid_argument("new_protocol is required"))?;
        let timeout = Duration::from_millis(u64::from(inner.drain_timeout_ms));
        let migrated = self
            .supervisor
            .hot_swap(&inner.instance_id, new_proto.protocol_id, timeout)
            .await
            .map_err(|e| status_from(&e))?;
        Ok(Response::new(pb::HotSwapProtocolResponse {
            instance_id: inner.instance_id,
            status: pb::CoreStatus::Running as i32,
            migrated_sessions: migrated,
        }))
    }

    async fn health_check(
        &self,
        _req: Request<pb::HealthCheckRequest>,
    ) -> Result<Response<pb::HealthCheckResponse>, Status> {
        let serving = self.supervisor.healthy().await;
        Ok(Response::new(pb::HealthCheckResponse {
            status: if serving {
                pb::health_check_response::ServingStatus::Serving as i32
            } else {
                pb::health_check_response::ServingStatus::NotServing as i32
            },
            version: self.build_version.to_string(),
        }))
    }

    async fn route(
        &self,
        req: Request<pb::RouteRequest>,
    ) -> Result<Response<pb::RouteResponse>, Status> {
        let r = req.into_inner();
        let domain = if r.domain.is_empty() {
            None
        } else {
            Some(r.domain.as_str())
        };
        let ip = if r.ip.is_empty() {
            None
        } else {
            match r.ip.parse::<std::net::IpAddr>() {
                Ok(parsed) => Some(parsed),
                Err(_) => return Err(Status::invalid_argument(format!("invalid ip: {}", r.ip))),
            }
        };
        let action = self.resolver.route(domain, ip);
        Ok(Response::new(pb::RouteResponse {
            action: action_to_proto(action),
            domain: r.domain,
            ip: r.ip,
        }))
    }

    async fn apply_policy(
        &self,
        req: Request<pb::ApplyPolicyRequest>,
    ) -> Result<Response<pb::ApplyPolicyResponse>, Status> {
        let inner = req.into_inner();
        let proto_policy = inner
            .policy
            .ok_or_else(|| Status::invalid_argument("policy is required"))?;
        let domain_policy = policy_from_proto(proto_policy);
        let eff = self
            .supervisor
            .apply_policy(&inner.instance_id, &domain_policy)
            .await
            .map_err(|e| status_from(&e))?;
        Ok(Response::new(pb::ApplyPolicyResponse {
            applied: true,
            effective_revision: eff,
        }))
    }

    type StreamTelemetryStream =
        std::pin::Pin<Box<dyn futures::Stream<Item = Result<TelemetryBatch, Status>> + Send>>;

    async fn stream_telemetry(
        &self,
        req: Request<pb::StreamTelemetryRequest>,
    ) -> Result<Response<Self::StreamTelemetryStream>, Status> {
        let kinds: std::collections::HashSet<i32> = req.into_inner().kinds.into_iter().collect();
        let collector = self.collector.clone();

        // Wrap the broadcast stream, buffering into FLUSH_INTERVAL batches.
        let stream = async_stream::try_stream! {
            let mut evs = collector.subscribe();
            let mut buf: Vec<TelemetryEvent> = Vec::new();
            loop {
                let next = tokio::time::timeout(FLUSH_INTERVAL, evs.next()).await;
                match next {
                    Ok(Some(Ok(ev))) => {
                        if kinds.is_empty() || kinds.contains(&ev.event) {
                            buf.push(ev);
                        }
                    }
                    Ok(Some(Err(_))) => continue, // broadcast lag; skip
                    Ok(None) => break,
                    Err(_) => {} // timed out — flush below
                }
                if !buf.is_empty() {
                    let batch = TelemetryBatch { events: std::mem::take(&mut buf) };
                    yield batch;
                }
            }
        };
        Ok(Response::new(Box::pin(stream)))
    }
}

// ---- proto <-> domain conversions --------------------------------------- //

fn now_unix_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

fn action_to_proto(a: Action) -> i32 {
    match a {
        Action::Direct => pb::RouteAction::Direct as i32,
        Action::Proxy => pb::RouteAction::Proxy as i32,
        Action::Block => pb::RouteAction::Block as i32,
    }
}

fn core_config_from_proto(c: pb::CoreConfig) -> Result<protocol::CoreConfig, Status> {
    let kind = protocol::kind_from_proto(c.kind).map_err(|e| status_from(&e))?;
    let proto_spec = c
        .protocol
        .ok_or_else(|| Status::invalid_argument("config.protocol is required"))?;
    let opaque = if proto_spec.opaque_config.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&proto_spec.opaque_config).map_err(|e| {
            Status::invalid_argument(format!("opaque_config is not valid JSON: {e}"))
        })?
    };
    let limits = c.limits.unwrap_or_default();
    Ok(protocol::CoreConfig {
        instance_id: c.instance_id,
        kind,
        protocol: protocol::ProtocolSpec {
            protocol_id: proto_spec.protocol_id,
            opaque_config: opaque,
            hot_swap_capable: proto_spec.hot_swap_capable,
            listen_addr: proto_spec.listen_addr,
        },
        limits: protocol::ResourceLimits {
            cpu_weight: limits.cpu_weight,
            memory_limit_bytes: limits.memory_limit_bytes,
            max_fds: limits.max_fds,
            max_inbound_conns: limits.max_inbound_conns,
        },
        max_restarts: c.max_restarts,
        restart_window_secs: c.restart_window_secs,
    })
}

fn policy_from_proto(p: pb::Policy) -> policy::Policy {
    let frag = p.fragmentation.unwrap_or_default();
    let mut offsets = [None; 4];
    for (i, o) in frag.split_offsets.iter().enumerate().take(4) {
        offsets[i] = Some(*o);
    }
    policy::Policy {
        protocol_id: p.protocol_id,
        fragmentation: fragmentation::FragmentationPolicy {
            enabled: frag.enabled,
            split_offsets: offsets,
            max_segments: frag.max_segments as u8,
        },
        fallback_chain: p.fallback_chain,
        revision: p.revision,
    }
}

fn core_status_to_proto(s: protocol::CoreStatus) -> pb::CoreStatus {
    match s {
        protocol::CoreStatus::Unspecified => pb::CoreStatus::Unspecified,
        protocol::CoreStatus::Starting => pb::CoreStatus::Starting,
        protocol::CoreStatus::Running => pb::CoreStatus::Running,
        protocol::CoreStatus::Draining => pb::CoreStatus::Draining,
        protocol::CoreStatus::Degraded => pb::CoreStatus::Degraded,
        protocol::CoreStatus::Stopped => pb::CoreStatus::Stopped,
        protocol::CoreStatus::Failed => pb::CoreStatus::Failed,
    }
}

fn status_from(e: &crate::SupervisorError) -> Status {
    use crate::SupervisorError as E;
    match e {
        E::InstanceNotFound(_) => Status::not_found(e.to_string()),
        E::InstanceExists(_) => Status::already_exists(e.to_string()),
        E::StalePolicy { .. } => Status::failed_precondition(e.to_string()),
        E::NotHotSwapCapable(_) => Status::unimplemented(e.to_string()),
        E::InvalidConfig { .. } => Status::invalid_argument(e.to_string()),
        E::RestartBudgetExhausted(_) => Status::resource_exhausted(e.to_string()),
        _ => Status::internal(e.to_string()),
    }
}

/// PEM material for a mutual-TLS supervisor listener.
///
/// The certificate must identify the DNS name used by the control plane (for
/// example `core-supervisor`) and `client_ca_pem` must be the CA that issued
/// the control-plane client certificate. The server does not accept anonymous
/// TLS clients when this configuration is supplied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsServerConfig {
    certificate_pem: Vec<u8>,
    private_key_pem: Vec<u8>,
    client_ca_pem: Vec<u8>,
}

impl TlsServerConfig {
    /// Load non-empty PEM files from explicit paths.
    pub fn from_paths(
        certificate_path: impl AsRef<Path>,
        private_key_path: impl AsRef<Path>,
        client_ca_path: impl AsRef<Path>,
    ) -> Result<Self, TlsConfigError> {
        Ok(Self {
            certificate_pem: read_pem(certificate_path.as_ref(), "server certificate")?,
            private_key_pem: read_pem(private_key_path.as_ref(), "server private key")?,
            client_ca_pem: read_pem(client_ca_path.as_ref(), "client CA")?,
        })
    }

    /// Load the supervisor's mTLS material from file paths in the environment.
    ///
    /// Required variables are `AETHER_SUPERVISOR_TLS_CERT`,
    /// `AETHER_SUPERVISOR_TLS_KEY`, and `AETHER_SUPERVISOR_CLIENT_CA`.
    pub fn from_environment() -> Result<Self, TlsConfigError> {
        let certificate_path = required_environment_path("AETHER_SUPERVISOR_TLS_CERT")?;
        let private_key_path = required_environment_path("AETHER_SUPERVISOR_TLS_KEY")?;
        let client_ca_path = required_environment_path("AETHER_SUPERVISOR_CLIENT_CA")?;
        Self::from_paths(certificate_path, private_key_path, client_ca_path)
    }

    fn into_tonic(self) -> ServerTlsConfig {
        ServerTlsConfig::new()
            .identity(Identity::from_pem(
                self.certificate_pem,
                self.private_key_pem,
            ))
            .client_ca_root(Certificate::from_pem(self.client_ca_pem))
    }
}

/// Errors raised while loading mTLS material before the listener starts.
#[derive(Debug, Error)]
pub enum TlsConfigError {
    /// A required path environment variable was not supplied.
    #[error("required mTLS environment variable {name} is missing or empty")]
    MissingEnvironment {
        /// Environment-variable name.
        name: &'static str,
    },
    /// A referenced file cannot be read.
    #[error("unable to read {kind} PEM at {path}: {source}")]
    Read {
        /// Material role, not secret contents.
        kind: &'static str,
        /// File path that failed.
        path: PathBuf,
        /// Underlying I/O failure.
        #[source]
        source: std::io::Error,
    },
    /// An empty file is never valid key material.
    #[error("{kind} PEM at {path} is empty")]
    Empty {
        /// Material role, not secret contents.
        kind: &'static str,
        /// Empty file path.
        path: PathBuf,
    },
}

fn required_environment_path(name: &'static str) -> Result<PathBuf, TlsConfigError> {
    let value = match std::env::var(name) {
        Ok(value) => value,
        Err(_) => {
            return Err(TlsConfigError::MissingEnvironment { name });
        }
    };
    if value.trim().is_empty() {
        return Err(TlsConfigError::MissingEnvironment { name });
    }
    Ok(PathBuf::from(value))
}

fn read_pem(path: &Path, kind: &'static str) -> Result<Vec<u8>, TlsConfigError> {
    let contents = std::fs::read(path).map_err(|source| TlsConfigError::Read {
        kind,
        path: path.to_path_buf(),
        source,
    })?;
    if contents.is_empty() {
        return Err(TlsConfigError::Empty {
            kind,
            path: path.to_path_buf(),
        });
    }
    Ok(contents)
}

/// Bind and serve the supervisor gRPC API on `addr`.
///
/// `tls` must be supplied for every non-loopback listener. When present, tonic
/// requires and verifies a client certificate against the configured CA before
/// dispatching a gRPC request. `None` is retained exclusively for local
/// loopback development; `main` enforces that boundary before calling this
/// function.
pub async fn serve(
    addr: SocketAddr,
    supervisor: Arc<CoreSupervisor>,
    collector: Collector,
    resolver: Arc<RouteResolver>,
    tls: Option<TlsServerConfig>,
) -> Result<(), Box<dyn std::error::Error>> {
    let svc = SupervisorServer::new(supervisor, collector, resolver);
    let tls_enabled = tls.is_some();
    let builder = Server::builder();
    let mut builder = match tls {
        Some(config) => builder.tls_config(config.into_tonic())?,
        None => builder,
    };
    info!(%addr, tls_enabled, "core supervisor gRPC server listening");
    builder
        .add_service(pb::core_supervisor_service_server::CoreSupervisorServiceServer::new(svc))
        .serve(addr)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tls_tests {
    use super::*;

    #[test]
    fn rejects_empty_mtls_material() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let certificate = directory.path().join("cert.pem");
        let private_key = directory.path().join("key.pem");
        let client_ca = directory.path().join("ca.pem");
        std::fs::write(&certificate, b"certificate")?;
        std::fs::write(&private_key, b"")?;
        std::fs::write(&client_ca, b"ca")?;

        let result = TlsServerConfig::from_paths(&certificate, &private_key, &client_ca);
        assert!(matches!(
            result,
            Err(TlsConfigError::Empty {
                kind: "server private key",
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn loads_non_empty_mtls_material() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let certificate = directory.path().join("cert.pem");
        let private_key = directory.path().join("key.pem");
        let client_ca = directory.path().join("ca.pem");
        std::fs::write(&certificate, b"certificate")?;
        std::fs::write(&private_key, b"private-key")?;
        std::fs::write(&client_ca, b"ca")?;

        let config = TlsServerConfig::from_paths(&certificate, &private_key, &client_ca)?;
        assert_eq!(config.certificate_pem, b"certificate");
        assert_eq!(config.private_key_pem, b"private-key");
        assert_eq!(config.client_ca_pem, b"ca");
        Ok(())
    }
}
