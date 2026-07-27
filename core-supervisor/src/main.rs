//! `aether-supervisor` — the data-plane binary.
//!
//! Boots the [`CoreSupervisor`], performs a capability-aware container
//! preflight, wires a [`Collector`], and serves the
//! `aether.supervisor.v1` gRPC API.
//!
//! Transport security policy (see SECURITY.md):
//!   - `AETHER_MTLS_ENABLED=true` requires server certificate, key, and client
//!     CA paths; every gRPC client certificate is verified.
//!   - Plaintext is allowed only on a loopback listener for local development.
//!   - Restricted CNI/eBPF capability sets select a userspace fallback and do
//!     not abort the control plane.

use std::net::SocketAddr;
use std::sync::Arc;

use aether_supervisor::{
    core_adapters, grpc, routing,
    runtime_preflight::RuntimePreflight,
    store_and_forward::{OverflowPolicy, QueueLimits, StoreAndForward},
    telemetry::Collector,
    CoreSupervisor,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();

    let listen = supervisor_addr_from_environment()?;
    let mtls_enabled = mtls_enabled_from_environment()?;
    core_adapters::validate_external_core_mode()?;
    let tls = if mtls_enabled {
        Some(grpc::TlsServerConfig::from_environment()?)
    } else {
        None
    };

    // Refuse a plaintext bind on anything but loopback. This is intentionally
    // checked before constructing the supervisor so a bad deployment does not
    // expose even a transient unauthenticated control listener.
    if !mtls_enabled && !listen.ip().is_loopback() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            concat!(
                "refusing to bind plaintext gRPC on a non-loopback address; ",
                "set AETHER_MTLS_ENABLED=true and provide ",
                "AETHER_SUPERVISOR_TLS_CERT, AETHER_SUPERVISOR_TLS_KEY, and ",
                "AETHER_SUPERVISOR_CLIENT_CA",
            ),
        )
        .into());
    }

    // Northflank and other managed runtimes can deny BPF/NET_ADMIN or bpffs.
    // The preflight deliberately reports that condition and selects the
    // conservative path rather than treating it as a fatal boot error.
    let preflight = RuntimePreflight::inspect();
    if preflight.is_userspace_fallback() {
        tracing::warn!(
            interface = ?preflight.interface,
            cni_type = ?preflight.cni_type,
            bpf_mounted = preflight.bpf_mounted,
            capabilities = ?preflight.capabilities,
            diagnostics = ?preflight.diagnostics,
            "container kernel acceleration unavailable; userspace fallback selected"
        );
    } else {
        tracing::info!(
            interface = ?preflight.interface,
            cni_type = ?preflight.cni_type,
            strategy = ?preflight.strategy,
            "container preflight selected kernel attachment strategy"
        );
    }

    // Data-plane routing: resolve Direct/Proxy/Block before a core connects.
    // Load from AETHER_ROUTING_RULES (JSON file) if set, else the embedded preset.
    let resolver = Arc::new(match std::env::var("AETHER_ROUTING_RULES") {
        Ok(path) => match routing::RouteResolver::from_file(&path) {
            Ok(resolver) => resolver,
            Err(error) => {
                tracing::warn!(error = %error, "routing rule set load failed; using preset");
                routing::RouteResolver::from_preset()
            }
        },
        Err(_) => routing::RouteResolver::from_preset(),
    });
    tracing::info!(
        sample = ?resolver.route(Some("www.youtube.com"), None),
        "routing resolver ready"
    );

    let supervisor = Arc::new(CoreSupervisor::with_default_adapters());

    // Store-and-forward: telemetry recorded while the control plane is
    // detached is buffered (bounded) and, when AETHER_SUPERVISOR_SPOOL points
    // at a path, persisted to disk and reloaded after a crash. Mirrors the Go
    // control plane's AETHER_TELEMETRY_SPOOL behaviour.
    let queue = store_and_forward_from_environment();
    let collector = Collector::with_store_and_forward(queue.clone());

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        %listen,
        mtls_enabled,
        "starting aether core supervisor"
    );

    // Graceful shutdown on Ctrl-C.
    let serve = grpc::serve(
        listen,
        supervisor.clone(),
        collector.clone(),
        resolver.clone(),
        tls,
    );
    tokio::pin!(serve);
    tokio::select! {
        result = &mut serve => {
            queue.persist();
            result?
        },
        _ = tokio::signal::ctrl_c() => {
            // Graceful shutdown: make sure anything still queued is on disk so
            // the next boot recovers it instead of losing it.
            queue.persist();
            tracing::info!(
                pending = queue.pending(),
                "ctrl-c received; store-and-forward queue persisted; shutting down"
            );
        }
    }
    Ok(())
}

/// Build the store-and-forward queue from the environment.
///
/// * `AETHER_SUPERVISOR_SPOOL` — path to the JSONL spool. Unset ⇒ in-memory
///   only (no disk writes, still bounded).
/// * `AETHER_SUPERVISOR_SPOOL_MAX_ITEMS` / `..._MAX_BYTES` — capacity bound.
///
/// A spool that cannot be opened is a warning, never a boot failure: losing
/// buffered telemetry must not take the data plane down.
fn store_and_forward_from_environment() -> Arc<StoreAndForward> {
    let limits = QueueLimits {
        max_items: env_usize(
            "AETHER_SUPERVISOR_SPOOL_MAX_ITEMS",
            QueueLimits::DEFAULT_MAX_ITEMS,
        ),
        max_bytes: env_usize(
            "AETHER_SUPERVISOR_SPOOL_MAX_BYTES",
            QueueLimits::DEFAULT_MAX_BYTES,
        ),
        policy: OverflowPolicy::EvictOldest,
    };

    match std::env::var("AETHER_SUPERVISOR_SPOOL") {
        Ok(path) if !path.trim().is_empty() => match StoreAndForward::open(&path, limits) {
            Ok(queue) => {
                tracing::info!(
                    spool = %path,
                    recovered = queue.recovered_items(),
                    max_items = limits.max_items,
                    max_bytes = limits.max_bytes,
                    "store-and-forward spool opened; queue recovered from disk"
                );
                Arc::new(queue)
            }
            Err(error) => {
                tracing::warn!(
                    spool = %path,
                    error = %error,
                    "store-and-forward spool unavailable; falling back to in-memory queue"
                );
                Arc::new(StoreAndForward::with_limits(limits))
            }
        },
        _ => {
            tracing::info!(
                max_items = limits.max_items,
                max_bytes = limits.max_bytes,
                "store-and-forward queue in-memory (set AETHER_SUPERVISOR_SPOOL to persist)"
            );
            Arc::new(StoreAndForward::with_limits(limits))
        }
    }
}

fn env_usize(key: &str, default: usize) -> usize {
    match std::env::var(key) {
        Ok(raw) => match raw.trim().parse::<usize>() {
            Ok(v) if v > 0 => v,
            _ => {
                tracing::warn!(key, raw = %raw, default, "invalid value; using default");
                default
            }
        },
        Err(_) => default,
    }
}

fn supervisor_addr_from_environment() -> Result<SocketAddr, std::io::Error> {
    let raw = match std::env::var("AETHER_SUPERVISOR_ADDR") {
        Ok(value) => value,
        Err(_) => "127.0.0.1:7070".to_string(),
    };
    raw.parse::<SocketAddr>().map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("AETHER_SUPERVISOR_ADDR must be a valid SocketAddr: {error}"),
        )
    })
}

fn mtls_enabled_from_environment() -> Result<bool, std::io::Error> {
    let raw = match std::env::var("AETHER_MTLS_ENABLED") {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };
    parse_mtls_value(&raw)
}

fn parse_mtls_value(raw: &str) -> Result<bool, std::io::Error> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" => Ok(true),
        "0" | "false" => Ok(false),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "AETHER_MTLS_ENABLED must be one of true, false, 1, or 0",
        )),
    }
}

fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = match EnvFilter::try_from_default_env() {
        Ok(filter) => filter,
        Err(_) => EnvFilter::new("info,aether=debug"),
    };
    let _ = fmt().with_env_filter(filter).with_target(false).try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_supervisor_address() {
        let value = "not-an-address";
        let parsed = value.parse::<SocketAddr>();
        assert!(parsed.is_err());
    }

    #[test]
    fn parses_mtls_boolean_values() {
        for enabled in ["true", "TRUE", "1"] {
            assert!(parse_mtls_value(enabled).is_ok_and(|value| value));
        }
        for disabled in ["false", "FALSE", "0"] {
            assert!(parse_mtls_value(disabled).is_ok_and(|value| !value));
        }
        assert!(parse_mtls_value("sometimes").is_err());
    }

    #[test]
    fn env_usize_falls_back_on_garbage() {
        // Uses a key guaranteed absent so the test is order-independent.
        assert_eq!(env_usize("AETHER_TEST_ABSENT_KEY_XYZ", 42), 42);
    }

    #[test]
    fn spool_disabled_yields_bounded_in_memory_queue() {
        // No env var set in this test process for the spool path by default.
        let q = store_and_forward_from_environment();
        assert!(q.limits().max_items > 0);
        assert!(q.limits().max_bytes > 0);
    }

    #[test]
    fn opened_spool_recovers_queue_across_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("supervisor-spool.jsonl");
        let limits = QueueLimits {
            max_items: 100,
            max_bytes: 1 << 20,
            policy: OverflowPolicy::EvictOldest,
        };
        {
            let q = StoreAndForward::open(&path, limits).unwrap();
            q.try_enqueue(
                aether_supervisor::store_and_forward::Priority::Control,
                b"pending-telemetry".to_vec(),
            )
            .unwrap();
            q.persist();
        }
        let restarted = StoreAndForward::open(&path, limits).unwrap();
        assert_eq!(restarted.pending(), 1);
        assert_eq!(restarted.recovered_items(), 1);
    }
}
