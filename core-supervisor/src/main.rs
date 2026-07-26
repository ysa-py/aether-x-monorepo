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
    core_adapters,
    grpc,
    routing,
    runtime_preflight::RuntimePreflight,
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
        return Err(
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                concat!(
                    "refusing to bind plaintext gRPC on a non-loopback address; ",
                    "set AETHER_MTLS_ENABLED=true and provide ",
                    "AETHER_SUPERVISOR_TLS_CERT, AETHER_SUPERVISOR_TLS_KEY, and ",
                    "AETHER_SUPERVISOR_CLIENT_CA",
                ),
            )
            .into(),
        );
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
    let collector = Collector::new();

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
        result = &mut serve => result?,
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("ctrl-c received; shutting down");
        }
    }
    Ok(())
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
}
