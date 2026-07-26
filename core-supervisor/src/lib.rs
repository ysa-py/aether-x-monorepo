//! Aether-X data plane library.
//!
//! The public surface of this crate is intentionally small:
//!   - [`CoreSupervisor`] — owns the lifecycle of every supervised core.
//!   - [`protocol::ProtocolCore`] — the trait every core adapter implements.
//!   - [`grpc`] — the tonic service that fronts [`CoreSupervisor`] over gRPC.
//!
//! See `ARCHITECTURE.md` for the plane split and the gRPC contract.

#![forbid(unsafe_code)]
// Tiered lint policy: correctness/suspicious/perf/style are HARD failures; the
// doc-flavored and cast-flavored pedantic lints are allowed because they are
// noisy on (a) internal data structs and (b) deliberate int/proto casts, and
// do not affect correctness. The genuinely valuable pedantic lints stay on.
#![warn(clippy::pedantic)]
#![allow(
    clippy::module_name_repetitions, // intentional prefixing for readability
    clippy::must_use_candidate,      // noisy on builders; enforce case-by-case
    clippy::missing_errors_doc,      // doc-coverage tracked separately, not hard
    clippy::missing_panics_doc,
    clippy::missing_docs_in_private_items,
    clippy::doc_markdown,            // we keep short tokens (SNI, RTT...) inline
    clippy::cast_possible_truncation, // deliberate casts at proto/i32 boundaries
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,      // usize/u64 -> f64 for small counts/rates
    clippy::result_large_err,         // Status is a large Err; acceptable here
    clippy::wildcard_imports          // used only in narrow test scopes
)]
#![allow(missing_docs)] // public-API docs are written by hand where they count

pub mod advanced_integration;
pub mod ai_dpi;
pub mod ai_morph;
pub mod anti_dpi;
pub mod active_probing_honeypot;
pub mod active_defense;
pub mod anomaly_detector;
pub mod autoheal;
pub mod blackout;
pub mod buffer_replay;
pub mod chaff;
pub mod cni_detector;
pub mod core_adapters;
pub mod decider;
pub mod deterministic_fallback;
pub mod dns_tunnel;
pub mod doh_tunnel;
pub mod domain_fronting;
pub mod domestic_intel;
pub mod dpi_forecast;
pub mod ebpf;
pub mod error;
pub mod failover;
pub mod fallback_transport;
pub mod fec_engine;
pub mod fragmentation;
pub mod grpc;
pub mod grpc_transport;
pub mod happy_eyeballs;
pub mod icmp_tunnel;
pub mod in_tls;
pub mod ipv6_routing;
pub mod isolation;
pub mod local_mesh;
pub mod loopback_buffer;
pub mod model_registry;
pub mod mpquic;
pub mod multi_tunnel;
pub mod multipath;
pub mod os_polymorphism;
pub mod out_of_band;
pub mod panic_wipe;
pub mod policy;
pub mod pqc_handshake;
pub mod probe_cadence;
pub mod protocol;
pub mod quic_migration;
pub mod resilience;
pub mod reverse_relay;
pub mod routing;
pub mod runtime_preflight;
pub mod seamless;
pub mod shadow_socket;
pub mod sni_whitelist;
pub mod sockops;
pub mod ssh_tunnel;
pub mod store_and_forward;
pub mod supervisor;
pub mod tcp_polymorphism;
pub mod telemetry;
pub mod tls;
pub mod tls_mimicry;
pub mod tor;
pub mod transparency;
pub mod xdp_engine;
pub mod zk_auth;
pub mod zkp_auth;
pub mod enterprise;

// Generated gRPC bindings. We declare the modules to mirror the protobuf
// package tree so prost's cross-package references (supervisor -> telemetry)
// resolve correctly: `crate::aether::supervisor::v1` etc. Generated code has
// no rustdoc, so we relax documentation lints for it.
#[allow(missing_docs, clippy::all, clippy::pedantic)]
pub mod aether {
    pub mod telemetry {
        pub mod v1 {
            tonic::include_proto!("aether.telemetry.v1");
        }
    }
    pub mod supervisor {
        pub mod v1 {
            tonic::include_proto!("aether.supervisor.v1");
        }
    }
}

pub use error::SupervisorError;
pub use supervisor::CoreSupervisor;
