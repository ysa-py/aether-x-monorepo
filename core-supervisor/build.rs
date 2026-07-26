// Compile the gRPC contracts. We build from the monorepo's canonical protos so
// the data plane can never drift from the control-plane client.
//
// NOTE: protoc is not required; tonic_build uses a pure-Rust parser via the
// `prost`/`protox` stack when `protoc` is absent. If you pin an environment
// without that fallback, install `protoc` and it will be used transparently.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let proto_root = manifest_dir.join("../api/proto");

    let protos = [
        proto_root.join("aether/telemetry/v1/telemetry.proto"),
        proto_root.join("aether/supervisor/v1/supervisor.proto"),
    ];

    // Fail the build fast if the contract is missing — better than a silent
    // miscompile of the data plane against a stale copy.
    for p in &protos {
        assert!(
            p.exists(),
            "proto contract not found: {}. Run from the monorepo root.",
            p.display()
        );
    }

    tonic_build::configure()
        .build_server(true)
        .build_client(true) // needed for tests + control-plane-style probing
        .build_transport(true)
        .compile_protos(
            &protos
                .iter()
                .map(|p| p.to_str().unwrap())
                .collect::<Vec<_>>(),
            &[proto_root.to_str().unwrap()],
        )?;

    // Re-run if the contract changes.
    println!(
        "cargo:rerun-if-changed={}",
        proto_root.join("aether").display()
    );

    Ok(())
}
