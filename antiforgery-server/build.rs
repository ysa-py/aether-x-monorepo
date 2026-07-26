// Compile the antiforgery gRPC contract from the monorepo's canonical protos.
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let proto_root = manifest_dir.join("../api/proto");
    let proto = proto_root.join("aether/antiforgery/v1/antiforgery.proto");
    assert!(
        proto.exists(),
        "antiforgery proto not found: {}. Run from the monorepo root.",
        proto.display()
    );

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&[proto.to_str().unwrap()], &[proto_root.to_str().unwrap()])?;

    println!("cargo:rerun-if-changed={}", proto.display());
    Ok(())
}
