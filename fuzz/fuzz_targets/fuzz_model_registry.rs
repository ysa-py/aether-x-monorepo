//! Fuzz target for model registry signature verification (Subsystem A).
//!
//! Ensures the ONNX artifact signature verification is robust against
//! malformed inputs and never panics.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Split input into: artifact_bytes | signature (64 bytes) | key (32 bytes).
    if data.len() < 97 {
        return; // need at least 1 + 64 + 32 bytes
    }
    let artifact_end = data.len() - 96;
    let artifact_bytes = &data[..artifact_end];
    let sig_bytes: [u8; 64] = data[artifact_end..artifact_end + 64]
        .try_into()
        .unwrap();
    let key_bytes: [u8; 32] = data[artifact_end + 64..artifact_end + 96]
        .try_into()
        .unwrap();

    // This must never panic.
    let _ = aether_supervisor::model_registry::verify_artifact_signature(
        artifact_bytes,
        &sig_bytes,
        &[key_bytes],
    );
});
