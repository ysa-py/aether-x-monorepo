//! Fuzz target for transparency log consistency proofs (Subsystem D).
//!
//! Ensures the transparency log Merkle operations are robust against
//! malformed inputs and never panic.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Interpret the data as a series of 32-byte leaf hashes.
    if data.len() < 64 {
        return;
    }
    let n_leaves = (data.len() / 32).min(20);
    let leaves: Vec<Vec<u8>> = (0..n_leaves)
        .map(|i| data[i * 32..(i + 1) * 32].to_vec())
        .collect();

    // Build a transparency log and exercise all operations.
    let log = aether_supervisor::transparency::TransparencyLog::new([42u8; 32]);
    for leaf in &leaves {
        let commitment = aether_supervisor::transparency::CatalogCommitment {
            catalog_hash: {
                let mut h = [0u8; 32];
                h.copy_from_slice(&leaf[..32.min(leaf.len())]);
                if leaf.len() < 32 {
                    h[leaf.len()..].fill(0);
                }
                h
            },
            timestamp_unix: 1_700_000_000,
            description: "fuzz-test".to_string(),
        };
        log.append(&commitment);
    }

    // Exercise signed tree head.
    let _sth = log.get_signed_tree_head();

    // Exercise inclusion proofs for all valid indices.
    for i in 0..n_leaves as u64 {
        let _ = log.get_inclusion_proof(i);
    }

    // Exercise consistency proofs for valid prefix sizes.
    let size = log.size();
    if size > 1 {
        for m in 1..size {
            let _ = log.get_consistency_proof(m);
        }
    }
});
