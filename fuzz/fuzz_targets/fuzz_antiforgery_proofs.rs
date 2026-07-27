#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the antiforgery token verifier and Merkle proof verifier with arbitrary
// bytes. Corrupt signatures, truncated tokens, and malformed proof arrays must
// be rejected cleanly without panicking.
fuzz_target!(|data: &[u8]| {
    // --- Token verification with arbitrary string input ---
    let sk = aether_antiforgery::token::generate_signing_key();
    let vk = sk.verifying_key();
    let token_str = std::str::from_utf8(data).unwrap_or("");
    let _ = aether_antiforgery::token::verify(&vk, token_str);

    // --- Merkle tree from arbitrary leaf data + proof verification ---
    if data.len() >= 2 {
        let n = (data[0] as usize % 16) + 1; // 1..=16 leaves
        let leaves: Vec<Vec<u8>> = (0..n)
            .map(|i| vec![data[i % data.len()], data[(i + 1) % data.len()]])
            .collect();
        let tree = aether_antiforgery::merkle::MerkleTree::from_leaves(&leaves);
        if let Some(root) = tree.root() {
            for i in 0..tree.leaf_count() {
                if let Some(proof) = tree.proof(i) {
                    // Verify the real proof (should succeed).
                    let _ = aether_antiforgery::merkle::verify_proof(&root, &leaves[i], &proof);
                    // Verify with WRONG data (should fail, not panic).
                    let wrong = [0u8; 1];
                    let _ = aether_antiforgery::merkle::verify_proof(&root, &wrong, &proof);
                }
            }
        }
    }
});
