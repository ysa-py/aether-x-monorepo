//! Property-based tests (proptest) for the anti-forgery core.
//!
//! These complement the example-based unit tests by exercising large random
//! input spaces. They satisfy the spec's §11 fuzz/coverage mandate at the
//! library level (cargo-fuzz libfuzzer targets are a separate, deeper layer).

use aether_antiforgery::{audit::AuditLog, merkle, token};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn merkle_every_inclusion_proof_verifies(
        leaves in prop::collection::vec("[a-z]{1,8}", 1..50)
    ) {
        let data: Vec<Vec<u8>> = leaves.iter().map(|s| s.as_bytes().to_vec()).collect();
        let tree = merkle::MerkleTree::from_leaves(&data);
        let root = tree.root().expect("non-empty");
        prop_assert_eq!(tree.leaf_count(), data.len());
        for (i, d) in data.iter().enumerate() {
            let proof = tree.proof(i).expect("in range");
            prop_assert!(
                merkle::verify_proof(&root, d, &proof),
                "inclusion proof failed for leaf {i}"
            );
        }
    }

    #[test]
    fn merkle_proof_height_is_logarithmic(n in 1usize..=2000) {
        let data: Vec<Vec<u8>> = (0..n).map(|i| (i as u64).to_le_bytes().to_vec()).collect();
        let tree = merkle::MerkleTree::from_leaves(&data);
        let proof = tree.proof(n / 2).expect("in range");
        let upper = ((n as f64).log2().ceil() as usize) + 1;
        prop_assert!(
            proof.len() <= upper,
            "proof height {} exceeds log bound {} for n={n}",
            proof.len(),
            upper
        );
    }

    #[test]
    fn merkle_root_is_deterministic_and_tamper_sensitive(
        leaves in prop::collection::vec("[a-z]{1,5}", 2..40)
    ) {
        let data: Vec<Vec<u8>> = leaves.iter().map(|s| s.as_bytes().to_vec()).collect();
        let root1 = merkle::MerkleTree::from_leaves(&data).root().expect("non-empty");
        // Determinism: same input, same root.
        let root1b = merkle::MerkleTree::from_leaves(&data).root().expect("non-empty");
        prop_assert_eq!(root1, root1b);

        // Any single-byte edit to any leaf MUST change the root (avalanche).
        let mut edited = data.clone();
        edited[0][0] ^= 0x01;
        let root2 = merkle::MerkleTree::from_leaves(&edited).root().expect("non-empty");
        prop_assert_ne!(root1, root2);
    }

    #[test]
    fn merkle_wrong_leaf_data_fails(n in 2usize..64, wrong in 1usize..64) {
        // Distinct payloads (each = its index) so a wrong index has genuinely
        // different data; otherwise equal-valued leaves would legitimately
        // verify against each other's proof.
        let data: Vec<Vec<u8>> = (0..n).map(|i| (i as u64).to_le_bytes().to_vec()).collect();
        let tree = merkle::MerkleTree::from_leaves(&data);
        let root = tree.root().expect("non-empty");
        let proof = tree.proof(0).expect("leaf 0 in range");
        let wrong_idx = wrong % n;
        if wrong_idx != 0 {
            // A proof for index 0 must NOT verify against a different leaf's data.
            prop_assert!(
                !merkle::verify_proof(&root, &data[wrong_idx], &proof),
                "wrong leaf {wrong_idx} unexpectedly verified against index-0 proof"
            );
        }
    }

    #[test]
    fn token_sign_verify_roundtrip(
        total in 1_000i64..1_000_000_000,
        used in 0i64..1_000,
        expires in 1i64..2_000_000_000
    ) {
        let sk = token::generate_signing_key();
        let vk = sk.verifying_key();
        let claims = token::Claims {
            subscription_id: "sub".into(),
            user_id: "u".into(),
            bytes_total: total + used,
            bytes_used: used,
            expires_unix: expires,
            issued_unix: 0,
            nonce: "n".into(),
        };
        let tok = token::issue(&sk, &claims).unwrap();
        prop_assert_eq!(token::verify(&vk, &tok).unwrap(), claims);
        // A forged key must fail to verify the same token.
        let other = token::generate_signing_key();
        prop_assert!(token::verify(&other.verifying_key(), &tok).is_err());
    }

    #[test]
    fn audit_honest_verifies_any_mutation_breaks(
        payloads in prop::collection::vec("[a-z0-9]{1,6}", 1..30)
    ) {
        let mut log = AuditLog::new();
        for p in &payloads {
            log.append(p.as_bytes().to_vec());
        }
        prop_assert!(log.verify().is_ok());
        prop_assert_eq!(log.len(), payloads.len());

        // Mutate the first record's payload; the chain must detect it.
        let mut records: Vec<_> = log.records().to_vec();
        if !records.is_empty() {
            records[0].payload[0] ^= 0x01;
            let tampered = AuditLog::from_records(records);
            prop_assert!(tampered.verify().is_err());
        }
    }

    #[test]
    fn audit_merkle_root_matches_tree(
        payloads in prop::collection::vec("[a-z0-9]{1,6}", 1..30)
    ) {
        let mut log = AuditLog::new();
        for p in &payloads {
            log.append(p.as_bytes().to_vec());
        }
        let via_log = log.merkle_root();
        let via_tree = merkle::MerkleTree::from_leaves(
            &log.records().iter().map(|r| r.payload.clone()).collect::<Vec<_>>(),
        )
        .root()
        .unwrap_or([0u8; 32]);
        prop_assert_eq!(via_log, via_tree);
        prop_assert_ne!(via_log, [0u8; 32]);
    }

    #[test]
    fn consistency_roundtrip_for_random_prefix(
        leaves in prop::collection::vec("[a-z]{1,4}", 2..64)
    ) {
        let data: Vec<Vec<u8>> = leaves.iter().map(|s| s.as_bytes().to_vec()).collect();
        let n = data.len();
        let big = merkle::MerkleTree::from_leaves(&data);
        let new_root = big.forest_root().expect("non-empty");
        for m in 1..n {
            let proof = big.consistency_proof(m).expect("0<m<n");
            let old_root = merkle::MerkleTree::from_leaves(&data[..m])
                .forest_root()
                .expect("non-empty");
            prop_assert!(
                merkle::verify_consistency(&old_root, &new_root, &proof),
                "consistency failed m={m} n={n}"
            );
        }
    }

    #[test]
    fn consistency_detects_tampered_old_root(
        leaves in prop::collection::vec("[a-z]{1,4}", 3..40),
        m in 1usize..40
    ) {
        let data: Vec<Vec<u8>> = leaves.iter().map(|s| s.as_bytes().to_vec()).collect();
        let n = data.len();
        let mm = (m % (n - 1).max(1)) + 1; // 1 <= mm < n
        let big = merkle::MerkleTree::from_leaves(&data);
        let proof = big.consistency_proof(mm).expect("in range");
        let mut bad_old = merkle::MerkleTree::from_leaves(&data[..mm])
            .forest_root()
            .expect("non-empty");
        bad_old[0] ^= 0x01;
        let new_root = big.forest_root().expect("non-empty");
        prop_assert!(!merkle::verify_consistency(&bad_old, &new_root, &proof));
    }
}
