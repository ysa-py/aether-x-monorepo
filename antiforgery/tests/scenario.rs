//! End-to-end scenario: issue a signed subscription token, append the lifecycle
//! to a tamper-evident audit log, refresh it under replay protection, and gate
//! it behind a concurrent-device limit. Exercises every module together.

use aether_antiforgery::{
    audit::AuditLog,
    device::DeviceRegistry,
    replay::{refresh_tag, RefreshVerifier, ReplayGuard},
    token::{self, Claims},
};

fn claims(bytes_used: i64, expires: i64) -> Claims {
    Claims {
        subscription_id: "sub-42".into(),
        user_id: "u-7".into(),
        bytes_total: 1_000_000_000,
        bytes_used,
        expires_unix: expires,
        issued_unix: 1_000_000,
        nonce: "issue-1".into(),
    }
}

#[test]
fn full_lifecycle_is_consistent_and_tamper_evident() {
    // 1. Issue a signed token.
    let sk = token::generate_signing_key();
    let vk = sk.verifying_key();
    let tok = token::issue(&sk, &claims(0, 2_000_000)).unwrap();
    let verified = token::verify(&vk, &tok).unwrap();
    assert!(verified.is_live(1_500_000));

    // 2. Record the lifecycle in a hash-chained audit log.
    let mut log = AuditLog::new();
    log.append(format!("create {}", verified.subscription_id).into_bytes());
    log.append(b"extend +30d".to_vec());
    log.append(b"reset quota".to_vec());
    assert!(log.verify().is_ok());

    // 3. Refresh under replay protection (rotating HMAC).
    let key = b"refresh-secret-key-xxxxxxxx".to_vec();
    let verifier = RefreshVerifier::new(key.clone(), 5_000);
    let now = 9_000_000_i64;
    let tag = refresh_tag(&key, &tok, "nonce-A", now);
    assert!(verifier.verify(&tok, "nonce-A", now, &tag, now).is_ok());

    let mut guard = ReplayGuard::new(60_000);
    assert!(guard.check_and_record("nonce-A", now).is_ok());
    // Replaying the same nonce is rejected.
    assert!(guard.check_and_record("nonce-A", now + 1).is_err());

    // 4. Gate usage behind a 2-device concurrent limit.
    let mut devices = DeviceRegistry::new();
    assert!(devices.register("sub-42", "fp-laptop", 2).is_ok());
    assert!(devices.register("sub-42", "fp-phone", 2).is_ok());
    assert!(devices.register("sub-42", "fp-tablet", 2).is_err());
    assert_eq!(devices.active_count("sub-42"), 2);
}

#[test]
fn forged_quota_is_rejected() {
    let sk = token::generate_signing_key();
    let vk = sk.verifying_key();
    let tok = token::issue(&sk, &claims(0, 2_000_000)).unwrap();

    // Attacker extracts claims, inflates the quota, re-signs with a forged key.
    let forged_sk = token::generate_signing_key();
    let mut tampered = token::verify(&vk, &tok).unwrap();
    tampered.bytes_total = 9_999_999_999_999;
    let forged_tok = token::issue(&forged_sk, &tampered).unwrap();

    // Against the REAL public key, the forged token fails verification.
    assert!(token::verify(&vk, &forged_tok).is_err());
}

#[test]
fn audit_detects_backdated_edit() {
    let mut log = AuditLog::new();
    log.append(b"create");
    log.append(b"extend");
    let root_before = log.root_hash();
    // A legitimate append changes the root.
    log.append(b"reset");
    assert_ne!(log.root_hash(), root_before);
    assert!(log.verify().is_ok());
    // Removing a middle record breaks the chain (prev_hash links no longer line up).
    let subset: Vec<_> = log
        .records()
        .iter()
        .enumerate()
        .filter_map(|(i, r)| if i != 1 { Some(r.clone()) } else { None })
        .collect();
    let tampered = AuditLog::from_records(subset);
    assert!(tampered.verify().is_err());
}

#[test]
fn audit_merkle_proofs_round_trip() {
    // The audit log can produce a Merkle root and per-record inclusion proofs.
    use aether_antiforgery::merkle;

    let mut log = AuditLog::new();
    for i in 0..50 {
        log.append(format!("mutation-{i}").into_bytes());
    }
    let root = log.merkle_root();
    assert_ne!(root, [0u8; 32]);

    // Build a tree over the same payloads and verify each record is provable.
    let tree = merkle::MerkleTree::from_leaves(
        &log.records()
            .iter()
            .map(|r| r.payload.clone())
            .collect::<Vec<_>>(),
    );
    assert_eq!(tree.root(), Some(root));
    for (i, r) in log.records().iter().enumerate() {
        let proof = tree.proof(i).expect("in range");
        assert!(
            merkle::verify_proof(&root, &r.payload, &proof),
            "record {i} should be provable"
        );
    }
    // O(log n): 50 leaves -> height ceil(log2(50)) = 6.
    assert_eq!(tree.proof(0).unwrap().len(), 6);
}
