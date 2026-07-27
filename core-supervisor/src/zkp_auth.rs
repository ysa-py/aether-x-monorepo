//! Zero-Knowledge Proof Authentication — zk-SNARKs
//!
//! Validates incoming client authentication proofs using Zero-Knowledge Proofs
//! to verify subscription validity without revealing token IDs or client metadata.
//!
//! Flow:
//! - Client has subscription token and knows its hash is in Merkle tree (transparency log)
//! - Client creates zk-proof: "I know a token whose hash is in the tree and not expired/revoked, without revealing token"
//! - Server verifies proof against Merkle root, no token disclosure
//!
//! Production would use `ark-groth16` + circom circuit; here mock with Pedersen-like commitments
//! and deterministic hashing for zero dependencies.

use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// Subscription commitment (hash of token + blinding)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Commitment(pub [u8; 32]);

impl Commitment {
    /// Create commitment from token + blinding factor
    #[must_use]
    pub fn from_token(token: &str, blinding: &[u8; 32]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        hasher.update(blinding);
        let h = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&h);
        Self(out)
    }
}

/// Mock zk-SNARK proof: proves knowledge of token that maps to commitment in allowed set
/// without revealing token
#[derive(Debug, Clone)]
pub struct ZkProof {
    pub commitment: Commitment,
    pub nullifier: [u8; 32], // prevents double spend, derived from token+domain separator
    pub challenge_response: [u8; 32], // mock Fiat-Shamir response
    pub merkle_root: [u8; 32], // root client claims membership in
}

/// Subscription state for verification (from transparency log / antiforgery)
#[derive(Debug, Clone)]
pub struct SubscriptionState {
    pub commitment: Commitment,
    pub expires_unix: i64,
    pub revoked: bool,
    pub bytes_total: i64,
    pub bytes_used: i64,
}

/// ZKP Verifier – validates proofs without learning token
#[derive(Debug)]
pub struct ZkpVerifier {
    // Set of valid commitments (from Merkle tree leaves)
    valid_commitments: RwLock<HashSet<Commitment>>,
    // Nullifiers already used (prevent replay)
    used_nullifiers: RwLock<HashSet<[u8; 32]>>,
    // Merkle root
    merkle_root: RwLock<[u8; 32]>,
    verified_count: std::sync::atomic::AtomicU64,
}

impl ZkpVerifier {
    #[must_use]
    pub fn new(initial_root: [u8; 32]) -> Self {
        Self {
            valid_commitments: RwLock::new(HashSet::new()),
            used_nullifiers: RwLock::new(HashSet::new()),
            merkle_root: RwLock::new(initial_root),
            verified_count: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Add valid commitment (called when new subscription issued, from audit log)
    pub fn add_commitment(&self, commitment: Commitment) {
        self.valid_commitments.write().insert(commitment);
    }

    /// Revoke commitment
    pub fn revoke_commitment(&self, commitment: &Commitment) -> bool {
        self.valid_commitments.write().remove(commitment)
    }

    /// Update merkle root (from transparency log)
    pub fn update_root(&self, new_root: [u8; 32]) {
        *self.merkle_root.write() = new_root;
    }

    /// Verify zk-proof without learning token
    /// Checks:
    /// 1. Commitment in valid set (membership proof)
    /// 2. Merkle root matches current
    /// 3. Nullifier not used before (prevent double use of same token proof)
    /// 4. Mock challenge_response validates (Fiat-Shamir)
    pub fn verify_proof(
        &self,
        proof: &ZkProof,
        now_unix: i64,
    ) -> Result<ZkVerificationResult, ZkError> {
        // 1. Merkle root check
        let current_root = *self.merkle_root.read();
        if proof.merkle_root != current_root {
            return Err(ZkError::InvalidMerkleRoot);
        }

        // 2. Commitment membership
        {
            let valid = self.valid_commitments.read();
            if !valid.contains(&proof.commitment) {
                return Err(ZkError::InvalidCommitment);
            }
        }

        // 3. Nullifier not used (prevent replay)
        {
            let used = self.used_nullifiers.read();
            if used.contains(&proof.nullifier) {
                return Err(ZkError::NullifierAlreadyUsed);
            }
        }

        // 4. Mock challenge response check: response = SHA256(commitment || nullifier || root)
        let mut hasher = Sha256::new();
        hasher.update(proof.commitment.0);
        hasher.update(proof.nullifier);
        hasher.update(proof.merkle_root);
        let expected = hasher.finalize();
        let mut expected_arr = [0u8; 32];
        expected_arr.copy_from_slice(&expected);
        if proof.challenge_response != expected_arr {
            return Err(ZkError::InvalidProof);
        }

        // 5. Expiry / quota would be checked via commitment's associated state in real circuit
        // Here we assume valid set only contains non-expired, non-revoked

        // Mark nullifier as used
        self.used_nullifiers.write().insert(proof.nullifier);
        self.verified_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        Ok(ZkVerificationResult {
            commitment: proof.commitment.clone(),
            verified_at: now_unix,
            is_valid: true,
        })
    }

    #[must_use]
    pub fn verified_count(&self) -> u64 {
        self.verified_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[must_use]
    pub fn commitment_count(&self) -> usize {
        self.valid_commitments.read().len()
    }
}

#[derive(Debug, Clone)]
pub struct ZkVerificationResult {
    pub commitment: Commitment,
    pub verified_at: i64,
    pub is_valid: bool,
}

/// Client side: create proof from token (without revealing token to verifier beyond commitment)
#[must_use]
pub fn create_proof(token: &str, blinding: &[u8; 32], merkle_root: [u8; 32]) -> ZkProof {
    let commitment = Commitment::from_token(token, blinding);

    // Nullifier = SHA256(token || "nullifier")
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.update(b"nullifier-domain-separator");
    let nullifier_hash = hasher.finalize();
    let mut nullifier = [0u8; 32];
    nullifier.copy_from_slice(&nullifier_hash);

    // Challenge response = SHA256(commitment || nullifier || root) – Fiat-Shamir
    let mut hasher2 = Sha256::new();
    hasher2.update(commitment.0);
    hasher2.update(nullifier);
    hasher2.update(merkle_root);
    let resp_hash = hasher2.finalize();
    let mut challenge_response = [0u8; 32];
    challenge_response.copy_from_slice(&resp_hash);

    ZkProof {
        commitment,
        nullifier,
        challenge_response,
        merkle_root,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZkError {
    InvalidCommitment,
    InvalidMerkleRoot,
    NullifierAlreadyUsed,
    InvalidProof,
    Expired,
}

impl std::fmt::Display for ZkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCommitment => write!(f, "commitment not in valid set"),
            Self::InvalidMerkleRoot => write!(f, "merkle root mismatch"),
            Self::NullifierAlreadyUsed => write!(f, "nullifier already used (replay)"),
            Self::InvalidProof => write!(f, "zk proof invalid"),
            Self::Expired => write!(f, "subscription expired"),
        }
    }
}

impl std::error::Error for ZkError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zk_proof_valid_without_revealing_token() {
        let root = [1u8; 32];
        let verifier = ZkpVerifier::new(root);

        let token = "super-secret-sub-token-123";
        let blinding = [2u8; 32];
        let commitment = Commitment::from_token(token, &blinding);
        verifier.add_commitment(commitment.clone());

        let proof = create_proof(token, &blinding, root);

        // Verifier verifies without ever seeing token
        let result = verifier.verify_proof(&proof, 1000).unwrap();
        assert!(result.is_valid);
        assert_eq!(result.commitment, commitment);
        assert_eq!(verifier.verified_count(), 1);

        // Proof does not contain token – only commitment, nullifier, response, root
        // So token privacy preserved
    }

    #[test]
    fn invalid_commitment_rejected() {
        let root = [1u8; 32];
        let verifier = ZkpVerifier::new(root);
        let token = "valid-token";
        let blinding = [0u8; 32];
        // Not added to valid set
        let proof = create_proof(token, &blinding, root);
        let err = verifier.verify_proof(&proof, 1000).unwrap_err();
        assert_eq!(err, ZkError::InvalidCommitment);
    }

    #[test]
    fn nullifier_prevents_replay() {
        let root = [1u8; 32];
        let verifier = ZkpVerifier::new(root);
        let token = "token-replay-test";
        let blinding = [3u8; 32];
        let commitment = Commitment::from_token(token, &blinding);
        verifier.add_commitment(commitment);

        let proof = create_proof(token, &blinding, root);
        verifier.verify_proof(&proof, 1000).unwrap();

        // Same token, same nullifier -> replay should fail
        let proof2 = create_proof(token, &blinding, root);
        let err = verifier.verify_proof(&proof2, 1001).unwrap_err();
        assert_eq!(err, ZkError::NullifierAlreadyUsed);
    }

    #[test]
    fn wrong_merkle_root_rejected() {
        let root = [1u8; 32];
        let verifier = ZkpVerifier::new(root);
        let token = "token";
        let blinding = [0u8; 32];
        let commitment = Commitment::from_token(token, &blinding);
        verifier.add_commitment(commitment);

        let wrong_root = [2u8; 32];
        let proof = create_proof(token, &blinding, wrong_root);
        let err = verifier.verify_proof(&proof, 1000).unwrap_err();
        assert_eq!(err, ZkError::InvalidMerkleRoot);
    }

    #[test]
    fn revoked_commitment_rejected() {
        let root = [0u8; 32];
        let verifier = ZkpVerifier::new(root);
        let token = "to-be-revoked";
        let blinding = [5u8; 32];
        let commitment = Commitment::from_token(token, &blinding);
        verifier.add_commitment(commitment.clone());
        assert_eq!(verifier.commitment_count(), 1);

        verifier.revoke_commitment(&commitment);
        assert_eq!(verifier.commitment_count(), 0);

        let proof = create_proof(token, &blinding, root);
        let err = verifier.verify_proof(&proof, 1000).unwrap_err();
        assert_eq!(err, ZkError::InvalidCommitment);
    }
}
