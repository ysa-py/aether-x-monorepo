//! Real Bulletproofs eligibility proofs for registered PASETO credentials.
//!
//! This module implements exactly the issuer-attested expiry statement in
//! `docs/zkp-design.md`. It does not claim to prove PASETO's Ed25519 signature
//! inside a zero-knowledge circuit. Instead, the issuer verifies the actual
//! PASETO v4.public token before registering a Pedersen commitment to its
//! expiration time. The prover later proves that the registered expiration is
//! still after the verifier's current time without disclosing the token bytes.

use std::collections::HashSet;

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use merlin::Transcript;
use rand::rngs::OsRng;
use thiserror::Error;
use zeroize::Zeroize;

use crate::token::{self, Claims};

const RANGE_BITS: usize = 64;
const TRANSCRIPT_DOMAIN: &[u8] = b"AETHER-X/registered-paseto-expiry/v1";
const TRANSCRIPT_COMMITMENT_LABEL: &[u8] = b"credential-expiry-commitment";
const TRANSCRIPT_NOW_LABEL: &[u8] = b"verifier-now-unix";

/// A public registry commitment. It is linkable by design; it is never a
/// PASETO string or a JSON claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CredentialCommitment([u8; 32]);

impl CredentialCommitment {
    /// Bytes used as the registry key and on the proof wire format.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    fn decompress(self) -> Result<CompressedRistretto, EligibilityProofError> {
        let compressed = CompressedRistretto(self.0);
        if compressed.decompress().is_none() {
            return Err(EligibilityProofError::InvalidCommitmentEncoding);
        }
        Ok(compressed)
    }
}

/// Private credential opening retained only by the legitimate prover.
///
/// `blinding` must not be serialized or logged. The scalar implementation has
/// zeroization support and this type zeroizes it explicitly on drop.
pub struct EligibilityCredential {
    commitment: CredentialCommitment,
    expires_unix: u64,
    blinding: Scalar,
}

impl std::fmt::Debug for EligibilityCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EligibilityCredential")
            .field("commitment", &self.commitment)
            .field("expires_unix", &self.expires_unix)
            .field("blinding", &"***OMITTED***")
            .finish()
    }
}

impl Drop for EligibilityCredential {
    fn drop(&mut self) {
        self.blinding.zeroize();
    }
}

impl EligibilityCredential {
    /// Public identifier used to find the issuer-registered commitment.
    #[must_use]
    pub const fn commitment(&self) -> CredentialCommitment {
        self.commitment
    }

    /// Construct a real 64-bit Bulletproof for `exp > now_unix`.
    pub fn prove_unexpired(&self, now_unix: u64) -> Result<ExpiryProof, EligibilityProofError> {
        let delta = expiry_delta(self.expires_unix, now_unix)?;
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(RANGE_BITS, 1);
        let mut transcript = transcript(self.commitment, now_unix);
        let (proof, shifted_commitment) = RangeProof::prove_single(
            &bp_gens,
            &pc_gens,
            &mut transcript,
            delta,
            &self.blinding,
            RANGE_BITS,
        )
        .map_err(|_| EligibilityProofError::ProofCreationFailed)?;

        let expected = shifted_commitment_for(self.commitment, now_unix, &pc_gens)?;
        if shifted_commitment != expected {
            return Err(EligibilityProofError::CommitmentMismatch);
        }

        Ok(ExpiryProof {
            commitment: self.commitment,
            now_unix,
            proof,
        })
    }
}

/// Wire-safe proof container. It contains a Bulletproof and public context,
/// but no PASETO string, JSON payload, expiration scalar, or blinding scalar.
#[derive(Debug, Clone)]
pub struct ExpiryProof {
    commitment: CredentialCommitment,
    now_unix: u64,
    proof: RangeProof,
}

impl ExpiryProof {
    /// Credential commitment to be checked against the issuer registry.
    #[must_use]
    pub const fn commitment(&self) -> CredentialCommitment {
        self.commitment
    }

    /// Verifier time bound into the proof transcript.
    #[must_use]
    pub const fn now_unix(&self) -> u64 {
        self.now_unix
    }

    /// Serialize only the Bulletproof bytes for transport/storage.
    #[must_use]
    pub fn proof_bytes(&self) -> Vec<u8> {
        self.proof.to_bytes()
    }

    /// Parse an externally received Bulletproof after caller supplies its
    /// public commitment and verifier time.
    pub fn from_bytes(
        commitment: CredentialCommitment,
        now_unix: u64,
        encoded_proof: &[u8],
    ) -> Result<Self, EligibilityProofError> {
        let proof = RangeProof::from_bytes(encoded_proof)
            .map_err(|_| EligibilityProofError::MalformedProof)?;
        Ok(Self {
            commitment,
            now_unix,
            proof,
        })
    }
}

/// Issuer-side active credential registry.
///
/// This type deliberately stores only public Pedersen commitment bytes. A
/// durable production deployment must back this registry with an authenticated
/// persistent store; an empty in-memory registry never manufactures a success.
#[derive(Debug, Default)]
pub struct EligibilityRegistry {
    active: HashSet<CredentialCommitment>,
}

impl EligibilityRegistry {
    /// Create an empty registry. Empty means every proof is rejected.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify a real PASETO v4.public token, then register a commitment to its
    /// expiration. Invalid, expired, and quota-exhausted tokens never enter the
    /// registry.
    pub fn register_verified_paseto(
        &mut self,
        verifying_key: &ed25519_dalek::VerifyingKey,
        paseto: &str,
        now_unix: u64,
    ) -> Result<EligibilityCredential, EligibilityProofError> {
        let claims = token::verify(verifying_key, paseto)
            .map_err(|_| EligibilityProofError::PasetoVerificationFailed)?;
        let now_i64 = i64::try_from(now_unix).map_err(|_| EligibilityProofError::InvalidTime)?;
        if !claims.is_live(now_i64) {
            return Err(EligibilityProofError::IneligiblePaseto);
        }
        self.register_verified_claims(&claims)
    }

    /// Revoke an issuer-registered credential. Revocation is checked before
    /// cryptographic proof verification.
    pub fn revoke(&mut self, commitment: CredentialCommitment) -> bool {
        self.active.remove(&commitment)
    }

    /// Verify a proof against this registry and the verifier's current time.
    pub fn verify_unexpired(
        &self,
        proof: &ExpiryProof,
        now_unix: u64,
    ) -> Result<(), EligibilityProofError> {
        if proof.now_unix != now_unix {
            return Err(EligibilityProofError::TimeContextMismatch);
        }
        if !self.active.contains(&proof.commitment) {
            return Err(EligibilityProofError::UnknownOrRevokedCredential);
        }

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(RANGE_BITS, 1);
        let shifted_commitment = shifted_commitment_for(proof.commitment, now_unix, &pc_gens)?;
        let mut transcript = transcript(proof.commitment, now_unix);
        proof
            .proof
            .verify_single(
                &bp_gens,
                &pc_gens,
                &mut transcript,
                &shifted_commitment,
                RANGE_BITS,
            )
            .map_err(|_| EligibilityProofError::ProofVerificationFailed)
    }

    /// Number of active issuer-registered commitments.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    fn register_verified_claims(
        &mut self,
        claims: &Claims,
    ) -> Result<EligibilityCredential, EligibilityProofError> {
        let expires_unix = u64::try_from(claims.expires_unix)
            .map_err(|_| EligibilityProofError::InvalidExpiration)?;
        let blinding = Scalar::random(&mut OsRng);
        let commitment = PedersenGens::default()
            .commit(Scalar::from(expires_unix), blinding)
            .compress();
        let credential_commitment = CredentialCommitment(commitment.to_bytes());
        self.active.insert(credential_commitment);
        Ok(EligibilityCredential {
            commitment: credential_commitment,
            expires_unix,
            blinding,
        })
    }
}

/// Fail-closed ZK eligibility errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EligibilityProofError {
    /// The Item A PASETO verifier rejected the credential before registration.
    #[error("PASETO verification failed")]
    PasetoVerificationFailed,
    /// A PASETO verified cryptographically but was expired or quota exhausted.
    #[error("PASETO is not live")]
    IneligiblePaseto,
    /// Unix time cannot safely be represented for this proof protocol.
    #[error("invalid verifier time")]
    InvalidTime,
    /// The PASETO expiration was negative or outside the supported range.
    #[error("invalid PASETO expiration")]
    InvalidExpiration,
    /// The credential is expired at the verifier-supplied current time.
    #[error("credential is expired")]
    Expired,
    /// The public Pedersen commitment is not a valid compressed Ristretto point.
    #[error("invalid credential commitment encoding")]
    InvalidCommitmentEncoding,
    /// The proof's computed commitment did not bind to the registered one.
    #[error("Pedersen commitment mismatch")]
    CommitmentMismatch,
    /// The external proof encoding failed to parse.
    #[error("malformed Bulletproof encoding")]
    MalformedProof,
    /// Prover-side Bulletproof construction failed closed.
    #[error("Bulletproof creation failed")]
    ProofCreationFailed,
    /// The proof was not generated for the verifier's supplied time context.
    #[error("proof time context mismatch")]
    TimeContextMismatch,
    /// The credential was never registered or has been revoked.
    #[error("unknown or revoked credential")]
    UnknownOrRevokedCredential,
    /// Cryptographic Bulletproof verification rejected the proof.
    #[error("Bulletproof verification failed")]
    ProofVerificationFailed,
}

fn expiry_delta(expires_unix: u64, now_unix: u64) -> Result<u64, EligibilityProofError> {
    let threshold = now_unix
        .checked_add(1)
        .ok_or(EligibilityProofError::InvalidTime)?;
    expires_unix
        .checked_sub(threshold)
        .ok_or(EligibilityProofError::Expired)
}

fn shifted_commitment_for(
    commitment: CredentialCommitment,
    now_unix: u64,
    pc_gens: &PedersenGens,
) -> Result<CompressedRistretto, EligibilityProofError> {
    let threshold = now_unix
        .checked_add(1)
        .ok_or(EligibilityProofError::InvalidTime)?;
    let point = commitment
        .decompress()?
        .decompress()
        .ok_or(EligibilityProofError::InvalidCommitmentEncoding)?;
    Ok((point - Scalar::from(threshold) * pc_gens.B).compress())
}

fn transcript(commitment: CredentialCommitment, now_unix: u64) -> Transcript {
    let mut transcript = Transcript::new(TRANSCRIPT_DOMAIN);
    transcript.append_message(TRANSCRIPT_COMMITMENT_LABEL, &commitment.to_bytes());
    transcript.append_u64(TRANSCRIPT_NOW_LABEL, now_unix);
    transcript
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn claims(expires_unix: i64) -> Claims {
        Claims {
            subscription_id: "zkp-subscription".into(),
            user_id: "zkp-user".into(),
            bytes_total: 10_000,
            bytes_used: 0,
            expires_unix,
            issued_unix: 1_700_000_000,
            nonce: "zkp-nonce".into(),
        }
    }

    fn registered_credential(
        now_unix: u64,
    ) -> (
        EligibilityRegistry,
        EligibilityCredential,
        SigningKey,
        String,
    ) {
        let signing = SigningKey::from_bytes(&[0x31; 32]);
        let token =
            token::issue(&signing, &claims(i64::try_from(now_unix + 120).unwrap())).unwrap();
        let mut registry = EligibilityRegistry::new();
        let credential = registry
            .register_verified_paseto(&signing.verifying_key(), &token, now_unix)
            .unwrap();
        (registry, credential, signing, token)
    }

    #[test]
    fn real_bulletproof_proves_registered_paseto_is_unexpired() {
        let now_unix = 1_700_000_000;
        let (registry, credential, _, _) = registered_credential(now_unix);
        let proof = credential.prove_unexpired(now_unix).unwrap();
        registry.verify_unexpired(&proof, now_unix).unwrap();
    }

    #[test]
    fn changed_proof_byte_is_rejected() {
        let now_unix = 1_700_000_000;
        let (registry, credential, _, _) = registered_credential(now_unix);
        let proof = credential.prove_unexpired(now_unix).unwrap();
        let mut encoded = proof.proof_bytes();
        encoded[0] ^= 0x01;
        let parsed = ExpiryProof::from_bytes(proof.commitment(), now_unix, &encoded);
        match parsed {
            Ok(forged) => assert_eq!(
                registry.verify_unexpired(&forged, now_unix),
                Err(EligibilityProofError::ProofVerificationFailed)
            ),
            Err(EligibilityProofError::MalformedProof) => {}
            Err(other) => panic!("unexpected altered-proof error: {other}"),
        }
    }

    #[test]
    fn proof_cannot_be_rebound_to_another_registered_commitment() {
        let now_unix = 1_700_000_000;
        let (mut registry, credential_a, signing, _) = registered_credential(now_unix);
        let token_b =
            token::issue(&signing, &claims(i64::try_from(now_unix + 240).unwrap())).unwrap();
        let credential_b = registry
            .register_verified_paseto(&signing.verifying_key(), &token_b, now_unix)
            .unwrap();
        let proof_a = credential_a.prove_unexpired(now_unix).unwrap();
        let rebound =
            ExpiryProof::from_bytes(credential_b.commitment(), now_unix, &proof_a.proof_bytes())
                .unwrap();
        assert_eq!(
            registry.verify_unexpired(&rebound, now_unix),
            Err(EligibilityProofError::ProofVerificationFailed)
        );
    }

    #[test]
    fn expired_and_revoked_credentials_fail_closed() {
        let now_unix = 1_700_000_000;
        let (mut registry, credential, _, _) = registered_credential(now_unix);
        assert!(matches!(
            credential.prove_unexpired(now_unix + 120),
            Err(EligibilityProofError::Expired)
        ));

        let proof = credential.prove_unexpired(now_unix).unwrap();
        assert!(registry.revoke(credential.commitment()));
        assert_eq!(
            registry.verify_unexpired(&proof, now_unix),
            Err(EligibilityProofError::UnknownOrRevokedCredential)
        );
    }

    #[test]
    fn altered_paseto_is_not_registered() {
        let now_unix = 1_700_000_000;
        let (_, _, signing, token) = registered_credential(now_unix);
        let mut registry = EligibilityRegistry::new();
        assert!(matches!(
            registry.register_verified_paseto(
                &signing.verifying_key(),
                &format!("{token}x"),
                now_unix,
            ),
            Err(EligibilityProofError::PasetoVerificationFailed)
        ));
        assert_eq!(registry.active_count(), 0);
    }
}
