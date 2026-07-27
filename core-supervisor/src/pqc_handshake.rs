//! Classical X25519 session-key agreement.
//!
//! This module formerly labelled a SHA-256/XOR construction as a
//! "X25519 + ML-KEM-768 hybrid". It never performed X25519, KEM
//! encapsulation/decapsulation, authenticated ECH, or an actual TLS handshake.
//! Returning a purported hybrid secret from that construction would be a
//! dangerous cryptographic claim, so it has been removed.
//!
//! The available path is now genuine X25519 (`x25519-dalek`) followed by
//! HKDF-SHA-256. It rejects the all-zero X25519 result in constant time. ML-KEM
//! is explicitly [`PostQuantumStatus::NotConfigured`]: as of 2026-07-27 the
//! maintained RustCrypto `ml-kem` crate documents that it has never received an
//! independent audit, so it does not meet this deployment's audited-primitive
//! requirement. ECH is likewise not presented as implemented here; it belongs
//! in a TLS stack that can perform the complete, authenticated ECH handshake.
//!
//! This is a key-agreement primitive, not a network protocol. A caller must
//! bind the resulting key to an authenticated transport handshake before using
//! it for application traffic.

use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

const HKDF_SALT: &[u8] = b"AETHER-X/X25519/session-key/v1";
const HKDF_INFO: &[u8] = b"AETHER-X authenticated transport session";

/// The honest deployment status of the requested post-quantum component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostQuantumStatus {
    /// No ML-KEM key, ciphertext, or claimed hybrid secret is produced.
    NotConfigured,
}

/// An X25519 static key pair whose secret key is zeroized on drop by
/// `x25519-dalek`'s `zeroize` feature.
pub struct X25519Keypair {
    private: StaticSecret,
    public: PublicKey,
}

impl std::fmt::Debug for X25519Keypair {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("X25519Keypair")
            .field("public", &self.public.to_bytes())
            .field("private", &"***OMITTED***")
            .finish()
    }
}

impl X25519Keypair {
    /// Generate a key pair from the operating system CSPRNG.
    pub fn generate() -> Result<Self, PqcError> {
        let mut secret_bytes = Zeroizing::new([0_u8; 32]);
        OsRng
            .try_fill_bytes(secret_bytes.as_mut())
            .map_err(|_| PqcError::RandomnessUnavailable)?;
        Ok(Self::from_secret_bytes(*secret_bytes))
    }

    /// Construct a key pair from operator-provisioned secret bytes.
    ///
    /// This exists for protected key-store integration. Callers must pass an
    /// unpredictable secret from a secure key store, not a counter or test
    /// seed. The `StaticSecret` type clamps the scalar as required by RFC 7748.
    #[must_use]
    pub fn from_secret_bytes(secret_bytes: [u8; 32]) -> Self {
        let private = StaticSecret::from(secret_bytes);
        let public = PublicKey::from(&private);
        Self { private, public }
    }

    /// Return the encoded X25519 public key.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Derive a session key from a peer's RFC 7748 X25519 public key.
    pub fn agree(&self, peer_public: &[u8; 32]) -> Result<[u8; 32], PqcError> {
        let peer = PublicKey::from(*peer_public);
        let mut shared = Zeroizing::new(*self.private.diffie_hellman(&peer).as_bytes());
        if bool::from(shared.ct_eq(&[0_u8; 32])) {
            shared.zeroize();
            return Err(PqcError::LowOrderPublicKey);
        }

        let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), shared.as_ref());
        let mut session_key = [0_u8; 32];
        hkdf.expand(HKDF_INFO, &mut session_key)
            .map_err(|_| PqcError::KeyDerivationFailed)?;
        shared.zeroize();
        Ok(session_key)
    }
}

/// Compatibility owner for the former PQC handshake entry point.
///
/// Its wire bundle now contains only a real X25519 public key. `mlkem_ciphertext`
/// is retained as an empty field solely so legacy callers can distinguish
/// `NotConfigured` from a valid KEM ciphertext; it is never generated or
/// accepted as a cryptographic value.
#[derive(Debug)]
pub struct PqcHandshake {
    x25519: X25519Keypair,
    handshakes: std::sync::atomic::AtomicU64,
}

impl PqcHandshake {
    /// Generate a fresh X25519 key agreement identity from OS randomness.
    pub fn generate() -> Result<Self, PqcError> {
        Ok(Self {
            x25519: X25519Keypair::generate()?,
            handshakes: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Construct from protected 32-byte key material.
    #[must_use]
    pub fn from_secret_bytes(secret_bytes: [u8; 32]) -> Self {
        Self {
            x25519: X25519Keypair::from_secret_bytes(secret_bytes),
            handshakes: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// The real X25519 public key that a peer must receive.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.x25519.public_key()
    }

    /// Report the PQC state without fabricating a hybrid capability.
    #[must_use]
    pub const fn post_quantum_status(&self) -> PostQuantumStatus {
        PostQuantumStatus::NotConfigured
    }

    /// Start a real X25519 agreement.
    ///
    /// A non-empty ML-KEM public key is rejected instead of being hashed into a
    /// fabricated hybrid secret. Deployments needing PQC must not silently
    /// downgrade this error; they must integrate an independently audited KEM.
    pub fn client_handshake(
        &self,
        server_x25519_public: &[u8; 32],
        server_mlkem_public: &[u8],
    ) -> Result<(PqcCiphertextBundle, [u8; 32]), PqcError> {
        if !server_mlkem_public.is_empty() {
            return Err(PqcError::PostQuantumNotConfigured);
        }
        let session_key = self.x25519.agree(server_x25519_public)?;
        self.handshakes
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok((
            PqcCiphertextBundle {
                x25519_public: self.x25519.public_key(),
                mlkem_ciphertext: Vec::new(),
                ech_encrypted_inner: None,
            },
            session_key,
        ))
    }

    /// Complete a real X25519 agreement.
    pub fn server_handshake(
        &self,
        client_bundle: &PqcCiphertextBundle,
    ) -> Result<[u8; 32], PqcError> {
        if !client_bundle.mlkem_ciphertext.is_empty() || client_bundle.ech_encrypted_inner.is_some()
        {
            return Err(PqcError::PostQuantumNotConfigured);
        }
        let session_key = self.x25519.agree(&client_bundle.x25519_public)?;
        self.handshakes
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(session_key)
    }

    /// Number of successful X25519 operations performed by this owner.
    #[must_use]
    pub fn handshakes_done(&self) -> u64 {
        self.handshakes.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Compatibility wire container for an X25519 agreement request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqcCiphertextBundle {
    /// The client X25519 public key.
    pub x25519_public: [u8; 32],
    /// Always empty while ML-KEM is not configured; a non-empty value is
    /// rejected by [`PqcHandshake::server_handshake`].
    pub mlkem_ciphertext: Vec<u8>,
    /// Always `None`: no userspace XOR construction is treated as ECH.
    pub ech_encrypted_inner: Option<Vec<u8>>,
}

/// Failure modes for key agreement and unavailable PQC features.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PqcError {
    /// The operating system CSPRNG was unavailable.
    RandomnessUnavailable,
    /// A peer supplied a low-order X25519 public key, yielding all-zero shared material.
    LowOrderPublicKey,
    /// HKDF could not produce the requested output length.
    KeyDerivationFailed,
    /// ML-KEM or ECH input was requested while no audited implementation is configured.
    PostQuantumNotConfigured,
}

impl std::fmt::Display for PqcError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RandomnessUnavailable => {
                write!(formatter, "operating-system randomness unavailable")
            }
            Self::LowOrderPublicKey => write!(
                formatter,
                "X25519 peer key produced an all-zero shared secret"
            ),
            Self::KeyDerivationFailed => write!(formatter, "HKDF session-key derivation failed"),
            Self::PostQuantumNotConfigured => {
                write!(formatter, "ML-KEM and ECH are not configured")
            }
        }
    }
}

impl std::error::Error for PqcError {}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::x25519;

    fn bytes_from_hex(input: &str) -> [u8; 32] {
        let mut output = [0_u8; 32];
        for (index, pair) in input.as_bytes().chunks_exact(2).enumerate() {
            let pair = std::str::from_utf8(pair).unwrap();
            output[index] = u8::from_str_radix(pair, 16).unwrap();
        }
        output
    }

    #[test]
    fn rfc7748_x25519_official_vector() {
        let scalar =
            bytes_from_hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let point =
            bytes_from_hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let expected =
            bytes_from_hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
        assert_eq!(x25519(scalar, point), expected);
    }

    #[test]
    fn rfc5869_hkdf_sha256_official_vector() {
        // RFC 5869, Appendix A.1 (SHA-256 test case 1).
        let ikm = [0x0b_u8; 22];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let expected = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut actual = [0_u8; 42];
        hkdf.expand(&info, &mut actual).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn real_x25519_agreement_derives_the_same_session_key() {
        let client = PqcHandshake::generate().unwrap();
        let server = PqcHandshake::generate().unwrap();
        let (bundle, client_key) = client.client_handshake(&server.public_key(), &[]).unwrap();
        let server_key = server.server_handshake(&bundle).unwrap();
        assert_eq!(client_key, server_key);
        assert_ne!(client_key, [0_u8; 32]);
    }

    #[test]
    fn low_order_public_key_is_rejected() {
        let peer = X25519Keypair::generate().unwrap();
        assert_eq!(peer.agree(&[0_u8; 32]), Err(PqcError::LowOrderPublicKey));
    }

    #[test]
    fn nonempty_pqc_input_is_rejected_not_hashed() {
        let client = PqcHandshake::generate().unwrap();
        let server = PqcHandshake::generate().unwrap();
        assert_eq!(
            client.client_handshake(&server.public_key(), &[0x42]),
            Err(PqcError::PostQuantumNotConfigured)
        );
        assert_eq!(
            client.post_quantum_status(),
            PostQuantumStatus::NotConfigured
        );
    }
}
