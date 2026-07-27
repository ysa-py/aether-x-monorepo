//! PASETO v4 subscription tokens.
//!
//! Subscription claims are carried in PASETO v4 tokens rather than an
//! application-invented `base64(payload).base64(signature)` envelope:
//!
//! * `v4.public` is the production subscription token. It is signed with the
//!   server's existing Ed25519 identity (`ed25519-dalek`).
//! * `v4.local` helpers are available where a confidential, server-only token
//!   is required. They use the maintained `pasetors` v4 implementation.
//!
//! The public implementation below follows the PASETO v4 signing construction
//! directly: `Ed25519.sign(PAE("v4.public.", payload, footer, implicit))`.
//! Keeping that small construction beside the `ed25519-dalek` identity avoids
//! converting a signing seed through a second Ed25519 implementation. Both
//! purposes are checked against the official PASETO v4 vector corpus.

use std::convert::TryFrom;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use pasetors::{
    keys::SymmetricKey,
    token::{Local, UntrustedToken},
    version4::{LocalToken, V4},
};
use rand::rngs::OsRng;

use crate::error::{AntiForgeryError, Result};

const PASETO_V4_PUBLIC_HEADER: &str = "v4.public.";

/// The signed claims for one subscription. Field order is the canonical order.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Claims {
    /// Stable subscription id.
    pub subscription_id: String,
    /// Owning user id.
    pub user_id: String,
    /// Total quota, bytes.
    pub bytes_total: i64,
    /// Bytes already consumed (server-verified).
    pub bytes_used: i64,
    /// Absolute expiry, unix seconds UTC.
    pub expires_unix: i64,
    /// Issuance time, unix seconds UTC.
    pub issued_unix: i64,
    /// Unique-per-issue nonce (defeats token replay at the verifier).
    pub nonce: String,
}

impl Claims {
    /// Remaining bytes, floored at zero.
    pub fn bytes_remaining(&self) -> i64 {
        (self.bytes_total - self.bytes_used).max(0)
    }

    /// Seconds remaining until expiry, floored at zero.
    pub fn secs_remaining(&self, now_unix: i64) -> i64 {
        (self.expires_unix - now_unix).max(0)
    }

    /// True if the token is valid right now: not expired AND quota remaining.
    pub fn is_live(&self, now_unix: i64) -> bool {
        !self.is_expired(now_unix) && self.bytes_remaining() > 0
    }

    /// True if past expiry.
    pub fn is_expired(&self, now_unix: i64) -> bool {
        now_unix >= self.expires_unix
    }
}

/// Sign `claims` as a PASETO v4.public token with `signing_key`.
///
/// PASETO's Pre-Authentication Encoding binds the protocol header, payload,
/// footer, and implicit assertion before the Ed25519 operation. A subscription
/// token currently uses an empty footer and implicit assertion; those empty
/// fields are still included in the PAE, as required by the v4 specification.
pub fn issue(signing_key: &SigningKey, claims: &Claims) -> Result<String> {
    let payload = serde_json::to_vec(claims)?;
    issue_public_payload(signing_key, &payload, &[], &[])
}

/// Verify a PASETO v4.public subscription token and return its claims.
///
/// This verifies the exact PASETO v4 pre-authenticated message using
/// `ed25519-dalek`; callers then apply expiry/quota policy at the time of use.
pub fn verify(verifying_key: &VerifyingKey, token: &str) -> Result<Claims> {
    let payload = verify_public_payload(verifying_key, token, None, &[])?;
    Ok(serde_json::from_slice(&payload)?)
}

/// Encrypt claims as a PASETO v4.local token.
///
/// This is intentionally separate from the public subscription format: callers
/// must provision a distinct 32-byte local key and must never reuse the
/// Ed25519 signing seed as an encryption key.
pub fn issue_local(local_key: &[u8; 32], claims: &Claims) -> Result<String> {
    let key = SymmetricKey::<V4>::from(local_key).map_err(AntiForgeryError::paseto)?;
    let payload = serde_json::to_vec(claims)?;
    LocalToken::encrypt(&key, &payload, None, None).map_err(AntiForgeryError::paseto)
}

/// Decrypt and authenticate a PASETO v4.local token.
pub fn verify_local(local_key: &[u8; 32], token: &str) -> Result<Claims> {
    let key = SymmetricKey::<V4>::from(local_key).map_err(AntiForgeryError::paseto)?;
    let untrusted =
        UntrustedToken::<Local, V4>::try_from(token).map_err(AntiForgeryError::paseto)?;
    let trusted =
        LocalToken::decrypt(&key, &untrusted, None, None).map_err(AntiForgeryError::paseto)?;
    Ok(serde_json::from_slice(trusted.payload().as_bytes())?)
}

/// Convenience: generate a fresh signing key using the OS CSPRNG.
pub fn generate_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

/// Owning wrapper around a [`SigningKey`] that bundles the common operations
/// (issue, public key). It never serializes or exposes private key material.
#[derive(Debug, Clone)]
pub struct TokenSigner {
    sk: SigningKey,
}

impl TokenSigner {
    /// Wrap an existing signing key.
    #[must_use]
    pub fn new(sk: SigningKey) -> Self {
        Self { sk }
    }

    /// Generate a fresh signer with a random key.
    ///
    /// Intended for tests and explicitly enabled local development only. A
    /// service deployment must load a stable secret so issued subscriptions
    /// remain verifiable after a restart.
    #[must_use]
    pub fn generate() -> Self {
        Self::new(generate_signing_key())
    }

    /// Build a stable signer from exactly 32 bytes of private seed material.
    ///
    /// The server loads this through a `zeroize::Zeroizing` buffer and the
    /// `ed25519-dalek` signing-key type zeroizes its secret material on drop.
    #[must_use]
    pub fn from_secret_bytes(secret: &[u8; 32]) -> Self {
        Self::new(SigningKey::from_bytes(secret))
    }

    /// The verifying (public) key for this signer.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.sk.verifying_key()
    }

    /// The verifying key as raw bytes (32).
    #[must_use]
    pub fn verifying_key_bytes(&self) -> Vec<u8> {
        self.sk.verifying_key().to_bytes().to_vec()
    }

    /// Sign `claims`, returning a PASETO v4.public token.
    pub fn issue(&self, claims: &Claims) -> Result<String> {
        issue(&self.sk, claims)
    }
}

/// Sign an arbitrary PASETO v4.public payload with explicit authenticated
/// footer and implicit assertion. Production subscription issuance calls this
/// with empty context; vector tests exercise the full construction.
fn issue_public_payload(
    signing_key: &SigningKey,
    payload: &[u8],
    footer: &[u8],
    implicit_assertion: &[u8],
) -> Result<String> {
    if payload.is_empty() {
        return Err(AntiForgeryError::Malformed(
            "PASETO v4.public payload must not be empty".into(),
        ));
    }
    let pae = pre_auth_encode(&[
        PASETO_V4_PUBLIC_HEADER.as_bytes(),
        payload,
        footer,
        implicit_assertion,
    ])?;
    let signature: Signature = signing_key.sign(&pae);
    let mut message = Vec::from(payload);
    message.extend_from_slice(&signature.to_bytes());
    let token = format!(
        "{PASETO_V4_PUBLIC_HEADER}{}",
        URL_SAFE_NO_PAD.encode(message)
    );
    if footer.is_empty() {
        Ok(token)
    } else {
        Ok(format!("{token}.{}", URL_SAFE_NO_PAD.encode(footer)))
    }
}

/// Verify an arbitrary PASETO v4.public payload with explicit context.
fn verify_public_payload(
    verifying_key: &VerifyingKey,
    token: &str,
    expected_footer: Option<&[u8]>,
    implicit_assertion: &[u8],
) -> Result<Vec<u8>> {
    use subtle::ConstantTimeEq;

    let (message, footer) = split_public_token(token)?;
    if let Some(expected_footer) = expected_footer {
        if !bool::from(footer.ct_eq(expected_footer)) {
            return Err(AntiForgeryError::BadSignature);
        }
    }
    if message.len() < Signature::BYTE_SIZE {
        return Err(AntiForgeryError::Malformed(
            "v4.public message is shorter than an Ed25519 signature".into(),
        ));
    }

    let payload_length = message.len() - Signature::BYTE_SIZE;
    let (payload, signature_bytes) = message.split_at(payload_length);
    let signature_array: [u8; Signature::BYTE_SIZE] = signature_bytes
        .try_into()
        .map_err(|_| AntiForgeryError::Malformed("v4.public signature must be 64 bytes".into()))?;
    let signature = Signature::from_bytes(&signature_array);
    let pae = pre_auth_encode(&[
        PASETO_V4_PUBLIC_HEADER.as_bytes(),
        payload,
        footer.as_slice(),
        implicit_assertion,
    ])?;
    verifying_key
        .verify(&pae, &signature)
        .map_err(|_| AntiForgeryError::BadSignature)?;
    Ok(payload.to_vec())
}

fn split_public_token(token: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut fields = token.split('.');
    let version = fields.next();
    let purpose = fields.next();
    let message = fields.next();
    let footer = fields.next();

    if version != Some("v4")
        || purpose != Some("public")
        || message.is_none()
        || fields.next().is_some()
    {
        return Err(AntiForgeryError::Malformed(
            "expected a v4.public token with zero or one footer".into(),
        ));
    }

    let encoded_message = match message {
        Some(value) => value,
        None => {
            return Err(AntiForgeryError::Malformed(
                "v4.public token has no message".into(),
            ));
        }
    };
    let message = URL_SAFE_NO_PAD.decode(encoded_message)?;
    let footer = match footer {
        Some(encoded) if !encoded.is_empty() => URL_SAFE_NO_PAD.decode(encoded)?,
        Some(_) => {
            return Err(AntiForgeryError::Malformed(
                "v4.public token footer must not be empty when present".into(),
            ));
        }
        None => Vec::new(),
    };
    Ok((message, footer))
}

/// PASETO Pre-Authentication Encoding (PAE).
///
/// PAE is defined by the PASETO specification as the little-endian count of
/// pieces followed by the little-endian byte length and bytes of every piece.
fn pre_auth_encode(pieces: &[&[u8]]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(
        &u64::try_from(pieces.len())
            .map_err(|_| AntiForgeryError::Malformed("too many PASETO PAE pieces".into()))?
            .to_le_bytes(),
    );
    for piece in pieces {
        out.extend_from_slice(
            &u64::try_from(piece.len())
                .map_err(|_| AntiForgeryError::Malformed("PASETO PAE piece is too large".into()))?
                .to_le_bytes(),
        );
        out.extend_from_slice(piece);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const V4_LOCAL_KEY: [u8; 32] = [
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e,
        0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
        0x8e, 0x8f,
    ];
    const V4_PUBLIC_SEED: [u8; 32] = [
        0xb4, 0xcb, 0xfb, 0x43, 0xdf, 0x4c, 0xe2, 0x10, 0x72, 0x7d, 0x95, 0x3e, 0x4a, 0x71, 0x33,
        0x07, 0xfa, 0x19, 0xbb, 0x7d, 0x9f, 0x85, 0x04, 0x14, 0x38, 0xd9, 0xe1, 0x1b, 0x94, 0x2a,
        0x37, 0x74,
    ];
    const V4_PUBLIC_KEY: [u8; 32] = [
        0x1e, 0xb9, 0xdb, 0xbb, 0xbc, 0x04, 0x7c, 0x03, 0xfd, 0x70, 0x60, 0x4e, 0x00, 0x71, 0xf0,
        0x98, 0x7e, 0x16, 0xb2, 0x8b, 0x75, 0x72, 0x25, 0xc1, 0x1f, 0x00, 0x41, 0x5d, 0x0e, 0x20,
        0xb1, 0xa2,
    ];
    const V4_PUBLIC_VECTOR: &str = "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9v3Jt8mx_TdM2ceTGoqwrh4yDFn0XsHvvV_D0DtwQxVrJEBMl0F2caAdgnpKlt4p7xBnx1HcO-SPo8FPp214HDw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";
    const V4_PUBLIC_FOOTER: &[u8] = b"{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
    const V4_LOCAL_VECTOR: &str = "v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AXe7If_ZgesdkUMvSwscFlAl1pk5HC0e8kApeaqMfGo_7OpBnwJOAbY9V7WU6abu74MmcUE8YWAiaArVI8XJ5hOb_4v9RmDkneN0S92dx0OW4pgy7omxgf3S8c3LlQg";

    fn sample_claims(nonce: &str) -> Claims {
        Claims {
            subscription_id: "sub-1".into(),
            user_id: "u-1".into(),
            bytes_total: 1_000_000_000,
            bytes_used: 250_000_000,
            expires_unix: 2_000_000_000,
            issued_unix: 1_999_000_000,
            nonce: nonce.into(),
        }
    }

    #[test]
    fn v4_public_official_vector_verifies_with_ed25519_dalek() {
        let verifying = VerifyingKey::from_bytes(&V4_PUBLIC_KEY).unwrap();
        let (message, footer) = split_public_token(V4_PUBLIC_VECTOR).unwrap();
        assert_eq!(footer, V4_PUBLIC_FOOTER);
        let payload = &message[..message.len() - Signature::BYTE_SIZE];
        let signature = Signature::from_bytes(
            message[message.len() - Signature::BYTE_SIZE..]
                .try_into()
                .unwrap(),
        );
        let pae = pre_auth_encode(&[
            PASETO_V4_PUBLIC_HEADER.as_bytes(),
            payload,
            V4_PUBLIC_FOOTER,
            &[],
        ])
        .unwrap();
        verifying.verify(&pae, &signature).unwrap();

        // The same official seed must reproduce the official vector exactly.
        let signing = SigningKey::from_bytes(&V4_PUBLIC_SEED);
        let actual = {
            let pae = pre_auth_encode(&[
                PASETO_V4_PUBLIC_HEADER.as_bytes(),
                payload,
                V4_PUBLIC_FOOTER,
                &[],
            ])
            .unwrap();
            let mut signed = payload.to_vec();
            signed.extend_from_slice(&signing.sign(&pae).to_bytes());
            format!(
                "{PASETO_V4_PUBLIC_HEADER}{}.{}",
                URL_SAFE_NO_PAD.encode(signed),
                URL_SAFE_NO_PAD.encode(V4_PUBLIC_FOOTER)
            )
        };
        assert_eq!(actual, V4_PUBLIC_VECTOR);
    }

    #[test]
    fn v4_local_official_vector_decrypts() {
        // The official vector intentionally has generic JSON, so check it via
        // pasetors directly before proving our structured local API below.
        let key = SymmetricKey::<V4>::from(&V4_LOCAL_KEY).unwrap();
        let untrusted = UntrustedToken::<Local, V4>::try_from(V4_LOCAL_VECTOR).unwrap();
        let trusted = LocalToken::decrypt(&key, &untrusted, None, None).unwrap();
        assert_eq!(
            trusted.payload(),
            "{\"data\":\"this is a secret message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}"
        );
    }

    #[derive(serde::Deserialize)]
    struct OfficialVectorFile {
        tests: Vec<OfficialVector>,
    }

    #[derive(serde::Deserialize)]
    struct OfficialVector {
        name: String,
        #[serde(rename = "expect-fail")]
        expect_fail: bool,
        key: Option<String>,
        #[serde(rename = "public-key")]
        public_key: Option<String>,
        #[serde(rename = "secret-key")]
        secret_key: Option<String>,
        token: String,
        payload: Option<String>,
        footer: String,
        #[serde(rename = "implicit-assertion")]
        implicit_assertion: String,
    }

    fn decode_hex(input: &str) -> Vec<u8> {
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn complete_official_paseto_v4_vector_corpus_passes() {
        let vectors: OfficialVectorFile =
            serde_json::from_str(include_str!("../tests/data/paseto-v4.json")).unwrap();

        for vector in vectors.tests {
            let footer = vector.footer.as_bytes();
            let implicit = vector.implicit_assertion.as_bytes();

            if let Some(public_key) = vector.public_key.as_deref() {
                let public_key: [u8; 32] = decode_hex(public_key).try_into().unwrap();
                let verifying = VerifyingKey::from_bytes(&public_key).unwrap();
                let result =
                    verify_public_payload(&verifying, &vector.token, Some(footer), implicit);
                if vector.expect_fail {
                    assert!(
                        result.is_err(),
                        "official vector {} unexpectedly verified",
                        vector.name
                    );
                } else {
                    let payload = vector.payload.as_deref().unwrap();
                    assert_eq!(
                        result.unwrap(),
                        payload.as_bytes(),
                        "official vector {} payload",
                        vector.name
                    );
                    let secret = decode_hex(vector.secret_key.as_deref().unwrap());
                    let seed: [u8; 32] = secret[..32].try_into().unwrap();
                    let signing = SigningKey::from_bytes(&seed);
                    assert_eq!(
                        issue_public_payload(&signing, payload.as_bytes(), footer, implicit)
                            .unwrap(),
                        vector.token,
                        "official vector {} encoding",
                        vector.name
                    );
                }
            }

            if let Some(local_key) = vector.key.as_deref() {
                let local_key: [u8; 32] = decode_hex(local_key).try_into().unwrap();
                let key = SymmetricKey::<V4>::from(&local_key).unwrap();
                let result = match UntrustedToken::<Local, V4>::try_from(vector.token.as_str()) {
                    Ok(untrusted) => LocalToken::decrypt(
                        &key,
                        &untrusted,
                        if footer.is_empty() {
                            None
                        } else {
                            Some(footer)
                        },
                        Some(implicit),
                    )
                    .map(|trusted| trusted.payload().to_string()),
                    Err(error) => Err(error),
                };
                if vector.expect_fail {
                    assert!(
                        result.is_err(),
                        "official vector {} unexpectedly decrypted",
                        vector.name
                    );
                } else {
                    assert_eq!(
                        result.unwrap(),
                        vector.payload.as_deref().unwrap(),
                        "official vector {} local payload",
                        vector.name
                    );
                }
            }
        }
    }

    #[test]
    fn public_roundtrip_verifies_as_paseto() {
        let sk = generate_signing_key();
        let vk = sk.verifying_key();
        let claims = sample_claims("n1");
        let token = issue(&sk, &claims).unwrap();
        assert!(token.starts_with(PASETO_V4_PUBLIC_HEADER));
        assert_eq!(verify(&vk, &token).unwrap(), claims);
    }

    #[test]
    fn local_roundtrip_verifies_as_paseto() {
        let claims = sample_claims("local-nonce");
        let token = issue_local(&V4_LOCAL_KEY, &claims).unwrap();
        assert!(token.starts_with("v4.local."));
        assert_eq!(verify_local(&V4_LOCAL_KEY, &token).unwrap(), claims);
    }

    #[test]
    fn wrong_key_rejects() {
        let sk1 = generate_signing_key();
        let sk2 = generate_signing_key();
        let token = issue(&sk1, &sample_claims("n2")).unwrap();
        assert!(matches!(
            verify(&sk2.verifying_key(), &token),
            Err(AntiForgeryError::BadSignature)
        ));
    }

    #[test]
    fn flipped_public_signature_byte_rejects() {
        let sk = generate_signing_key();
        let vk = sk.verifying_key();
        let token = issue(&sk, &sample_claims("n3")).unwrap();
        let (message, _) = split_public_token(&token).unwrap();
        let mut tampered = message;
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        let tampered = format!(
            "{PASETO_V4_PUBLIC_HEADER}{}",
            URL_SAFE_NO_PAD.encode(tampered)
        );
        assert!(matches!(
            verify(&vk, &tampered),
            Err(AntiForgeryError::BadSignature)
        ));
    }

    #[test]
    fn flipped_local_ciphertext_byte_rejects() {
        let token = issue_local(&V4_LOCAL_KEY, &sample_claims("n4")).unwrap();
        let mut fields: Vec<&str> = token.split('.').collect();
        let mut message = URL_SAFE_NO_PAD.decode(fields[2]).unwrap();
        message[32] ^= 0x01;
        let encoded = URL_SAFE_NO_PAD.encode(message);
        fields[2] = &encoded;
        let tampered = fields.join(".");
        assert!(verify_local(&V4_LOCAL_KEY, &tampered).is_err());
    }

    #[test]
    fn quota_and_expiry_helpers() {
        let claims = sample_claims("n5");
        assert_eq!(claims.bytes_remaining(), 750_000_000);
        assert!(claims.is_live(1_999_500_000));
        assert!(!claims.is_expired(1_999_500_000));
        assert!(claims.is_expired(2_000_000_001));
        let exhausted = Claims {
            bytes_used: 1_000_000_000,
            ..claims.clone()
        };
        assert!(!exhausted.is_live(1_999_500_000));
    }
}
