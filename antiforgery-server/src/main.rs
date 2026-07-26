//! `aether-antiforgery` — the anti-forgery gRPC service binary.
//!
//! Boots a tonic server that wraps the [`aether_antiforgery`] core (Ed25519
//! subscription tokens + tamper-evident audit log) and serves the
//! `aether.antiforgery.v1.AntiForgeryService` contract. The Go control plane is
//! the only intended client.

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::module_name_repetitions,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::too_many_lines
)]

mod server;

use std::net::SocketAddr;

use aether_antiforgery::token;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();

    // Subscription signatures must remain valid across a process restart.
    // Production therefore loads a stable 32-byte Ed25519 seed from the secret
    // environment; an ephemeral signer is available only with AETHER_DEV=true.
    let signer = signer_from_environment()?;
    tracing::info!(
        verifying_key = %hex(&signer.verifying_key_bytes()),
        "anti-forgery signing identity loaded"
    );

    let addr = antiforgery_addr_from_environment()?;
    let mtls_enabled = mtls_enabled_from_environment()?;
    let tls = if mtls_enabled {
        Some(server::TlsServerConfig::from_environment()?)
    } else {
        None
    };
    if !mtls_enabled && !addr.ip().is_loopback() {
        return Err(
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                concat!(
                    "refusing to bind plaintext anti-forgery gRPC on a non-loopback address; ",
                    "set AETHER_MTLS_ENABLED=true and provide anti-forgery mTLS PEM paths",
                ),
            )
            .into(),
        );
    }

    let state = server::State::new(signer);
    tracing::info!(%addr, mtls_enabled, "starting anti-forgery gRPC server");

    server::serve(addr, state, tls).await
}

fn antiforgery_addr_from_environment() -> Result<SocketAddr, std::io::Error> {
    let raw = match std::env::var("AETHER_ANTIFORGERY_ADDR") {
        Ok(value) => value,
        Err(_) => "127.0.0.1:7071".to_string(),
    };
    raw.parse::<SocketAddr>().map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("AETHER_ANTIFORGERY_ADDR must be a valid SocketAddr: {error}"),
        )
    })
}

fn mtls_enabled_from_environment() -> Result<bool, std::io::Error> {
    let raw = match std::env::var("AETHER_MTLS_ENABLED") {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" => Ok(true),
        "0" | "false" => Ok(false),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "AETHER_MTLS_ENABLED must be one of true, false, 1, or 0",
        )),
    }
}

fn signer_from_environment() -> Result<token::TokenSigner, std::io::Error> {
    match std::env::var("AETHER_ANTIFORGERY_SIGNING_KEY") {
        Ok(encoded) => Ok(token::TokenSigner::from_secret_bytes(decode_secret_seed(&encoded)?)),
        Err(_) if development_mode() => {
            tracing::warn!("AETHER_DEV=true: using an ephemeral anti-forgery signing key");
            Ok(token::TokenSigner::generate())
        }
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            concat!(
                "AETHER_ANTIFORGERY_SIGNING_KEY must contain a 64-character hexadecimal ",
                "Ed25519 seed outside development mode",
            ),
        )),
    }
}

fn development_mode() -> bool {
    match std::env::var("AETHER_DEV") {
        Ok(value) => matches!(value.trim().to_ascii_lowercase().as_str(), "1" | "true"),
        Err(_) => false,
    }
}

fn decode_secret_seed(encoded: &str) -> Result<[u8; 32], std::io::Error> {
    let value = encoded.trim();
    if value.len() != 64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "AETHER_ANTIFORGERY_SIGNING_KEY must be exactly 64 hexadecimal characters",
        ));
    }

    let mut secret = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(pair).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("anti-forgery signing key is not UTF-8: {error}"),
            )
        })?;
        let byte = u8::from_str_radix(pair, 16).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("anti-forgery signing key is not hexadecimal: {error}"),
            )
        })?;
        let Some(slot) = secret.get_mut(index) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "anti-forgery signing key has too many bytes",
            ));
        };
        *slot = byte;
    }
    Ok(secret)
}

fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = match EnvFilter::try_from_default_env() {
        Ok(filter) => filter,
        Err(_) => EnvFilter::new("info,aether=debug"),
    };
    let _ = fmt().with_env_filter(filter).with_target(false).try_init();
}

/// Lowercase hex of a byte slice (no external dep needed).
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_exactly_32_bytes_of_hex_key_material() -> Result<(), Box<dyn std::error::Error>> {
        let seed = decode_secret_seed(
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        )?;
        assert_eq!(
            hex(&seed),
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
        );
        Ok(())
    }

    #[test]
    fn rejects_invalid_signing_key_encodings() {
        assert!(decode_secret_seed("abcd").is_err());
        assert!(decode_secret_seed(
            "g0112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        )
        .is_err());
    }
}
