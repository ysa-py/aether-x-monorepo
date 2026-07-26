//! tonic implementation of `aether.antiforgery.v1.AntiForgeryService`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use tonic::{
    transport::{Certificate, Identity, Server, ServerTlsConfig},
    Request, Response, Status,
};
use tracing::info;

use aether_antiforgery::audit::AuditLog;
use aether_antiforgery::token::{self, Claims, TokenSigner};

use aether::antiforgery::v1 as pb;

// Generated gRPC bindings. Relax lints for generated code (no rustdoc, and
// clippy dislikes generated patterns like 4-bool structs / default exprs).
#[allow(clippy::all, clippy::pedantic, missing_docs)]
pub mod aether {
    pub mod antiforgery {
        pub mod v1 {
            tonic::include_proto!("aether.antiforgery.v1");
        }
    }
}

/// Server state: a signer + an append-only audit log.
pub struct State {
    signer: TokenSigner,
    audit: Mutex<AuditLog>,
}

impl State {
    /// Construct with an explicit signing key (load from a secret in prod).
    pub fn new(signer: TokenSigner) -> Self {
        Self {
            signer,
            audit: Mutex::new(AuditLog::new()),
        }
    }
}

#[tonic::async_trait]
impl pb::anti_forgery_service_server::AntiForgeryService for State {
    async fn issue_token(
        &self,
        req: Request<pb::IssueTokenRequest>,
    ) -> Result<Response<pb::IssueTokenResponse>, Status> {
        let r = req.into_inner();
        if r.subscription_id.is_empty() {
            return Err(Status::invalid_argument("subscription_id is required"));
        }
        let now = now_unix();
        let claims = Claims {
            subscription_id: r.subscription_id,
            user_id: r.user_id,
            bytes_total: r.bytes_total,
            bytes_used: r.bytes_used,
            expires_unix: r.expires_unix,
            issued_unix: now,
            nonce: uuid::Uuid::new_v4().to_string(),
        };

        let token_str = self
            .signer
            .issue(&claims)
            .map_err(|e| Status::internal(format!("issue failed: {e}")))?;

        // Record the issuance in the tamper-evident audit log.
        let payload = serde_json::to_vec(&claims)
            .map_err(|e| Status::internal(format!("serialize claims: {e}")))?;
        let (seq, hash) = {
            let mut log = self.audit.lock();
            let seq = log.append(payload);
            let hash = log.records()[seq as usize].hash;
            (seq, hash)
        };

        Ok(Response::new(pb::IssueTokenResponse {
            token: token_str,
            audit_seq: seq as i64,
            audit_hash: hash.to_vec(),
            verifying_key: self.signer.verifying_key_bytes(),
        }))
    }

    async fn verify_token(
        &self,
        req: Request<pb::VerifyTokenRequest>,
    ) -> Result<Response<pb::VerifyTokenResponse>, Status> {
        let r = req.into_inner();
        let vk = self.signer.verifying_key();
        let Ok(claims) = token::verify(&vk, &r.token) else {
            return Ok(Response::new(pb::VerifyTokenResponse {
                signature_valid: false,
                ..Default::default()
            }));
        };
        let expired = claims.is_expired(r.now_unix);
        let quota_exhausted = claims.bytes_remaining() <= 0;
        let is_live = claims.is_live(r.now_unix);
        Ok(Response::new(pb::VerifyTokenResponse {
            signature_valid: true,
            expired,
            quota_exhausted,
            is_live,
            claims: Some(pb::Claims {
                subscription_id: claims.subscription_id,
                user_id: claims.user_id,
                bytes_total: claims.bytes_total,
                bytes_used: claims.bytes_used,
                expires_unix: claims.expires_unix,
                issued_unix: claims.issued_unix,
                nonce: claims.nonce,
            }),
        }))
    }

    async fn audit_root(
        &self,
        _req: Request<pb::AuditRootRequest>,
    ) -> Result<Response<pb::AuditRootResponse>, Status> {
        let log = self.audit.lock();
        Ok(Response::new(pb::AuditRootResponse {
            merkle_root: log.merkle_root().to_vec(),
            chain_root: log.root_hash().to_vec(),
            count: log.len() as i64,
        }))
    }
}

/// PEM material for the anti-forgery mTLS listener.
///
/// The service verifies control-plane client certificates against the supplied
/// CA before making signing or audit operations available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsServerConfig {
    certificate_pem: Vec<u8>,
    private_key_pem: Vec<u8>,
    client_ca_pem: Vec<u8>,
}

impl TlsServerConfig {
    /// Load non-empty PEM files from explicit paths.
    pub fn from_paths(
        certificate_path: impl AsRef<Path>,
        private_key_path: impl AsRef<Path>,
        client_ca_path: impl AsRef<Path>,
    ) -> Result<Self, std::io::Error> {
        Ok(Self {
            certificate_pem: read_pem(certificate_path.as_ref(), "server certificate")?,
            private_key_pem: read_pem(private_key_path.as_ref(), "server private key")?,
            client_ca_pem: read_pem(client_ca_path.as_ref(), "client CA")?,
        })
    }

    /// Load paths from `AETHER_ANTIFORGERY_TLS_CERT`,
    /// `AETHER_ANTIFORGERY_TLS_KEY`, and `AETHER_ANTIFORGERY_CLIENT_CA`.
    pub fn from_environment() -> Result<Self, std::io::Error> {
        let certificate_path = required_environment_path("AETHER_ANTIFORGERY_TLS_CERT")?;
        let private_key_path = required_environment_path("AETHER_ANTIFORGERY_TLS_KEY")?;
        let client_ca_path = required_environment_path("AETHER_ANTIFORGERY_CLIENT_CA")?;
        Self::from_paths(certificate_path, private_key_path, client_ca_path)
    }

    fn into_tonic(self) -> ServerTlsConfig {
        ServerTlsConfig::new()
            .identity(Identity::from_pem(
                self.certificate_pem,
                self.private_key_pem,
            ))
            .client_ca_root(Certificate::from_pem(self.client_ca_pem))
    }
}

fn required_environment_path(name: &str) -> Result<PathBuf, std::io::Error> {
    let value = std::env::var(name).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("required mTLS environment variable {name} is missing"),
        )
    })?;
    if value.trim().is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("required mTLS environment variable {name} is empty"),
        ));
    }
    Ok(PathBuf::from(value))
}

fn read_pem(path: &Path, kind: &str) -> Result<Vec<u8>, std::io::Error> {
    let contents = std::fs::read(path).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("unable to read {kind} PEM at {}: {error}", path.display()),
        )
    })?;
    if contents.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{kind} PEM at {} is empty", path.display()),
        ));
    }
    Ok(contents)
}

/// Serve the anti-forgery gRPC API.
///
/// `tls` is mandatory for non-loopback listeners; `main` rejects an unsafe
/// plaintext bind before this function is called.
pub async fn serve(
    addr: SocketAddr,
    state: State,
    tls: Option<TlsServerConfig>,
) -> Result<(), Box<dyn std::error::Error>> {
    let tls_enabled = tls.is_some();
    let builder = Server::builder();
    let builder = match tls {
        Some(config) => builder.tls_config(config.into_tonic())?,
        None => builder,
    };
    info!(%addr, tls_enabled, "anti-forgery gRPC server listening");
    builder
        .add_service(pb::anti_forgery_service_server::AntiForgeryServiceServer::new(state))
        .serve(addr)
        .await?;
    Ok(())
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}
