//! Real-process PASETO subscription flow.
//!
//! This test starts the production `aether-antiforgery` binary on a loopback
//! TCP listener, uses the generated tonic client over that socket, then asks
//! the server to issue and verify a PASETO v4.public token. It deliberately
//! does not call `server::State` directly.

use std::{
    net::TcpListener,
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aether_antiforgery::token::{Claims, TokenSigner};
use tonic::transport::Endpoint;

pub mod aether {
    pub mod antiforgery {
        pub mod v1 {
            tonic::include_proto!("aether.antiforgery.v1");
        }
    }
}

use aether::antiforgery::v1::{
    anti_forgery_service_client::AntiForgeryServiceClient, IssueTokenRequest, VerifyTokenRequest,
};

const TEST_SIGNING_SEED: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const TEST_SIGNING_SEED_BYTES: [u8; 32] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];

#[tokio::test]
async fn production_binary_issues_and_verifies_a_paseto_v4_public_token() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("allocate a loopback port");
    let address = listener.local_addr().expect("read loopback address");
    // The production binary owns the listener; reserving then releasing the
    // OS-assigned port avoids a hard-coded port while preserving a real socket.
    drop(listener);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_secs() as i64;
    // This PASETO comes from Item A's real issuer implementation. The spawned
    // production binary must verify it, register its commitment, create a real
    // Bulletproof, and verify that proof before opening its gRPC listener.
    let zkp_token = TokenSigner::from_secret_bytes(&TEST_SIGNING_SEED_BYTES)
        .issue(&Claims {
            subscription_id: "binary-zkp-subscription".into(),
            user_id: "binary-zkp-user".into(),
            bytes_total: 10_000,
            bytes_used: 0,
            expires_unix: now + 120,
            issued_unix: now,
            nonce: "binary-zkp-nonce".into(),
        })
        .expect("issue a real PASETO for production ZK validation");

    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_aether-antiforgery"))
        .env("AETHER_ANTIFORGERY_ADDR", address.to_string())
        .env("AETHER_ANTIFORGERY_SIGNING_KEY", TEST_SIGNING_SEED)
        .env("AETHER_ANTIFORGERY_ZKP_VERIFY_TOKEN", zkp_token)
        .env("AETHER_MTLS_ENABLED", "false")
        .stdout(Stdio::null())
        // Keep child diagnostics in the real CI log when startup rejects the
        // configured cryptographic validation rather than hiding an error.
        .stderr(Stdio::inherit())
        .spawn()
        .expect("start the production anti-forgery binary");

    let endpoint = format!("http://{address}");
    let mut client = connect_with_retry(&endpoint).await;
    let issued = client
        .issue_token(IssueTokenRequest {
            subscription_id: "binary-e2e-subscription".into(),
            user_id: "binary-e2e-user".into(),
            bytes_total: 10_000,
            bytes_used: 0,
            expires_unix: now + 60,
        })
        .await
        .expect("issue PASETO through the production process")
        .into_inner();

    assert!(issued.token.starts_with("v4.public."));
    let verified = client
        .verify_token(VerifyTokenRequest {
            token: issued.token.clone(),
            now_unix: now,
        })
        .await
        .expect("verify PASETO through the production process")
        .into_inner();
    assert!(verified.signature_valid);
    assert!(verified.is_live);
    assert_eq!(
        verified
            .claims
            .expect("verified token has claims")
            .subscription_id,
        "binary-e2e-subscription"
    );

    let rejected = client
        .verify_token(VerifyTokenRequest {
            token: format!("{}x", issued.token),
            now_unix: now,
        })
        .await
        .expect("server responds to a malformed/tampered token")
        .into_inner();
    assert!(!rejected.signature_valid);

    child.kill().await.expect("stop production binary");
    child.wait().await.expect("reap production binary");
}

async fn connect_with_retry(endpoint: &str) -> AntiForgeryServiceClient<tonic::transport::Channel> {
    let endpoint = Endpoint::from_shared(endpoint.to_string()).expect("loopback endpoint is valid");
    for _ in 0..100 {
        match AntiForgeryServiceClient::connect(endpoint.clone()).await {
            Ok(client) => return client,
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
    panic!("production anti-forgery binary did not accept a loopback gRPC connection");
}
