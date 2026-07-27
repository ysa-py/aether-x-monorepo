//! Real-I/O acceptance tests for the production TCP connection path.
//!
//! These tests use OS-assigned loopback sockets, an RFC 5737 black-hole target,
//! and the system resolver. They never implement a fake `Transport`.

use std::time::Duration;

use aether_supervisor::tor::{
    connect_tcp, ConnectError, ConnectOptions, TcpConnectTarget, TcpEndpointTransport, Transport,
};
use tokio::net::TcpListener;
use tokio::time::Instant;

async fn listener_for_connections(connections: usize) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        for _ in 0..connections {
            let _ = listener.accept().await;
        }
    });
    address
}

#[tokio::test]
async fn real_tcp_connect_measures_loopback_rtt_without_static_sentinel() {
    let address = listener_for_connections(2).await;
    let options = ConnectOptions::new(Duration::from_secs(1)).unwrap();

    let direct = connect_tcp(
        "integration-loopback-direct",
        TcpConnectTarget::SocketAddr(address),
        options,
    )
    .await
    .unwrap();
    assert!(direct.established);
    assert_eq!(direct.peer, address);
    assert!((1..1000).contains(&direct.rtt_ms));
    // `50` was the previous fabricated RTT. A measured loopback connection
    // must never regain that sentinel implementation value.
    assert_ne!(direct.rtt_ms, 50);

    let endpoint = TcpEndpointTransport::new(
        "integration-loopback-trait",
        1,
        TcpConnectTarget::SocketAddr(address),
        options,
    );
    let through_trait = tokio::task::spawn_blocking(move || endpoint.connect())
        .await
        .unwrap()
        .unwrap();
    assert!(through_trait.established);
    assert_eq!(through_trait.peer, address);
    assert!((1..1000).contains(&through_trait.rtt_ms));
    // Millisecond rounding can legitimately produce equal values across runs;
    // timing must be plausible rather than artificially forced to differ.
}

#[tokio::test]
async fn real_tcp_connect_reports_connection_refused() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);

    let error = connect_tcp(
        "integration-refused",
        TcpConnectTarget::SocketAddr(address),
        ConnectOptions::new(Duration::from_secs(1)).unwrap(),
    )
    .await
    .unwrap_err();
    assert!(matches!(error, ConnectError::ConnectionRefused { .. }));
}

#[tokio::test]
async fn real_tcp_connect_reports_timeout_for_rfc5737_blackhole() {
    let options = ConnectOptions::new(Duration::from_millis(150)).unwrap();
    let started = Instant::now();
    let error = connect_tcp(
        "integration-blackhole",
        TcpConnectTarget::SocketAddr("192.0.2.1:443".parse().unwrap()),
        options,
    )
    .await
    .unwrap_err();
    let elapsed = started.elapsed();
    assert!(matches!(error, ConnectError::Timeout { after } if after == options.timeout));
    assert!(elapsed >= Duration::from_millis(100));
    assert!(elapsed < Duration::from_secs(2));
}

#[tokio::test]
async fn real_tcp_connect_reports_dns_resolution_failure() {
    let hostname = "aether-x-real-connect-regression.invalid".to_string();
    let error = connect_tcp(
        "integration-dns-failure",
        TcpConnectTarget::Hostname {
            hostname: hostname.clone(),
            port: 443,
        },
        ConnectOptions::new(Duration::from_secs(5)).unwrap(),
    )
    .await
    .unwrap_err();
    assert!(matches!(
        error,
        ConnectError::DnsResolutionFailed { hostname: actual, .. } if actual == hostname
    ));
}

#[test]
fn anti_mock_guard_rejects_historical_static_rtt_assignment() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/tor.rs"),
    )
    .unwrap();
    let historical_assignment = format!("rtt_ms: {}", 50);
    assert!(
        !source.contains(&historical_assignment),
        "the historical fabricated RTT assignment must not return"
    );
}
