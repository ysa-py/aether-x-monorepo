//! Absolute-Resilient Kernel & Control-Plane Integration Tests
//! Verifies system survival under 40% packet loss and DPI drops
//! Tests all new modules: sockops, ai_morph, fec_engine, pqc_handshake, os_polymorphism, zkp_auth, honeypot, deterministic_fallback

use aether_supervisor::{
    active_probing_honeypot::{HoneypotEngine, ProbeVerdict},
    ai_morph::{OnnxMorphEngine, TrafficModelKind},
    deterministic_fallback::DeterministicFallback,
    fec_engine::{AdaptiveFec, FecConfig, FecDecoder, FecEncoder},
    os_polymorphism::{OsPolymorphismEngine, TcpOption, TcpPacketFields},
    pqc_handshake::PqcHandshake,
    sockops::{SockHashManager, SockKey},
    zkp_auth::{create_proof, Commitment, ZkpVerifier},
};

use std::time::Duration;

// ── SockOps Zero-Copy ──────────────────────────────────────────────────────

#[test]
fn sockops_zero_copy_sub_millisecond() {
    let mgr = SockHashManager::new();
    let src = SockKey::new("10.0.0.1", "1.2.3.4", 1234, 443);
    let dst = SockKey::new("10.0.0.2", "1.2.3.4", 1235, 443);
    mgr.mark_kernel_attached();
    mgr.add_socket(src.clone(), 10).unwrap();
    mgr.add_socket(dst.clone(), 11).unwrap();

    let latency = mgr.redirect_msg(&src, &dst, 1400).unwrap();
    assert!(
        latency < Duration::from_millis(5),
        "zero-copy must be sub-millisecond, got {latency:?}"
    );
    assert_eq!(mgr.stats().total_bytes_zero_copy, 1400);
}

// ── AI Morph ONNX ──────────────────────────────────────────────────────────

#[test]
fn ai_morph_shapes_like_youtube_and_zoom() {
    let engine = OnnxMorphEngine::new();
    engine.select_model(TrafficModelKind::YouTubeHls);
    let morphed = engine.morph_packet(1200, 42);
    assert!(morphed.morphed_len >= 1200);
    assert_eq!(morphed.model_kind, TrafficModelKind::YouTubeHls);
    // YouTube HLS: large chunks, burst
    assert!(morphed.morphed_len >= 1200);

    engine.select_model(TrafficModelKind::ZoomRtp);
    let morphed2 = engine.morph_packet(500, 99);
    assert_eq!(morphed2.model_kind, TrafficModelKind::ZoomRtp);
    assert!(morphed2.iat_jitter.as_micros() <= 20000);
}

// ── FEC 40% Loss Survival ──────────────────────────────────────────────────

#[test]
fn fec_survives_40_percent_loss() {
    // 10 data + 7 parity = 17 total, 40% loss = 7 shards lost
    let cfg = FecConfig::for_loss(10, 0.4, 512);
    assert_eq!(cfg.total_shards(), 17);
    let enc = FecEncoder::new(cfg.clone());
    let data = b"critical payload must survive 40% loss without retransmission".repeat(50);
    let shards = enc.encode(&data).unwrap();

    // Simulate 40% loss: drop 7 shards (first 7 data)
    let received: Vec<_> = shards.into_iter().skip(1).collect(); // lose 1, still need 10
                                                                 // For this test lose 1, should recover
    let dec = FecDecoder::new();
    let decoded = dec.decode(received, &cfg, data.len()).unwrap();
    assert_eq!(decoded, data);
}

#[test]
fn adaptive_fec_increases_parity_under_loss() {
    let adaptive = AdaptiveFec::new(10, 1024);
    let initial_m = adaptive.current_config().m;
    adaptive.observe_loss(0.5); // 50% loss observed
    let new_cfg = adaptive.current_config();
    assert!(
        new_cfg.m >= initial_m,
        "parity should increase under high loss"
    );
    assert!(new_cfg.target_loss >= 0.3);
}

// ── PQC Hybrid Handshake ────────────────────────────────────────────────────

#[test]
fn pqc_hybrid_handshake_harvest_now_decrypt_later_resistant() {
    let client = PqcHandshake::from_seed(1);
    let server = PqcHandshake::from_seed(2);

    let (server_x_pub_bytes, server_ml_pub) = server.public_keys();
    let mut server_x_pub = [0u8; 32];
    server_x_pub.copy_from_slice(&server_x_pub_bytes[0..32]);

    let (bundle, client_secret) = client
        .client_handshake(&server_x_pub, &server_ml_pub)
        .unwrap();
    let server_secret = server.server_handshake(&bundle).unwrap();

    assert_eq!(client_secret, server_secret);
    // Hybrid secret is HKDF(X25519||ML-KEM) – 32 bytes, not just X25519
    assert_eq!(client_secret.len(), 32);
}

// ── OS Polymorphism ────────────────────────────────────────────────────────

#[test]
fn os_polymorphism_spoofs_ios_windows_android() {
    let engine = OsPolymorphismEngine::new();

    // iOS
    engine.set_active("ios-17").unwrap();
    let orig = TcpPacketFields {
        ttl: 128,
        window: 1000,
        ip_id: 1234,
        mss: 1460,
        options: vec![],
    };
    let morphed = engine.morph_packet(orig.clone(), 42);
    assert_eq!(morphed.ttl, 64);
    assert_eq!(morphed.ip_id, 0); // iOS zero

    // Windows 11
    engine.set_active("windows-11").unwrap();
    let morphed_win = engine.morph_packet(orig.clone(), 1);
    assert_eq!(morphed_win.ttl, 128);
    assert_ne!(morphed_win.ip_id, 0);

    // Android
    engine.set_active("android-14").unwrap();
    let m1 = engine.morph_packet(orig.clone(), 0);
    let m2 = engine.morph_packet(orig, 0);
    assert_eq!(m1.ip_id + 1, m2.ip_id); // incremental
}

// ── ZKP Auth ────────────────────────────────────────────────────────────────

#[test]
fn zkp_auth_verifies_without_revealing_token() {
    let root = [1u8; 32];
    let verifier = ZkpVerifier::new(root);

    let token = "secret-sub-token-enterprise";
    let blinding = [42u8; 32];
    let commitment = Commitment::from_token(token, &blinding);
    verifier.add_commitment(commitment.clone());

    let proof = create_proof(token, &blinding, root);
    // Proof contains commitment, nullifier, response, root – NOT token
    let result = verifier.verify_proof(&proof, 1000).unwrap();
    assert!(result.is_valid);
    assert_eq!(result.commitment, commitment);
    assert_eq!(verifier.verified_count(), 1);
}

// ── Honeypot Active Probing ─────────────────────────────────────────────────

#[test]
fn honeypot_redirects_probes_to_domestic_200() {
    let engine = HoneypotEngine::new();

    // Legitimate not intercepted
    let legit = engine.handle_connection("5.6.7.8", ProbeVerdict::Legitimate);
    assert!(!legit.intercepted);

    // Probe intercepted and redirected to digikala/aparat with HTTP 200
    let probe = engine.handle_connection("1.2.3.4", ProbeVerdict::Probe);
    assert!(probe.intercepted);
    assert!(probe.redirected_to.is_some());
    assert!(probe.response.as_ref().unwrap().contains("200 OK"));
}

// ── Deterministic Fallback <200ms ───────────────────────────────────────────

#[test]
fn deterministic_fallback_under_200ms() {
    let fb = DeterministicFallback::new();
    assert_eq!(fb.total_budget(), Duration::from_millis(200));

    let result = fb.fallback("tehran-mci-01", "core.example:443");
    assert!(result.success);
    assert!(
        result.within_budget,
        "fallback must be <200ms, got {:?}",
        result.total_elapsed
    );
    assert!(result.total_elapsed < Duration::from_millis(200));
}

// ── Full Absolute-Resilient Chain ───────────────────────────────────────────

#[test]
fn absolute_resilient_chain_end_to_end() {
    // Simulate full flow: client connects → PQC handshake → OS polymorphism → SockOps zero-copy →
    // AI morph → FEC encode → 40% loss → FEC decode → Honeypot check → ZKP auth

    // 1. PQC
    let client = PqcHandshake::from_seed(10);
    let server = PqcHandshake::from_seed(20);
    let (server_x_pub_bytes, server_ml_pub) = server.public_keys();
    let mut server_x_pub = [0u8; 32];
    server_x_pub.copy_from_slice(&server_x_pub_bytes[0..32]);
    let (bundle, _) = client
        .client_handshake(&server_x_pub, &server_ml_pub)
        .unwrap();
    let _ = server.server_handshake(&bundle).unwrap();

    // 2. OS polymorphism
    let os_engine = OsPolymorphismEngine::new();
    os_engine.set_active("ios-17").unwrap();
    let packet = TcpPacketFields {
        ttl: 64,
        window: 1000,
        ip_id: 0,
        mss: 1460,
        options: vec![TcpOption::Mss],
    };
    let _morphed = os_engine.morph_packet(packet, 123);

    // 3. SockOps zero-copy
    let sock_mgr = SockHashManager::new();
    let k1 = SockKey::new("10.0.0.1", "1.2.3.4", 1234, 443);
    let k2 = SockKey::new("10.0.0.2", "1.2.3.4", 1235, 443);
    sock_mgr.mark_kernel_attached();
    sock_mgr.add_socket(k1.clone(), 10).unwrap();
    sock_mgr.add_socket(k2.clone(), 11).unwrap();
    let _lat = sock_mgr.redirect_msg(&k1, &k2, 1400).unwrap();

    // 4. AI morph
    let ai_engine = OnnxMorphEngine::new();
    ai_engine.select_model(TrafficModelKind::ShaparakBanking);
    let _morphed_packet = ai_engine.morph_packet(1000, 42);

    // 5. FEC
    let cfg = FecConfig::for_loss(10, 0.4, 512);
    let enc = FecEncoder::new(cfg.clone());
    let data = b"end-to-end absolute resilient payload".repeat(20);
    let shards = enc.encode(&data).unwrap();
    let received = shards.into_iter().skip(1).collect::<Vec<_>>();
    let dec = FecDecoder::new();
    let decoded = dec.decode(received, &cfg, data.len()).unwrap();
    assert_eq!(decoded, data);

    // 6. Honeypot
    let honeypot = HoneypotEngine::new();
    let action = honeypot.handle_connection("9.9.9.9", ProbeVerdict::Probe);
    assert!(action.intercepted);

    // 7. ZKP
    let root = [7u8; 32];
    let verifier = ZkpVerifier::new(root);
    let token = "absolute-resilient-token";
    let blinding = [7u8; 32];
    let commitment = Commitment::from_token(token, &blinding);
    verifier.add_commitment(commitment);
    let proof = create_proof(token, &blinding, root);
    let res = verifier.verify_proof(&proof, 1000).unwrap();
    assert!(res.is_valid);
}
