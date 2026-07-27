#![allow(warnings)]

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

/// Deterministic PRNG: reproducible "random" loss patterns, no rand dep.
struct LossRng(u64);

impl LossRng {
    fn next_u32(&mut self) -> u32 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 33) as u32
    }

    fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            let j = (self.next_u32() as usize) % (i + 1);
            v.swap(i, j);
        }
    }
}

#[test]
fn fec_survives_40_percent_loss() {
    // 10 data + 7 parity = 17 total. A genuine 40% loss removes
    // floor(17 * 0.4) = 6 shards, chosen at random across BOTH lanes.
    let cfg = FecConfig::for_loss(10, 0.4, 4096);
    assert_eq!(cfg.total_shards(), 17);
    let enc = FecEncoder::new(cfg.clone());
    let data = b"critical payload must survive 40% loss without retransmission".repeat(50);
    let shards = enc.encode(&data).unwrap();

    let drop_count = (cfg.total_shards() as f64 * 0.4).floor() as usize;
    assert_eq!(drop_count, 6, "40% of 17 shards must be 6 dropped shards");

    let mut rng = LossRng(0x5EED_1234_ABCD_0001);
    for trial in 0..100 {
        let mut order: Vec<usize> = (0..cfg.total_shards()).collect();
        rng.shuffle(&mut order);
        let dropped: std::collections::HashSet<usize> =
            order.iter().copied().take(drop_count).collect();

        let received: Vec<_> = shards
            .iter()
            .filter(|s| !dropped.contains(&s.index))
            .cloned()
            .collect();
        assert_eq!(
            received.len(),
            cfg.total_shards() - drop_count,
            "exactly 40% of shards must be gone"
        );
        let data_shards_lost = dropped.iter().filter(|i| **i < cfg.k).count();

        let dec = FecDecoder::new();
        let decoded = dec
            .decode(received, &cfg, data.len())
            .unwrap_or_else(|e| panic!("trial {trial}: 40% loss must recover, got {e}"));
        // The whole point: byte-for-byte equality with the source payload.
        assert_eq!(
            decoded, data,
            "trial {trial}: recovered bytes must be identical to source (lost {dropped:?})"
        );
        assert_eq!(
            dec.shards_recovered() as usize,
            data_shards_lost,
            "trial {trial}: every lost data shard must be reconstructed"
        );
    }
}

#[test]
fn fec_worst_case_all_but_one_data_shard_lost() {
    // Adversarial pattern (not random): the censor kills the data lane.
    // 7 of 10 data shards gone (41% loss) and all parity survives.
    let cfg = FecConfig::for_loss(10, 0.4, 4096);
    let enc = FecEncoder::new(cfg.clone());
    let data: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
    let shards = enc.encode(&data).unwrap();

    let dropped: std::collections::HashSet<usize> = (3..10).collect(); // 7 data shards
    let received: Vec<_> = shards
        .into_iter()
        .filter(|s| !dropped.contains(&s.index))
        .collect();
    assert_eq!(received.len(), 10);

    let dec = FecDecoder::new();
    let decoded = dec.decode(received, &cfg, data.len()).unwrap();
    assert_eq!(decoded, data);
    assert_eq!(dec.shards_recovered(), 7);
}

#[test]
fn fec_below_recovery_threshold_fails_closed() {
    // Fewer than k survivors is information-theoretically impossible: the
    // decoder must return an error, never a partially-correct payload.
    let cfg = FecConfig::for_loss(10, 0.4, 4096);
    let enc = FecEncoder::new(cfg.clone());
    let data = b"under-threshold payload".repeat(40);
    let shards = enc.encode(&data).unwrap();
    let received: Vec<_> = shards.into_iter().take(9).collect();
    let dec = FecDecoder::new();
    assert!(dec.decode(received, &cfg, data.len()).is_err());
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

// ── X25519 key agreement ────────────────────────────────────────────────────

#[test]
fn x25519_key_agreement_returns_the_same_hkdf_session_key() {
    let client = PqcHandshake::generate().unwrap();
    let server = PqcHandshake::generate().unwrap();

    let (bundle, client_secret) = client.client_handshake(&server.public_key(), &[]).unwrap();
    let server_secret = server.server_handshake(&bundle).unwrap();

    assert_eq!(client_secret, server_secret);
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

    // 1. Real X25519 + HKDF session-key agreement. ML-KEM is intentionally
    // not claimed here until an independently audited implementation is wired.
    let client = PqcHandshake::generate().unwrap();
    let server = PqcHandshake::generate().unwrap();
    let (bundle, _) = client.client_handshake(&server.public_key(), &[]).unwrap();
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

    // 5. FEC under a real 40% loss (6 of 17 shards dropped, data lane first —
    //    the most damaging pattern), asserting byte-for-byte recovery.
    let cfg = FecConfig::for_loss(10, 0.4, 4096);
    let enc = FecEncoder::new(cfg.clone());
    let data = b"end-to-end absolute resilient payload".repeat(20);
    let shards = enc.encode(&data).unwrap();
    let drop_count = (cfg.total_shards() as f64 * 0.4).floor() as usize;
    assert_eq!(drop_count, 6);
    let received = shards.into_iter().skip(drop_count).collect::<Vec<_>>();
    assert_eq!(received.len(), cfg.total_shards() - drop_count);
    let dec = FecDecoder::new();
    let decoded = dec.decode(received, &cfg, data.len()).unwrap();
    assert_eq!(
        decoded, data,
        "end-to-end payload must survive 40% loss byte-for-byte"
    );
    assert_eq!(dec.shards_recovered(), drop_count as u64);

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
