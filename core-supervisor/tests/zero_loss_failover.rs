#![allow(warnings)]

//! Zero-loss failover test suite — verifies enterprise hyper-resilient architecture
//! under simulated network blackouts and DPI drops.
//!
//! Tests the full chain:
//! - Reverse tunnel manager auto-failover across fallback transports
//! - eBPF morph engine fragmentation + OOO + window scaling
//! - Chaffing Poisson distribution obscures size
//! - Happy Eyeballs v2 racing finds fastest working path
//! - QUIC CID migration preserves session (zero disconnection)
//! - Blackout isolation bounds honest reporting (never false "connected")
//! - Seamless controller pre-warming ensures <1ms swap

use aether_supervisor::{
    blackout::{BlackoutController, BlackoutSignal, IsolationLevel},
    buffer_replay::RingBufferReplay,
    chaff::{ChaffConfig, ChaffEngine},
    ebpf::{EbpfMorphEngine, FragMapEntry, OooInjectionConfig, WindowScaleConfig},
    enterprise::EnterpriseEngine,
    fallback_transport::{FallbackKind, ReverseTunnelManager},
    happy_eyeballs::{HappyEyeballs, HappyEyeballsConfig, ProbeCandidate},
    quic_migration::{
        ConnectionId, NetworkPath, QuicConnection, QuicMigrationManager, QuicProtocol,
    },
    reverse_relay::{EdgeRelay, ReverseRelayEngine},
};

use std::sync::Arc;
use std::time::{Duration, Instant};

// ── Helper: simulate DPI blocking primary TLS then escalating ──────────────

fn normal_signal() -> BlackoutSignal {
    BlackoutSignal {
        international_ip_severed: false,
        dns_resolves_international: true,
        tcp_rst_rate: 0.0,
        tls_trunc_rate: 0.0,
        dns_anomaly_rate: 0.0,
        domestic_intranet_up: true,
    }
}

fn dpi_signal() -> BlackoutSignal {
    BlackoutSignal {
        tcp_rst_rate: 0.9,
        tls_trunc_rate: 0.8,
        dns_anomaly_rate: 0.2,
        ..normal_signal()
    }
}

fn routing_severed_signal() -> BlackoutSignal {
    BlackoutSignal {
        international_ip_severed: true,
        dns_resolves_international: true,
        ..normal_signal()
    }
}

fn full_isolation_signal() -> BlackoutSignal {
    BlackoutSignal {
        international_ip_severed: true,
        dns_resolves_international: false,
        ..normal_signal()
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[test]
fn zero_loss_blackout_escalation_chain() {
    // Simulate: Nominal -> DPI -> Routing severed -> Full isolation -> Recovery
    let mut controller = BlackoutController::with_full_tier("primary-core");

    // Nominal: no escalation
    let a0 = controller.react(&normal_signal());
    assert_eq!(a0.level, IsolationLevel::Normal);
    assert!(!a0.bound_reached);
    assert!(a0.promoted_transport.is_none());

    // DPI blocking: morph to aparat-vod, but still primary tier
    let a1 = controller.react(&dpi_signal());
    assert_eq!(a1.level, IsolationLevel::DpiBlocking);
    assert_eq!(a1.morph_profile, "aparat-vod");
    assert!(!a1.bound_reached);

    // Routing severed: should escalate to last-resort tier (webtunnel etc)
    let a2 = controller.react(&routing_severed_signal());
    assert_eq!(a2.level, IsolationLevel::RoutingSevered);
    assert!(a2.promoted_transport.is_some());
    assert_eq!(a2.morph_profile, "shaparak-banking");
    assert!(!a2.bound_reached);

    // Full isolation: bound reached, no transport promoted
    let a3 = controller.react(&full_isolation_signal());
    assert_eq!(a3.level, IsolationLevel::FullIsolation);
    assert!(a3.bound_reached);
    assert!(a3.promoted_transport.is_none());
    assert!(a3.surviving_paths.is_empty());

    // Recovery: one success should drop straight to Normal (instant)
    let a4 = controller.react(&normal_signal());
    assert_eq!(a4.level, IsolationLevel::Normal);
    assert!(!a4.bound_reached);
}

#[test]
fn reverse_tunnel_auto_failover_zero_loss() {
    let mgr = ReverseTunnelManager::new();
    // Initially TLS-in-TLS is best
    let best = mgr.select_best().unwrap();
    assert_eq!(best, FallbackKind::TlsInTls);

    // Simulate DPI blocking TLS-in-TLS (3 failures)
    for _ in 0..3 {
        mgr.record_failure(FallbackKind::TlsInTls);
    }
    let fallback = mgr.select_best().unwrap();
    assert_ne!(fallback, FallbackKind::TlsInTls);

    // Establish tunnel for Tehran edge
    let tunnel_id = mgr.establish_tunnel("tehran-01", "core.example:443", fallback);
    assert!(!tunnel_id.is_empty());
    assert_eq!(mgr.active_tunnels().len(), 1);

    // Simulate relaying bytes — zero loss means bytes are accounted
    assert!(mgr.relay_bytes("tehran-01", 10240));
    assert_eq!(mgr.total_bytes_relayed(), 10240);

    // Auto-failover when current transport dies should pick next
    for _ in 0..3 {
        mgr.record_failure(fallback);
    }
    let next = mgr.auto_failover("tehran-02", "core.example:443");
    assert!(next.is_some());

    // Close and ensure no active tunnels leak
    mgr.close_tunnel("tehran-01");
    // tehran-02 still active
    assert_eq!(mgr.active_tunnels().len(), 1);
}

#[test]
fn ebpf_morph_engine_fragmentation_and_ooo() {
    let mut engine = EbpfMorphEngine::new();
    engine.load("eth0").unwrap();
    assert!(engine.is_active());

    // Program fragmentation for flow 0xABCD
    let flow = 0xABCD;
    engine.set_fragmentation(FragMapEntry {
        flow_key: flow,
        split_offsets: vec![10, 30, 50],
        enabled: true,
    });

    // Simulate ClientHello of 100 bytes — should be 4 fragments
    let ch = vec![0x16u8; 100];
    let frags = engine.fragment_clienthello(flow, &ch);
    assert_eq!(frags.len(), 4);
    let total: usize = frags.iter().map(|f| f.len()).sum();
    assert_eq!(total, 100);

    // OOO injection
    engine.set_ooo_injection(OooInjectionConfig {
        flow_key: flow,
        inject_seq_offset: -5,
        payload_len: 20,
        enabled: true,
    });
    let ooo = engine
        .inject_ooo(flow, 1000, b"abcdefghijklmnopqrstuvwxyz")
        .unwrap();
    assert_eq!(ooo.seq, 995);
    assert_eq!(ooo.payload.len(), 20);

    // Window scaling manipulation
    engine.set_window_scale(WindowScaleConfig {
        flow_key: flow,
        scale_factor: 2,
        window_override: 0,
        enabled: true,
    });
    let manipulated = engine.manipulate_window(flow, 1000);
    assert_ne!(manipulated, 1000);

    // Stats should show applied
    let stats = engine.stats();
    assert_eq!(stats.frag_applied, 1);
    assert_eq!(stats.ooo_injected, 1);
    assert_eq!(stats.wscale_manipulated, 1);
}

#[test]
fn chaffing_obscures_size_distribution() {
    let mut engine = ChaffEngine::new(ChaffConfig {
        lambda: 64.0,
        max_padding: 512,
        min_padding: 16,
        iat_std_us: 1000.0,
        iat_mean_us: 200,
    });

    let mut padded_sizes = Vec::new();
    for seed in 0..1000u64 {
        let chaffed = engine.chaff_packet(1200, seed);
        // Padded length must be >= original and <= original+max
        assert!(chaffed.padded_len >= 1200);
        assert!(chaffed.padded_len <= 1200 + 512);
        assert!(chaffed.padding >= 16);
        padded_sizes.push(chaffed.padded_len);
    }

    // Check distribution: not all same (Poisson randomization)
    let unique: std::collections::HashSet<u32> = padded_sizes.iter().cloned().collect();
    assert!(
        unique.len() > 20,
        "chaffing should produce varied sizes, got {} unique",
        unique.len()
    );
}

#[test]
fn happy_eyeballs_racing_zero_perceived_disconnect() {
    let config = HappyEyeballsConfig {
        connection_attempt_delay: Duration::from_millis(50),
        overall_timeout: Duration::from_secs(5),
        ..Default::default()
    };
    let racer = HappyEyeballs::with_config(config);

    let candidates = vec![
        ProbeCandidate::new("tls-ipv4", "1.2.3.4:443", "tls", 10, false),
        ProbeCandidate::new("tls-ipv6", "[2001:db8::1]:443", "tls", 10, true),
        ProbeCandidate::new("grpc-front", "www.digikala.com:443", "grpc", 20, false),
        ProbeCandidate::new("doh-tunnel", "8.8.8.8:443", "doh", 30, false),
        ProbeCandidate::new("icmp-encap", "1.1.1.1:0", "icmp", 40, false),
    ];

    let start = Instant::now();
    let result = racer.race(candidates);
    let elapsed = start.elapsed();

    assert!(result.is_success(), "racing should find a working path");
    assert!(
        elapsed < Duration::from_secs(1),
        "racing must be fast (<1s), took {elapsed:?}"
    );
    assert!(result.winner.is_some());
    // Winner should be IPv6 or TLS (fastest)
    let winner_id = result.winner.unwrap().candidate_id;
    assert!(winner_id.contains("tls") || winner_id.contains("grpc") || winner_id.contains("ipv6"));
}

#[test]
fn quic_cid_migration_zero_disconnection() {
    let mgr = QuicMigrationManager::new();
    let conn_id = ConnectionId::new_random(0xDEADBEEF);
    let id_str = conn_id.0.clone();

    let initial_path = NetworkPath::new("192.168.1.100:54321", "5.6.7.8:443");
    let mut conn = QuicConnection::new(conn_id, QuicProtocol::Hysteria2, initial_path);
    conn.bytes_before_migration = 10_000;
    mgr.register(conn);

    // Simulate NAT rebinding / ISP throttling -> migrate to new local IP
    let new_path = NetworkPath::new("10.0.0.5:54321", "5.6.7.8:443");
    let outcome = mgr.migrate(&id_str, new_path);
    assert_eq!(
        outcome,
        aether_supervisor::quic_migration::MigrationOutcome::ValidationStarted
    );

    // Path validation succeeds (PATH_CHALLENGE/RESPONSE)
    assert!(mgr.complete_validation(&id_str, true, 45));
    let snap = mgr.get(&id_str).unwrap();
    assert_eq!(snap.migration_count, 1);

    // Stabilize: connection ID preserved, session continuous
    assert!(mgr.stabilize(&id_str));
    let snap2 = mgr.get(&id_str).unwrap();
    assert_eq!(
        snap2.conn_id, id_str,
        "Connection ID must survive migration (zero disconnection)"
    );

    // Total migrations
    assert_eq!(mgr.total_migrations(), 1);
}

#[test]
fn reverse_relay_engine_full_cycle() {
    let engine = ReverseRelayEngine::new();
    engine.register_edge(EdgeRelay::new("tehran-mci-01", "tehran", "MCI"));
    engine.register_edge(EdgeRelay::new("isfahan-irancell-01", "isfahan", "Irancell"));

    // Connect both edges
    let r1 = engine.connect_edge("tehran-mci-01", "core.eu:443");
    let r2 = engine.connect_edge("isfahan-irancell-01", "core.eu:443");
    assert!(matches!(
        r1,
        aether_supervisor::reverse_relay::ConnectResult::Connected { .. }
    ));
    assert!(matches!(
        r2,
        aether_supervisor::reverse_relay::ConnectResult::Connected { .. }
    ));
    assert_eq!(engine.active_edges().len(), 2);

    // Simulate DPI disconnect of one edge
    engine.handle_disconnect("tehran-mci-01");
    assert_eq!(engine.active_edges().len(), 1);

    // Tick should auto-reconnect
    let reconnects = engine.tick("core.eu:443");
    assert_eq!(reconnects.len(), 1);
    assert_eq!(engine.active_edges().len(), 2);
}

#[test]
fn enterprise_engine_end_to_end_blackout() {
    let engine = EnterpriseEngine::with_defaults();

    // Nominal tick
    let candidates = vec![
        ProbeCandidate::new("tls", "1.2.3.4:443", "tls", 10, false),
        ProbeCandidate::new("grpc", "www.digikala.com:443", "grpc", 20, false),
    ];
    let res_nominal = engine.tick(&normal_signal(), candidates.clone());
    assert!(!res_nominal.bound_reached);
    assert_eq!(res_nominal.morph_profile, "https-browsing");

    // Routing severed: escalate + race + bond
    let res_severed = engine.tick(&routing_severed_signal(), candidates.clone());
    assert_eq!(
        res_severed.blackout_level,
        aether_supervisor::blackout::IsolationLevel::RoutingSevered
    );
    assert!(res_severed.race_winner.is_some());
    assert!(res_severed.throughput_multiplier >= 1.0);

    // Full isolation: bound reached, honest reporting (never fake connected)
    let res_full = engine.tick(&full_isolation_signal(), vec![]);
    assert!(res_full.bound_reached);
    assert!(res_full.race_winner.is_none());

    // Recovery: should go back to Normal instantly
    let res_recovery = engine.tick(&normal_signal(), candidates);
    assert_eq!(
        res_recovery.blackout_level,
        aether_supervisor::blackout::IsolationLevel::Normal
    );
}

#[test]
fn buffer_replay_preserves_data_across_failover() {
    let replay = Arc::new(RingBufferReplay::new(64));
    let payload = b"critical user data that must not be lost".to_vec();
    let _seq = replay.push(payload.clone());

    // Simulate transport drop
    let frames = replay.on_drop();
    assert_eq!(frames.len(), 1);
    assert_eq!(
        frames[0].data, payload,
        "buffer replay must preserve data across failover (zero loss)"
    );
}
