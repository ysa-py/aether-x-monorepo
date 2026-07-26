// Fuzz the Tor/Transport registry, AI-DPI morpher, and failover bridge with
// adversarial byte streams. Exercises pad_packet, ja4_fingerprint,
// rotate_profile, transport selection, and failover under ASan.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // --- AI-DPI morpher ---
    let morpher = aether_supervisor::ai_dpi::TrafficMorpher::with_default_profiles();

    // Rotate profiles based on first byte.
    if !data.is_empty() {
        for _ in 0..(data[0] % 5) {
            let _ = morpher.rotate_profile();
        }
    }

    // Pad arbitrary packet lengths — pad_packet may return a SMALLER value
    // when the input exceeds all target lengths (clamps to largest target).
    for chunk in data.chunks(4) {
        let mut buf = [0u8; 4];
        let n = chunk.len().min(4);
        buf[..n].copy_from_slice(&chunk[..n]);
        let len = u32::from_le_bytes(buf);
        let _padded = morpher.pad_packet(len);
    }

    // Generate JA4 fingerprints from various seeds.
    for chunk in data.chunks(8) {
        if chunk.len() >= 8 {
            let seed = u64::from_le_bytes([
                chunk[0], chunk[1], chunk[2], chunk[3],
                chunk[4], chunk[5], chunk[6], chunk[7],
            ]);
            let fp = morpher.ja4_fingerprint(seed);
            assert!(!fp.extensions_order.is_empty());
        }
    }

    // IAT jitter — just assert no panic.
    if data.len() >= 8 {
        let seed = u64::from_le_bytes([
            data[0], data[1], data[2], data[3],
            data[4], data[5], data[6], data[7],
        ]);
        let _jitter = morpher.iat_jitter_ms(seed);
    }

    // --- Transport registry ---
    let reg = aether_supervisor::tor::TransportRegistry::with_all_transports();
    let best = reg.select_best();
    assert!(best.is_some(), "registry should have an available transport");

    // --- Failover bridge ---
    use aether_supervisor::failover::{FailoverBridge, TransportHandle};
    use std::time::Instant;

    let active = TransportHandle {
        name: "direct-ip".into(),
        established_at: Instant::now(),
        bytes_forwarded: 0,
    };
    let standbys = vec![
        TransportHandle {
            name: "webtunnel".into(),
            established_at: Instant::now(),
            bytes_forwarded: 0,
        },
        TransportHandle {
            name: "arti-tor".into(),
            established_at: Instant::now(),
            bytes_forwarded: 0,
        },
    ];
    let bridge = FailoverBridge::new(active, standbys);

    // Trigger failover(s) based on fuzz input length (capped at 2 to
    // match the 2 standbys — extra failovers are no-ops).
    let failover_count = data.len().min(2);
    for _ in 0..failover_count {
        let (name, us) = bridge.failover();
        assert!(us < 2_000_000, "failover took {us}us, expected < 2s");
        assert!(!name.is_empty());
    }

    // Verify standby count never underflows.
    assert!(bridge.standby_count() <= 2);
});
