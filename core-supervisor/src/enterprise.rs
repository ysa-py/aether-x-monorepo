//! Enterprise Absolute-Resilient Network Architecture — top-level integration
//! Covers both Enterprise Quantum and Absolute-Resilient Kernel
//! Composes every anti-DPI, anti-censorship, zero-disconnection subsystem into single automatic engine
//! Ensures "کاربر قطعی را حس نکند" + Northflank native CNI adaptation with fallback

use crate::active_defense::ActiveDefenseEngine;
use crate::anomaly_detector::{AnomalyDetector, TcpSample};
use crate::blackout::{BlackoutController, BlackoutSignal};
use crate::chaff::{ChaffConfig, ChaffEngine};
use crate::cni_detector::CniDetector;
use crate::deterministic_fallback::DeterministicFallback;
use crate::domain_fronting::DomainFrontingEngine;
use crate::ebpf::EbpfMorphEngine;
use crate::fallback_transport::ReverseTunnelManager;
use crate::fec_engine::{AdaptiveFec, FecConfig};
use crate::happy_eyeballs::{HappyEyeballs, HappyEyeballsConfig, ProbeCandidate};
use crate::loopback_buffer::LoopbackBuffer;
use crate::mpquic::MpQuicSession;
use crate::os_polymorphism::OsPolymorphismEngine;
use crate::pqc_handshake::PqcHandshake;
use crate::quic_migration::QuicMigrationManager;
use crate::reverse_relay::ReverseRelayEngine;
use crate::shadow_socket::ShadowSocketManager;
use crate::sni_whitelist::SniWhitelist;
use crate::sockops::SockHashManager;
use crate::tls_mimicry::TlsMimicryEngine;
use crate::xdp_engine::XdpEngine;
use crate::zkp_auth::{Commitment, ZkpVerifier};
use parking_lot::RwLock;
use std::sync::Arc;
use std::time::Instant;

/// Enterprise engine configuration
#[derive(Debug, Clone)]
pub struct EnterpriseConfig {
    pub core_addr: String,
    pub prefer_ipv6: bool,
    pub enable_chaff: bool,
    pub enable_ebpf: bool,
    pub enable_quic_migration: bool,
    pub enable_pqc: bool,
    pub enable_fec: bool,
    pub enable_sockops: bool,
    pub enable_xdp: bool,
    pub enable_mpquic: bool,
}

impl Default for EnterpriseConfig {
    fn default() -> Self {
        Self {
            core_addr: "core.aether-x.example:443".to_string(),
            prefer_ipv6: true,
            enable_chaff: true,
            enable_ebpf: true,
            enable_quic_migration: true,
            enable_pqc: true,
            enable_fec: true,
            enable_sockops: true,
            enable_xdp: true,
            enable_mpquic: true,
        }
    }
}

/// The absolute-resilient enterprise engine
pub struct EnterpriseEngine {
    pub config: EnterpriseConfig,
    pub reverse_relay: Arc<ReverseRelayEngine>,
    pub fallback_mgr: Arc<ReverseTunnelManager>,
    pub deterministic_fallback: Arc<DeterministicFallback>,
    pub fronting: Arc<DomainFrontingEngine>,
    pub whitelist: Arc<SniWhitelist>,
    pub ebpf_morph: RwLock<EbpfMorphEngine>,
    pub xdp_engine: Arc<XdpEngine>,
    pub sockops: Arc<SockHashManager>,
    pub shadow_socket: Arc<ShadowSocketManager>,
    pub chaff: RwLock<ChaffEngine>,
    pub tls_mimicry: Arc<TlsMimicryEngine>,
    pub quic_migration: Arc<QuicMigrationManager>,
    pub mpquic: RwLock<Option<MpQuicSession>>,
    pub blackout: RwLock<BlackoutController>,
    pub happy_eyeballs: HappyEyeballs,
    pub anomaly_detector: Arc<AnomalyDetector>,
    pub loopback_buffer: Arc<LoopbackBuffer>,
    pub os_poly: Arc<OsPolymorphismEngine>,
    pub active_defense: Arc<ActiveDefenseEngine>,
    pub zkp_verifier: Arc<ZkpVerifier>,
    pub pqc_handshake: RwLock<Option<PqcHandshake>>,
    pub adaptive_fec: Arc<AdaptiveFec>,
    pub cni_detector: Arc<CniDetector>,
    pub started_at: Instant,
}

impl EnterpriseEngine {
    #[must_use]
    pub fn new(config: EnterpriseConfig) -> Self {
        let whitelist = Arc::new(SniWhitelist::with_iran_defaults());
        let fronting = Arc::new(DomainFrontingEngine::new(Arc::clone(&whitelist)));
        let mut morph = EbpfMorphEngine::new();
        let _ = morph.load("eth0");
        let xdp = Arc::new(XdpEngine::new());
        let _ = xdp.detect_and_attach("veth-northflank");

        Self {
            config: config.clone(),
            reverse_relay: Arc::new(ReverseRelayEngine::new()),
            fallback_mgr: Arc::new(ReverseTunnelManager::new()),
            deterministic_fallback: Arc::new(DeterministicFallback::new()),
            fronting,
            whitelist,
            ebpf_morph: RwLock::new(morph),
            xdp_engine: xdp,
            sockops: Arc::new(SockHashManager::new()),
            shadow_socket: Arc::new(ShadowSocketManager::new()),
            chaff: RwLock::new(ChaffEngine::new(ChaffConfig::default())),
            tls_mimicry: Arc::new(TlsMimicryEngine::with_chrome()),
            quic_migration: Arc::new(QuicMigrationManager::new()),
            mpquic: RwLock::new(None),
            blackout: RwLock::new(BlackoutController::with_full_tier("primary-core")),
            happy_eyeballs: HappyEyeballs::with_config(HappyEyeballsConfig {
                prefer_ipv6: config.prefer_ipv6,
                ..Default::default()
            }),
            anomaly_detector: Arc::new(AnomalyDetector::new(64)),
            loopback_buffer: Arc::new(LoopbackBuffer::new(1024)),
            os_poly: Arc::new(OsPolymorphismEngine::new()),
            active_defense: Arc::new(ActiveDefenseEngine::new()),
            zkp_verifier: Arc::new(ZkpVerifier::new([0u8; 32])),
            pqc_handshake: RwLock::new(Some(PqcHandshake::from_seed(1))),
            adaptive_fec: Arc::new(AdaptiveFec::new(10, 1024)),
            cni_detector: Arc::new(CniDetector::new()),
            started_at: Instant::now(),
        }
    }

    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(EnterpriseConfig::default())
    }

    /// One fully automatic tick: handles blackout, picks best transport, applies chaff, ensures QUIC migration, updates eBPF maps
    /// Also runs anomaly detector for proactive failover 200ms before drop, and deterministic fallback chain <200ms
    pub fn tick(&self, signal: &BlackoutSignal, probe_candidates: Vec<ProbeCandidate>) -> EnterpriseTickResult {
        // 1. Anomaly detection — proactive failover 200ms before drop
        let anomaly = self.anomaly_detector.predict();
        let should_proactive = self.anomaly_detector.should_failover_early();

        // 2. Blackout classification drives morph profile & escalation
        let blackout_action = {
            let mut bc = self.blackout.write();
            bc.react_fast(signal)
        };

        // 3. Happy Eyeballs racing
        let race_result = if probe_candidates.is_empty() {
            None
        } else {
            Some(self.happy_eyeballs.race(probe_candidates))
        };

        // 4. Deterministic fallback chain if needed and within budget
        let fallback_result = if blackout_action.base.level != crate::blackout::IsolationLevel::Normal {
            Some(
                self.deterministic_fallback
                    .fallback("edge-auto", &self.config.core_addr),
            )
        } else {
            None
        };

        // 5. Reverse relay reconnect
        let relay_reconnects = self.reverse_relay.tick(&self.config.core_addr);

        // 6. Stats
        let chaff_stats = self.chaff.read().stats();
        let ebpf_stats = self.ebpf_morph.read().stats();
        let xdp_stats = self.xdp_engine.stats();
        let sockops_stats = self.sockops.stats();

        EnterpriseTickResult {
            blackout_level: blackout_action.base.level,
            morph_profile: blackout_action.base.morph_profile.clone(),
            bound_reached: blackout_action.base.bound_reached,
            race_winner: race_result
                .as_ref()
                .and_then(|r| r.winner.as_ref().map(|w| w.candidate_id.clone())),
            bonded_paths: blackout_action.bonded_paths.clone(),
            throughput_multiplier: blackout_action.throughput_multiplier,
            relay_reconnects: relay_reconnects.len(),
            chaff_packets: chaff_stats.packets_chaffed,
            ebpf_flows: ebpf_stats.frag_applied + ebpf_stats.ooo_injected,
            xdp_mode: xdp_stats.mode.as_str().to_string(),
            xdp_packets: xdp_stats.packets,
            sockops_redirects: sockops_stats.total_redirects,
            anomaly_prediction: format!("{:?}", anomaly.prediction),
            should_proactive_failover: should_proactive,
            fallback_winner: fallback_result
                .as_ref()
                .and_then(|r| r.winning_transport.map(|k| k.as_str().to_string())),
            fallback_elapsed_ms: fallback_result
                .as_ref()
                .map(|r| r.total_elapsed.as_millis() as u64)
                .unwrap_or(0),
            fec_target_loss: self.adaptive_fec.current_config().target_loss,
        }
    }

    /// Buffer outgoing data in loopback buffer during micro-failover to prevent socket drop
    pub fn buffer_outgoing(&self, data: Vec<u8>) -> u64 {
        self.loopback_buffer.buffer_segment(data)
    }

    /// Apply chaffing
    pub fn chaff_packet(&self, original_len: u32, seed: u64) -> crate::chaff::ChaffedPacket {
        let mut eng = self.chaff.write();
        eng.chaff_packet(original_len, seed)
    }

    /// Observe TCP sample for anomaly detection
    pub fn observe_tcp(&self, rtt_ms: u32, ack_delay_ms: u32, loss: bool) {
        let sample = TcpSample {
            rtt_ms,
            ack_delay_ms,
            loss,
            timestamp: Instant::now(),
        };
        self.anomaly_detector.observe(sample);
    }

    #[must_use]
    pub fn uptime(&self) -> std::time::Duration {
        self.started_at.elapsed()
    }
}

#[derive(Debug, Clone)]
pub struct EnterpriseTickResult {
    pub blackout_level: crate::blackout::IsolationLevel,
    pub morph_profile: String,
    pub bound_reached: bool,
    pub race_winner: Option<String>,
    pub bonded_paths: Vec<String>,
    pub throughput_multiplier: f64,
    pub relay_reconnects: usize,
    pub chaff_packets: u64,
    pub ebpf_flows: u64,
    pub xdp_mode: String,
    pub xdp_packets: u64,
    pub sockops_redirects: u64,
    pub anomaly_prediction: String,
    pub should_proactive_failover: bool,
    pub fallback_winner: Option<String>,
    pub fallback_elapsed_ms: u64,
    pub fec_target_loss: f64,
}

impl Default for EnterpriseEngine {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blackout::BlackoutSignal;
    use crate::happy_eyeballs::ProbeCandidate;

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

    fn severed_signal() -> BlackoutSignal {
        BlackoutSignal {
            international_ip_severed: true,
            dns_resolves_international: true,
            tcp_rst_rate: 0.0,
            tls_trunc_rate: 0.0,
            dns_anomaly_rate: 0.0,
            domestic_intranet_up: true,
        }
    }

    #[test]
    fn enterprise_tick_nominal() {
        let engine = EnterpriseEngine::with_defaults();
        let result = engine.tick(&normal_signal(), vec![]);
        assert!(!result.bound_reached);
        assert_eq!(result.morph_profile, "https-browsing");
    }

    #[test]
    fn enterprise_tick_severed_with_fallback() {
        let engine = EnterpriseEngine::with_defaults();
        let candidates = vec![
            ProbeCandidate::new("tls", "1.2.3.4:443", "tls", 10, false),
            ProbeCandidate::new("grpc", "1.2.3.4:443", "grpc", 20, false),
        ];
        let result = engine.tick(&severed_signal(), candidates);
        assert_eq!(
            result.blackout_level,
            crate::blackout::IsolationLevel::RoutingSevered
        );
        assert!(result.race_winner.is_some());
        assert!(result.fallback_winner.is_some());
        assert!(result.fallback_elapsed_ms < 200);
    }

    #[test]
    fn loopback_buffer_prevents_drop() {
        let engine = EnterpriseEngine::with_defaults();
        let seq = engine.buffer_outgoing(b"critical data".to_vec());
        assert!(seq > 0);
        let unacked = engine.loopback_buffer.unacked_segments();
        assert_eq!(unacked.len(), 1);
        let replay = engine.loopback_buffer.replay_unacked();
        assert_eq!(replay.len(), 1);
    }

    #[test]
    fn anomaly_detector_triggers_early() {
        let engine = EnterpriseEngine::with_defaults();
        for _ in 0..10 {
            engine.observe_tcp(50, 10, false);
        }
        let result = engine.tick(&normal_signal(), vec![]);
        assert!(!result.should_proactive_failover);

        for _ in 0..10 {
            engine.observe_tcp(100, 50, true);
        }
        let result2 = engine.tick(&normal_signal(), vec![]);
        assert!(result2.should_proactive_failover || result2.anomaly_prediction.contains("RisingLoss") || result2.anomaly_prediction.contains("DropImminent") || result2.anomaly_prediction.contains("AckStall"));
    }

    #[test]
    fn xdp_and_sockops_stats() {
        let engine = EnterpriseEngine::with_defaults();
        let result = engine.tick(&normal_signal(), vec![]);
        assert!(!result.xdp_mode.is_empty());
    }
}
