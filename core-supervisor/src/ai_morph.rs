//! AI Traffic Morphing with ONNX Runtime — real-time models
//!
//! Lightweight runtime to dynamically shape inter-packet arrival times (IAT)
//! and packet size distributions matching:
//! - Zoom RTP (real-time video conferencing)
//! - YouTube HLS (adaptive streaming)
//! - TLS WebSocket (interactive browsing)
//!
//! Production uses `ort` crate for ONNX inference; here mock models with statistical profiles
//! The morpher selects best model based on current DPI pressure and blackout level.

use parking_lot::RwLock;
use std::time::Duration;

/// Traffic model type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficModelKind {
    ZoomRtp,
    YouTubeHls,
    TlsWebSocket,
    AparatVod,       // existing Iranian domestic
    ShaparakBanking, // most whitelisted
}

impl TrafficModelKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ZoomRtp => "zoom-rtp",
            Self::YouTubeHls => "youtube-hls",
            Self::TlsWebSocket => "tls-websocket",
            Self::AparatVod => "aparat-vod",
            Self::ShaparakBanking => "shaparak-banking",
        }
    }
}

/// Statistical profile for a traffic model
#[derive(Debug, Clone)]
pub struct TrafficProfileModel {
    pub kind: TrafficModelKind,
    /// Packet size distribution: (mean, stddev, min, max)
    pub size_mean: f64,
    pub size_std: f64,
    pub size_min: u32,
    pub size_max: u32,
    /// IAT distribution in microseconds: (mean, stddev, min, max)
    pub iat_mean_us: f64,
    pub iat_std_us: f64,
    pub iat_min_us: u64,
    pub iat_max_us: u64,
    /// Burstiness: packets per burst
    pub burst_size: u32,
    /// Entropy target (0-8 bits per byte)
    pub entropy_target: f64,
}

impl TrafficProfileModel {
    /// Zoom RTP: small frequent packets, low jitter, ~100-1400 bytes, 5-20ms IAT
    #[must_use]
    pub fn zoom_rtp() -> Self {
        Self {
            kind: TrafficModelKind::ZoomRtp,
            size_mean: 1100.0,
            size_std: 250.0,
            size_min: 200,
            size_max: 1400,
            iat_mean_us: 8000.0,
            iat_std_us: 1500.0,
            iat_min_us: 2000,
            iat_max_us: 20000,
            burst_size: 1,
            entropy_target: 7.2,
        }
    }

    /// YouTube HLS: large chunks, bursty, 1316-1420 bytes typical
    #[must_use]
    pub fn youtube_hls() -> Self {
        Self {
            kind: TrafficModelKind::YouTubeHls,
            size_mean: 1380.0,
            size_std: 80.0,
            size_min: 1200,
            size_max: 1420,
            iat_mean_us: 12000.0,
            iat_std_us: 3000.0,
            iat_min_us: 5000,
            iat_max_us: 40000,
            burst_size: 8,
            entropy_target: 7.8,
        }
    }

    /// TLS WebSocket: interactive, variable sizes, 517-1400 bytes
    #[must_use]
    pub fn tls_websocket() -> Self {
        Self {
            kind: TrafficModelKind::TlsWebSocket,
            size_mean: 900.0,
            size_std: 400.0,
            size_min: 200,
            size_max: 1400,
            iat_mean_us: 15000.0,
            iat_std_us: 8000.0,
            iat_min_us: 1000,
            iat_max_us: 100000,
            burst_size: 3,
            entropy_target: 6.5,
        }
    }

    #[must_use]
    pub fn aparat_vod() -> Self {
        Self {
            kind: TrafficModelKind::AparatVod,
            size_mean: 1360.0,
            size_std: 50.0,
            size_min: 1316,
            size_max: 1420,
            iat_mean_us: 10000.0,
            iat_std_us: 2000.0,
            iat_min_us: 5000,
            iat_max_us: 25000,
            burst_size: 10,
            entropy_target: 7.5,
        }
    }

    #[must_use]
    pub fn shaparak_banking() -> Self {
        Self {
            kind: TrafficModelKind::ShaparakBanking,
            size_mean: 700.0,
            size_std: 150.0,
            size_min: 512,
            size_max: 896,
            iat_mean_us: 70000.0,
            iat_std_us: 25000.0,
            iat_min_us: 30000,
            iat_max_us: 150000,
            burst_size: 2,
            entropy_target: 6.0,
        }
    }
}

/// ONNX Engine Mock – in production would use `ort` crate to run real models
/// Here simulates inference with deterministic LCG
#[derive(Debug)]
pub struct OnnxMorphEngine {
    active_model: RwLock<TrafficProfileModel>,
    models: Vec<TrafficProfileModel>,
    inferences: std::sync::atomic::AtomicU64,
}

impl OnnxMorphEngine {
    #[must_use]
    pub fn new() -> Self {
        let models = vec![
            TrafficProfileModel::zoom_rtp(),
            TrafficProfileModel::youtube_hls(),
            TrafficProfileModel::tls_websocket(),
            TrafficProfileModel::aparat_vod(),
            TrafficProfileModel::shaparak_banking(),
        ];
        Self {
            active_model: RwLock::new(TrafficProfileModel::tls_websocket()),
            models,
            inferences: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Select best model based on DPI level and isolation
    pub fn select_model_for_isolation(&self, isolation_level: u8) {
        // 0=Normal -> tls-websocket, 1=DpiBlocking -> aparat, 2=RoutingSevered -> shaparak, 3=FullIsolation -> shaparak
        let kind = match isolation_level {
            0 => TrafficModelKind::TlsWebSocket,
            1 => TrafficModelKind::AparatVod,
            2 | 3 => TrafficModelKind::ShaparakBanking,
            _ => TrafficModelKind::TlsWebSocket,
        };
        if let Some(m) = self.models.iter().find(|x| x.kind == kind) {
            *self.active_model.write() = m.clone();
        }
    }

    /// Select model based on real-time recommendation from ClickHouse telemetry
    pub fn select_model(&self, kind: TrafficModelKind) -> bool {
        if let Some(m) = self.models.iter().find(|x| x.kind == kind) {
            *self.active_model.write() = m.clone();
            true
        } else {
            false
        }
    }

    #[must_use]
    pub fn active_model(&self) -> TrafficProfileModel {
        self.active_model.read().clone()
    }

    #[must_use]
    pub fn models(&self) -> Vec<TrafficProfileModel> {
        self.models.clone()
    }

    /// Morph packet: given original_len and seed, returns morphed size + IAT jitter
    /// Simulates ONNX inference: Box-Muller for Gaussian size/IAT
    pub fn morph_packet(&self, original_len: u32, seed: u64) -> MorphedPacket {
        let model = self.active_model.read().clone();
        let mut lcg_state = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);

        let next_u64 = |state: &mut u64| {
            *state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *state
        };

        let next_f64 = |state: &mut u64| {
            let v = next_u64(state) >> 11;
            let f = (v as f64) / 9_007_199_254_740_992.0;
            if f <= 0.0 {
                f64::MIN_POSITIVE
            } else {
                f
            }
        };

        // Gaussian for size
        let mut s = lcg_state;
        let u1 = next_f64(&mut s);
        let u2 = next_f64(&mut s);
        let r = (-2.0 * u1.ln()).sqrt();
        let theta = 2.0 * std::f64::consts::PI * u2;
        let z_size = r * theta.cos();
        let morphed_size_f = model.size_mean + z_size * model.size_std;
        let morphed_size = (morphed_size_f as u32).clamp(model.size_min, model.size_max);
        // Ensure at least original_len (padding, not truncating)
        let padded_size = morphed_size.max(original_len);

        // Gaussian for IAT
        let u1_iat = next_f64(&mut s);
        let u2_iat = next_f64(&mut s);
        let r_iat = (-2.0 * u1_iat.ln()).sqrt();
        let theta_iat = 2.0 * std::f64::consts::PI * u2_iat;
        let mut z_iat = r_iat * theta_iat.cos();
        z_iat = z_iat.clamp(-4.0, 4.0);
        let iat_f = model.iat_mean_us + z_iat * model.iat_std_us;
        let iat_us = (iat_f as u64).clamp(model.iat_min_us, model.iat_max_us);

        self.inferences
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        MorphedPacket {
            original_len,
            morphed_len: padded_size,
            padding: padded_size - original_len,
            iat_jitter: Duration::from_micros(iat_us),
            model_kind: model.kind,
            entropy_target: model.entropy_target,
        }
    }

    #[must_use]
    pub fn inference_count(&self) -> u64 {
        self.inferences.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[derive(Debug, Clone)]
pub struct MorphedPacket {
    pub original_len: u32,
    pub morphed_len: u32,
    pub padding: u32,
    pub iat_jitter: Duration,
    pub model_kind: TrafficModelKind,
    pub entropy_target: f64,
}

impl Default for OnnxMorphEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_selection_and_morph() {
        let engine = OnnxMorphEngine::new();
        assert_eq!(engine.active_model().kind, TrafficModelKind::TlsWebSocket);

        engine.select_model(TrafficModelKind::ZoomRtp);
        assert_eq!(engine.active_model().kind, TrafficModelKind::ZoomRtp);

        let morphed = engine.morph_packet(1000, 42);
        assert!(morphed.morphed_len >= 1000);
        assert!(morphed.iat_jitter.as_micros() >= 2000);
        assert_eq!(morphed.model_kind, TrafficModelKind::ZoomRtp);
    }

    #[test]
    fn isolation_drives_model() {
        let engine = OnnxMorphEngine::new();
        engine.select_model_for_isolation(0);
        assert_eq!(engine.active_model().kind, TrafficModelKind::TlsWebSocket);
        engine.select_model_for_isolation(1);
        assert_eq!(engine.active_model().kind, TrafficModelKind::AparatVod);
        engine.select_model_for_isolation(2);
        assert_eq!(
            engine.active_model().kind,
            TrafficModelKind::ShaparakBanking
        );
    }

    #[test]
    fn morph_distribution() {
        let engine = OnnxMorphEngine::new();
        engine.select_model(TrafficModelKind::YouTubeHls);
        let mut sizes = Vec::new();
        for seed in 0..1000 {
            let m = engine.morph_packet(1200, seed);
            sizes.push(m.morphed_len);
        }
        // YouTube HLS mean ~1380, should cluster
        let avg = sizes.iter().map(|&x| x as f64).sum::<f64>() / sizes.len() as f64;
        assert!((avg - 1380.0).abs() < 100.0, "avg {avg} not near 1380");
        let unique: std::collections::HashSet<u32> = sizes.into_iter().collect();
        assert!(unique.len() > 20, "should vary");
    }

    #[test]
    fn inference_count() {
        let engine = OnnxMorphEngine::new();
        assert_eq!(engine.inference_count(), 0);
        engine.morph_packet(100, 1);
        engine.morph_packet(100, 2);
        assert_eq!(engine.inference_count(), 2);
    }

    #[test]
    fn all_models_available() {
        let engine = OnnxMorphEngine::new();
        let models = engine.models();
        assert_eq!(models.len(), 5);
        assert!(models.iter().any(|m| m.kind == TrafficModelKind::ZoomRtp));
        assert!(models
            .iter()
            .any(|m| m.kind == TrafficModelKind::YouTubeHls));
    }
}
