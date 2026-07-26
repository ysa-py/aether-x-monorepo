//! Model Registry & ONNX Loader with Shadow Mode (Subsystem A).
//!
//! Loads signed ONNX artifacts from the model registry. Every artifact MUST be
//! signed by `antiforgery`'s Ed25519 key material — unsigned or tampered
//! artifacts are rejected at load time.
//!
//! Models run in **shadow mode** for ≥ 7 days or ≥ 10,000 decisions before
//! promotion. In shadow mode, the model's prediction is logged via
//! `TelemetryEvent(SHADOW_DECISION)` but the FSM's real decision is what ships.
//!
//! Rollback: a promoted model reverts to FSM-only in < 5s via `ApplyPolicy`.
//!
//! # Safety
//! `#![forbid(unsafe_code)]` is enforced at the crate level.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::policy::{Decision, FailureSignature, FallbackEngine};

/// Identifier for a model in the registry.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ModelKind {
    /// Censorship Event Classifier (block-type probability per window).
    CensorshipClassifier,
    /// Protocol Fitness Predictor (expected success rate, RTT per protocol/ISP).
    ProtocolFitness,
    /// Fingerprint Drift Detector (autoencoder anomaly score).
    FingerprintDrift,
    /// Adaptive Fallback Policy (PPO/DQN action distribution).
    AdaptiveFallback,
    /// Artifact Signer (validates ONNX artifact signatures).
    ArtifactSigner,
}

impl std::fmt::Display for ModelKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CensorshipClassifier => write!(f, "censorship_classifier"),
            Self::ProtocolFitness => write!(f, "protocol_fitness"),
            Self::FingerprintDrift => write!(f, "fingerprint_drift"),
            Self::AdaptiveFallback => write!(f, "adaptive_fallback"),
            Self::ArtifactSigner => write!(f, "artifact_signer"),
        }
    }
}

/// The operational mode of a loaded model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModelMode {
    /// Model is loaded but predictions are only logged — FSM decides.
    Shadow,
    /// Model is promoted and its predictions influence real decisions.
    Promoted,
    /// Model was promoted but rolled back to FSM-only.
    RolledBack,
}

/// Metadata about a loaded model artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelArtifact {
    pub kind: ModelKind,
    pub version: String,
    pub signature_hex: String,
    pub loaded_at: Instant,
    pub mode: ModelMode,
    pub shadow_decision_count: u64,
    pub promoted_at: Option<Instant>,
}

/// Shadow decision log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowDecision {
    pub model_kind: String,
    pub model_version: String,
    pub model_prediction: String,
    pub fsm_decision: String,
    pub timestamp_unix_ms: u64,
    pub isp: String,
}

/// Aggregated, privacy-preserving evidence collected while a model is in
/// shadow mode. It deliberately contains no subscriber, destination, IP, or
/// raw traffic data: callers may only report the two boolean outcomes from an
/// authorized replay/canary evaluation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowEvaluation {
    /// Number of paired outcomes evaluated against the deterministic FSM.
    pub samples: u64,
    /// Evaluations in which the model recommendation met the declared success
    /// criterion (for example a successful reconnect inside the chosen SLO).
    pub model_successes: u64,
    /// Evaluations in which the deterministic FSM recommendation met that
    /// same criterion.
    pub fsm_successes: u64,
    /// Paired cases where the model succeeded and the FSM did not.
    pub model_only_successes: u64,
    /// Paired cases where the FSM succeeded and the model did not.
    pub fsm_only_successes: u64,
}

impl ShadowEvaluation {
    /// Add one paired result. The caller must use identical success criteria
    /// for model and FSM paths; this type never receives raw observation data.
    pub fn observe(&mut self, model_succeeded: bool, fsm_succeeded: bool) {
        self.samples = self.samples.saturating_add(1);
        if model_succeeded {
            self.model_successes = self.model_successes.saturating_add(1);
        }
        if fsm_succeeded {
            self.fsm_successes = self.fsm_successes.saturating_add(1);
        }
        if model_succeeded && !fsm_succeeded {
            self.model_only_successes = self.model_only_successes.saturating_add(1);
        }
        if fsm_succeeded && !model_succeeded {
            self.fsm_only_successes = self.fsm_only_successes.saturating_add(1);
        }
    }

    /// Model success rate over evaluated paired outcomes.
    #[must_use]
    pub fn model_success_rate(self) -> f64 {
        rate(self.model_successes, self.samples)
    }

    /// FSM success rate over the same evaluated paired outcomes.
    #[must_use]
    pub fn fsm_success_rate(self) -> f64 {
        rate(self.fsm_successes, self.samples)
    }

    /// Whether the model has enough evidence to be allowed to influence the
    /// data plane. The gate demands a minimum sample count, a material success
    /// margin, and no net paired regression versus the FSM.
    #[must_use]
    pub fn meets_promotion_quality_gate(self) -> bool {
        if self.samples < SHADOW_MIN_EVALUATED_OUTCOMES {
            return false;
        }
        let model_rate = self.model_success_rate();
        let fsm_rate = self.fsm_success_rate();
        let model_has_margin = model_rate >= fsm_rate + PROMOTION_MIN_SUCCESS_MARGIN;
        let no_net_paired_regression = self.model_only_successes >= self.fsm_only_successes;
        model_has_margin && no_net_paired_regression
    }
}

/// A complete explanation of whether a model may be promoted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct PromotionReadiness {
    /// The requested model exists in the signed registry.
    pub loaded: bool,
    /// Only the adaptive fallback model is allowed to influence routing.
    pub controls_routing: bool,
    /// Seven-day shadow interval completed.
    pub shadow_duration_satisfied: bool,
    /// At least 10,000 shadow predictions completed.
    pub shadow_decisions_satisfied: bool,
    /// Paired outcome quality gate completed.
    pub quality_gate_satisfied: bool,
    /// Aggregated evidence used for the quality check.
    pub evaluation: ShadowEvaluation,
}

impl PromotionReadiness {
    /// True only when every safety and evidence gate is satisfied.
    #[must_use]
    pub fn eligible(self) -> bool {
        self.loaded
            && self.controls_routing
            && self.shadow_duration_satisfied
            && self.shadow_decisions_satisfied
            && self.quality_gate_satisfied
    }
}

/// The result of an ONNX artifact signature verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureStatus {
    /// Valid Ed25519 signature from a trusted key.
    Valid,
    /// Signature does not match the artifact bytes.
    Invalid,
    /// No signature present.
    Missing,
    /// The signing key is not in the trusted set.
    UntrustedKey,
}

/// Verifies an ONNX artifact's Ed25519 signature against trusted public keys.
///
/// `artifact_bytes`: the raw ONNX model bytes.
/// `signature`: the 64-byte Ed25519 signature.
/// `trusted_keys`: set of 32-byte Ed25519 public keys.
pub fn verify_artifact_signature(
    artifact_bytes: &[u8],
    signature: &[u8; 64],
    trusted_keys: &[[u8; 32]],
) -> SignatureStatus {
    if signature.iter().all(|&b| b == 0) {
        return SignatureStatus::Missing;
    }
    // We verify by checking the signature against each trusted key.
    // In production, this uses ed25519-dalek via the antiforgery crate.
    // Here we implement the verification logic deterministically.
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let sig = Signature::from_bytes(signature);
    for key_bytes in trusted_keys {
        if let Ok(vk) = VerifyingKey::from_bytes(key_bytes) {
            if vk.verify(artifact_bytes, &sig).is_ok() {
                return SignatureStatus::Valid;
            }
        }
    }
    if trusted_keys.is_empty() {
        SignatureStatus::UntrustedKey
    } else {
        SignatureStatus::Invalid
    }
}

/// Minimum shadow-mode duration before a model can be promoted.
pub const SHADOW_MIN_DURATION: Duration = Duration::from_secs(7 * 24 * 3600); // 7 days
/// Minimum shadow-mode decisions before promotion.
pub const SHADOW_MIN_DECISIONS: u64 = 10_000;
/// Maximum time for a rollback to take effect.
pub const ROLLBACK_BUDGET: Duration = Duration::from_secs(5);
/// Minimum number of paired shadow outcomes required before promotion.
pub const SHADOW_MIN_EVALUATED_OUTCOMES: u64 = 1_000;
/// Required absolute success-rate advantage over the deterministic FSM.
pub const PROMOTION_MIN_SUCCESS_MARGIN: f64 = 0.01;
/// Bounded retained audit entries. Aggregate evidence remains available after
/// old, non-sensitive prediction records roll out of this ring.
pub const SHADOW_LOG_CAPACITY: usize = 4_096;

fn rate(successes: u64, samples: u64) -> f64 {
    if samples == 0 {
        return 0.0;
    }
    successes as f64 / samples as f64
}

/// The model registry holds all loaded models and tracks shadow/promoted state.
pub struct ModelRegistry {
    models: RwLock<HashMap<ModelKind, ModelArtifact>>,
    shadow_log: RwLock<VecDeque<ShadowDecision>>,
    evaluations: RwLock<HashMap<ModelKind, ShadowEvaluation>>,
    fsm_engine: FallbackEngine,
    trusted_keys: RwLock<Vec<[u8; 32]>>,
    total_shadow_decisions: AtomicU64,
    total_rollbacks: AtomicU64,
    total_promotions: AtomicU64,
    /// If true, all model inference is bypassed (FSM-only mode).
    fsm_only: AtomicBool,
}

impl ModelRegistry {
    /// Create an empty registry with the default FSM fallback engine.
    #[must_use]
    pub fn new() -> Self {
        Self {
            models: RwLock::new(HashMap::new()),
            shadow_log: RwLock::new(VecDeque::with_capacity(SHADOW_LOG_CAPACITY)),
            evaluations: RwLock::new(HashMap::new()),
            fsm_engine: FallbackEngine::default(),
            trusted_keys: RwLock::new(Vec::new()),
            total_shadow_decisions: AtomicU64::new(0),
            total_rollbacks: AtomicU64::new(0),
            total_promotions: AtomicU64::new(0),
            fsm_only: AtomicBool::new(true),
        }
    }

    /// Register a trusted Ed25519 public key for artifact verification.
    pub fn add_trusted_key(&self, key: [u8; 32]) {
        self.trusted_keys.write().push(key);
    }

    /// Attempt to load a model artifact. Rejects unsigned/tampered artifacts.
    /// Newly loaded models always start in **shadow mode**.
    pub fn load_artifact(
        &self,
        kind: ModelKind,
        version: &str,
        artifact_bytes: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), ModelRegistryError> {
        let keys = self.trusted_keys.read();
        let status = verify_artifact_signature(artifact_bytes, signature, &keys);
        match status {
            SignatureStatus::Valid => {}
            SignatureStatus::Invalid => return Err(ModelRegistryError::InvalidSignature),
            SignatureStatus::Missing => return Err(ModelRegistryError::MissingSignature),
            SignatureStatus::UntrustedKey => return Err(ModelRegistryError::UntrustedKey),
        }

        let sig_hex = hex_encode(signature);
        let artifact = ModelArtifact {
            kind: kind.clone(),
            version: version.to_string(),
            signature_hex: sig_hex,
            loaded_at: Instant::now(),
            mode: ModelMode::Shadow,
            shadow_decision_count: 0,
            promoted_at: None,
        };

        self.models.write().insert(kind.clone(), artifact);
        self.evaluations.write().remove(&kind);
        Ok(())
    }

    /// Load a model artifact without signature verification (test/dev only).
    /// The model starts in shadow mode.
    #[cfg(test)]
    pub fn load_unsigned_for_testing(&self, kind: ModelKind, version: &str) {
        let artifact = ModelArtifact {
            kind: kind.clone(),
            version: version.to_string(),
            signature_hex: "test".to_string(),
            loaded_at: Instant::now(),
            mode: ModelMode::Shadow,
            shadow_decision_count: 0,
            promoted_at: None,
        };
        self.models.write().insert(kind.clone(), artifact);
        self.evaluations.write().remove(&kind);
    }

    /// Record a shadow-mode decision. Returns the FSM decision that actually
    /// ships (the model prediction is logged but never applied).
    ///
    /// Calls for an unloaded or already-promoted model are intentionally a
    /// no-op beyond calculating the FSM decision. This prevents an arbitrary
    /// caller from inflating shadow counters or retaining unbounded data.
    pub fn record_shadow_decision(
        &self,
        kind: &ModelKind,
        model_prediction: &str,
        sig: FailureSignature,
        current_protocol: &str,
        isp: &str,
    ) -> Decision {
        let fsm_decision = self.fsm_engine.decide(current_protocol, sig);
        let model_version = {
            let models = self.models.read();
            let Some(artifact) = models.get(kind) else {
                return fsm_decision;
            };
            if artifact.mode != ModelMode::Shadow {
                return fsm_decision;
            }
            artifact.version.clone()
        };

        let entry = ShadowDecision {
            model_kind: kind.to_string(),
            model_version,
            model_prediction: model_prediction.to_string(),
            fsm_decision: format!("{fsm_decision:?}"),
            timestamp_unix_ms: unix_millis_now(),
            isp: isp.to_string(),
        };
        let mut log = self.shadow_log.write();
        if log.len() == SHADOW_LOG_CAPACITY {
            let _ = log.pop_front();
        }
        log.push_back(entry);
        drop(log);
        self.total_shadow_decisions.fetch_add(1, Ordering::Relaxed);

        if let Some(artifact) = self.models.write().get_mut(kind) {
            artifact.shadow_decision_count = artifact.shadow_decision_count.saturating_add(1);
        }

        fsm_decision
    }

    /// Record a paired aggregate outcome from a shadow replay or canary. No
    /// user identifier, destination, packet, or model input is accepted here.
    /// Returns false when the requested model is not actively in shadow mode.
    pub fn record_shadow_outcome(
        &self,
        kind: &ModelKind,
        model_succeeded: bool,
        fsm_succeeded: bool,
    ) -> bool {
        let in_shadow = self
            .models
            .read()
            .get(kind)
            .is_some_and(|artifact| artifact.mode == ModelMode::Shadow);
        if !in_shadow {
            return false;
        }
        self.evaluations
            .write()
            .entry(kind.clone())
            .or_default()
            .observe(model_succeeded, fsm_succeeded);
        true
    }

    /// Return every promotion gate and its current evidence. This lets an
    /// operator see exactly why an artifact remains advisory instead of
    /// exposing a privileged bypass for the deterministic floor.
    #[must_use]
    pub fn promotion_readiness(&self, kind: &ModelKind) -> PromotionReadiness {
        let artifact = self.models.read().get(kind).cloned();
        let evaluation = match self.evaluations.read().get(kind).copied() {
            Some(evaluation) => evaluation,
            None => ShadowEvaluation::default(),
        };
        let Some(artifact) = artifact else {
            return PromotionReadiness {
                evaluation,
                ..PromotionReadiness::default()
            };
        };

        let is_shadow = artifact.mode == ModelMode::Shadow;
        PromotionReadiness {
            loaded: true,
            // Classifiers and drift detectors can advise the FSM, but only an
            // adaptive fallback model is allowed to influence routing.
            controls_routing: matches!(kind, ModelKind::AdaptiveFallback) && is_shadow,
            shadow_duration_satisfied: is_shadow
                && artifact.loaded_at.elapsed() >= SHADOW_MIN_DURATION,
            shadow_decisions_satisfied: is_shadow
                && artifact.shadow_decision_count >= SHADOW_MIN_DECISIONS,
            quality_gate_satisfied: is_shadow && evaluation.meets_promotion_quality_gate(),
            evaluation,
        }
    }

    /// Check if a model is eligible for promotion. In addition to the seven
    /// days and 10,000 shadow predictions, the model must beat the FSM by the
    /// predeclared paired-outcome margin.
    #[must_use]
    pub fn is_promotion_eligible(&self, kind: &ModelKind) -> bool {
        self.promotion_readiness(kind).eligible()
    }

    /// Promote the adaptive fallback model to production. Other model kinds
    /// remain advisory even after a successful shadow evaluation, so a traffic
    /// classifier cannot acquire routing authority by itself.
    pub fn promote(&self, kind: &ModelKind) -> bool {
        if !self.is_promotion_eligible(kind) {
            return false;
        }
        let mut models = self.models.write();
        if let Some(artifact) = models.get_mut(kind) {
            if artifact.mode != ModelMode::Shadow {
                return false;
            }
            artifact.mode = ModelMode::Promoted;
            artifact.promoted_at = Some(Instant::now());
            self.total_promotions.fetch_add(1, Ordering::Relaxed);
            self.fsm_only.store(false, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Roll back a promoted model to FSM-only. Must complete in < 5s.
    /// Returns the elapsed rollback duration.
    pub fn rollback(&self, kind: &ModelKind) -> Result<Duration, ModelRegistryError> {
        let start = Instant::now();
        let mut models = self.models.write();
        let was_promoted = {
            let Some(artifact) = models.get_mut(kind) else {
                return Err(ModelRegistryError::NotLoaded);
            };
            if artifact.mode == ModelMode::Promoted {
                artifact.mode = ModelMode::RolledBack;
                true
            } else {
                false
            }
        };
        if was_promoted {
            self.total_rollbacks.fetch_add(1, Ordering::Relaxed);
            // Check if any other model is still promoted.
            let any_promoted = models.values().any(|a| a.mode == ModelMode::Promoted);
            if !any_promoted {
                self.fsm_only.store(true, Ordering::Relaxed);
            }
        }
        let elapsed = start.elapsed();
        // Verify we stayed within the rollback budget.
        if elapsed > ROLLBACK_BUDGET {
            return Err(ModelRegistryError::RollbackBudgetExceeded(elapsed));
        }
        Ok(elapsed)
    }

    /// Get the current mode of a loaded model.
    #[must_use]
    pub fn model_mode(&self, kind: &ModelKind) -> Option<ModelMode> {
        self.models.read().get(kind).map(|a| a.mode)
    }

    /// Whether the system is in FSM-only mode (no promoted models).
    #[must_use]
    pub fn is_fsm_only(&self) -> bool {
        self.fsm_only.load(Ordering::Relaxed)
    }

    /// Get the current model status for all loaded models.
    #[must_use]
    pub fn status(&self) -> Vec<ModelStatus> {
        let artifacts: Vec<ModelArtifact> = self.models.read().values().cloned().collect();
        artifacts
            .into_iter()
            .map(|artifact| {
                let readiness = self.promotion_readiness(&artifact.kind);
                ModelStatus {
                    kind: artifact.kind,
                    version: artifact.version,
                    mode: artifact.mode,
                    shadow_decisions: artifact.shadow_decision_count,
                    loaded_duration: artifact.loaded_at.elapsed(),
                    promotion_eligible: readiness.eligible(),
                    promotion_readiness: readiness,
                }
            })
            .collect()
    }

    /// Total shadow decisions logged across all models.
    #[must_use]
    pub fn total_shadow_decisions(&self) -> u64 {
        self.total_shadow_decisions.load(Ordering::Relaxed)
    }

    /// Total rollbacks performed.
    #[must_use]
    pub fn total_rollbacks(&self) -> u64 {
        self.total_rollbacks.load(Ordering::Relaxed)
    }

    /// Total promotions performed.
    #[must_use]
    pub fn total_promotions(&self) -> u64 {
        self.total_promotions.load(Ordering::Relaxed)
    }

    /// Get the shadow decision log (cloned).
    #[must_use]
    pub fn shadow_log(&self) -> Vec<ShadowDecision> {
        self.shadow_log.read().iter().cloned().collect()
    }

    /// Aggregate paired outcome evidence for a model. This is safe to expose to
    /// control-plane status because it contains no raw traffic or identity.
    #[must_use]
    pub fn shadow_evaluation(&self, kind: &ModelKind) -> ShadowEvaluation {
        match self.evaluations.read().get(kind).copied() {
            Some(evaluation) => evaluation,
            None => ShadowEvaluation::default(),
        }
    }

    /// Whether a given model kind is loaded (regardless of mode).
    #[must_use]
    pub fn is_loaded(&self, kind: &ModelKind) -> bool {
        self.models.read().contains_key(kind)
    }
}

impl Default for ModelRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Status snapshot for one model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelStatus {
    pub kind: ModelKind,
    pub version: String,
    pub mode: ModelMode,
    pub shadow_decisions: u64,
    pub loaded_duration: Duration,
    pub promotion_eligible: bool,
    /// Detailed, aggregate-only explanation for the promotion state.
    pub promotion_readiness: PromotionReadiness,
}

/// Errors from model registry operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelRegistryError {
    /// The artifact's Ed25519 signature does not match.
    InvalidSignature,
    /// No signature was provided.
    MissingSignature,
    /// The signing key is not in the trusted set.
    UntrustedKey,
    /// Rollback exceeded the 5s budget.
    RollbackBudgetExceeded(Duration),
    /// The model is not loaded.
    NotLoaded,
}

impl std::fmt::Display for ModelRegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSignature => write!(f, "artifact signature is invalid"),
            Self::MissingSignature => write!(f, "artifact signature is missing"),
            Self::UntrustedKey => write!(f, "signing key is not trusted"),
            Self::RollbackBudgetExceeded(d) => {
                write!(f, "rollback took {:?}, exceeding 5s budget", d)
            }
            Self::NotLoaded => write!(f, "model is not loaded"),
        }
    }
}

impl std::error::Error for ModelRegistryError {}

fn unix_millis_now() -> u64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_millis() as u64,
        Err(_) => 0,
    }
}

/// Encode bytes as lowercase hex.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsigned_artifact_is_rejected() {
        let registry = ModelRegistry::new();
        let zero_sig = [0u8; 64];
        let result = registry.load_artifact(
            ModelKind::CensorshipClassifier,
            "v1",
            b"model-bytes",
            &zero_sig,
        );
        assert_eq!(result, Err(ModelRegistryError::MissingSignature));
    }

    #[test]
    fn model_starts_in_shadow_mode() {
        let registry = ModelRegistry::new();
        registry.load_unsigned_for_testing(ModelKind::CensorshipClassifier, "v1");
        assert_eq!(
            registry.model_mode(&ModelKind::CensorshipClassifier),
            Some(ModelMode::Shadow)
        );
    }

    #[test]
    fn shadow_decision_logs_but_returns_fsm() {
        let registry = ModelRegistry::new();
        registry.load_unsigned_for_testing(ModelKind::CensorshipClassifier, "v1");
        let sig = FailureSignature {
            sample_count: 50,
            success_rate: 0.2,
            tcp_rst_rate: 0.6,
            tls_trunc_rate: 0.0,
            dns_anomaly_rate: 0.0,
        };
        let decision = registry.record_shadow_decision(
            &ModelKind::CensorshipClassifier,
            "rst-storm-predicted",
            sig,
            "reality-vision",
            "MCI",
        );
        // FSM should switch (RST storm), and that's what's returned.
        assert_eq!(decision, Decision::Switch("hysteria2".to_string()));
        assert_eq!(registry.total_shadow_decisions(), 1);
        assert_eq!(registry.shadow_log().len(), 1);
    }

    #[test]
    fn shadow_audit_log_is_bounded() {
        let registry = ModelRegistry::new();
        registry.load_unsigned_for_testing(ModelKind::CensorshipClassifier, "v1");
        let sig = FailureSignature {
            sample_count: 20,
            success_rate: 0.9,
            tcp_rst_rate: 0.0,
            tls_trunc_rate: 0.0,
            dns_anomaly_rate: 0.0,
        };
        for _ in 0..(SHADOW_LOG_CAPACITY + 1) {
            let _ = registry.record_shadow_decision(
                &ModelKind::CensorshipClassifier,
                "keep",
                sig,
                "reality-vision",
                "MCI",
            );
        }
        assert_eq!(registry.shadow_log().len(), SHADOW_LOG_CAPACITY);
        assert_eq!(registry.total_shadow_decisions(), (SHADOW_LOG_CAPACITY + 1) as u64);
    }

    #[test]
    fn promotion_requires_eligibility() {
        let registry = ModelRegistry::new();
        registry.load_unsigned_for_testing(ModelKind::ProtocolFitness, "v1");
        // Not eligible: too few decisions, too short duration.
        assert!(!registry.is_promotion_eligible(&ModelKind::ProtocolFitness));
        assert!(!registry.promote(&ModelKind::ProtocolFitness));
        assert_eq!(
            registry.model_mode(&ModelKind::ProtocolFitness),
            Some(ModelMode::Shadow)
        );
    }

    fn make_adaptive_fallback_promotion_eligible(
        registry: &ModelRegistry,
    ) -> Result<(), String> {
        registry.load_unsigned_for_testing(ModelKind::AdaptiveFallback, "v1");
        let Some(past) = Instant::now().checked_sub(SHADOW_MIN_DURATION) else {
            return Err("test clock cannot represent the required shadow interval".to_string());
        };
        {
            let mut models = registry.models.write();
            let Some(artifact) = models.get_mut(&ModelKind::AdaptiveFallback) else {
                return Err("adaptive fallback model is missing".to_string());
            };
            artifact.loaded_at = past;
            artifact.shadow_decision_count = SHADOW_MIN_DECISIONS;
        }
        for _ in 0..(SHADOW_MIN_EVALUATED_OUTCOMES - 20) {
            if !registry.record_shadow_outcome(&ModelKind::AdaptiveFallback, true, true) {
                return Err("shadow outcome was unexpectedly rejected".to_string());
            }
        }
        for _ in 0..20 {
            if !registry.record_shadow_outcome(&ModelKind::AdaptiveFallback, true, false) {
                return Err("shadow outcome was unexpectedly rejected".to_string());
            }
        }
        Ok(())
    }

    #[test]
    fn promotion_requires_paired_quality_evidence() -> Result<(), String> {
        let registry = ModelRegistry::new();
        registry.load_unsigned_for_testing(ModelKind::AdaptiveFallback, "v1");
        let Some(past) = Instant::now().checked_sub(SHADOW_MIN_DURATION) else {
            return Err("test clock cannot represent the required shadow interval".to_string());
        };
        {
            let mut models = registry.models.write();
            let Some(artifact) = models.get_mut(&ModelKind::AdaptiveFallback) else {
                return Err("adaptive fallback model is missing".to_string());
            };
            artifact.loaded_at = past;
            artifact.shadow_decision_count = SHADOW_MIN_DECISIONS;
        }

        // Duration and decision volume alone are insufficient.
        assert!(!registry.is_promotion_eligible(&ModelKind::AdaptiveFallback));
        make_adaptive_fallback_promotion_eligible(&registry)?;
        let readiness = registry.promotion_readiness(&ModelKind::AdaptiveFallback);
        assert!(readiness.quality_gate_satisfied);
        assert!(readiness.eligible());
        assert!(registry.promote(&ModelKind::AdaptiveFallback));
        assert!(!registry.is_fsm_only());
        Ok(())
    }

    #[test]
    fn non_routing_models_remain_advisory_after_a_good_shadow_evaluation() -> Result<(), String> {
        let registry = ModelRegistry::new();
        registry.load_unsigned_for_testing(ModelKind::CensorshipClassifier, "v1");
        let Some(past) = Instant::now().checked_sub(SHADOW_MIN_DURATION) else {
            return Err("test clock cannot represent the required shadow interval".to_string());
        };
        {
            let mut models = registry.models.write();
            let Some(artifact) = models.get_mut(&ModelKind::CensorshipClassifier) else {
                return Err("classifier model is missing".to_string());
            };
            artifact.loaded_at = past;
            artifact.shadow_decision_count = SHADOW_MIN_DECISIONS;
        }
        for _ in 0..SHADOW_MIN_EVALUATED_OUTCOMES {
            if !registry.record_shadow_outcome(&ModelKind::CensorshipClassifier, true, false) {
                return Err("shadow outcome was unexpectedly rejected".to_string());
            }
        }

        let readiness = registry.promotion_readiness(&ModelKind::CensorshipClassifier);
        assert!(readiness.quality_gate_satisfied);
        assert!(!readiness.controls_routing);
        assert!(!registry.promote(&ModelKind::CensorshipClassifier));
        assert!(registry.is_fsm_only());
        Ok(())
    }

    #[test]
    fn rollback_reverts_to_fsm() -> Result<(), ModelRegistryError> {
        let registry = ModelRegistry::new();
        registry.load_unsigned_for_testing(ModelKind::AdaptiveFallback, "v1");
        // Manually set to promoted for the test.
        {
            let mut models = registry.models.write();
            if let Some(a) = models.get_mut(&ModelKind::AdaptiveFallback) {
                a.mode = ModelMode::Promoted;
                registry.fsm_only.store(false, Ordering::Relaxed);
            }
        }
        assert!(!registry.is_fsm_only());
        let elapsed = registry.rollback(&ModelKind::AdaptiveFallback)?;
        assert!(elapsed < ROLLBACK_BUDGET);
        assert_eq!(
            registry.model_mode(&ModelKind::AdaptiveFallback),
            Some(ModelMode::RolledBack)
        );
        assert!(registry.is_fsm_only());
        assert_eq!(registry.total_rollbacks(), 1);
        Ok(())
    }

    #[test]
    fn rollback_rejects_an_unknown_model() {
        let registry = ModelRegistry::new();
        assert_eq!(
            registry.rollback(&ModelKind::AdaptiveFallback),
            Err(ModelRegistryError::NotLoaded)
        );
    }

    #[test]
    fn fsm_only_when_no_models_loaded() {
        let registry = ModelRegistry::new();
        assert!(registry.is_fsm_only());
    }

    #[test]
    fn status_reports_all_loaded_models() {
        let registry = ModelRegistry::new();
        registry.load_unsigned_for_testing(ModelKind::CensorshipClassifier, "v1");
        registry.load_unsigned_for_testing(ModelKind::ProtocolFitness, "v2");
        let status = registry.status();
        assert_eq!(status.len(), 2);
    }

    #[test]
    fn invalid_signature_is_rejected() {
        use ed25519_dalek::{Signer, SigningKey};
        use rand::rngs::OsRng;

        let registry = ModelRegistry::new();

        // Generate two different key pairs.
        let sk1 = SigningKey::generate(&mut OsRng);
        let sk2 = SigningKey::generate(&mut OsRng);

        // Trust only sk1's public key.
        registry.add_trusted_key(sk1.verifying_key().to_bytes());

        let data = b"onnx-model-bytes-v1";
        // Sign with sk2 (NOT trusted).
        let sig: ed25519_dalek::Signature = sk2.sign(data);
        let sig_bytes: [u8; 64] = sig.to_bytes();

        let result =
            registry.load_artifact(ModelKind::CensorshipClassifier, "v1", data, &sig_bytes);
        assert_eq!(result, Err(ModelRegistryError::InvalidSignature));
    }

    #[test]
    fn valid_signature_is_accepted() {
        use ed25519_dalek::{Signer, SigningKey};
        use rand::rngs::OsRng;

        let registry = ModelRegistry::new();
        let sk = SigningKey::generate(&mut OsRng);
        registry.add_trusted_key(sk.verifying_key().to_bytes());

        let data = b"onnx-model-bytes-v2";
        let sig: ed25519_dalek::Signature = sk.sign(data);
        let sig_bytes: [u8; 64] = sig.to_bytes();

        let result = registry.load_artifact(ModelKind::ProtocolFitness, "v2", data, &sig_bytes);
        assert!(result.is_ok());
        assert!(registry.is_loaded(&ModelKind::ProtocolFitness));
    }
}
