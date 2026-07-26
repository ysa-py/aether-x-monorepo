# Aether-X AI Training Pipeline
#
# This is the ONLY place Python may live. It is never deployed, never packaged
# into a production image, and never reachable from the data or control planes
# at runtime.
#
# Pipeline stages:
# 1. Feature extraction from ClickHouse feature store
# 2. Censorship Event Classifier (gradient-boosted trees → ONNX)
# 3. Protocol Fitness Predictor (multi-output regression → ONNX)
# 4. Fingerprint Drift Detector (autoencoder anomaly score → ONNX)
# 5. Adaptive Fallback Policy (PPO/DQN → ONNX)
# 6. ONNX export + Ed25519 signature (reuses antiforgery keys)
#
# All artifacts are signed before registry push. Unsigned artifacts are
# rejected at load time by the Rust ort loader.

__version__ = "0.1.0"
