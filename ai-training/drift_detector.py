"""Fingerprint Drift Detector (Subsystem A, Stage 4).

Autoencoder anomaly score → ONNX. Detects when JA4/uTLS fingerprint
distributions drift from the expected domestic-traffic profile, triggering
proactive fingerprint rotation before a pattern is fully burned.

Input: JA4 feature vector (extension order encoding, cipher suite histogram).
Output: anomaly score (reconstruction error).
"""

import json
import numpy as np
from dataclasses import dataclass


@dataclass
class DriftDetectorConfig:
    """Configuration for the drift detector."""
    input_size: int = 32  # JA4 feature vector size
    hidden_size: int = 16
    latent_size: int = 8
    anomaly_threshold: float = 0.5


class SimpleAutoencoder:
    """A minimal autoencoder for anomaly detection.

    Encoder: input -> hidden -> latent
    Decoder: latent -> hidden -> reconstruction
    Anomaly score = MSE(input, reconstruction).
    """

    def __init__(self, input_size: int, hidden_size: int, latent_size: int):
        rng = np.random.RandomState(42)
        # Encoder.
        s1 = np.sqrt(2.0 / input_size)
        s2 = np.sqrt(2.0 / hidden_size)
        self.W_enc1 = rng.randn(input_size, hidden_size).astype(np.float32) * s1
        self.b_enc1 = np.zeros(hidden_size, dtype=np.float32)
        self.W_enc2 = rng.randn(hidden_size, latent_size).astype(np.float32) * s2
        self.b_enc2 = np.zeros(latent_size, dtype=np.float32)
        # Decoder.
        s3 = np.sqrt(2.0 / latent_size)
        s4 = np.sqrt(2.0 / hidden_size)
        self.W_dec1 = rng.randn(latent_size, hidden_size).astype(np.float32) * s3
        self.b_dec1 = np.zeros(hidden_size, dtype=np.float32)
        self.W_dec2 = rng.randn(hidden_size, input_size).astype(np.float32) * s4
        self.b_dec2 = np.zeros(input_size, dtype=np.float32)

    def encode(self, x: np.ndarray) -> np.ndarray:
        h = np.tanh(x @ self.W_enc1 + self.b_enc1)
        return h @ self.W_enc2 + self.b_enc2

    def decode(self, z: np.ndarray) -> np.ndarray:
        h = np.tanh(z @ self.W_dec1 + self.b_dec1)
        return h @ self.W_dec2 + self.b_dec2

    def reconstruct(self, x: np.ndarray) -> np.ndarray:
        z = self.encode(x)
        return self.decode(z)

    def anomaly_score(self, x: np.ndarray) -> float:
        """MSE reconstruction error — higher = more anomalous."""
        recon = self.reconstruct(x)
        return float(np.mean((x - recon) ** 2))

    def fit(self, X: np.ndarray, epochs: int = 100, lr: float = 0.01):
        """Train the autoencoder to minimize reconstruction error."""
        for _ in range(epochs):
            # Forward.
            h1 = np.tanh(X @ self.W_enc1 + self.b_enc1)
            z = h1 @ self.W_enc2 + self.b_enc2
            h2 = np.tanh(z @ self.W_dec1 + self.b_dec1)
            recon = h2 @ self.W_dec2 + self.b_dec2
            # MSE gradient.
            d_recon = 2 * (recon - X) / len(X)
            d_W_dec2 = h2.T @ d_recon
            d_b_dec2 = d_recon.sum(axis=0)
            d_h2 = d_recon @ self.W_dec2.T
            d_h2 *= (1 - h2 ** 2)  # tanh gradient
            d_W_dec1 = z.T @ d_h2
            d_b_dec1 = d_h2.sum(axis=0)
            d_z = d_h2 @ self.W_dec1.T
            d_W_enc2 = h1.T @ d_z
            d_b_enc2 = d_z.sum(axis=0)
            d_h1 = d_z @ self.W_enc2.T
            d_h1 *= (1 - h1 ** 2)
            d_W_enc1 = X.T @ d_h1
            d_b_enc1 = d_h1.sum(axis=0)
            # Update.
            self.W_dec2 -= lr * d_W_dec2
            self.b_dec2 -= lr * d_b_dec2
            self.W_dec1 -= lr * d_W_dec1
            self.b_dec1 -= lr * d_b_dec1
            self.W_enc2 -= lr * d_W_enc2
            self.b_enc2 -= lr * d_b_enc2
            self.W_enc1 -= lr * d_W_enc1
            self.b_enc1 -= lr * d_b_enc1


class FingerprintDriftDetector:
    """Detects JA4/uTLS fingerprint drift via autoencoder anomaly score."""

    def __init__(self, config: DriftDetectorConfig = None):
        self.config = config or DriftDetectorConfig()
        self.autoencoder = SimpleAutoencoder(
            self.config.input_size,
            self.config.hidden_size,
            self.config.latent_size,
        )

    def train(self, normal_samples: np.ndarray):
        """Train on normal (non-drifted) fingerprint samples."""
        self.autoencoder.fit(normal_samples)

    def anomaly_score(self, sample: np.ndarray) -> float:
        """Compute the anomaly score for a single sample."""
        return self.autoencoder.anomaly_score(sample)

    def is_drifting(self, sample: np.ndarray) -> bool:
        """Check if a sample indicates fingerprint drift."""
        return self.anomaly_score(sample) > self.config.anomaly_threshold

    def export_onnx_stub(self) -> bytes:
        """Export a stub ONNX artifact."""
        model_info = {
            "type": "fingerprint_drift_detector",
            "version": "0.1.0",
            "input_size": self.config.input_size,
            "anomaly_threshold": self.config.anomaly_threshold,
        }
        return json.dumps(model_info).encode("utf-8")


def generate_ja4_samples(n: int = 1000, seed: int = 42) -> np.ndarray:
    """Generate synthetic JA4 feature vectors for testing."""
    rng = np.random.RandomState(seed)
    return rng.randn(n, 32).astype(np.float32) * 0.1
