"""Protocol Fitness Predictor (Subsystem A, Stage 3).

Multi-output regression → ONNX. Predicts:
  - Expected success rate per protocol per ISP
  - Expected RTT per protocol per ISP
  - Time-to-block estimate per protocol per ISP

Input: feature vector + protocol ID.
Output: [success_rate, rtt_ms, time_to_block_hours].

Used by decider::LocalDecider for transport ranking.
"""

import json
import numpy as np
from dataclasses import dataclass
from typing import List


@dataclass
class FitnessPredictorConfig:
    """Configuration for the fitness predictor."""
    hidden_size: int = 32
    n_outputs: int = 3  # success_rate, rtt_ms, time_to_block


class SimpleMLP:
    """A minimal 2-layer MLP for regression (no PyTorch dependency).

    In production, this would be a proper PyTorch/Lightning model exported
    to ONNX via torch.onnx.export.
    """

    def __init__(self, input_size: int, hidden_size: int, output_size: int):
        rng = np.random.RandomState(42)
        scale1 = np.sqrt(2.0 / input_size)
        scale2 = np.sqrt(2.0 / hidden_size)
        self.W1 = rng.randn(input_size, hidden_size).astype(np.float32) * scale1
        self.b1 = np.zeros(hidden_size, dtype=np.float32)
        self.W2 = rng.randn(hidden_size, output_size).astype(np.float32) * scale2
        self.b2 = np.zeros(output_size, dtype=np.float32)

    def forward(self, x: np.ndarray) -> np.ndarray:
        """Forward pass: x -> ReLU -> linear."""
        h = np.maximum(0, x @ self.W1 + self.b1)  # ReLU
        return h @ self.W2 + self.b2

    def fit(self, X: np.ndarray, Y: np.ndarray, epochs: int = 50, lr: float = 0.01):
        """Simple SGD training."""
        for _ in range(epochs):
            h = np.maximum(0, X @ self.W1 + self.b1)
            out = h @ self.W2 + self.b2
            # MSE loss gradient.
            d_out = 2 * (out - Y) / len(X)
            d_W2 = h.T @ d_out
            d_b2 = d_out.sum(axis=0)
            d_h = d_out @ self.W2.T
            d_h[h <= 0] = 0  # ReLU gradient
            d_W1 = X.T @ d_h
            d_b1 = d_h.sum(axis=0)
            self.W1 -= lr * d_W1
            self.b1 -= lr * d_b1
            self.W2 -= lr * d_W2
            self.b2 -= lr * d_b2


class ProtocolFitnessPredictor:
    """Predicts protocol fitness metrics per ISP."""

    def __init__(self, config: FitnessPredictorConfig = None):
        self.config = config or FitnessPredictorConfig()
        self.model: SimpleMLP = None

    def fit(self, X: np.ndarray, Y: np.ndarray):
        """Train the predictor.

        X: feature matrix (n_samples, input_size).
        Y: target matrix (n_samples, 3) — [success_rate, rtt_ms, time_to_block].
        """
        self.model = SimpleMLP(X.shape[1], self.config.hidden_size, self.config.n_outputs)
        self.model.fit(X, Y)

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict fitness metrics for a batch.

        Returns: (n_samples, 3) — [success_rate, rtt_ms, time_to_block].
        """
        if self.model is None:
            raise RuntimeError("model not trained")
        out = self.model.forward(X)
        # Clamp success_rate to [0, 1].
        out[:, 0] = np.clip(out[:, 0], 0, 1)
        # Clamp RTT to positive.
        out[:, 1] = np.maximum(out[:, 1], 0)
        # Clamp time-to-block to positive.
        out[:, 2] = np.maximum(out[:, 2], 0)
        return out

    def export_onnx_stub(self) -> bytes:
        """Export a stub ONNX artifact."""
        model_info = {
            "type": "protocol_fitness_predictor",
            "version": "0.1.0",
            "outputs": ["success_rate", "rtt_ms", "time_to_block_hours"],
            "input_shape": [None, 18],
        }
        return json.dumps(model_info).encode("utf-8")


def generate_fitness_targets(features: np.ndarray) -> np.ndarray:
    """Generate synthetic fitness targets for testing.

    In production, targets come from the ClickHouse feature store
    (actual observed success rates, RTTs, and time-to-block).
    """
    n = len(features)
    Y = np.zeros((n, 3), dtype=np.float32)
    for i, row in enumerate(features):
        # success_rate is directly from the feature.
        Y[i, 0] = row[1]
        # RTT is from the feature.
        Y[i, 1] = row[5]
        # time-to-block: higher success → longer time to block.
        Y[i, 2] = row[1] * 24 + (1 - row[2]) * 12  # hours
    return Y
