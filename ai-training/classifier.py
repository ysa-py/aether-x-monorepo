"""Censorship Event Classifier (Subsystem A, Stage 2).

Gradient-boosted trees → ONNX. Classifies per-window block-type:
  - RST injection
  - TLS truncation
  - DNS hijack
  - Throttle
  - None (no censorship detected)

Input: feature vector from features.extract_features().
Output: per-class probability distribution.

This is a booster over the deterministic FailureSignature — never a replacement.
"""

import numpy as np
from dataclasses import dataclass
from typing import List, Tuple

# Block type labels.
BLOCK_TYPES = ["none", "rst_injection", "tls_truncation", "dns_hijack", "throttle"]


@dataclass
class ClassifierConfig:
    """Configuration for the censorship classifier."""
    n_estimators: int = 100
    max_depth: int = 6
    learning_rate: float = 0.1
    n_classes: int = len(BLOCK_TYPES)


def label_from_window(success_rate: float, rst_rate: float,
                      trunc_rate: float, dns_rate: float) -> int:
    """Assign a block-type label from windowed rates (for training)."""
    if dns_rate > 0.5:
        return BLOCK_TYPES.index("dns_hijack")
    if rst_rate > 0.3:
        return BLOCK_TYPES.index("rst_injection")
    if trunc_rate > 0.3:
        return BLOCK_TYPES.index("tls_truncation")
    if success_rate < 0.5:
        return BLOCK_TYPES.index("throttle")
    return BLOCK_TYPES.index("none")


def generate_training_labels(features: np.ndarray) -> np.ndarray:
    """Generate training labels from feature matrix.

    Features layout: [sample_count, success_rate, rst_rate, trunc_rate,
                      dns_anomaly_rate, median_rtt, isp_onehot..., proto_onehot...]
    """
    labels = []
    for row in features:
        success_rate = row[1]
        rst_rate = row[2]
        trunc_rate = row[3]
        dns_rate = row[4]
        labels.append(label_from_window(success_rate, rst_rate, trunc_rate, dns_rate))
    return np.array(labels, dtype=np.int64)


class SimpleDecisionTree:
    """A minimal decision tree for the classifier (no sklearn dependency).

    In production, this would be replaced by a proper GBDT library (LightGBM,
    XGBoost) and exported to ONNX via sklearn-onnx or onnxmltools.
    """

    def __init__(self, max_depth: int = 6):
        self.max_depth = max_depth
        self.tree = None

    def fit(self, X: np.ndarray, y: np.ndarray):
        """Build the tree (simplified greedy split)."""
        self.tree = self._build(X, y, depth=0)

    def _build(self, X: np.ndarray, y: np.ndarray, depth: int):
        if depth >= self.max_depth or len(np.unique(y)) == 1 or len(X) < 4:
            # Leaf: return class distribution.
            counts = np.bincount(y, minlength=len(BLOCK_TYPES))
            probs = counts / max(counts.sum(), 1)
            return {"leaf": True, "probs": probs}

        best_feature, best_threshold, best_score = 0, 0.0, float("inf")
        for f in range(X.shape[1]):
            thresholds = np.percentile(X[:, f], [25, 50, 75])
            for t in thresholds:
                left_mask = X[:, f] <= t
                right_mask = ~left_mask
                if left_mask.sum() < 2 or right_mask.sum() < 2:
                    continue
                score = self._gini(y[left_mask]) * left_mask.sum() + \
                        self._gini(y[right_mask]) * right_mask.sum()
                if score < best_score:
                    best_score = score
                    best_feature = f
                    best_threshold = t

        left_mask = X[:, best_feature] <= best_threshold
        right_mask = ~left_mask
        if left_mask.sum() == 0 or right_mask.sum() == 0:
            counts = np.bincount(y, minlength=len(BLOCK_TYPES))
            probs = counts / max(counts.sum(), 1)
            return {"leaf": True, "probs": probs}

        return {
            "leaf": False,
            "feature": best_feature,
            "threshold": best_threshold,
            "left": self._build(X[left_mask], y[left_mask], depth + 1),
            "right": self._build(X[right_mask], y[right_mask], depth + 1),
        }

    def _gini(self, y: np.ndarray) -> float:
        if len(y) == 0:
            return 0.0
        counts = np.bincount(y, minlength=len(BLOCK_TYPES))
        probs = counts / len(y)
        return 1.0 - np.sum(probs ** 2)

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        """Predict class probabilities for a single sample."""
        node = self.tree
        while not node["leaf"]:
            if x[node["feature"]] <= node["threshold"]:
                node = node["left"]
            else:
                node = node["right"]
        return node["probs"]


class CensorshipClassifier:
    """The censorship event classifier.

    Uses a simple decision tree ensemble. In production, this would be
    a proper GBDT exported to ONNX.
    """

    def __init__(self, config: ClassifierConfig = None):
        self.config = config or ClassifierConfig()
        self.trees: List[SimpleDecisionTree] = []

    def fit(self, X: np.ndarray, y: np.ndarray):
        """Train the classifier."""
        self.trees = []
        for _ in range(self.config.n_estimators):
            # Bootstrap sample.
            idx = np.random.choice(len(X), size=len(X), replace=True)
            tree = SimpleDecisionTree(max_depth=self.config.max_depth)
            tree.fit(X[idx], y[idx])
            self.trees.append(tree)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Predict class probabilities for a batch of samples."""
        probs = np.zeros((len(X), len(BLOCK_TYPES)))
        for tree in self.trees:
            for i, x in enumerate(X):
                probs[i] += tree.predict_proba(x)
        probs /= max(len(self.trees), 1)
        return probs

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict class labels."""
        return np.argmax(self.predict_proba(X), axis=1)

    def export_onnx_stub(self) -> bytes:
        """Export a stub ONNX artifact (placeholder for real export).

        In production, this would use onnxmltools or skl2onnx to export
        the trained model to ONNX format.
        """
        import json
        model_info = {
            "type": "censorship_classifier",
            "version": "0.1.0",
            "n_estimators": len(self.trees),
            "classes": BLOCK_TYPES,
            "input_shape": [None, 18],  # 6 numeric + 6 ISP + 6 protocol
        }
        return json.dumps(model_info).encode("utf-8")
