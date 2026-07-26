"""Feature extraction from the ClickHouse feature store.

Reads anonymized per-(ISP, protocol) windowed features (success/RST/truncation/
DNS-anomaly rates, median RTT) and produces training-ready tensors.

This module is offline-only and never touches the production path.
"""

import hashlib
from dataclasses import dataclass
from typing import List, Optional

import numpy as np


@dataclass
class FeatureWindow:
    """One windowed feature point from the ClickHouse feature store."""
    isp: str
    protocol: str
    sample_count: int
    success_rate: float
    rst_rate: float
    trunc_rate: float
    dns_anomaly_rate: float
    median_rtt_ms: float
    timestamp_unix: int

    def to_vector(self) -> np.ndarray:
        """Convert to a numeric feature vector for model input."""
        return np.array([
            self.sample_count,
            self.success_rate,
            self.rst_rate,
            self.trunc_rate,
            self.dns_anomaly_rate,
            self.median_rtt_ms,
        ], dtype=np.float32)


# ISP encoding — one-hot over known Iranian carriers.
KNOWN_ISPS = ["MCI", "Irancell", "Rightel", "Shatel", "TCI", "Other"]


def isp_to_onehot(isp: str) -> np.ndarray:
    """Encode an ISP name as a one-hot vector."""
    vec = np.zeros(len(KNOWN_ISPS), dtype=np.float32)
    if isp in KNOWN_ISPS:
        vec[KNOWN_ISPS.index(isp)] = 1.0
    else:
        vec[-1] = 1.0  # "Other"
    return vec


# Protocol encoding — one-hot over known protocols.
KNOWN_PROTOCOLS = [
    "reality-vision", "hysteria2", "tuic-v5",
    "shadowtls-v3-ss2022", "amneziawg", "persis-cover-front",
]


def protocol_to_onehot(protocol: str) -> np.ndarray:
    """Encode a protocol name as a one-hot vector."""
    vec = np.zeros(len(KNOWN_PROTOCOLS), dtype=np.float32)
    if protocol in KNOWN_PROTOCOLS:
        vec[KNOWN_PROTOCOLS.index(protocol)] = 1.0
    return vec


def extract_features(windows: List[FeatureWindow]) -> np.ndarray:
    """Extract a feature matrix from a list of windows.

    Each row is: [numeric_features | isp_onehot | protocol_onehot].
    """
    rows = []
    for w in windows:
        numeric = w.to_vector()
        isp_oh = isp_to_onehot(w.isp)
        proto_oh = protocol_to_onehot(w.protocol)
        row = np.concatenate([numeric, isp_oh, proto_oh])
        rows.append(row)
    if not rows:
        return np.zeros((0, 6 + len(KNOWN_ISPS) + len(KNOWN_PROTOCOLS)), dtype=np.float32)
    return np.stack(rows)


def generate_synthetic_data(n: int = 10000, seed: int = 42) -> List[FeatureWindow]:
    """Generate synthetic feature windows for testing the pipeline.

    This is used when real telemetry data is not yet available (Phase 0).
    In production, this function is replaced by the ClickHouse query.
    """
    rng = np.random.RandomState(seed)
    windows = []
    for i in range(n):
        isp = rng.choice(KNOWN_ISPS)
        protocol = rng.choice(KNOWN_PROTOCOLS)
        # Simulate varying censorship intensity.
        censorship_level = rng.uniform(0, 1)
        success_rate = max(0, 1.0 - censorship_level * rng.uniform(0.3, 1.0))
        rst_rate = censorship_level * rng.uniform(0, 0.8)
        trunc_rate = censorship_level * rng.uniform(0, 0.5)
        dns_anomaly = rng.choice([0.0, rng.uniform(0, 0.9)], p=[0.7, 0.3])
        rtt = rng.uniform(20, 500) * (1 + censorship_level * 0.5)
        windows.append(FeatureWindow(
            isp=isp,
            protocol=protocol,
            sample_count=int(rng.uniform(10, 200)),
            success_rate=success_rate,
            rst_rate=rst_rate,
            trunc_rate=trunc_rate,
            dns_anomaly_rate=dns_anomaly,
            median_rtt_ms=rtt,
            timestamp_unix=1700000000 + i * 300,
        ))
    return windows
