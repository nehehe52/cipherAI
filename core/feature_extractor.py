"""
Flow Feature Extraction Engine for Encrypted Network Traffic Analysis.
Computes 26 statistical, behavioral, and cryptographic features from packet sequences
and TLS flow metadata.
"""

import math
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional

FEATURE_NAMES = [
    "flow_duration",
    "total_packets",
    "fwd_packets",
    "bwd_packets",
    "total_bytes",
    "fwd_bytes",
    "bwd_bytes",
    "bytes_per_sec",
    "packets_per_sec",
    "pcr",
    "pkt_len_mean",
    "pkt_len_std",
    "pkt_len_min",
    "pkt_len_max",
    "fwd_pkt_len_mean",
    "bwd_pkt_len_mean",
    "bimodal_ratio",
    "iat_mean_ms",
    "iat_std_ms",
    "iat_min_ms",
    "iat_max_ms",
    "iat_jitter_coeff",
    "beaconing_score",
    "pkt_size_entropy",
    "sni_entropy",
    "sni_length",
    "ja3_threat_flag",
    "is_suspicious_port"
]


def calculate_entropy_of_distribution(values: List[int]) -> float:
    """Calculates Shannon entropy across integer values (e.g. packet lengths)."""
    if not values:
        return 0.0
    n = len(values)
    counts = {}
    for v in values:
        counts[v] = counts.get(v, 0) + 1
    
    entropy = 0.0
    for c in counts.values():
        p = c / n
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_flow_features(flow_dict: Dict[str, Any]) -> Dict[str, float]:
    """
    Extracts numerical feature vector from a single flow dictionary.
    flow_dict should contain:
    - packet_lengths: List[int]
    - packet_directions: List[int] (1 for forward, -1 for backward)
    - packet_timestamps: List[float] (epoch or relative seconds)
    - sni: Optional[str]
    - sni_entropy: Optional[float]
    - dst_port: int
    - ja3_threat: bool or int
    """
    lengths = flow_dict.get("packet_lengths", [])
    directions = flow_dict.get("packet_directions", [])
    timestamps = flow_dict.get("packet_timestamps", [])
    dst_port = flow_dict.get("dst_port", 443)
    sni = flow_dict.get("sni", "") or ""
    sni_entropy = flow_dict.get("sni_entropy", 0.0)
    ja3_threat_flag = 1.0 if flow_dict.get("ja3_threat", False) else 0.0

    total_packets = len(lengths)
    if total_packets == 0:
        return {feat: 0.0 for feat in FEATURE_NAMES}

    # Split directions (1 = client->server / fwd, -1 = server->client / bwd)
    fwd_lengths = [l for l, d in zip(lengths, directions) if d >= 0]
    bwd_lengths = [l for l, d in zip(lengths, directions) if d < 0]

    fwd_packets = len(fwd_lengths)
    bwd_packets = len(bwd_lengths)

    fwd_bytes = sum(fwd_lengths)
    bwd_bytes = sum(bwd_lengths)
    total_bytes = fwd_bytes + bwd_bytes

    # Duration & Rate
    if len(timestamps) > 1:
        duration = max(timestamps[-1] - timestamps[0], 0.001)
    else:
        duration = flow_dict.get("duration", 0.05)
    duration = max(float(duration), 0.001)

    bytes_per_sec = total_bytes / duration
    packets_per_sec = total_packets / duration

    # Producer-Consumer Ratio (PCR) in [-1.0, 1.0]
    # PCR = (fwd - bwd) / (fwd + bwd)
    if total_bytes > 0:
        pcr = (fwd_bytes - bwd_bytes) / total_bytes
    else:
        pcr = 0.0

    # Packet Length Statistics
    np_lengths = np.array(lengths, dtype=float)
    pkt_len_mean = float(np.mean(np_lengths))
    pkt_len_std = float(np.std(np_lengths)) if total_packets > 1 else 0.0
    pkt_len_min = float(np.min(np_lengths))
    pkt_len_max = float(np.max(np_lengths))

    fwd_pkt_len_mean = float(np.mean(fwd_lengths)) if fwd_packets > 0 else 0.0
    bwd_pkt_len_mean = float(np.mean(bwd_lengths)) if bwd_packets > 0 else 0.0

    # Bimodal ratio: ACK-like (<= 80 bytes) and MTU-like (>= 1300 bytes)
    bimodal_count = sum(1 for l in lengths if l <= 80 or l >= 1300)
    bimodal_ratio = bimodal_count / total_packets

    # Inter-Arrival Times (IAT)
    if len(timestamps) > 1:
        iats_sec = np.diff(timestamps)
        iats_ms = np.maximum(iats_sec * 1000.0, 0.0)
        iat_mean_ms = float(np.mean(iats_ms))
        iat_std_ms = float(np.std(iats_ms)) if len(iats_ms) > 1 else 0.0
        iat_min_ms = float(np.min(iats_ms))
        iat_max_ms = float(np.max(iats_ms))

        # Check forward cycle intervals (crucial for C2 pulse periodicity detection)
        fwd_timestamps = [t for t, d in zip(timestamps, directions) if d >= 0]
        if len(fwd_timestamps) >= 3:
            fwd_iats_sec = np.diff(fwd_timestamps)
            fwd_iats_ms = np.maximum(fwd_iats_sec * 1000.0, 0.0)
            fwd_iat_mean = float(np.mean(fwd_iats_ms))
            fwd_iat_std = float(np.std(fwd_iats_ms)) if len(fwd_iats_ms) > 1 else 0.0
            fwd_jitter = fwd_iat_std / max(fwd_iat_mean, 1e-6)
        else:
            fwd_jitter = 1.0
            fwd_iat_mean = iat_mean_ms

        # Overall Jitter coefficient: std / (mean + 1e-6)
        if iat_mean_ms > 0:
            iat_jitter_coeff = min(iat_std_ms / iat_mean_ms, fwd_jitter)
        else:
            iat_jitter_coeff = 0.0
    else:
        iat_mean_ms = flow_dict.get("iat_mean_ms", 100.0)
        iat_std_ms = flow_dict.get("iat_std_ms", 20.0)
        iat_min_ms = 0.0
        iat_max_ms = 200.0
        iat_jitter_coeff = iat_std_ms / max(iat_mean_ms, 1e-6)
        fwd_iat_mean = iat_mean_ms

    # Beaconing periodicity score:
    # Highly periodic connections (C2 beacons) have very low jitter (< 0.20) and consistent pacing.
    if total_packets >= 4 and (fwd_iat_mean > 500.0 or iat_mean_ms > 500.0):
        if iat_jitter_coeff < 0.15:
            beaconing_score = 0.95
        elif iat_jitter_coeff < 0.35:
            beaconing_score = 0.75
        elif iat_jitter_coeff < 0.60:
            beaconing_score = 0.40
        else:
            beaconing_score = 0.10
    else:
        beaconing_score = 0.05

    # Packet size distribution entropy
    pkt_size_entropy = calculate_entropy_of_distribution(lengths)

    # SNI features
    sni_len = float(len(sni))

    # Port check
    is_suspicious_port = 1.0 if dst_port not in (443, 8443, 853) else 0.0

    return {
        "flow_duration": round(duration, 4),
        "total_packets": float(total_packets),
        "fwd_packets": float(fwd_packets),
        "bwd_packets": float(bwd_packets),
        "total_bytes": float(total_bytes),
        "fwd_bytes": float(fwd_bytes),
        "bwd_bytes": float(bwd_bytes),
        "bytes_per_sec": round(bytes_per_sec, 2),
        "packets_per_sec": round(packets_per_sec, 2),
        "pcr": round(pcr, 4),
        "pkt_len_mean": round(pkt_len_mean, 2),
        "pkt_len_std": round(pkt_len_std, 2),
        "pkt_len_min": round(pkt_len_min, 2),
        "pkt_len_max": round(pkt_len_max, 2),
        "fwd_pkt_len_mean": round(fwd_pkt_len_mean, 2),
        "bwd_pkt_len_mean": round(bwd_pkt_len_mean, 2),
        "bimodal_ratio": round(bimodal_ratio, 4),
        "iat_mean_ms": round(iat_mean_ms, 2),
        "iat_std_ms": round(iat_std_ms, 2),
        "iat_min_ms": round(iat_min_ms, 2),
        "iat_max_ms": round(iat_max_ms, 2),
        "iat_jitter_coeff": round(iat_jitter_coeff, 4),
        "beaconing_score": round(beaconing_score, 4),
        "pkt_size_entropy": round(pkt_size_entropy, 4),
        "sni_entropy": round(float(sni_entropy), 4),
        "sni_length": sni_len,
        "ja3_threat_flag": ja3_threat_flag,
        "is_suspicious_port": is_suspicious_port
    }


def flows_to_dataframe(flows: List[Dict[str, Any]]) -> pd.DataFrame:
    """Converts a list of flow dictionaries into a structured DataFrame."""
    feature_rows = [extract_flow_features(f) for f in flows]
    return pd.DataFrame(feature_rows, columns=FEATURE_NAMES)
