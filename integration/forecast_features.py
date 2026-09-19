"""
Step 3a — Forecast Feature Extraction

Extends NTAV's anomaly detection to emit per-time-window feature vectors
that the forecasting model (Step 3b) consumes.

Feature schema per window:
  host, window_start, window_end,
  port_diversity, connection_rate, syn_rst_ratio,
  unique_ports, payload_size_mean, payload_size_max,
  anomaly_types_in_window, src_ip, dst_ip
"""

import json
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List

logger = logging.getLogger(__name__)


def _parse_ts(ts_str: str) -> datetime:
    """Parse ISO timestamp string."""
    try:
        return datetime.fromisoformat(ts_str)
    except Exception:
        return datetime.now()


class ForecastFeatureExtractor:
    """
    Reads packets.jsonl and emits sliding-window feature vectors
    suitable for the escalation forecaster.
    """

    def __init__(
        self,
        packets_file: str = "data/packets.jsonl",
        window_size: int = 30,
        window_step: int = 10,
    ):
        self.packets_file = Path(packets_file)
        self.window_size = window_size
        self.window_step = window_step
        self.packets: List[Dict] = []

        if self.packets_file.exists():
            self._load_packets()

    def _load_packets(self):
        """Load packets from JSONL."""
        try:
            with open(self.packets_file) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        self.packets.append(json.loads(line))
            logger.info(f"Loaded {len(self.packets)} packets for feature extraction")
        except Exception as e:
            logger.error(f"Error loading packets: {e}")

    def extract_forecast_features(self) -> List[Dict]:
        """
        Compute sliding-window features across all source IPs.

        Returns a list of feature vectors, one per (src_ip, window) pair.
        """
        if not self.packets:
            logger.warning("No packets loaded — returning empty feature set")
            return []

        # Group packets by (src_ip, dst_ip)
        pairs = defaultdict(list)
        for pkt in self.packets:
            key = (pkt.get("src_ip", ""), pkt.get("dst_ip", ""))
            pairs[key].append(pkt)

        features = []

        for (src_ip, dst_ip), pkts in pairs.items():
            # Sort by timestamp
            pkts.sort(key=lambda p: p.get("timestamp", ""))

            if not pkts:
                continue

            first_ts = _parse_ts(pkts[0]["timestamp"])
            last_ts = _parse_ts(pkts[-1]["timestamp"])

            # Slide windows
            win_start = first_ts
            while win_start <= last_ts:
                win_end = win_start + timedelta(seconds=self.window_size)
                window_pkts = [p for p in pkts if win_start <= _parse_ts(p["timestamp"]) < win_end]

                if window_pkts:
                    feat = self._compute_window_features(
                        window_pkts, src_ip, dst_ip, win_start, win_end
                    )
                    features.append(feat)

                win_start += timedelta(seconds=self.window_step)

        logger.info(
            f"Extracted {len(features)} feature vectors across {(len(pairs))} src-dst pairs"
        )
        return features

    def _compute_window_features(
        self,
        pkts: List[Dict],
        src_ip: str,
        dst_ip: str,
        win_start: datetime,
        win_end: datetime,
    ) -> Dict:
        """Compute features for a single window of packets."""
        total = len(pkts)
        window_duration = max((win_end - win_start).total_seconds(), 1.0)

        # Port diversity
        unique_ports = set()
        flags_count = {"S": 0, "R": 0, "A": 0, "other": 0}
        payload_sizes = []

        for pkt in pkts:
            dst_port = pkt.get("dst_port")
            if dst_port:
                unique_ports.add(dst_port)

            flags = pkt.get("flags", "")
            if isinstance(flags, str):
                if "S" in flags and "A" not in flags:
                    flags_count["S"] += 1
                elif "R" in flags:
                    flags_count["R"] += 1
                elif "A" in flags:
                    flags_count["A"] += 1
                else:
                    flags_count["other"] += 1
            else:
                flags_count["other"] += 1

            ps = pkt.get("payload_size", 0)
            if ps is not None:
                payload_sizes.append(ps)

        syn_total = flags_count["S"]
        rst_total = flags_count["R"]
        syn_rst_ratio = syn_total / max(rst_total, 1)
        connection_rate = total / window_duration

        payload_mean = sum(payload_sizes) / max(len(payload_sizes), 1)
        payload_max = max(payload_sizes) if payload_sizes else 0

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "window_start": win_start.isoformat(),
            "window_end": win_end.isoformat(),
            "window_duration_sec": window_duration,
            "total_packets": total,
            "port_diversity": len(unique_ports),
            "unique_ports": sorted(unique_ports),
            "connection_rate": round(connection_rate, 4),
            "syn_count": syn_total,
            "rst_count": rst_total,
            "syn_rst_ratio": round(syn_rst_ratio, 4),
            "payload_size_mean": round(payload_mean, 2),
            "payload_size_max": payload_max,
        }

    def save_features(self, output_file: str = "data/forecast_features.jsonl"):
        """Extract and save features to JSONL."""
        features = self.extract_forecast_features()
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            for feat in features:
                f.write(json.dumps(feat) + "\n")

        logger.info(f"Saved {len(features)} feature vectors to {output_path}")
        return features


def extract_and_label_features(
    features: List[Dict],
    anomalies_file: str = "data/anomalies.jsonl",
) -> List[Dict]:
    """
    Label feature vectors with escalation ground truth.

    A window is labeled as 'escalated' (1) if it overlaps in time
    with any detected anomaly from the anomaly detection step.
    Otherwise it's 'normal' (0).

    This gives us training data for Model B.
    """
    anomalies = []
    anom_path = Path(anomalies_file)
    if anom_path.exists():
        with open(anom_path) as f:
            for line in f:
                line = line.strip()
                if line:
                    anomalies.append(json.loads(line))

    # Build time ranges for anomalies
    anomaly_windows = []
    for anom in anomalies:
        ts = _parse_ts(anom.get("timestamp", ""))
        # Consider the anomaly window as ±5 seconds around detection
        anomaly_windows.append((ts - timedelta(seconds=5), ts + timedelta(seconds=5)))

    labeled = []
    for feat in features:
        win_start = _parse_ts(feat["window_start"])
        win_end = _parse_ts(feat["window_end"])

        # Check if this window overlaps with any anomaly
        escalated = 0
        for a_start, a_end in anomaly_windows:
            if win_start <= a_end and win_end >= a_start:
                escalated = 1
                break

        feat["escalation_label"] = escalated
        labeled.append(feat)

    escalated_count = sum(1 for f in labeled if f["escalation_label"] == 1)
    logger.info(
        f"Labeled {len(labeled)} windows: {escalated_count} escalated, {len(labeled) - escalated_count} normal"
    )
    return labeled


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Extract forecast features from packet data")
    parser.add_argument("--input", "-i", default="data/packets.jsonl", help="Input packets file")
    parser.add_argument(
        "--output", "-o", default="data/forecast_features.jsonl", help="Output features file"
    )
    parser.add_argument("--window-size", type=int, default=30, help="Window size in seconds")
    parser.add_argument("--window-step", type=int, default=10, help="Window step in seconds")

    args = parser.parse_args()

    extractor = ForecastFeatureExtractor(
        packets_file=args.input,
        window_size=args.window_size,
        window_step=args.window_step,
    )
    extractor.save_features(args.output)
