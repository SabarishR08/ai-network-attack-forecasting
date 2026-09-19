"""
SIH26153 — Full Pipeline Orchestrator

Runs the complete pipeline end-to-end:
  1. Generate / load synthetic traffic (NTAV generate_test_data)
  2. Detect anomalies (NTAV AnomalyDetector)
  3. Extract forecast features (ForecastFeatureExtractor)
  4. Run Model A — point-in-time classifier (PS40)
  5. Run Model B — escalation forecaster (EscalationForecaster)  [optional]
  6. Kill chain enrichment + MITRE mapping                        [optional]
  7. Build attack graph JSON

All feature flags are controlled via environment variables (see config.py).
"""

import json
import sys
import time
from datetime import datetime, timezone

UTC = timezone.utc
from pathlib import Path
from typing import Dict, Optional

from integration.logging_config import get_logger, setup_logging

setup_logging()
logger = get_logger("pipeline")

# ── Bootstrap paths ────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parents[1]
NTAV_DIR = PROJECT_ROOT / "repos" / "Network-Threat-Anomaly-Visualizer"
PS40_DIR = PROJECT_ROOT / "repos" / "network-intrusion-detection"
KILLCHAIN_DIR = PROJECT_ROOT / "repos" / "cyber-killchain-reconstruction-engine"
DATA_DIR = PROJECT_ROOT / "data"

for p in [
    str(PROJECT_ROOT),
    str(NTAV_DIR),
    str(NTAV_DIR / "src"),
    str(PS40_DIR),
    str(PS40_DIR / "src"),
    str(KILLCHAIN_DIR),
]:
    if p not in sys.path:
        sys.path.insert(0, p)

from integration.config import (
    ANOMALIES_FILE,
    ENABLE_FORECASTING_MODEL,
    ENABLE_KILLCHAIN,
    FEATURES_FILE,
    GRAPH_JSON,
    KILLCHAIN_INCIDENTS_FILE,
    PACKETS_FILE,
)

# ── Step helpers ───────────────────────────────────────────


def step_generate_traffic(packets_file: Path) -> Dict:
    """Step 1 — Generate synthetic traffic using NTAV generator."""
    logger.info("Step 1: Generating synthetic traffic data")
    try:
        from generate_test_data import SyntheticDataGenerator

        gen = SyntheticDataGenerator(str(packets_file))
        gen.generate_dataset()
        count = sum(1 for _ in packets_file.open())
        return {"status": "ok", "packets": count, "mode": "synthetic"}
    except Exception as exc:
        logger.error(f"Traffic generation failed: {exc}")
        return {"status": "error", "error": str(exc)}


def step_live_capture(
    packets_file: Path,
    duration: int = 30,
    interface: Optional[str] = None,
    bpf_filter: Optional[str] = None,
) -> Dict:
    """Step 1 (live) — Capture real traffic using scapy."""
    logger.info(f"Step 1 (LIVE): Capturing real traffic for {duration}s")
    try:
        from integration.packet_capture import PacketCapturer, get_local_ip

        local_ip = get_local_ip()
        logger.info(f"Local IP: {local_ip}")

        capturer = PacketCapturer(
            interface=interface,
            output_file=str(packets_file),
            bpf_filter=bpf_filter,
        )
        capturer.start(timeout=duration)

        # Wait for capture to finish
        if capturer._capture:
            capturer._capture.join()
        capturer.stop()

        count = 0
        if packets_file.exists():
            with open(packets_file) as f:
                count = sum(1 for _ in f)

        return {
            "status": "ok",
            "packets": count,
            "mode": "live",
            "local_ip": local_ip,
            "duration_sec": duration,
            "interface": interface or "auto",
        }
    except PermissionError:
        import platform as _platform

        if _platform.system() == "Windows":
            msg = (
                "Live capture requires admin privileges on Windows. "
                "Right-click terminal -> Run as administrator, "
                "or run: python run.py --live (auto-elevates)"
            )
        else:
            msg = "Live capture requires root/admin privileges. Run with: sudo python run.py --live"
        logger.error(msg)
        return {"status": "error", "error": msg}
    except Exception as exc:
        logger.error(f"Live capture failed: {exc}")
        return {"status": "error", "error": str(exc)}


def step_anomaly_detection(packets_file: Path, anomalies_file: Path) -> Dict:
    """Step 2 — NTAV heuristic anomaly detection."""
    logger.info("Step 2: Running anomaly detection (NTAV)")
    try:
        from anomaly_detection import AnomalyDetector

        detector = AnomalyDetector(str(packets_file))
        anomalies = detector.detect_all_anomalies()
        detector.save_anomalies(str(anomalies_file))
        by_type: Dict[str, int] = {}
        for a in anomalies:
            t = a.get("anomaly_type", "Unknown")
            by_type[t] = by_type.get(t, 0) + 1
        return {"status": "ok", "total": len(anomalies), "by_type": by_type}
    except Exception as exc:
        logger.error(f"Anomaly detection failed: {exc}")
        return {"status": "error", "error": str(exc)}


def step_model_a(packets_file: Path) -> Dict:
    """
    Step 3 — Model A: PS40 point-in-time classifier.

    PS40's training pipeline requires the full NSL-KDD CSV dataset.
    For the demo we use the pre-trained model if it exists; if not, we
    report that it needs to be trained separately (see docs/DEMO_SCRIPT.md).
    """
    logger.info("Step 3: Model A — point-in-time classifier (PS40)")
    try:
        model_dir = PS40_DIR / "models"
        if not model_dir.exists() or not list(model_dir.glob("*.pkl")):
            logger.warning(
                "Model A: no pre-trained model found. "
                "Run 'python main.py' inside repos/network-intrusion-detection to train."
            )
            return {
                "status": "skipped",
                "note": "No trained Model A found. Run repos/network-intrusion-detection/main.py to train.",
            }

        # If model exists, load metrics
        metrics_path = PS40_DIR / "reports" / "metrics.json"
        metrics = {}
        if metrics_path.exists():
            with open(metrics_path) as f:
                metrics = json.load(f)

        return {
            "status": "ok",
            "model": metrics.get("best_model", "unknown"),
            "accuracy": metrics.get("validation", {}).get("accuracy", "N/A"),
            "f1": metrics.get("validation", {}).get("f1", "N/A"),
        }
    except Exception as exc:
        logger.error(f"Model A step failed: {exc}")
        return {"status": "error", "error": str(exc)}


def step_model_b(packets_file: Path, anomalies_file: Path, features_file: Path) -> Dict:
    """Step 4 — Model B: Escalation forecaster."""
    if not ENABLE_FORECASTING_MODEL:
        logger.info("Step 4: Model B disabled (ENABLE_FORECASTING_MODEL=0)")
        return {"status": "disabled"}

    logger.info("Step 4: Model B — escalation forecaster")
    try:
        from integration.model_forecaster import run_forecasting_pipeline

        result = run_forecasting_pipeline(
            packets_file=str(packets_file),
            anomalies_file=str(anomalies_file),
            features_file=str(features_file),
            train_mode=True,
        )
        return result
    except Exception as exc:
        logger.error(f"Model B failed: {exc}")
        return {"status": "error", "error": str(exc)}


def step_killchain(anomalies_file: Path, features_file: Path, incidents_file: Path) -> Dict:
    """Step 5 — Kill chain enrichment + MITRE mapping."""
    if not ENABLE_KILLCHAIN:
        logger.info("Step 5: Kill chain disabled (ENABLE_KILLCHAIN=0)")
        return {"status": "disabled"}

    logger.info("Step 5: Kill chain enrichment (MITRE ATT&CK)")
    try:
        events_file = DATA_DIR / "killchain_events.json"
        from integration.killchain_adapter import run_killchain_enrichment

        incidents = run_killchain_enrichment(
            anomalies_file=str(anomalies_file),
            features_file=str(features_file),
            events_output=str(events_file),
            incidents_output=str(incidents_file),
        )
        return {
            "status": "ok",
            "incidents": len(incidents),
        }
    except Exception as exc:
        logger.error(f"Kill chain step failed: {exc}")
        return {"status": "error", "error": str(exc)}


def step_build_graph(anomalies_file: Path, graph_json: Path) -> Dict:
    """Step 6 — Build attack graph JSON for dashboard."""
    logger.info("Step 6: Building attack graph")
    try:
        with open(anomalies_file, encoding="utf-8") as f:
            anomalies = [json.loads(line) for line in f if line.strip()]

        nodes, edges, seen = [], [], set()
        color_map = {
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#eab308",
            "LOW": "#22c55e",
        }

        for a in anomalies:
            src = a.get("src_ip", "")
            dst = a.get("dst_ip", "")
            if not src or not dst:
                continue
            for ip, kind in [(src, "attacker"), (dst, "target")]:
                if ip not in seen:
                    seen.add(ip)
                    nodes.append({"id": ip, "type": kind, "label": ip})
            sev = a.get("severity", "MEDIUM")
            edges.append(
                {
                    "from": src,
                    "to": dst,
                    "label": a.get("anomaly_type", ""),
                    "severity": sev,
                    "color": color_map.get(sev, "#6b7280"),
                }
            )

        graph = {"nodes": nodes, "edges": edges}
        graph_json.parent.mkdir(parents=True, exist_ok=True)
        with open(graph_json, "w", encoding="utf-8") as f:
            json.dump(graph, f, indent=2)

        return {"status": "ok", "nodes": len(nodes), "edges": len(edges)}
    except Exception as exc:
        logger.error(f"Graph build failed: {exc}")
        return {"status": "error", "error": str(exc)}


# ── Main orchestrator ───────────────────────────────────────


def run_full_pipeline(
    use_existing_packets: bool = False,
    live_mode: bool = False,
    live_duration: int = 30,
    live_interface: Optional[str] = None,
    live_filter: Optional[str] = None,
) -> Dict:
    """
    Run the complete SIH26153 pipeline.

    Args:
        use_existing_packets: if True, skip packet generation and reuse
                              whatever is already in data/packets.jsonl.
        live_mode: if True, capture real traffic instead of generating synthetic.
        live_duration: seconds to capture in live mode.
        live_interface: network interface for live capture (None = auto-detect).
        live_filter: BPF filter for live capture (None = no filter).
    Returns:
        dict with per-step results and overall summary.
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    start = time.time()
    results: Dict = {"started_at": datetime.now(UTC).isoformat() + "Z"}

    # ── Step 1: Traffic ────────────────────────────────────
    if live_mode:
        results["step1_traffic"] = step_live_capture(
            PACKETS_FILE,
            duration=live_duration,
            interface=live_interface,
            bpf_filter=live_filter,
        )
    elif use_existing_packets and PACKETS_FILE.exists():
        logger.info("Step 1: Reusing existing packets file")
        results["step1_traffic"] = {
            "status": "reused",
            "packets": sum(1 for _ in open(PACKETS_FILE)),
            "mode": "existing",
        }
    else:
        results["step1_traffic"] = step_generate_traffic(PACKETS_FILE)

    if results["step1_traffic"]["status"] == "error":
        results["pipeline_status"] = "failed_at_step1"
        return results

    # ── Step 2: Anomaly detection ──────────────────────────
    results["step2_anomalies"] = step_anomaly_detection(PACKETS_FILE, ANOMALIES_FILE)

    # ── Step 3: Model A ────────────────────────────────────
    results["step3_model_a"] = step_model_a(PACKETS_FILE)

    # ── Step 4: Model B ────────────────────────────────────
    results["step4_model_b"] = step_model_b(PACKETS_FILE, ANOMALIES_FILE, FEATURES_FILE)

    # If Model B skipped / errored but we still need a features file, create empty one
    if not FEATURES_FILE.exists():
        FEATURES_FILE.write_text("")

    # ── Step 5: Kill chain ─────────────────────────────────
    results["step5_killchain"] = step_killchain(
        ANOMALIES_FILE, FEATURES_FILE, KILLCHAIN_INCIDENTS_FILE
    )

    # ── Step 6: Attack graph ───────────────────────────────
    if ANOMALIES_FILE.exists():
        results["step6_graph"] = step_build_graph(ANOMALIES_FILE, GRAPH_JSON)
    else:
        results["step6_graph"] = {"status": "skipped", "note": "No anomalies file"}

    elapsed = round(time.time() - start, 2)
    results["elapsed_sec"] = elapsed
    results["completed_at"] = datetime.now(UTC).isoformat() + "Z"

    errors = [k for k, v in results.items() if isinstance(v, dict) and v.get("status") == "error"]
    results["pipeline_status"] = "failed" if errors else "completed"
    results["failed_steps"] = errors

    logger.info(
        f"Pipeline {'completed' if not errors else 'completed with errors'} in {elapsed}s. "
        f"Steps: {list(results.keys())}"
    )
    return results


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run SIH26153 full pipeline")
    parser.add_argument(
        "--reuse-packets",
        action="store_true",
        help="Skip packet generation and reuse existing data/packets.jsonl",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Capture real traffic instead of generating synthetic data",
    )
    parser.add_argument(
        "--live-duration",
        type=int,
        default=30,
        help="Seconds to capture in live mode (default: 30)",
    )
    parser.add_argument("--live-interface", default=None, help="Network interface for live capture")
    parser.add_argument(
        "--live-filter", default=None, help="BPF filter for live capture (e.g. 'tcp port 22')"
    )
    args = parser.parse_args()

    result = run_full_pipeline(
        use_existing_packets=args.reuse_packets,
        live_mode=args.live,
        live_duration=args.live_duration,
        live_interface=args.live_interface,
        live_filter=args.live_filter,
    )
    print(json.dumps(result, indent=2, default=str))
