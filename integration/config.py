"""
Shared configuration for the SIH26153 integrated pipeline.

Feature flags control which layers are active.
Adjust ENABLE_FORECASTING_MODEL and ENABLE_KILLCHAIN to toggle layers.
"""

import os
from pathlib import Path

# ── Paths ──────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parents[1]
INTEGRATION_DIR = PROJECT_ROOT / "integration"
DATA_DIR = PROJECT_ROOT / "data"
REPOS_DIR = PROJECT_ROOT / "repos"

# Source repo paths
NTAV_DIR = REPOS_DIR / "Network-Threat-Anomaly-Visualizer"
PS40_DIR = REPOS_DIR / "network-intrusion-detection"
KILLCHAIN_DIR = REPOS_DIR / "cyber-killchain-reconstruction-engine"

# Output directories
PACKETS_FILE = DATA_DIR / "packets.jsonl"
ANOMALIES_FILE = DATA_DIR / "anomalies.jsonl"
FEATURES_FILE = DATA_DIR / "forecast_features.jsonl"
KILLCHAIN_EVENTS_FILE = DATA_DIR / "killchain_events.jsonl"
KILLCHAIN_INCIDENTS_FILE = DATA_DIR / "killchain_incidents.jsonl"
INCIDENT_REPORT_FILE = DATA_DIR / "incident_report.json"
ATTACK_GRAPH_HTML = DATA_DIR / "attack_graph.html"
ATTACK_GRAPH_PNG = DATA_DIR / "attack_graph.png"
GRAPH_JSON = DATA_DIR / "graph.json"
PREDICTIONS_FILE = DATA_DIR / "predictions.csv"
MODEL_DIR = PS40_DIR / "models"

# ── Feature Flags ──────────────────────────────────────────
ENABLE_FORECASTING_MODEL = os.getenv("ENABLE_FORECASTING_MODEL", "1") == "1"
ENABLE_KILLCHAIN = os.getenv("ENABLE_KILLCHAIN", "1") == "1"

# ── Forecasting Model Config ──────────────────────────────
WINDOW_SIZE_SECONDS = 30  # sliding window for aggregation
WINDOW_STEP_SECONDS = 10  # step between windows
ESCALATION_THRESHOLD = 0.5  # probability above which we flag escalation
FORECAST_MODEL_PATH = DATA_DIR / "forecast_model.pkl"

# ── Anomaly Detection Thresholds (inherited from NTAV) ────
PORT_SCAN_THRESHOLD = 10
PORT_SCAN_TIME_WINDOW = 10
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_TIME_WINDOW = 30
CONNECTION_CYCLING_THRESHOLD = 20
CONNECTION_CYCLING_WINDOW = 5

# ── Kill Chain Config ──────────────────────────────────────
KILLCHAIN_TIME_WINDOW_MINUTES = 10


def ensure_dirs():
    """Create all required output directories."""
    for d in [DATA_DIR, INTEGRATION_DIR]:
        d.mkdir(parents=True, exist_ok=True)
