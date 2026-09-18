"""
Step 3c — Kill Chain Adapter

Converts network-flow / anomaly records (from NTAV Step 3a / PS40 Step 3b)
into the NormalizedEvent schema expected by the killchain reconstruction engine.

Network events are mapped to kill chain stages:
  - Port scan detected       → Reconnaissance
  - Brute force on service   → Exploitation (existing brute_force pattern)
  - Connection cycling       → Reconnaissance / Delivery
  - DoS / traffic spike      → Denial of Service (Actions on Objectives)
  - Escalation forecast high → Potential future attack (preventive alert)
"""

import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# Add killchain repo to path for imports
KILLCHAIN_DIR = str(
    Path(__file__).resolve().parents[1] / "repos" / "cyber-killchain-reconstruction-engine"
)
if KILLCHAIN_DIR not in sys.path:
    sys.path.insert(0, KILLCHAIN_DIR)

from ingestion.schemas import NormalizedEvent

logger = logging.getLogger(__name__)


# ── Mapping Tables ─────────────────────────────────────────

ANOMALY_TYPE_MAP = {
    "Port Scan": {
        "event_type": "port_scan_detected",
        "severity": 7,
        "kill_chain_stage": "Reconnaissance",
    },
    "Brute Force": {
        "event_type": "brute_force_attempt",
        "severity": 8,
        "kill_chain_stage": "Exploitation",
    },
    "Connection Cycling": {
        "event_type": "connection_cycling",
        "severity": 5,
        "kill_chain_stage": "Reconnaissance",
    },
    "Suspicious Connection": {
        "event_type": "suspicious_connection",
        "severity": 5,
        "kill_chain_stage": "Reconnaissance",
    },
}

# Mapping for escalation forecast
ESCALATION_MAP = {
    "high": {
        "event_type": "escalation_forecast",
        "severity": 9,
        "kill_chain_stage": "Exploitation",
    },
    "medium": {
        "event_type": "escalation_forecast",
        "severity": 6,
        "kill_chain_stage": "Delivery",
    },
    "low": {
        "event_type": "escalation_forecast",
        "severity": 3,
        "kill_chain_stage": "Reconnaissance",
    },
}


def anomaly_to_normalized_event(anomaly: Dict) -> Optional[NormalizedEvent]:
    """
    Convert a single NTAV anomaly record to a NormalizedEvent.

    Args:
        anomaly: dict from anomalies.jsonl

    Returns:
        NormalizedEvent compatible with killchain engine, or None on error
    """
    anomaly_type = anomaly.get("anomaly_type", "")
    mapping = ANOMALY_TYPE_MAP.get(anomaly_type)

    if not mapping:
        logger.debug(f"No mapping for anomaly type: {anomaly_type}")
        return None

    # Parse timestamp
    ts_str = anomaly.get("timestamp", "")
    try:
        timestamp = datetime.fromisoformat(ts_str)
    except Exception:
        timestamp = datetime.now()

    # Build entity from src_ip (the attacker)
    entity = anomaly.get("src_ip", "unknown")

    # Metadata includes network-specific fields
    metadata = {
        "src_ip": anomaly.get("src_ip", ""),
        "dst_ip": anomaly.get("dst_ip", ""),
        "anomaly_type": anomaly_type,
        "confidence": anomaly.get("confidence", 0.5),
        "source": "ntav_network",
    }

    # Add type-specific metadata
    if anomaly_type == "Port Scan":
        metadata["ports_scanned"] = anomaly.get("ports_scanned", [])
        metadata["port_count"] = anomaly.get("port_count", 0)
    elif anomaly_type == "Brute Force":
        metadata["dst_port"] = anomaly.get("dst_port", 0)
        metadata["failed_attempts"] = anomaly.get("failed_attempts", 0)
        metadata["service"] = anomaly.get("service", "Unknown")

    return NormalizedEvent(
        timestamp=timestamp,
        source="network",
        event_type=mapping["event_type"],
        entity=entity,
        severity=mapping["severity"],
        metadata=metadata,
    )


def forecast_to_normalized_event(feat: Dict) -> Optional[NormalizedEvent]:
    """
    Convert a forecast feature vector with escalation prediction
    to a NormalizedEvent for the killchain engine.
    """
    if not feat.get("escalation_predicted", False):
        return None  # Only emit events for predicted escalations

    prob = feat.get("escalation_probability", 0.0)
    if prob >= 0.7:
        risk = "high"
    elif prob >= 0.5:
        risk = "medium"
    else:
        risk = "low"

    mapping = ESCALATION_MAP[risk]

    try:
        timestamp = datetime.fromisoformat(feat.get("window_start", ""))
    except Exception:
        timestamp = datetime.now()

    return NormalizedEvent(
        timestamp=timestamp,
        source="forecast_model",
        event_type=mapping["event_type"],
        entity=feat.get("src_ip", "unknown"),
        severity=mapping["severity"],
        metadata={
            "src_ip": feat.get("src_ip", ""),
            "dst_ip": feat.get("dst_ip", ""),
            "escalation_probability": prob,
            "risk_level": risk,
            "window_start": feat.get("window_start", ""),
            "window_end": feat.get("window_end", ""),
            "source": "model_b_forecast",
        },
    )


def convert_anomalies_to_killchain_events(
    anomalies_file: str = "data/anomalies.jsonl",
    output_file: str = "data/killchain_events.jsonl",
) -> List[NormalizedEvent]:
    """
    Convert all anomalies from NTAV to killchain NormalizedEvents.
    """
    events = []
    path = Path(anomalies_file)

    if not path.exists():
        logger.warning(f"Anomalies file not found: {anomalies_file}")
        return events

    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            anomaly = json.loads(line)
            event = anomaly_to_normalized_event(anomaly)
            if event:
                events.append(event)

    logger.info(f"Converted {len(events)} anomalies to killchain events")

    # Save as JSON for the killchain engine
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    event_dicts = []
    for ev in events:
        event_dicts.append(
            {
                "timestamp": ev.timestamp.isoformat(),
                "user": ev.entity,
                "src_ip": ev.metadata.get("src_ip", ""),
                "status": "FAIL",  # All anomalies map to FAIL-like events
                "source": ev.source,
                "event_type": ev.event_type,
                "severity": ev.severity,
                "metadata": ev.metadata,
            }
        )

    with open(output_path, "w") as f:
        json.dump(event_dicts, f, indent=2)

    return events


def convert_forecasts_to_killchain_events(
    features_file: str = "data/forecast_features.jsonl",
    output_file: str = "data/killchain_events.jsonl",
    append: bool = True,
) -> List[NormalizedEvent]:
    """
    Convert forecast escalation predictions to killchain events.
    Optionally append to existing killchain events file.
    """
    events = []
    path = Path(features_file)

    if not path.exists():
        logger.warning(f"Features file not found: {features_file}")
        return events

    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            feat = json.loads(line)
            event = forecast_to_normalized_event(feat)
            if event:
                events.append(event)

    logger.info(f"Converted {len(events)} forecast predictions to killchain events")

    if events:
        # Load existing events if appending
        existing = []
        out_path = Path(output_file)
        if append and out_path.exists():
            try:
                with open(out_path) as f:
                    existing = json.load(f)
            except Exception:
                existing = []

        new_dicts = []
        for ev in events:
            new_dicts.append(
                {
                    "timestamp": ev.timestamp.isoformat(),
                    "user": ev.entity,
                    "src_ip": ev.metadata.get("src_ip", ""),
                    "status": "FAIL",
                    "source": ev.source,
                    "event_type": ev.event_type,
                    "severity": ev.severity,
                    "metadata": ev.metadata,
                }
            )

        all_events = existing + new_dicts
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w") as f:
            json.dump(all_events, f, indent=2)

    return events


def run_killchain_enrichment(
    anomalies_file: str = "data/anomalies.jsonl",
    features_file: str = "data/forecast_features.jsonl",
    events_output: str = "data/killchain_events.jsonl",
    incidents_output: str = "data/killchain_incidents.jsonl",
) -> List[Dict]:
    """
    Full killchain enrichment pipeline:
    1. Convert network events → killchain schema
    2. Run correlation engine
    3. Enrich with MITRE ATT&CK
    4. Generate incidents
    """
    # Step 1: Convert events
    network_events = convert_anomalies_to_killchain_events(anomalies_file, events_output)
    forecast_events = convert_forecasts_to_killchain_events(
        features_file, events_output, append=True
    )

    # Step 2: Correlate
    try:
        from correlation.correlator import correlate_events
    except ImportError:
        # Try relative import from killchain repo
        sys.path.insert(0, KILLCHAIN_DIR)
        from correlation.correlator import correlate_events

    all_events = network_events + forecast_events
    if not all_events:
        logger.warning("No events to correlate")
        return []

    incidents = correlate_events(all_events)
    logger.info(f"Killchain engine detected {len(incidents)} incidents")

    # Step 3: Enrich with MITRE
    try:
        from killchain.mitre_mapping import enrich_incident_with_mitre
    except ImportError:
        sys.path.insert(0, KILLCHAIN_DIR)
        from killchain.mitre_mapping import enrich_incident_with_mitre

    from reporting.scoring import prioritize_incidents

    enriched = []
    for incident in incidents:
        # Convert events back to NormalizedEvent if needed
        if "events" in incident:
            incident["events"] = [
                e
                if isinstance(e, NormalizedEvent)
                else NormalizedEvent(
                    timestamp=datetime.fromisoformat(e.get("timestamp", "2026-01-01T00:00:00"))
                    if isinstance(e, dict)
                    else datetime.now(),
                    source=e.get("source", "network") if isinstance(e, dict) else "network",
                    event_type=e.get("event_type", "unknown") if isinstance(e, dict) else "unknown",
                    entity=e.get("entity", "unknown") if isinstance(e, dict) else "unknown",
                    severity=e.get("severity", 5) if isinstance(e, dict) else 5,
                    metadata=e.get("metadata", {}) if isinstance(e, dict) else {},
                )
                for e in incident.get("events", [])
            ]

        incident = enrich_incident_with_mitre(incident)
        enriched.append(incident)

    # Step 4: Score and prioritize
    prioritized = prioritize_incidents(enriched)

    # Save incidents
    output_path = Path(incidents_output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    serializable = []
    for inc in prioritized:
        inc_copy = {k: v for k, v in inc.items() if k != "events"}
        if "events" in inc:
            inc_copy["event_count"] = len(inc["events"])
        serializable.append(inc_copy)

    with open(output_path, "w") as f:
        json.dump(serializable, f, indent=2, default=str)

    logger.info(f"Saved {len(serializable)} enriched incidents to {incidents_output}")
    return prioritized


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run killchain adapter for network events")
    parser.add_argument("--anomalies", default="data/anomalies.jsonl")
    parser.add_argument("--features", default="data/forecast_features.jsonl")
    parser.add_argument("--events-output", default="data/killchain_events.jsonl")
    parser.add_argument("--incidents-output", default="data/killchain_incidents.jsonl")

    args = parser.parse_args()

    incidents = run_killchain_enrichment(
        anomalies_file=args.anomalies,
        features_file=args.features,
        events_output=args.events_output,
        incidents_output=args.incidents_output,
    )

    print(f"\nKillchain enrichment complete: {len(incidents)} incidents")
    for inc in incidents:
        print(
            f"  [{inc.get('priority', '?')}] {inc.get('pattern', 'unknown')} "
            f"- {inc.get('entity', 'unknown')} "
            f"(risk: {inc.get('risk_score', '?')})"
        )
