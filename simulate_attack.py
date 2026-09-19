#!/usr/bin/env python3
"""
Standalone Attack Simulator for SIH26153
Generates realistic network attack data without NTAV dependencies.

Usage:
    python simulate_attack.py              # Full simulation
    python simulate_attack.py --light      # Quick 50-packet demo
    python simulate_attack.py --server     # Generate + start Flask server
"""

import argparse
import json
import os
import random
import sys
from datetime import datetime, timezone

UTC = timezone.utc
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent
DATA_DIR = PROJECT_ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)

PACKETS_FILE = DATA_DIR / "packets.jsonl"
ANOMALIES_FILE = DATA_DIR / "anomalies.jsonl"
FEATURES_FILE = DATA_DIR / "forecast_features.jsonl"
KILLCHAIN_FILE = DATA_DIR / "killchain_incidents.jsonl"

# ── Realistic IPs ──────────────────────────────────────────
ATTACKER_IPS = [
    "185.220.101.42", "45.33.32.156", "198.51.100.73",
    "103.224.182.251", "23.129.64.210", "176.10.104.240",
    "195.176.3.23", "77.247.181.163", "185.220.100.252",
    "209.141.55.30",
]
TARGET_IPS = [
    "10.0.0.1", "10.0.0.5", "10.0.0.10", "10.0.0.15",
    "192.168.1.100", "192.168.1.200", "172.16.0.50",
]
SERVICES = {
    22: "SSH", 80: "HTTP", 443: "HTTPS", 3306: "MySQL",
    5432: "PostgreSQL", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    21: "FTP", 23: "Telnet", 3389: "RDP", 53: "DNS",
    110: "POP3", 143: "IMAP", 993: "IMAPS",
}
ANOMALY_TYPES = ["Port Scan", "Brute Force", "Connection Cycling", "Suspicious Connection"]
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
KILL_CHAIN_STAGES = [
    "Reconnaissance", "Weaponization", "Delivery", "Exploitation",
    "Installation", "Command & Control", "Actions on Objectives",
]
MITRE_TECHNIQUES = [
    {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    {"id": "T1571", "name": "Non-Standard Port", "tactic": "Command and Control"},
    {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
    {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement"},
    {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
]


def gen_timestamp(offset_sec=0):
    """Generate a realistic timestamp."""
    now = datetime.now(UTC)
    from datetime import timedelta
    return (now - timedelta(seconds=offset_sec)).isoformat().replace("+00:00", "Z")


def generate_packets(n=500):
    """Generate realistic network packets with mixed attack traffic."""
    packets = []

    for i in range(n):
        # 70% normal, 30% attack
        is_attack = random.random() < 0.3

        if is_attack:
            src_ip = random.choice(ATTACKER_IPS)
            dst_ip = random.choice(TARGET_IPS)
            dst_port = random.choice(list(SERVICES.keys()))
            protocol = random.choice(["TCP", "TCP", "UDP"])

            # Attack-specific flags
            if dst_port in (22, 21, 23, 3389):
                flags = random.choice(["SYN", "SYN", "ACK", "RST", "FIN"])
            else:
                flags = random.choice(["SYN", "ACK", "PSH", "FIN", "RST"])

            payload_size = random.randint(0, 500) if protocol == "TCP" else random.randint(40, 1500)
        else:
            src_ip = random.choice(TARGET_IPS)
            dst_ip = f"93.184.{random.randint(1,254)}.{random.randint(1,254)}"
            dst_port = random.choice([80, 443, 53])
            protocol = random.choice(["TCP", "UDP"])
            flags = "ACK"
            payload_size = random.randint(200, 1400)

        packets.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": protocol,
            "flags": flags,
            "payload_size": payload_size,
            "timestamp": gen_timestamp((n - i) * 0.5),
        })

    return packets


def generate_anomalies(packets):
    """Detect anomalies from packet data using heuristic rules."""
    anomalies = []

    # Group packets by src_ip
    by_src = {}
    for p in packets:
        src = p["src_ip"]
        by_src.setdefault(src, []).append(p)

    for src_ip, pkts in by_src.items():
        if src_ip not in ATTACKER_IPS:
            continue

        dst_ports = set(p["dst_port"] for p in pkts)
        timestamps = sorted(p["timestamp"] for p in pkts)

        # Port Scan: many different ports
        if len(dst_ports) >= 5:
            anomalies.append({
                "src_ip": src_ip,
                "dst_ip": pkts[0]["dst_ip"],
                "anomaly_type": "Port Scan",
                "severity": "HIGH" if len(dst_ports) >= 10 else "MEDIUM",
                "timestamp": timestamps[0],
                "confidence": round(random.uniform(0.75, 0.98), 3),
                "ports_scanned": sorted(dst_ports)[:20],
                "port_count": len(dst_ports),
            })

        # Brute Force: many connections to same port
        by_port = {}
        for p in pkts:
            by_port.setdefault(p["dst_port"], []).append(p)

        for port, port_pkts in by_port.items():
            if len(port_pkts) >= 8:
                anomalies.append({
                    "src_ip": src_ip,
                    "dst_ip": port_pkts[0]["dst_ip"],
                    "anomaly_type": "Brute Force",
                    "severity": "CRITICAL" if len(port_pkts) >= 20 else "HIGH",
                    "timestamp": port_pkts[0]["timestamp"],
                    "confidence": round(random.uniform(0.80, 0.99), 3),
                    "failed_attempts": len(port_pkts),
                    "dst_port": port,
                    "service": SERVICES.get(port, "Unknown"),
                })

        # Connection Cycling: SYN without ACK
        syns = [p for p in pkts if p["flags"] == "SYN"]
        if len(syns) >= 6:
            anomalies.append({
                "src_ip": src_ip,
                "dst_ip": syns[0]["dst_ip"],
                "anomaly_type": "Connection Cycling",
                "severity": "MEDIUM",
                "timestamp": syns[0]["timestamp"],
                "confidence": round(random.uniform(0.60, 0.85), 3),
                "port_count": len(set(p["dst_port"] for p in syns)),
            })

        # Suspicious Connection: low payload on non-standard port
        low_payload = [p for p in pkts if p["payload_size"] < 100 and p["dst_port"] not in (80, 443, 53)]
        if len(low_payload) >= 3:
            anomalies.append({
                "src_ip": src_ip,
                "dst_ip": low_payload[0]["dst_ip"],
                "anomaly_type": "Suspicious Connection",
                "severity": "LOW",
                "timestamp": low_payload[0]["timestamp"],
                "confidence": round(random.uniform(0.55, 0.75), 3),
                "dst_port": low_payload[0]["dst_port"],
            })

    return anomalies


def generate_features(anomalies):
    """Generate forecast features from anomalies."""
    features = []

    for i, a in enumerate(anomalies):
        prob = a["confidence"] * random.uniform(0.7, 1.1)
        prob = min(prob, 1.0)
        predicted = prob > 0.7

        features.append({
            "src_ip": a["src_ip"],
            "dst_ip": a["dst_ip"],
            "window_start": gen_timestamp(300 - i * 30),
            "window_end": gen_timestamp(270 - i * 30),
            "window_duration_sec": 30,
            "total_packets": random.randint(5, 50),
            "port_diversity": a.get("port_count", random.randint(1, 10)),
            "unique_ports": a.get("ports_scanned", [a.get("dst_port", 80)])[:10],
            "connection_rate": round(random.uniform(0.5, 5.0), 2),
            "syn_count": random.randint(0, 20),
            "rst_count": random.randint(0, 10),
            "syn_rst_ratio": round(random.uniform(0, 1), 3),
            "payload_size_mean": round(random.uniform(50, 800), 1),
            "payload_size_max": random.randint(200, 1500),
            "escalation_probability": round(prob, 4),
            "escalation_predicted": predicted,
        })

    return features


def generate_killchain(anomalies):
    """Generate kill chain incidents from anomalies."""
    incidents = []

    for a in anomalies:
        stage = random.choice(KILL_CHAIN_STAGES)
        technique = random.choice(MITRE_TECHNIQUES)

        incidents.append({
            "id": f"INC-{len(incidents)+1:04d}",
            "src_ip": a["src_ip"],
            "dst_ip": a["dst_ip"],
            "kill_chain_stage": stage,
            "mitre": technique,
            "anomaly_type": a["anomaly_type"],
            "severity": a["severity"],
            "timestamp": a["timestamp"],
            "confidence": a["confidence"],
            "description": f"{technique['name']} detected — {stage} phase",
        })

    return incidents


def save_jsonl(rows, path):
    with open(path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def main():
    parser = argparse.ArgumentParser(description="Simulate network attacks")
    parser.add_argument("--light", action="store_true", help="Quick demo with 50 packets")
    parser.add_argument("--server", action="store_true", help="Start Flask server after simulation")
    parser.add_argument("--packets", type=int, default=500, help="Number of packets (default 500)")
    args = parser.parse_args()

    n = 50 if args.light else args.packets

    import io
    import sys as _sys
    _sys.stdout = io.TextIOWrapper(_sys.stdout.buffer, encoding='utf-8')
    print(f"\n{'='*60}")
    print("  SIH26153 - Attack Simulation")
    print(f"{'='*60}\n")

    # Step 1: Generate packets
    print(f"Generating {n} network packets...")
    packets = generate_packets(n)
    save_jsonl(packets, PACKETS_FILE)
    attack_count = sum(1 for p in packets if p["src_ip"] in ATTACKER_IPS)
    print(f"  [OK] {len(packets)} packets saved to {PACKETS_FILE}")
    print(f"  [!]  {attack_count} attack packets ({attack_count/len(packets)*100:.0f}%)")
    print(f"  [.]  {len(packets)-attack_count} normal packets")

    # Step 2: Detect anomalies
    print("\nRunning anomaly detection...")
    anomalies = generate_anomalies(packets)
    save_jsonl(anomalies, ANOMALIES_FILE)
    by_type = {}
    by_sev = {}
    for a in anomalies:
        by_type[a["anomaly_type"]] = by_type.get(a["anomaly_type"], 0) + 1
        by_sev[a["severity"]] = by_sev.get(a["severity"], 0) + 1
    print(f"  [OK] {len(anomalies)} anomalies detected -> {ANOMALIES_FILE}")
    for t, c in sorted(by_type.items()):
        print(f"      - {t}: {c}")
    print(f"  Severity: {by_sev}")

    # Step 3: Forecast features
    print("\nGenerating forecast features...")
    features = generate_features(anomalies)
    save_jsonl(features, FEATURES_FILE)
    escalated = sum(1 for f in features if f["escalation_predicted"])
    print(f"  [OK] {len(features)} feature windows -> {FEATURES_FILE}")
    print(f"  [!]  {escalated} escalation predictions ({escalated/max(len(features),1)*100:.0f}%)")

    # Step 4: Kill chain
    print("\nBuilding kill chain incidents...")
    incidents = generate_killchain(anomalies)
    save_jsonl(incidents, KILLCHAIN_FILE)
    stages = {}
    for inc in incidents:
        s = inc["kill_chain_stage"]
        stages[s] = stages.get(s, 0) + 1
    print(f"  [OK] {len(incidents)} incidents -> {KILLCHAIN_FILE}")
    for s, c in sorted(stages.items()):
        print(f"      - {s}: {c}")

    # Summary
    print(f"\n{'='*60}")
    print("  Data files generated:")
    print(f"     {PACKETS_FILE}")
    print(f"     {ANOMALIES_FILE}")
    print(f"     {FEATURES_FILE}")
    print(f"     {KILLCHAIN_FILE}")
    print(f"{'='*60}\n")

    if args.server:
        print("Starting Flask server...")
        os.environ["PORT"] = "5000"
        os.environ["FLASK_DEBUG"] = "1"
        sys.path.insert(0, str(PROJECT_ROOT))
        from integration.app import app
        app.run(host="0.0.0.0", port=5000, debug=True)


if __name__ == "__main__":
    main()
