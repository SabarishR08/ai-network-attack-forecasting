"""
SIH26153 -- Live Packet Processor

Continuously captures real packets and runs anomaly detection on them.
This replaces the synthetic data generator with a real IDS engine.

Requires admin/root privileges for packet capture.
On Windows, run as Administrator or use: python run.py --monitor
On Linux/macOS, use: sudo python -m integration.live_processor

Note: On Windows, install Npcap first: https://npcap.com/#download
"""

import argparse
import json
import logging
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone

UTC = timezone.utc
from pathlib import Path
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# ── Bootstrap paths ────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parents[1]
for p in [
    str(PROJECT_ROOT),
    str(PROJECT_ROOT / "repos" / "Network-Threat-Anomaly-Visualizer"),
    str(PROJECT_ROOT / "repos" / "Network-Threat-Anomaly-Visualizer" / "src"),
]:
    if p not in sys.path:
        sys.path.insert(0, p)

from integration.config import ANOMALIES_FILE, PACKETS_FILE
from integration.detection_engine import DetectionEngine
from integration.packet_capture import PacketCapturer, get_local_ip

# ── Rolling Buffer for Real-Time Detection ─────────────────


class RollingPacketBuffer:
    """
    In-memory rolling buffer of recent packets.

    Used for real-time anomaly detection without re-reading the full
    JSONL file on every check. Keeps the last N seconds of packets
    per (src_ip, dst_ip) pair.
    """

    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds
        self._buffer: Dict[str, List[Dict]] = defaultdict(list)
        self._lock = threading.Lock()

    def add(self, packet: Dict):
        """Add a packet to the rolling buffer."""
        src = packet.get("src_ip", "")
        dst = packet.get("dst_ip", "")
        key = f"{src}->{dst}"

        with self._lock:
            self._buffer[key].append(packet)
            self._evict(key)

    def get_packets(self, src_ip: Optional[str] = None) -> List[Dict]:
        """Get all non-expired packets, optionally filtered by src_ip."""
        cutoff = datetime.now(UTC) - timedelta(seconds=self.window_seconds)
        result = []

        with self._lock:
            for key, pkts in self._buffer.items():
                if src_ip and not key.startswith(src_ip + "->"):
                    continue
                for pkt in pkts:
                    ts = self._parse_ts(pkt.get("timestamp", ""))
                    if ts and ts >= cutoff:
                        result.append(pkt)
        return result

    def _evict(self, key: str):
        """Remove expired packets from a key."""
        cutoff = datetime.now(UTC) - timedelta(seconds=self.window_seconds)
        pkts = self._buffer[key]
        self._buffer[key] = [
            p
            for p in pkts
            if self._parse_ts(p.get("timestamp", ""))
            and self._parse_ts(p.get("timestamp", "")) >= cutoff
        ]

    def _parse_ts(self, ts_str: str) -> Optional[datetime]:
        try:
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except Exception:
            return None

    @property
    def total_packets(self) -> int:
        with self._lock:
            return sum(len(pkts) for pkts in self._buffer.values())


# ── Real-Time Anomaly Detector ─────────────────────────────


class LiveAnomalyDetector:
    """
    Detects anomalies from the rolling packet buffer.

    Runs heuristic checks similar to NTAV's AnomalyDetector but
    works incrementally on live traffic.
    """

    # Detection thresholds
    PORT_SCAN_UNIQUE_PORTS = 5  # Unique ports in window → scan
    PORT_SCAN_WINDOW = 10  # Seconds

    BRUTE_FORCE_THRESHOLD = 5  # Failed attempts → brute force
    BRUTE_FORCE_WINDOW = 30  # Seconds

    CONNECTION_CYCLING_THRESHOLD = 20  # Connections in window
    CONNECTION_CYCLING_WINDOW = 5  # Seconds

    SUSPICIOUS_PORTS = {
        22: "SSH",
        3389: "RDP",
        5900: "VNC",
        3306: "MySQL",
        5432: "PostgreSQL",
        27017: "MongoDB",
        6379: "Redis",
        21: "FTP",
        23: "Telnet",
    }

    def __init__(self, local_ip: str):
        self.local_ip = local_ip
        self._seen_anomalies: Dict[str, datetime] = {}
        self._lock = threading.Lock()

    def detect(self, packets: List[Dict]) -> List[Dict]:
        """
        Run detection on a list of recent packets.
        Returns only NEW anomalies (not duplicates).
        """
        anomalies = []
        anomalies.extend(self._detect_port_scans(packets))
        anomalies.extend(self._detect_brute_force(packets))
        anomalies.extend(self._detect_connection_cycling(packets))
        return anomalies

    def _is_new(self, anomaly_id: str) -> bool:
        """Check if this anomaly was already reported recently (dedup within 60s)."""
        with self._lock:
            now = datetime.now(UTC)
            last = self._seen_anomalies.get(anomaly_id)
            if last and (now - last).total_seconds() < 60:
                return False
            self._seen_anomalies[anomaly_id] = now
            return True

    def _detect_port_scans(self, packets: List[Dict]) -> List[Dict]:
        """Detect port scanning: one src_ip hitting many different dst_ports."""
        # Group by (src_ip, dst_ip)
        by_pair = defaultdict(list)
        for pkt in packets:
            if pkt.get("dst_port") is not None:
                by_pair[(pkt["src_ip"], pkt["dst_ip"])].append(pkt)

        anomalies = []
        for (src_ip, dst_ip), pkts in by_pair.items():
            # Only flag traffic TO our machine (inbound scan)
            if dst_ip != self.local_ip and src_ip == self.local_ip:
                continue  # Outbound, skip

            ports = set(p["dst_port"] for p in pkts if p.get("dst_port") is not None)
            if len(ports) >= self.PORT_SCAN_UNIQUE_PORTS:
                anomaly_id = f"PORTSCAN-{src_ip.replace('.', '')}-{dst_ip.replace('.', '')}"
                if not self._is_new(anomaly_id):
                    continue

                severity = "HIGH" if len(ports) >= 10 else "MEDIUM"
                system_ports = [p for p in ports if p < 1024]
                if len(system_ports) >= 3:
                    severity = "CRITICAL"

                anomalies.append(
                    {
                        "anomaly_id": anomaly_id,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "anomaly_type": "Port Scan",
                        "severity": severity,
                        "confidence": min(0.85 + len(ports) * 0.01, 0.99),
                        "ports_scanned": sorted(ports)[:50],
                        "port_count": len(ports),
                        "time_window": self.PORT_SCAN_WINDOW,
                        "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                        "detection_mode": "live",
                    }
                )
        return anomalies

    def _detect_brute_force(self, packets: List[Dict]) -> List[Dict]:
        """Detect brute-force: many failed connections to same port."""
        # Group by (src_ip, dst_ip, dst_port)
        by_triplet = defaultdict(list)
        for pkt in packets:
            if pkt.get("dst_port") is not None:
                key = (pkt["src_ip"], pkt["dst_ip"], pkt["dst_port"])
                by_triplet[key].append(pkt)

        anomalies = []
        for (src_ip, dst_ip, dst_port), pkts in by_triplet.items():
            # Count "failed" indicators: RST flags, SYN-only (no ACK), low payload
            failed = [
                p
                for p in pkts
                if p.get("flags") in ("R", "RA", "S")
                or (p.get("flags") == "S" and p.get("payload_size", 0) == 0)
            ]

            if len(failed) >= self.BRUTE_FORCE_THRESHOLD:
                anomaly_id = f"BRUTEFORCE-{src_ip.replace('.', '')}-{dst_port}"
                if not self._is_new(anomaly_id):
                    continue

                severity = "MEDIUM"
                if dst_port in self.SUSPICIOUS_PORTS:
                    severity = "CRITICAL" if dst_port in (22, 3389, 5900) else "HIGH"

                anomalies.append(
                    {
                        "anomaly_id": anomaly_id,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "anomaly_type": "Brute Force",
                        "severity": severity,
                        "confidence": min(0.80 + len(failed) * 0.01, 0.99),
                        "failed_attempts": len(failed),
                        "time_window": self.BRUTE_FORCE_WINDOW,
                        "service": self.SUSPICIOUS_PORTS.get(dst_port, "Unknown"),
                        "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                        "detection_mode": "live",
                    }
                )
        return anomalies

    def _detect_connection_cycling(self, packets: List[Dict]) -> List[Dict]:
        """Detect rapid connection cycling from a single source."""
        by_src = defaultdict(list)
        for pkt in packets:
            by_src[pkt["src_ip"]].append(pkt)

        anomalies = []
        for src_ip, pkts in by_src.items():
            syns = [p for p in pkts if p.get("flags") in ("S", "SA")]
            if len(syns) >= self.CONNECTION_CYCLING_THRESHOLD:
                anomaly_id = f"CYCLING-{src_ip.replace('.', '')}"
                if not self._is_new(anomaly_id):
                    continue

                anomalies.append(
                    {
                        "anomaly_id": anomaly_id,
                        "src_ip": src_ip,
                        "dst_ip": syns[0].get("dst_ip", ""),
                        "anomaly_type": "Connection Cycling",
                        "severity": "MEDIUM",
                        "confidence": 0.70,
                        "connections_in_window": len(syns),
                        "time_window": self.CONNECTION_CYCLING_WINDOW,
                        "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                        "detection_mode": "live",
                    }
                )
        return anomalies


# ── Live Processor ─────────────────────────────────────────


class LiveProcessor:
    """
    Orchestrates real-time packet capture + anomaly detection.

    Flow:
      1. Captures packets in real-time (via PacketCapturer)
      2. Stores them in a rolling buffer
      3. Periodically runs anomaly detection on recent packets
      4. Appends new anomalies to anomalies.jsonl
      5. Optionally feeds data to forecast features + kill chain
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        bpf_filter: Optional[str] = None,
        packets_file: str = str(PACKETS_FILE),
        anomalies_file: str = str(ANOMALIES_FILE),
        detection_interval: int = 5,
        buffer_window: int = 60,
        auto_block: bool = False,
    ):
        self.packets_file = Path(packets_file)
        self.anomalies_file = Path(anomalies_file)
        self.detection_interval = detection_interval

        self.local_ip = get_local_ip()
        self.buffer = RollingPacketBuffer(window_seconds=buffer_window)
        self.engine = DetectionEngine(
            local_ip=self.local_ip,
            window_seconds=buffer_window,
            dedup_cooldown=60,
        )

        self.capturer = PacketCapturer(
            interface=interface,
            output_file=str(self.packets_file),
            bpf_filter=bpf_filter,
            packet_callback=self._on_packet,
        )

        self._running = False
        self._detection_thread: Optional[threading.Thread] = None
        self._anomaly_count = 0
        self.auto_block = auto_block
        self._blocked_ips: Set[str] = set()

        # Ensure output directories exist
        self.packets_file.parent.mkdir(parents=True, exist_ok=True)

    def _on_packet(self, packet: Dict):
        """Called for every captured packet — feed to engine and buffer."""
        self.buffer.add(packet)
        self.engine.process_packet(packet)

    def _detection_loop(self):
        """Background thread: periodically run anomaly detection via the engine."""
        cycle = 0
        while self._running:
            try:
                # Run stateful detection engine
                new_anomalies = self.engine.detect_all()

                if new_anomalies:
                    # Append to anomalies file
                    with open(self.anomalies_file, "a", encoding="utf-8") as f:
                        for a in new_anomalies:
                            f.write(json.dumps(a, default=str) + "\n")

                    self._anomaly_count += len(new_anomalies)

                    for a in new_anomalies:
                        sev = a["severity"]
                        atype = a["anomaly_type"]
                        src = a["src_ip"]
                        mitre_id = a.get("mitre", {}).get("technique_id", "?")
                        logger.warning(
                            f"[{sev}] {atype} from {src} "
                            f"(confidence: {a['confidence']:.2f}, MITRE: {mitre_id})"
                        )
                        # Log prevention steps
                        for rec in a.get("prevention", [])[:2]:
                            logger.info(f"  -> {rec}")

                        # Auto-block: apply firewall rule for CRITICAL/HIGH
                        if self.auto_block and sev in ("CRITICAL", "HIGH"):
                            self._auto_block_ip(src, a)

                # Periodic stats
                cycle += 1
                total = self.capturer.packet_count
                if cycle % 6 == 0:  # Every ~30s at 5s interval
                    stats = self.engine.stats
                    logger.info(
                        f"📊 Packets: {total} | IPs: {stats['tracked_ips']} | "
                        f"Anomalies: {self._anomaly_count} | "
                        f"History: {stats['alert_history_size']}"
                    )
                    # Cleanup expired dedup entries
                    self.engine.cleanup()

            except Exception as e:
                logger.error(f"Detection loop error: {e}")

            time.sleep(self.detection_interval)

    def start(self, timeout: Optional[int] = None):
        """
        Start live processing.

        Args:
            timeout: Stop after N seconds (None = run until Ctrl+C).
        """
        self._running = True

        print(f"\n{'=' * 60}")
        print("  SIH26153 — Live Network Intrusion Detection")
        print(f"{'=' * 60}")
        print(f"  Local IP:    {self.local_ip}")
        print(f"  Interface:   {self.capturer.interface or '(auto-detect)'}")
        print(f"  Filter:      {self.capturer.bpf_filter or '(none)'}")
        print(f"  Packets:     {self.packets_file}")
        print(f"  Anomalies:   {self.anomalies_file}")
        print(f"  Detection:   every {self.detection_interval}s")
        print(f"  Buffer:      {self.buffer.window_seconds}s rolling window")
        print(f"{'=' * 60}\n")

        # Start capture
        self.capturer.start(timeout=timeout)

        # Start detection loop
        self._detection_thread = threading.Thread(target=self._detection_loop, daemon=True)
        self._detection_thread.start()
        logger.info("Live detection engine started")

    def _auto_block_ip(self, src_ip: str, anomaly: Dict):
        """Apply firewall rule to block an attacker IP."""
        if src_ip in self._blocked_ips:
            logger.info(f"  [AUTO-BLOCK] {src_ip} already blocked, skipping")
            return

        try:
            from integration.prevention import PreventionEngine

            engine = PreventionEngine()
            applied = engine.auto_block(anomaly)
            if applied:
                self._blocked_ips.add(src_ip)
                logger.warning(f"  [AUTO-BLOCK] Successfully blocked {src_ip}")
            else:
                logger.warning(
                    f"  [AUTO-BLOCK] Failed to block {src_ip} (rule generated but not applied)"
                )
        except Exception as e:
            logger.error(f"  [AUTO-BLOCK] Error blocking {src_ip}: {e}")

    def stop(self):
        """Stop live processing."""
        self._running = False
        self.capturer.stop()

        if self._detection_thread:
            self._detection_thread.join(timeout=5)

        logger.info(
            f"Live processor stopped. "
            f"Packets: {self.capturer.packet_count}, "
            f"Anomalies: {self._anomaly_count}, "
            f"Blocked IPs: {len(self._blocked_ips)}"
        )

    @property
    def stats(self) -> Dict:
        engine_stats = self.engine.stats
        return {
            "running": self._running,
            "local_ip": self.local_ip,
            "packets_captured": self.capturer.packet_count,
            "anomalies_detected": self._anomaly_count,
            "buffer_size": self.buffer.total_packets,
            "tracked_ips": engine_stats["tracked_ips"],
            "per_ip_stats": engine_stats["per_ip_stats"],
            "auto_block": self.auto_block,
            "blocked_ips": list(self._blocked_ips),
        }


# ── CLI Entry Point ────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="SIH26153 — Live Network Intrusion Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Windows (run as Administrator):
  python -m integration.live_processor
  python run.py --monitor

  # Linux/macOS:
  sudo python -m integration.live_processor

  # Monitor for 120 seconds:
  python -m integration.live_processor --timeout 120

  # Detect only TCP port scans:
  python -m integration.live_processor --filter "tcp"

  # Monitor specific interface:
  python -m integration.live_processor --interface eth0

Note: On Windows, install Npcap first: https://npcap.com/#download
        """,
    )
    parser.add_argument("--interface", "-i", default=None, help="Network interface")
    parser.add_argument("--filter", "-f", default=None, help="BPF filter string")
    parser.add_argument("--timeout", "-t", type=int, default=None, help="Stop after N seconds")
    parser.add_argument(
        "--interval",
        type=int,
        default=5,
        help="Detection interval in seconds (default: 5)",
    )
    parser.add_argument("--packets-file", default=str(PACKETS_FILE), help="Packets output file")
    parser.add_argument(
        "--anomalies-file", default=str(ANOMALIES_FILE), help="Anomalies output file"
    )
    parser.add_argument(
        "--auto-block", action="store_true", help="Auto-block attacker IPs via firewall rules"
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    processor = LiveProcessor(
        interface=args.interface,
        bpf_filter=args.filter,
        packets_file=args.packets_file,
        anomalies_file=args.anomalies_file,
        detection_interval=args.interval,
        auto_block=args.auto_block,
    )

    try:
        processor.start(timeout=args.timeout)
        # Block main thread until capture finishes or Ctrl+C
        if processor.capturer._capture:
            processor.capturer._capture.join()
    except KeyboardInterrupt:
        print("\n\nShutting down...")
    finally:
        processor.stop()

    stats = processor.stats
    print(f"\n{'=' * 60}")
    print("  Session Summary")
    print(f"{'=' * 60}")
    print(f"  Packets captured:  {stats['packets_captured']}")
    print(f"  Anomalies found:   {stats['anomalies_detected']}")
    print(f"  Packets file:      {processor.packets_file}")
    print(f"  Anomalies file:    {processor.anomalies_file}")
    print(f"  Auto-blocked IPs:  {len(stats.get('blocked_ips', []))}")
    print(f"{'=' * 60}\n")


if __name__ == "__main__":
    main()
