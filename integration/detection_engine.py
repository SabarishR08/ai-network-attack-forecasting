"""
SIH26153 — Stateful Real-Time Anomaly Detection Engine

A production-grade detection engine that analyzes live network traffic
using per-IP state tracking, sliding time windows, and technique-specific
detectors for SYN floods, port scans, brute force, and more.

Each alert includes:
  - MITRE ATT&CK technique mapping
  - Confidence score
  - Severity (CRITICAL / HIGH / MEDIUM / LOW)
  - Actionable prevention recommendations
  - Evidentiary packet details

Usage:
    from integration.detection_engine import DetectionEngine

    engine = DetectionEngine(local_ip="192.168.1.5")
    anomalies = engine.process_packet(packet_dict)
"""

import json
import logging
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone

UTC = timezone.utc
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# ── Constants ──────────────────────────────────────────────

SUSPICIOUS_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 110: "POP3", 135: "MS-RPC", 139: "NetBIOS",
    143: "IMAP", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

HIGH_RISK_PORTS = {22, 23, 3389, 5900, 3306, 5432, 6379, 27017, 1433, 445}

# MITRE ATT&CK mappings per anomaly type
MITRE_MAP = {
    "SYN Flood": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": "Impact",
        "description": "Attacker floods target with SYN packets to exhaust connection resources.",
    },
    "SYN Scan": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Stealthy half-open scan probing services without completing TCP handshake.",
    },
    "Connect Scan": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Full TCP connect scan establishing and immediately closing connections.",
    },
    "FIN Scan": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Stealthy scan using FIN flag to bypass basic stateless firewalls.",
    },
    "XMAS Scan": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Stealthy scan with FIN+PSH+URG flags set (Christmas tree packet).",
    },
    "NULL Scan": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Stealthy scan with no TCP flags set to map firewall rules.",
    },
    "Port Scan": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Attacker probing multiple ports to discover running services.",
    },
    "Brute Force": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Repeated authentication attempts to guess credentials.",
    },
    "Distributed Brute Force": {
        "technique_id": "T1110.004",
        "technique_name": "Brute Force: Credential Stuffing",
        "tactic": "Credential Access",
        "description": "Multiple sources brute-forcing the same service simultaneously.",
    },
    "UDP Flood": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": "Impact",
        "description": "High-rate UDP traffic targeting a single host to saturate bandwidth.",
    },
    "ICMP Flood": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": "Impact",
        "description": "Ping flood overwhelming target with ICMP echo requests.",
    },
    "Connection Cycling": {
        "technique_id": "T1571",
        "technique_name": "Non-Standard Port",
        "tactic": "Command and Control",
        "description": "Rapid connection attempts cycling through ports to find open services.",
    },
    "Suspicious Payload": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Traffic contains payload patterns associated with command injection.",
    },
}


from integration.prevention import get_prevention


# ── Per-IP State Tracker ───────────────────────────────────

class PerIPState:
    """Sliding-window counters for a single source IP."""

    def __init__(self, window_seconds: int = 30):
        self.window = window_seconds
        self.syn_count = 0
        self.ack_count = 0
        self.rst_count = 0
        self.fin_count = 0
        self.psh_count = 0
        self.urg_count = 0
        self.total_packets = 0
        self.unique_dst_ports: Set[int] = set()
        self.unique_dst_ips: Set[str] = set()
        self.payload_sizes: List[int] = []
        self.timestamps: List[float] = []
        self.port_syn_count: Dict[int, int] = defaultdict(int)   # per-port SYN count
        self.port_ack_count: Dict[int, int] = defaultdict(int)   # per-port ACK count
        self.port_rst_count: Dict[int, int] = defaultdict(int)   # per-port RST count
        self.half_open_ports: Set[int] = set()                   # SYN sent, no ACK received

    def add(self, pkt: Dict):
        """Record a packet, evicting expired entries."""
        now = time.time()
        self.timestamps.append(now)
        self._evict(now)

        self.total_packets += 1

        flags = pkt.get("flags") or ""
        dst_port = pkt.get("dst_port")
        dst_ip = pkt.get("dst_ip", "")

        if dst_port is not None:
            self.unique_dst_ports.add(dst_port)
        if dst_ip:
            self.unique_dst_ips.add(dst_ip)

        ps = pkt.get("payload_size", 0)
        if ps is not None:
            self.payload_sizes.append(ps)

        # Flag counting
        if "S" in flags and "A" not in flags:
            self.syn_count += 1
            if dst_port is not None:
                self.port_syn_count[dst_port] += 1
                self.half_open_ports.add(dst_port)
        if "A" in flags:
            self.ack_count += 1
            if dst_port is not None:
                self.port_ack_count[dst_port] += 1
                self.half_open_ports.discard(dst_port)
        if "R" in flags:
            self.rst_count += 1
            if dst_port is not None:
                self.port_rst_count[dst_port] += 1
        if "F" in flags:
            self.fin_count += 1
        if "P" in flags:
            self.psh_count += 1
        if "U" in flags:
            self.urg_count += 1

    def _evict(self, now: float):
        """Remove timestamps older than window, then rebuild counters."""
        cutoff = now - self.window
        idx = 0
        for i, ts in enumerate(self.timestamps):
            if ts >= cutoff:
                idx = i
                break
        else:
            # All expired
            self.timestamps.clear()
            self._reset_counters()
            return

        if idx > 0:
            self.timestamps = self.timestamps[idx:]

    def _reset_counters(self):
        self.syn_count = 0
        self.ack_count = 0
        self.rst_count = 0
        self.fin_count = 0
        self.psh_count = 0
        self.urg_count = 0
        self.total_packets = 0
        self.unique_dst_ports.clear()
        self.unique_dst_ips.clear()
        self.payload_sizes.clear()
        self.port_syn_count.clear()
        self.port_ack_count.clear()
        self.port_rst_count.clear()
        self.half_open_ports.clear()

    @property
    def packets_per_second(self) -> float:
        if not self.timestamps:
            return 0.0
        span = self.timestamps[-1] - self.timestamps[0]
        return self.total_packets / max(span, 0.001)

    @property
    def syn_ack_ratio(self) -> float:
        """SYN count / ACK count — high values indicate SYN flood or scan."""
        return self.syn_count / max(self.ack_count, 1)

    @property
    def payload_mean(self) -> float:
        return sum(self.payload_sizes) / max(len(self.payload_sizes), 1)

    @property
    def payload_max(self) -> int:
        return max(self.payload_sizes) if self.payload_sizes else 0

    @property
    def half_open_count(self) -> int:
        return len(self.half_open_ports)


# ── Detectors ──────────────────────────────────────────────

class SYNFloodDetector:
    """Detect SYN flood attacks via rate, SYN/ACK ratio, and half-open connections."""

    def __init__(
        self,
        rate_threshold: float = 80.0,
        syn_ack_ratio_threshold: float = 5.0,
        half_open_threshold: int = 20,
    ):
        self.rate_threshold = rate_threshold
        self.syn_ack_ratio_threshold = syn_ack_ratio_threshold
        self.half_open_threshold = half_open_threshold

    def detect(self, src_ip: str, state: PerIPState, local_ip: str) -> Optional[Dict]:
        if state.syn_count == 0:
            return None

        reasons = []
        severity_score = 0

        # 1. Rate-based: too many SYNs per second
        syn_rate = state.syn_count / max(state.window, 1)
        if syn_rate > self.rate_threshold:
            reasons.append(f"SYN rate {syn_rate:.0f}/s exceeds threshold {self.rate_threshold}/s")
            severity_score += 3

        # 2. SYN/ACK ratio: many SYNs but few ACKs = half-open flood
        ratio = state.syn_ack_ratio
        if ratio > self.syn_ack_ratio_threshold and state.syn_count > 10:
            reasons.append(
                f"SYN/ACK ratio {ratio:.1f}:1 exceeds {self.syn_ack_ratio_threshold}:1 "
                f"(SYN={state.syn_count}, ACK={state.ack_count})"
            )
            severity_score += 3

        # 3. Half-open connections: SYN sent to many ports without completion
        half_open = state.half_open_count
        if half_open > self.half_open_threshold:
            reasons.append(
                f"{half_open} half-open connections exceed threshold {self.half_open_threshold}"
            )
            severity_score += 2

        if not reasons:
            return None

        severity = "CRITICAL" if severity_score >= 6 else "HIGH" if severity_score >= 3 else "MEDIUM"
        confidence = min(0.70 + severity_score * 0.05, 0.99)

        return {
            "anomaly_type": "SYN Flood",
            "severity": severity,
            "confidence": round(confidence, 3),
            "src_ip": src_ip,
            "dst_ip": local_ip,
            "reasons": reasons,
            "metrics": {
                "syn_count": state.syn_count,
                "ack_count": state.ack_count,
                "syn_rate_per_sec": round(syn_rate, 1),
                "syn_ack_ratio": round(ratio, 2),
                "half_open_connections": half_open,
                "unique_ports": len(state.unique_dst_ports),
                "window_sec": state.window,
            },
        }


class PortScanDetector:
    """Detect port scans — SYN scan, connect scan, FIN/XMAS/NULL scan, and generic sweep."""

    # Thresholds
    MIN_UNIQUE_PORTS = 5
    SYN_SCAN_SYN_ONLY_THRESHOLD = 3       # SYN with no ACK response
    CONNECT_SCAN_THRESHOLD = 10            # full connect + RST/FIN
    FIN_XMAS_NULL_THRESHOLD = 3            # stealth scan packets

    def __init__(self, local_ip: str):
        self.local_ip = local_ip

    def detect(self, src_ip: str, state: PerIPState) -> Optional[Dict]:
        if len(state.unique_dst_ports) < self.MIN_UNIQUE_PORTS:
            return None

        scan_type = None
        reasons = []
        severity_score = 0

        # --- SYN Scan (half-open scan / nmap -sS) ---
        syn_only_ports = [
            p for p, c in state.port_syn_count.items()
            if c > 0 and state.port_ack_count.get(p, 0) == 0
        ]
        if len(syn_only_ports) >= self.SYN_SCAN_SYN_ONLY_THRESHOLD:
            scan_type = "SYN Scan"
            reasons.append(
                f"{len(syn_only_ports)} ports received SYN with no ACK response "
                f"(half-open scan pattern)"
            )
            severity_score += 3

        # --- Connect Scan (full TCP connect / nmap -sT) ---
        connect_ports = [
            p for p in state.unique_dst_ports
            if state.port_ack_count.get(p, 0) > 0 and state.port_rst_count.get(p, 0) > 0
        ]
        if len(connect_ports) >= self.CONNECT_SCAN_THRESHOLD:
            scan_type = scan_type or "Connect Scan"
            reasons.append(
                f"{len(connect_ports)} ports completed full TCP connect then RST/FIN"
            )
            severity_score += 2

        # --- FIN / XMAS / NULL Scan (stealth scans) ---
        stealth_packets = state.fin_count + state.urg_count
        # NULL scan: packets with no flags — hard to detect from flags alone,
        # but if total_packets is high and SYN/ACK/RST are all low, it's suspicious.
        if state.total_packets > 10:
            no_flag_ratio = 1.0 - (
                (state.syn_count + state.ack_count + state.rst_count + state.fin_count)
                / max(state.total_packets, 1)
            )
            if no_flag_ratio > 0.5 and state.total_packets >= self.FIN_XMAS_NULL_THRESHOLD:
                scan_type = scan_type or "NULL Scan"
                reasons.append(
                    f"{state.total_packets} packets with no standard TCP flags "
                    f"({no_flag_ratio*100:.0f}% NULL packets)"
                )
                severity_score += 3

        if stealth_packets >= self.FIN_XMAS_NULL_THRESHOLD and len(state.unique_dst_ports) >= 3:
            scan_type = scan_type or "FIN Scan"
            reasons.append(
                f"{stealth_packets} FIN/URG packets to {len(state.unique_dst_ports)} ports"
            )
            severity_score += 3

        # --- Generic Port Sweep (fallback) ---
        if not scan_type and len(state.unique_dst_ports) >= self.MIN_UNIQUE_PORTS:
            scan_type = "Port Scan"
            reasons.append(
                f"{len(state.unique_dst_ports)} unique ports probed from single source"
            )
            severity_score += 2

        if not scan_type:
            return None

        # Severity escalation for high-risk ports
        high_risk_hit = state.unique_dst_ports & HIGH_RISK_PORTS
        if high_risk_hit:
            reasons.append(f"Targets include high-risk ports: {sorted(high_risk_hit)}")
            severity_score += 2

        severity = "CRITICAL" if severity_score >= 7 else "HIGH" if severity_score >= 4 else "MEDIUM"
        confidence = min(0.80 + severity_score * 0.03, 0.99)

        return {
            "anomaly_type": scan_type,
            "severity": severity,
            "confidence": round(confidence, 3),
            "src_ip": src_ip,
            "dst_ip": self.local_ip,
            "reasons": reasons,
            "metrics": {
                "unique_ports": len(state.unique_dst_ports),
                "ports_scanned": sorted(state.unique_dst_ports)[:50],
                "syn_only_ports": len(syn_only_ports),
                "connect_ports": len(connect_ports),
                "syn_count": state.syn_count,
                "ack_count": state.ack_count,
                "rst_count": state.rst_count,
                "fin_count": state.fin_count,
                "half_open": state.half_open_count,
                "window_sec": state.window,
            },
        }


class BruteForceDetector:
    """Detect brute-force and distributed brute-force attacks."""

    FAILED_FLAGS = {"R", "RA", "S"}  # RST or bare SYN = rejected/failed

    def __init__(
        self,
        threshold: int = 5,
        distributed_threshold: int = 3,
        window_seconds: int = 30,
    ):
        self.threshold = threshold
        self.distributed_threshold = distributed_threshold
        self.window_seconds = window_seconds

    def detect(
        self,
        all_states: Dict[str, PerIPState],
        local_ip: str,
    ) -> List[Dict]:
        """
        Detect brute force across ALL tracked IPs.

        Args:
            all_states: dict of src_ip → PerIPState
            local_ip: our machine's IP
        """
        # Group by (dst_ip, dst_port) to find coordinated attacks
        target_port_map: Dict[Tuple[str, int], List[Tuple[str, int]]] = defaultdict(list)

        for src_ip, state in all_states.items():
            for port, syn_cnt in state.port_syn_count.items():
                rst_cnt = state.port_rst_count.get(port, 0)
                failed = rst_cnt + max(0, syn_cnt - state.port_ack_count.get(port, 0))
                if failed >= self.threshold:
                    target_port_map[(local_ip, port)].append((src_ip, failed))

        anomalies = []
        for (dst_ip, dst_port), attackers in target_port_map.items():
            if len(attackers) < 1:
                continue

            is_distributed = len(attackers) >= self.distributed_threshold
            anomaly_type = "Distributed Brute Force" if is_distributed else "Brute Force"

            total_failed = sum(f for _, f in attackers)
            max_failed = max(f for _, f in attackers)
            src_ips = [ip for ip, _ in attackers]

            severity_score = 2
            if dst_port in HIGH_RISK_PORTS:
                severity_score += 3
            if is_distributed:
                severity_score += 2
            if total_failed >= 20:
                severity_score += 2

            severity = (
                "CRITICAL" if severity_score >= 7
                else "HIGH" if severity_score >= 4
                else "MEDIUM"
            )
            confidence = min(0.75 + severity_score * 0.03, 0.99)

            reasons = [
                f"{total_failed} failed connection attempts to port {dst_port} "
                f"({SUSPICIOUS_PORTS.get(dst_port, 'Unknown')})",
            ]
            if is_distributed:
                reasons.append(
                    f"Distributed from {len(attackers)} unique source IPs: "
                    f"{', '.join(src_ips[:5])}"
                )

            anomaly = {
                "anomaly_type": anomaly_type,
                "severity": severity,
                "confidence": round(confidence, 3),
                "src_ip": src_ips[0] if len(src_ips) == 1 else ",".join(src_ips[:10]),
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "reasons": reasons,
                "metrics": {
                    "total_failed_attempts": total_failed,
                    "max_single_ip": max_failed,
                    "attacker_count": len(attackers),
                    "attacker_ips": src_ips[:20],
                    "service": SUSPICIOUS_PORTS.get(dst_port, "Unknown"),
                    "window_sec": self.window_seconds,
                },
            }
            anomalies.append(anomaly)

        return anomalies


class FloodDetector:
    """Detect UDP and ICMP flood attacks."""

    def __init__(
        self,
        udp_rate_threshold: float = 200.0,
        icmp_rate_threshold: float = 100.0,
    ):
        self.udp_rate_threshold = udp_rate_threshold
        self.icmp_rate_threshold = icmp_rate_threshold

    def detect(self, src_ip: str, state: PerIPState) -> List[Dict]:
        anomalies = []

        # Count UDP and ICMP from packet data
        # We rely on total_packets and absence of TCP flags for UDP/ICMP
        has_tcp = state.syn_count + state.ack_count + state.rst_count + state.fin_count
        non_tcp = state.total_packets - has_tcp

        if non_tcp < 10:
            return anomalies

        rate = non_tcp / max(state.window, 1)

        # UDP Flood heuristic: high packet rate with no TCP handshake
        if rate > self.udp_rate_threshold and non_tcp > 50:
            severity = "CRITICAL" if rate > self.udp_rate_threshold * 2 else "HIGH"
            anomalies.append({
                "anomaly_type": "UDP Flood",
                "severity": severity,
                "confidence": min(0.75 + (rate / self.udp_rate_threshold) * 0.05, 0.99),
                "src_ip": src_ip,
                "dst_ip": state.unique_dst_ips.pop() if state.unique_dst_ips else "",
                "reasons": [
                    f"High non-TCP packet rate: {rate:.0f}/s "
                    f"({non_tcp} packets in {state.window}s window)"
                ],
                "metrics": {
                    "non_tcp_packets": non_tcp,
                    "rate_per_sec": round(rate, 1),
                    "total_packets": state.total_packets,
                    "window_sec": state.window,
                },
            })

        # ICMP Flood: many packets with tiny payloads and no ports
        if (not state.unique_dst_ports and state.total_packets > 20
                and state.payload_mean < 100):
            rate_icmp = state.total_packets / max(state.window, 1)
            if rate_icmp > self.icmp_rate_threshold:
                anomalies.append({
                    "anomaly_type": "ICMP Flood",
                    "severity": "HIGH",
                    "confidence": min(0.70 + rate_icmp / self.icmp_rate_threshold * 0.05, 0.95),
                    "src_ip": src_ip,
                    "dst_ip": state.unique_dst_ips.pop() if state.unique_dst_ips else "",
                    "reasons": [
                        f"ICMP-style traffic: {state.total_packets} no-port packets "
                        f"with avg payload {state.payload_mean:.0f}B at {rate_icmp:.0f}/s"
                    ],
                    "metrics": {
                        "icmp_packets": state.total_packets,
                        "rate_per_sec": round(rate_icmp, 1),
                        "avg_payload": round(state.payload_mean, 1),
                        "window_sec": state.window,
                    },
                })

        return anomalies


# ── Main Detection Engine ──────────────────────────────────

class DetectionEngine:
    """
    Orchestrates all detectors against live packet streams.

    Maintains per-IP state and runs technique-specific detectors
    each cycle. Deduplicates alerts within a configurable cooldown.
    """

    def __init__(
        self,
        local_ip: str,
        window_seconds: int = 30,
        dedup_cooldown: int = 60,
        syn_flood_rate: float = 80.0,
        brute_force_threshold: int = 5,
    ):
        self.local_ip = local_ip
        self.window_seconds = window_seconds
        self.dedup_cooldown = dedup_cooldown

        # Per-IP state
        self._states: Dict[str, PerIPState] = defaultdict(
            lambda: PerIPState(window_seconds=window_seconds)
        )
        self._lock = __import__("threading").Lock()

        # Dedup tracking: anomaly_id → last_alert_time
        self._alert_history: Dict[str, float] = {}

        # Detectors
        self.syn_flood = SYNFloodDetector(rate_threshold=syn_flood_rate)
        self.port_scan = PortScanDetector(local_ip=local_ip)
        self.brute_force = BruteForceDetector(
            threshold=brute_force_threshold,
            window_seconds=window_seconds,
        )
        self.flood = FloodDetector()

        # Counters
        self._total_packets = 0
        self._total_anomalies = 0

    def process_packet(self, packet: Dict) -> List[Dict]:
        """
        Ingest one packet and return any NEW anomalies detected.

        This is the hot path — called for every captured packet.
        Anomalies are only emitted when the detection cycle runs
        (via detect_all), but per-IP state is updated immediately.
        """
        src_ip = packet.get("src_ip", "")
        if not src_ip or src_ip == self.local_ip:
            return []  # Skip our own traffic

        with self._lock:
            self._states[src_ip].add(packet)
            self._total_packets += 1

        return []  # Detection runs on a timer, not per-packet

    def detect_all(self) -> List[Dict]:
        """
        Run all detectors on current state and return NEW anomalies.

        Called periodically (e.g. every 5 seconds) by the live processor.
        """
        new_anomalies = []

        with self._lock:
            states_snapshot = dict(self._states)

        for src_ip, state in states_snapshot.items():
            # SYN Flood
            result = self.syn_flood.detect(src_ip, state, self.local_ip)
            if result:
                new_anomalies.extend(self._finalize([result], src_ip))

            # Port Scan
            result = self.port_scan.detect(src_ip, state)
            if result:
                new_anomalies.extend(self._finalize([result], src_ip))

            # UDP / ICMP Flood
            results = self.flood.detect(src_ip, state)
            if results:
                new_anomalies.extend(self._finalize(results, src_ip))

        # Brute Force (cross-IP, runs on all states)
        bf_results = self.brute_force.detect(states_snapshot, self.local_ip)
        if bf_results:
            new_anomalies.extend(self._finalize(bf_results, bf_results[0].get("src_ip", "")))

        self._total_anomalies += len(new_anomalies)
        return new_anomalies

    def _finalize(self, raw_anomalies: List[Dict], src_ip: str) -> List[Dict]:
        """Add IDs, timestamps, MITRE mapping, and prevention to each anomaly."""
        finalized = []
        now = datetime.now(UTC).isoformat().replace("+00:00", "Z")

        for a in raw_anomalies:
            atype = a["anomaly_type"]
            dst_port = a.get("dst_port", 0)
            aid = f"{atype.replace(' ', '').upper()}-{src_ip.replace('.', '')}-{dst_port}"

            # Dedup
            if self._is_duplicate(aid):
                continue

            # Enrich
            a["anomaly_id"] = aid
            a["timestamp"] = now
            a["detection_mode"] = "live"
            a["mitre"] = MITRE_MAP.get(atype, {})
            a["prevention"] = get_prevention(atype, src_ip, dst_port)
            a["evidence"] = {
                "packets_analyzed": a.get("metrics", {}).get("total_packets", 0),
                "window_sec": a.get("metrics", {}).get("window_sec", self.window_seconds),
            }
            finalized.append(a)

        return finalized

    def _is_duplicate(self, anomaly_id: str) -> bool:
        """Check cooldown to avoid alert storms."""
        now = time.time()
        last = self._alert_history.get(anomaly_id)
        if last and (now - last) < self.dedup_cooldown:
            return True
        self._alert_history[anomaly_id] = now
        return False

    def cleanup(self):
        """Evict expired alert history entries (call periodically)."""
        now = time.time()
        expired = [
            aid for aid, ts in self._alert_history.items()
            if (now - ts) > self.dedup_cooldown * 3
        ]
        for aid in expired:
            del self._alert_history[aid]

    @property
    def stats(self) -> Dict:
        with self._lock:
            return {
                "tracked_ips": len(self._states),
                "total_packets_processed": self._total_packets,
                "total_anomalies_detected": self._total_anomalies,
                "alert_history_size": len(self._alert_history),
                "window_seconds": self.window_seconds,
                "dedup_cooldown": self.dedup_cooldown,
                "per_ip_stats": {
                    ip: {
                        "packets": s.total_packets,
                        "syn": s.syn_count,
                        "ack": s.ack_count,
                        "rst": s.rst_count,
                        "unique_ports": len(s.unique_dst_ports),
                        "half_open": s.half_open_count,
                        "pps": round(s.packets_per_second, 1),
                    }
                    for ip, s in list(self._states.items())[:20]
                },
            }

    def reset(self):
        """Clear all state (e.g. on restart)."""
        with self._lock:
            self._states.clear()
            self._alert_history.clear()
            self._total_packets = 0
            self._total_anomalies = 0
