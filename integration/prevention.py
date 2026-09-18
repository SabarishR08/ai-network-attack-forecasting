"""
SIH26153 — Prevention Recommendation Engine

Generates actionable, OS-aware firewall rules and hardening recommendations
for each detected threat. Supports Linux (iptables/nftables/ufw), macOS
(pf), and Windows (netsh) backends.

Features:
  - OS detection (Linux / macOS / Windows)
  - Multi-backend rule generation (iptables, nftables, ufw, pf, netsh)
  - Tiered recommendations: IMMEDIATE / HARDENING / MONITORING
  - Auto-block mode: applies rules with user elevation
  - Rule export: saves to file for manual review or later application
  - Persistent blocklist: remembers blocked IPs across restarts

Usage:
    from integration.prevention import PreventionEngine

    engine = PreventionEngine()
    rec = engine.generate(anomaly_dict)
    print(rec.summary())

    # Auto-block
    engine.auto_block(anomaly_dict)

    # Export all rules
    engine.export_rules("data/firewall_rules.sh")
"""

import json
import logging
import platform
import subprocess
from datetime import datetime, timezone

UTC = timezone.utc
from pathlib import Path
from typing import Dict, List

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BLOCKLIST_FILE = PROJECT_ROOT / "data" / "blocklist.json"

# ── Service & Port Intelligence ────────────────────────────

SUSPICIOUS_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MS-RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

HIGH_RISK_PORTS = {22, 23, 3389, 5900, 3306, 5432, 6379, 27017, 1433, 445}


# ── OS Detection ───────────────────────────────────────────


def detect_os() -> str:
    """Detect the host operating system."""
    system = platform.system().lower()
    if "linux" in system:
        return "linux"
    elif "darwin" in system:
        return "macos"
    elif "windows" in system:
        return "windows"
    return "unknown"


def detect_firewall_backend() -> str:
    """Detect the available firewall backend on this system."""
    os_name = detect_os()

    if os_name == "linux":
        # Prefer ufw > nftables > iptables
        for cmd in ("ufw", "nft", "iptables"):
            try:
                subprocess.run(["which", cmd], capture_output=True, timeout=5)
                return cmd
            except Exception:
                continue
        return "iptables"  # Assume iptables as fallback

    elif os_name == "macos":
        return "pf"

    elif os_name == "windows":
        return "netsh"

    return "unknown"


# ── Recommendation Data Classes ────────────────────────────


class PreventionRecommendation:
    """A structured prevention recommendation with tiered actions."""

    def __init__(
        self,
        anomaly_type: str,
        src_ip: str,
        severity: str = "MEDIUM",
        dst_port: int = 0,
    ):
        self.anomaly_type = anomaly_type
        self.src_ip = src_ip
        self.severity = severity
        self.dst_port = dst_port
        self.os_name = detect_os()
        self.backend = detect_firewall_backend()
        self.timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")

        # Tiered recommendations
        self.immediate: List[str] = []  # Block attacker NOW
        self.hardening: List[str] = []  # System hardening steps
        self.monitoring: List[str] = []  # Ongoing monitoring

        # Generated rules for each backend
        self.iptables_rules: List[str] = []
        self.nftables_rules: List[str] = []
        self.ufw_commands: List[str] = []
        self.pf_rules: List[str] = []
        self.netsh_commands: List[str] = []

        self._generate()

    def _generate(self):
        """Route to the correct generator based on anomaly type."""
        generators = {
            "SYN Flood": self._gen_flood,
            "UDP Flood": self._gen_flood,
            "ICMP Flood": self._gen_flood,
            "SYN Scan": self._gen_scan,
            "Connect Scan": self._gen_scan,
            "FIN Scan": self._gen_scan,
            "XMAS Scan": self._gen_scan,
            "NULL Scan": self._gen_scan,
            "Port Scan": self._gen_scan,
            "Brute Force": self._gen_brute_force,
            "Distributed Brute Force": self._gen_brute_force,
            "Connection Cycling": self._gen_scan,
            "Suspicious Payload": self._gen_payload,
        }
        gen = generators.get(self.anomaly_type, self._gen_generic)
        gen()
        self._generate_backend_rules()

    # ── Flood (SYN / UDP / ICMP) ───────────────────────────

    def _gen_flood(self):
        self.immediate.extend(
            [
                f"DROP all traffic from attacker IP {self.src_ip}",
                "Apply SYN rate-limiting: max 50 SYNs/sec per source",
                "Enable SYN cookies in kernel",
            ]
        )
        self.hardening.extend(
            [
                "Enable SYN cookies: sysctl -w net.ipv4.tcp_syncookies=1",
                "Reduce SYN-ACK retries: sysctl -w net.ipv4.tcp_synack_retries=2",
                "Set tcp_max_syn_backlog: sysctl -w net.ipv4.tcp_max_syn_backlog=4096",
                "Enable tcp_synack_retries: sysctl -w net.ipv4.tcp_synack_retries=1",
                "Consider deploying fail2ban or CrowdSec for automated blocking",
                "Enable connection tracking: modprobe nf_conntrack",
                "Set conntrack table size: sysctl -w net.netfilter.nf_conntrack_max=262144",
            ]
        )
        self.monitoring.extend(
            [
                "Monitor for sustained flood patterns over 5+ minutes",
                "Watch for packet rate exceeding 1000/sec from any single IP",
                "Set up alerting for bandwidth saturation (>80% link capacity)",
                "Consider upstream DDoS protection (Cloudflare, AWS Shield)",
            ]
        )

    # ── Port Scans ─────────────────────────────────────────

    def _gen_scan(self):
        self.immediate.extend(
            [
                f"BLOCK all traffic from {self.src_ip}",
                "Drop invalid/malformed packets at firewall",
                "Enable connection tracking to detect half-open scans",
            ]
        )
        self.hardening.extend(
            [
                "Drop invalid packets: iptables -A INPUT -m conntrack --ctstate INVALID -j DROP",
                "Enable SYN cookies: sysctl -w net.ipv4.tcp_syncookies=1",
                "Restrict exposed services — close unused ports",
                "Deploy fail2ban with sshd jail for ongoing protection",
                "Enable port knocking for sensitive services (SSH, RDP)",
                "Use allowlist-based firewall (default deny, explicit allow)",
            ]
        )
        self.monitoring.extend(
            [
                "Log all connection attempts to closed ports",
                "Alert on >5 unique ports probed from single IP in 10s",
                "Monitor for scan-then-exploit patterns",
            ]
        )

        if self.dst_port and self.dst_port in HIGH_RISK_PORTS:
            svc = SUSPICIOUS_PORTS.get(self.dst_port, "unknown")
            self.hardening.append(
                f"CRITICAL: Port {self.dst_port} ({svc}) targeted — "
                f"verify it is intentionally exposed and restrict access via VPN or IP allowlist"
            )

    # ── Brute Force ────────────────────────────────────────

    def _gen_brute_force(self):
        service = SUSPICIOUS_PORTS.get(self.dst_port, "Unknown")
        self.immediate.extend(
            [
                f"BLOCK {self.src_ip} immediately",
                f"Rate-limit connections to port {self.dst_port} ({service})",
                "Consider temporarily disabling the targeted service if under active attack",
            ]
        )
        self.hardening.extend(
            [
                "Switch to SSH key-based authentication (disable password auth)",
                "Install fail2ban: apt install fail2ban && systemctl enable fail2ban",
                "Configure fail2ban jail for the targeted service",
                "Rate-limit auth endpoints: max 5 attempts per IP per minute",
                "Enable account lockout after 3 failed attempts (15-minute lockout)",
                "Deploy multi-factor authentication (MFA) for all remote access",
                "Use strong password policies (12+ chars, complexity requirements)",
            ]
        )
        self.monitoring.extend(
            [
                "Alert on >10 failed auth attempts per IP per minute",
                "Monitor for distributed brute force (3+ IPs targeting same service)",
                "Log all authentication events for forensic analysis",
                "Set up real-time alerting for successful logins after failed attempts",
            ]
        )

        if self.dst_port in (22, 3389, 5900):
            svc = SUSPICIOUS_PORTS.get(self.dst_port, "unknown")
            self.hardening.append(
                f"URGENT: {svc} (port {self.dst_port}) brute force active — "
                f"restrict to VPN or trusted IP ranges immediately"
            )

    # ── Suspicious Payload ─────────────────────────────────

    def _gen_payload(self):
        self.immediate.extend(
            [
                f"BLOCK {self.src_ip}",
                "Inspect payload contents for command injection patterns",
                "Enable deep packet inspection if available",
            ]
        )
        self.hardening.extend(
            [
                "Update WAF rules to block matching payload signatures",
                "Enable application-level input validation",
                "Deploy IDS signatures for known attack payloads",
                "Keep all software patched and up to date",
            ]
        )
        self.monitoring.extend(
            [
                "Capture full payloads for forensic analysis",
                "Set up signature-based alerting in IDS/IPS",
            ]
        )

    # ── Generic Fallback ───────────────────────────────────

    def _gen_generic(self):
        self.immediate.extend(
            [
                f"BLOCK {self.src_ip}",
                "Review the detected traffic pattern manually",
            ]
        )
        self.hardening.extend(
            [
                "Enable connection tracking and stateful firewall rules",
                "Apply default-deny inbound policy",
                "Keep firewall rules updated and audited regularly",
            ]
        )
        self.monitoring.extend(
            [
                "Continue monitoring the source IP for escalation",
            ]
        )

    # ── Backend-Specific Rule Generation ───────────────────

    def _generate_backend_rules(self):
        """Generate rules for all supported firewall backends."""
        self._gen_iptables_rules()
        self._gen_nftables_rules()
        self._gen_ufw_rules()
        self._gen_pf_rules()
        self._gen_netsh_rules()

    def _gen_iptables_rules(self):
        """Generate iptables rules."""
        rules = []

        # Block attacker IP
        rules.append(f"iptables -A INPUT -s {self.src_ip} -j DROP")
        rules.append(f"iptables -A FORWARD -s {self.src_ip} -j DROP")

        if self.anomaly_type in ("SYN Flood", "UDP Flood", "ICMP Flood"):
            rules.append(
                "iptables -A INPUT -p tcp --syn -m limit --limit 50/s --limit-burst 100 -j ACCEPT"
            )
            rules.append("iptables -A INPUT -p tcp --syn -j DROP")
            rules.append(
                "iptables -A INPUT -p icmp --icmp-type echo-request "
                "-m limit --limit 10/s --limit-burst 20 -j ACCEPT"
            )
            rules.append("iptables -A INPUT -p icmp --icmp-type echo-request -j DROP")

        if self.anomaly_type in ("Brute Force", "Distributed Brute Force"):
            rules.append(
                f"iptables -A INPUT -p tcp --dport {self.dst_port} -m recent --set --name BRUTE"
            )
            rules.append(
                f"iptables -A INPUT -p tcp --dport {self.dst_port} "
                "-m recent --update --seconds 60 --hitcount 5 "
                "--name BRUTE -j DROP"
            )

        rules.append("iptables -A INPUT -m conntrack --ctstate INVALID -j DROP")

        self.iptables_rules = rules

    def _gen_nftables_rules(self):
        """Generate nftables rules."""
        rules = []
        rules.append(f"add rule inet filter input ip saddr {self.src_ip} drop")

        if self.anomaly_type in ("SYN Flood", "UDP Flood", "ICMP Flood"):
            rules.append(
                "add rule inet filter input tcp flags syn meter syn-flood "
                "{ ip saddr limit rate 50/second burst 100 packets } accept"
            )
            rules.append("add rule inet filter input tcp flags syn drop")

        self.nftables_rules = rules

    def _gen_ufw_rules(self):
        """Generate ufw commands."""
        commands = []
        commands.append(f"ufw deny from {self.src_ip} to any")

        if self.anomaly_type in ("SYN Flood", "UDP Flood"):
            commands.append("ufw --force enable")
            commands.append("ufw default deny incoming")

        self.ufw_commands = commands

    def _gen_pf_rules(self):
        """Generate pf (macOS) rules."""
        rules = []
        rules.append(f"block in from {self.src_ip} to any")
        rules.append(f"block out from any to {self.src_ip}")

        if self.anomaly_type in ("SYN Flood", "UDP Flood", "ICMP Flood"):
            rules.append(
                "pass in on en0 proto tcp from any to any "
                "flags S/SA keep state "
                "(max-src-conn 100, max-src-conn-rate 50/10)"
            )
            rules.append("block in quick proto icmp all")

        self.pf_rules = rules

    def _gen_netsh_rules(self):
        """Generate Windows netsh commands."""
        commands = []
        commands.append(
            f"netsh advfirewall firewall add rule "
            f'name="Block {self.src_ip}" '
            f"dir=in action=block remoteip={self.src_ip}"
        )

        if self.anomaly_type in ("SYN Flood", "UDP Flood"):
            commands.append(
                "netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound"
            )

        self.netsh_commands = commands

    # ── Output ─────────────────────────────────────────────

    def to_dict(self) -> Dict:
        """Serialize to a JSON-compatible dict."""
        return {
            "anomaly_type": self.anomaly_type,
            "src_ip": self.src_ip,
            "dst_port": self.dst_port,
            "severity": self.severity,
            "timestamp": self.timestamp,
            "detected_os": self.os_name,
            "firewall_backend": self.backend,
            "recommendations": {
                "immediate": self.immediate,
                "hardening": self.hardening,
                "monitoring": self.monitoring,
            },
            "firewall_rules": {
                "iptables": self.iptables_rules,
                "nftables": self.nftables_rules,
                "ufw": self.ufw_commands,
                "pf": self.pf_rules,
                "netsh": self.netsh_commands,
            },
        }

    def summary(self) -> str:
        """Human-readable summary for console output."""
        lines = []
        lines.append(f"\n{'=' * 60}")
        lines.append(f"  PREVENTION: {self.anomaly_type}")
        lines.append(f"{'=' * 60}")
        lines.append(f"  Attacker:    {self.src_ip}")
        lines.append(f"  Target Port: {self.dst_port or 'N/A'}")
        lines.append(f"  Severity:    {self.severity}")
        lines.append(f"  OS:          {self.os_name}")
        lines.append(f"  Backend:     {self.backend}")

        lines.append("\n  [!!!] IMMEDIATE ACTIONS:")
        for i, rec in enumerate(self.immediate, 1):
            lines.append(f"    {i}. {rec}")

        lines.append("\n  [~] HARDENING:")
        for i, rec in enumerate(self.hardening, 1):
            lines.append(f"    {i}. {rec}")

        lines.append("\n  [i] MONITORING:")
        for i, rec in enumerate(self.monitoring, 1):
            lines.append(f"    {i}. {rec}")

        # Show rules for detected backend
        backend_rules = {
            "iptables": self.iptables_rules,
            "nftables": self.nftables_rules,
            "ufw": self.ufw_commands,
            "pf": self.pf_rules,
            "netsh": self.netsh_commands,
        }
        rules = backend_rules.get(self.backend, self.iptables_rules)
        if rules:
            lines.append(f"\n  [#] {self.backend.upper()} RULES (copy & run):")
            for rule in rules:
                lines.append(f"    $ {rule}")

        lines.append(f"{'=' * 60}\n")
        return "\n".join(lines)


# ── Prevention Engine ──────────────────────────────────────


class PreventionEngine:
    """
    Central engine that:
      1. Generates PreventionRecommendation for each anomaly
      2. Maintains a persistent blocklist
      3. Can auto-block attackers (with elevation)
      4. Exports rules to file for manual review
    """

    def __init__(self, auto_block: bool = False):
        self.auto_block = auto_block
        self.os_name = detect_os()
        self.backend = detect_firewall_backend()
        self._blocklist: List[Dict] = []
        self._load_blocklist()

    def _load_blocklist(self):
        """Load previously blocked IPs from disk."""
        if BLOCKLIST_FILE.exists():
            try:
                with open(BLOCKLIST_FILE, encoding="utf-8") as f:
                    self._blocklist = json.load(f)
                logger.info(f"Loaded {len(self._blocklist)} entries from blocklist")
            except Exception as e:
                logger.warning(f"Failed to load blocklist: {e}")
                self._blocklist = []

    def _save_blocklist(self):
        """Persist blocklist to disk."""
        BLOCKLIST_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(BLOCKLIST_FILE, "w", encoding="utf-8") as f:
            json.dump(self._blocklist, f, indent=2)

    def generate(self, anomaly: Dict) -> PreventionRecommendation:
        """
        Generate a full PreventionRecommendation for a detected anomaly.

        Args:
            anomaly: dict from the detection engine (needs anomaly_type,
                     src_ip, severity, and optionally dst_port)

        Returns:
            PreventionRecommendation with all tiers and rules
        """
        return PreventionRecommendation(
            anomaly_type=anomaly.get("anomaly_type", "Unknown"),
            src_ip=anomaly.get("src_ip", "unknown"),
            severity=anomaly.get("severity", "MEDIUM"),
            dst_port=anomaly.get("dst_port", 0),
        )

    def auto_block(self, anomaly: Dict) -> Dict:
        """
        Attempt to auto-block an attacker IP using the detected firewall backend.

        Returns a dict with status and the commands that were/would be run.
        """
        src_ip = anomaly.get("src_ip", "")
        if not src_ip or src_ip == "127.0.0.1":
            return {"status": "skipped", "reason": "Cannot block loopback"}

        # Check if already blocked
        already_blocked = any(entry.get("ip") == src_ip for entry in self._blocklist)
        if already_blocked:
            return {"status": "already_blocked", "ip": src_ip}

        rec = self.generate(anomaly)
        commands = self._get_block_commands(src_ip, rec)

        result = {
            "ip": src_ip,
            "anomaly_type": anomaly.get("anomaly_type", ""),
            "severity": anomaly.get("severity", ""),
            "backend": self.backend,
            "commands": commands,
            "status": "pending",
        }

        if not self.auto_block:
            result["status"] = "dry_run"
            result["note"] = (
                "Auto-block is disabled. Run with --auto-block to apply. "
                "Commands listed above can be run manually."
            )
        else:
            # Execute the block commands
            try:
                for cmd in commands:
                    logger.info(f"Executing: {cmd}")
                    proc = subprocess.run(
                        cmd,
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=15,
                    )
                    if proc.returncode != 0:
                        result["status"] = "error"
                        result["error"] = proc.stderr.strip()
                        logger.error(f"Block command failed: {proc.stderr}")
                        return result

                result["status"] = "blocked"
                logger.warning(f"BLOCKED attacker IP: {src_ip}")

            except subprocess.TimeoutExpired:
                result["status"] = "error"
                result["error"] = "Command timed out"
            except Exception as e:
                result["status"] = "error"
                result["error"] = str(e)

        # Add to blocklist regardless
        self._blocklist.append(
            {
                "ip": src_ip,
                "anomaly_type": anomaly.get("anomaly_type", ""),
                "severity": anomaly.get("severity", ""),
                "timestamp": datetime.now(UTC).isoformat(),
                "backend": self.backend,
                "applied": result["status"] == "blocked",
            }
        )
        self._save_blocklist()

        return result

    def _get_block_commands(self, src_ip: str, rec: PreventionRecommendation) -> List[str]:
        """Get the appropriate block commands for the detected backend."""
        if self.backend == "iptables":
            return [
                f"iptables -A INPUT -s {src_ip} -j DROP",
                f"iptables -A FORWARD -s {src_ip} -j DROP",
            ]
        elif self.backend == "nftables":
            return [f"add rule inet filter input ip saddr {src_ip} drop"]
        elif self.backend == "ufw":
            return [f"ufw deny from {src_ip} to any"]
        elif self.backend == "pf":
            return [f"echo 'block in from {src_ip} to any' | pfctl -ef -"]
        elif self.backend == "netsh":
            return [
                f"netsh advfirewall firewall add rule "
                f'name="IDS-Block {src_ip}" '
                f"dir=in action=block remoteip={src_ip}"
            ]
        else:
            return [f"# Unknown backend — manual block needed for {src_ip}"]

    def export_rules(
        self,
        anomalies: List[Dict],
        output_path: str = "data/firewall_rules",
    ) -> str:
        """
        Export firewall rules for all anomalies to a runnable script.

        Generates:
          - {output_path}.sh  (Linux/macOS)
          - {output_path}.bat (Windows)
          - {output_path}.json (all rules as JSON)

        Returns the path of the primary script generated.
        """
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        recommendations = []
        for anomaly in anomalies:
            rec = self.generate(anomaly)
            recommendations.append(rec.to_dict())

        # ── JSON export ────────────────────────────────────
        json_path = out.with_suffix(".json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(recommendations, f, indent=2)
        logger.info(f"Exported {len(recommendations)} rules to {json_path}")

        # ── Shell script (Linux/macOS) ─────────────────────
        sh_path = out.with_suffix(".sh")
        with open(sh_path, "w", encoding="utf-8") as f:
            f.write("#!/bin/bash\n")
            f.write("# SIH26153 — Auto-Generated Firewall Rules\n")
            f.write(f"# Generated: {datetime.now(UTC).isoformat()}\n")
            f.write(f"# Backend: {self.backend}\n")
            f.write("# Review these rules before applying!\n\n")
            f.write("set -e\n\n")

            for rec in recommendations:
                f.write(f"# --- {rec['anomaly_type']} from {rec['src_ip']} ---\n")
                f.write(f"# Severity: {rec['severity']}\n")
                rules = rec.get("firewall_rules", {})
                backend_rules = rules.get(self.backend, rules.get("iptables", []))
                for rule in backend_rules:
                    f.write(f"{rule}\n")
                f.write("\n")

            f.write("\necho 'Firewall rules applied successfully.'\n")
        logger.info(f"Exported shell script to {sh_path}")

        # ── Windows batch ──────────────────────────────────
        bat_path = out.with_suffix(".bat")
        with open(bat_path, "w", encoding="utf-8") as f:
            f.write("@echo off\n")
            f.write("REM SIH26153 — Auto-Generated Firewall Rules\n")
            f.write(f"REM Generated: {datetime.now(UTC).isoformat()}\n")
            f.write("REM Review these rules before applying!\n\n")

            for rec in recommendations:
                f.write(f"REM --- {rec['anomaly_type']} from {rec['src_ip']} ---\n")
                f.write(f"REM Severity: {rec['severity']}\n")
                rules = rec.get("firewall_rules", {})
                for cmd in rules.get("netsh", []):
                    f.write(f"{cmd}\n")
                f.write("\n")

            f.write("\necho Firewall rules applied successfully.\n")
        logger.info(f"Exported batch script to {bat_path}")

        return str(sh_path)

    @property
    def blocklist(self) -> List[Dict]:
        return list(self._blocklist)

    def is_blocked(self, ip: str) -> bool:
        return any(entry.get("ip") == ip for entry in self._blocklist)

    def stats(self) -> Dict:
        return {
            "total_blocked": len(self._blocklist),
            "applied": sum(1 for e in self._blocklist if e.get("applied")),
            "pending": sum(1 for e in self._blocklist if not e.get("applied")),
            "os": self.os_name,
            "backend": self.backend,
            "auto_block_enabled": self.auto_block,
        }


# ── Legacy compatibility: replace get_prevention() ─────────


def get_prevention(anomaly_type: str, src_ip: str, dst_port: int = 0) -> List[str]:
    """
    Generate prevention recommendations (legacy API).

    Returns a flat list of human-readable recommendation strings.
    For structured output, use PreventionEngine.generate() instead.
    """
    rec = PreventionRecommendation(
        anomaly_type=anomaly_type,
        src_ip=src_ip,
        dst_port=dst_port,
    )
    # Flatten all tiers into a single list
    all_recs = []
    all_recs.extend(rec.immediate)
    all_recs.extend(rec.hardening)
    all_recs.extend(rec.monitoring)

    # Add the primary backend command at the top
    backend_rules = {
        "iptables": rec.iptables_rules,
        "nftables": rec.nftables_rules,
        "ufw": rec.ufw_commands,
        "pf": rec.pf_rules,
        "netsh": rec.netsh_commands,
    }
    rules = backend_rules.get(rec.backend, rec.iptables_rules)
    if rules:
        all_recs.insert(0, f"Run: {rules[0]}")

    return all_recs


# ── CLI Entry Point ────────────────────────────────────────


def main():
    """CLI for testing the prevention engine."""
    import argparse

    parser = argparse.ArgumentParser(
        description="SIH26153 — Prevention Recommendation Engine",
    )
    parser.add_argument("--type", default="SYN Scan", help="Anomaly type to simulate")
    parser.add_argument("--src-ip", default="192.168.1.100", help="Attacker IP")
    parser.add_argument("--dst-port", type=int, default=22, help="Targeted port")
    parser.add_argument("--severity", default="HIGH", help="Threat severity")
    parser.add_argument("--auto-block", action="store_true", help="Apply block rules")
    parser.add_argument("--export", default=None, help="Export rules to file prefix")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    engine = PreventionEngine(auto_block=args.auto_block)

    anomaly = {
        "anomaly_type": args.type,
        "src_ip": args.src_ip,
        "dst_port": args.dst_port,
        "severity": args.severity,
    }

    # Generate recommendation
    rec = engine.generate(anomaly)
    print(rec.summary())

    # Auto-block if requested
    if args.auto_block:
        result = engine.auto_block(anomaly)
        print(f"\nAuto-block result: {json.dumps(result, indent=2)}")

    # Export if requested
    if args.export:
        path = engine.export_rules([anomaly], output_path=args.export)
        print(f"\nRules exported to: {path}")
        print(f"  Review before applying: bash {path}")

    # Show blocklist stats
    stats = engine.stats()
    print(
        f"\nBlocklist: {stats['total_blocked']} IPs "
        f"({stats['applied']} applied, {stats['pending']} pending)"
    )


if __name__ == "__main__":
    main()
