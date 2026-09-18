"""End-to-end integration tests for the full SIH26153 pipeline.

These tests create realistic mock data, run the pipeline steps,
and verify that all API responses are correct and consistent.
"""

import json
from datetime import datetime, timedelta

import pytest

from integration.app import app

# ── Fixtures ─────────────────────────────────────────────────


@pytest.fixture
def client():
    """Create a Flask test client."""
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def _make_packets(n=50, base_ts="2024-01-15T10:00:00"):
    """Generate realistic synthetic packet data."""
    import random

    random.seed(42)

    src_ips = [f"192.168.1.{i}" for i in range(1, 11)]
    dst_ips = [f"10.0.0.{i}" for i in range(1, 6)]
    protocols = ["TCP", "UDP", "ICMP"]
    flags_list = ["S", "SA", "A", "R", "F", "P"]
    ports = [22, 80, 443, 3306, 8080, 8443, 3389, 21, 25, 53]

    base = datetime.fromisoformat(base_ts)
    packets = []
    for i in range(n):
        offset = timedelta(seconds=i * 0.5)
        pkt = {
            "src_ip": random.choice(src_ips),
            "dst_ip": random.choice(dst_ips),
            "dst_port": random.choice(ports),
            "protocol": random.choice(protocols),
            "flags": random.choice(flags_list),
            "payload_size": random.randint(32, 1500),
            "timestamp": (base + offset).isoformat(),
        }
        packets.append(pkt)
    return packets


def _make_anomalies(n=15, base_ts="2024-01-15T10:00:00"):
    """Generate realistic anomaly records."""
    import random

    random.seed(42)

    types_sev = [
        ("Port Scan", "HIGH"),
        ("Brute Force", "CRITICAL"),
        ("Connection Cycling", "MEDIUM"),
        ("Suspicious Connection", "LOW"),
        ("Port Scan", "MEDIUM"),
        ("Brute Force", "HIGH"),
    ]

    base = datetime.fromisoformat(base_ts)
    anomalies = []
    for i in range(n):
        atype, sev = types_sev[i % len(types_sev)]
        offset = timedelta(seconds=i * 5)
        anom = {
            "src_ip": f"192.168.1.{(i % 10) + 1}",
            "dst_ip": f"10.0.0.{(i % 5) + 1}",
            "anomaly_type": atype,
            "severity": sev,
            "timestamp": (base + offset).isoformat(),
            "confidence": round(random.uniform(0.5, 0.99), 2),
        }
        if atype == "Port Scan":
            anom["ports_scanned"] = sorted(random.sample(range(1, 1024), 5))
            anom["port_count"] = len(anom["ports_scanned"])
        elif atype == "Brute Force":
            anom["dst_port"] = random.choice([22, 3389, 21])
            anom["failed_attempts"] = random.randint(5, 50)
            anom["service"] = random.choice(["SSH", "RDP", "FTP"])
        anomalies.append(anom)
    return anomalies


def _make_features(n=20, flagged_ratio=0.3, base_ts="2024-01-15T10:00:00"):
    """Generate forecast feature vectors."""
    import random

    random.seed(42)

    base = datetime.fromisoformat(base_ts)
    features = []
    for i in range(n):
        is_flagged = i < int(n * flagged_ratio)
        prob = (
            round(random.uniform(0.6, 0.95), 4)
            if is_flagged
            else round(random.uniform(0.01, 0.4), 4)
        )
        offset = timedelta(seconds=i * 30)
        feat = {
            "src_ip": f"192.168.1.{(i % 10) + 1}",
            "dst_ip": f"10.0.0.{(i % 5) + 1}",
            "window_start": (base + offset).isoformat(),
            "window_end": (base + offset + timedelta(seconds=30)).isoformat(),
            "window_duration_sec": 30.0,
            "total_packets": random.randint(10, 200),
            "port_diversity": random.randint(1, 20),
            "unique_ports": sorted(random.sample(range(1, 1024), random.randint(1, 5))),
            "connection_rate": round(random.uniform(0.1, 10.0), 4),
            "syn_count": random.randint(0, 50),
            "rst_count": random.randint(0, 10),
            "syn_rst_ratio": round(random.uniform(0.5, 20.0), 4),
            "payload_size_mean": round(random.uniform(50.0, 800.0), 2),
            "payload_size_max": random.randint(100, 1500),
            "escalation_probability": prob,
            "escalation_predicted": is_flagged,
            "escalation_label": 1 if is_flagged else 0,
        }
        features.append(feat)
    return features


def _make_incidents(n=5):
    """Generate killchain incident records."""
    techniques = [
        {"technique_id": "T1046", "technique_name": "Network Service Scanning"},
        {"technique_id": "T1110", "technique_name": "Brute Force"},
        {"technique_id": "T1021", "technique_name": "Remote Services"},
    ]
    stages = ["Reconnaissance", "Exploitation", "Delivery", "Command and Control"]

    incidents = []
    for i in range(n):
        tech = techniques[i % len(techniques)]
        incidents.append(
            {
                "pattern": f"incident_{i}",
                "entity": f"192.168.1.{i + 1}",
                "risk_score": round(50 + i * 10, 1),
                "priority": "high" if i < 2 else "medium",
                "kill_chain_stage": stages[i % len(stages)],
                "mitre": {
                    "technique_id": tech["technique_id"],
                    "technique_name": tech["technique_name"],
                },
                "event_count": i + 2,
            }
        )
    return incidents


@pytest.fixture
def full_mock_data(tmp_path, monkeypatch):
    """Create a complete set of mock data files and patch all config paths."""
    import integration.app as app_module

    packets = _make_packets(50)
    anomalies = _make_anomalies(15)
    features = _make_features(20, flagged_ratio=0.3)
    incidents = _make_incidents(5)

    files = {}
    for name, data, fmt in [
        ("packets", packets, "jsonl"),
        ("anomalies", anomalies, "jsonl"),
        ("features", features, "jsonl"),
    ]:
        fpath = tmp_path / f"{name}.jsonl"
        with open(fpath, "w") as f:
            for item in data:
                f.write(json.dumps(item) + "\n")
        files[name] = fpath

    incidents_path = tmp_path / "killchain_incidents.jsonl"
    with open(incidents_path, "w") as f:
        json.dump(incidents, f)
    files["incidents"] = incidents_path

    graph_path = tmp_path / "graph.json"
    files["graph"] = graph_path

    # Patch all config references in app module
    monkeypatch.setattr(app_module, "PACKETS_FILE", files["packets"])
    monkeypatch.setattr(app_module, "ANOMALIES_FILE", files["anomalies"])
    monkeypatch.setattr(app_module, "FEATURES_FILE", files["features"])
    monkeypatch.setattr(app_module, "KILLCHAIN_INCIDENTS_FILE", files["incidents"])
    monkeypatch.setattr(app_module, "GRAPH_JSON", files["graph"])

    return {
        "packets": packets,
        "anomalies": anomalies,
        "features": features,
        "incidents": incidents,
        "files": files,
    }


@pytest.fixture
def multi_attacker_data(tmp_path, monkeypatch):
    """Create data with multiple distinct attackers for graph testing."""
    import integration.app as app_module

    packets = []
    anomalies = []
    attackers = ["192.168.1.10", "192.168.1.20", "10.10.10.5"]
    targets = ["172.16.0.1", "172.16.0.2"]

    for i, src in enumerate(attackers):
        for j, dst in enumerate(targets):
            for k in range(5):
                ts = f"2024-01-15T10:0{i}:{j * 30 + k:02d}"
                packets.append(
                    {
                        "src_ip": src,
                        "dst_ip": dst,
                        "dst_port": 80 + k,
                        "protocol": "TCP",
                        "flags": "S",
                        "payload_size": 64,
                        "timestamp": ts,
                    }
                )
            anomalies.append(
                {
                    "src_ip": src,
                    "dst_ip": dst,
                    "anomaly_type": "Port Scan" if i % 2 == 0 else "Brute Force",
                    "severity": ["HIGH", "CRITICAL", "MEDIUM"][i % 3],
                    "timestamp": f"2024-01-15T10:0{i}:{j * 30:02d}",
                    "confidence": 0.9,
                }
            )

    # Write files
    packets_file = tmp_path / "packets.jsonl"
    anomalies_file = tmp_path / "anomalies.jsonl"
    features_file = tmp_path / "features.jsonl"
    incidents_file = tmp_path / "incidents.jsonl"
    graph_file = tmp_path / "graph.json"

    with open(packets_file, "w") as f:
        for p in packets:
            f.write(json.dumps(p) + "\n")
    with open(anomalies_file, "w") as f:
        for a in anomalies:
            f.write(json.dumps(a) + "\n")
    features_file.write_text("")
    with open(incidents_file, "w") as f:
        json.dump([], f)

    monkeypatch.setattr(app_module, "PACKETS_FILE", packets_file)
    monkeypatch.setattr(app_module, "ANOMALIES_FILE", anomalies_file)
    monkeypatch.setattr(app_module, "FEATURES_FILE", features_file)
    monkeypatch.setattr(app_module, "KILLCHAIN_INCIDENTS_FILE", incidents_file)
    monkeypatch.setattr(app_module, "GRAPH_JSON", graph_file)

    return {
        "packets": packets,
        "anomalies": anomalies,
        "files": {
            "packets": packets_file,
            "anomalies": anomalies_file,
            "features": features_file,
            "incidents": incidents_file,
            "graph": graph_file,
        },
    }


# ── Full Pipeline E2E Tests ────────────────────────────────────


class TestFullDashboardResponse:
    """Verify the /api/dashboard endpoint returns correct aggregated data."""

    def test_dashboard_sections(self, client, full_mock_data):
        resp = client.get("/api/dashboard")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        for section in ["traffic", "anomalies", "forecast", "killchain", "model_a"]:
            assert section in data, f"Missing section: {section}"
        assert "generated_at" in data

    def test_dashboard_traffic_accuracy(self, client, full_mock_data):
        resp = client.get("/api/dashboard")
        data = json.loads(resp.data)
        traffic = data["traffic"]

        assert traffic["total_packets"] == len(full_mock_data["packets"])
        src_ips = {p["src_ip"] for p in full_mock_data["packets"]}
        dst_ips = {p["dst_ip"] for p in full_mock_data["packets"]}
        assert traffic["unique_src_ips"] == len(src_ips)
        assert traffic["unique_dst_ips"] == len(dst_ips)

        # Verify protocol counts
        expected_protocols = {}
        for p in full_mock_data["packets"]:
            proto = p.get("protocol", "Other")
            expected_protocols[proto] = expected_protocols.get(proto, 0) + 1
        assert traffic["protocols"] == expected_protocols

    def test_dashboard_anomaly_accuracy(self, client, full_mock_data):
        resp = client.get("/api/dashboard")
        data = json.loads(resp.data)
        anomalies = data["anomalies"]

        assert anomalies["total"] == len(full_mock_data["anomalies"])

        # Verify by_type counts
        expected_types = {}
        for a in full_mock_data["anomalies"]:
            t = a["anomaly_type"]
            expected_types[t] = expected_types.get(t, 0) + 1
        assert anomalies["by_type"] == expected_types

        # Verify by_severity counts
        expected_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for a in full_mock_data["anomalies"]:
            s = a["severity"].upper()
            if s in expected_sev:
                expected_sev[s] += 1
        assert anomalies["by_severity"] == expected_sev

    def test_dashboard_forecast_accuracy(self, client, full_mock_data):
        resp = client.get("/api/dashboard")
        data = json.loads(resp.data)
        forecast = data["forecast"]

        features = full_mock_data["features"]
        assert forecast["total_windows"] == len(features)

        flagged = sum(1 for f in features if f["escalation_predicted"])
        assert forecast["escalation_predicted"] == flagged

        avg_prob = sum(f["escalation_probability"] for f in features) / len(features)
        assert abs(forecast["avg_escalation_prob"] - round(avg_prob, 4)) < 0.0001

    def test_dashboard_killchain_accuracy(self, client, full_mock_data):
        resp = client.get("/api/dashboard")
        data = json.loads(resp.data)
        kc = data["killchain"]

        incidents = full_mock_data["incidents"]
        assert kc["total_incidents"] == len(incidents)

        # Verify MITRE technique IDs
        expected_techs = set()
        for inc in incidents:
            tid = (inc.get("mitre") or {}).get("technique_id", "")
            if tid and tid != "UNKNOWN":
                expected_techs.add(tid)
        assert kc["mitre_techniques"] == sorted(expected_techs)

        # Verify stages
        expected_stages = {}
        for inc in incidents:
            stage = inc.get("kill_chain_stage", "Unknown")
            expected_stages[stage] = expected_stages.get(stage, 0) + 1
        assert kc["stages"] == expected_stages

    def test_dashboard_timeline(self, client, full_mock_data):
        resp = client.get("/api/dashboard")
        data = json.loads(resp.data)
        timeline = data["anomalies"]["timeline"]

        # Timeline should be sorted by timestamp
        timestamps = [t["t"] for t in timeline]
        assert timestamps == sorted(timestamps)

        # Each entry should have 't' and 'v'
        for entry in timeline:
            assert "t" in entry
            assert "v" in entry
            assert entry["v"] > 0


class TestAnomaliesEndpoint:
    """Verify /api/anomalies filtering and pagination."""

    def test_returns_all(self, client, full_mock_data):
        resp = client.get("/api/anomalies")
        data = json.loads(resp.data)
        assert len(data) == len(full_mock_data["anomalies"])

    def test_filter_high_severity(self, client, full_mock_data):
        resp = client.get("/api/anomalies?severity=HIGH")
        data = json.loads(resp.data)
        for a in data:
            assert a["severity"] == "HIGH"
        assert len(data) > 0

    def test_filter_critical_severity(self, client, full_mock_data):
        resp = client.get("/api/anomalies?severity=CRITICAL")
        data = json.loads(resp.data)
        for a in data:
            assert a["severity"] == "CRITICAL"

    def test_filter_nonexistent_severity_returns_400(self, client, full_mock_data):
        resp = client.get("/api/anomalies?severity=NONE")
        assert resp.status_code == 400
        data = json.loads(resp.data)
        assert data["error"] is True

    def test_limit(self, client, full_mock_data):
        resp = client.get("/api/anomalies?limit=3")
        data = json.loads(resp.data)
        assert len(data) == 3

    def test_limit_zero_returns_all(self, client, full_mock_data):
        # limit=0 means rows[-0:] which is all rows in Python slicing
        resp = client.get("/api/anomalies?limit=0")
        data = json.loads(resp.data)
        assert len(data) == len(full_mock_data["anomalies"])

    def test_limit_exceeds_data(self, client, full_mock_data):
        resp = client.get("/api/anomalies?limit=9999")
        data = json.loads(resp.data)
        assert len(data) == len(full_mock_data["anomalies"])


class TestForecastEndpoint:
    """Verify /api/forecast filtering."""

    def test_returns_all(self, client, full_mock_data):
        resp = client.get("/api/forecast")
        data = json.loads(resp.data)
        assert len(data) == len(full_mock_data["features"])

    def test_flagged_only(self, client, full_mock_data):
        resp = client.get("/api/forecast?flagged=1")
        data = json.loads(resp.data)
        assert len(data) > 0
        for f in data:
            assert f["escalation_predicted"] is True

    def test_unflagged_only(self, client, full_mock_data):
        resp = client.get("/api/forecast?flagged=0")
        data = json.loads(resp.data)
        assert len(data) == len(full_mock_data["features"])

    def test_limit(self, client, full_mock_data):
        resp = client.get("/api/forecast?limit=5")
        data = json.loads(resp.data)
        assert len(data) == 5

    def test_has_forecast_fields(self, client, full_mock_data):
        resp = client.get("/api/forecast")
        data = json.loads(resp.data)
        for f in data:
            assert "escalation_probability" in f
            assert "escalation_predicted" in f
            assert 0.0 <= f["escalation_probability"] <= 1.0


class TestPacketsEndpoint:
    """Verify /api/packets endpoint."""

    def test_returns_all(self, client, full_mock_data):
        resp = client.get("/api/packets")
        data = json.loads(resp.data)
        assert len(data) == len(full_mock_data["packets"])

    def test_limit(self, client, full_mock_data):
        resp = client.get("/api/packets?limit=10")
        data = json.loads(resp.data)
        assert len(data) == 10

    def test_packet_structure(self, client, full_mock_data):
        resp = client.get("/api/packets?limit=1")
        data = json.loads(resp.data)
        pkt = data[0]
        for key in ["src_ip", "dst_ip", "dst_port", "protocol", "flags", "timestamp"]:
            assert key in pkt


class TestGraphEndpoint:
    """Verify /api/graph builds correct node-link structure."""

    def test_graph_structure(self, client, full_mock_data):
        resp = client.get("/api/graph")
        data = json.loads(resp.data)
        assert "nodes" in data
        assert "edges" in data

    def test_graph_node_types(self, client, multi_attacker_data):
        resp = client.get("/api/graph")
        data = json.loads(resp.data)
        node_types = {n["type"] for n in data["nodes"]}
        assert "attacker" in node_types
        assert "target" in node_types

    def test_graph_deduplicates_nodes(self, client, multi_attacker_data):
        resp = client.get("/api/graph")
        data = json.loads(resp.data)
        node_ids = [n["id"] for n in data["nodes"]]
        assert len(node_ids) == len(set(node_ids))

    def test_graph_edge_attributes(self, client, multi_attacker_data):
        resp = client.get("/api/graph")
        data = json.loads(resp.data)
        for edge in data["edges"]:
            assert "from" in edge
            assert "to" in edge
            assert "label" in edge
            assert "severity" in edge
            assert "color" in edge
            assert edge["color"].startswith("#")

    def test_graph_multiple_attackers(self, client, multi_attacker_data):
        resp = client.get("/api/graph")
        data = json.loads(resp.data)
        attackers = [n for n in data["nodes"] if n["type"] == "attacker"]
        assert len(attackers) == 3  # 3 distinct attackers

    def test_graph_from_prebuilt_json(self, client, full_mock_data):
        """If graph.json exists, it should be used instead of on-the-fly building."""
        # Write a pre-built graph
        graph_path = full_mock_data["files"]["graph"]
        prebuilt = {
            "nodes": [{"id": "prebuilt_node", "type": "attacker", "label": "Prebuilt"}],
            "edges": [],
        }
        with open(graph_path, "w") as f:
            json.dump(prebuilt, f)

        resp = client.get("/api/graph")
        data = json.loads(resp.data)
        assert len(data["nodes"]) == 1
        assert data["nodes"][0]["id"] == "prebuilt_node"


class TestIncidentsEndpoint:
    """Verify /api/incidents endpoint."""

    def test_returns_incidents(self, client, full_mock_data):
        resp = client.get("/api/incidents")
        data = json.loads(resp.data)
        assert isinstance(data, list)
        assert len(data) == len(full_mock_data["incidents"])

    def test_incident_structure(self, client, full_mock_data):
        resp = client.get("/api/incidents")
        data = json.loads(resp.data)
        for inc in data:
            assert "pattern" in inc
            assert "entity" in inc
            assert "risk_score" in inc


class TestStatusEndpoint:
    """Verify /api/status health check."""

    def test_status_running(self, client):
        resp = client.get("/api/status")
        data = json.loads(resp.data)
        assert data["status"] == "running"
        assert "server_time" in data
        # Verify server_time is valid ISO format
        ts = data["server_time"].rstrip("Z")
        datetime.fromisoformat(ts)

    def test_status_file_detection(self, client, full_mock_data):
        resp = client.get("/api/status")
        data = json.loads(resp.data)
        assert data["packets_file"] is True
        assert data["anomalies_file"] is True
        assert data["features_file"] is True

    def test_status_missing_files(self, client):
        resp = client.get("/api/status")
        data = json.loads(resp.data)
        # When no mock data, files don't exist
        assert isinstance(data["packets_file"], bool)


class TestRunPipelineEndpoint:
    """Verify /api/run-pipeline POST endpoint."""

    def test_pipeline_returns_result(self, client, monkeypatch):
        import integration.model_forecaster as mf
        import integration.pipeline_runner as pr
        from integration.ratelimit import get_counter

        get_counter().clear()  # Reset rate limiter for this test
        monkeypatch.setattr(mf, "ENABLE_FORECASTING_MODEL", False)
        monkeypatch.setattr(pr, "ENABLE_FORECASTING_MODEL", False)
        monkeypatch.setattr(pr, "ENABLE_KILLCHAIN", False)

        resp = client.post("/api/run-pipeline")
        data = json.loads(resp.data)
        assert "status" in data
        assert data["status"] in ("ok", "error")

    def test_pipeline_invalid_method(self, client):
        resp = client.get("/api/run-pipeline")
        assert resp.status_code == 405  # Method Not Allowed


class TestSSEStreamEndpoint:
    """Verify /api/stream returns correct SSE headers."""

    def test_stream_headers(self, client, full_mock_data):
        resp = client.get("/api/stream")
        assert resp.status_code == 200
        assert resp.mimetype == "text/event-stream"
        assert resp.headers.get("Cache-Control") == "no-cache"
        assert resp.headers.get("X-Accel-Buffering") == "no"


class TestPageRoutes:
    """Verify all HTML pages render correctly."""

    def test_index(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert b"<!DOCTYPE html>" in resp.data or b"<html" in resp.data

    def test_events(self, client):
        resp = client.get("/events")
        assert resp.status_code == 200

    def test_graph(self, client):
        resp = client.get("/graph")
        assert resp.status_code == 200

    def test_killchain(self, client):
        resp = client.get("/killchain")
        assert resp.status_code == 200


class TestCrossEndpointConsistency:
    """Verify data consistency across different API endpoints."""

    def test_anomaly_count_matches_dashboard(self, client, full_mock_data):
        dash = json.loads(client.get("/api/dashboard").data)
        anom = json.loads(client.get("/api/anomalies").data)
        assert dash["anomalies"]["total"] == len(anom)

    def test_forecast_count_matches_dashboard(self, client, full_mock_data):
        dash = json.loads(client.get("/api/dashboard").data)
        forecast = json.loads(client.get("/api/forecast").data)
        assert dash["forecast"]["total_windows"] == len(forecast)

    def test_incident_count_matches_dashboard(self, client, full_mock_data):
        dash = json.loads(client.get("/api/dashboard").data)
        incidents = json.loads(client.get("/api/incidents").data)
        assert dash["killchain"]["total_incidents"] == len(incidents)

    def test_packet_count_matches_dashboard(self, client, full_mock_data):
        dash = json.loads(client.get("/api/dashboard").data)
        packets = json.loads(client.get("/api/packets").data)
        assert dash["traffic"]["total_packets"] == len(packets)

    def test_flagged_forecast_subset_of_total(self, client, full_mock_data):
        all_feat = json.loads(client.get("/api/forecast").data)
        flagged = json.loads(client.get("/api/forecast?flagged=1").data)
        assert len(flagged) <= len(all_feat)
        assert len(flagged) > 0

    def test_anomaly_severity_filter_subset(self, client, full_mock_data):
        all_anom = json.loads(client.get("/api/anomalies").data)
        high = json.loads(client.get("/api/anomalies?severity=HIGH").data)
        critical = json.loads(client.get("/api/anomalies?severity=CRITICAL").data)
        medium = json.loads(client.get("/api/anomalies?severity=MEDIUM").data)
        low = json.loads(client.get("/api/anomalies?severity=LOW").data)
        assert len(high) + len(critical) + len(medium) + len(low) == len(all_anom)


class TestEmptyDataScenario:
    """Verify behavior with simulated data (from simulate_attack.py)."""

    def test_dashboard_has_data(self, client):
        resp = client.get("/api/dashboard")
        data = json.loads(resp.data)
        assert "traffic" in data
        assert "anomalies" in data
        assert "forecast" in data

    def test_anomalies_returns_list(self, client):
        resp = client.get("/api/anomalies")
        data = json.loads(resp.data)
        assert isinstance(data, list)

    def test_forecast_returns_list(self, client):
        resp = client.get("/api/forecast")
        data = json.loads(resp.data)
        assert isinstance(data, list)

    def test_packets_returns_list(self, client):
        resp = client.get("/api/packets")
        data = json.loads(resp.data)
        assert isinstance(data, list)

    def test_graph_returns_dict(self, client):
        resp = client.get("/api/graph")
        data = json.loads(resp.data)
        assert "nodes" in data
        assert "edges" in data

    def test_incidents_returns_list(self, client):
        resp = client.get("/api/incidents")
        data = json.loads(resp.data)
        assert isinstance(data, list)
