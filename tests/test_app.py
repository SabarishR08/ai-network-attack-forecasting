"""Tests for integration.app Flask application."""

import json

import pytest


@pytest.fixture
def sample_data_dir(tmp_path, monkeypatch):
    """Set up a temporary data directory with sample data."""
    import integration.app as app_module

    # Create sample packets
    packets = [
        {
            "src_ip": "192.168.1.1",
            "dst_ip": "10.0.0.1",
            "dst_port": 80,
            "protocol": "TCP",
            "flags": "S",
            "payload_size": 64,
            "timestamp": "2024-01-15T10:00:00",
        }
    ]

    # Create sample anomalies
    anomalies = [
        {
            "src_ip": "192.168.1.1",
            "dst_ip": "10.0.0.1",
            "anomaly_type": "Port Scan",
            "severity": "HIGH",
            "timestamp": "2024-01-15T10:00:00",
            "confidence": 0.85,
        }
    ]

    # Create sample forecast features
    features = [
        {
            "src_ip": "192.168.1.1",
            "dst_ip": "10.0.0.1",
            "window_start": "2024-01-15T10:00:00",
            "window_end": "2024-01-15T10:00:30",
            "total_packets": 100,
            "port_diversity": 5,
            "connection_rate": 3.33,
            "syn_count": 50,
            "rst_count": 5,
            "syn_rst_ratio": 10.0,
            "payload_size_mean": 256.0,
            "payload_size_max": 1024,
            "escalation_probability": 0.85,
            "escalation_predicted": True,
        }
    ]

    # Write files
    packets_file = tmp_path / "packets.jsonl"
    anomalies_file = tmp_path / "anomalies.jsonl"
    features_file = tmp_path / "forecast_features.jsonl"
    incidents_file = tmp_path / "killchain_incidents.jsonl"

    with open(packets_file, "w") as f:
        for p in packets:
            f.write(json.dumps(p) + "\n")
    with open(anomalies_file, "w") as f:
        for a in anomalies:
            f.write(json.dumps(a) + "\n")
    with open(features_file, "w") as f:
        for feat in features:
            f.write(json.dumps(feat) + "\n")
    with open(incidents_file, "w") as f:
        json.dump([], f)

    # Monkeypatch the config paths
    monkeypatch.setattr(app_module, "PACKETS_FILE", packets_file)
    monkeypatch.setattr(app_module, "ANOMALIES_FILE", anomalies_file)
    monkeypatch.setattr(app_module, "FEATURES_FILE", features_file)
    monkeypatch.setattr(app_module, "KILLCHAIN_INCIDENTS_FILE", incidents_file)

    return {
        "packets": packets_file,
        "anomalies": anomalies_file,
        "features": features_file,
        "incidents": incidents_file,
    }


class TestPageRoutes:
    """Test HTML page routes."""

    def test_index_page(self, client):
        response = client.get("/")
        assert response.status_code == 200

    def test_events_page(self, client):
        response = client.get("/events")
        assert response.status_code == 200

    def test_graph_page(self, client):
        response = client.get("/graph")
        assert response.status_code == 200

    def test_killchain_page(self, client):
        response = client.get("/killchain")
        assert response.status_code == 200


class TestAPIStatus:
    """Test /api/status endpoint."""

    def test_status_returns_json(self, client):
        response = client.get("/api/status")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert "status" in data
        assert data["status"] == "running"

    def test_status_has_required_fields(self, client):
        response = client.get("/api/status")
        data = json.loads(response.data)
        assert "packets_file" in data
        assert "anomalies_file" in data
        assert "features_file" in data
        assert "server_time" in data


class TestAPIDashboard:
    """Test /api/dashboard endpoint."""

    def test_dashboard_with_data(self, client, sample_data_dir):
        response = client.get("/api/dashboard")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert "traffic" in data
        assert "anomalies" in data
        assert "forecast" in data
        assert "generated_at" in data

    def test_dashboard_traffic_counts(self, client, sample_data_dir):
        response = client.get("/api/dashboard")
        data = json.loads(response.data)
        assert data["traffic"]["total_packets"] == 1
        assert data["traffic"]["unique_src_ips"] == 1

    def test_dashboard_anomaly_counts(self, client, sample_data_dir):
        response = client.get("/api/dashboard")
        data = json.loads(response.data)
        assert data["anomalies"]["total"] == 1
        assert data["anomalies"]["by_severity"]["HIGH"] == 1

    def test_dashboard_empty_data(self, client):
        response = client.get("/api/dashboard")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert "traffic" in data
        assert "anomalies" in data


class TestAPIAnomalies:
    """Test /api/anomalies endpoint."""

    def test_anomalies_returns_list(self, client, sample_data_dir):
        response = client.get("/api/anomalies")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert isinstance(data, list)

    def test_anomalies_filter_by_severity(self, client, sample_data_dir):
        response = client.get("/api/anomalies?severity=HIGH")
        data = json.loads(response.data)
        assert len(data) == 1
        assert data[0]["severity"] == "HIGH"

    def test_anomalies_limit(self, client, sample_data_dir):
        response = client.get("/api/anomalies?limit=0")
        data = json.loads(response.data)
        assert isinstance(data, list)


class TestAPIForecast:
    """Test /api/forecast endpoint."""

    def test_forecast_returns_list(self, client, sample_data_dir):
        response = client.get("/api/forecast")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert isinstance(data, list)

    def test_forecast_flagged_filter(self, client, sample_data_dir):
        response = client.get("/api/forecast?flagged=1")
        data = json.loads(response.data)
        for feat in data:
            assert feat.get("escalation_predicted") is True


class TestAPIPackets:
    """Test /api/packets endpoint."""

    def test_packets_returns_list(self, client, sample_data_dir):
        response = client.get("/api/packets")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert isinstance(data, list)
        assert len(data) == 1

    def test_packets_limit(self, client, sample_data_dir):
        response = client.get("/api/packets?limit=1")
        data = json.loads(response.data)
        assert len(data) <= 1


class TestAPIGraph:
    """Test /api/graph endpoint."""

    def test_graph_returns_nodes_and_edges(self, client, sample_data_dir):
        response = client.get("/api/graph")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert "nodes" in data
        assert "edges" in data
        assert len(data["nodes"]) > 0
        assert len(data["edges"]) > 0

    def test_graph_node_structure(self, client, sample_data_dir):
        response = client.get("/api/graph")
        data = json.loads(response.data)
        for node in data["nodes"]:
            assert "id" in node
            assert "type" in node
            assert node["type"] in ("attacker", "target")

    def test_graph_edge_structure(self, client, sample_data_dir):
        response = client.get("/api/graph")
        data = json.loads(response.data)
        for edge in data["edges"]:
            assert "from" in edge
            assert "to" in edge
            assert "severity" in edge


class TestHelperFunctions:
    """Test internal helper functions."""

    def test_severity_color(self, client):
        from integration.app import _severity_color

        assert _severity_color("CRITICAL") == "#ef4444"
        assert _severity_color("HIGH") == "#f97316"
        assert _severity_color("MEDIUM") == "#eab308"
        assert _severity_color("LOW") == "#22c55e"
        assert _severity_color("UNKNOWN") == "#6b7280"

    def test_load_jsonl_valid(self, tmp_path):
        from integration.app import _load_jsonl

        data_file = tmp_path / "test.jsonl"
        with open(data_file, "w") as f:
            f.write('{"key": "value1"}\n')
            f.write('{"key": "value2"}\n')
            f.write("\n")  # empty line
            f.write("invalid json\n")
        result = _load_jsonl(data_file)
        assert len(result) == 2

    def test_load_jsonl_nonexistent(self, tmp_path):
        from integration.app import _load_jsonl

        result = _load_jsonl(tmp_path / "nonexistent.jsonl")
        assert result == []

    def test_load_json_valid(self, tmp_path):
        from integration.app import _load_json

        data_file = tmp_path / "test.json"
        with open(data_file, "w") as f:
            json.dump({"key": "value"}, f)
        result = _load_json(data_file)
        assert result == {"key": "value"}

    def test_load_json_nonexistent(self, tmp_path):
        from integration.app import _load_json

        result = _load_json(tmp_path / "nonexistent.json")
        assert result == []
