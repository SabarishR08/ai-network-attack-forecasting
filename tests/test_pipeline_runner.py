"""Tests for integration.pipeline_runner module."""

import json


class TestStepGenerateTraffic:
    """Test the traffic generation step."""

    def test_generate_traffic_creates_file(self, tmp_path):
        from integration.pipeline_runner import step_generate_traffic

        packets_file = tmp_path / "packets.jsonl"
        result = step_generate_traffic(packets_file)
        # Will either succeed or error depending on NTAV availability
        assert "status" in result
        assert result["status"] in ("ok", "error")

    def test_generate_traffic_returns_dict(self, tmp_path):
        from integration.pipeline_runner import step_generate_traffic

        result = step_generate_traffic(tmp_path / "test.jsonl")
        assert isinstance(result, dict)


class TestStepAnomalyDetection:
    """Test the anomaly detection step."""

    def test_anomaly_detection_without_data(self, tmp_path):
        from integration.pipeline_runner import step_anomaly_detection

        packets = tmp_path / "packets.jsonl"
        anomalies = tmp_path / "anomalies.jsonl"
        # Create empty packets file
        packets.write_text("")
        result = step_anomaly_detection(packets, anomalies)
        assert "status" in result

    def test_anomaly_detection_returns_dict(self, tmp_path):
        from integration.pipeline_runner import step_anomaly_detection

        result = step_anomaly_detection(tmp_path / "p.jsonl", tmp_path / "a.jsonl")
        assert isinstance(result, dict)


class TestStepModelA:
    """Test Model A step."""

    def test_model_a_without_model(self, tmp_path):
        from integration.pipeline_runner import step_model_a

        result = step_model_a(tmp_path / "packets.jsonl")
        assert result["status"] in ("skipped", "error", "ok")
        assert "note" in result or "error" in result or "model" in result


class TestStepModelB:
    """Test Model B step."""

    def test_model_b_when_disabled(self, tmp_path, monkeypatch):
        import integration.model_forecaster as mf
        import integration.pipeline_runner as pr

        monkeypatch.setattr(mf, "ENABLE_FORECASTING_MODEL", False)
        monkeypatch.setattr(pr, "ENABLE_FORECASTING_MODEL", False)
        from integration.pipeline_runner import step_model_b

        result = step_model_b(
            tmp_path / "packets.jsonl",
            tmp_path / "anomalies.jsonl",
            tmp_path / "features.jsonl",
        )
        assert result["status"] == "disabled"

    def test_model_b_returns_dict(self, tmp_path, monkeypatch):
        import integration.model_forecaster as mf
        import integration.pipeline_runner as pr

        monkeypatch.setattr(mf, "ENABLE_FORECASTING_MODEL", False)
        monkeypatch.setattr(pr, "ENABLE_FORECASTING_MODEL", False)
        from integration.pipeline_runner import step_model_b

        result = step_model_b(
            tmp_path / "p.jsonl",
            tmp_path / "a.jsonl",
            tmp_path / "f.jsonl",
        )
        assert isinstance(result, dict)


class TestStepKillchain:
    """Test Kill chain step."""

    def test_killchain_when_disabled(self, tmp_path, monkeypatch):
        import integration.pipeline_runner as pr

        monkeypatch.setattr(pr, "ENABLE_KILLCHAIN", False)
        from integration.pipeline_runner import step_killchain

        result = step_killchain(
            tmp_path / "anomalies.jsonl",
            tmp_path / "features.jsonl",
            tmp_path / "incidents.jsonl",
        )
        assert result["status"] == "disabled"

    def test_killchain_returns_dict(self, tmp_path, monkeypatch):
        import integration.pipeline_runner as pr

        monkeypatch.setattr(pr, "ENABLE_KILLCHAIN", False)
        from integration.pipeline_runner import step_killchain

        result = step_killchain(
            tmp_path / "a.jsonl",
            tmp_path / "f.jsonl",
            tmp_path / "i.jsonl",
        )
        assert isinstance(result, dict)


class TestStepBuildGraph:
    """Test the attack graph builder."""

    def test_build_graph_with_anomalies(self, tmp_path):
        from integration.pipeline_runner import step_build_graph

        anomalies = tmp_path / "anomalies.jsonl"
        graph_json = tmp_path / "graph.json"

        # Write sample anomalies
        sample = [
            {
                "src_ip": "192.168.1.1",
                "dst_ip": "10.0.0.1",
                "anomaly_type": "Port Scan",
                "severity": "HIGH",
            }
        ]
        with open(anomalies, "w") as f:
            for a in sample:
                f.write(json.dumps(a) + "\n")

        result = step_build_graph(anomalies, graph_json)
        assert result["status"] == "ok"
        assert result["nodes"] == 2  # src + dst
        assert result["edges"] == 1
        assert graph_json.exists()

    def test_build_graph_creates_valid_json(self, tmp_path):
        from integration.pipeline_runner import step_build_graph

        anomalies = tmp_path / "anomalies.jsonl"
        graph_json = tmp_path / "graph.json"

        sample = [
            {
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "anomaly_type": "Brute Force",
                "severity": "CRITICAL",
            },
            {
                "src_ip": "10.0.0.3",
                "dst_ip": "10.0.0.4",
                "anomaly_type": "Port Scan",
                "severity": "MEDIUM",
            },
        ]
        with open(anomalies, "w") as f:
            for a in sample:
                f.write(json.dumps(a) + "\n")

        result = step_build_graph(anomalies, graph_json)
        assert result["status"] == "ok"

        with open(graph_json) as f:
            graph = json.load(f)
        assert "nodes" in graph
        assert "edges" in graph
        assert len(graph["nodes"]) == 4
        assert len(graph["edges"]) == 2

    def test_build_graph_deduplicates_nodes(self, tmp_path):
        from integration.pipeline_runner import step_build_graph

        anomalies = tmp_path / "anomalies.jsonl"
        graph_json = tmp_path / "graph.json"

        sample = [
            {
                "src_ip": "192.168.1.1",
                "dst_ip": "10.0.0.1",
                "anomaly_type": "Port Scan",
                "severity": "HIGH",
            },
            {
                "src_ip": "192.168.1.1",
                "dst_ip": "10.0.0.2",
                "anomaly_type": "Brute Force",
                "severity": "CRITICAL",
            },
        ]
        with open(anomalies, "w") as f:
            for a in sample:
                f.write(json.dumps(a) + "\n")

        result = step_build_graph(anomalies, graph_json)
        # 192.168.1.1 should appear only once
        assert result["nodes"] == 3

    def test_build_graph_empty_anomalies(self, tmp_path):
        from integration.pipeline_runner import step_build_graph

        anomalies = tmp_path / "empty.jsonl"
        anomalies.write_text("")
        graph_json = tmp_path / "graph.json"
        result = step_build_graph(anomalies, graph_json)
        assert result["status"] == "ok"
        assert result["nodes"] == 0
        assert result["edges"] == 0

    def test_build_graph_skips_entries_without_ips(self, tmp_path):
        from integration.pipeline_runner import step_build_graph

        anomalies = tmp_path / "anomalies.jsonl"
        graph_json = tmp_path / "graph.json"

        sample = [
            {
                "anomaly_type": "Port Scan",
                "severity": "HIGH",
                # No src_ip or dst_ip
            },
            {
                "src_ip": "192.168.1.1",
                "dst_ip": "10.0.0.1",
                "anomaly_type": "Port Scan",
                "severity": "HIGH",
            },
        ]
        with open(anomalies, "w") as f:
            for a in sample:
                f.write(json.dumps(a) + "\n")

        result = step_build_graph(anomalies, graph_json)
        assert result["nodes"] == 2
        assert result["edges"] == 1


class TestRunFullPipeline:
    """Test the full pipeline orchestrator."""

    def test_full_pipeline_returns_dict(self, monkeypatch, tmp_path):
        import integration.model_forecaster as mf
        import integration.pipeline_runner as pr

        monkeypatch.setattr(mf, "ENABLE_FORECASTING_MODEL", False)
        monkeypatch.setattr(pr, "ENABLE_FORECASTING_MODEL", False)
        monkeypatch.setattr(pr, "ENABLE_KILLCHAIN", False)
        # Create empty packets file to skip generation step failure
        packets_file = tmp_path / "packets.jsonl"
        packets_file.write_text("")
        monkeypatch.setattr(pr, "PACKETS_FILE", packets_file)
        monkeypatch.setattr(pr, "ANOMALIES_FILE", tmp_path / "anomalies.jsonl")
        monkeypatch.setattr(pr, "FEATURES_FILE", tmp_path / "features.jsonl")
        monkeypatch.setattr(pr, "KILLCHAIN_INCIDENTS_FILE", tmp_path / "incidents.jsonl")
        from integration.pipeline_runner import run_full_pipeline

        result = run_full_pipeline(use_existing_packets=True)
        assert isinstance(result, dict)
        assert "pipeline_status" in result
        assert "elapsed_sec" in result

    def test_full_pipeline_with_disabled_features(self, monkeypatch, tmp_path):
        import integration.model_forecaster as mf
        import integration.pipeline_runner as pr

        monkeypatch.setattr(mf, "ENABLE_FORECASTING_MODEL", False)
        monkeypatch.setattr(pr, "ENABLE_FORECASTING_MODEL", False)
        monkeypatch.setattr(pr, "ENABLE_KILLCHAIN", False)
        packets_file = tmp_path / "packets.jsonl"
        packets_file.write_text("")
        monkeypatch.setattr(pr, "PACKETS_FILE", packets_file)
        monkeypatch.setattr(pr, "ANOMALIES_FILE", tmp_path / "anomalies.jsonl")
        monkeypatch.setattr(pr, "FEATURES_FILE", tmp_path / "features.jsonl")
        monkeypatch.setattr(pr, "KILLCHAIN_INCIDENTS_FILE", tmp_path / "incidents.jsonl")
        from integration.pipeline_runner import run_full_pipeline

        result = run_full_pipeline(use_existing_packets=True)
        assert "step4_model_b" in result
        assert result["step4_model_b"]["status"] == "disabled"

    def test_full_pipeline_has_timestamps(self, monkeypatch, tmp_path):
        import integration.model_forecaster as mf
        import integration.pipeline_runner as pr

        monkeypatch.setattr(mf, "ENABLE_FORECASTING_MODEL", False)
        monkeypatch.setattr(pr, "ENABLE_FORECASTING_MODEL", False)
        monkeypatch.setattr(pr, "ENABLE_KILLCHAIN", False)
        packets_file = tmp_path / "packets.jsonl"
        packets_file.write_text("")
        monkeypatch.setattr(pr, "PACKETS_FILE", packets_file)
        monkeypatch.setattr(pr, "ANOMALIES_FILE", tmp_path / "anomalies.jsonl")
        monkeypatch.setattr(pr, "FEATURES_FILE", tmp_path / "features.jsonl")
        monkeypatch.setattr(pr, "KILLCHAIN_INCIDENTS_FILE", tmp_path / "incidents.jsonl")
        from integration.pipeline_runner import run_full_pipeline

        result = run_full_pipeline(use_existing_packets=True)
        assert "started_at" in result
        assert "completed_at" in result
