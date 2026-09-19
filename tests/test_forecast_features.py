"""Tests for integration.forecast_features module."""

import json
from datetime import datetime

import pytest

from integration.forecast_features import (
    ForecastFeatureExtractor,
    extract_and_label_features,
)


@pytest.fixture
def sample_packets_file(tmp_path):
    """Create a sample packets.jsonl file for testing."""
    packets = [
        {
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.1",
            "dst_port": 80,
            "protocol": "TCP",
            "flags": "S",
            "payload_size": 64,
            "timestamp": "2024-01-15T10:00:00",
        },
        {
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.1",
            "dst_port": 443,
            "protocol": "TCP",
            "flags": "SA",
            "payload_size": 128,
            "timestamp": "2024-01-15T10:00:05",
        },
        {
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.1",
            "dst_port": 22,
            "protocol": "TCP",
            "flags": "R",
            "payload_size": 32,
            "timestamp": "2024-01-15T10:00:10",
        },
        {
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.1",
            "dst_port": 8080,
            "protocol": "TCP",
            "flags": "S",
            "payload_size": 256,
            "timestamp": "2024-01-15T10:00:15",
        },
        {
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.1",
            "dst_port": 3306,
            "protocol": "TCP",
            "flags": "A",
            "payload_size": 512,
            "timestamp": "2024-01-15T10:00:20",
        },
        {
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.1",
            "dst_port": 80,
            "protocol": "TCP",
            "flags": "S",
            "payload_size": 64,
            "timestamp": "2024-01-15T10:00:25",
        },
    ]
    path = tmp_path / "packets.jsonl"
    with open(path, "w") as f:
        for pkt in packets:
            f.write(json.dumps(pkt) + "\n")
    return path


@pytest.fixture
def sample_anomalies_file(tmp_path):
    """Create a sample anomalies.jsonl file for labeling."""
    anomalies = [
        {
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.1",
            "anomaly_type": "Port Scan",
            "severity": "HIGH",
            "timestamp": "2024-01-15T10:00:10",
            "confidence": 0.85,
        },
    ]
    path = tmp_path / "anomalies.jsonl"
    with open(path, "w") as f:
        for anom in anomalies:
            f.write(json.dumps(anom) + "\n")
    return path


class TestForecastFeatureExtractor:
    """Test the ForecastFeatureExtractor class."""

    def test_init_with_valid_file(self, sample_packets_file):
        extractor = ForecastFeatureExtractor(
            packets_file=str(sample_packets_file),
            window_size=30,
            window_step=10,
        )
        assert len(extractor.packets) == 6

    def test_init_with_nonexistent_file(self, tmp_path):
        extractor = ForecastFeatureExtractor(
            packets_file=str(tmp_path / "nonexistent.jsonl"),
        )
        assert len(extractor.packets) == 0

    def test_extract_features_returns_list(self, sample_packets_file):
        extractor = ForecastFeatureExtractor(
            packets_file=str(sample_packets_file),
            window_size=30,
            window_step=10,
        )
        features = extractor.extract_forecast_features()
        assert isinstance(features, list)
        assert len(features) > 0

    def test_extract_features_schema(self, sample_packets_file):
        extractor = ForecastFeatureExtractor(
            packets_file=str(sample_packets_file),
            window_size=30,
            window_step=10,
        )
        features = extractor.extract_forecast_features()
        required_keys = {
            "src_ip",
            "dst_ip",
            "window_start",
            "window_end",
            "window_duration_sec",
            "total_packets",
            "port_diversity",
            "unique_ports",
            "connection_rate",
            "syn_count",
            "rst_count",
            "syn_rst_ratio",
            "payload_size_mean",
            "payload_size_max",
        }
        for feat in features:
            assert required_keys.issubset(feat.keys()), (
                f"Missing keys: {required_keys - feat.keys()}"
            )

    def test_extract_features_empty_when_no_packets(self, tmp_path):
        extractor = ForecastFeatureExtractor(
            packets_file=str(tmp_path / "empty.jsonl"),
        )
        features = extractor.extract_forecast_features()
        assert features == []

    def test_save_features(self, sample_packets_file, tmp_path):
        extractor = ForecastFeatureExtractor(
            packets_file=str(sample_packets_file),
            window_size=30,
            window_step=10,
        )
        output = tmp_path / "features_out.jsonl"
        extractor.save_features(str(output))
        assert output.exists()
        with open(output) as f:
            lines = [line.strip() for line in f if line.strip()]
        assert len(lines) > 0
        # Each line should be valid JSON
        for line in lines:
            data = json.loads(line)
            assert isinstance(data, dict)

    def test_window_parameters(self, sample_packets_file):
        extractor = ForecastFeatureExtractor(
            packets_file=str(sample_packets_file),
            window_size=60,
            window_step=20,
        )
        features = extractor.extract_forecast_features()
        # With larger window, should have fewer features
        assert len(features) > 0
        for feat in features:
            assert feat["window_duration_sec"] == 60.0


class TestExtractAndLabelFeatures:
    """Test the extract_and_label_features function."""

    def test_labels_features(self, sample_packets_file, sample_anomalies_file):
        extractor = ForecastFeatureExtractor(
            packets_file=str(sample_packets_file),
            window_size=30,
            window_step=10,
        )
        features = extractor.extract_forecast_features()
        labeled = extract_and_label_features(features, str(sample_anomalies_file))
        assert len(labeled) == len(features)
        for feat in labeled:
            assert "escalation_label" in feat
            assert feat["escalation_label"] in (0, 1)

    def test_labels_without_anomalies_file(self, sample_packets_file, tmp_path):
        extractor = ForecastFeatureExtractor(
            packets_file=str(sample_packets_file),
            window_size=30,
            window_step=10,
        )
        features = extractor.extract_forecast_features()
        labeled = extract_and_label_features(features, str(tmp_path / "nonexistent.jsonl"))
        for feat in labeled:
            assert feat["escalation_label"] == 0

    def test_escalation_label_is_int(self, sample_packets_file, sample_anomalies_file):
        extractor = ForecastFeatureExtractor(
            packets_file=str(sample_packets_file),
            window_size=30,
            window_step=10,
        )
        features = extractor.extract_forecast_features()
        labeled = extract_and_label_features(features, str(sample_anomalies_file))
        for feat in labeled:
            assert isinstance(feat["escalation_label"], int)


class TestParseTs:
    """Test timestamp parsing."""

    def test_valid_iso_timestamp(self):
        from integration.forecast_features import _parse_ts

        result = _parse_ts("2024-01-15T10:00:00")
        assert isinstance(result, datetime)
        assert result.year == 2024

    def test_invalid_timestamp_returns_now(self):
        from integration.forecast_features import _parse_ts

        result = _parse_ts("not-a-timestamp")
        assert isinstance(result, datetime)
        # Should be close to now
        assert abs((result - datetime.now()).total_seconds()) < 5
