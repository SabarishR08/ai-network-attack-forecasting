"""Tests for integration.model_forecaster module."""

import numpy as np
import pytest

from integration.model_forecaster import (
    FEATURE_COLUMNS,
    EscalationForecaster,
)


@pytest.fixture
def labeled_features():
    """Create synthetic labeled feature data for testing."""
    np.random.seed(42)
    features = []
    for i in range(100):
        is_escalated = i < 30  # 30% escalation rate
        feat = {
            "src_ip": f"192.168.1.{i % 255}",
            "dst_ip": "10.0.0.1",
            "window_start": f"2024-01-15T10:{i // 60:02d}:{i % 60:02d}",
            "window_end": f"2024-01-15T10:{i // 60:02d}:{(i % 60) + 10:02d}",
            "total_packets": int(np.random.poisson(50 if is_escalated else 10)),
            "port_diversity": int(np.random.poisson(20 if is_escalated else 3)),
            "connection_rate": float(np.random.exponential(5.0 if is_escalated else 0.5)),
            "syn_count": int(np.random.poisson(30 if is_escalated else 5)),
            "rst_count": int(np.random.poisson(3 if is_escalated else 1)),
            "syn_rst_ratio": float(np.random.exponential(10 if is_escalated else 5)),
            "payload_size_mean": float(np.random.normal(500 if is_escalated else 100, 50)),
            "payload_size_max": int(np.random.poisson(1500 if is_escalated else 200)),
            "escalation_label": 1 if is_escalated else 0,
        }
        features.append(feat)
    return features


@pytest.fixture
def minimal_features():
    """Minimal feature set with only one class."""
    return [
        {
            "src_ip": "192.168.1.1",
            "dst_ip": "10.0.0.1",
            "window_start": f"2024-01-15T10:00:{i:02d}",
            "window_end": f"2024-01-15T10:00:{i + 10:02d}",
            "total_packets": 10,
            "port_diversity": 3,
            "connection_rate": 1.0,
            "syn_count": 5,
            "rst_count": 1,
            "syn_rst_ratio": 5.0,
            "payload_size_mean": 100.0,
            "payload_size_max": 200,
            "escalation_label": 0,
        }
        for i in range(20)
    ]


class TestEscalationForecaster:
    """Test the EscalationForecaster class."""

    def test_init_default_path(self):
        forecaster = EscalationForecaster()
        assert forecaster.model is None
        assert forecaster.is_trained is False

    def test_init_custom_path(self, tmp_path):
        custom_path = tmp_path / "custom_model.pkl"
        forecaster = EscalationForecaster(model_path=custom_path)
        assert forecaster.model_path == custom_path

    def test_features_to_df(self, labeled_features):
        forecaster = EscalationForecaster()
        df = forecaster._features_to_df(labeled_features)
        assert len(df) == len(labeled_features)
        assert list(df.columns) == FEATURE_COLUMNS

    def test_train_with_sufficient_data(self, labeled_features):
        forecaster = EscalationForecaster()
        metrics = forecaster.train(labeled_features)
        assert metrics["status"] == "trained"
        assert forecaster.is_trained is True
        assert forecaster.model is not None
        assert "accuracy" in metrics
        assert "f1" in metrics

    def test_train_with_insufficient_data(self):
        few_features = [
            {
                "total_packets": 10,
                "port_diversity": 3,
                "connection_rate": 1.0,
                "syn_count": 5,
                "rst_count": 1,
                "syn_rst_ratio": 5.0,
                "payload_size_mean": 100.0,
                "payload_size_max": 200,
                "escalation_label": 0,
            }
            for _ in range(5)
        ]
        forecaster = EscalationForecaster()
        metrics = forecaster.train(few_features)
        assert metrics["status"] == "insufficient_data"

    def test_train_with_single_class(self, minimal_features):
        forecaster = EscalationForecaster()
        metrics = forecaster.train(minimal_features)
        assert metrics["status"] in ("trained", "degenerate")

    def test_predict_before_training(self, labeled_features):
        forecaster = EscalationForecaster()
        result = forecaster.predict(labeled_features[:5])
        for feat in result:
            assert feat["escalation_probability"] == 0.0
            assert feat["escalation_predicted"] is False

    def test_predict_after_training(self, labeled_features):
        forecaster = EscalationForecaster()
        forecaster.train(labeled_features)
        result = forecaster.predict(labeled_features[:5])
        for feat in result:
            assert "escalation_probability" in feat
            assert "escalation_predicted" in feat
            assert 0.0 <= feat["escalation_probability"] <= 1.0

    def test_predict_produces_valid_probabilities(self, labeled_features):
        forecaster = EscalationForecaster()
        forecaster.train(labeled_features)
        result = forecaster.predict(labeled_features)
        for feat in result:
            prob = feat["escalation_probability"]
            assert isinstance(prob, float)
            assert 0.0 <= prob <= 1.0

    def test_save_and_load(self, labeled_features, tmp_path):
        model_path = tmp_path / "test_model.pkl"
        forecaster = EscalationForecaster(model_path=model_path)
        forecaster.train(labeled_features)
        forecaster.save()

        # Load in a new forecaster
        new_forecaster = EscalationForecaster(model_path=model_path)
        loaded = new_forecaster.load()
        assert loaded is True
        assert new_forecaster.is_trained is True

    def test_load_nonexistent_model(self, tmp_path):
        forecaster = EscalationForecaster(model_path=tmp_path / "nope.pkl")
        loaded = forecaster.load()
        assert loaded is False
        assert forecaster.is_trained is False

    def test_feature_importances_in_metrics(self, labeled_features):
        forecaster = EscalationForecaster()
        metrics = forecaster.train(labeled_features)
        if metrics.get("status") == "trained":
            assert "feature_importances" in metrics
            importances = metrics["feature_importances"]
            assert isinstance(importances, dict)
            # All feature columns should have an importance
            assert len(importances) == len(FEATURE_COLUMNS)

    def test_train_metrics_have_required_keys(self, labeled_features):
        forecaster = EscalationForecaster()
        metrics = forecaster.train(labeled_features)
        if metrics.get("status") == "trained":
            required = {"accuracy", "precision", "recall", "f1", "train_samples", "val_samples"}
            assert required.issubset(metrics.keys())


class TestFeatureColumns:
    """Test the FEATURE_COLUMNS constant."""

    def test_feature_columns_not_empty(self):
        assert len(FEATURE_COLUMNS) > 0

    def test_feature_columns_are_strings(self):
        for col in FEATURE_COLUMNS:
            assert isinstance(col, str)

    def test_expected_features_present(self):
        expected = {"total_packets", "connection_rate", "syn_rst_ratio", "payload_size_mean"}
        assert expected.issubset(set(FEATURE_COLUMNS))
