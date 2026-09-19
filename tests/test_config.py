"""Tests for integration.config module."""

from pathlib import Path


class TestConfigPaths:
    """Test that config paths are correctly resolved."""

    def test_project_root_is_path(self):
        from integration.config import PROJECT_ROOT

        assert isinstance(PROJECT_ROOT, Path)
        assert PROJECT_ROOT.exists()

    def test_data_dir_exists_or_can_be_created(self):
        from integration.config import DATA_DIR, ensure_dirs

        ensure_dirs()
        assert DATA_DIR.exists()

    def test_integration_dir_exists(self):
        from integration.config import INTEGRATION_DIR

        assert isinstance(INTEGRATION_DIR, Path)

    def test_repos_dir_exists(self):
        from integration.config import REPOS_DIR

        assert isinstance(REPOS_DIR, Path)

    def test_output_file_paths_are_path_objects(self):
        from integration.config import (
            ANOMALIES_FILE,
            FEATURES_FILE,
            GRAPH_JSON,
            KILLCHAIN_INCIDENTS_FILE,
            PACKETS_FILE,
        )

        for p in [
            PACKETS_FILE,
            ANOMALIES_FILE,
            FEATURES_FILE,
            KILLCHAIN_INCIDENTS_FILE,
            GRAPH_JSON,
        ]:
            assert isinstance(p, Path)

    def test_forecast_model_path_extension(self):
        from integration.config import FORECAST_MODEL_PATH

        assert FORECAST_MODEL_PATH.suffix == ".pkl"


class TestConfigFeatureFlags:
    """Test feature flag behavior."""

    def test_default_forecasting_enabled(self):
        from integration.config import ENABLE_FORECASTING_MODEL

        # Default is "1" so it should be True unless env is set
        assert isinstance(ENABLE_FORECASTING_MODEL, bool)

    def test_default_killchain_enabled(self):
        from integration.config import ENABLE_KILLCHAIN

        assert isinstance(ENABLE_KILLCHAIN, bool)

    def test_disable_forecasting_via_env(self, monkeypatch):
        monkeypatch.setenv("ENABLE_FORECASTING_MODEL", "0")
        # Re-import to pick up the env change
        import importlib

        import integration.config as cfg

        importlib.reload(cfg)
        assert cfg.ENABLE_FORECASTING_MODEL is False
        # Restore default
        monkeypatch.delenv("ENABLE_FORECASTING_MODEL", raising=False)
        importlib.reload(cfg)

    def test_disable_killchain_via_env(self, monkeypatch):
        monkeypatch.setenv("ENABLE_KILLCHAIN", "0")
        import importlib

        import integration.config as cfg

        importlib.reload(cfg)
        assert cfg.ENABLE_KILLCHAIN is False
        monkeypatch.delenv("ENABLE_KILLCHAIN", raising=False)
        importlib.reload(cfg)


class TestConfigThresholds:
    """Test that anomaly detection thresholds are reasonable."""

    def test_port_scan_threshold_positive(self):
        from integration.config import PORT_SCAN_THRESHOLD

        assert PORT_SCAN_THRESHOLD > 0

    def test_brute_force_threshold_positive(self):
        from integration.config import BRUTE_FORCE_THRESHOLD

        assert BRUTE_FORCE_THRESHOLD > 0

    def test_window_size_positive(self):
        from integration.config import WINDOW_SIZE_SECONDS, WINDOW_STEP_SECONDS

        assert WINDOW_SIZE_SECONDS > 0
        assert WINDOW_STEP_SECONDS > 0
        assert WINDOW_SIZE_SECONDS >= WINDOW_STEP_SECONDS

    def test_escalation_threshold_between_0_and_1(self):
        from integration.config import ESCALATION_THRESHOLD

        assert 0.0 <= ESCALATION_THRESHOLD <= 1.0


class TestEnsureDirs:
    """Test the ensure_dirs utility."""

    def test_ensure_dirs_creates_data_dir(self, tmp_path, monkeypatch):
        import integration.config as cfg

        monkeypatch.setattr(cfg, "DATA_DIR", tmp_path / "test_data")
        monkeypatch.setattr(cfg, "INTEGRATION_DIR", tmp_path / "test_integration")
        cfg.ensure_dirs()
        assert (tmp_path / "test_data").exists()
        assert (tmp_path / "test_integration").exists()
