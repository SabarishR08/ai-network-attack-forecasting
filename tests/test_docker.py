"""Tests for Docker configuration files — Dockerfile, docker-compose.yml, .dockerignore."""

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestDockerfile:
    """Validate Dockerfile structure and best practices."""

    @pytest.fixture
    def dockerfile(self):
        return (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")

    def test_exists(self):
        assert (REPO_ROOT / "Dockerfile").exists()

    def test_has_multi_stage_builds(self, dockerfile):
        assert "FROM python:" in dockerfile
        assert "AS base" in dockerfile
        assert "AS development" in dockerfile
        assert "AS production" in dockerfile

    def test_base_installs_requirements(self, dockerfile):
        assert "COPY requirements.txt" in dockerfile
        assert "pip install" in dockerfile

    def test_production_user(self, dockerfile):
        """Production stage should run as non-root."""
        assert "useradd" in dockerfile or "adduser" in dockerfile
        assert "USER appuser" in dockerfile

    def test_production_healthcheck(self, dockerfile):
        assert "HEALTHCHECK" in dockerfile

    def test_production_uses_gunicorn(self, dockerfile):
        assert "gunicorn" in dockerfile

    def test_exposes_port(self, dockerfile):
        assert "EXPOSE 5000" in dockerfile

    def test_python_unbuffered(self, dockerfile):
        assert "PYTHONUNBUFFERED=1" in dockerfile

    def test_no_cache_dir(self, dockerfile):
        assert "PIP_NO_CACHE_DIR=1" in dockerfile or "--no-cache-dir" in dockerfile

    def test_production_copies_minimal_files(self, dockerfile):
        """Production stage should only copy necessary files."""
        # Should copy integration/, repos/, data/, run.py
        assert "COPY integration/" in dockerfile
        assert "COPY repos/" in dockerfile
        assert "COPY run.py" in dockerfile

    def test_dev_has_dev_tools(self, dockerfile):
        """Development stage should have dev tools."""
        # Check the development section specifically
        dev_section = dockerfile.split("AS development")[1]
        assert "ruff" in dev_section or "mypy" in dev_section

    def test_dev_mounts_source(self, dockerfile):
        """Development stage should copy full source."""
        dev_section = dockerfile.split("AS development")[1]
        assert "COPY" in dev_section


class TestDockerCompose:
    """Validate docker-compose.yml structure."""

    @pytest.fixture
    def compose(self):
        return (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")

    def test_exists(self):
        assert (REPO_ROOT / "docker-compose.yml").exists()

    def test_has_services(self, compose):
        assert "services:" in compose

    def test_has_dev_service(self, compose):
        assert "dev:" in compose

    def test_has_prod_service(self, compose):
        assert "prod:" in compose

    def test_has_pipeline_service(self, compose):
        assert "pipeline:" in compose

    def test_has_test_service(self, compose):
        assert "test:" in compose

    def test_dev_uses_development_target(self, compose):
        assert "target: development" in compose

    def test_prod_uses_production_target(self, compose):
        assert "target: production" in compose

    def test_dev_exposes_port(self, compose):
        assert "5000:5000" in compose or "${PORT:-5000}:5000" in compose

    def test_prod_exposes_port(self, compose):
        assert "${PROD_PORT:-8000}:5000" in compose

    def test_dev_has_debug_enabled(self, compose):
        assert "FLASK_DEBUG=1" in compose

    def test_prod_has_rate_limiting(self, compose):
        assert "RATE_LIMIT_ENABLED=1" in compose

    def test_prod_has_restart_policy(self, compose):
        assert "restart:" in compose

    def test_prod_has_resource_limits(self, compose):
        assert "limits:" in compose

    def test_has_healthchecks(self, compose):
        assert "healthcheck:" in compose

    def test_has_volumes(self, compose):
        assert "volumes:" in compose

    def test_dev_mounts_source_code(self, compose):
        """Dev service should mount source for live reload."""
        dev_section = compose.split("dev:")[1].split("pipeline:")[0]
        assert ".:/app" in dev_section or "./:/app" in dev_section

    def test_pipeline_is_profile_only(self, compose):
        """Pipeline should be in a profile (not started by default)."""
        assert "profiles:" in compose

    def test_test_is_profile_only(self, compose):
        """Test should be in a profile."""
        pipeline_section = compose.split("test:")[1]
        assert "profiles:" in pipeline_section

    def test_dev_has_healthcheck(self, compose):
        dev_section = compose.split("dev:")[1].split("pipeline:")[0]
        assert "healthcheck:" in dev_section

    def test_prod_has_healthcheck(self, compose):
        prod_section = compose.split("prod:")[1].split("test:")[0]
        assert "healthcheck:" in prod_section


class TestDockerignore:
    """Validate .dockerignore excludes unnecessary files."""

    @pytest.fixture
    def dockerignore(self):
        return (REPO_ROOT / ".dockerignore").read_text(encoding="utf-8")

    def test_exists(self):
        assert (REPO_ROOT / ".dockerignore").exists()

    def test_excludes_git(self, dockerignore):
        assert ".git" in dockerignore

    def test_excludes_pycache(self, dockerignore):
        assert "__pycache__" in dockerignore

    def test_excludes_pytest_cache(self, dockerignore):
        assert ".pytest_cache" in dockerignore

    def test_excludes_venv(self, dockerignore):
        assert "venv" in dockerignore

    def test_excludes_env_files(self, dockerignore):
        assert ".env" in dockerignore

    def test_excludes_docker_files(self, dockerignore):
        assert "Dockerfile" in dockerignore
        assert "docker-compose" in dockerignore

    def test_excludes_data_files(self, dockerignore):
        """Data files should be excluded (mounted as volumes)."""
        assert "data/*.jsonl" in dockerignore or "data/" in dockerignore

    def test_excludes_ide_files(self, dockerignore):
        assert ".vscode" in dockerignore or ".idea" in dockerignore

    def test_excludes_test_artifacts(self, dockerignore):
        assert "htmlcov" in dockerignore or "coverage" in dockerignore


class TestRequirementsCompatibility:
    """Verify requirements are compatible with Docker build."""

    def test_requirements_file_exists(self):
        assert (REPO_ROOT / "requirements.txt").exists()

    def test_requirements_has_flask(self):
        reqs = (REPO_ROOT / "requirements.txt").read_text()
        assert "flask" in reqs.lower()

    def test_requirements_has_gunicorn(self):
        reqs = (REPO_ROOT / "requirements.txt").read_text()
        assert "gunicorn" in reqs.lower()

    def test_requirements_has_pytest(self):
        reqs = (REPO_ROOT / "requirements.txt").read_text()
        assert "pytest" in reqs.lower()

    def test_requirements_has_pinned_versions(self):
        """All deps should have pinned versions for reproducible builds."""
        reqs = (REPO_ROOT / "requirements.txt").read_text()
        for line in reqs.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and line:
                # Should have == or >= for version pinning
                assert "==" in line or ">=" in line, f"Unpinned: {line}"
