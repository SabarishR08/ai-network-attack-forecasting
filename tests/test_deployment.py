"""Tests for deployment configuration — Render and Vercel."""

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestRenderConfig:
    """Validate Render deployment configuration."""

    @pytest.fixture
    def render_yaml(self):
        return (REPO_ROOT / "render.yaml").read_text(encoding="utf-8")

    def test_render_yaml_exists(self):
        assert (REPO_ROOT / "render.yaml").exists()

    def test_has_web_service(self, render_yaml):
        assert "type: web" in render_yaml

    def test_has_python_runtime(self, render_yaml):
        assert "runtime: python" in render_yaml

    def test_has_build_command(self, render_yaml):
        assert "buildCommand:" in render_yaml
        assert "pip install" in render_yaml

    def test_has_start_command(self, render_yaml):
        assert "startCommand:" in render_yaml
        assert "gunicorn" in render_yaml

    def test_has_health_check(self, render_yaml):
        assert "healthCheckPath:" in render_yaml
        assert "/api/status" in render_yaml

    def test_has_required_env_vars(self, render_yaml):
        assert "FLASK_SECRET_KEY" in render_yaml
        assert "ENABLE_FORECASTING_MODEL" in render_yaml
        assert "ENABLE_KILLCHAIN" in render_yaml

    def test_has_workers_config(self, render_yaml):
        assert "workers" in render_yaml

    def test_has_logging_config(self, render_yaml):
        assert "LOG_LEVEL" in render_yaml
        assert "LOG_FORMAT" in render_yaml


class TestVercelConfig:
    """Validate Vercel frontend deployment configuration."""

    @pytest.fixture
    def vercel_json(self):
        frontend_dir = REPO_ROOT / "frontend"
        return (frontend_dir / "vercel.json").read_text(encoding="utf-8")

    def test_vercel_json_exists(self):
        assert (REPO_ROOT / "frontend" / "vercel.json").exists()

    def test_has_version(self, vercel_json):
        data = json.loads(vercel_json)
        assert "version" in data
        assert data["version"] == 2

    def test_has_builds(self, vercel_json):
        data = json.loads(vercel_json)
        assert "builds" in data
        assert len(data["builds"]) > 0

    def test_has_routes(self, vercel_json):
        data = json.loads(vercel_json)
        assert "routes" in data

    def test_has_api_proxy_route(self, vercel_json):
        data = json.loads(vercel_json)
        api_routes = [r for r in data["routes"] if "/api/" in r.get("src", "")]
        assert len(api_routes) > 0

    def test_has_cors_headers(self, vercel_json):
        data = json.loads(vercel_json)
        assert "headers" in data
        # Check for Access-Control headers in the header definitions
        found_cors = False
        for h in data["headers"]:
            header_list = h.get("headers", [])
            for header_entry in header_list:
                if isinstance(header_entry, dict) and "Access-Control" in header_entry.get(
                    "key", ""
                ):
                    found_cors = True
                    break
                elif isinstance(header_entry, str) and "Access-Control" in header_entry:
                    found_cors = True
                    break
        assert found_cors, "No CORS headers found in vercel.json"


class TestVercelFrontend:
    """Validate Vercel frontend files exist."""

    def test_index_html_exists(self):
        assert (REPO_ROOT / "frontend" / "public" / "index.html").exists()

    def test_main_js_exists(self):
        assert (REPO_ROOT / "frontend" / "public" / "static" / "js" / "main.js").exists()

    def test_main_css_exists(self):
        assert (REPO_ROOT / "frontend" / "public" / "static" / "css" / "main.css").exists()

    def test_api_proxy_exists(self):
        assert (REPO_ROOT / "frontend" / "api" / "proxy.js").exists()

    def test_package_json_exists(self):
        assert (REPO_ROOT / "frontend" / "package.json").exists()

    def test_deploy_guide_exists(self):
        assert (REPO_ROOT / "frontend" / "DEPLOY.md").exists()

    def test_index_has_api_references(self):
        html = (REPO_ROOT / "frontend" / "public" / "index.html").read_text(encoding="utf-8")
        # Should reference API endpoints or contain api-related content
        assert "/api/" in html or "api" in html.lower() or "fetch" in html.lower()

    def test_proxy_has_backend_url(self):
        proxy = (REPO_ROOT / "frontend" / "api" / "proxy.js").read_text()
        assert "API_BASE" in proxy or "API_BASE_URL" in proxy

    def test_main_js_has_fetch(self):
        js = (REPO_ROOT / "frontend" / "public" / "static" / "js" / "main.js").read_text()
        assert "fetch" in js
        assert "/api/" in js


class TestProcfile:
    """Validate Procfile for Heroku/Render compatibility."""

    def test_procfile_exists(self):
        assert (REPO_ROOT / "Procfile").exists()

    def test_procfile_has_web(self):
        procfile = (REPO_ROOT / "Procfile").read_text()
        assert "web:" in procfile

    def test_procfile_uses_gunicorn(self):
        procfile = (REPO_ROOT / "Procfile").read_text()
        assert "gunicorn" in procfile

    def test_procfile_binds_port(self):
        procfile = (REPO_ROOT / "Procfile").read_text()
        assert "$PORT" in procfile or "0.0.0.0" in procfile


class TestDockerDeployment:
    """Validate Docker deployment files exist."""

    def test_dockerfile_exists(self):
        assert (REPO_ROOT / "Dockerfile").exists()

    def test_docker_compose_exists(self):
        assert (REPO_ROOT / "docker-compose.yml").exists()

    def test_dockerignore_exists(self):
        assert (REPO_ROOT / ".dockerignore").exists()
