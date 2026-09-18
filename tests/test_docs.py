"""Tests for API documentation endpoints (/api/docs, /api/openapi.json)."""

import json


class TestOpenAPISpec:
    """Test /api/openapi.json endpoint."""

    def test_spec_returns_json(self, client):
        resp = client.get("/api/openapi.json")
        assert resp.status_code == 200
        assert resp.content_type == "application/json"

    def test_spec_valid_openapi(self, client):
        resp = client.get("/api/openapi.json")
        spec = json.loads(resp.data)
        assert spec["openapi"].startswith("3.0")
        assert "info" in spec
        assert "paths" in spec
        assert "components" in spec

    def test_spec_has_all_endpoints(self, client):
        resp = client.get("/api/openapi.json")
        spec = json.loads(resp.data)
        paths = spec["paths"]
        expected = [
            "/api/dashboard",
            "/api/anomalies",
            "/api/forecast",
            "/api/packets",
            "/api/graph",
            "/api/incidents",
            "/api/status",
            "/api/run-pipeline",
            "/api/stream",
        ]
        for ep in expected:
            assert ep in paths, f"Missing endpoint: {ep}"

    def test_spec_has_info(self, client):
        resp = client.get("/api/openapi.json")
        spec = json.loads(resp.data)
        assert "title" in spec["info"]
        assert "version" in spec["info"]
        assert "SIH26153" in spec["info"]["title"]

    def test_spec_has_schemas(self, client):
        resp = client.get("/api/openapi.json")
        spec = json.loads(resp.data)
        schemas = spec["components"]["schemas"]
        expected = [
            "DashboardResponse",
            "Anomaly",
            "ForecastFeature",
            "Packet",
            "GraphResponse",
            "Incident",
            "StatusResponse",
            "ErrorResponse",
        ]
        for name in expected:
            assert name in schemas, f"Missing schema: {name}"

    def test_spec_has_parameters(self, client):
        resp = client.get("/api/openapi.json")
        spec = json.loads(resp.data)
        # /api/anomalies should have limit and severity params
        anom_params = spec["paths"]["/api/anomalies"]["get"]["parameters"]
        param_names = [p["name"] for p in anom_params]
        assert "limit" in param_names
        assert "severity" in param_names

    def test_spec_has_error_responses(self, client):
        resp = client.get("/api/openapi.json")
        spec = json.loads(resp.data)
        # Shared error responses should be defined
        responses = spec["components"]["responses"]
        assert "ValidationError" in responses

    def test_spec_post_method(self, client):
        resp = client.get("/api/openapi.json")
        spec = json.loads(resp.data)
        # /api/run-pipeline should have POST
        assert "post" in spec["paths"]["/api/run-pipeline"]


class TestSwaggerUI:
    """Test /api/docs endpoint."""

    def test_docs_returns_html(self, client):
        resp = client.get("/api/docs")
        assert resp.status_code == 200
        assert "text/html" in resp.content_type

    def test_docs_has_swagger_ui(self, client):
        resp = client.get("/api/docs")
        html = resp.data.decode("utf-8")
        assert "swagger-ui" in html
        assert "swagger-ui-dist" in html

    def test_docs_references_spec(self, client):
        resp = client.get("/api/docs")
        html = resp.data.decode("utf-8")
        assert "/api/openapi.json" in html
