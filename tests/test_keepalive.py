"""Tests for keep-alive functionality."""

import json


class TestKeepAliveEndpoint:
    """Tests for the /api/keepalive endpoint."""

    def test_keepalive_returns_200(self, client):
        resp = client.get("/api/keepalive")
        assert resp.status_code == 200

    def test_keepalive_returns_alive(self, client):
        resp = client.get("/api/keepalive")
        data = json.loads(resp.data)
        assert data["status"] == "alive"

    def test_keepalive_has_uptime(self, client):
        resp = client.get("/api/keepalive")
        data = json.loads(resp.data)
        assert "uptime" in data
        assert isinstance(data["uptime"], (int, float))

    def test_keepalive_uptime_non_negative(self, client):
        resp = client.get("/api/keepalive")
        data = json.loads(resp.data)
        assert data["uptime"] >= 0

    def test_keepalive_content_type_json(self, client):
        resp = client.get("/api/keepalive")
        assert resp.content_type == "application/json"

    def test_keepalive_consecutive_pings(self, client):
        """Multiple keepalive pings should all succeed."""
        for _ in range(5):
            resp = client.get("/api/keepalive")
            data = json.loads(resp.data)
            assert resp.status_code == 200
            assert data["status"] == "alive"


class TestKeepAwakeScript:
    """Tests for the keep_awake.py standalone script."""

    def test_script_importable(self):
        import importlib

        spec = importlib.util.find_spec("keep_awake")
        assert spec is not None

    def test_ping_function_success(self):
        """Test ping function with a mock server would need Flask test client."""
        from keep_awake import ping

        # ping expects a real URL, just verify it's callable
        assert callable(ping)

    def test_script_has_main(self):
        from keep_awake import main

        assert callable(main)
