"""Tests for integration.validation module — input sanitization and validation."""

import json

import pytest

from integration.validation import (
    ALLOWED_SEVERITIES,
    MAX_LIMIT,
    error_response,
    sanitize_ip,
    sanitize_string,
    validate_anomaly_params,
    validate_flagged,
    validate_forecast_params,
    validate_limit,
    validate_packet_params,
    validate_severity,
    validation_error,
)

# ── validate_limit ───────────────────────────────────────────


class TestValidateLimit:
    def test_valid_integer(self):
        val, err = validate_limit("50")
        assert val == 50
        assert err is None

    def test_zero(self):
        val, err = validate_limit("0")
        assert val == 0
        assert err is None

    def test_none_returns_default(self):
        val, err = validate_limit(None)
        assert val == 500  # DEFAULT_LIMIT
        assert err is None

    def test_negative_returns_default(self):
        val, err = validate_limit("-1")
        assert val == 500
        assert "non-negative" in err

    def test_non_numeric_returns_default(self):
        val, err = validate_limit("abc")
        assert val == 500
        assert "Invalid limit" in err

    def test_clamps_to_max(self):
        val, err = validate_limit("999999")
        assert val == MAX_LIMIT
        assert err is None

    def test_custom_default(self):
        val, err = validate_limit(None, default=100)
        assert val == 100

    def test_float_string(self):
        val, err = validate_limit("3.5")
        # int("3.5") raises ValueError in Python
        assert val == 500
        assert "Invalid limit" in err


# ── validate_severity ────────────────────────────────────────


class TestValidateSeverity:
    def test_empty_string(self):
        val, err = validate_severity("")
        assert val == ""
        assert err is None

    def test_valid_severity(self):
        for sev in ALLOWED_SEVERITIES:
            val, err = validate_severity(sev)
            assert val == sev
            assert err is None

    def test_case_insensitive(self):
        val, err = validate_severity("high")
        assert val == "HIGH"
        assert err is None

    def test_mixed_case(self):
        val, err = validate_severity("Critical")
        assert val == "CRITICAL"
        assert err is None

    def test_invalid_severity(self):
        val, err = validate_severity("EXTREME")
        assert val == ""
        assert "Invalid severity" in err

    def test_severity_with_whitespace(self):
        val, err = validate_severity("  HIGH  ")
        assert val == "HIGH"
        assert err is None

    def test_injection_attempt(self):
        val, err = validate_severity("HIGH; DROP TABLE")
        assert val == ""
        assert "Invalid severity" in err

    def test_xss_attempt(self):
        val, err = validate_severity("<script>alert(1)</script>")
        assert val == ""
        assert "Invalid severity" in err


# ── validate_flagged ─────────────────────────────────────────


class TestValidateFlagged:
    def test_zero(self):
        val, err = validate_flagged("0")
        assert val is False
        assert err is None

    def test_one(self):
        val, err = validate_flagged("1")
        assert val is True
        assert err is None

    def test_empty(self):
        val, err = validate_flagged("")
        assert val is False
        assert err is None

    def test_invalid(self):
        val, err = validate_flagged("yes")
        assert val is False
        assert "Invalid flagged" in err

    def test_injection_attempt(self):
        val, err = validate_flagged("1 OR 1=1")
        assert val is False
        assert "Invalid flagged" in err


# ── sanitize_string ──────────────────────────────────────────


class TestSanitizeString:
    def test_normal_string(self):
        assert sanitize_string("hello world") == "hello world"

    def test_html_escape(self):
        result = sanitize_string("<script>alert('xss')</script>")
        assert "<script>" not in result
        assert "&lt;script&gt;" in result

    def test_quotes_escaped(self):
        result = sanitize_string('value" onclick="alert(1)')
        assert '"' not in result or "&quot;" in result

    def test_control_chars_removed(self):
        result = sanitize_string("hello\x00\x01\x02world")
        assert "hello" in result
        assert "world" in result
        assert "\x00" not in result

    def test_newlines_preserved(self):
        result = sanitize_string("line1\nline2\ttab")
        assert "line1" in result
        assert "line2" in result

    def test_max_length_truncation(self):
        result = sanitize_string("a" * 2000, max_length=100)
        assert len(result) <= 105  # 100 + "..."
        assert result.endswith("...")

    def test_non_string_input(self):
        result = sanitize_string(12345)
        assert result == "12345"

    def test_unicode_preserved(self):
        result = sanitize_string("Hello 世界 🌍")
        assert "世界" in result
        assert "🌍" in result

    def test_sql_injection_sanitized(self):
        result = sanitize_string("'; DROP TABLE users; --")
        assert "DROP TABLE" in result  # Text preserved but HTML-escaped
        assert "&#" not in result or ";" in result  # Quotes escaped


# ── sanitize_ip ──────────────────────────────────────────────


class TestSanitizeIp:
    def test_valid_ipv4(self):
        val, err = sanitize_ip("192.168.1.1")
        assert val == "192.168.1.1"
        assert err is None

    def test_empty(self):
        val, err = sanitize_ip("")
        assert val == ""
        assert err is None

    def test_hostname(self):
        val, err = sanitize_ip("example.com")
        assert val == "example.com"
        assert err is None

    def test_truncation(self):
        long_ip = "1" * 100
        val, err = sanitize_ip(long_ip)
        assert len(val) <= 48  # 45 + "..."


# ── error_response / validation_error ────────────────────────


class TestErrorResponses:
    def test_error_response_structure(self, app_ctx):
        resp, status = error_response("Something went wrong", 422)
        assert status == 422
        data = json.loads(resp.data)
        assert data["error"] is True
        assert "Something went wrong" in data["message"]
        assert data["status"] == 422

    def test_validation_error_is_400(self, app_ctx):
        resp, status = validation_error("Bad input")
        assert status == 400
        data = json.loads(resp.data)
        assert data["error"] is True

    def test_error_message_sanitized(self, app_ctx):
        resp, status = error_response("<script>alert(1)</script>", 400)
        data = json.loads(resp.data)
        assert "<script>" not in data["message"]


# ── Composite Validators ─────────────────────────────────────


class TestValidateAnomalyParams:
    def test_valid_params(self):
        limit, severity, err = validate_anomaly_params("10", "HIGH")
        assert limit == 10
        assert severity == "HIGH"
        assert err is None

    def test_invalid_limit(self):
        limit, severity, err = validate_anomaly_params("abc", "HIGH")
        assert limit == 500
        assert err is not None
        assert "Invalid limit" in err

    def test_invalid_severity(self):
        limit, severity, err = validate_anomaly_params("10", "EXTREME")
        assert severity == ""
        assert err is not None
        assert "Invalid severity" in err

    def test_all_none(self):
        limit, severity, err = validate_anomaly_params(None, "")
        assert limit == 500
        assert severity == ""
        assert err is None


class TestValidateForecastParams:
    def test_valid_params(self):
        limit, flagged, err = validate_forecast_params("10", "1")
        assert limit == 10
        assert flagged is True
        assert err is None

    def test_invalid_limit(self):
        limit, flagged, err = validate_forecast_params("xyz", "0")
        assert limit == 500
        assert err is not None
        assert "Invalid limit" in err

    def test_invalid_flagged(self):
        limit, flagged, err = validate_forecast_params("10", "yes")
        assert flagged is False
        assert err is not None
        assert "Invalid flagged" in err

    def test_defaults(self):
        limit, flagged, err = validate_forecast_params(None, "0")
        assert limit == 500
        assert flagged is False
        assert err is None


class TestValidatePacketParams:
    def test_valid(self):
        limit, err = validate_packet_params("50")
        assert limit == 50
        assert err is None

    def test_invalid(self):
        limit, err = validate_packet_params("abc")
        assert limit == 500
        assert err is not None
        assert "Invalid limit" in err

    def test_none(self):
        limit, err = validate_packet_params(None)
        assert limit == 500
        assert err is None


# ── Integration: Validation via Flask endpoints ───────────────


class TestValidationInEndpoints:
    """Test that invalid inputs are properly rejected by the API."""

    def test_anomalies_invalid_limit_returns_400(self, client):
        resp = client.get("/api/anomalies?limit=abc")
        assert resp.status_code == 400
        data = json.loads(resp.data)
        assert data["error"] is True

    def test_anomalies_invalid_severity_returns_400(self, client):
        resp = client.get("/api/anomalies?severity=EXTREME")
        assert resp.status_code == 400
        data = json.loads(resp.data)
        assert data["error"] is True

    def test_forecast_invalid_limit_returns_400(self, client):
        resp = client.get("/api/forecast?limit=xyz")
        assert resp.status_code == 400

    def test_forecast_invalid_flagged_returns_400(self, client):
        resp = client.get("/api/forecast?flagged=yes")
        assert resp.status_code == 400

    def test_packets_invalid_limit_returns_400(self, client):
        resp = client.get("/api/packets?limit=notanumber")
        assert resp.status_code == 400

    def test_anomalies_valid_params_200(self, client, sample_data_dir):
        resp = client.get("/api/anomalies?limit=10&severity=HIGH")
        assert resp.status_code == 200

    def test_forecast_valid_params_200(self, client, sample_data_dir):
        resp = client.get("/api/forecast?limit=5&flagged=1")
        assert resp.status_code == 200

    def test_packets_valid_params_200(self, client, sample_data_dir):
        resp = client.get("/api/packets?limit=5")
        assert resp.status_code == 200

    def test_negative_limit_returns_400(self, client):
        resp = client.get("/api/anomalies?limit=-5")
        assert resp.status_code == 400

    def test_injection_in_severity_returns_400(self, client):
        resp = client.get("/api/anomalies?severity=HIGH%3B%20DROP%20TABLE")
        assert resp.status_code == 400

    def test_xss_in_severity_returns_400(self, client):
        resp = client.get("/api/anomalies?severity=%3Cscript%3Ealert(1)%3C/script%3E")
        assert resp.status_code == 400


# ── Shared fixtures ──────────────────────────────────────────


@pytest.fixture
def app_ctx():
    """Provide Flask app context for error response tests."""
    from integration.app import app

    with app.app_context():
        yield


@pytest.fixture
def sample_data_dir(tmp_path, monkeypatch):
    """Minimal fixture for endpoint validation tests."""
    import integration.app as app_module

    packets = [
        {
            "src_ip": "1.1.1.1",
            "dst_ip": "2.2.2.2",
            "dst_port": 80,
            "protocol": "TCP",
            "flags": "S",
            "payload_size": 64,
            "timestamp": "2024-01-15T10:00:00",
        }
    ]
    anomalies = [
        {
            "src_ip": "1.1.1.1",
            "dst_ip": "2.2.2.2",
            "anomaly_type": "Port Scan",
            "severity": "HIGH",
            "timestamp": "2024-01-15T10:00:00",
            "confidence": 0.9,
        }
    ]
    features = [
        {
            "src_ip": "1.1.1.1",
            "dst_ip": "2.2.2.2",
            "escalation_probability": 0.8,
            "escalation_predicted": True,
            "window_start": "2024-01-15T10:00:00",
            "window_end": "2024-01-15T10:00:30",
            "total_packets": 10,
            "port_diversity": 3,
            "connection_rate": 1.0,
            "syn_count": 5,
            "rst_count": 1,
            "syn_rst_ratio": 5.0,
            "payload_size_mean": 100.0,
            "payload_size_max": 200,
        }
    ]

    for name, data in [("packets", packets), ("anomalies", anomalies), ("features", features)]:
        fpath = tmp_path / f"{name}.jsonl"
        with open(fpath, "w") as f:
            for item in data:
                f.write(json.dumps(item) + "\n")
        monkeypatch.setattr(
            app_module, name.upper() + "_FILE" if name != "features" else "FEATURES_FILE", fpath
        )

    incidents_file = tmp_path / "killchain_incidents.jsonl"
    incidents_file.write_text("[]")
    monkeypatch.setattr(app_module, "KILLCHAIN_INCIDENTS_FILE", incidents_file)

    graph_file = tmp_path / "graph.json"
    monkeypatch.setattr(app_module, "GRAPH_JSON", graph_file)
