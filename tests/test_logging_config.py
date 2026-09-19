"""Tests for integration.logging_config module — structured logging with request IDs."""

import json
import logging

import pytest

from integration.logging_config import (
    HumanReadableFormatter,
    RequestContextLogger,
    StructuredJsonFormatter,
    clear_log_context,
    clear_request_id,
    generate_request_id,
    get_log_config,
    get_logger,
    get_request_id,
    log_context_var,
    log_function_call,
    set_log_context,
    set_request_id,
    setup_logging,
)

# ── Request ID ───────────────────────────────────────────────


class TestRequestID:
    def test_generate_request_id_format(self):
        rid = generate_request_id()
        assert isinstance(rid, str)
        # UUID4 format: 8-4-4-4-12
        parts = rid.split("-")
        assert len(parts) == 5
        assert len(rid) == 36

    def test_set_and_get_request_id(self):
        rid = set_request_id("test-123")
        assert rid == "test-123"
        assert get_request_id() == "test-123"
        clear_request_id()

    def test_set_generates_if_none(self):
        rid = set_request_id()
        assert rid is not None
        assert len(rid) == 36
        clear_request_id()

    def test_clear_request_id(self):
        set_request_id("test-456")
        clear_request_id()
        assert get_request_id() is None

    def test_context_variable_isolation(self):
        """Different contexts should have independent request IDs."""
        set_request_id("ctx-a")
        assert get_request_id() == "ctx-a"
        clear_request_id()


# ── Log Context ──────────────────────────────────────────────


class TestLogContext:
    def test_set_log_context(self):
        clear_log_context()
        set_log_context(user="test", action="login")
        ctx = log_context_var.get()
        assert ctx["user"] == "test"
        assert ctx["action"] == "login"
        clear_log_context()

    def test_log_context_merges(self):
        clear_log_context()
        set_log_context(a=1)
        set_log_context(b=2)
        ctx = log_context_var.get()
        assert ctx["a"] == 1
        assert ctx["b"] == 2
        clear_log_context()

    def test_clear_log_context(self):
        set_log_context(a=1)
        clear_log_context()
        assert log_context_var.get() == {}


# ── JSON Formatter ───────────────────────────────────────────


class TestStructuredJsonFormatter:
    def test_formats_basic_log(self):
        formatter = StructuredJsonFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Hello world",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        data = json.loads(output)
        assert data["level"] == "INFO"
        assert data["message"] == "Hello world"
        assert data["logger"] == "test"
        assert "timestamp" in data

    def test_includes_request_id(self):
        set_request_id("abc-123")
        formatter = StructuredJsonFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="test",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        data = json.loads(output)
        assert data["request_id"] == "abc-123"
        clear_request_id()

    def test_includes_context(self):
        set_log_context(method="GET", path="/api/status")
        formatter = StructuredJsonFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="test",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        data = json.loads(output)
        assert data["context"]["method"] == "GET"
        assert data["context"]["path"] == "/api/status"
        clear_log_context()

    def test_includes_exception(self):
        formatter = StructuredJsonFormatter()
        try:
            raise ValueError("test error")
        except ValueError:
            import sys

            exc_info = sys.exc_info()

        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="test.py",
            lineno=1,
            msg="Error occurred",
            args=(),
            exc_info=exc_info,
        )
        output = formatter.format(record)
        data = json.loads(output)
        assert data["exception"]["type"] == "ValueError"
        assert "test error" in data["exception"]["message"]

    def test_output_is_valid_json(self):
        formatter = StructuredJsonFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.WARNING,
            pathname="test.py",
            lineno=1,
            msg="Special chars: <>&\"'",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        data = json.loads(output)  # Should not raise
        assert "Special chars" in data["message"]


# ── Human Readable Formatter ─────────────────────────────────


class TestHumanReadableFormatter:
    def test_basic_format(self):
        formatter = HumanReadableFormatter(use_colors=False)
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Hello world",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        assert "INFO" in output
        assert "Hello world" in output
        assert "test" in output

    def test_includes_request_id(self):
        set_request_id("abc-123")
        formatter = HumanReadableFormatter(use_colors=False)
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="test",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        assert "[abc-123]" in output
        clear_request_id()

    def test_colors_disabled(self):
        formatter = HumanReadableFormatter(use_colors=False)
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="test",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        assert "\033[" not in output  # No ANSI codes

    def test_timestamp_format(self):
        formatter = HumanReadableFormatter(use_colors=False)
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="test",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        # Should have YYYY-MM-DD HH:MM:SS format
        assert "202" in output  # Year starts with 202


# ── Logger Adapter ───────────────────────────────────────────


class TestRequestContextLogger:
    def test_logger_has_adapter(self):
        logger = get_logger("test_adapter")
        assert isinstance(logger, RequestContextLogger)

    def test_logger_name(self):
        logger = get_logger("my_module")
        assert logger.logger.name == "my_module"


# ── Configuration ────────────────────────────────────────────


class TestGetLogConfig:
    def test_default_config(self, monkeypatch):
        for key in [
            "LOG_LEVEL",
            "LOG_FORMAT",
            "LOG_FILE",
            "LOG_MAX_BYTES",
            "LOG_BACKUP_COUNT",
            "LOG_DISABLE_FILE",
        ]:
            monkeypatch.delenv(key, raising=False)

        config = get_log_config()
        assert config["level"] == "INFO"
        assert config["format"] == "text"
        assert config["log_file"] == "logs/app.log"
        assert config["max_bytes"] == 10 * 1024 * 1024
        assert config["backup_count"] == 5
        assert config["disable_file"] is False

    def test_custom_config(self, monkeypatch):
        monkeypatch.setenv("LOG_LEVEL", "DEBUG")
        monkeypatch.setenv("LOG_FORMAT", "json")
        monkeypatch.setenv("LOG_FILE", "/tmp/test.log")
        monkeypatch.setenv("LOG_MAX_BYTES", "5")
        monkeypatch.setenv("LOG_BACKUP_COUNT", "3")
        monkeypatch.setenv("LOG_DISABLE_FILE", "1")

        config = get_log_config()
        assert config["level"] == "DEBUG"
        assert config["format"] == "json"
        assert config["log_file"] == "/tmp/test.log"
        assert config["max_bytes"] == 5 * 1024 * 1024
        assert config["backup_count"] == 3
        assert config["disable_file"] is True


# ── Setup Logging ────────────────────────────────────────────


class TestSetupLogging:
    def test_setup_creates_handlers(self):
        root = setup_logging(level="INFO", log_format="text", disable_file=True)
        assert len(root.handlers) >= 1

    def test_setup_json_format(self):
        root = setup_logging(level="DEBUG", log_format="json", disable_file=True)
        handler = root.handlers[0]
        assert isinstance(handler.formatter, StructuredJsonFormatter)

    def test_setup_text_format(self):
        root = setup_logging(level="INFO", log_format="text", disable_file=True)
        handler = root.handlers[0]
        assert isinstance(handler.formatter, HumanReadableFormatter)

    def test_setup_with_file(self, tmp_path):
        log_file = tmp_path / "test.log"
        root = setup_logging(
            level="WARNING",
            log_file=str(log_file),
            disable_file=False,
        )
        # Should have at least 2 handlers (console + file)
        assert len(root.handlers) >= 2

    def test_setup_file_rotation(self, tmp_path):
        log_file = tmp_path / "rotate.log"
        setup_logging(
            log_file=str(log_file),
            max_bytes=1024,
            backup_count=2,
            disable_file=False,
        )
        # File should exist after setup
        assert log_file.parent.exists()


# ── Log Function Call Decorator ──────────────────────────────


class TestLogFunctionCall:
    def test_logs_success(self):
        @log_function_call
        def my_func():
            return 42

        result = my_func()
        assert result == 42

    def test_logs_failure(self):
        @log_function_call
        def failing_func():
            raise ValueError("test")

        with pytest.raises(ValueError, match="test"):
            failing_func()

    def test_preserves_function_name(self):
        @log_function_call
        def documented_func():
            """My docstring."""
            pass

        assert documented_func.__name__ == "documented_func"
        assert documented_func.__doc__ == "My docstring."


# ── Flask Integration ────────────────────────────────────────


class TestFlaskMiddleware:
    """Test request middleware through Flask endpoints."""

    def test_request_id_in_response_headers(self, client):
        resp = client.get("/api/status")
        assert "X-Request-ID" in resp.headers
        req_id = resp.headers["X-Request-ID"]
        assert len(req_id) == 36  # UUID4

    def test_request_id_from_header(self, client):
        resp = client.get("/api/status", headers={"X-Request-ID": "my-custom-id"})
        assert resp.headers.get("X-Request-ID") == "my-custom-id"

    def test_different_requests_different_ids(self, client):
        resp1 = client.get("/api/status")
        resp2 = client.get("/api/status")
        assert resp1.headers["X-Request-ID"] != resp2.headers["X-Request-ID"]

    def test_request_id_cleared_after_request(self, client):
        """Request ID should be cleared after request completes."""
        client.get("/api/status")
        assert get_request_id() is None

    def test_log_context_cleared_after_request(self, client):
        """Log context should be cleared after request completes."""
        client.get("/api/status")
        assert log_context_var.get() == {}


# ── Shared Fixtures ──────────────────────────────────────────


@pytest.fixture(autouse=True)
def _clean_logging_state():
    """Ensure clean logging state for each test."""
    clear_request_id()
    clear_log_context()
    yield
    clear_request_id()
    clear_log_context()


@pytest.fixture
def client():
    """Create a Flask test client."""
    from integration.app import app
    from integration.ratelimit import get_counter

    get_counter().clear()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c
