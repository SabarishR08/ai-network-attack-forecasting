"""
Structured logging with request IDs, JSON formatting, and log rotation.

Features:
- Unique request IDs (UUID4) injected into every log entry
- JSON-structured log format for machine parsing
- Human-readable console format for development
- Rotating file handler with configurable size/backup count
- Context variable support for async request tracking

Configuration via environment variables:
    LOG_LEVEL              Logging level (default: INFO)
    LOG_FORMAT             "json" or "text" (default: text)
    LOG_FILE               Path to log file (default: logs/app.log)
    LOG_MAX_BYTES          Max log file size in MB (default: 10)
    LOG_BACKUP_COUNT       Number of backup files (default: 5)
    LOG_DISABLE_FILE       Set to 1 to disable file logging
"""

import json
import logging
import logging.handlers
import os
import sys
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone

UTC = timezone.utc
from pathlib import Path
from typing import Optional

# ── Context Variables ────────────────────────────────────────

# Request ID propagated across the request lifecycle
request_id_var: ContextVar[Optional[str]] = ContextVar("request_id", default=None)

# Additional context fields added to every log entry
log_context_var: ContextVar[dict] = ContextVar("log_context", default={})


# ── JSON Formatter ───────────────────────────────────────────


class StructuredJsonFormatter(logging.Formatter):
    """
    Formats log records as structured JSON with request ID and context.

    Output format:
    {
        "timestamp": "2024-01-15T10:00:00.000Z",
        "level": "INFO",
        "logger": "integration.app",
        "message": "Request processed",
        "request_id": "abc-123",
        "module": "app",
        "function": "api_dashboard",
        "line": 42,
        "extra": {}
    }
    """

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add request ID from context
        request_id = request_id_var.get()
        if request_id:
            log_entry["request_id"] = request_id

        # Add any extra context
        context = log_context_var.get()
        if context:
            log_entry["context"] = context

        # Add exception info if present
        if record.exc_info and record.exc_info[0] is not None:
            log_entry["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
                "traceback": self.formatException(record.exc_info),
            }

        # Add any extra fields set via LoggerAdapter
        extra_fields = {}
        for key in list(record.__dict__.keys()):
            if key not in logging.LogRecord("", 0, "", 0, "", (), None).__dict__:
                if not key.startswith("_"):
                    extra_fields[key] = getattr(record, key)
        if extra_fields:
            log_entry["extra"] = extra_fields

        return json.dumps(log_entry, default=str, ensure_ascii=False)


class HumanReadableFormatter(logging.Formatter):
    """
    Human-readable format for development console output.

    Format: [TIMESTAMP] LEVEL [request_id] logger: message
    """

    COLORS = {
        "DEBUG": "\033[36m",  # Cyan
        "INFO": "\033[32m",  # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",  # Red
        "CRITICAL": "\033[35m",  # Magenta
    }
    RESET = "\033[0m"

    def __init__(self, use_colors: bool = True):
        super().__init__()
        self.use_colors = use_colors and sys.stderr.isatty()

    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.fromtimestamp(record.created, tz=UTC).strftime("%Y-%m-%d %H:%M:%S")
        level = record.levelname.ljust(8)

        # Request ID (truncated for readability)
        request_id = request_id_var.get()
        req_id_str = ""
        if request_id:
            req_id_str = f" [{request_id[:8]}]"

        # Color coding
        if self.use_colors:
            color = self.COLORS.get(record.levelname, "")
            level = f"{color}{level}{self.RESET}"

        message = record.getMessage()
        logger_name = record.name

        line = f"[{timestamp}] {level}{req_id_str} {logger_name}: {message}"

        if record.exc_info and record.exc_info[0] is not None:
            line += "\n" + self.formatException(record.exc_info)

        return line


# ── Logger Adapter ───────────────────────────────────────────


class RequestContextLogger(logging.LoggerAdapter):
    """
    Logger adapter that automatically adds request context to log entries.
    """

    def process(self, msg, kwargs):
        extra = kwargs.get("extra", {})
        context = log_context_var.get()

        # Merge any new context
        if context:
            extra["context"] = context

        kwargs["extra"] = extra
        return msg, kwargs


# ── Configuration ────────────────────────────────────────────


def get_log_config() -> dict:
    """Load logging configuration from environment variables."""
    return {
        "level": os.getenv("LOG_LEVEL", "INFO").upper(),
        "format": os.getenv("LOG_FORMAT", "text").lower(),
        "log_file": os.getenv("LOG_FILE", "logs/app.log"),
        "max_bytes": int(os.getenv("LOG_MAX_BYTES", "10")) * 1024 * 1024,  # MB to bytes
        "backup_count": int(os.getenv("LOG_BACKUP_COUNT", "5")),
        "disable_file": os.getenv("LOG_DISABLE_FILE", "0") == "1",
    }


def setup_logging(
    level: Optional[str] = None,
    log_format: Optional[str] = None,
    log_file: Optional[str] = None,
    max_bytes: Optional[int] = None,
    backup_count: Optional[int] = None,
    disable_file: Optional[bool] = None,
) -> logging.Logger:
    """
    Configure structured logging for the application.

    Sets up:
    - Console handler (human-readable or JSON based on LOG_FORMAT)
    - Rotating file handler (JSON format for machine parsing)
    - Request context propagation

    Returns the root logger for the application.
    """
    config = get_log_config()

    # Override with explicit parameters
    if level is not None:
        config["level"] = level.upper()
    if log_format is not None:
        config["format"] = log_format.lower()
    if log_file is not None:
        config["log_file"] = log_file
    if max_bytes is not None:
        config["max_bytes"] = max_bytes
    if backup_count is not None:
        config["backup_count"] = backup_count
    if disable_file is not None:
        config["disable_file"] = disable_file

    log_level = getattr(logging, config["level"], logging.INFO)

    # Clear existing handlers
    root_logger = logging.getLogger()
    root_logger.handlers.clear()

    # ── Console Handler ──────────────────────────────────
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(log_level)

    if config["format"] == "json":
        console_handler.setFormatter(StructuredJsonFormatter())
    else:
        console_handler.setFormatter(HumanReadableFormatter(use_colors=sys.stderr.isatty()))

    root_logger.addHandler(console_handler)

    # ── File Handler (rotating) ──────────────────────────
    if not config["disable_file"]:
        log_path = Path(config["log_file"])
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.handlers.RotatingFileHandler(
            filename=str(log_path),
            maxBytes=config["max_bytes"],
            backupCount=config["backup_count"],
            encoding="utf-8",
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(StructuredJsonFormatter())
        root_logger.addHandler(file_handler)

    root_logger.setLevel(log_level)

    # Log startup message
    logger = logging.getLogger("logging_config")
    logger.info(
        f"Logging initialized: level={config['level']}, "
        f"format={config['format']}, "
        f"file={'disabled' if config['disable_file'] else config['log_file']}"
    )

    return root_logger


# ── Request ID Utilities ─────────────────────────────────────


def generate_request_id() -> str:
    """Generate a new unique request ID."""
    return str(uuid.uuid4())


def set_request_id(request_id: Optional[str] = None) -> str:
    """Set the request ID for the current context. Returns the ID."""
    if request_id is None:
        request_id = generate_request_id()
    request_id_var.set(request_id)
    return request_id


def get_request_id() -> Optional[str]:
    """Get the current request ID."""
    return request_id_var.get()


def clear_request_id():
    """Clear the current request ID."""
    request_id_var.set(None)


def set_log_context(**kwargs):
    """Set additional context fields for the current request."""
    current = log_context_var.get().copy()
    current.update(kwargs)
    log_context_var.set(current)


def clear_log_context():
    """Clear the current log context."""
    log_context_var.set({})


# ── Flask Middleware ──────────────────────────────────────────


def create_request_middleware(app):
    """
    Create Flask middleware that:
    1. Generates a request ID for each request
    2. Stores it in context variables
    3. Adds it to response headers
    4. Logs request start/end
    """
    from flask import request as flask_request

    @app.before_request
    def before_request():
        # Use existing request ID from header, or generate new one
        req_id = flask_request.headers.get("X-Request-ID")
        if not req_id:
            req_id = generate_request_id()

        set_request_id(req_id)
        set_log_context(
            method=flask_request.method,
            path=flask_request.path,
            remote_addr=flask_request.remote_addr,
        )

        logger = logging.getLogger("request")
        logger.info(f"Request started: {flask_request.method} {flask_request.path}")

    @app.after_request
    def after_request(response):
        req_id = get_request_id()
        if req_id:
            response.headers["X-Request-ID"] = req_id

        logger = logging.getLogger("request")
        logger.info(
            f"Request completed: {flask_request.method} {flask_request.path} "
            f"-> {response.status_code}"
        )

        # Clear context for next request
        clear_log_context()
        clear_request_id()

        return response

    @app.teardown_request
    def teardown_request(exc):
        if exc:
            logger = logging.getLogger("request")
            logger.error(f"Request teardown with exception: {exc}")
        clear_request_id()
        clear_log_context()


# ── Convenience Functions ────────────────────────────────────


def get_logger(name: str) -> RequestContextLogger:
    """
    Get a logger with request context support.

    Usage:
        logger = get_logger(__name__)
        logger.info("Processing data")  # Automatically includes request_id
    """
    base_logger = logging.getLogger(name)
    return RequestContextLogger(base_logger, {})


def log_function_call(func):
    """Decorator that logs function entry and exit with timing."""
    import functools
    import time

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        logger = get_logger(func.__module__)
        start = time.time()
        logger.info(f"Starting {func.__name__}")
        try:
            result = func(*args, **kwargs)
            elapsed = round((time.time() - start) * 1000, 2)
            logger.info(f"Completed {func.__name__} in {elapsed}ms")
            return result
        except Exception as e:
            elapsed = round((time.time() - start) * 1000, 2)
            logger.error(f"Failed {func.__name__} after {elapsed}ms: {e}")
            raise

    return wrapper
