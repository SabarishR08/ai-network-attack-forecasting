"""
Lightweight in-memory sliding window rate limiter for Flask.

Uses a per-IP sliding window counter. No external dependencies required.
Configure via environment variables:

    RATE_LIMIT_ENABLED=1           Enable/disable (default: enabled)
    RATE_LIMIT_DEFAULT=60/min      Default limit for unclassified endpoints
    RATE_LIMIT_API=120/min         Limit for read-only API endpoints
    RATE_LIMIT_PIPELINE=5/hour     Limit for heavy endpoints (pipeline)
    RATE_LIMIT_DOCS=30/min         Limit for documentation endpoints

Rate limit headers are added to every response:
    X-RateLimit-Limit     — max requests in window
    X-RateLimit-Remaining — remaining requests
    X-RateLimit-Reset     — seconds until window resets

When exceeded, returns 429 Too Many Requests with Retry-After header.
"""

import os
import threading
import time
from collections import defaultdict
from functools import wraps
from typing import Callable, Optional, Tuple

from flask import Flask, jsonify, request

# ── Configuration ────────────────────────────────────────────


def _parse_rate(rate_str: str) -> Tuple[int, int]:
    """Parse a rate string like '60/min' into (count, window_seconds)."""
    parts = rate_str.strip().split("/")
    if len(parts) != 2:
        return 60, 60  # default: 60 per minute

    count = int(parts[0])
    unit = parts[1].lower()

    window_map = {
        "sec": 1,
        "s": 1,
        "min": 60,
        "m": 60,
        "hour": 3600,
        "h": 3600,
        "day": 86400,
        "d": 86400,
    }
    window = window_map.get(unit, 60)
    return count, window


def _get_config() -> dict:
    """Load rate limit configuration from environment."""
    enabled = os.getenv("RATE_LIMIT_ENABLED", "1") == "1"
    return {
        "enabled": enabled,
        "default": _parse_rate(os.getenv("RATE_LIMIT_DEFAULT", "60/min")),
        "api": _parse_rate(os.getenv("RATE_LIMIT_API", "120/min")),
        "pipeline": _parse_rate(os.getenv("RATE_LIMIT_PIPELINE", "5/hour")),
        "docs": _parse_rate(os.getenv("RATE_LIMIT_DOCS", "30/min")),
    }


# ── Sliding Window Counter ───────────────────────────────────


class SlidingWindowCounter:
    """
    Thread-safe sliding window rate limiter.

    Tracks request timestamps per key (typically IP address)
    and enforces a maximum count within a rolling time window.
    """

    def __init__(self):
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def check(self, key: str, max_requests: int, window_seconds: int) -> Tuple[bool, int, int]:
        """
        Check if a request is allowed.

        Args:
            key: Identifier (e.g., IP address)
            max_requests: Maximum allowed requests in the window
            window_seconds: Window duration in seconds

        Returns:
            (allowed, remaining, reset_seconds)
        """
        now = time.time()
        cutoff = now - window_seconds

        with self._lock:
            # Prune old entries
            timestamps = self._requests[key]
            self._requests[key] = [t for t in timestamps if t > cutoff]
            timestamps = self._requests[key]

            if len(timestamps) >= max_requests:
                # Calculate when the oldest request in window expires
                reset = int(timestamps[0] - cutoff) + 1
                remaining = 0
                return False, remaining, max(1, reset)

            # Record this request
            timestamps.append(now)
            remaining = max_requests - len(timestamps)

            # Reset in window_seconds from now
            reset = window_seconds
            return True, remaining, reset

    def clear(self):
        """Reset all counters."""
        with self._lock:
            self._requests.clear()


# ── Global instance ──────────────────────────────────────────

_counter = SlidingWindowCounter()


def get_counter() -> SlidingWindowCounter:
    """Get the global rate limiter counter (useful for testing)."""
    return _counter


# ── Client Key Resolution ────────────────────────────────────


def _get_client_key() -> str:
    """Get the client identifier for rate limiting."""
    # Use X-Forwarded-For if behind a proxy, otherwise remote_addr
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


# ── Rate Limit Decorator ─────────────────────────────────────


def rate_limit(
    max_requests: Optional[int] = None,
    window_seconds: Optional[int] = None,
    category: str = "api",
    key_func: Optional[Callable] = None,
):
    """
    Flask route decorator for rate limiting.

    Args:
        max_requests: Override max requests (if None, uses config for category)
        window_seconds: Override window (if None, uses config for category)
        category: Config category ('api', 'pipeline', 'docs', 'default')
        key_func: Custom key function (default: client IP)
    """

    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            config = _get_config()

            if not config["enabled"]:
                return f(*args, **kwargs)

            # Determine limits
            if max_requests is not None and window_seconds is not None:
                limit_count, limit_window = max_requests, window_seconds
            else:
                limit_count, limit_window = config.get(category, config["default"])

            # Get client key
            key = key_func() if key_func else _get_client_key()

            # Check rate limit
            allowed, remaining, reset = _counter.check(key, limit_count, limit_window)

            if not allowed:
                response = jsonify(
                    {
                        "error": True,
                        "message": "Rate limit exceeded. Try again later.",
                        "status": 429,
                    }
                )
                response.status_code = 429
                response.headers["X-RateLimit-Limit"] = str(limit_count)
                response.headers["X-RateLimit-Remaining"] = "0"
                response.headers["X-RateLimit-Reset"] = str(reset)
                response.headers["Retry-After"] = str(reset)
                return response

            # Execute the route
            result = f(*args, **kwargs)

            # Add rate limit headers to Flask response objects
            def _add_headers(resp):
                if hasattr(resp, "headers"):
                    resp.headers["X-RateLimit-Limit"] = str(limit_count)
                    resp.headers["X-RateLimit-Remaining"] = str(remaining)
                    resp.headers["X-RateLimit-Reset"] = str(reset)

            if isinstance(result, tuple):
                _add_headers(result[0])
            else:
                _add_headers(result)

            return result

        return wrapped

    return decorator


# ── Convenience Decorators ────────────────────────────────────


def api_rate_limit(f):
    """Apply default API rate limit (120/min)."""
    return rate_limit(category="api")(f)


def pipeline_rate_limit(f):
    """Apply strict pipeline rate limit (5/hour)."""
    return rate_limit(category="pipeline")(f)


def docs_rate_limit(f):
    """Apply docs rate limit (30/min)."""
    return rate_limit(category="docs")(f)


# ── Flask Integration ────────────────────────────────────────


def init_rate_limiting(app: Flask):
    """
    Initialize rate limiting for a Flask app.

    This registers an error handler for 429 responses
    and sets up configuration.
    """

    @app.errorhandler(429)
    def ratelimit_handler(e):
        return jsonify(
            {
                "error": True,
                "message": "Rate limit exceeded. Try again later.",
                "status": 429,
            }
        ), 429
