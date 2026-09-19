"""
Input validation and sanitization for SIH26153 Flask API endpoints.

Provides reusable validators that:
- Clamp numeric parameters to safe ranges
- Whitelist string parameters against allowed values
- Sanitize strings to prevent injection (XSS, log injection, etc.)
- Return consistent error responses via Flask's jsonify
"""

import html
import re
from typing import Any, Optional, Tuple

from flask import jsonify

# ── Constants ────────────────────────────────────────────────

# Maximum allowed limit for paginated endpoints
MAX_LIMIT = 10_000
DEFAULT_LIMIT = 500

# Allowed severity values (uppercase)
ALLOWED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

# Allowed anomaly type values
ALLOWED_ANOMALY_TYPES = {
    "Port Scan",
    "Brute Force",
    "Connection Cycling",
    "Suspicious Connection",
}

# Regex for IP address validation (IPv4)
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

# Characters considered dangerous in log/message contexts
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


# ── Numeric Validators ───────────────────────────────────────


def validate_limit(value: Any, default: int = DEFAULT_LIMIT) -> Tuple[int, Optional[str]]:
    """
    Validate and clamp a pagination limit parameter.

    Returns:
        (clamped_value, None) on success
        (default, error_message) on failure
    """
    if value is None:
        return default, None

    try:
        limit = int(value)
    except (TypeError, ValueError):
        return default, f"Invalid limit value: {value!r} (must be an integer)"

    if limit < 0:
        return default, f"Invalid limit value: {limit} (must be non-negative)"

    if limit > MAX_LIMIT:
        return MAX_LIMIT, None

    return limit, None


# ── String Validators ────────────────────────────────────────


def validate_severity(value: str) -> Tuple[str, Optional[str]]:
    """
    Validate a severity filter against the allowed set.

    Returns:
        (normalized_severity, None) on success
        ("", error_message) on failure
    """
    if not value:
        return "", None

    normalized = value.strip().upper()

    if normalized not in ALLOWED_SEVERITIES:
        return "", (
            f"Invalid severity: {value!r}. Allowed values: {', '.join(sorted(ALLOWED_SEVERITIES))}"
        )

    return normalized, None


def validate_flagged(value: str) -> Tuple[bool, Optional[str]]:
    """
    Validate the 'flagged' query parameter (must be '0' or '1').

    Returns:
        (bool_value, None) on success
        (False, error_message) on failure
    """
    if not value or value == "0":
        return False, None
    if value == "1":
        return True, None
    return False, f"Invalid flagged value: {value!r} (must be '0' or '1')"


# ── String Sanitizers ────────────────────────────────────────


def sanitize_string(value: str, max_length: int = 1000) -> str:
    """
    Sanitize a string value for safe use in responses and logs.

    - Strips control characters (except newlines/tabs)
    - HTML-escapes special characters
    - Truncates to max_length
    """
    if not isinstance(value, str):
        value = str(value)

    # Remove control characters (keep printable, newline, tab)
    cleaned = _CONTROL_CHARS_RE.sub("", value)

    # HTML-escape to prevent XSS in rendered responses
    cleaned = html.escape(cleaned, quote=True)

    # Truncate
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length] + "..."

    return cleaned


def sanitize_ip(value: str) -> Tuple[str, Optional[str]]:
    """
    Validate and sanitize an IP address string.

    Returns:
        (ip_address, None) on success
        ("", error_message) on failure
    """
    if not value:
        return "", None

    cleaned = sanitize_string(value, max_length=45)  # IPv6 max length

    if _IPV4_RE.match(cleaned):
        return cleaned, None

    return cleaned, None  # Accept non-IPv4 (could be hostname, IPv6, etc.)


# ── Response Helpers ─────────────────────────────────────────


def error_response(message: str, status_code: int = 400):
    """Create a consistent JSON error response."""
    return jsonify(
        {
            "error": True,
            "message": sanitize_string(message),
            "status": status_code,
        }
    ), status_code


def validation_error(message: str):
    """Shorthand for a 400 validation error response."""
    return error_response(message, 400)


# ── Composite Validators ─────────────────────────────────────


def validate_anomaly_params(limit_raw: Any, severity_raw: str) -> Tuple[int, str, Optional[str]]:
    """
    Validate all parameters for /api/anomalies.

    Returns:
        (limit, severity, None) on success
        (default, "", error_message) on failure
    """
    limit, err = validate_limit(limit_raw)
    if err:
        return DEFAULT_LIMIT, "", err

    severity, err = validate_severity(severity_raw)
    if err:
        return limit, "", err

    return limit, severity, None


def validate_forecast_params(limit_raw: Any, flagged_raw: str) -> Tuple[int, bool, Optional[str]]:
    """
    Validate all parameters for /api/forecast.

    Returns:
        (limit, flagged, None) on success
        (default, False, error_message) on failure
    """
    limit, err = validate_limit(limit_raw)
    if err:
        return DEFAULT_LIMIT, False, err

    flagged, err = validate_flagged(flagged_raw)
    if err:
        return limit, False, err

    return limit, flagged, None


def validate_packet_params(limit_raw: Any) -> Tuple[int, Optional[str]]:
    """
    Validate all parameters for /api/packets.

    Returns:
        (limit, None) on success
        (default, error_message) on failure
    """
    limit, err = validate_limit(limit_raw)
    if err:
        return DEFAULT_LIMIT, err

    return limit, None
