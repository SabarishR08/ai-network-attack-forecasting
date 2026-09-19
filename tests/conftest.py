"""Shared pytest configuration and fixtures."""

import sys
from pathlib import Path

import pytest

# Ensure the project root is on sys.path for imports
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Also add repo paths needed by the integration modules
for p in [
    str(PROJECT_ROOT / "repos" / "Network-Threat-Anomaly-Visualizer"),
    str(PROJECT_ROOT / "repos" / "Network-Threat-Anomaly-Visualizer" / "src"),
    str(PROJECT_ROOT / "repos" / "network-intrusion-detection"),
    str(PROJECT_ROOT / "repos" / "network-intrusion-detection" / "src"),
    str(PROJECT_ROOT / "repos" / "cyber-killchain-reconstruction-engine"),
]:
    if p not in sys.path:
        sys.path.insert(0, p)


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Reset rate limiter state between tests to prevent cross-test leaks."""
    from integration.ratelimit import get_counter

    get_counter().clear()
    yield
    get_counter().clear()


@pytest.fixture
def client():
    """Create a Flask test client available to all test modules."""
    from integration.app import app

    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c
