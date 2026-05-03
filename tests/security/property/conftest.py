"""Shared hypothesis settings for security property tests."""

from hypothesis import HealthCheck, settings


# Default settings for property tests. Per-test override via:
#     @settings(parent=PROPERTY_SETTINGS, max_examples=200)
PROPERTY_SETTINGS = settings(
    database=None,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
    max_examples=100,
)
