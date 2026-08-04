"""The coverage_restored security event and its sibling warning.

Mirrors the mask_collision pair: a structured *_event() builder for the
report/detailed shapes, and a warn_*() emitter that reaches every return shape.
"""

import warnings

import pytest

from argus_redact.exceptions import SecurityWarning
from argus_redact.pure.replacer import coverage_restored_event, warn_coverage_restored


def test_event_is_none_when_nothing_was_restored():
    assert coverage_restored_event([]) is None


def test_event_names_types_only_and_counts_them():
    event = coverage_restored_event(["phone", "id_number", "phone"])
    assert event["type"] == "security"
    assert event["reason_code"] == "coverage_restored"
    assert event["count"] == 3
    # PII-free: type names only, never a value.
    assert event["detail"] == "types: id_number, phone"


def test_warning_is_silent_when_nothing_was_restored():
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        warn_coverage_restored([])


def test_warning_names_the_count_and_is_a_security_warning():
    with pytest.warns(SecurityWarning, match="coverage"):
        warn_coverage_restored(["phone", "id_number"])
