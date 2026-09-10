"""The coverage_restored security event and its sibling warning.

Mirrors the mask_collision pair: a structured *_event() builder for the
report/detailed shapes, and a warn_*() emitter that reaches every return shape.
"""

import warnings

import pytest

from argus_redact.exceptions import SecurityWarning
from argus_redact.pure.replacer import coverage_restored_event, warn_coverage_restored


def test_coverage_restored_event_should_return_none_when_nothing_was_restored():
    assert coverage_restored_event([]) is None


def test_coverage_restored_event_should_report_types_and_counts_when_types_were_restored():
    event = coverage_restored_event(["phone", "id_number", "phone"])
    assert event["type"] == "security"
    assert event["reason_code"] == "coverage_restored"
    assert event["count"] == 3
    # PII-free: type names only, never a value.
    assert event["detail"] == "types: id_number, phone"


def test_warn_coverage_restored_should_stay_silent_when_nothing_was_restored():
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        warn_coverage_restored([])


def test_warn_coverage_restored_should_emit_security_warning_when_types_were_restored():
    with pytest.warns(SecurityWarning, match="coverage"):
        warn_coverage_restored(["phone", "id_number"])
