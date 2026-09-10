"""Theme B: collect_security_events unifies event extraction across shapes."""

from argus_redact._types import RedactReport
from argus_redact.compose.audit import collect_security_events

_EV = {"type": "security", "reason_code": "keep_downgraded", "count": 1, "detail": "types: phone"}


def test_collect_security_events_should_extract_events_from_a_redact_3_tuple():
    result = ("redacted", {"P-1": "x"}, {"entities": [], "stats": {}, "security_events": [_EV]})
    assert collect_security_events(result) == [_EV]


def test_collect_security_events_should_extract_events_from_a_restore_2_tuple():
    result = ("restored", {"security_events": [_EV]})
    assert collect_security_events(result) == [_EV]


def test_collect_security_events_should_extract_events_from_a_redact_report():
    report = RedactReport(redacted_text="x", key={}, security_events=(_EV,))
    assert collect_security_events(report) == [_EV]


def test_collect_security_events_should_return_empty_when_key_is_missing():
    assert collect_security_events(("redacted", {"P-1": "x"}, {"entities": [], "stats": {}})) == []


def test_collect_security_events_should_return_empty_when_given_a_non_result_value():
    assert collect_security_events("just a string") == []
    assert collect_security_events(None) == []
