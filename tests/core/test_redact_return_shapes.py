"""v0.6.11: lock return shape of redact() across with_types/detailed/report combos.

Precedence: report > detailed > with_types > default.

The four shapes:
  - default                       → 2-tuple (redacted, key)
  - with_types=True               → 3-tuple (redacted, key, types_dict)
  - detailed=True                 → 3-tuple (redacted, key, details_dict)
  - report=True                   → RedactReport object

When multiple flags are set, the higher-precedence one wins. ``detailed``'s
``details_dict`` carries per-entity type info too, so promoting it over
``with_types`` is lossless for the caller.
"""

import pytest

from argus_redact import redact


@pytest.fixture
def call():
    def _call(**kw):
        return redact("Alice: 555-1234", lang="en", salt=42, **kw)

    return _call


def test_redact_should_return_2_tuple_by_default(call):
    r = call()
    assert isinstance(r, tuple) and len(r) == 2


def test_redact_should_return_3_tuple_when_with_types_is_set(call):
    r = call(with_types=True)
    assert isinstance(r, tuple) and len(r) == 3
    _redacted, _key, types = r
    assert isinstance(types, dict)


def test_redact_should_return_3_tuple_when_detailed_is_set(call):
    r = call(detailed=True)
    assert isinstance(r, tuple) and len(r) == 3
    _redacted, _key, details = r
    assert isinstance(details, dict)


def test_redact_should_return_report_object_when_report_is_set(call):
    r = call(report=True)
    # The exact type is RedactReport (dataclass); just lock that it's NOT a
    # tuple — the report object encapsulates everything.
    assert not isinstance(r, tuple)


def test_redact_should_prefer_detailed_over_with_types(call):
    """``detailed=True`` + ``with_types=True`` (no report) → detailed shape."""
    r_both = call(detailed=True, with_types=True)
    r_detailed = call(detailed=True)
    # Same 3-tuple shape; third element is the details dict (has "entities" / "stats")
    assert isinstance(r_both, tuple) and len(r_both) == len(r_detailed) == 3
    assert "entities" in r_both[2]
    assert "stats" in r_both[2]


def test_redact_should_prefer_report_over_detailed_and_with_types(call):
    r_all = call(report=True, detailed=True, with_types=True)
    r_report = call(report=True)
    # Same shape — both return the RedactReport object
    assert type(r_all) is type(r_report)
    assert not isinstance(r_all, tuple)


def test_redact_should_prefer_report_over_detailed(call):
    r_both = call(report=True, detailed=True)
    r_report = call(report=True)
    assert type(r_both) is type(r_report)
    assert not isinstance(r_both, tuple)


def test_redact_should_prefer_report_over_with_types(call):
    r_both = call(report=True, with_types=True)
    r_report = call(report=True)
    assert type(r_both) is type(r_report)
    assert not isinstance(r_both, tuple)
