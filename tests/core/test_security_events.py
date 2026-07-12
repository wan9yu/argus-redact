import warnings

from argus_redact.pure.security_events import (
    GUARD_NO_ANCHOR,
    INJECTION_SUSPECTED,
    KEEP_DOWNGRADED,
    OUT_OF_SCOPE_PSEUDONYM,
    PROVENANCE_FAILED,
    advisory_events,
    security_event,
    warn_security_events,
)


def test_security_event_shape():
    e = security_event(PROVENANCE_FAILED, count=1, detail="nonce absent")
    assert e == {
        "type": "security",
        "reason_code": "provenance_failed",
        "count": 1,
        "detail": "nonce absent",
    }


def test_security_event_default_detail_none():
    assert security_event(PROVENANCE_FAILED, count=2)["detail"] is None


def test_explicit_stacklevel_override_is_still_honoured():
    """``stacklevel=None`` (the default) auto-detects the caller's frame; an
    explicit value must still bypass auto-detection for advanced callers that
    know their own call depth."""
    events = [security_event(PROVENANCE_FAILED, count=1)]

    def _wrapper():
        warn_security_events(events, stacklevel=1)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        _wrapper()
    # stacklevel=1 attributes to the warn() call site itself (inside
    # security_events.py). Auto-detection would instead point at _wrapper's
    # frame in THIS file, so this proves the explicit value won, not autodetect.
    assert caught[0].filename.endswith("security_events.py"), (
        f"explicit stacklevel was not honoured: {caught[0].filename}"
    )


def test_advisory_events_filters_out_withheld_codes():
    """advisory_events() must DROP withheld codes and KEEP advisory ones.

    A mixed list — at least one withheld code, at least one advisory code —
    is required to make this non-vacuous: an implementation that returns
    ``events`` unchanged would pass a list of advisory-only events but must
    FAIL here, because the withheld ones would leak through.
    """
    withheld = [
        security_event(PROVENANCE_FAILED, count=1),
        security_event(GUARD_NO_ANCHOR, count=1),
        security_event(OUT_OF_SCOPE_PSEUDONYM, count=1),
    ]
    advisory = [
        security_event(INJECTION_SUSPECTED, count=1),
        security_event(KEEP_DOWNGRADED, count=1),
    ]
    mixed = withheld + advisory

    result = advisory_events(mixed)

    assert result == advisory
    result_codes = {e["reason_code"] for e in result}
    withheld_codes = {e["reason_code"] for e in withheld}
    assert result_codes.isdisjoint(withheld_codes)


def test_advisory_events_empty_input_returns_empty():
    assert advisory_events([]) == []


def test_advisory_events_all_withheld_returns_empty():
    withheld = [security_event(PROVENANCE_FAILED, count=1)]
    assert advisory_events(withheld) == []
