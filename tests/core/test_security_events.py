import warnings

from argus_redact.pure.security_events import (
    PROVENANCE_FAILED,
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
