"""Task 7 (C1): mask-family collisions are signalled, not silently misattributed.

Two different originals masking to the same visible string (e.g. two phones ->
"138****5678") are disambiguated only by a trailing circled digit (①). An LLM
that normalizes that glyph away collapses both key entries, so restore()
returns the FIRST person's data for BOTH — a silent wrong-identity swap.

The fix keeps the direct in-process key entry (both originals stay restorable
in-process) but makes the collision honest: a SecurityWarning fires, and a
`mask_collision` security_event is emitted in the structured channel, naming
that the disambiguator is not LLM-round-trip-durable.
"""

import warnings

import pytest

from argus_redact import redact
from argus_redact.exceptions import SecurityWarning

# Two distinct CN mobile numbers that both mask to "138****5678" (mask only
# shows the first 3 + last 4 chars; the middle 4 digits are hidden either way).
_TEXT = "电话13812345678 和 13800005678"
_CONFIG = {"phone": {"strategy": "mask"}}


def test_mask_collision_emits_security_warning():
    """A real mask-family collision must fire a SecurityWarning naming it."""
    with pytest.warns(SecurityWarning, match="collided"):
        redact(_TEXT, lang="zh", mode="fast", config=_CONFIG)


def test_mask_collision_structured_event_has_right_count():
    """redact(detailed=True) surfaces a `mask_collision` security_event."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SecurityWarning)
        _redacted, _key, details = redact(
            _TEXT, lang="zh", mode="fast", config=_CONFIG, detailed=True
        )
    events = [e for e in details["security_events"] if e["reason_code"] == "mask_collision"]
    assert len(events) == 1
    assert events[0]["count"] == 1
    assert events[0]["type"] == "security"
    # PII-free: only the TYPE is named, never the raw or masked value.
    assert events[0]["detail"] == "types: phone"
    assert "13812345678" not in events[0]["detail"]
    assert "13800005678" not in events[0]["detail"]


def test_mask_collision_key_keeps_both_originals():
    """Signal-not-remove: the collided entry stays in the key (direct restore
    still works) — only the SecurityWarning/event is added."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SecurityWarning)
        _redacted, key = redact(_TEXT, lang="zh", mode="fast", config=_CONFIG)
    assert len(key) == 2
    assert set(key.values()) == {"13812345678", "13800005678"}
    assert "138****5678" in key
    assert "138****5678①" in key


def test_no_collision_no_warning_no_event():
    """A single masked phone (no collision) fires neither signal."""
    text = "电话13812345678"
    with warnings.catch_warnings():
        warnings.simplefilter("error", SecurityWarning)
        _redacted, _key, details = redact(
            text, lang="zh", mode="fast", config=_CONFIG, detailed=True
        )
    assert not any(e["reason_code"] == "mask_collision" for e in details["security_events"])
