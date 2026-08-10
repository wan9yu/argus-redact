"""v0.6.8 Presidio bridge routes through public redact(), inheriting
pipeline guarantees that the previous direct-merger+replace path skipped.
"""

from __future__ import annotations

import pytest


def test_presidio_respects_max_input_size():
    """MAX_INPUT_SIZE guard inherited via public redact()."""
    pytest.importorskip("presidio_analyzer")
    from argus_redact.integrations.presidio import PresidioBridge
    from argus_redact.pure.normalize import MAX_INPUT_SIZE

    bridge = PresidioBridge()
    huge_text = "x" * (MAX_INPUT_SIZE + 1)

    with pytest.raises(ValueError, match="MAX_INPUT_SIZE|too large|exceeds"):
        bridge.redact(huge_text)


def test_presidio_rejects_non_string_input():
    """isinstance(text, str) check inherited."""
    pytest.importorskip("presidio_analyzer")
    from argus_redact.integrations.presidio import PresidioBridge

    bridge = PresidioBridge()
    with pytest.raises(TypeError):
        bridge.redact(b"bytes not str")  # type: ignore


def test_presidio_returns_redacted_and_key():
    """End-to-end smoke: Presidio detects, argus-redact replaces."""
    pytest.importorskip("presidio_analyzer")
    from argus_redact.integrations.presidio import PresidioBridge

    bridge = PresidioBridge()
    text = "Contact Mr. John Smith at john@example.com"
    redacted, key = bridge.redact(text)
    # Some redaction must have happened
    assert redacted != text or len(key) > 0


class _NoOpAnalyzer:
    """Stub analyzer that always finds nothing — no presidio_analyzer install
    required, since PresidioBridge(analyzer=...) bypasses AnalyzerEngine()."""

    def analyze(self, *, text, language):
        return []


def test_presidio_empty_detection_still_routes_through_redact_pipeline():
    """The empty-detection branch must run the SAME redact() pipeline as the
    detected path — telemetry included — not an early return that skips it.
    Before the fix, `if not results: return text, key or {}` short-circuited
    before redact() ever ran, so telemetry never fired for empty detections.
    """
    from argus_redact.integrations.presidio import PresidioBridge
    from argus_redact.telemetry import set_perf_hook

    bridge = PresidioBridge(analyzer=_NoOpAnalyzer())
    records = []
    set_perf_hook(lambda r: records.append(r))
    try:
        redacted, key = bridge.redact("nothing sensitive here", language="en", salt=42)
    finally:
        set_perf_hook(None)

    # Same return shape as the detected path: (redacted_text, key).
    assert redacted == "nothing sensitive here"
    assert key == {}
    assert records, "empty-detection path must still run redact()'s telemetry emission"


def test_presidio_empty_detection_with_existing_key_preserves_it():
    """The empty-detection route (above) must also honor a pre-existing key: when
    nothing new is detected, the returned key is value-equal to the key that was
    passed in (object identity may differ) — not silently dropped or replaced
    with a fresh empty dict.
    """
    from argus_redact.integrations.presidio import PresidioBridge

    bridge = PresidioBridge(analyzer=_NoOpAnalyzer())
    existing_key = {"P-1": "张三"}

    _redacted, key = bridge.redact(
        "nothing sensitive here", language="en", salt=42, key=existing_key
    )

    assert key == existing_key
