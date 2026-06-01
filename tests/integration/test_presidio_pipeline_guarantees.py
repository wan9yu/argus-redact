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
