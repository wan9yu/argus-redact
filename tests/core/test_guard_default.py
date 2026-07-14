"""v0.8.0 guard-default flip + R4 visible-consequence warning.

The default of ``restore(..., guard=)`` flipped from ``None`` (legacy, silent)
to ``True`` (deterministic provenance + scope guard) in v0.8.0. A bare
``restore(text, key)`` with no anchor now FAILS CLOSED — the text is returned
un-restored. Callers who want the old plain substitution opt out explicitly with
``guard=False``.

R4 makes the unguarded path visible in production:
- ``guard=None`` (caller has NOT chosen) that actually substitutes → a
  ``SecurityWarning`` naming the consequence, ALONGSIDE the migration
  ``DeprecationWarning``.
- ``guard=False`` (the informed opt-out the warning text points to) → silent.
"""

from __future__ import annotations

import warnings

from argus_redact import restore
from argus_redact.compose.anchor import make_anchor
from argus_redact.exceptions import SecurityWarning


def test_bare_restore_fails_closed_by_default():
    """(a) No guard=, no anchor → fail closed; the original is NOT reinserted."""
    result = restore("x P-1 y", {"P-1": "Alice"})
    assert "Alice" not in result
    assert "P-1" in result  # placeholder left in place


def test_bare_restore_detailed_reports_guard_no_anchor():
    result, details = restore("x P-1 y", {"P-1": "Alice"}, detailed=True)
    assert "Alice" not in result
    codes = [e["reason_code"] for e in details["security_events"]]
    assert "guard_no_anchor" in codes


def test_guard_true_with_anchor_round_trips():
    key = {"P-1": "Alice"}
    anchor = make_anchor(key)
    text = f"hello P-1\n{anchor.nonce}"
    result = restore(text, key, guard=True, anchor=anchor)
    assert "Alice" in result
    assert anchor.nonce not in result  # verification token stripped


# --- R4: the visible-consequence SecurityWarning ---------------------------


def test_guard_none_substituting_emits_security_warning():
    """(b) guard=None that actually substitutes → a SecurityWarning (R4)."""
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        result = restore("x P-1 y", {"P-1": "Alice"}, guard=None)
    assert "Alice" in result  # legacy path substitutes
    assert any(issubclass(w.category, SecurityWarning) for w in caught), (
        "guard=None that reinserted an original must warn about the missing guard"
    )


def test_guard_none_still_emits_deprecation_warning():
    """The migration DeprecationWarning is a DISTINCT warning from R4's SecurityWarning."""
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        restore("x P-1 y", {"P-1": "Alice"}, guard=None)
    categories = {w.category for w in caught}
    assert any(issubclass(c, DeprecationWarning) for c in categories)
    assert any(issubclass(c, SecurityWarning) for c in categories)
    # SecurityWarning is a UserWarning, DeprecationWarning is not — they must not
    # collapse into one category.
    assert DeprecationWarning not in {SecurityWarning}


def test_guard_none_no_substitution_no_security_warning():
    """(b) guard=None that substitutes NOTHING → no SecurityWarning (still deprecated)."""
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        result = restore("nothing here", {"P-1": "Alice"}, guard=None)
    assert result == "nothing here"
    assert not any(issubclass(w.category, SecurityWarning) for w in caught), (
        "a no-op restore reinserted nothing — there is no consequence to warn about"
    )
    # The DeprecationWarning is about the call SHAPE, so it still fires.
    assert any(issubclass(w.category, DeprecationWarning) for w in caught)


def test_guard_false_is_silent_even_when_substituting():
    """guard=False is the informed opt-out — NO SecurityWarning, NO DeprecationWarning."""
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        result = restore("x P-1 y", {"P-1": "Alice"}, guard=False)
    assert "Alice" in result  # legacy substitution still happens
    assert not any(issubclass(w.category, SecurityWarning) for w in caught)
    assert not any(issubclass(w.category, DeprecationWarning) for w in caught)


def test_guard_false_detailed_returns_empty_events():
    result, details = restore("x P-1 y", {"P-1": "Alice"}, guard=False, detailed=True)
    assert "Alice" in result
    assert details["security_events"] == []


def test_fail_closed_logs_to_ops_channel(caplog):
    """_fail_closed emits a PII-free logger.warning (no per-callsite dedup)."""
    import logging

    with caplog.at_level(logging.WARNING, logger="argus_redact.pure.restore"):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            restore("x P-1 y", {"P-1": "Alice"})
    assert any("fail-closed" in r.message for r in caplog.records)
    # PII-free: the original value never reaches the log line.
    assert all("Alice" not in r.getMessage() for r in caplog.records)
