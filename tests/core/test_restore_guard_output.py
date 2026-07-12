"""v0.7.19 — what the CALLER actually receives from a guarded restore.

The v0.7.18 guard was verified leak-free (P + S hold), but nothing asserted the
*shape* of the value handed back. Two defects lived in that gap:

- D0: the verification nonce was checked but never stripped, so every successful
  guarded restore returned plaintext with a 32-hex token stapled to it.
- D3: a fail-closed restore returned a bare ``str`` indistinguishable from success,
  with no signal at all on the default (``strict=False, detailed=False``) path —
  contradicting the documented "emits a UserWarning" contract.

These tests assert on EQUALITY, not substring containment. The `in`-style assertions
are exactly what let D0 through.
"""

from __future__ import annotations

import warnings

import pytest

from argus_redact import make_anchor, redact, restore
from argus_redact.pure.replacer import SecurityWarning


def _round_trip(text: str = "张三的电话是13912345678"):
    """redact -> anchor -> simulate an honest LLM that echoes the token as instructed."""
    redacted, key = redact(text, lang="zh", mode="fast")
    anchor = make_anchor(key)
    llm_reply = redacted + "\n" + anchor.nonce
    return text, key, anchor, llm_reply


# ── D0: the nonce must not survive into the restored output ──────────────────


def test_guarded_restore_strips_the_nonce():
    original, key, anchor, llm_reply = _round_trip()
    out = restore(llm_reply, key, guard=True, anchor=anchor)
    assert anchor.nonce not in out
    # EQUALITY — the whole point. `in` would have passed on the buggy version.
    assert out == original


def test_guarded_restore_strips_nonce_in_detailed_mode():
    original, key, anchor, llm_reply = _round_trip()
    out, details = restore(llm_reply, key, guard=True, anchor=anchor, detailed=True)
    assert anchor.nonce not in out
    assert out == original
    assert details["security_events"] == []


def test_guarded_restore_strips_nonce_echoed_inline():
    """Defensive: the prompt asks for the token on its own line, but a model may
    inline it. It must still not reach the caller."""
    original, key, anchor, _ = _round_trip()
    redacted, _ = redact(original, lang="zh", mode="fast", key=dict(key))
    llm_reply = f"{redacted} {anchor.nonce}"
    out = restore(llm_reply, key, guard=True, anchor=anchor)
    assert anchor.nonce not in out


# ── D3: fail-closed must be observable on the default path ───────────────────


def test_fail_closed_no_anchor_warns():
    _original, key, _anchor, llm_reply = _round_trip()
    with pytest.warns(SecurityWarning, match="guard_no_anchor"):
        out = restore(llm_reply, key, guard=True)  # no anchor -> fail closed
    assert "13912345678" not in out  # still fail-closed: no PII substituted


def test_fail_closed_bad_nonce_warns():
    original, key, anchor, _ = _round_trip()
    redacted, _ = redact(original, lang="zh", mode="fast", key=dict(key))
    tampered = redacted + "\ndeadbeef" * 4  # nonce absent
    with pytest.warns(SecurityWarning, match="provenance_failed"):
        out = restore(tampered, key, guard=True, anchor=anchor)
    assert "13912345678" not in out


def test_fail_closed_warning_is_attributed_to_the_caller():
    """The fail-closed path goes restore() -> _fail_closed() -> warn, one frame deeper
    than the partial-restore path. A single hardcoded stacklevel cannot serve both; if it
    points inside argus, warnings' dedup collapses a whole loop into one warning."""
    _original, key, _anchor, llm_reply = _round_trip()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        restore(llm_reply, key, guard=True)  # no anchor -> fail closed
    assert caught[0].filename == __file__, (
        f"warning attributed to {caught[0].filename}, not the caller ({__file__})"
    )


def test_fail_closed_warning_says_pii_was_withheld():
    """Counterpart to the advisory case: here the pseudonyms really were withheld, and
    the message must say so."""
    _original, key, _anchor, llm_reply = _round_trip()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        restore(llm_reply, key, guard=True)
    msg = str(caught[0].message)
    assert "guard_no_anchor" in msg
    assert "NOT substituted" in msg


def test_clean_guarded_restore_does_not_warn():
    _original, key, anchor, llm_reply = _round_trip()
    with warnings.catch_warnings():
        warnings.simplefilter("error", SecurityWarning)
        restore(llm_reply, key, guard=True, anchor=anchor)  # must not raise


def test_strict_still_raises_and_does_not_rely_on_the_warning():
    from argus_redact import RestoreGuardError

    _original, key, _anchor, llm_reply = _round_trip()
    with pytest.raises(RestoreGuardError):
        restore(llm_reply, key, guard=True, strict=True)


def test_legacy_paths_unchanged():
    """guard=False stays a silent legacy restore; guard=None keeps its DeprecationWarning."""
    original, key, _anchor, _ = _round_trip()
    redacted, _ = redact(original, lang="zh", mode="fast", key=dict(key))
    with warnings.catch_warnings():
        warnings.simplefilter("error", SecurityWarning)
        assert restore(redacted, key, guard=False) == original
    with pytest.warns(DeprecationWarning):
        assert restore(redacted, key) == original


def test_deprecation_warning_is_attributed_to_the_caller():
    """A deprecation warning exists to say WHERE the caller must change their code.
    Hardcoded, it pointed at argus's own glue/restore.py — useless, and warnings' dedup
    then collapses a whole loop of bare restores into a single warning."""
    original, key, _anchor, _ = _round_trip()
    redacted, _ = redact(original, lang="zh", mode="fast", key=dict(key))
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        restore(redacted, key)  # bare -> DeprecationWarning
    dep = [w for w in caught if issubclass(w.category, DeprecationWarning)][0]
    assert dep.filename == __file__, (
        f"deprecation warning attributed to {dep.filename}, not the caller ({__file__})"
    )
