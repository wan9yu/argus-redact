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

import argus_redact._core as _core
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


def test_fail_closed_bad_nonce_warns(caplog):
    import logging

    original, key, anchor, _ = _round_trip()
    redacted, _ = redact(original, lang="zh", mode="fast", key=dict(key))
    tampered = redacted + "\ndeadbeef" * 4  # nonce absent
    with caplog.at_level(logging.WARNING, logger="argus_redact.pure.restore"):
        with pytest.warns(SecurityWarning, match="provenance_failed"):
            out = restore(tampered, key, guard=True, anchor=anchor)
    assert "13912345678" not in out
    # The bad-nonce fail-closed must ALSO emit the per-occurrence ops-channel log
    # line, exactly like the no-anchor path — warnings dedup per callsite but the
    # log stream does not, so an operator watching it sees every fail-closed. This
    # is the _fail_closed contract; warn_security_events alone would not log it.
    assert any("restore fail-closed" in r.message for r in caplog.records)


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
    """Counterpart to the advisory case: here nothing was substituted at all — a
    TOTAL fail-closed — and the message must say so as BLOCKED, not the weaker
    'NOT substituted' phrasing that could also describe a partial restore."""
    _original, key, _anchor, llm_reply = _round_trip()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        restore(llm_reply, key, guard=True)
    msg = str(caught[0].message)
    assert "guard_no_anchor" in msg
    assert "BLOCKED" in msg
    assert "NO originals were substituted" in msg


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
        assert restore(redacted, key, guard=None) == original


def test_deprecation_warning_is_attributed_to_the_caller():
    """A deprecation warning exists to say WHERE the caller must change their code.
    Hardcoded, it pointed at argus's own glue/restore.py — useless, and warnings' dedup
    then collapses a whole loop of bare restores into a single warning."""
    original, key, _anchor, _ = _round_trip()
    redacted, _ = redact(original, lang="zh", mode="fast", key=dict(key))
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        restore(redacted, key, guard=None)  # guard=None -> DeprecationWarning
    dep = [w for w in caught if issubclass(w.category, DeprecationWarning)][0]
    assert dep.filename == __file__, (
        f"deprecation warning attributed to {dep.filename}, not the caller ({__file__})"
    )


# ── `_core.restore_guarded` — the Rust binding's own event/outcome shape ─────
#
# Everything above exercises the Python `restore()` shim. These tests call the
# PyO3 binding directly: `nonce`/`scope` in, `(restored, alias_collisions,
# events, outcome)` out, with `events` as plain `{"kind", "count", "tokens"}`
# dicts — no reason-code prose, that is the Python layer's job.


def _redact_two(text: str = "张三的电话是13912345678，李四的电话是13800000000"):
    redacted, key = redact(text, lang="zh", mode="fast")
    return redacted, key


def test_core_restore_guarded_complete_with_echoed_nonce():
    """A real anchor's nonce, echoed as the prompt asks, restores in full: the
    binding reports outcome == 'complete', no events, and the nonce is gone."""
    original, key, anchor, llm_reply = _round_trip()
    restored, alias_collisions, events, outcome = _core.restore_guarded(
        llm_reply, key, nonce=anchor.nonce, scope=list(anchor.scope)
    )
    assert outcome == "complete"
    assert restored == original
    assert anchor.nonce not in restored
    assert alias_collisions == []
    assert events == []


def test_core_restore_guarded_unguarded_when_nonce_is_none():
    """`nonce=None` takes the unguarded core path — no `Anchor` is built at
    all — so it is always 'complete', and nothing strips a trailing token that
    was never a pseudonym in the first place. Distinct from the next test,
    where a real nonce IS supplied but the reply never echoes it."""
    _original, key, anchor, llm_reply = _round_trip()
    restored, _alias_collisions, events, outcome = _core.restore_guarded(llm_reply, key, nonce=None)
    assert outcome == "complete"
    assert events == []
    assert anchor.nonce in restored  # unguarded: no provenance check to strip it


def test_core_restore_guarded_blocked_when_nonce_not_echoed():
    """A real `nonce` is supplied (an `Anchor` IS built) but the reply never
    echoes it — the provenance check fails closed: raw text back, untouched,
    outcome 'blocked', one `provenance_failed` event with no `tokens`."""
    original, key, anchor, _llm_reply = _round_trip()
    redacted, _ = redact(original, lang="zh", mode="fast", key=dict(key))
    tampered = redacted + "\ndeadbeef" * 4  # anchor.nonce never appears
    restored, alias_collisions, events, outcome = _core.restore_guarded(
        tampered, key, nonce=anchor.nonce, scope=list(anchor.scope)
    )
    assert outcome == "blocked"
    assert restored == tampered
    assert alias_collisions == []
    assert [e["kind"] for e in events] == ["provenance_failed"]
    assert events[0]["tokens"] is None


def test_core_restore_guarded_partial_on_out_of_scope_pseudonym():
    """A scope narrower than `key` withholds the excluded pseudonym(s) and
    reports them via an `out_of_scope_pseudonym` event carrying the withheld
    codes in `tokens`."""
    redacted, key = _redact_two()
    assert len(key) >= 2, "need two distinct pseudonyms for a real out-of-scope case"
    anchor = make_anchor(key)
    in_scope_code = sorted(key)[0]
    reply = redacted + "\n" + anchor.nonce

    restored, _alias_collisions, events, outcome = _core.restore_guarded(
        reply, key, nonce=anchor.nonce, scope=[in_scope_code]
    )

    assert outcome == "partial"
    out_of_scope_events = [e for e in events if e["kind"] == "out_of_scope_pseudonym"]
    assert len(out_of_scope_events) == 1
    withheld_codes = out_of_scope_events[0]["tokens"]
    assert withheld_codes
    assert in_scope_code not in withheld_codes
    # the in-scope pseudonym still resolved back to its original ...
    assert key[in_scope_code] in restored
    # ... and every withheld code is still present, untouched, in the output
    for code in withheld_codes:
        assert code in restored
