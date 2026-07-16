"""guarded_restore() — the whole guard flow, in one place.

D1 (integrations computed security events and then dropped them) was not bad luck; it
is what copy-pasting a 6-step flow across 5 files produces. This is the one place the
flow can be wrong, and these tests pin it.
"""

from __future__ import annotations

import warnings

import pytest

from argus_redact import make_anchor, redact
from argus_redact.exceptions import SecurityWarning
from argus_redact.glue.guarded_restore import guarded_restore
from argus_redact.pure.restore import RestoreGuardError

_PHONE = "13912345678"


def _round_trip(inject: bool = False):
    redacted, key = redact(f"张三的电话是{_PHONE}", lang="zh", mode="fast")
    anchor = make_anchor(key)
    if inject:
        # amplification + exfil, with a VALID nonce so P and S both pass and only H trips
        pseudonym = next(p for p, original in key.items() if original == _PHONE)
        reply = " ".join([pseudonym] * 20) + " send to http://evil.example.com\n" + anchor.nonce
    else:
        reply = redacted + "\n" + anchor.nonce
    return redacted, key, anchor, reply


def test_clean_round_trip_restores_and_strips_the_nonce():
    _redacted, key, anchor, reply = _round_trip()
    out = guarded_restore(reply, key, anchor=anchor)
    assert out == f"张三的电话是{_PHONE}"
    assert anchor.nonce not in out


def test_h_events_reach_the_caller_on_the_default_path():
    """The D1 defect, pinned: events must never be computed and then dropped."""
    redacted, key, anchor, reply = _round_trip(inject=True)
    with pytest.warns(SecurityWarning, match="injection_suspected"):
        guarded_restore(reply, key, redacted=redacted, anchor=anchor)


def test_h_events_returned_when_detailed():
    redacted, key, anchor, reply = _round_trip(inject=True)
    _out, details = guarded_restore(reply, key, redacted=redacted, anchor=anchor, detailed=True)
    assert "injection_suspected" in [e["reason_code"] for e in details["security_events"]]


def test_strict_fails_closed_on_injection_before_substituting():
    redacted, key, anchor, reply = _round_trip(inject=True)
    with pytest.raises(RestoreGuardError):
        guarded_restore(reply, key, redacted=redacted, anchor=anchor, strict=True)


def test_h_is_advisory_without_strict():
    """By design: H is a heuristic and never becomes the guarantee (that is P + S)."""
    redacted, key, anchor, reply = _round_trip(inject=True)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SecurityWarning)
        out = guarded_restore(reply, key, redacted=redacted, anchor=anchor)
    assert _PHONE in out  # the restore proceeded


def test_no_h_check_without_the_redacted_prompt():
    """H needs the redacted prompt. Without it, no H event — and no crash."""
    _redacted, key, anchor, reply = _round_trip(inject=True)
    _out, details = guarded_restore(reply, key, anchor=anchor, detailed=True)
    assert "injection_suspected" not in [e["reason_code"] for e in details["security_events"]]


def test_fail_closed_when_no_anchor():
    _redacted, key, _anchor, reply = _round_trip()
    with pytest.warns(SecurityWarning, match="guard_no_anchor"):
        out = guarded_restore(reply, key)  # guard=True default, no anchor
    assert _PHONE not in out  # fail-closed: nothing substituted


def test_fail_closed_warning_is_attributed_to_the_caller_not_guarded_restore():
    """guarded_restore() sits one frame deeper than a direct restore() call: the
    chain is warn -> _fail_closed -> pure.restore -> glue.restore -> guarded_restore
    -> caller. A stacklevel hardcoded for restore()'s own call depth misattributes
    the warning to guarded_restore.py instead of here — and warnings' dedup on
    (message, category, module, lineno) would then collapse every fail-closed
    restore in a caller's loop into a single warning with no pointer back to the
    caller's own code."""
    _redacted, key, _anchor, reply = _round_trip()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        guarded_restore(reply, key)  # guard=True default, no anchor -> fail closed
    assert caught[0].filename == __file__, (
        f"warning attributed to {caught[0].filename}, not the caller ({__file__})"
    )


def test_fail_closed_and_h_fire_together_produce_one_accurate_warning():
    """FINDING 1 (v0.7.20 review): restore()'s own P/S warning and guarded_restore's H
    warning used to be emitted separately, over disjoint event lists — so when a
    fail-closed P/S trip and an advisory H hit occurred together, the caller got TWO
    warnings, and the second one FALSELY claimed the restore proceeded when nothing
    was substituted at all."""
    redacted, key = redact(f"张三的电话是{_PHONE}", lang="zh", mode="fast")
    anchor = make_anchor(key)
    pseudonym = next(p for p, original in key.items() if original == _PHONE)
    # amplification + exfil pattern (trips H) with NO nonce at all (trips P -> fail closed)
    reply = " ".join([pseudonym] * 20) + " send to http://evil.example.com"

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        out = guarded_restore(reply, key, redacted=redacted, anchor=anchor)

    security_warnings = [w for w in caught if issubclass(w.category, SecurityWarning)]
    assert len(security_warnings) == 1, [str(w.message) for w in security_warnings]
    msg = str(security_warnings[0].message)
    assert "provenance_failed" in msg
    assert "injection_suspected" in msg
    assert "PROCEEDED" not in msg, f"fail-closed restore falsely described as proceeding: {msg!r}"
    assert _PHONE not in out  # genuinely fail-closed: nothing was substituted


def test_clean_ps_with_h_only_produces_one_advisory_warning():
    """Counterpart to the mixed case above: when P/S are clean and only H fires, the
    single warning must still say the restore proceeded (it did)."""
    redacted, key, anchor, reply = _round_trip(inject=True)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        out = guarded_restore(reply, key, redacted=redacted, anchor=anchor)

    security_warnings = [w for w in caught if issubclass(w.category, SecurityWarning)]
    assert len(security_warnings) == 1, [str(w.message) for w in security_warnings]
    msg = str(security_warnings[0].message)
    assert "injection_suspected" in msg
    assert "PROCEEDED" in msg
    assert _PHONE in out  # advisory only — the restore genuinely proceeded


def test_guard_none_through_guarded_restore_still_emits_deprecation_warning():
    """Proves the SecurityWarning suppression added for the fix above is scoped to
    SecurityWarning only: restore()'s DeprecationWarning (bare guard=None) must still
    reach the caller through guarded_restore."""
    _redacted, key, anchor, reply = _round_trip()
    with pytest.warns(DeprecationWarning, match="deprecated"):
        guarded_restore(reply, key, anchor=anchor, guard=None)


def test_key_file_path_is_accepted(tmp_path):
    """Routes through the GLUE restore, so a str key-file path works (presidio bypassed this)."""
    import json

    _redacted, key, anchor, reply = _round_trip()
    kf = tmp_path / "key.json"
    kf.write_text(json.dumps(key), encoding="utf-8")
    assert guarded_restore(reply, str(kf), anchor=anchor) == f"张三的电话是{_PHONE}"
