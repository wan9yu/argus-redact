"""guarded_restore() — the whole guard flow, in one place.

D1 (integrations computed security events and then dropped them) was not bad luck; it
is what copy-pasting a 6-step flow across 5 files produces. This is the one place the
flow can be wrong, and these tests pin it.
"""

from __future__ import annotations

import warnings

import pytest

from argus_redact import make_anchor, redact
from argus_redact.glue.guarded_restore import guarded_restore
from argus_redact.pure.replacer import SecurityWarning
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


def test_key_file_path_is_accepted(tmp_path):
    """Routes through the GLUE restore, so a str key-file path works (presidio bypassed this)."""
    import json

    _redacted, key, anchor, reply = _round_trip()
    kf = tmp_path / "key.json"
    kf.write_text(json.dumps(key), encoding="utf-8")
    assert guarded_restore(reply, str(kf), anchor=anchor) == f"张三的电话是{_PHONE}"
